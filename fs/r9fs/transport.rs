// SPDX-License-Identifier: GPL-2.0

//! virtio-9p transport.
//!
//! Each virtio-9p device is a [`Channel`] identified by its mount tag. A channel serves one
//! mount at a time and carries one request at a time: the channel mutex is held from
//! submission until the reply is consumed, so a single tag suffices and the virtqueue is never
//! accessed concurrently.

use crate::proto::{Dec, Enc, HDR, NOTAG, RLERROR, TVERSION};
use core::ptr::NonNull;
use kernel::{
    new_mutex,
    prelude::*,
    sync::{Arc, ArcBorrow, Completion, Mutex},
    virtio::{self, Device, DeviceId, VirtQueue},
};

const VIRTIO_ID_9P: u32 = 9;
const VIRTIO_9P_MOUNT_TAG: u32 = 0;
/// Offsets in `struct virtio_9p_config`.
const CFG_TAG_LEN: u32 = 0;
const CFG_TAG: u32 = 2;

kernel::sync::global_lock! {
    // SAFETY: Initialised in module init before the driver is registered.
    pub(crate) unsafe(uninit) static CHANNELS: Mutex<KVec<Arc<Channel>>> = KVec::new();
}

struct State {
    /// Set by device removal; the virtqueue must not be touched afterwards.
    dead: bool,
    /// A mount currently owns the channel.
    in_use: bool,
    tbuf: KVec<u8>,
    rbuf: KVec<u8>,
}

/// A virtio-9p device.
#[pin_data]
pub(crate) struct Channel {
    tag: KVec<u8>,
    vq: VirtQueue,
    #[pin]
    state: Mutex<State>,
    #[pin]
    done: Completion,
}

impl Channel {
    /// Claims the channel whose mount tag is `tag` for a mount, with buffers of `msize` bytes.
    pub(crate) fn claim(tag: &[u8], msize: u32) -> Result<Arc<Channel>> {
        let chans = CHANNELS.lock();
        let chan = chans
            .iter()
            .find(|c| c.tag.as_slice() == tag)
            .ok_or(ENOENT)?
            .clone();
        drop(chans);

        let mut st = chan.state.lock();
        if st.dead {
            return Err(ENODEV);
        }
        if st.in_use {
            return Err(EBUSY);
        }
        st.tbuf = KVec::from_elem(0u8, msize as usize, GFP_KERNEL)?;
        st.rbuf = KVec::from_elem(0u8, msize as usize, GFP_KERNEL)?;
        st.in_use = true;
        drop(st);
        Ok(chan)
    }

    /// Releases a claim and frees the request buffers.
    pub(crate) fn release(&self) {
        let mut st = self.state.lock();
        st.in_use = false;
        st.tbuf = KVec::new();
        st.rbuf = KVec::new();
    }

    /// Shrinks the buffers after version negotiation lowered `msize`.
    pub(crate) fn set_msize(&self, msize: u32) {
        let mut st = self.state.lock();
        st.tbuf.truncate(msize as usize);
        st.rbuf.truncate(msize as usize);
    }

    /// Sends a `typ` request whose body `enc` writes and decodes the reply body with `dec`.
    ///
    /// `Rlerror` replies become the server's errno; any other reply type than `typ + 1`, a tag
    /// mismatch, or a malformed reply is `EIO`.
    pub(crate) fn rpc<R>(
        &self,
        typ: u8,
        enc: impl FnOnce(&mut Enc<'_>) -> Result,
        dec: impl FnOnce(&mut Dec<'_>) -> Result<R>,
    ) -> Result<R> {
        let mut guard = self.state.lock();
        let st = &mut *guard;
        if st.dead {
            return Err(EIO);
        }
        let tag = if typ == TVERSION { NOTAG } else { 0 };

        let mut e = Enc::new(&mut st.tbuf, HDR);
        enc(&mut e)?;
        let size = e.pos();
        st.tbuf[0..4].copy_from_slice(&(size as u32).to_le_bytes());
        st.tbuf[4] = typ;
        st.tbuf[5..7].copy_from_slice(&tag.to_le_bytes());

        let token = NonNull::from(&mut st.tbuf[0]).cast();
        self.done.reinit();
        // SAFETY: The queue is live (`!dead`) and serialised by the channel mutex. Both buffers
        // are `kmalloc` memory owned by `State`, which is neither touched nor freed while the
        // mutex is held, and the request is reaped below before the mutex is released.
        let len = unsafe {
            self.vq.add_buf(&st.tbuf[..size], &mut st.rbuf, token)?;
            if !self.vq.kick() {
                st.dead = true;
                return Err(EIO);
            }
            loop {
                self.done.wait_for_completion();
                if let Some((_, len)) = self.vq.get_buf() {
                    break len as usize;
                }
            }
        };

        let reply = st.rbuf.get(..len).ok_or(EIO)?;
        let mut d = Dec::new(reply);
        let rsize = d.u32()? as usize;
        let rtype = d.u8()?;
        let rtag = d.u16()?;
        if rsize < HDR || rsize > len || rtag != tag {
            return Err(EIO);
        }
        let mut body = Dec::new(&reply[HDR..rsize]);
        if rtype == RLERROR {
            let ecode = body.u32()?;
            return Err(i32::try_from(ecode)
                .ok()
                .filter(|e| (1..4096).contains(e))
                .map(|e| Error::from_errno(-e))
                .unwrap_or(EIO));
        }
        if rtype != typ + 1 {
            return Err(EIO);
        }
        dec(&mut body)
    }
}

/// The virtio driver for 9P devices.
pub(crate) struct Driver;

impl virtio::Driver for Driver {
    type Data = Arc<Channel>;
    const NAME: &'static CStr = c"r9fs_virtio";
    const ID_TABLE: &'static [DeviceId] = &[virtio::device_id(VIRTIO_ID_9P), virtio::DEVICE_ID_END];
    const FEATURES: &'static [u32] = &[VIRTIO_9P_MOUNT_TAG];

    fn probe(dev: &Device) -> Result<Arc<Channel>> {
        if !dev.has_config_get() || !dev.has_feature(VIRTIO_9P_MOUNT_TAG) {
            return Err(EINVAL);
        }
        let vq = dev.find_single_vq::<Self>(c"requests")?;
        let tag_len = dev.cread16(CFG_TAG_LEN);
        let mut tag = KVec::from_elem(0u8, tag_len.into(), GFP_KERNEL)?;
        dev.cread_bytes(CFG_TAG, &mut tag);
        Arc::pin_init(
            pin_init!(Channel {
                tag,
                vq,
                state <- new_mutex!(State {
                    dead: false,
                    in_use: false,
                    tbuf: KVec::new(),
                    rbuf: KVec::new(),
                }),
                done <- Completion::new(),
            }),
            GFP_KERNEL,
        )
    }

    fn post_probe(dev: &Device, chan: ArcBorrow<'_, Channel>) -> Result {
        dev.ready();
        CHANNELS.lock().push(chan.into(), GFP_KERNEL)?;
        Ok(())
    }

    fn remove(_dev: &Device, chan: ArcBorrow<'_, Channel>) {
        let mut chans = CHANNELS.lock();
        if let Some(i) = chans.iter().position(|c| core::ptr::eq(&**c, &*chan)) {
            drop(chans.remove(i));
        }
        drop(chans);
        chan.state.lock().dead = true;
    }

    fn vq_done(chan: ArcBorrow<'_, Channel>) {
        chan.done.complete();
    }
}
