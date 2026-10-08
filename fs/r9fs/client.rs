// SPDX-License-Identifier: GPL-2.0

//! 9P2000.L client session over one [`Channel`].

use crate::proto::{
    Attr, Dec, Qid, StatFs, GETATTR_BASIC, IOHDR, NOFID, TATTACH, TCLUNK, TGETATTR, TLOPEN,
    TREAD, TREADDIR, TREADLINK, TSTATFS, TVERSION, TWALK, VERSION_9P2000_L,
};
use crate::transport::Channel;
use core::sync::atomic::{AtomicU32, Ordering};
use kernel::{prelude::*, sync::Arc};

/// Connection parameters.
pub(crate) struct Options<'a> {
    pub(crate) tag: &'a [u8],
    pub(crate) msize: u32,
    pub(crate) uname: &'a [u8],
    pub(crate) aname: &'a [u8],
    pub(crate) uid: u32,
}

/// An attached 9P session.
pub(crate) struct Session {
    chan: Arc<Channel>,
    msize: u32,
    root_fid: u32,
    next_fid: AtomicU32,
}

impl Session {
    /// Claims the channel, negotiates the protocol version and attaches.
    pub(crate) fn connect(opts: &Options<'_>) -> Result<Self> {
        let chan = Channel::claim(opts.tag, opts.msize)?;
        let res = (|| {
            let msize = chan.rpc(
                TVERSION,
                |e| {
                    e.u32(opts.msize)?;
                    e.str(VERSION_9P2000_L)
                },
                |d| {
                    let msize = d.u32()?;
                    if d.str()? != VERSION_9P2000_L {
                        return Err(EPROTONOSUPPORT);
                    }
                    Ok(msize)
                },
            )?;
            if msize < 4096 || msize > opts.msize {
                return Err(EREMOTEIO);
            }
            chan.set_msize(msize);
            let root_fid = 0;
            chan.rpc(
                TATTACH,
                |e| {
                    e.u32(root_fid)?;
                    e.u32(NOFID)?;
                    e.str(opts.uname)?;
                    e.str(opts.aname)?;
                    e.u32(opts.uid)
                },
                |d| d.qid().map(|_| ()),
            )?;
            Ok((msize, root_fid))
        })();
        match res {
            Ok((msize, root_fid)) => Ok(Self {
                chan,
                msize,
                root_fid,
                next_fid: AtomicU32::new(root_fid + 1),
            }),
            Err(e) => {
                chan.release();
                Err(e)
            }
        }
    }

    pub(crate) fn root_fid(&self) -> u32 {
        self.root_fid
    }

    /// Largest payload of a single read or readdir reply.
    pub(crate) fn max_io(&self) -> u32 {
        self.msize - IOHDR
    }

    fn alloc_fid(&self) -> Result<u32> {
        let fid = self.next_fid.fetch_add(1, Ordering::Relaxed);
        if fid == NOFID {
            return Err(EMFILE);
        }
        Ok(fid)
    }

    /// Walks from `fid` through at most one path element, returning a new fid.
    ///
    /// With no element this clones `fid`. A missing element is `ENOENT`.
    pub(crate) fn walk(&self, fid: u32, name: Option<&[u8]>) -> Result<u32> {
        let newfid = self.alloc_fid()?;
        let nwname: u16 = if name.is_some() { 1 } else { 0 };
        let nwqid = self.chan.rpc(
            TWALK,
            |e| {
                e.u32(fid)?;
                e.u32(newfid)?;
                e.u16(nwname)?;
                if let Some(n) = name {
                    e.str(n)?;
                }
                Ok(())
            },
            |d| {
                let n = d.u16()?;
                for _ in 0..n {
                    d.qid()?;
                }
                Ok(n)
            },
        )?;
        if nwqid > nwname {
            // Malformed reply; the server may still have bound `newfid`.
            self.clunk(newfid);
            return Err(EIO);
        }
        if nwqid < nwname {
            // A partial walk does not create `newfid`.
            return Err(ENOENT);
        }
        Ok(newfid)
    }

    pub(crate) fn getattr(&self, fid: u32) -> Result<Attr> {
        self.chan.rpc(
            TGETATTR,
            |e| {
                e.u32(fid)?;
                e.u64(GETATTR_BASIC)
            },
            Attr::decode,
        )
    }

    /// Opens `fid` with Linux open `flags`; returns the qid and the server's `iounit`.
    pub(crate) fn lopen(&self, fid: u32, flags: u32) -> Result<(Qid, u32)> {
        self.chan.rpc(
            TLOPEN,
            |e| {
                e.u32(fid)?;
                e.u32(flags)
            },
            |d| Ok((d.qid()?, d.u32()?)),
        )
    }

    fn read_into(&self, typ: u8, fid: u32, offset: u64, out: &mut [u8]) -> Result<usize> {
        let count = u32::try_from(out.len()).unwrap_or(u32::MAX).min(self.max_io());
        self.chan.rpc(
            typ,
            |e| {
                e.u32(fid)?;
                e.u64(offset)?;
                e.u32(count)
            },
            |d: &mut Dec<'_>| {
                let n = d.u32()? as usize;
                if n > count as usize || n > d.remaining() {
                    return Err(EIO);
                }
                out[..n].copy_from_slice(d.bytes(n)?);
                Ok(n)
            },
        )
    }

    /// Reads file data at `offset` into `out`; returns the byte count (0 at end of file).
    pub(crate) fn read(&self, fid: u32, offset: u64, out: &mut [u8]) -> Result<usize> {
        self.read_into(TREAD, fid, offset, out)
    }

    /// Reads packed directory entries starting after server cookie `offset`.
    pub(crate) fn readdir(&self, fid: u32, offset: u64, out: &mut [u8]) -> Result<usize> {
        self.read_into(TREADDIR, fid, offset, out)
    }

    pub(crate) fn readlink(&self, fid: u32) -> Result<KVec<u8>> {
        self.chan.rpc(
            TREADLINK,
            |e| e.u32(fid),
            |d| {
                let s = d.str()?;
                let mut v = KVec::with_capacity(s.len(), GFP_KERNEL)?;
                v.extend_from_slice(s, GFP_KERNEL)?;
                Ok(v)
            },
        )
    }

    pub(crate) fn statfs(&self, fid: u32) -> Result<StatFs> {
        self.chan.rpc(TSTATFS, |e| e.u32(fid), StatFs::decode)
    }

    /// Releases `fid` on the server. Errors are ignored: the fid is gone either way.
    pub(crate) fn clunk(&self, fid: u32) {
        let _ = self.chan.rpc(TCLUNK, |e| e.u32(fid), |_| Ok(()));
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.clunk(self.root_fid);
        self.chan.release();
    }
}
