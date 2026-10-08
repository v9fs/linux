// SPDX-License-Identifier: GPL-2.0

//! Virtio drivers and virtqueues.
//!
//! This is a minimal binding: one driver registration per [`Driver`] type, a single request
//! virtqueue per device, and scatter-gather submission of caller-owned buffers.
//!
//! C headers: [`include/linux/virtio.h`](srctree/include/linux/virtio.h) and
//! [`include/linux/virtio_config.h`](srctree/include/linux/virtio_config.h).

use crate::{
    bindings,
    error::{from_err_ptr, to_result, Result},
    prelude::*,
    types::{ForeignOwnable, Opaque},
    ThisModule,
};
use core::{ffi::c_void, marker::PhantomData, ptr::NonNull};

/// Matches any vendor in a [`DeviceId`].
pub const VIRTIO_DEV_ANY_ID: u32 = 0xffff_ffff;

/// A virtio device id table entry.
pub type DeviceId = bindings::virtio_device_id;

/// Builds a [`DeviceId`] matching `device` from any vendor.
pub const fn device_id(device: u32) -> DeviceId {
    DeviceId {
        device,
        vendor: VIRTIO_DEV_ANY_ID,
    }
}

/// The terminating all-zero entry of a [`DeviceId`] table.
pub const DEVICE_ID_END: DeviceId = DeviceId {
    device: 0,
    vendor: 0,
};

/// A virtio device.
///
/// # Invariants
///
/// The wrapped `struct virtio_device` is valid for the lifetime of the reference.
#[repr(transparent)]
pub struct Device(Opaque<bindings::virtio_device>);

impl Device {
    /// # Safety
    ///
    /// `ptr` must point to a valid `struct virtio_device` that outlives `'a`.
    unsafe fn from_raw<'a>(ptr: *mut bindings::virtio_device) -> &'a Self {
        // SAFETY: `Device` is `repr(transparent)` over the C struct; validity per caller.
        unsafe { &*ptr.cast() }
    }

    /// Returns the raw `struct virtio_device` pointer.
    pub fn as_raw(&self) -> *mut bindings::virtio_device {
        self.0.get()
    }

    /// Returns whether feature bit `fbit` was negotiated.
    pub fn has_feature(&self, fbit: u32) -> bool {
        // SAFETY: The device is valid by the type invariant.
        unsafe { bindings::virtio_has_feature(self.as_raw(), fbit) }
    }

    /// Returns whether the transport allows config space reads.
    pub fn has_config_get(&self) -> bool {
        // SAFETY: The device and its `config` ops table are valid by the type invariant.
        unsafe { (*(*self.as_raw()).config).get.is_some() }
    }

    /// Reads `buf.len()` bytes of device config space starting at `offset`.
    pub fn cread_bytes(&self, offset: u32, buf: &mut [u8]) {
        // SAFETY: The device is valid and `buf` is writable for its whole length.
        unsafe {
            bindings::virtio_cread_bytes(
                self.as_raw(),
                offset,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        }
    }

    /// Reads a 16-bit config field at `offset`, converted from the device byte order.
    pub fn cread16(&self, offset: u32) -> u16 {
        // SAFETY: The device is valid by the type invariant.
        unsafe { bindings::virtio_cread16(self.as_raw(), offset) }
    }

    /// Marks the device ready (`DRIVER_OK`). Virtqueues must be set up first.
    pub fn ready(&self) {
        // SAFETY: The device is valid by the type invariant.
        unsafe { bindings::virtio_device_ready(self.as_raw()) }
    }

    /// Finds the device's single virtqueue, invoking [`Driver::vq_done`] on completions.
    ///
    /// The queue is deleted by the [`Registration`] after [`Driver::remove`] returns; callers
    /// must not use the returned [`VirtQueue`] after that point.
    pub fn find_single_vq<T: Driver>(&self, name: &'static CStr) -> Result<VirtQueue> {
        // SAFETY: The device is valid; the callback is a valid `vq_callback_t` and `name` is
        // a static NUL-terminated string.
        let vq = from_err_ptr(unsafe {
            bindings::virtio_find_single_vq(
                self.as_raw(),
                Some(vq_callback::<T>),
                name.as_ptr().cast(),
            )
        })?;
        Ok(VirtQueue(NonNull::new(vq).ok_or(EINVAL)?))
    }
}

/// Callback for completed buffers on a virtqueue owned by driver `T`.
///
/// # Safety
///
/// Called by the virtio core with a valid virtqueue whose device is bound to `T`.
unsafe extern "C" fn vq_callback<T: Driver>(vq: *mut bindings::virtqueue) {
    // SAFETY: The virtio core passes a valid virtqueue whose `vdev` is valid.
    let priv_ = unsafe { (*(*vq).vdev).priv_ };
    if priv_.is_null() {
        // Probe has not finished publishing driver data; nothing can be pending yet.
        return;
    }
    // SAFETY: `priv_` was set from `T::Data::into_foreign` after a successful probe and is only
    // reclaimed after the virtqueue is deleted in `remove_callback`, so it is valid here.
    let data = unsafe { <T::Data as ForeignOwnable>::borrow(priv_.cast()) };
    T::vq_done(data);
}

/// A virtqueue.
///
/// # Invariants
///
/// The pointer refers to a live virtqueue until the owning device's queues are deleted.
/// Callers must serialise `add_sgs`, `kick` and `get_buf` on one queue.
pub struct VirtQueue(NonNull<bindings::virtqueue>);

// SAFETY: Virtqueue operations may be invoked from any thread provided callers serialise them,
// which the methods' contracts require.
unsafe impl Send for VirtQueue {}
// SAFETY: See `Send`; shared references only expose operations whose serialisation is the
// caller's responsibility, as documented.
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Exposes buffers to the device: `out` readable segments followed by `in_` writable ones.
    ///
    /// # Safety
    ///
    /// - The queue must still be live and the caller must serialise queue operations.
    /// - Every buffer must be physically contiguous kernel memory (e.g. `kmalloc`) and stay
    ///   valid and otherwise untouched until [`VirtQueue::get_buf`] returns `token`.
    pub unsafe fn add_buf(
        &self,
        out: &[u8],
        in_: &mut [u8],
        token: NonNull<c_void>,
    ) -> Result {
        let mut sg_out = core::mem::MaybeUninit::<bindings::scatterlist>::uninit();
        let mut sg_in = core::mem::MaybeUninit::<bindings::scatterlist>::uninit();
        let out_len = u32::try_from(out.len()).map_err(|_| EINVAL)?;
        let in_len = u32::try_from(in_.len()).map_err(|_| EINVAL)?;
        // SAFETY: The scatterlists are writable; the buffers are contiguous kernel memory per
        // the caller's contract.
        unsafe {
            bindings::sg_init_one(sg_out.as_mut_ptr(), out.as_ptr().cast(), out_len);
            bindings::sg_init_one(sg_in.as_mut_ptr(), in_.as_mut_ptr().cast(), in_len);
        }
        let mut sgs = [sg_out.as_mut_ptr(), sg_in.as_mut_ptr()];
        // SAFETY: The queue is live and serialised per the caller; the scatterlists are
        // initialised and the core copies them into descriptors before returning.
        to_result(unsafe {
            bindings::virtqueue_add_sgs(
                self.0.as_ptr(),
                sgs.as_mut_ptr(),
                1,
                1,
                token.as_ptr(),
                bindings::GFP_KERNEL,
            )
        })
    }

    /// Notifies the device of new buffers. Returns `false` if the device is broken.
    ///
    /// # Safety
    ///
    /// The queue must still be live and the caller must serialise queue operations.
    pub unsafe fn kick(&self) -> bool {
        // SAFETY: Per the caller's contract.
        unsafe { bindings::virtqueue_kick(self.0.as_ptr()) }
    }

    /// Returns the next used buffer's token and the number of bytes the device wrote.
    ///
    /// # Safety
    ///
    /// The queue must still be live and the caller must serialise queue operations.
    pub unsafe fn get_buf(&self) -> Option<(NonNull<c_void>, u32)> {
        let mut len = 0u32;
        // SAFETY: Per the caller's contract; `len` is writable.
        let tok = unsafe { bindings::virtqueue_get_buf(self.0.as_ptr(), &mut len) };
        NonNull::new(tok).map(|t| (t, len))
    }
}

/// A virtio driver.
pub trait Driver: Send + Sync + Sized + 'static {
    /// Per-device data published in `vdev->priv` after a successful probe.
    type Data: ForeignOwnable + Send + Sync;

    /// Driver name.
    const NAME: &'static CStr;

    /// Device ids, terminated by [`DEVICE_ID_END`].
    const ID_TABLE: &'static [DeviceId];

    /// Feature bits the driver supports.
    const FEATURES: &'static [u32];

    /// Binds to `dev`: sets up virtqueues and returns the per-device data. Virtqueues found
    /// here are deleted automatically if probe fails.
    fn probe(dev: &Device) -> Result<Self::Data>;

    /// Called once the data is published in `vdev->priv`, so queue callbacks can reach it.
    /// Typically marks the device ready and makes it visible to users. On error the device is
    /// unbound as if probe had failed.
    fn post_probe(dev: &Device, _data: <Self::Data as ForeignOwnable>::Borrowed<'_>) -> Result {
        dev.ready();
        Ok(())
    }

    /// Unbinds from `dev`. After this returns the registration resets the device, deletes its
    /// virtqueues and drops the data; the driver must stop using its [`VirtQueue`]s here.
    fn remove(dev: &Device, data: <Self::Data as ForeignOwnable>::Borrowed<'_>);

    /// Called from interrupt context when buffers complete on a queue of this device.
    fn vq_done(_data: <Self::Data as ForeignOwnable>::Borrowed<'_>) {}
}

/// A registered virtio driver.
///
/// # Invariants
///
/// `drv` is registered with the virtio core from successful construction until drop.
#[pin_data(PinnedDrop)]
pub struct Registration<T: Driver> {
    #[pin]
    drv: Opaque<bindings::virtio_driver>,
    _t: PhantomData<T>,
}

// SAFETY: Unregistration may happen on any thread.
unsafe impl<T: Driver> Send for Registration<T> {}
// SAFETY: No `&self` methods mutate the registration.
unsafe impl<T: Driver> Sync for Registration<T> {}

unsafe extern "C" fn probe_callback<T: Driver>(vdev: *mut bindings::virtio_device) -> c_int {
    // SAFETY: The virtio core passes a valid device for the duration of probe.
    let dev = unsafe { Device::from_raw(vdev) };
    let res = T::probe(dev).and_then(|data| {
        let p = data.into_foreign();
        // SAFETY: `vdev` is valid; publishing the data lets callbacks and remove find it.
        unsafe { (*vdev).priv_ = p };
        // SAFETY: `p` was just produced by `into_foreign` and is reclaimed only below or in
        // `remove_callback`.
        let r = T::post_probe(dev, unsafe { <T::Data as ForeignOwnable>::borrow(p) });
        if r.is_err() {
            // SAFETY: The device is valid. Reset alone does not synchronise callbacks on every
            // transport; deleting the queues frees their interrupts, so no callback can still be
            // running or start once `priv` is cleared.
            unsafe {
                bindings::virtio_reset_device(vdev);
                bindings::virtio_del_vqs(vdev);
                (*vdev).priv_ = core::ptr::null_mut();
            }
            // SAFETY: Reclaimed exactly once; nothing else can observe `p` any more.
            drop(unsafe { <T::Data as ForeignOwnable>::from_foreign(p) });
        }
        r
    });
    match res {
        Ok(()) => 0,
        Err(e) => {
            // SAFETY: The device is valid; deleting no or already-found queues is allowed.
            unsafe { bindings::virtio_del_vqs(vdev) };
            e.to_errno()
        }
    }
}

unsafe extern "C" fn remove_callback<T: Driver>(vdev: *mut bindings::virtio_device) {
    // SAFETY: The virtio core passes a valid, bound device.
    let dev = unsafe { Device::from_raw(vdev) };
    // SAFETY: `vdev` is valid.
    let priv_ = unsafe { (*vdev).priv_ };
    {
        // SAFETY: `priv_` came from `into_foreign` in a successful probe and is not reclaimed
        // until below.
        let data = unsafe { <T::Data as ForeignOwnable>::borrow(priv_.cast()) };
        T::remove(dev, data);
    }
    // SAFETY: The device is valid; resetting stops further interrupts and buffer use, after
    // which the queues can be deleted.
    unsafe {
        bindings::virtio_reset_device(vdev);
        bindings::virtio_del_vqs(vdev);
        (*vdev).priv_ = core::ptr::null_mut();
    }
    // SAFETY: No callback can observe `priv_` any more; reclaim ownership exactly once.
    drop(unsafe { <T::Data as ForeignOwnable>::from_foreign(priv_.cast()) });
}

impl<T: Driver> Registration<T> {
    /// Registers driver `T`, owned by `module`.
    pub fn new(module: &'static ThisModule) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            drv <- Opaque::try_ffi_init(move |slot: *mut bindings::virtio_driver| {
                // SAFETY: `slot` is valid for writes; an all-zero `virtio_driver` is valid.
                unsafe { slot.write(pin_init::zeroed()) };
                // SAFETY: `slot` was just initialised; the tables are `'static`.
                unsafe {
                    (*slot).driver.name = T::NAME.as_ptr().cast();
                    (*slot).id_table = T::ID_TABLE.as_ptr();
                    (*slot).feature_table = T::FEATURES.as_ptr();
                    (*slot).feature_table_size = T::FEATURES.len() as u32;
                    (*slot).probe = Some(probe_callback::<T>);
                    (*slot).remove = Some(remove_callback::<T>);
                }
                // SAFETY: `slot` is a fully initialised, pinned driver; it stays registered until
                // `drop` unregisters it.
                to_result(unsafe { bindings::__register_virtio_driver(slot, module.as_ptr()) })
            }),
            _t: PhantomData,
        })
    }
}

#[pinned_drop]
impl<T: Driver> PinnedDrop for Registration<T> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: Registered by the type invariant; unregistering removes all bound devices.
        unsafe { bindings::unregister_virtio_driver(self.drv.get()) };
    }
}
