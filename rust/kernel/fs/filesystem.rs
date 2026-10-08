// SPDX-License-Identifier: GPL-2.0

//! File system registration, mount contexts and superblocks.
//!
//! A file system implements [`FileSystem`] and is registered with a pinned [`Registration`].
//! Mounting creates an anonymous (`nodev`) superblock whose private data is
//! [`FileSystem::Data`]; inodes carry [`FileSystem::INodeData`] and open files carry
//! [`FileSystem::FileData`].
//!
//! The abstractions have no write paths, so every superblock is read-only: `SB_RDONLY` is
//! forced at mount time and kept on remount. Remount does not re-parse file system options.
//!
//! Dentries are never cached once unused and inodes are dropped on last reference, so every
//! path walk consults the file system again (the equivalent of `cache=none`).
//!
//! C headers: [`include/linux/fs.h`](srctree/include/linux/fs.h) and
//! [`include/linux/fs_context.h`](srctree/include/linux/fs_context.h).

use super::inode::{self, DirEmitter, INode};
use crate::{
    alloc::KVec,
    bindings,
    error::{to_result, Result},
    iov::IovIterDest,
    prelude::*,
    sync::aref::ARef,
    types::{ForeignOwnable, Opaque},
    ThisModule,
};
use core::{ffi::c_void, marker::PhantomData};

/// File system statistics returned by [`FileSystem::statfs`].
#[derive(Default, Clone, Copy)]
pub struct Stat {
    /// File system magic number.
    pub magic: u64,
    /// Optimal transfer block size.
    pub bsize: u64,
    /// Total data blocks.
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Free blocks available to unprivileged users.
    pub bavail: u64,
    /// Total inodes.
    pub files: u64,
    /// Free inodes.
    pub ffree: u64,
    /// File system id.
    pub fsid: u64,
    /// Maximum file name length.
    pub namelen: u64,
}

/// A file system type.
pub trait FileSystem: Sized + Send + Sync + 'static {
    /// The name used with `mount -t`.
    const NAME: &'static CStr;

    /// Per-superblock data, stored in `s_fs_info`.
    type Data: ForeignOwnable + Send + Sync;

    /// Per-inode data. Dropped (via [`FileSystem::evict`]) when the inode is evicted.
    type INodeData: Send + Sync;

    /// Per-open-file data, stored in `file->private_data`.
    type FileData: ForeignOwnable + Send + Sync;

    /// Initialises a new superblock from mount parameters and returns its data.
    fn fill_super(sb: &mut NewSuperBlock<'_, Self>, params: &MountParams) -> Result<Self::Data>;

    /// Returns the root inode. Called after [`FileSystem::fill_super`] has published the data.
    fn init_root(sb: &SuperBlock<Self>) -> Result<ARef<INode<Self>>>;

    /// Looks up `name` in directory `parent`; `Ok(None)` means it does not exist.
    fn lookup(parent: &INode<Self>, name: &[u8]) -> Result<Option<ARef<INode<Self>>>>;

    /// Opens `inode` (regular file or directory) with the given `f_flags`.
    fn open(inode: &INode<Self>, flags: u32) -> Result<Self::FileData>;

    /// Releases an open file.
    fn release(_inode: &INode<Self>, data: Self::FileData) {
        drop(data);
    }

    /// Reads from a regular file at `pos` into `buf`, returning the number of bytes read.
    fn read(
        inode: &INode<Self>,
        data: <Self::FileData as ForeignOwnable>::Borrowed<'_>,
        pos: i64,
        buf: &mut IovIterDest<'_>,
    ) -> Result<usize>;

    /// Emits directory entries starting at `emitter.pos()`.
    fn read_dir(
        inode: &INode<Self>,
        data: <Self::FileData as ForeignOwnable>::Borrowed<'_>,
        emitter: &mut DirEmitter,
    ) -> Result;

    /// Returns a symbolic link's target (without a trailing NUL).
    fn get_link(inode: &INode<Self>) -> Result<KVec<u8>>;

    /// Returns file system statistics.
    fn statfs(sb: &SuperBlock<Self>) -> Result<Stat>;

    /// Disposes of an evicted inode's data. May sleep.
    fn evict(_sb: &SuperBlock<Self>, data: Self::INodeData) {
        drop(data);
    }
}

/// Mount parameters collected from the mount context.
///
/// Keys and values are stored as given; a key without a value (a flag) has `None`.
pub struct MountParams {
    source: Option<KVec<u8>>,
    params: KVec<(KVec<u8>, Option<KVec<u8>>)>,
}

impl MountParams {
    /// The mount source (device name), if any.
    pub fn source(&self) -> Option<&[u8]> {
        self.source.as_deref()
    }

    /// Returns the last value given for `key`: `None` if absent, `Some(None)` for a flag.
    pub fn get(&self, key: &[u8]) -> Option<Option<&[u8]>> {
        self.params
            .iter()
            .rev()
            .find(|(k, _)| k.as_slice() == key)
            .map(|(_, v)| v.as_deref())
    }

    /// Iterates over all keys in the order given.
    pub fn keys(&self) -> impl Iterator<Item = &[u8]> {
        self.params.iter().map(|(k, _)| k.as_slice())
    }
}

fn copy_bytes(src: &[u8]) -> Result<KVec<u8>> {
    let mut v = KVec::with_capacity(src.len(), GFP_KERNEL)?;
    v.extend_from_slice(src, GFP_KERNEL)?;
    Ok(v)
}

/// A superblock of file system `T`.
///
/// # Invariants
///
/// The wrapped `super_block` is valid and, once handed out as `&SuperBlock<T>`, has `s_fs_info`
/// set from `T::Data::into_foreign`.
#[repr(transparent)]
pub struct SuperBlock<T: FileSystem>(Opaque<bindings::super_block>, PhantomData<T>);

impl<T: FileSystem> SuperBlock<T> {
    /// # Safety
    ///
    /// `ptr` must be a valid superblock of type `T` with `s_fs_info` initialised, outliving `'a`.
    pub(crate) unsafe fn from_raw<'a>(ptr: *mut bindings::super_block) -> &'a Self {
        // SAFETY: `repr(transparent)`; validity per the caller.
        unsafe { &*ptr.cast() }
    }

    /// Returns the raw `struct super_block` pointer.
    pub fn as_raw(&self) -> *mut bindings::super_block {
        self.0.get()
    }

    /// Returns the file system's per-superblock data.
    pub fn data(&self) -> <T::Data as ForeignOwnable>::Borrowed<'_> {
        // SAFETY: By the type invariant `s_fs_info` came from `into_foreign` and is only
        // reclaimed in `kill_sb` after all users of the superblock are gone.
        unsafe { <T::Data as ForeignOwnable>::borrow((*self.as_raw()).s_fs_info) }
    }

    /// Returns the inode numbered `ino`, either already initialised or new and locked.
    pub fn get_or_create_inode(&self, ino: u64) -> Result<inode::Either<T>> {
        inode::get_or_create(self, ino)
    }
}

/// A superblock under construction, passed to [`FileSystem::fill_super`].
pub struct NewSuperBlock<'a, T: FileSystem> {
    sb: *mut bindings::super_block,
    _p: PhantomData<(&'a mut bindings::super_block, T)>,
}

impl<T: FileSystem> NewSuperBlock<'_, T> {
    /// Sets the magic number reported by `statfs` callers that consult `s_magic`.
    pub fn set_magic(&mut self, magic: u64) -> &mut Self {
        // SAFETY: The superblock is exclusively ours during `fill_super`.
        unsafe { (*self.sb).s_magic = magic as _ };
        self
    }

    /// Sets the block size, which must be a power of two.
    pub fn set_blocksize_bits(&mut self, bits: u8) -> &mut Self {
        // SAFETY: The superblock is exclusively ours during `fill_super`.
        unsafe {
            (*self.sb).s_blocksize_bits = bits;
            (*self.sb).s_blocksize = 1 << bits;
        }
        self
    }
}

/// A registered file system type.
///
/// # Invariants
///
/// `fs` is registered from successful construction until drop.
#[pin_data(PinnedDrop)]
pub struct Registration<T: FileSystem> {
    #[pin]
    fs: Opaque<bindings::file_system_type>,
    _t: PhantomData<T>,
}

// SAFETY: Unregistration may happen on any thread.
unsafe impl<T: FileSystem> Send for Registration<T> {}
// SAFETY: No `&self` methods mutate the registration.
unsafe impl<T: FileSystem> Sync for Registration<T> {}

impl<T: FileSystem> Registration<T> {
    /// Registers file system `T`, owned by `module`.
    ///
    /// The registration embeds lockdep class keys, so it must live in static storage (for
    /// example inside the module's pinned state).
    pub fn new(module: &'static ThisModule) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            fs <- Opaque::try_ffi_init(move |slot: *mut bindings::file_system_type| {
                // SAFETY: `slot` is valid for writes; an all-zero `file_system_type` is valid.
                unsafe { slot.write(pin_init::zeroed()) };
                // SAFETY: `slot` was just initialised; the name is `'static`.
                unsafe {
                    (*slot).name = T::NAME.as_ptr().cast();
                    (*slot).owner = module.as_ptr();
                    (*slot).init_fs_context = Some(Tables::<T>::init_fs_context);
                    (*slot).kill_sb = Some(Tables::<T>::kill_sb);
                }
                // SAFETY: `slot` is pinned and fully initialised; `drop` unregisters it.
                to_result(unsafe { bindings::register_filesystem(slot) })
            }),
            _t: PhantomData,
        })
    }
}

#[pinned_drop]
impl<T: FileSystem> PinnedDrop for Registration<T> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: Registered by the type invariant.
        unsafe { bindings::unregister_filesystem(self.fs.get()) };
    }
}

struct Tables<T>(PhantomData<T>);

impl<T: FileSystem> Tables<T> {
    const CONTEXT_OPS: bindings::fs_context_operations = bindings::fs_context_operations {
        free: Some(Self::free),
        parse_param: Some(Self::parse_param),
        get_tree: Some(Self::get_tree),
        reconfigure: Some(Self::reconfigure),
        ..pin_init::zeroed()
    };

    const SUPER_OPS: bindings::super_operations = bindings::super_operations {
        alloc_inode: Some(inode::alloc_inode::<T>),
        free_inode: Some(inode::free_inode::<T>),
        evict_inode: Some(inode::evict_inode::<T>),
        drop_inode: Some(bindings::inode_just_drop),
        statfs: Some(Self::statfs),
        ..pin_init::zeroed()
    };

    const DENTRY_OPS: bindings::dentry_operations = bindings::dentry_operations {
        d_delete: Some(bindings::always_delete_dentry),
        ..pin_init::zeroed()
    };

    unsafe extern "C" fn init_fs_context(fc: *mut bindings::fs_context) -> c_int {
        let params = match KBox::new(
            MountParams {
                source: None,
                params: KVec::new(),
            },
            GFP_KERNEL,
        ) {
            Ok(p) => p,
            Err(e) => return Error::from(e).to_errno(),
        };
        // SAFETY: `fc` is a valid context being initialised; `free` reclaims `fs_private`.
        unsafe {
            (*fc).fs_private = KBox::into_raw(params).cast();
            (*fc).ops = &Self::CONTEXT_OPS;
        }
        0
    }

    unsafe extern "C" fn free(fc: *mut bindings::fs_context) {
        // SAFETY: `fc` is valid; `fs_private` is null or came from `KBox::into_raw`.
        let p = unsafe { (*fc).fs_private };
        if !p.is_null() {
            // SAFETY: See above; this is the only place it is reclaimed.
            drop(unsafe { KBox::from_raw(p.cast::<MountParams>()) });
        }
    }

    unsafe extern "C" fn parse_param(
        fc: *mut bindings::fs_context,
        param: *mut bindings::fs_parameter,
    ) -> c_int {
        let res = (|| -> Result {
            // SAFETY: The VFS passes a valid parameter whose key is a NUL-terminated string.
            let key = unsafe { CStr::from_char_ptr((*param).key) };
            if key.to_bytes() == b"source" {
                // Let the VFS record the source in `fc->source`.
                return Err(Error::from_errno(-(bindings::ENOPARAM as i32)));
            }
            // SAFETY: `param` is valid.
            let value = match unsafe { (*param).type_() } {
                bindings::fs_value_type_fs_value_is_flag => None,
                bindings::fs_value_type_fs_value_is_string => {
                    // SAFETY: For string parameters the union holds a NUL-terminated string.
                    let s = unsafe { CStr::from_char_ptr((*param).__bindgen_anon_1.string) };
                    Some(copy_bytes(s.to_bytes())?)
                }
                _ => return Err(EINVAL),
            };
            // SAFETY: `fs_private` was set in `init_fs_context` and is exclusively accessed
            // during parameter parsing.
            let params = unsafe { &mut *(*fc).fs_private.cast::<MountParams>() };
            params.params.push((copy_bytes(key.to_bytes())?, value), GFP_KERNEL)?;
            Ok(())
        })();
        match res {
            Ok(()) => 0,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn get_tree(fc: *mut bindings::fs_context) -> c_int {
        // SAFETY: `fc` is a valid context for this file system type.
        unsafe { bindings::get_tree_nodev(fc, Some(Self::fill_super)) }
    }

    unsafe extern "C" fn fill_super(
        sb: *mut bindings::super_block,
        fc: *mut bindings::fs_context,
    ) -> c_int {
        let res = (|| -> Result {
            // SAFETY: `fs_private` was set in `init_fs_context`; mounting has exclusive access.
            let params = unsafe { &mut *(*fc).fs_private.cast::<MountParams>() };
            // SAFETY: `fc` is valid.
            let src = unsafe { (*fc).source };
            if !src.is_null() {
                // SAFETY: `fc->source` is a NUL-terminated string owned by the context.
                let s = unsafe { CStr::from_char_ptr(src) };
                params.source = Some(copy_bytes(s.to_bytes())?);
            }

            // SAFETY: The new superblock is exclusively ours until `fill_super` returns.
            unsafe {
                // These abstractions have no write paths, so every mount is read-only.
                (*sb).s_flags |= bindings::SB_RDONLY;
                (*sb).s_op = &Self::SUPER_OPS;
                (*sb).s_maxbytes = i64::MAX;
                (*sb).s_time_gran = 1;
                bindings::set_default_d_op(sb, &Self::DENTRY_OPS);
            }

            let mut new = NewSuperBlock::<T> {
                sb,
                _p: PhantomData,
            };
            let data = T::fill_super(&mut new, params)?;
            // SAFETY: Publishing the data; `kill_sb` reclaims it even if the rest fails.
            unsafe { (*sb).s_fs_info = data.into_foreign() };

            // SAFETY: `s_fs_info` is now initialised for type `T`.
            let sbref = unsafe { SuperBlock::<T>::from_raw(sb) };
            let root = T::init_root(sbref)?;
            if !core::ptr::eq(root.super_block(), sbref) {
                return Err(EIO);
            }
            // SAFETY: `d_make_root` consumes the inode reference, dropping it on failure.
            let dentry = unsafe { bindings::d_make_root(ARef::into_raw(root).as_ptr().cast()) };
            if dentry.is_null() {
                return Err(ENOMEM);
            }
            // SAFETY: The superblock is still exclusively ours.
            unsafe { (*sb).s_root = dentry };
            Ok(())
        })();
        match res {
            Ok(()) => 0,
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn reconfigure(fc: *mut bindings::fs_context) -> c_int {
        // Like erofs and squashfs: keep the superblock read-only instead of failing, so that
        // remounts changing only other flags (legacy `mount(2)` always passes the full
        // `MS_RMT_MASK`) still work.
        // SAFETY: The VFS passes a valid reconfiguration context.
        unsafe { (*fc).sb_flags |= bindings::SB_RDONLY as c_uint };
        0
    }

    unsafe extern "C" fn kill_sb(sb: *mut bindings::super_block) {
        // SAFETY: The VFS passes a superblock of this type being torn down. Inodes are evicted
        // (and may still use `s_fs_info`) inside `kill_anon_super`.
        unsafe { bindings::kill_anon_super(sb) };
        // SAFETY: The superblock memory remains valid until the VFS drops its last reference.
        let p: *mut c_void = unsafe { (*sb).s_fs_info };
        if !p.is_null() {
            // SAFETY: Came from `into_foreign` in `fill_super`; reclaimed exactly once here.
            drop(unsafe { <T::Data as ForeignOwnable>::from_foreign(p) });
        }
    }

    unsafe extern "C" fn statfs(
        dentry: *mut bindings::dentry,
        buf: *mut bindings::kstatfs,
    ) -> c_int {
        // SAFETY: The VFS passes a valid dentry of a live superblock of this type.
        let sb = unsafe { SuperBlock::<T>::from_raw((*dentry).d_sb) };
        match T::statfs(sb) {
            Ok(st) => {
                // SAFETY: `buf` is a valid, writable `kstatfs`.
                unsafe {
                    (*buf).f_type = st.magic as _;
                    (*buf).f_bsize = st.bsize as _;
                    (*buf).f_frsize = st.bsize as _;
                    (*buf).f_blocks = st.blocks;
                    (*buf).f_bfree = st.bfree;
                    (*buf).f_bavail = st.bavail;
                    (*buf).f_files = st.files;
                    (*buf).f_ffree = st.ffree;
                    (*buf).f_fsid.val = [st.fsid as i32, (st.fsid >> 32) as i32];
                    (*buf).f_namelen = st.namelen as _;
                }
                0
            }
            Err(e) => e.to_errno(),
        }
    }
}
