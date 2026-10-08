// SPDX-License-Identifier: GPL-2.0

//! Inodes, directory emission, and inode/file operation tables for [`FileSystem`]s.
//!
//! C header: [`include/linux/fs.h`](srctree/include/linux/fs.h)

use super::filesystem::{FileSystem, SuperBlock};
use crate::{
    bindings,
    error::Result,
    iov::IovIterDest,
    prelude::*,
    sync::aref::{ARef, AlwaysRefCounted},
    types::{ForeignOwnable, Opaque},
};
use core::{cell::UnsafeCell, marker::PhantomData, mem::offset_of, ptr::NonNull};

/// The type of an inode and its type-specific attributes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum INodeType {
    /// Directory.
    Dir,
    /// Regular file.
    Reg,
    /// Symbolic link.
    Lnk,
    /// Character device with the given `dev_t`.
    Chr(u32),
    /// Block device with the given `dev_t`.
    Blk(u32),
    /// Named pipe.
    Fifo,
    /// Unix domain socket.
    Sock,
}

impl INodeType {
    fn mode_bits(self) -> u16 {
        (match self {
            Self::Dir => bindings::S_IFDIR,
            Self::Reg => bindings::S_IFREG,
            Self::Lnk => bindings::S_IFLNK,
            Self::Chr(_) => bindings::S_IFCHR,
            Self::Blk(_) => bindings::S_IFBLK,
            Self::Fifo => bindings::S_IFIFO,
            Self::Sock => bindings::S_IFSOCK,
        }) as u16
    }
}

/// A point in time, in seconds and nanoseconds since the epoch.
#[derive(Clone, Copy, Default)]
pub struct Timespec {
    /// Seconds.
    pub sec: i64,
    /// Nanoseconds.
    pub nsec: u32,
}

/// Attributes used to initialise a new inode.
pub struct INodeParams<D> {
    /// Inode type.
    pub typ: INodeType,
    /// Permission and set-id/sticky bits (`0o7777`).
    pub mode: u16,
    /// Size in bytes.
    pub size: i64,
    /// Number of 512-byte blocks.
    pub blocks: u64,
    /// Link count.
    pub nlink: u32,
    /// Owner, in the initial user namespace.
    pub uid: u32,
    /// Group, in the initial user namespace.
    pub gid: u32,
    /// Last access time.
    pub atime: Timespec,
    /// Last modification time.
    pub mtime: Timespec,
    /// Last status change time.
    pub ctime: Timespec,
    /// File-system-specific data.
    pub value: D,
}

#[repr(C)]
struct INodeWithData<D> {
    data: UnsafeCell<Option<D>>,
    inode: Opaque<bindings::inode>,
}

/// An inode of file system `T`.
///
/// # Invariants
///
/// The wrapped inode is valid, belongs to a superblock of type `T`, is embedded in an
/// `INodeWithData<T::INodeData>`, and its data is `Some` once handed out by reference.
#[repr(transparent)]
pub struct INode<T: FileSystem>(Opaque<bindings::inode>, PhantomData<T>);

// SAFETY: Inodes are reference counted with `ihold`/`iput` and may be used from any thread.
unsafe impl<T: FileSystem> Send for INode<T> {}
// SAFETY: Shared access only reads immutable-after-init fields or uses the VFS's own locking.
unsafe impl<T: FileSystem> Sync for INode<T> {}

// SAFETY: `ihold`/`iput` keep the inode alive; all `INode`s are reference counted by the VFS.
unsafe impl<T: FileSystem> AlwaysRefCounted for INode<T> {
    fn inc_ref(&self) {
        // SAFETY: The inode is valid and already referenced by `self`.
        unsafe { bindings::ihold(self.as_raw()) };
    }

    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: The caller owns a reference being released.
        unsafe { bindings::iput(obj.as_ptr().cast()) };
    }
}

impl<T: FileSystem> INode<T> {
    /// # Safety
    ///
    /// `ptr` must satisfy the type invariants and outlive `'a`.
    unsafe fn from_raw<'a>(ptr: *mut bindings::inode) -> &'a Self {
        // SAFETY: `repr(transparent)`; validity per the caller.
        unsafe { &*ptr.cast() }
    }

    /// Returns the raw `struct inode` pointer.
    pub fn as_raw(&self) -> *mut bindings::inode {
        self.0.get()
    }

    /// Returns the inode number.
    pub fn ino(&self) -> u64 {
        // SAFETY: `i_ino` is immutable after initialisation.
        unsafe { (*self.as_raw()).i_ino }
    }

    /// Returns the superblock this inode belongs to.
    pub fn super_block(&self) -> &SuperBlock<T> {
        // SAFETY: An initialised inode keeps its live, initialised superblock alive.
        unsafe { SuperBlock::from_raw((*self.as_raw()).i_sb) }
    }

    /// Returns the file-system-specific data.
    pub fn data(&self) -> &T::INodeData {
        let outer = container_of_inode::<T>(self.as_raw());
        // SAFETY: By the type invariant the data is `Some` and is not mutated until eviction,
        // which cannot happen while `self` is borrowed.
        unsafe { (*(*outer).data.get()).as_ref().unwrap_unchecked() }
    }
}

fn container_of_inode<T: FileSystem>(
    inode: *mut bindings::inode,
) -> *mut INodeWithData<T::INodeData> {
    let off = offset_of!(INodeWithData<T::INodeData>, inode);
    inode.cast::<u8>().wrapping_sub(off).cast()
}

/// Result of [`SuperBlock::get_or_create_inode`].
pub enum Either<T: FileSystem> {
    /// An existing, initialised inode.
    Existing(ARef<INode<T>>),
    /// A new, locked inode that must be initialised with [`NewINode::init`].
    New(NewINode<T>),
}

pub(crate) fn get_or_create<T: FileSystem>(sb: &SuperBlock<T>, ino: u64) -> Result<Either<T>> {
    // SAFETY: The superblock is valid.
    let inode = unsafe { bindings::iget_locked(sb.as_raw(), ino) };
    let inode = NonNull::new(inode).ok_or(ENOMEM)?;
    let outer = container_of_inode::<T>(inode.as_ptr());
    // SAFETY: `iget_locked` returns either an initialised inode or a new `I_NEW` one that only
    // this thread can touch; our data is `None` exactly in the latter case.
    let is_new = unsafe { (*(*outer).data.get()).is_none() };
    if is_new {
        Ok(Either::New(NewINode(inode, PhantomData)))
    } else {
        // SAFETY: `iget_locked` returned a reference we now own.
        Ok(Either::Existing(unsafe { ARef::from_raw(inode.cast()) }))
    }
}

/// A new, locked (`I_NEW`) inode. Dropping it without [`NewINode::init`] fails the inode.
pub struct NewINode<T: FileSystem>(NonNull<bindings::inode>, PhantomData<T>);

impl<T: FileSystem> NewINode<T> {
    /// Initialises the inode, unlocks it and returns a reference to it.
    pub fn init(self, params: INodeParams<T::INodeData>) -> Result<ARef<INode<T>>> {
        let inode = self.0.as_ptr();
        let typ = params.typ;
        let mode = typ.mode_bits() | (params.mode & 0o7777);
        // SAFETY: The inode is `I_NEW`, so this thread has exclusive access to its fields.
        unsafe {
            (*inode).i_mode = mode;
            (*inode).i_uid = bindings::make_kuid_init_ns(params.uid);
            (*inode).i_gid = bindings::make_kgid_init_ns(params.gid);
            bindings::set_nlink(inode, params.nlink);
            bindings::i_size_write(inode, params.size);
            (*inode).i_blocks = params.blocks;
            (*inode).i_atime_sec = params.atime.sec;
            (*inode).i_atime_nsec = params.atime.nsec;
            (*inode).i_mtime_sec = params.mtime.sec;
            (*inode).i_mtime_nsec = params.mtime.nsec;
            (*inode).i_ctime_sec = params.ctime.sec;
            (*inode).i_ctime_nsec = params.ctime.nsec;
            match typ {
                INodeType::Dir => {
                    (*inode).i_op = &Tables::<T>::DIR_IOPS;
                    (*inode).__bindgen_anon_3.i_fop = &Tables::<T>::DIR_FOPS;
                }
                INodeType::Reg => {
                    (*inode).i_op = &Tables::<T>::FILE_IOPS;
                    (*inode).__bindgen_anon_3.i_fop = &Tables::<T>::FILE_FOPS;
                }
                INodeType::Lnk => {
                    (*inode).i_op = &Tables::<T>::LINK_IOPS;
                }
                INodeType::Chr(dev) | INodeType::Blk(dev) => {
                    (*inode).i_op = &Tables::<T>::FILE_IOPS;
                    bindings::init_special_inode(inode, mode, dev);
                }
                INodeType::Fifo | INodeType::Sock => {
                    (*inode).i_op = &Tables::<T>::FILE_IOPS;
                    bindings::init_special_inode(inode, mode, 0);
                }
            }
            *(*container_of_inode::<T>(inode)).data.get() = Some(params.value);
            bindings::unlock_new_inode(inode);
        }
        let ptr = self.0;
        core::mem::forget(self);
        // SAFETY: We own the reference returned by `iget_locked`; the inode is initialised.
        Ok(unsafe { ARef::from_raw(ptr.cast()) })
    }
}

impl<T: FileSystem> Drop for NewINode<T> {
    fn drop(&mut self) {
        // SAFETY: The inode is `I_NEW` and we own its reference; `iget_failed` drops both.
        unsafe { bindings::iget_failed(self.0.as_ptr()) };
    }
}

/// Emits directory entries into a `readdir`/`getdents` buffer.
pub struct DirEmitter(*mut bindings::dir_context);

impl DirEmitter {
    /// The position at which emission resumes.
    pub fn pos(&self) -> i64 {
        // SAFETY: The context is valid for the duration of `read_dir`.
        unsafe { (*self.0).pos }
    }

    /// Sets the position to resume from after the last emitted entry.
    pub fn set_pos(&mut self, pos: i64) {
        // SAFETY: The context is valid for the duration of `read_dir`.
        unsafe { (*self.0).pos = pos };
    }

    /// Emits one entry; returns `false` when the caller's buffer is full.
    ///
    /// `dtype` is a `DT_*` value.
    pub fn emit(&mut self, name: &[u8], ino: u64, dtype: u32) -> bool {
        let Ok(len) = i32::try_from(name.len()) else {
            return false;
        };
        // SAFETY: The context is valid; `name` is readable for `len` bytes.
        unsafe { bindings::dir_emit(self.0, name.as_ptr().cast(), len, ino, dtype) }
    }
}

pub(crate) unsafe extern "C" fn alloc_inode<T: FileSystem>(
    _sb: *mut bindings::super_block,
) -> *mut bindings::inode {
    let Ok(outer) = KBox::new(
        INodeWithData::<T::INodeData> {
            data: UnsafeCell::new(None),
            inode: Opaque::uninit(),
        },
        GFP_KERNEL,
    ) else {
        return core::ptr::null_mut();
    };
    let outer = KBox::into_raw(outer);
    // SAFETY: `outer` is a valid allocation; `inode_init_once` initialises the embedded inode.
    unsafe {
        let inode = (*outer).inode.get();
        bindings::inode_init_once(inode);
        inode
    }
}

pub(crate) unsafe extern "C" fn free_inode<T: FileSystem>(inode: *mut bindings::inode) {
    // SAFETY: `inode` was allocated by `alloc_inode::<T>`; its data was taken at eviction (or
    // never set), so dropping the box does not sleep. This may run from an RCU callback.
    drop(unsafe { KBox::from_raw(container_of_inode::<T>(inode)) });
}

pub(crate) unsafe extern "C" fn evict_inode<T: FileSystem>(inode: *mut bindings::inode) {
    // SAFETY: The VFS has exclusive access to an inode being evicted.
    let data = unsafe {
        bindings::truncate_inode_pages_final(&mut (*inode).i_data);
        bindings::clear_inode(inode);
        (*(*container_of_inode::<T>(inode)).data.get()).take()
    };
    if let Some(data) = data {
        // SAFETY: The superblock of an inode being evicted is live and initialised.
        let sb = unsafe { SuperBlock::<T>::from_raw((*inode).i_sb) };
        T::evict(sb, data);
    }
}

struct Tables<T>(PhantomData<T>);

impl<T: FileSystem> Tables<T> {
    const DIR_IOPS: bindings::inode_operations = bindings::inode_operations {
        lookup: Some(Self::lookup),
        setattr: Some(Self::setattr),
        ..pin_init::zeroed()
    };

    const FILE_IOPS: bindings::inode_operations = bindings::inode_operations {
        setattr: Some(Self::setattr),
        ..pin_init::zeroed()
    };

    const LINK_IOPS: bindings::inode_operations = bindings::inode_operations {
        get_link: Some(Self::get_link),
        setattr: Some(Self::setattr),
        ..pin_init::zeroed()
    };

    // Without this, `notify_change` falls back to `simple_setattr` and would change only the
    // in-memory inode.
    unsafe extern "C" fn setattr(
        _idmap: *mut bindings::mnt_idmap,
        _dentry: *mut bindings::dentry,
        _attr: *mut bindings::iattr,
    ) -> c_int {
        EROFS.to_errno()
    }

    const DIR_FOPS: bindings::file_operations = bindings::file_operations {
        open: Some(Self::open),
        release: Some(Self::release),
        iterate_shared: Some(Self::iterate_shared),
        read: Some(bindings::generic_read_dir),
        llseek: Some(bindings::generic_file_llseek),
        ..pin_init::zeroed()
    };

    const FILE_FOPS: bindings::file_operations = bindings::file_operations {
        open: Some(Self::open),
        release: Some(Self::release),
        read_iter: Some(Self::read_iter),
        llseek: Some(bindings::generic_file_llseek),
        ..pin_init::zeroed()
    };

    unsafe extern "C" fn lookup(
        dir: *mut bindings::inode,
        dentry: *mut bindings::dentry,
        _flags: c_uint,
    ) -> *mut bindings::dentry {
        // SAFETY: The VFS passes a valid, initialised directory inode of this type.
        let parent = unsafe { INode::<T>::from_raw(dir) };
        // SAFETY: The dentry and its name are valid and stable during lookup.
        let name = unsafe {
            let qstr = &(*dentry).__bindgen_anon_1.d_name;
            core::slice::from_raw_parts(qstr.name, qstr.__bindgen_anon_1.__bindgen_anon_1.len as usize)
        };
        let inode = match T::lookup(parent, name) {
            // An inode of another superblock could outlive its `s_fs_info`.
            Ok(Some(i)) if !core::ptr::eq(i.super_block(), parent.super_block()) => {
                return EIO.to_ptr()
            }
            Ok(Some(i)) => ARef::into_raw(i).as_ptr().cast(),
            Ok(None) => core::ptr::null_mut(),
            Err(e) => return e.to_ptr(),
        };
        // SAFETY: `d_splice_alias` consumes the inode reference (if any).
        unsafe { bindings::d_splice_alias(inode, dentry) }
    }

    unsafe extern "C" fn get_link(
        dentry: *mut bindings::dentry,
        inode: *mut bindings::inode,
        done: *mut bindings::delayed_call,
    ) -> *const c_char {
        if dentry.is_null() {
            // RCU path walk: fetching the target may sleep.
            return ECHILD.to_ptr();
        }
        // SAFETY: The VFS passes a valid, initialised symlink inode of this type.
        let inode = unsafe { INode::<T>::from_raw(inode) };
        let mut target = match T::get_link(inode) {
            Ok(t) => t,
            Err(e) => return e.to_ptr(),
        };
        if target.contains(&0) {
            return EIO.to_ptr();
        }
        if let Err(e) = target.push(0, GFP_KERNEL) {
            return Error::from(e).to_ptr();
        }
        let (ptr, _, _) = target.into_raw_parts();
        // SAFETY: `ptr` is a `kmalloc` allocation released by `kfree_link` when the walk ends.
        unsafe { bindings::set_delayed_call(done, Some(bindings::kfree_link), ptr.cast()) };
        ptr.cast()
    }

    unsafe extern "C" fn open(inode: *mut bindings::inode, file: *mut bindings::file) -> c_int {
        // SAFETY: The VFS passes a valid, initialised inode of this type and the file being
        // opened.
        let (inode, flags) = unsafe { (INode::<T>::from_raw(inode), (*file).f_flags) };
        match T::open(inode, flags) {
            Ok(data) => {
                // SAFETY: The opening file's private data is ours; `release` reclaims it.
                unsafe { (*file).private_data = data.into_foreign() };
                0
            }
            Err(e) => e.to_errno(),
        }
    }

    unsafe extern "C" fn release(inode: *mut bindings::inode, file: *mut bindings::file) -> c_int {
        // SAFETY: `private_data` came from `into_foreign` in `open`; reclaimed exactly once.
        let (inode, data) = unsafe {
            (
                INode::<T>::from_raw(inode),
                <T::FileData as ForeignOwnable>::from_foreign((*file).private_data),
            )
        };
        T::release(inode, data);
        0
    }

    unsafe extern "C" fn read_iter(
        kiocb: *mut bindings::kiocb,
        iter: *mut bindings::iov_iter,
    ) -> isize {
        // SAFETY: The VFS passes a valid kiocb for an open file of this type and a destination
        // iterator.
        let (file, pos, iov) = unsafe {
            (
                (*kiocb).ki_filp,
                (*kiocb).ki_pos,
                IovIterDest::from_raw(iter),
            )
        };
        // SAFETY: The file is open, so its inode and private data are valid.
        let (inode, data) = unsafe {
            (
                INode::<T>::from_raw((*file).f_inode),
                <T::FileData as ForeignOwnable>::borrow((*file).private_data),
            )
        };
        match T::read(inode, data, pos, iov) {
            Ok(n) => {
                // SAFETY: The kiocb is valid and owned by this call.
                unsafe { (*kiocb).ki_pos += n as i64 };
                n as isize
            }
            Err(e) => e.to_errno() as isize,
        }
    }

    unsafe extern "C" fn iterate_shared(
        file: *mut bindings::file,
        ctx: *mut bindings::dir_context,
    ) -> c_int {
        // SAFETY: The file is an open directory of this type.
        let (inode, data) = unsafe {
            (
                INode::<T>::from_raw((*file).f_inode),
                <T::FileData as ForeignOwnable>::borrow((*file).private_data),
            )
        };
        let mut emitter = DirEmitter(ctx);
        match T::read_dir(inode, data, &mut emitter) {
            Ok(()) => 0,
            Err(e) => e.to_errno(),
        }
    }
}
