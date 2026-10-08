// SPDX-License-Identifier: GPL-2.0

//! r9fs: a read-only 9P2000.L file system over virtio, written in Rust.
//!
//! Mount with `mount -t r9fs <tag> <dir> [-o aname=..,uname=..,uid=..,msize=..]`.
//! Every lookup, open and directory read goes to the server; nothing is cached.

mod client;
mod proto;
mod transport;

use client::{Options, Session};
use kernel::{
    fs::{
        self, inode::Either, DirEmitter, FileSystem, INode, INodeParams, INodeType, MountParams,
        NewSuperBlock, Stat, SuperBlock, Timespec,
    },
    iov::IovIterDest,
    prelude::*,
    sync::aref::ARef,
    virtio,
};
use proto::{Attr, Dec, Dirent};

module! {
    type: R9fsModule,
    name: "r9fs",
    authors: ["v9fs"],
    description: "Rust 9P2000.L file system over virtio (read-only)",
    license: "GPL",
    alias: ["fs-r9fs"],
}

const V9FS_MAGIC: u64 = 0x0102_1997;
const DEFAULT_MSIZE: u32 = 128 * 1024;
const MAX_MSIZE: u32 = 1024 * 1024;

#[pin_data]
struct R9fsModule {
    #[pin]
    fs: fs::Registration<R9fs>,
    #[pin]
    virtio: virtio::Registration<transport::Driver>,
}

impl kernel::InPlaceModule for R9fsModule {
    fn init(module: &'static ThisModule) -> impl PinInit<Self, Error> {
        // SAFETY: Called once, before the driver that uses the channel list is registered.
        unsafe { transport::CHANNELS.init() };
        try_pin_init!(Self {
            fs <- fs::Registration::new(module),
            virtio <- virtio::Registration::new(module),
        })
    }
}

/// Per-inode data: a fid walked to this file.
struct InodeData {
    fid: u32,
}

/// Per-open-file data: a fid opened with `Tlopen`.
struct OpenFile {
    fid: u32,
    iounit: u32,
}

struct R9fs;

fn parse_u32(v: Option<&[u8]>) -> Result<u32> {
    core::str::from_utf8(v.ok_or(EINVAL)?)
        .map_err(|_| EINVAL)?
        .parse()
        .map_err(|_| EINVAL)
}

/// Converts a Linux `new_encode_dev` value to a kernel `dev_t`.
fn decode_dev(rdev: u64) -> u32 {
    let major = ((rdev & 0xfff00) >> 8) as u32;
    let minor = ((rdev & 0xff) | ((rdev >> 12) & 0xfff00)) as u32;
    (major << 20) | minor
}

fn ts((sec, nsec): (u64, u64)) -> Timespec {
    Timespec {
        sec: sec as i64,
        nsec: nsec.min(999_999_999) as u32,
    }
}

fn inode_type(attr: &Attr) -> Result<INodeType> {
    Ok(match attr.mode & 0o170000 {
        0o040000 => INodeType::Dir,
        0o100000 => INodeType::Reg,
        0o120000 => INodeType::Lnk,
        0o020000 => INodeType::Chr(decode_dev(attr.rdev)),
        0o060000 => INodeType::Blk(decode_dev(attr.rdev)),
        0o010000 => INodeType::Fifo,
        0o140000 => INodeType::Sock,
        _ => return Err(EIO),
    })
}

/// Returns the inode for `fid`, consuming `fid`: it becomes the inode's fid if the inode is new
/// and is clunked otherwise.
fn make_inode(sb: &SuperBlock<R9fs>, fid: u32) -> Result<ARef<INode<R9fs>>> {
    let session = sb.data();
    let attr = match session.getattr(fid) {
        Ok(a) => a,
        Err(e) => {
            session.clunk(fid);
            return Err(e);
        }
    };
    let typ = match inode_type(&attr) {
        Ok(t) => t,
        Err(e) => {
            session.clunk(fid);
            return Err(e);
        }
    };
    match sb.get_or_create_inode(attr.qid.path) {
        Ok(Either::Existing(inode)) => {
            session.clunk(fid);
            Ok(inode)
        }
        Ok(Either::New(new)) => new.init(INodeParams {
            typ,
            mode: (attr.mode & 0o7777) as u16,
            size: attr.size.min(i64::MAX as u64) as i64,
            blocks: attr.blocks,
            nlink: attr.nlink.min(u32::MAX.into()) as u32,
            uid: attr.uid,
            gid: attr.gid,
            atime: ts(attr.atime),
            mtime: ts(attr.mtime),
            ctime: ts(attr.ctime),
            value: InodeData { fid },
        }),
        Err(e) => {
            session.clunk(fid);
            Err(e)
        }
    }
}

impl FileSystem for R9fs {
    const NAME: &'static CStr = c"r9fs";
    type Data = KBox<Session>;
    type INodeData = InodeData;
    type FileData = KBox<OpenFile>;

    fn fill_super(sb: &mut NewSuperBlock<'_, Self>, params: &MountParams) -> Result<KBox<Session>> {
        let mut opts = Options {
            tag: params.source().ok_or(EINVAL)?,
            msize: DEFAULT_MSIZE,
            uname: b"root",
            aname: b"",
            uid: 0,
        };
        for key in params.keys() {
            let val = params.get(key).flatten();
            match key {
                b"msize" => opts.msize = parse_u32(val)?.clamp(4096, MAX_MSIZE),
                b"uname" => opts.uname = val.ok_or(EINVAL)?,
                b"aname" => opts.aname = val.ok_or(EINVAL)?,
                b"uid" => opts.uid = parse_u32(val)?,
                b"trans" if val == Some(b"virtio") => {}
                b"version" if val == Some(b"9p2000.L") => {}
                _ => {
                    pr_err!("unsupported mount option\n");
                    return Err(EINVAL);
                }
            }
        }
        sb.set_magic(V9FS_MAGIC)
            .set_blocksize_bits(12)
            .set_read_only();
        Ok(KBox::new(Session::connect(&opts)?, GFP_KERNEL)?)
    }

    fn init_root(sb: &SuperBlock<Self>) -> Result<ARef<INode<Self>>> {
        let session = sb.data();
        let fid = session.walk(session.root_fid(), None)?;
        make_inode(sb, fid)
    }

    fn lookup(parent: &INode<Self>, name: &[u8]) -> Result<Option<ARef<INode<Self>>>> {
        let sb = parent.super_block();
        match sb.data().walk(parent.data().fid, Some(name)) {
            Ok(fid) => make_inode(sb, fid).map(Some),
            Err(e) if e == ENOENT => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn open(inode: &INode<Self>, _flags: u32) -> Result<KBox<OpenFile>> {
        let session = inode.super_block().data();
        let fid = session.walk(inode.data().fid, None)?;
        // Read-only mount: always open for reading (`O_RDONLY`).
        match session.lopen(fid, 0) {
            Ok((_, iounit)) => Ok(KBox::new(OpenFile { fid, iounit }, GFP_KERNEL)?),
            Err(e) => {
                session.clunk(fid);
                Err(e)
            }
        }
    }

    fn release(inode: &INode<Self>, file: KBox<OpenFile>) {
        inode.super_block().data().clunk(file.fid);
    }

    fn read(
        inode: &INode<Self>,
        file: &OpenFile,
        mut pos: i64,
        buf: &mut IovIterDest<'_>,
    ) -> Result<usize> {
        let session = inode.super_block().data();
        let mut chunk = session.max_io();
        if file.iounit != 0 {
            chunk = chunk.min(file.iounit);
        }
        let want = buf.len().min(chunk as usize);
        if want == 0 {
            return Ok(0);
        }
        let mut bounce = KVec::from_elem(0u8, want, GFP_KERNEL)?;
        let mut total = 0usize;
        while !buf.is_empty() {
            let len = buf.len().min(want);
            let off = u64::try_from(pos).map_err(|_| EINVAL)?;
            let n = match session.read(file.fid, off, &mut bounce[..len]) {
                Ok(n) => n,
                Err(e) if total == 0 => return Err(e),
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            let copied = buf.copy_to_iter(&bounce[..n]);
            total += copied;
            pos += copied as i64;
            if copied < n {
                if total == 0 {
                    return Err(EFAULT);
                }
                break;
            }
            if n < len {
                break;
            }
        }
        Ok(total)
    }

    fn read_dir(inode: &INode<Self>, file: &OpenFile, emitter: &mut DirEmitter) -> Result {
        let session = inode.super_block().data();
        let mut buf = KVec::from_elem(0u8, session.max_io() as usize, GFP_KERNEL)?;
        loop {
            let off = u64::try_from(emitter.pos()).map_err(|_| EINVAL)?;
            let n = session.readdir(file.fid, off, &mut buf)?;
            if n == 0 {
                return Ok(());
            }
            let mut d = Dec::new(&buf[..n]);
            while d.remaining() > 0 {
                let ent = Dirent::decode(&mut d)?;
                if !emitter.emit(ent.name, ent.qid.path, ent.typ.into()) {
                    return Ok(());
                }
                emitter.set_pos(i64::try_from(ent.offset).map_err(|_| EIO)?);
            }
            if emitter.pos() as u64 == off {
                // The server returned entries without advancing its cookie.
                return Err(EIO);
            }
        }
    }

    fn get_link(inode: &INode<Self>) -> Result<KVec<u8>> {
        inode.super_block().data().readlink(inode.data().fid)
    }

    fn statfs(sb: &SuperBlock<Self>) -> Result<Stat> {
        let session = sb.data();
        let st = session.statfs(session.root_fid())?;
        Ok(Stat {
            magic: st.typ.into(),
            bsize: st.bsize.into(),
            blocks: st.blocks,
            bfree: st.bfree,
            bavail: st.bavail,
            files: st.files,
            ffree: st.ffree,
            fsid: st.fsid,
            namelen: st.namelen.into(),
        })
    }

    fn evict(sb: &SuperBlock<Self>, data: InodeData) {
        sb.data().clunk(data.fid);
    }
}
