// SPDX-License-Identifier: GPL-2.0

//! 9P2000.L wire encoding.
//!
//! Messages are `size[4] type[1] tag[2] body`, little endian; strings are `len[2] bytes`.

use kernel::prelude::*;

pub(crate) const VERSION_9P2000_L: &[u8] = b"9P2000.L";
pub(crate) const HDR: usize = 7;
/// Room reserved for the header of an `Rread`/`Rreaddir` reply (`size type tag count`).
pub(crate) const IOHDR: u32 = 11;
pub(crate) const NOTAG: u16 = 0xffff;
pub(crate) const NOFID: u32 = 0xffff_ffff;

pub(crate) const RLERROR: u8 = 7;
pub(crate) const TSTATFS: u8 = 8;
pub(crate) const TLOPEN: u8 = 12;
pub(crate) const TREADLINK: u8 = 22;
pub(crate) const TGETATTR: u8 = 24;
pub(crate) const TREADDIR: u8 = 40;
pub(crate) const TVERSION: u8 = 100;
pub(crate) const TATTACH: u8 = 104;
pub(crate) const TWALK: u8 = 110;
pub(crate) const TREAD: u8 = 116;
pub(crate) const TCLUNK: u8 = 120;

pub(crate) const GETATTR_BASIC: u64 = 0x0000_07ff;

/// A server file identity.
#[derive(Clone, Copy, Default)]
pub(crate) struct Qid {
    pub(crate) path: u64,
}

impl Qid {
    /// Inode number for this file, as `fs/9p` computes it (`QID2INO` on 64-bit): servers may use
    /// path 0, and readdir consumers skip entries whose inode number is 0.
    pub(crate) fn ino(&self) -> u64 {
        self.path.wrapping_add(2)
    }
}

/// Writes a message body into a fixed-size buffer.
pub(crate) struct Enc<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Enc<'a> {
    pub(crate) fn new(buf: &'a mut [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    fn put(&mut self, bytes: &[u8]) -> Result {
        let end = self.pos.checked_add(bytes.len()).ok_or(EINVAL)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(ENOSPC)?
            .copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    pub(crate) fn u16(&mut self, v: u16) -> Result {
        self.put(&v.to_le_bytes())
    }

    pub(crate) fn u32(&mut self, v: u32) -> Result {
        self.put(&v.to_le_bytes())
    }

    pub(crate) fn u64(&mut self, v: u64) -> Result {
        self.put(&v.to_le_bytes())
    }

    pub(crate) fn str(&mut self, s: &[u8]) -> Result {
        self.u16(u16::try_from(s.len()).map_err(|_| ENAMETOOLONG)?)?;
        self.put(s)
    }
}

/// Reads a message body; every short read is reported as `EIO` (a protocol error).
pub(crate) struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(EIO)?;
        let s = self.buf.get(self.pos..end).ok_or(EIO)?;
        self.pos = end;
        Ok(s)
    }

    fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.bytes(N)?);
        Ok(a)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.arr::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.arr()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.arr()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.arr()?))
    }

    pub(crate) fn str(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()?;
        self.bytes(n.into())
    }

    pub(crate) fn qid(&mut self) -> Result<Qid> {
        let _typ = self.u8()?;
        let _version = self.u32()?;
        Ok(Qid { path: self.u64()? })
    }
}

/// `Rgetattr` fields used by the client.
#[derive(Clone, Copy, Default)]
pub(crate) struct Attr {
    pub(crate) qid: Qid,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) nlink: u64,
    pub(crate) rdev: u64,
    pub(crate) size: u64,
    pub(crate) blocks: u64,
    pub(crate) atime: (u64, u64),
    pub(crate) mtime: (u64, u64),
    pub(crate) ctime: (u64, u64),
}

impl Attr {
    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self> {
        let _valid = d.u64()?;
        let qid = d.qid()?;
        let mode = d.u32()?;
        let uid = d.u32()?;
        let gid = d.u32()?;
        let nlink = d.u64()?;
        let rdev = d.u64()?;
        let size = d.u64()?;
        let _blksize = d.u64()?;
        let blocks = d.u64()?;
        let atime = (d.u64()?, d.u64()?);
        let mtime = (d.u64()?, d.u64()?);
        let ctime = (d.u64()?, d.u64()?);
        Ok(Self {
            qid,
            mode,
            uid,
            gid,
            nlink,
            rdev,
            size,
            blocks,
            atime,
            mtime,
            ctime,
        })
    }
}

/// One `Rreaddir` entry.
pub(crate) struct Dirent<'a> {
    pub(crate) qid: Qid,
    pub(crate) offset: u64,
    pub(crate) typ: u8,
    pub(crate) name: &'a [u8],
}

impl<'a> Dirent<'a> {
    pub(crate) fn decode(d: &mut Dec<'a>) -> Result<Self> {
        Ok(Self {
            qid: d.qid()?,
            offset: d.u64()?,
            typ: d.u8()?,
            name: d.str()?,
        })
    }
}

/// `Rstatfs` fields.
#[derive(Clone, Copy, Default)]
pub(crate) struct StatFs {
    pub(crate) typ: u32,
    pub(crate) bsize: u32,
    pub(crate) blocks: u64,
    pub(crate) bfree: u64,
    pub(crate) bavail: u64,
    pub(crate) files: u64,
    pub(crate) ffree: u64,
    pub(crate) fsid: u64,
    pub(crate) namelen: u32,
}

impl StatFs {
    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self> {
        Ok(Self {
            typ: d.u32()?,
            bsize: d.u32()?,
            blocks: d.u64()?,
            bfree: d.u64()?,
            bavail: d.u64()?,
            files: d.u64()?,
            ffree: d.u64()?,
            fsid: d.u64()?,
            namelen: d.u32()?,
        })
    }
}
