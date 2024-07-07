// Copyright (C) 2019-2021 O.S. Systems Software LTDA
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `compress-tools` crate aims to provide a convenient and easy to use set
//! of methods which builds on top of `libarchive` exposing a small set of it’s
//! functionalities.
//!
//! | Platform | Build Status |
//! | -------- | ------------ |
//! | Linux - x86_64 | [![build status](https://github.com/OSSystems/compress-tools-rs/workflows/CI%20-%20Linux%20-%20x86_64/badge.svg)](https://github.com/OSSystems/compress-tools-rs/actions) |
//! | macOS - x86_64 | [![build status](https://github.com/OSSystems/compress-tools-rs/workflows/CI%20-%20macOS%20-%20x86_64/badge.svg)](https://github.com/OSSystems/compress-tools-rs/actions) |
//! | Windows - x86_64 | [![build status](https://github.com/OSSystems/compress-tools-rs/workflows/CI%20-%20Windows%20-%20x86_64/badge.svg)](https://github.com/OSSystems/compress-tools-rs/actions) |
//!
//! ---
//!
//! # Dependencies
//!
//! You must have `libarchive`, 3.2.0 or newer, properly installed on your
//! system in order to use this. If building on *nix and Windows GNU
//! systems, `pkg-config` is used to locate the `libarchive`; on Windows
//! MSVC, `vcpkg` will be used to locating the `libarchive`.
//!
//! The minimum supported Rust version is 1.59.
//!
//! # Features
//!
//! This crate is capable of extracting:
//!
//! * compressed files
//! * archive files
//! * single file from an archive
//!
//! For example, to extract an archive file it is as simple as:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use compress_tools::*;
//! use std::fs::File;
//! use std::path::Path;
//!
//! let mut source = File::open("tree.tar.gz")?;
//! let dest = Path::new("/tmp/dest");
//!
//! uncompress_archive(&mut source, &dest, Ownership::Preserve)?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "async_support")]
pub mod async_support;
mod carchive;

mod error;
#[cfg(feature = "futures_support")]
pub mod futures_support;
mod iterator;
#[cfg(feature = "tokio_support")]
pub mod tokio_support;
// #[cfg(feature = "writer")]
pub mod writer;

use error::archive_result;
pub use error::{Error, Result};
use io::{Seek, SeekFrom};
pub use iterator::{ArchiveContents, ArchiveIterator, ArchiveIteratorBuilder};
use std::{
    ffi::{CStr, CString},
    io::{self, Read, Write},
    os::raw::{c_int, c_void},
    path::{Component, Path},
    slice,
};

const READER_BUFFER_SIZE: usize = 16384;

/// Determine the ownership behavior when unpacking the archive.
#[derive(Clone, Copy, Debug)]
pub enum Ownership {
    /// Preserve the ownership of the files when uncompressing the archive.
    Preserve,
    /// Ignore the ownership information of the files when uncompressing the
    /// archive.
    Ignore,
}

struct ReaderPipe<'a> {
    reader: &'a mut dyn Read,
    buffer: &'a mut [u8],
}

trait ReadAndSeek: Read + Seek {}
impl<T> ReadAndSeek for T where T: Read + Seek {}

struct SeekableReaderPipe<'a> {
    reader: &'a mut dyn ReadAndSeek,
    buffer: &'a mut [u8],
}

pub type DecodeCallback = fn(&[u8]) -> Result<String>;

pub(crate) fn decode_utf8(bytes: &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(bytes)?.to_owned())
}

/// Get all files in a archive using `source` as a reader.
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use compress_tools::*;
/// use std::fs::File;
///
/// let mut source = File::open("tree.tar")?;
/// let decode_utf8 = |bytes: &[u8]| Ok(std::str::from_utf8(bytes)?.to_owned());
///
/// let file_list = list_archive_files_with_encoding(&mut source, decode_utf8)?;
/// # Ok(())
/// # }
/// ```
pub fn list_archive_files_with_encoding<R>(source: R, decode: DecodeCallback) -> Result<Vec<String>>
where
    R: Read + Seek,
{
    let _utf8_guard = carchive::UTF8LocaleGuard::new();
    run_with_archive(
        Ownership::Ignore,
        source,
        |archive_reader, _, mut entry| unsafe {
            let mut file_list = Vec::new();
            loop {
                match carchive::archive_read_next_header(archive_reader, &mut entry) {
                    carchive::ARCHIVE_EOF => return Ok(file_list),
                    value => archive_result(value, archive_reader)?,
                }

                let _utf8_guard = carchive::WindowsUTF8LocaleGuard::new();
                let cstr = libarchive_entry_pathname(entry)?;
                let file_name = decode(cstr.to_bytes())?;
                file_list.push(file_name);
            }
        },
    )
}

/// Get all files in a archive using `source` as a reader.
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use compress_tools::*;
/// use std::fs::File;
///
/// let mut source = File::open("tree.tar")?;
///
/// let file_list = list_archive_files(&mut source)?;
/// # Ok(())
/// # }
/// ```
pub fn list_archive_files<R>(source: R) -> Result<Vec<String>>
where
    R: Read + Seek,
{
    list_archive_files_with_encoding(source, decode_utf8)
}

/// Uncompress a file using the `source` need as reader and the `target` as a
/// writer.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use compress_tools::*;
/// use std::fs::File;
///
/// let mut source = File::open("file.txt.gz")?;
/// let mut target = Vec::default();
///
/// uncompress_data(&mut source, &mut target)?;
/// # Ok(())
/// # }
/// ```
///
/// Slices can be used if you know the exact length of the uncompressed data.
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use compress_tools::*;
/// use std::fs::File;
///
/// let mut source = File::open("file.txt.gz")?;
/// let mut target = [0 as u8; 313];
///
/// uncompress_data(&mut source, &mut target as &mut [u8])?;
/// # Ok(())
/// # }
/// ```
pub fn uncompress_data<R, W>(source: R, target: W) -> Result<usize>
where
    R: Read,
    W: Write,
{
    let _utf8_guard = carchive::UTF8LocaleGuard::new();
    run_with_unseekable_archive(source, |archive_reader, _, mut entry| unsafe {
        archive_result(
            carchive::archive_read_next_header(archive_reader, &mut entry),
            archive_reader,
        )?;
        libarchive_write_data_block(archive_reader, target)
    })
}

/// Uncompress an archive using `source` as a reader and `dest` as the
/// destination directory.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use compress_tools::*;
/// use std::fs::File;
/// use std::path::Path;
///
/// let mut source = File::open("tree.tar.gz")?;
/// let dest = Path::new("/tmp/dest");
/// let decode_utf8 = |bytes: &[u8]| Ok(std::str::from_utf8(bytes)?.to_owned());
///
/// uncompress_archive_with_encoding(&mut source, &dest, Ownership::Preserve, decode_utf8)?;
/// # Ok(())
/// # }
/// ```
pub fn uncompress_archive_with_encoding<R>(
    source: R,
    dest: &Path,
    ownership: Ownership,
    decode: DecodeCallback,
) -> Result<()>
where
    R: Read + Seek,
{
    let _utf8_guard = carchive::UTF8LocaleGuard::new();
    run_with_archive(
        ownership,
        source,
        |archive_reader, archive_writer, mut entry| unsafe {
            loop {
                match carchive::archive_read_next_header(archive_reader, &mut entry) {
                    carchive::ARCHIVE_EOF => return Ok(()),
                    value => archive_result(value, archive_reader)?,
                }

                let _utf8_guard = carchive::WindowsUTF8LocaleGuard::new();
                let cstr = libarchive_entry_pathname(entry)?;
                let target_path = CString::new(
                    dest.join(sanitize_destination_path(Path::new(&decode(
                        cstr.to_bytes(),
                    )?))?)
                    .to_str()
                    .unwrap(),
                )
                .unwrap();

                carchive::archive_entry_set_pathname(entry, target_path.as_ptr());

                let link_name = carchive::archive_entry_hardlink(entry);
                if !link_name.is_null() {
                    let target_path = CString::new(
                        dest.join(sanitize_destination_path(Path::new(&decode(
                            CStr::from_ptr(link_name).to_bytes(),
                        )?))?)
                        .to_str()
                        .unwrap(),
                    )
                    .unwrap();

                    carchive::archive_entry_set_hardlink(entry, target_path.as_ptr());
                }

                carchive::archive_write_header(archive_writer, entry);
                libarchive_copy_data(archive_reader, archive_writer)?;

                archive_result(
                    carchive::archive_write_finish_entry(archive_writer),
                    archive_writer,
                )?;
            }
        },
    )
}

/// Uncompress an archive using `source` as a reader and `dest` as the
/// destination directory.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use compress_tools::*;
/// use std::fs::File;
/// use std::path::Path;
///
/// let mut source = File::open("tree.tar.gz")?;
/// let dest = Path::new("/tmp/dest");
///
/// uncompress_archive(&mut source, &dest, Ownership::Preserve)?;
/// # Ok(())
/// # }
/// ```
pub fn uncompress_archive<R>(source: R, dest: &Path, ownership: Ownership) -> Result<()>
where
    R: Read + Seek,
{
    uncompress_archive_with_encoding(source, dest, ownership, decode_utf8)
}

/// Uncompress a specific file from an archive. The `source` is used as a
/// reader, the `target` as a writer and the `path` is the relative path for
/// the file to be extracted from the archive.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use compress_tools::*;
/// use std::fs::File;
///
/// let mut source = File::open("tree.tar.gz")?;
/// let mut target = Vec::default();
/// let decode_utf8 = |bytes: &[u8]| Ok(std::str::from_utf8(bytes)?.to_owned());
///
/// uncompress_archive_file_with_encoding(&mut source, &mut target, "file/path", decode_utf8)?;
/// # Ok(())
/// # }
/// ```
pub fn uncompress_archive_file_with_encoding<R, W>(
    source: R,
    target: W,
    path: &str,
    decode: DecodeCallback,
) -> Result<usize>
where
    R: Read + Seek,
    W: Write,
{
    let _utf8_guard = carchive::UTF8LocaleGuard::new();
    run_with_archive(
        Ownership::Ignore,
        source,
        |archive_reader, _, mut entry| unsafe {
            loop {
                match carchive::archive_read_next_header(archive_reader, &mut entry) {
                    carchive::ARCHIVE_EOF => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("path {} doesn't exist inside archive", path),
                        )
                        .into())
                    }
                    value => archive_result(value, archive_reader)?,
                }

                let _utf8_guard = carchive::WindowsUTF8LocaleGuard::new();
                let cstr = libarchive_entry_pathname(entry)?;
                let file_name = decode(cstr.to_bytes())?;
                if file_name == path {
                    break;
                }
            }

            libarchive_write_data_block(archive_reader, target)
        },
    )
}

/// Uncompress a specific file from an archive. The `source` is used as a
/// reader, the `target` as a writer and the `path` is the relative path for
/// the file to be extracted from the archive.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use compress_tools::*;
/// use std::fs::File;
///
/// let mut source = File::open("tree.tar.gz")?;
/// let mut target = Vec::default();
///
/// uncompress_archive_file(&mut source, &mut target, "file/path")?;
/// # Ok(())
/// # }
/// ```
pub fn uncompress_archive_file<R, W>(source: R, target: W, path: &str) -> Result<usize>
where
    R: Read + Seek,
    W: Write,
{
    uncompress_archive_file_with_encoding(source, target, path, decode_utf8)
}

fn run_with_archive<F, R, T>(ownership: Ownership, mut reader: R, f: F) -> Result<T>
where
    F: FnOnce(
        *mut carchive::archive,
        *mut carchive::archive,
        *mut carchive::archive_entry,
    ) -> Result<T>,
    R: Read + Seek,
{
    let _utf8_guard = carchive::UTF8LocaleGuard::new();
    unsafe {
        let archive_entry: *mut carchive::archive_entry = std::ptr::null_mut();
        let archive_reader = carchive::archive_read_new();
        let archive_writer = carchive::archive_write_disk_new();

        let res = (|| {
            archive_result(
                carchive::archive_read_support_filter_all(archive_reader),
                archive_reader,
            )?;

            archive_result(
                carchive::archive_read_support_format_raw(archive_reader),
                archive_reader,
            )?;

            archive_result(
                carchive::archive_read_set_seek_callback(
                    archive_reader,
                    Some(libarchive_seek_callback),
                ),
                archive_reader,
            )?;

            let mut writer_flags = carchive::ARCHIVE_EXTRACT_TIME
                | carchive::ARCHIVE_EXTRACT_PERM
                | carchive::ARCHIVE_EXTRACT_ACL
                | carchive::ARCHIVE_EXTRACT_FFLAGS
                | carchive::ARCHIVE_EXTRACT_XATTR;

            if let Ownership::Preserve = ownership {
                writer_flags |= carchive::ARCHIVE_EXTRACT_OWNER;
            };

            archive_result(
                carchive::archive_write_disk_set_options(archive_writer, writer_flags),
                archive_writer,
            )?;
            archive_result(
                carchive::archive_write_disk_set_standard_lookup(archive_writer),
                archive_writer,
            )?;
            archive_result(
                carchive::archive_read_support_format_all(archive_reader),
                archive_reader,
            )?;

            if archive_reader.is_null() || archive_writer.is_null() {
                return Err(Error::NullArchive);
            }

            let mut pipe = SeekableReaderPipe {
                reader: &mut reader,
                buffer: &mut [0; READER_BUFFER_SIZE],
            };

            archive_result(
                carchive::archive_read_open(
                    archive_reader,
                    std::ptr::addr_of_mut!(pipe) as *mut c_void,
                    None,
                    Some(libarchive_seekable_read_callback),
                    None,
                ),
                archive_reader,
            )?;

            f(archive_reader, archive_writer, archive_entry)
        })();

        archive_result(carchive::archive_read_close(archive_reader), archive_reader)?;
        archive_result(carchive::archive_read_free(archive_reader), archive_reader)?;

        archive_result(
            carchive::archive_write_close(archive_writer),
            archive_writer,
        )?;
        archive_result(carchive::archive_write_free(archive_writer), archive_writer)?;

        carchive::archive_entry_free(archive_entry);

        res
    }
}

fn run_with_unseekable_archive<F, R, T>(mut reader: R, f: F) -> Result<T>
where
    F: FnOnce(
        *mut carchive::archive,
        *mut carchive::archive,
        *mut carchive::archive_entry,
    ) -> Result<T>,
    R: Read,
{
    let _utf8_guard = carchive::UTF8LocaleGuard::new();
    unsafe {
        let archive_entry: *mut carchive::archive_entry = std::ptr::null_mut();
        let archive_reader = carchive::archive_read_new();
        let archive_writer = carchive::archive_write_disk_new();

        let res = (|| {
            archive_result(
                carchive::archive_read_support_filter_all(archive_reader),
                archive_reader,
            )?;

            archive_result(
                carchive::archive_read_support_format_raw(archive_reader),
                archive_reader,
            )?;

            if archive_reader.is_null() || archive_writer.is_null() {
                return Err(Error::NullArchive);
            }

            let mut pipe = ReaderPipe {
                reader: &mut reader,
                buffer: &mut [0; READER_BUFFER_SIZE],
            };

            archive_result(
                carchive::archive_read_open(
                    archive_reader,
                    std::ptr::addr_of_mut!(pipe) as *mut c_void,
                    None,
                    Some(libarchive_read_callback),
                    None,
                ),
                archive_reader,
            )?;

            f(archive_reader, archive_writer, archive_entry)
        })();

        archive_result(carchive::archive_read_close(archive_reader), archive_reader)?;
        archive_result(carchive::archive_read_free(archive_reader), archive_reader)?;

        archive_result(
            carchive::archive_write_close(archive_writer),
            archive_writer,
        )?;
        archive_result(carchive::archive_write_free(archive_writer), archive_writer)?;

        carchive::archive_entry_free(archive_entry);

        res
    }
}

// This ensures we're not affected by the zip-slip vulnerability. In summary, it
// uses relative destination paths to unpack files in unexpected places. This
// also handles absolute paths, where the leading '/' will be stripped, matching
// behaviour from gnu tar and bsdtar.
//
// More details can be found at: http://snyk.io/research/zip-slip-vulnerability
fn sanitize_destination_path(dest: &Path) -> Result<&Path> {
    let dest = dest.strip_prefix("/").unwrap_or(dest);

    dest.components()
        .find(|c| c == &Component::ParentDir)
        .map_or(Ok(dest), |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cannot use relative destination directory",
            )
            .into())
        })
}

fn libarchive_copy_data(
    archive_reader: *mut carchive::archive,
    archive_writer: *mut carchive::archive,
) -> Result<()> {
    let mut buffer = std::ptr::null();
    let mut offset = 0;
    let mut size = 0;

    unsafe {
        loop {
            match carchive::archive_read_data_block(
                archive_reader,
                &mut buffer,
                &mut size,
                &mut offset,
            ) {
                carchive::ARCHIVE_EOF => return Ok(()),
                value => archive_result(value, archive_reader)?,
            }

            archive_result(
                /* Might depending on the version of libarchive on success
                 * return 0 or the number of bytes written,
                 * see man:archive_write_data(3) */
                match carchive::archive_write_data_block(archive_writer, buffer, size, offset) {
                    x if x >= 0 => 0,
                    x => i32::try_from(x).unwrap(),
                },
                archive_writer,
            )?;
        }
    }
}

fn libarchive_entry_pathname<'a>(entry: *mut carchive::archive_entry) -> Result<&'a CStr> {
    let pathname = unsafe { carchive::archive_entry_pathname(entry) };
    if pathname.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive entry has unreadable filename.".to_string(),
        )
        .into());
    }

    Ok(unsafe { CStr::from_ptr(pathname) })
}

unsafe fn libarchive_write_data_block<W>(
    archive_reader: *mut carchive::archive,
    mut target: W,
) -> Result<usize>
where
    W: Write,
{
    let mut buffer = std::ptr::null();
    let mut offset = 0;
    let mut size = 0;
    let mut written = 0;

    loop {
        match carchive::archive_read_data_block(archive_reader, &mut buffer, &mut size, &mut offset)
        {
            carchive::ARCHIVE_EOF => return Ok(written),
            value => archive_result(value, archive_reader)?,
        }

        let content = slice::from_raw_parts(buffer as *const u8, size);
        target.write_all(content)?;
        written += size;
    }
}

unsafe extern "C" fn libarchive_seek_callback(
    _: *mut carchive::archive,
    client_data: *mut c_void,
    offset: carchive::la_int64_t,
    whence: c_int,
) -> i64 {
    let pipe = (client_data as *mut SeekableReaderPipe).as_mut().unwrap();
    let whence = match whence {
        0 => SeekFrom::Start(offset as u64),
        1 => SeekFrom::Current(offset),
        2 => SeekFrom::End(offset),
        _ => return -1,
    };

    match pipe.reader.seek(whence) {
        Ok(offset) => offset as i64,
        Err(_) => -1,
    }
}

unsafe extern "C" fn libarchive_seekable_read_callback(
    archive: *mut carchive::archive,
    client_data: *mut c_void,
    buffer: *mut *const c_void,
) -> carchive::la_ssize_t {
    let pipe = (client_data as *mut SeekableReaderPipe).as_mut().unwrap();

    *buffer = pipe.buffer.as_ptr() as *const c_void;

    match pipe.reader.read(pipe.buffer) {
        Ok(size) => size as carchive::la_ssize_t,
        Err(e) => {
            let description = CString::new(e.to_string()).unwrap();

            carchive::archive_set_error(
                archive,
                e.raw_os_error().unwrap_or(0),
                description.as_ptr(),
            );

            -1
        }
    }
}

unsafe extern "C" fn libarchive_read_callback(
    archive: *mut carchive::archive,
    client_data: *mut c_void,
    buffer: *mut *const c_void,
) -> carchive::la_ssize_t {
    let pipe = (client_data as *mut ReaderPipe).as_mut().unwrap();

    *buffer = pipe.buffer.as_ptr() as *const c_void;

    match pipe.reader.read(pipe.buffer) {
        Ok(size) => size as carchive::la_ssize_t,
        Err(e) => {
            let description = CString::new(e.to_string()).unwrap();

            carchive::archive_set_error(
                archive,
                e.raw_os_error().unwrap_or(0),
                description.as_ptr(),
            );

            -1
        }
    }
}

pub use carchive::AE_IFMT;
pub use carchive::AE_IFREG;
pub use carchive::AE_IFLNK;
pub use carchive::AE_IFSOCK;
pub use carchive::AE_IFCHR;
pub use carchive::AE_IFBLK;
pub use carchive::AE_IFDIR;
pub use carchive::AE_IFIFO;

pub use carchive::ARCHIVE_OK;
pub use carchive::ARCHIVE_WARN;
pub use carchive::ARCHIVE_FATAL;
pub use carchive::ARCHIVE_FAILED;


pub use  carchive::ARCHIVE_FORMAT_CPIO;
pub use  carchive::ARCHIVE_FORMAT_CPIO_POSIX;
pub use  carchive::ARCHIVE_FORMAT_CPIO_BIN_LE;
pub use  carchive::ARCHIVE_FORMAT_CPIO_SVR4_NOCRC;
pub use  carchive::ARCHIVE_FORMAT_CPIO_PWB;

pub use  carchive::ARCHIVE_FORMAT_SHAR;
pub use  carchive::ARCHIVE_FORMAT_SHAR_DUMP;

pub use  carchive::ARCHIVE_FORMAT_TAR;
pub use  carchive::ARCHIVE_FORMAT_TAR_USTAR;
pub use  carchive::ARCHIVE_FORMAT_TAR_PAX_INTERCHANGE;
pub use  carchive::ARCHIVE_FORMAT_TAR_PAX_RESTRICTED;
pub use  carchive::ARCHIVE_FORMAT_TAR_GNUTAR;

pub use  carchive::ARCHIVE_FORMAT_ISO9660;
pub use  carchive::ARCHIVE_FORMAT_ZIP;
pub use  carchive::ARCHIVE_FORMAT_EMPTY;

pub use  carchive::ARCHIVE_FORMAT_MTREE;
pub use  carchive::ARCHIVE_FORMAT_RAW;
pub use  carchive::ARCHIVE_FORMAT_XAR;
pub use  carchive::ARCHIVE_FORMAT_CAB;
pub use  carchive::ARCHIVE_FORMAT_RAR;
pub use  carchive::ARCHIVE_FORMAT_7ZIP;
pub use  carchive::ARCHIVE_FORMAT_WARC;

pub use  carchive::ARCHIVE_FILTER_NONE;
pub use  carchive::ARCHIVE_FILTER_GZIP;
pub use  carchive::ARCHIVE_FILTER_BZIP2;
pub use  carchive::ARCHIVE_FILTER_COMPRESS;
pub use  carchive::ARCHIVE_FILTER_PROGRAM;
pub use  carchive::ARCHIVE_FILTER_LZMA;
pub use  carchive::ARCHIVE_FILTER_XZ;
pub use  carchive::ARCHIVE_FILTER_UU;
pub use  carchive::ARCHIVE_FILTER_RPM;
pub use  carchive::ARCHIVE_FILTER_LZIP;
pub use  carchive::ARCHIVE_FILTER_LRZIP;
pub use  carchive::ARCHIVE_FILTER_LZOP;
pub use  carchive::ARCHIVE_FILTER_GRZIP;
pub use  carchive::ARCHIVE_FILTER_LZ4;
pub use  carchive::ARCHIVE_FILTER_ZSTD;
