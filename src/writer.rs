use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    ptr::null_mut,
};

use libc::{c_char, c_void};

use crate::{
    carchive::{
        self, archive, archive_entry_free, archive_entry_new, archive_entry_set_atime, archive_entry_set_ctime, archive_entry_set_mode, archive_entry_set_mtime, archive_entry_set_pathname, archive_entry_set_perm, archive_entry_set_size, archive_write_data, archive_write_free, archive_write_header, AE_IFREG, ARCHIVE_OK
    },
    error::archive_result,
    Error, Result,
};
use std::os::raw::c_int;

const BUFFER_SIZE: usize = 16384;

pub struct ArchiveWriter<R: Write> {
    archive_writer: *mut archive,
    _fileref: Box<FileWriter<R>>,
}

struct FileWriter<R: Write> {
    obj: R,
}

// fn localfile_read_callback(_file_obj: *mut c_void) -> Result<()> {
//     Ok(())
// }
//

unsafe extern "C" fn archivewriter_opener<R: Write>(
    _archive: *mut carchive::archive,
    _client_data: *mut c_void,
) -> c_int {
    ARCHIVE_OK
}

unsafe extern "C" fn archivewriter_writer<R: Write>(
    _archive: *mut carchive::archive,
    client_data: *mut c_void,
    _buffer: *const c_void,
    size: usize,
) -> carchive::la_ssize_t {
    let writer = (client_data as *mut FileWriter<R>).as_mut().unwrap();
    let writable = std::slice::from_raw_parts(_buffer as *const u8, size);
    writer.obj.write(writable).unwrap() as isize
}

unsafe extern "C" fn archivewriter_freer<R: Write>(
    _archive: *mut carchive::archive,
    _client_data: *mut c_void,
) -> c_int {
    ARCHIVE_OK
}

impl<R: Write> ArchiveWriter<R> {
    pub fn new(dest: R, format: c_int, filter: c_int) -> Result<ArchiveWriter<R>>
    where
        R: Write,
    {
        let mut fref = Box::new(FileWriter { obj: dest });
        unsafe {
            let archive_writer = carchive::archive_write_new();

            if archive_writer.is_null() {
                return Err(Error::NullArchive);
            }

            archive_result(
                carchive::archive_write_add_filter(archive_writer, filter),
                archive_writer,
            )?;

            archive_result(
                carchive::archive_write_set_format(archive_writer, format),
                archive_writer,
            )?;

            archive_result(
                carchive::archive_write_open(
                    archive_writer,
                    std::ptr::addr_of_mut!(*fref) as *mut c_void,
                    Some(archivewriter_opener::<R>),
                    Some(archivewriter_writer::<R>),
                    Some(archivewriter_freer::<R>),
                ),
                archive_writer,
            )?;

            Ok(ArchiveWriter {
                archive_writer,
                _fileref: fref,
            })
        }
    }

    pub fn free(&mut self) -> Result<()> {
        unsafe {
            archive_result(archive_write_free(self.archive_writer), self.archive_writer)?;
        };
        Ok(())
    }

    pub fn add_compression_option(&mut self, name: &str, value: &str) -> Result<()> {
        unsafe {
            archive_result(
                carchive::archive_write_set_filter_option(
                    self.archive_writer,
                    null_mut(),
                    name.as_ptr() as *const c_char,
                    value.as_ptr() as *const c_char,
                ),
                self.archive_writer,
            )?;
        };
        Ok(())
    }

    pub fn add_file(&mut self, localpath: &str, archivepath: &str) -> Result<()> {
        let mut source = File::open(localpath)?;
        let meta = source.metadata()?;
        let size = meta.len();
        let p = CString::new(archivepath.to_string()).expect("no funciona");

        unsafe {
            let mut readed: usize;
            let mut buffer: [u8; BUFFER_SIZE] = [0u8; BUFFER_SIZE];
            let entry = archive_entry_new();

            archive_entry_set_size(entry, size as i64); // quick way to get the size?
                                                        // archive_entry_set_perm(entry, 0o777);
                                                        // archive_entry_set_filetype(entry, AE_IFREG);
            archive_entry_set_mode(entry, AE_IFREG | 0o755);
            archive_entry_set_perm(entry, 0o755);
            archive_entry_set_ctime(entry, meta.ctime(), meta.ctime_nsec());
            archive_entry_set_mtime(entry, meta.mtime(), meta.mtime_nsec());
            archive_entry_set_atime(entry, meta.atime(), meta.atime_nsec());
            archive_entry_set_pathname(entry, p.as_ptr());

            archive_result(
                archive_write_header(self.archive_writer, entry),
                self.archive_writer,
            )?;

            loop {
                readed = source.read(&mut buffer)?;
                if readed == 0 {
                    break;
                }

                println!("Readed: {readed}");
                if archive_write_data(
                    self.archive_writer,
                    buffer.as_ptr() as *const c_void,
                    readed,
                ) != readed as isize
                {
                    return Err(Error::from(self.archive_writer));
                }
            }

            //write file
            archive_entry_free(entry);
        }
        Ok(())
    }
}

impl<R: Write> Drop for ArchiveWriter<R> {
    fn drop(&mut self) {
        drop(self.free());
    }
}
