use std::{
    fs::File,
    io::{Read, Write},
    ptr::null_mut,
};

use libc::{c_char, c_void};

use crate::{
    carchive::{
        self, archive, archive_entry_free, archive_entry_new, archive_entry_set_filetype,
        archive_entry_set_perm, archive_entry_set_size, archive_write_data, archive_write_free,
        archive_write_header, la_ssize_t, AE_IFREG, ARCHIVE_OK,
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

unsafe extern "C" fn archivewriter_write<R: Write>(
    _archive: *mut carchive::archive,
    client_data: *mut c_void,
    _buffer: *const c_void,
    size: usize,
) -> carchive::la_ssize_t {
    let writer = (client_data as *mut FileWriter<R>).as_mut().unwrap();
    let writable = std::slice::from_raw_parts(_buffer as *const u8, size);
    writer.obj.write(writable).unwrap() as isize
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
                carchive::archive_write_set_format(archive_writer, format),
                archive_writer,
            )?;

            archive_result(
                carchive::archive_write_add_filter(archive_writer, filter),
                archive_writer,
            )?;

            archive_result(
                carchive::archive_write_open(
                    archive_writer,
                    std::ptr::addr_of_mut!(*fref) as *mut c_void,
                    Some(archivewriter_opener::<R>),
                    Some(archivewriter_write::<R>),
                    Some(archivewriter_opener::<R>),
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

    pub fn add_file(&mut self, localpath: &str, _archivepath: &str) -> Result<()> {
        let mut source = File::open(localpath)?;
        let size = source.metadata()?.len();

        unsafe {
            let mut readed: usize;
            let mut buffer: [u8; BUFFER_SIZE] = [0u8; BUFFER_SIZE];
            let entry = archive_entry_new();

            archive_entry_set_size(entry, size as i64); // quick way to get the size?
            archive_entry_set_perm(entry, 0o777);
            archive_entry_set_filetype(entry, AE_IFREG);
            archive_write_header(self.archive_writer, entry);

            loop {
                readed = source.read(&mut buffer)?;
                if readed == 0 {
                    break;
                }

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
