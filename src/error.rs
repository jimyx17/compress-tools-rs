// Copyright (C) 2019-2021 O.S. Systems Software LTDA
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::carchive;
use derive_more::{Display, Error, From};
use std::{borrow::Cow, ffi::CStr, io};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Display, From, Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[display(fmt = "Extraction error: '{}'", _0)]
    Extraction(#[error(not(source))] String),

    Io(io::Error),

    Utf(std::str::Utf8Error),

    #[display(fmt = "Encoding error: '{}'", _0)]
    Encoding(#[error(not(source))] Cow<'static, str>),

    #[cfg(feature = "tokio_support")]
    JoinError(tokio::task::JoinError),

    #[display(fmt = "Error to create the archive struct, is null")]
    NullArchive,

    #[display(fmt = "Archive has been allocated but no filter nor format has been defined")]
    IncompleteInitialization,

    #[display(fmt = "Unknown filter")]
    UnknownFilter,

    #[display(fmt = "Unknown format")]
    UnknownFormat,

    #[display(fmt = "Unknown error")]
    Unknown,
}

pub(crate) fn archive_result(value: i32, archive: *mut carchive::archive) -> Result<()> {
    match value {
        carchive::ARCHIVE_OK | carchive::ARCHIVE_WARN => Ok(()),
        _ => Err(Error::from(archive)),
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
impl From<*mut carchive::archive> for Error {
    fn from(input: *mut carchive::archive) -> Self {
        unsafe {
            let error_string = carchive::archive_error_string(input);
            if !error_string.is_null() {
                return Error::Extraction(
                    CStr::from_ptr(error_string).to_string_lossy().to_string(),
                );
            }

            let errno = carchive::archive_errno(input);
            if errno != 0 {
                return io::Error::from_raw_os_error(errno).into();
            }
        }

        Error::Unknown
    }
}
