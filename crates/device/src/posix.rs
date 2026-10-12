// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! A [`TpmTransport`] for Unix, backed by a TPM character device.

use nix::{
    fcntl,
    poll::{PollFd, PollFlags, poll},
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::fd::{AsFd, AsRawFd},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::{TPM_HEADER_SIZE, TpmDeviceError, TpmTransport, frame_size};

impl From<nix::Error> for TpmDeviceError {
    fn from(err: nix::Error) -> Self {
        Self::Io(std::io::Error::from_raw_os_error(err as i32))
    }
}

/// A [`TpmTransport`] backed by a Linux TPM character device.
pub struct TpmPosixDevice {
    file: File,
    interrupted: Box<dyn Fn() -> bool>,
    timeout: Duration,
}

impl TpmPosixDevice {
    /// Creates a new builder for a `TpmPosixDevice`.
    #[must_use]
    pub fn builder() -> TpmPosixDeviceBuilder {
        TpmPosixDeviceBuilder::default()
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, TpmDeviceError> {
        let fd = self.file.as_fd();
        let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];

        let num_events = match poll(&mut fds, 100u16) {
            Ok(num) => num,
            Err(nix::Error::EINTR) => return Ok(0),
            Err(e) => return Err(e.into()),
        };

        if num_events == 0 {
            return Ok(0);
        }

        let revents = fds[0].revents().unwrap_or(PollFlags::empty());

        if revents.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
            return Err(TpmDeviceError::UnexpectedEof);
        }

        if revents.contains(PollFlags::POLLIN) {
            match self.file.read(buf) {
                Ok(0) => Err(TpmDeviceError::UnexpectedEof),
                Ok(n) => Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(0),
                Err(e) => Err(e.into()),
            }
        } else if revents.contains(PollFlags::POLLHUP) {
            Err(TpmDeviceError::UnexpectedEof)
        } else {
            Ok(0)
        }
    }
}

impl TpmTransport for TpmPosixDevice {
    fn send(&mut self, frame: &[u8]) -> Result<(), TpmDeviceError> {
        self.file.write_all(frame)?;
        self.file.flush()?;
        Ok(())
    }

    fn recv(&mut self, buf: &mut Vec<u8>) -> Result<(), TpmDeviceError> {
        buf.clear();
        let start_time = Instant::now();
        let mut total_size: Option<usize> = None;
        let mut temp_buf = [0u8; 1024];

        loop {
            if (self.interrupted)() {
                return Err(TpmDeviceError::Interrupted);
            }
            if start_time.elapsed() > self.timeout {
                return Err(TpmDeviceError::Timeout);
            }

            let n = self.receive(&mut temp_buf)?;
            if n > 0 {
                buf.extend_from_slice(&temp_buf[..n]);
            }

            if total_size.is_none() && buf.len() >= TPM_HEADER_SIZE {
                total_size = Some(frame_size(buf)?);
            }

            if let Some(size) = total_size {
                if buf.len() == size {
                    break;
                }
                if buf.len() > size {
                    return Err(TpmDeviceError::TrailingData);
                }
            }
        }

        Ok(())
    }
}

/// A builder for constructing a [`TpmPosixDevice`].
pub struct TpmPosixDeviceBuilder {
    path: PathBuf,
    timeout: Duration,
    interrupted: Box<dyn Fn() -> bool>,
}

impl Default for TpmPosixDeviceBuilder {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/dev/tpmrm0"),
            timeout: Duration::from_mins(2),
            interrupted: Box::new(|| false),
        }
    }
}

impl TpmPosixDeviceBuilder {
    /// Sets the device file path.
    #[must_use]
    pub fn with_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.path = path.as_ref().to_path_buf();
        self
    }

    /// Sets the operation timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the interruption check callback.
    #[must_use]
    pub fn with_interrupted<F>(mut self, handler: F) -> Self
    where
        F: Fn() -> bool + 'static,
    {
        self.interrupted = Box::new(handler);
        self
    }

    /// Opens the TPM character device and constructs the [`TpmPosixDevice`].
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::TpmDeviceError::Io) when the device file cannot be
    /// opened or when configuring the file descriptor flags fails.
    pub fn build(self) -> Result<TpmPosixDevice, TpmDeviceError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(TpmDeviceError::Io)?;

        let fd = file.as_raw_fd();
        let flags = fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL)?;
        let mut oflags = fcntl::OFlag::from_bits_truncate(flags);
        oflags.insert(fcntl::OFlag::O_NONBLOCK);
        fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFL(oflags))?;

        Ok(TpmPosixDevice {
            file,
            interrupted: self.interrupted,
            timeout: self.timeout,
        })
    }
}
