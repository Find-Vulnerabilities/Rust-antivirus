//! Windows Named Pipe implementation for inter-process communication
//!
//! This module provides a wrapper around Windows named pipes
//! for sending serialized IPC messages between processes.

use std::io::{self, Read, Write};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::um::fileapi::CreateFileW;
use winapi::um::namedpipeapi::CreateNamedPipeW;
use winapi::um::winnt::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use winapi::um::fileapi::{ReadFile, WriteFile};
use winapi::shared::minwindef::FALSE;
use winapi::ctypes::c_void;

// Windows pipe constants
const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
const PIPE_TYPE_BYTE: u32 = 0x00000000;
const PIPE_WAIT: u32 = 0x00000000;

/// Windows Named Pipe server for listening to client connections
pub struct NamedPipeServer {
    pipe_name: String,
    handle: *mut c_void,
}

/// Windows Named Pipe client for connecting to a pipe
pub struct NamedPipeClient {
    handle: *mut c_void,
}

impl NamedPipeServer {
    /// Create a new named pipe server (listener)
    pub fn new(pipe_name: &str) -> io::Result<Self> {
        log::info!("Creating named pipe: {}", pipe_name);

        // Convert pipe name to wide string
        let wide_name = Self::string_to_wstring(pipe_name);

        unsafe {
            let handle = CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_WAIT,
                1,  // Max instances
                4096,  // Output buffer size
                4096,  // Input buffer size
                0,  // Default timeout
                std::ptr::null_mut(),
            );

            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }

            Ok(NamedPipeServer {
                pipe_name: pipe_name.to_string(),
                handle,
            })
        }
    }

    /// Get the pipe name
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Accept a client connection (blocking)
    pub fn accept(&mut self) -> io::Result<NamedPipeConnection> {
        unsafe {
            let result = winapi::um::namedpipeapi::ConnectNamedPipe(
                self.handle,
                std::ptr::null_mut(),
            );

            if result == FALSE {
                let err = io::Error::last_os_error();
                // ERROR_PIPE_CONNECTED (535) is OK - pipe was already connected
                if err.raw_os_error() != Some(535) {
                    return Err(err);
                }
            }

            Ok(NamedPipeConnection {
                handle: self.handle,
            })
        }
    }

    /// Helper to convert string to wide string (UTF-16)
    fn string_to_wstring(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

impl Drop for NamedPipeServer {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// A connected pipe for communication
pub struct NamedPipeConnection {
    handle: *mut c_void,
}

impl NamedPipeConnection {
    /// Read a message from the pipe
    pub fn read_message(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read = 0u32;
        unsafe {
            let result = ReadFile(
                self.handle,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            );

            if result == FALSE {
                return Err(io::Error::last_os_error());
            }

            Ok(bytes_read as usize)
        }
    }

    /// Write a message to the pipe
    pub fn write_message(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut bytes_written = 0u32;
        unsafe {
            let result = WriteFile(
                self.handle,
                data.as_ptr() as *const c_void,
                data.len() as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            );

            if result == FALSE {
                return Err(io::Error::last_os_error());
            }

            log::debug!("Wrote {} bytes to pipe", bytes_written);
            Ok(bytes_written as usize)
        }
    }
}

impl Read for NamedPipeConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_message(buf)
    }
}

impl Write for NamedPipeConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_message(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl NamedPipeClient {
    /// Connect to an existing named pipe server
    pub fn connect(pipe_name: &str) -> io::Result<Self> {
        log::info!("Connecting to named pipe: {}", pipe_name);

        // Convert pipe name to wide string
        let wide_name = Self::string_to_wstring(pipe_name);

        unsafe {
            let handle = CreateFileW(
                wide_name.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,  // No sharing
                std::ptr::null_mut(),
                3,  // OPEN_EXISTING
                0,  // No special attributes
                std::ptr::null_mut(),
            );

            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }

            Ok(NamedPipeClient { handle })
        }
    }

    /// Read data from the pipe
    pub fn read_message(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read = 0u32;
        unsafe {
            let result = ReadFile(
                self.handle,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            );

            if result == FALSE {
                return Err(io::Error::last_os_error());
            }

            Ok(bytes_read as usize)
        }
    }

    /// Write data to the pipe
    pub fn write_message(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut bytes_written = 0u32;
        unsafe {
            let result = WriteFile(
                self.handle,
                data.as_ptr() as *const c_void,
                data.len() as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            );

            if result == FALSE {
                return Err(io::Error::last_os_error());
            }

            log::debug!("Wrote {} bytes to pipe", bytes_written);
            Ok(bytes_written as usize)
        }
    }

    /// Helper to convert string to wide string (UTF-16)
    fn string_to_wstring(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

impl Read for NamedPipeClient {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_message(buf)
    }
}

impl Write for NamedPipeClient {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_message(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for NamedPipeClient {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipe_server_creation() {
        let server = NamedPipeServer::new(r"\.\pipe\test_pipe");
        assert!(server.is_ok());
    }

    #[test]
    fn test_pipe_client_creation() {
        let client = NamedPipeClient::connect(r"\.\pipe\test_pipe");
        assert!(client.is_ok());
    }
}
