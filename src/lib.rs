//! Read memory from another process' address space.
//!
//! This crate provides a trait—[`CopyAddress`](trait.CopyAddress.html),
//! and a helper function—[`copy_address`](fn.copy_address.html) that
//! allow reading memory from another process.
//!
//! Note: you may not always have permission to read memory from another
//! process! This may require `sudo` on some systems, and may fail even with
//! `sudo` on OS X. You are most likely to succeed if you are attempting to
//! read a process that you have spawned yourself.
//!
//! # Examples
//!
//! ```rust,no_run
//! # use std::io;
//! use read_process_memory::*;
//!
//! # fn foo(pid: Pid, address: usize, size: usize) -> io::Result<()> {
//! let handle = try!(pid.try_into_process_handle());
//! let bytes = try!(copy_address(address, size, &handle));
//! # Ok(())
//! # }
//! ```

#[macro_use]
extern crate log;
extern crate libc;

use std::io;

/// A trait that provides a method for reading memory from another process.
pub trait CopyAddress {
    /// Try to copy `buf.len()` bytes from `addr` in the process `self`, placing them in `buf`.
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()>;
}

/// A process ID.
pub use platform::Pid;
/// A handle to a running process. This is not a process ID on all platforms.
pub use platform::ProcessHandle;

/// Attempt to get a process handle for a running process.
///
/// This operation is not guaranteed to succeed. Specifically, on Windows
/// `OpenProcess` may fail, and on OS X `task_for_pid` will generally fail
/// unless run as root, and even then it may fail when called on certain
/// programs.
///
/// This should be dropped in favor of TryInto when that stabilizes:
/// https://github.com/rust-lang/rust/issues/33417
pub trait TryIntoProcessHandle {
    /// Attempt to get a `ProcessHandle` from `self`.
    fn try_into_process_handle(&self) -> io::Result<ProcessHandle>;
}

/// Trivial implementation of `TryIntoProcessHandle`.
///
/// A `ProcessHandle` is always usable.
impl TryIntoProcessHandle for ProcessHandle {
    fn try_into_process_handle(&self) -> io::Result<platform::ProcessHandle> {
        Ok(*self)
    }
}

#[cfg(target_os="linux")]
mod platform {
    use libc::{pid_t, c_void, iovec, process_vm_readv};
    use std::io;
    use std::process::Child;

    use super::{CopyAddress, TryIntoProcessHandle};

    /// On Linux a `Pid` is just a `libc::pid_t`.
    pub type Pid = pid_t;
    /// On Linux a `ProcessHandle` is just a `libc::pid_t`.
    pub type ProcessHandle = pid_t;

    /// A `process::Child` always has a pid, which is all we need on Linux.
    impl TryIntoProcessHandle for Child {
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
            Ok(self.id() as pid_t)
        }
    }

    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            let local_iov = iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            };
            let remote_iov = iovec {
                iov_base: addr as *mut c_void,
                iov_len: buf.len(),
            };
            let result = unsafe { process_vm_readv(*self, &local_iov, 1, &remote_iov, 1, 0) };
            if result == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(target_os="macos")]
mod platform {
    extern crate mach;

    use libc::{pid_t, c_int};
    use self::mach::kern_return::{kern_return_t, KERN_SUCCESS};
    use self::mach::port::{mach_port_t, mach_port_name_t, MACH_PORT_NULL};
    use self::mach::vm_types::{mach_vm_address_t, mach_vm_size_t};
    use std::io;
    use std::process::Child;

    use super::{CopyAddress, TryIntoProcessHandle};

    #[allow(non_camel_case_types)]
    type vm_map_t = mach_port_t;
    #[allow(non_camel_case_types)]
    type vm_address_t = mach_vm_address_t;
    #[allow(non_camel_case_types)]
    type vm_size_t = mach_vm_size_t;

    /// On OS X a `Pid` is just a `libc::pid_t`.
    pub type Pid = pid_t;
    /// On OS X a `ProcessHandle` is a mach port.
    pub type ProcessHandle = mach_port_name_t;

    extern "C" {
        fn vm_read_overwrite(target_task: vm_map_t,
                             address: vm_address_t,
                             size: vm_size_t,
                             data: vm_address_t,
                             out_size: *mut vm_size_t) -> kern_return_t;
    }

    /// A small wrapper around `task_for_pid`, which takes a pid and returns the mach port
    /// representing its task.
    fn task_for_pid(pid: pid_t) -> io::Result<mach_port_name_t> {
        let mut task: mach_port_name_t = MACH_PORT_NULL;

        unsafe {
            let result =
                mach::traps::task_for_pid(mach::traps::mach_task_self(), pid as c_int, &mut task);
            if result != KERN_SUCCESS {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(task)
    }

    /// `Pid` can be turned into a `ProcessHandle` with `task_for_pid`.
    impl TryIntoProcessHandle for Pid {
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
            task_for_pid(*self)
        }
    }

    /// This `TryIntoProcessHandle` impl simply calls the `TryIntoProcessHandle` impl for `Pid`.
    ///
    /// Unfortunately spawning a process on OS X does not hand back a mach
    /// port by default (you have to jump through several hoops to get at it),
    /// so there's no simple implementation of `TryIntoProcessHandle` for
    /// `std::process::Child`. This implementation is just provided for symmetry
    /// with other platforms to make writing cross-platform code easier.
    ///
    /// Ideally we would provide an implementation of `std::process::Command::spawn`
    /// that jumped through those hoops and provided the task port.
    impl TryIntoProcessHandle for Child {
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
            self.id().try_into_process_handle()
        }
    }

    /// Use `vm_read` to read memory from another process on OS X.
    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            let mut read_len = buf.len() as vm_size_t;
            let result = unsafe {
                vm_read_overwrite(*self,
                                  addr as vm_address_t,
                                  buf.len() as vm_size_t,
                                  buf.as_mut_ptr() as vm_address_t,
                                  &mut read_len)

            };

            if read_len != buf.len() as vm_size_t {
                panic!("Mismatched read sizes for `vm_read` (expected {}, got {})",
                       buf.len(),
                       read_len)
            }

            if result != KERN_SUCCESS {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

#[cfg(target_os="freebsd")]
mod platform {
    use libc::{pid_t, c_void, c_int, waitpid, WIFSTOPPED, PT_ATTACH, PT_DETACH, PT_IO};
    use std::{io, ptr};
    use std::process::Child;

    use super::{CopyAddress, TryIntoProcessHandle};

    /// On FreeBSD a `Pid` is just a `libc::pid_t`.
    pub type Pid = pid_t;
    /// On FreeBSD a `ProcessHandle` is just a `libc::pid_t`.
    pub type ProcessHandle = pid_t;

    #[repr(C)]
    struct PtraceIoDesc {
        piod_op: c_int,
        piod_offs: *mut c_void,
        piod_addr: *mut c_void,
        piod_len: usize,
    }

    extern "C" {
        /// libc version of ptrace takes *mut i8 as third argument,
        /// which is not very ergonomic if we have a struct.
        fn ptrace(request: c_int,
                  pid: pid_t,
                  io_desc: *const PtraceIoDesc,
                  data: c_int) -> c_int;
    }

    /// Following variable is not exposed via libc, yet.
    /// https://github.com/freebsd/freebsd/blob/1d6e4247415d264485ee94b59fdbc12e0c566fd0/sys/sys/ptrace.h#L112
    const PIOD_READ: c_int = 1;

    /// A `process::Child` always has a pid, which is all we need on FreeBSD.
    impl TryIntoProcessHandle for Child {
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
            Ok(self.id() as pid_t)
        }
    }

    /// Attach to a process `pid` and wait for the process to be stopped.
    fn ptrace_attach(pid: ProcessHandle) -> io::Result<()> {
        let attach_status = unsafe {
            ptrace(PT_ATTACH, pid, ptr::null_mut(), 0)
        };

        if attach_status == -1 {
            return Err(io::Error::last_os_error())
        }

        let mut wait_status = 0;

        let stopped = unsafe {
            waitpid(pid, &mut wait_status as *mut _, 0);
            WIFSTOPPED(wait_status)
        };

        if !stopped {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Read process `pid` memory at `addr` to `buf` via PT_IO ptrace call.
    fn ptrace_io(pid: ProcessHandle, addr: usize, buf: &mut [u8])
                 -> io::Result<()> {
        let ptrace_io_desc = PtraceIoDesc {
            piod_op: PIOD_READ,
            piod_offs: addr as *mut c_void,
            piod_addr: buf.as_mut_ptr() as *mut c_void,
            piod_len: buf.len(),
        };

        let result = unsafe {
            ptrace(PT_IO, pid, &ptrace_io_desc as *const _, 0)
        };

        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }


    /// Detach from the process `pid`.
    fn ptrace_detach(pid: ProcessHandle) -> io::Result<()> {
        let detach_status = unsafe {
            ptrace(PT_DETACH, pid, ptr::null_mut(), 0)
        };

        if detach_status == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            ptrace_attach(*self)?;

            ptrace_io(*self, addr, buf)?;

            ptrace_detach(*self)
        }
    }
}

#[cfg(windows)]
mod platform {
    extern crate winapi;
    extern crate kernel32;

    use std::io;
    use std::mem;
    use std::os::windows::io::{AsRawHandle, RawHandle};
    use std::process::Child;
    use std::ptr;

    use super::{CopyAddress, TryIntoProcessHandle};

    /// On Windows a `Pid` is a `DWORD`.
    pub type Pid = winapi::DWORD;
    /// On Windows a `ProcessHandle` is a `HANDLE`.
    pub type ProcessHandle = RawHandle;

    /// A `Pid` can be turned into a `ProcessHandle` with `OpenProcess`.
    impl TryIntoProcessHandle for winapi::DWORD {
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
            let handle = unsafe {
                kernel32::OpenProcess(winapi::winnt::PROCESS_VM_READ, winapi::FALSE, *self)
            };
            if handle == (0 as RawHandle) {
                Err(io::Error::last_os_error())
            } else {
                Ok(handle)
            }
        }
    }

    /// A `std::process::Child` has a `HANDLE` from calling `CreateProcess`.
    impl TryIntoProcessHandle for Child {
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
            Ok(self.as_raw_handle())
        }
    }

    /// Use `ReadProcessMemory` to read memory from another process on Windows.
    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            if buf.len() == 0 {
                return Ok(());
            }

            if unsafe {
                kernel32::ReadProcessMemory(*self,
                                            addr as winapi::LPVOID,
                                            buf.as_mut_ptr() as winapi::LPVOID,
                                            mem::size_of_val(buf) as winapi::SIZE_T,
                                            ptr::null_mut())
            } == winapi::FALSE {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

/// Copy `length` bytes of memory at `addr` from `source`.
///
/// This is just a convenient way to call `CopyAddress::copy_address` without
/// having to provide your own buffer.
pub fn copy_address<T>(addr: usize, length: usize, source: &T) -> io::Result<Vec<u8>>
    where T: CopyAddress
{
    debug!("copy_address: addr: {:x}", addr);

    let mut copy = vec![0; length];

    source.copy_address(addr, &mut copy)
        .map_err(|e| {
            warn!("copy_address failed for {:x}: {:?}", addr, e);
            e
        })
        .and(Ok(copy))
}

#[cfg(test)]
mod test {
    #[cfg(target_os="macos")]
    extern crate spawn_task_port;

    use super::*;
    use std::env;
    use std::io::{self, BufRead, BufReader};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    fn test_process_path() -> Option<PathBuf> {
        env::current_exe()
            .ok()
            .and_then(|p| {
                p.parent().map(|p| {
                    p.with_file_name("test")
                        .with_extension(env::consts::EXE_EXTENSION)
                })
            })
    }

    #[cfg(not(target_os="macos"))]
    fn spawn_with_handle(cmd: &mut Command) -> io::Result<(Child, ProcessHandle)> {
        let child = try!(cmd.spawn()
            .map_err(|e| {
                println!("Error spawning test process '{:?}': {:?}", cmd, e);
                e
            }));
        let handle = try!(child.try_into_process_handle());
        Ok((child, handle))
    }

    #[cfg(target_os="macos")]
    fn spawn_with_handle(cmd: &mut Command) -> io::Result<(Child, ProcessHandle)> {
        use self::spawn_task_port::CommandSpawnWithTask;
        cmd.spawn_get_task_port()
    }

    fn read_test_process(args: Option<&[&str]>) -> io::Result<Vec<u8>> {
        // Spawn a child process and attempt to read its memory.
        let path = test_process_path().unwrap();
        let mut cmd = Command::new(&path);
        {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped());
        }
        if let Some(a) = args {
            cmd.args(a);
        }
        let (mut child, handle) = try!(spawn_with_handle(&mut cmd));
        // The test program prints the address and size.
        // See `src/bin/test.rs` for its source.
        let reader = BufReader::new(child.stdout.take().unwrap());
        let line = reader.lines().next().unwrap().unwrap();
        let bits = line.split(' ').collect::<Vec<_>>();
        let addr = usize::from_str_radix(&bits[0][2..], 16).unwrap();
        let size = bits[1].parse::<usize>().unwrap();
        let mem = try!(copy_address(addr, size, &handle));
        try!(child.wait());
        Ok(mem)
    }

    #[test]
    fn test_read_small() {
        let mem = read_test_process(None).unwrap();
        assert_eq!(mem, (0..32u8).collect::<Vec<u8>>());
    }

    #[test]
    fn test_read_large() {
        // 5000 should be greater than a single page on most systems.
        const SIZE: usize = 5000;
        let arg = format!("{}", SIZE);
        let mem = read_test_process(Some(&[&arg])).unwrap();
        let expected =
            (0..SIZE).map(|v| (v % (u8::max_value() as usize + 1)) as u8).collect::<Vec<u8>>();
        assert_eq!(mem, expected);
    }
}
