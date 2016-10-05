#[macro_use] extern crate log;
extern crate libc;

use std::io;

pub trait CopyAddress {
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()>;
}

// This should be dropped in favor of TryInto when that stabilizes:
// https://github.com/rust-lang/rust/issues/33417
pub trait TryIntoProcessHandle {
    fn try_into_process_handle(self) -> io::Result<platform::ProcessHandle>;
}

/// Trivial implementation of `TryIntoProcessHandle`.
impl TryIntoProcessHandle for platform::ProcessHandle {
    fn try_into_process_handle(self) -> io::Result<platform::ProcessHandle> {
        Ok(self)
    }
}

pub struct Process {
    handle: platform::ProcessHandle,
}

pub use platform::Pid;

impl Process {
    pub fn new<T>(process: T) -> io::Result<Process> where T: TryIntoProcessHandle {
        Ok(Process {
            handle: try!(process.try_into_process_handle()),
        })
    }
}

#[cfg(target_os="linux")]
mod platform {
    use libc::{pid_t, c_void, iovec, process_vm_readv};
    use std::io;
    use std::process::Child;

    use super::{CopyAddress, Process, TryIntoProcessHandle};

    pub type Pid = pid_t;
    pub type ProcessHandle = pid_t;

    impl<'a> TryIntoProcessHandle for &'a Child {
        fn try_into_process_handle(self) -> io::Result<ProcessHandle> {
            Ok(self.id() as pid_t)
        }
    }

    impl CopyAddress for Process {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            let local_iov = iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            };
            let remote_iov = iovec {
                iov_base: addr as *mut c_void,
                iov_len: buf.len(),
            };
            let result = unsafe {
                process_vm_readv(self.handle, &local_iov, 1, &remote_iov, 1, 0)
            };
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
    use self::mach::message::{mach_msg_type_number_t};
    use std::io;
    use std::ptr;
    use std::slice;

    use super::{CopyAddress, Process, TryIntoProcessHandle};

    #[allow(non_camel_case_types)] type vm_map_t = mach_port_t;
    #[allow(non_camel_case_types)] type vm_address_t = mach_vm_address_t;
    #[allow(non_camel_case_types)] type vm_size_t = mach_vm_size_t;

    pub type Pid = pid_t;
    pub type ProcessHandle = mach_port_name_t;

    extern "C" {
        fn vm_read(target_task: vm_map_t, address: vm_address_t, size: vm_size_t, data: &*mut u8, data_size: *mut mach_msg_type_number_t) -> kern_return_t;
    }

    fn task_for_pid(pid: pid_t) -> io::Result<mach_port_name_t> {
        let mut task: mach_port_name_t = MACH_PORT_NULL;

        unsafe {
            let result = mach::traps::task_for_pid(mach::traps::mach_task_self(), pid as c_int, &mut task);
            if result != KERN_SUCCESS {
                return Err(io::Error::last_os_error())
            }
        }

        Ok(task)
    }

    /// `pid_t` can be turned into a `mach_port_name_t` with `task_for_pid`.
    impl TryIntoProcessHandle for pid_t {
        fn try_into_process_handle(self) -> io::Result<ProcessHandle> {
            task_for_pid(self)
        }
    }

    impl CopyAddress for Process {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            let page_addr      = (addr as i64 & (-4096)) as mach_vm_address_t;
	    let last_page_addr = ((addr as i64 + buf.len() as i64 + 4095) & (-4096)) as mach_vm_address_t;
            let page_size      = last_page_addr as usize - page_addr as usize;

            let read_ptr: *mut u8 = ptr::null_mut();
            let mut read_len: mach_msg_type_number_t = 0;

            let result = unsafe {
                vm_read(self.handle, page_addr as u64, page_size as vm_size_t, &read_ptr, &mut read_len)
            };

            if result != KERN_SUCCESS {
                // panic!("({}) {:?}", result, io::Error::last_os_error());
                return Err(io::Error::last_os_error())
            }

            if read_len != page_size as u32 {
                panic!("Mismatched read sizes for `vm_read` (expected {}, got {})", page_size, read_len)
            }

            let read_buf = unsafe { slice::from_raw_parts(read_ptr, read_len as usize) };

            let offset = addr - page_addr as usize;
            let len = buf.len();
            buf.copy_from_slice(&read_buf[offset..(offset + len)]);

            Ok(())
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

    use super::{CopyAddress, Process, TryIntoProcessHandle};

    pub type Pid = winapi::DWORD;
    pub type ProcessHandle = RawHandle;

    /// `DWORD` can be turned into a `HANDLE` with `OpenProcess`.
    impl TryIntoProcessHandle for winapi::DWORD {
        fn try_into_process_handle(self) -> io::Result<ProcessHandle> {
            let handle = unsafe { kernel32::OpenProcess(winapi::winnt::PROCESS_VM_READ, winapi::FALSE, self) };
            if handle == (0 as RawHandle) {
                Err(io::Error::last_os_error())
            } else {
                Ok(handle)
            }
        }
    }

    impl<'a> TryIntoProcessHandle for &'a Child {
        fn try_into_process_handle(self) -> io::Result<ProcessHandle> {
            Ok(self.as_raw_handle())
        }
    }

    impl CopyAddress for Process {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            if buf.len() == 0 {
                return Ok(());
            }

            if unsafe { kernel32::ReadProcessMemory(self.handle,
                                                    addr as winapi::LPVOID,
                                                    buf.as_mut_ptr() as winapi::LPVOID,
                                                    mem::size_of_val(buf) as winapi::SIZE_T,
                                                    ptr::null_mut()) } == winapi::FALSE
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

pub fn copy_address_raw<T>(addr: usize, length: usize, source: &T) -> io::Result<Vec<u8>>
    where T: CopyAddress
{
    debug!("copy_address_raw: addr: {:x}", addr);

    let mut copy = vec![0; length];

    source.copy_address(addr, &mut copy)
        .map_err(|e| {
            warn!("copy_address failed for {:x}: {:?}", addr, e);
            e
        })
        .and(Ok(copy))
}

//TODO: make the tests work on OS X by sending task rights:
// http://www.foldr.org/~michaelw/log/computers/macosx/task-info-fun-with-mach
#[cfg(test)]
#[cfg(not(target_os="macos"))]
mod test {
    use super::*;
    use std::env;
    use std::io::{self, BufRead, BufReader};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    fn test_process_path() -> io::Result<PathBuf> {
        env::current_exe().map(|mut p| { p.set_file_name("test"); p })
    }

    #[test]
    fn read_test_process() {
        let child = Command::new(test_process_path().unwrap())
            .stdout(Stdio::piped())
            .spawn().unwrap();
        let p = Process::new(&child).unwrap();
        // The test program prints the address and size.
        let reader = BufReader::new(child.stdout.unwrap());
        let line = reader.lines().next().unwrap().unwrap();
        let bits = line.split(' ').collect::<Vec<_>>();
        let addr = usize::from_str_radix(&bits[0][2..], 16).unwrap();
        let size = bits[1].parse::<usize>().unwrap();
        let mem = copy_address_raw(addr, size, &p).unwrap();
        assert_eq!(mem, (0..32u8).collect::<Vec<u8>>());
    }
}
