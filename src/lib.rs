//! Read memory from another process' address space.
//!
//! This crate provides a trait—[`CopyAddress`](trait.CopyAddress.html),
//! and a helper function—[`copy_address`](fn.copy_address.html) that
//! allow reading memory from another process.
//!
//! Note: you may not always have permission to read memory from another
//! process! This may require `sudo` on some systems, and may fail even with
//! `sudo` on macOS. You are most likely to succeed if you are attempting to
//! read a process that you have spawned yourself.
//!
//! # Examples
//!
//! ```rust,no_run
//! # use std::convert::TryInto;
//! # use std::io;
//! use read_process_memory::*;
//!
//! # fn foo(pid: Pid, address: usize, size: usize) -> io::Result<()> {
//! let handle: ProcessHandle = pid.try_into()?;
//! let bytes = copy_address(address, size, &handle)?;
//! # Ok(())
//! # }
//! ```

#[doc(hidden)]
#[doc = include_str!("../README.md")]
mod readme {}

use std::alloc::{self, Layout};
use std::io;

/// A trait that provides a method for reading memory from another process.
pub trait CopyAddress {
    /// Try to copy `buf.len()` bytes from `addr` in the process `self`, placing
    /// them in `buf`.
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()>;
}

/// A process ID.
pub use crate::platform::Pid;
/// A handle to a running process. This is not a process ID on all platforms.
///
/// For convenience, this crate implements `TryFrom`-backed conversions from
/// `Pid` to `ProcessHandle`.
///
/// # Examples
///
/// ```rust,no_run
/// use read_process_memory::*;
/// use std::convert::TryInto;
/// use std::io;
///
/// fn pid_to_handle(pid: Pid) -> io::Result<ProcessHandle> {
///     Ok(pid.try_into()?)
/// }
/// ```
///
/// This operation is not guaranteed to succeed. Specifically, on Windows
/// `OpenProcess` may fail. On macOS `task_for_pid` will generally fail
/// unless run as root, and even then it may fail when called on certain
/// programs; it may however run without root on the current process.
pub use crate::platform::ProcessHandle;

#[cfg(target_os = "linux")]
mod platform {
    use libc::{c_void, iovec, pid_t, process_vm_readv};
    use std::convert::TryFrom;
    use std::fs;
    use std::io;
    use std::io::Read;
    use std::io::Seek;
    use std::process::Child;

    use super::CopyAddress;

    /// On Linux a `Pid` is just a `libc::pid_t`.
    pub type Pid = pid_t;
    /// On Linux a `ProcessHandle` is just a `libc::pid_t`.
    #[derive(Clone)]
    pub struct ProcessHandle(Pid);

    /// On Linux, process handle is a pid.
    impl TryFrom<Pid> for ProcessHandle {
        type Error = io::Error;

        fn try_from(pid: Pid) -> io::Result<Self> {
            Ok(Self(pid))
        }
    }

    /// A `process::Child` always has a pid, which is all we need on Linux.
    impl TryFrom<&Child> for ProcessHandle {
        type Error = io::Error;

        fn try_from(child: &Child) -> io::Result<Self> {
            Self::try_from(child.id() as Pid)
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
            let result = unsafe { process_vm_readv(self.0, &local_iov, 1, &remote_iov, 1, 0) };
            if result == -1 {
                match io::Error::last_os_error().raw_os_error() {
                    Some(libc::ENOSYS) | Some(libc::EPERM) => {
                        // fallback to reading /proc/$pid/mem if kernel does not
                        // implement process_vm_readv()
                        let mut procmem = fs::File::open(format!("/proc/{}/mem", self.0))?;
                        procmem.seek(io::SeekFrom::Start(addr as u64))?;
                        procmem.read_exact(buf)
                    }
                    _ => Err(io::Error::last_os_error()),
                }
            } else if result as usize != buf.len() {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Mismatched read sizes for `process_vm_readv` (expected {}, got {})",
                        buf.len(),
                        result
                    ),
                ))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use libc::{c_char, c_int, pid_t};
    use mach2::kern_return::{
        kern_return_t, KERN_FAILURE, KERN_INVALID_ADDRESS, KERN_INVALID_NAME, KERN_INVALID_TASK,
        KERN_PROTECTION_FAILURE, KERN_SUCCESS,
    };
    use mach2::message::MACH_SEND_INVALID_DEST;
    use mach2::port::{mach_port_name_t, mach_port_t, MACH_PORT_NULL};
    use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

    use std::convert::TryFrom;
    use std::ffi::CStr;
    use std::io;
    use std::process::Child;
    use std::sync::Arc;

    use super::CopyAddress;

    #[allow(non_camel_case_types)]
    type vm_map_t = mach_port_t;
    #[allow(non_camel_case_types)]
    type vm_address_t = mach_vm_address_t;
    #[allow(non_camel_case_types)]
    type vm_size_t = mach_vm_size_t;

    /// On macOS a `Pid` is just a `libc::pid_t`.
    pub type Pid = pid_t;
    struct ProcessHandleInner {
        port: mach_port_name_t,
        /// Whether we hold a send right from `task_for_pid` that we must release.
        owned: bool,
    }

    impl Drop for ProcessHandleInner {
        fn drop(&mut self) {
            if self.owned {
                unsafe {
                    mach2::mach_port::mach_port_deallocate(
                        mach2::traps::mach_task_self(),
                        self.port,
                    )
                };
            }
        }
    }

    /// On macOS a `ProcessHandle` is a mach port.
    #[derive(Clone)]
    pub struct ProcessHandle(Arc<ProcessHandleInner>);

    extern "C" {
        fn vm_read_overwrite(
            target_task: vm_map_t,
            address: vm_address_t,
            size: vm_size_t,
            data: vm_address_t,
            out_size: *mut vm_size_t,
        ) -> kern_return_t;
        fn mach_error_string(error_value: kern_return_t) -> *const c_char;
    }

    /// Mach calls report failure through their `kern_return_t`, not `errno`, so
    /// build the `io::Error` from the return code. Unreadable addresses map to
    /// `EFAULT` to match what the other platforms report for the same condition.
    fn kern_error(call: &str, kr: kern_return_t) -> io::Error {
        let kind = match kr {
            KERN_INVALID_ADDRESS | KERN_PROTECTION_FAILURE => {
                return io::Error::from_raw_os_error(libc::EFAULT)
            }
            // `task_for_pid` returns KERN_FAILURE when the caller lacks the
            // privileges or entitlements to get the task port.
            KERN_FAILURE => io::ErrorKind::PermissionDenied,
            // The task port is dead because the process has exited.
            KERN_INVALID_NAME | KERN_INVALID_TASK | MACH_SEND_INVALID_DEST => {
                io::ErrorKind::NotFound
            }
            _ => io::ErrorKind::Other,
        };
        let msg = unsafe { CStr::from_ptr(mach_error_string(kr)) };
        io::Error::new(
            kind,
            format!("`{}` failed: {} ({:#x})", call, msg.to_string_lossy(), kr),
        )
    }

    /// A small wrapper around `task_for_pid`, which takes a pid and returns the
    /// mach port representing its task, and whether the caller owns a send
    /// right to it.
    fn task_for_pid(pid: Pid) -> io::Result<(mach_port_name_t, bool)> {
        if pid == unsafe { libc::getpid() } as Pid {
            return Ok((unsafe { mach2::traps::mach_task_self() }, false));
        }

        let mut task: mach_port_name_t = MACH_PORT_NULL;

        unsafe {
            let result =
                mach2::traps::task_for_pid(mach2::traps::mach_task_self(), pid as c_int, &mut task);
            if result != KERN_SUCCESS {
                return Err(kern_error("task_for_pid", result));
            }
        }

        Ok((task, true))
    }

    impl ProcessHandle {
        #[cfg(test)]
        pub(crate) fn task_port(&self) -> mach_port_name_t {
            self.0.port
        }
    }

    /// A `Pid` can be turned into a `ProcessHandle` with `task_for_pid`.
    ///
    /// The task port's send right is released once the last clone of the
    /// `ProcessHandle` is dropped.
    impl TryFrom<Pid> for ProcessHandle {
        type Error = io::Error;

        fn try_from(pid: Pid) -> io::Result<Self> {
            let (port, owned) = task_for_pid(pid)?;
            Ok(Self(Arc::new(ProcessHandleInner { port, owned })))
        }
    }

    /// On Darwin, process handle is a mach port name.
    ///
    /// This **borrows** `mach_port_name`: the caller keeps ownership of the
    /// send right and must keep it alive while the `ProcessHandle` is in use.
    impl TryFrom<mach_port_name_t> for ProcessHandle {
        type Error = io::Error;

        fn try_from(mach_port_name: mach_port_name_t) -> io::Result<Self> {
            Ok(Self(Arc::new(ProcessHandleInner {
                port: mach_port_name,
                owned: false,
            })))
        }
    }

    /// This `TryFrom` impl simply calls the `TryFrom` impl for `Pid`.
    ///
    /// Unfortunately spawning a process on macOS does not hand back a mach
    /// port by default (you have to jump through several hoops to get at it),
    /// so there's no simple implementation of `TryFrom` Child
    /// `for::Child`. This implementation is just provided for symmetry
    /// with other platforms to make writing cross-platform code easier.
    ///
    /// Ideally we would provide an implementation of
    /// `std::process::Command::spawn` that jumped through those hoops and
    /// provided the task port.
    impl TryFrom<&Child> for ProcessHandle {
        type Error = io::Error;

        fn try_from(child: &Child) -> io::Result<Self> {
            Self::try_from(child.id() as Pid)
        }
    }

    /// Use `vm_read` to read memory from another process on macOS.
    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            let mut read_len = buf.len() as vm_size_t;
            let result = unsafe {
                vm_read_overwrite(
                    self.0.port,
                    addr as vm_address_t,
                    buf.len() as vm_size_t,
                    buf.as_mut_ptr() as vm_address_t,
                    &mut read_len,
                )
            };

            if result != KERN_SUCCESS {
                return Err(kern_error("vm_read_overwrite", result));
            }

            if read_len != buf.len() as vm_size_t {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Mismatched read sizes for `vm_read` (expected {}, got {})",
                        buf.len(),
                        read_len
                    ),
                ));
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "freebsd")]
mod platform {
    use libc::{c_int, c_void, pid_t};
    use libc::{
        waitpid, EBUSY, ESRCH, PIOD_READ_D, PT_ATTACH, PT_DETACH, PT_IO, SIGSTOP, WIFSTOPPED,
        WSTOPSIG,
    };
    use std::convert::TryFrom;
    use std::process::Child;
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::{Mutex, MutexGuard, Once};
    use std::{io, ptr};

    use super::CopyAddress;

    /// On FreeBSD a `Pid` is just a `libc::pid_t`.
    pub type Pid = pid_t;
    /// On FreeBSD a `ProcessHandle` is just a `libc::pid_t`.
    #[derive(Clone)]
    pub struct ProcessHandle(Pid);

    #[repr(C)]
    struct PtraceIoDesc {
        piod_op: c_int,
        piod_offs: *mut c_void,
        piod_addr: *mut c_void,
        piod_len: usize,
    }

    /// An attachment made by `ptrace_attach`. Dropping it detaches from the
    /// process, so the target is resumed on every exit path.
    struct PtraceAttachment {
        pid: Pid,
        /// A signal that stopped the process before our attach `SIGSTOP` did.
        /// It is re-delivered on detach instead of being discarded.
        signal: c_int,
        /// Whether dropping this guard still needs to detach from the process.
        needs_detach: bool,
    }

    impl PtraceAttachment {
        /// Detach on the normal path and report failures to the caller. `Drop`
        /// remains as a fallback for early returns and unwinding.
        fn detach(mut self) -> io::Result<()> {
            self.needs_detach = false;
            ptrace_detach(self.pid, self.signal)
        }
    }

    impl Drop for PtraceAttachment {
        fn drop(&mut self) {
            if !self.needs_detach {
                return;
            }
            // PT_DETACH also discards our `SIGSTOP` if it's still pending.
            if let Err(err) = ptrace_detach(self.pid, self.signal) {
                log::warn!("PT_DETACH failed for pid {}: {}", self.pid, err);
            }
        }
    }

    extern "C" {
        /// libc version of ptrace takes *mut i8 as third argument,
        /// which is not very ergonomic if we have a struct.
        fn ptrace(request: c_int, pid: pid_t, io_desc: *mut PtraceIoDesc, data: c_int) -> c_int;
    }

    /// On FreeBSD, process handle is a pid.
    impl TryFrom<Pid> for ProcessHandle {
        type Error = io::Error;

        fn try_from(pid: Pid) -> io::Result<Self> {
            Ok(Self(pid))
        }
    }

    /// A `process::Child` always has a pid, which is all we need on FreeBSD.
    impl TryFrom<&Child> for ProcessHandle {
        type Error = io::Error;

        fn try_from(child: &Child) -> io::Result<Self> {
            Self::try_from(child.id() as Pid)
        }
    }

    /// Serializes attach/read/detach across threads. Without it, a second
    /// thread reading the same process gets EBUSY from the first thread's
    /// attach, and the first thread can detach while the second is mid-read.
    fn ptrace_lock() -> MutexGuard<'static, ()> {
        static INIT: Once = Once::new();
        static LOCK: AtomicPtr<Mutex<()>> = AtomicPtr::new(ptr::null_mut());
        INIT.call_once(|| LOCK.store(Box::into_raw(Box::new(Mutex::new(()))), Ordering::Release));
        let lock = unsafe { &*LOCK.load(Ordering::Acquire) };
        // The lock guards no data, so a panic while holding it is harmless.
        lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Attach to a process `pid` and wait for the process to be stopped.
    ///
    /// Returns `None` if the process is already traced, in which case it isn't
    /// ours to detach from.
    fn ptrace_attach(pid: Pid) -> io::Result<Option<PtraceAttachment>> {
        if unsafe { ptrace(PT_ATTACH, pid, ptr::null_mut(), 0) } == -1 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(EBUSY) => Ok(None),
                _ => Err(err),
            };
        }
        let mut attachment = PtraceAttachment {
            pid,
            signal: 0,
            needs_detach: true,
        };

        let mut wait_status = 0;
        while unsafe { waitpid(pid, &mut wait_status, 0) } == -1 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }

        if !WIFSTOPPED(wait_status) {
            // The process exited or was killed, so there's nothing to detach.
            attachment.needs_detach = false;
            return Err(io::Error::from_raw_os_error(ESRCH));
        }
        let signal = WSTOPSIG(wait_status);
        if signal != SIGSTOP {
            attachment.signal = signal;
        }
        Ok(Some(attachment))
    }

    /// Detach from process `pid`, re-delivering `signal` if one was pending.
    fn ptrace_detach(pid: Pid, signal: c_int) -> io::Result<()> {
        if unsafe { ptrace(PT_DETACH, pid, ptr::null_mut(), signal) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Read process `pid` memory at `addr` to `buf` via PT_IO ptrace call.
    fn ptrace_io(pid: Pid, addr: usize, buf: &mut [u8]) -> io::Result<()> {
        let mut ptrace_io_desc = PtraceIoDesc {
            piod_op: PIOD_READ_D,
            piod_offs: addr as *mut c_void,
            piod_addr: buf.as_mut_ptr() as *mut c_void,
            piod_len: buf.len(),
        };

        let result = unsafe { ptrace(PT_IO, pid, &mut ptrace_io_desc as *mut _, 0) };

        if result == -1 {
            Err(io::Error::last_os_error())
        } else if ptrace_io_desc.piod_len != buf.len() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "Mismatched read sizes for `PT_IO` (expected {}, got {})",
                    buf.len(),
                    ptrace_io_desc.piod_len
                ),
            ))
        } else {
            Ok(())
        }
    }

    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            if buf.is_empty() {
                return Ok(());
            }

            let _lock = ptrace_lock();
            let attachment = ptrace_attach(self.0)?;
            let result = ptrace_io(self.0, addr, buf);
            if let Some(attachment) = attachment {
                attachment.detach()?;
            }
            result
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::convert::TryFrom;
    use std::io;
    use std::mem;
    use std::ops::Deref;
    use std::os::raw::c_void;
    use std::os::windows::io::RawHandle;
    use std::process::Child;
    use std::ptr;
    use std::sync::Arc;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

    use super::CopyAddress;

    /// On Windows a `Pid` is a `DWORD`.
    pub type Pid = u32;
    #[derive(Eq, PartialEq, Hash)]
    struct ProcessHandleInner(HANDLE);

    // A HANDLE is an index into the process-wide kernel handle table rather than
    // an address, so it stays valid on any thread
    unsafe impl Send for ProcessHandleInner {}
    unsafe impl Sync for ProcessHandleInner {}

    /// On Windows a `ProcessHandle` is a `HANDLE`.
    #[derive(Clone, Eq, PartialEq, Hash)]
    pub struct ProcessHandle(Arc<ProcessHandleInner>);

    impl Deref for ProcessHandle {
        type Target = HANDLE;

        fn deref(&self) -> &Self::Target {
            &self.0 .0
        }
    }

    impl Drop for ProcessHandleInner {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    /// A `Pid` can be turned into a `ProcessHandle` with `OpenProcess`.
    impl TryFrom<Pid> for ProcessHandle {
        type Error = io::Error;

        fn try_from(pid: Pid) -> io::Result<Self> {
            let handle = unsafe { OpenProcess(PROCESS_VM_READ, 0, pid) };
            if handle.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(Arc::new(ProcessHandleInner(handle))))
            }
        }
    }

    /// A `std::process::Child` can be turned into a `ProcessHandle` with
    /// `OpenProcess`. The `Child` keeps ownership of its own handle.
    impl TryFrom<&Child> for ProcessHandle {
        type Error = io::Error;

        fn try_from(child: &Child) -> io::Result<Self> {
            Self::try_from(child.id() as Pid)
        }
    }

    /// Wrap an existing `RawHandle` in a `ProcessHandle`.
    ///
    /// This **takes ownership** of `handle`. The resulting `ProcessHandle`
    /// closes it with `CloseHandle` once the last clone is dropped. Pass an
    /// owned handle (e.g. from `OpenProcess`), not a borrowed one such as
    /// `Child::as_raw_handle`.
    impl From<RawHandle> for ProcessHandle {
        fn from(handle: RawHandle) -> Self {
            Self(Arc::new(ProcessHandleInner(handle as HANDLE)))
        }
    }

    /// Use `ReadProcessMemory` to read memory from another process on Windows.
    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            if buf.is_empty() {
                return Ok(());
            }

            if unsafe {
                ReadProcessMemory(
                    self.0 .0,
                    addr as *const c_void,
                    buf.as_mut_ptr().cast(),
                    mem::size_of_val(buf),
                    ptr::null_mut(),
                )
            } == 0
            {
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
where
    T: CopyAddress,
{
    log::debug!("copy_address: addr: {:x}", addr);

    let mut copy = zeroed_buffer(length)?;

    source
        .copy_address(addr, &mut copy)
        .map_err(|e| {
            log::warn!("copy_address failed for {:x}: {:?}", addr, e);
            e
        })
        .and(Ok(copy))
}

/// Allocate a zeroed buffer, failing instead of aborting the process when
/// `length` can't be allocated. Callers often read `length` out of the target
/// process, so it can't be trusted.
fn zeroed_buffer(length: usize) -> io::Result<Vec<u8>> {
    if length == 0 {
        return Ok(Vec::new());
    }
    let too_large = || {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("can't allocate {} bytes to copy into", length),
        )
    };
    let layout = Layout::array::<u8>(length).map_err(|_| too_large())?;
    let ptr = unsafe { alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return Err(too_large());
    }
    // SAFETY: `ptr` came from the global allocator with the layout of a
    // `[u8; length]`, and zeroing initialized all of it.
    Ok(unsafe { Vec::from_raw_parts(ptr, length, length) })
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::TryFrom;
    use std::env;
    use std::io::{self, BufRead, BufReader};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    #[allow(unused)]
    const fn assert_send_sync<T: Send + Sync>() {}
    const _: () = assert_send_sync::<ProcessHandle>();
    const _: () = assert_send_sync::<Pid>();

    fn test_process_path() -> Option<PathBuf> {
        env::current_exe().ok().and_then(|p| {
            p.parent().map(|p| {
                p.with_file_name("test")
                    .with_extension(env::consts::EXE_EXTENSION)
            })
        })
    }

    fn read_test_process(args: Option<&[&str]>) -> io::Result<Vec<u8>> {
        read_test_process_with(args, |child| ProcessHandle::try_from(child.id() as Pid))
    }

    /// Spawn the test child, build a handle to it via `make_handle`, and read
    /// the block of memory it advertises on stdout.
    ///
    /// The handle is dropped before `child.wait()` so that both the wrapper's
    /// `CloseHandle` (on Windows) and the `Child`'s own run against a live
    /// process: if the two ever closed the same handle, the `wait()` here would
    /// fail. This is what exercises the `TryFrom<&Child>` ownership contract.
    fn read_test_process_with<F>(args: Option<&[&str]>, make_handle: F) -> io::Result<Vec<u8>>
    where
        F: FnOnce(&Child) -> io::Result<ProcessHandle>,
    {
        let path = test_process_path().unwrap();
        let mut cmd = Command::new(&path);
        {
            cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        }
        if let Some(a) = args {
            cmd.args(a);
        }
        let mut child = cmd.spawn()?;
        let handle = make_handle(&child)?;
        // The test program prints the address and size.
        // See `src/bin/test.rs` for its source.
        let reader = BufReader::new(child.stdout.take().unwrap());
        let line = reader.lines().next().unwrap().unwrap();
        let bits = line.split(' ').collect::<Vec<_>>();
        let addr = usize::from_str_radix(&bits[0][2..], 16).unwrap();
        let size = bits[1].parse::<usize>().unwrap();
        let mem = copy_address(addr, size, &handle)?;
        drop(handle);
        child.wait()?;
        Ok(mem)
    }

    #[test]
    fn test_read_small() {
        let mem = read_test_process(None).unwrap();
        assert_eq!(mem, (0..32u8).collect::<Vec<u8>>());
    }

    #[test]
    fn test_read_large() {
        // 20,000 should be greater than a single page on most systems.
        // macOS on ARM is 16384.
        const SIZE: usize = 20_000;
        let arg = format!("{}", SIZE);
        let mem = read_test_process(Some(&[&arg])).unwrap();
        let expected = (0..SIZE)
            .map(|v| (v % (u8::max_value() as usize + 1)) as u8)
            .collect::<Vec<u8>>();
        assert_eq!(mem, expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_fails_on_short_read() {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mem, libc::MAP_FAILED);
        assert_eq!(
            unsafe { libc::mprotect((mem as usize + page) as *mut _, page, libc::PROT_NONE) },
            0
        );

        let handle = ProcessHandle::try_from(std::process::id() as Pid).unwrap();
        let end = mem as usize + page;
        let mut buf = [0u8; 8];
        assert!(handle.copy_address(end - 8, &mut buf).is_ok());
        let err = handle.copy_address(end - 4, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        unsafe { libc::munmap(mem, 2 * page) };
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_read_fails_on_short_read() {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mem, libc::MAP_FAILED);
        assert_eq!(
            unsafe { libc::mprotect((mem as usize + page) as *mut _, page, libc::PROT_NONE) },
            0
        );

        let handle = ProcessHandle::try_from(std::process::id() as Pid).unwrap();
        let end = mem as usize + page;
        let mut buf = [0u8; 8];
        assert!(handle.copy_address(end - 8, &mut buf).is_ok());
        // Like FreeBSD, `vm_read_overwrite` fails the whole request rather than
        // reporting a short transfer.
        let err = handle.copy_address(end - 4, &mut buf).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EFAULT));
        let err = handle.copy_address(end, &mut buf).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EFAULT));
        unsafe { libc::munmap(mem, 2 * page) };
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_drop_releases_task_port() {
        use mach2::kern_return::KERN_SUCCESS;
        use mach2::port::{mach_port_name_t, mach_port_right_t, MACH_PORT_RIGHT_SEND};

        extern "C" {
            fn mach_port_get_refs(
                task: mach2::port::mach_port_t,
                name: mach_port_name_t,
                right: mach_port_right_t,
                refs: *mut u32,
            ) -> mach2::kern_return::kern_return_t;
        }

        fn send_refs(name: mach_port_name_t) -> u32 {
            let mut refs = 0;
            let kr = unsafe {
                mach_port_get_refs(
                    mach2::traps::mach_task_self(),
                    name,
                    MACH_PORT_RIGHT_SEND,
                    &mut refs,
                )
            };
            // Once the last right is released the name is gone entirely.
            if kr == KERN_SUCCESS {
                refs
            } else {
                0
            }
        }

        let mut child = Command::new(test_process_path().unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // Getting another process's task port requires root.
        let handle = match ProcessHandle::try_from(child.id() as Pid) {
            Ok(handle) => handle,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                drop(child.stdin.take());
                child.wait().unwrap();
                return;
            }
            Err(e) => panic!("{}", e),
        };
        let port = handle.task_port();
        let before = send_refs(port);
        assert!(before > 0);
        let clone = handle.clone();
        drop(handle);
        assert_eq!(send_refs(port), before);
        drop(clone);
        assert_eq!(send_refs(port), before - 1);
        drop(child.stdin.take());
        child.wait().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_task_for_pid_error_is_not_errno() {
        // Without root, `task_for_pid` on another process fails. As root it may
        // succeed, in which case there is nothing to check.
        if let Err(err) = ProcessHandle::try_from(1 as Pid) {
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(err.raw_os_error(), None);
        }
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn test_read_fails_on_short_read() {
        let mut child = Command::new(test_process_path().unwrap())
            .arg("short-read")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let handle = ProcessHandle::try_from(child.id() as Pid).unwrap();
        let reader = BufReader::new(child.stdout.take().unwrap());
        let line = reader.lines().next().unwrap().unwrap();
        let end = usize::from_str_radix(&line[2..], 16).unwrap();

        let mut buf = [0u8; 8];
        assert!(handle.copy_address(end - 8, &mut buf).is_ok());
        // Unlike Linux, FreeBSD fails the whole `PT_IO` request with EFAULT
        // instead of reporting a short transfer.
        let err = handle.copy_address(end - 4, &mut buf).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EFAULT));
        child.wait().unwrap();
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn test_empty_read_does_not_attach() {
        // A process can't ptrace itself, so this only succeeds if the read
        // returns before attaching.
        let handle = ProcessHandle::try_from(std::process::id() as Pid).unwrap();
        assert!(handle.copy_address(0, &mut []).is_ok());
    }

    #[test]
    fn test_concurrent_reads_from_cloned_handles() {
        let mut child = Command::new(test_process_path().unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let handle = ProcessHandle::try_from(child.id() as Pid).unwrap();
        let reader = BufReader::new(child.stdout.take().unwrap());
        let line = reader.lines().next().unwrap().unwrap();
        let bits = line.split(' ').collect::<Vec<_>>();
        let addr = usize::from_str_radix(&bits[0][2..], 16).unwrap();
        let size = bits[1].parse::<usize>().unwrap();

        let threads = (0..8)
            .map(|_| {
                let handle = handle.clone();
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        let mem = copy_address(addr, size, &handle).unwrap();
                        assert_eq!(mem, (0..32u8).collect::<Vec<u8>>());
                    }
                })
            })
            .collect::<Vec<_>>();
        for t in threads {
            t.join().unwrap();
        }

        // The child must not be left stopped or traced: closing its stdin
        // should let it exit normally.
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn test_huge_length_fails_without_aborting() {
        let handle = ProcessHandle::try_from(std::process::id() as Pid).unwrap();
        let data = [0u8; 4];
        let err = copy_address(data.as_ptr() as usize, usize::MAX, &handle).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::OutOfMemory);
        assert!(zeroed_buffer(0).unwrap().is_empty());
    }

    #[test]
    fn test_read_from_child_handle() {
        let mem = read_test_process_with(None, |child| ProcessHandle::try_from(child)).unwrap();
        assert_eq!(mem, (0..32u8).collect::<Vec<u8>>());
    }
}
