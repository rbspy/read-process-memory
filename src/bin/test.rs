// This test program is used in the tests in src/lib.rs.
use std::env;
use std::io::{self, Read};

#[cfg(target_os = "freebsd")]
use std::io::Write;

#[cfg(target_os = "freebsd")]
struct Mapping {
    address: *mut libc::c_void,
    length: usize,
}

#[cfg(target_os = "freebsd")]
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.address, self.length) };
    }
}

#[cfg(target_os = "freebsd")]
fn run_short_read_test() {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(page > 0);
    let page = page as usize;
    let length = 2 * page;
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert_ne!(address, libc::MAP_FAILED);
    let _mapping = Mapping { address, length };

    unsafe {
        std::slice::from_raw_parts_mut(address as *mut u8, page).fill(0xaa);
        assert_eq!(
            libc::mprotect(
                (address as usize + page) as *mut libc::c_void,
                page,
                libc::PROT_NONE,
            ),
            0
        );
    }

    println!("{:x}", address as usize + page);
    io::stdout().flush().unwrap();

    let mut buf = vec![];
    io::stdin().read_to_end(&mut buf).unwrap();
}

fn main() {
    #[cfg(target_os = "freebsd")]
    if env::args().nth(1).as_deref() == Some("short-read") {
        run_short_read_test();
        return;
    }

    let size = env::args()
        .nth(1)
        .and_then(|a| a.parse::<usize>().ok())
        .unwrap_or(32);
    let data = if size <= u8::max_value() as usize {
        (0..size as u8).collect::<Vec<u8>>()
    } else {
        (0..size)
            .map(|v| (v % (u8::max_value() as usize + 1)) as u8)
            .collect::<Vec<u8>>()
    };
    println!("{:p} {}", data.as_ptr(), data.len());
    // Wait to exit until stdin is closed.
    let mut buf = vec![];
    io::stdin().read_to_end(&mut buf).unwrap();
}
