// This test program is used in the tests in src/lib.rs.
use std::env;
use std::io::{self, Read};

fn main() {
    // Map a readable page followed by an unreadable one. A FreeBSD process can't ptrace itself,
    // so this has to be a child.
    #[cfg(target_os = "freebsd")]
    if env::args().nth(1).as_deref() == Some("short-read") {
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
        let end = mem as usize + page;
        assert_eq!(
            unsafe { libc::mprotect(end as *mut _, page, libc::PROT_NONE) },
            0
        );
        println!("{:#x}", end);
        io::stdin().read_to_end(&mut Vec::new()).unwrap();
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
