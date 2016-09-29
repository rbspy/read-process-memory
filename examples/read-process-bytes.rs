extern crate libc;
extern crate read_process_memory;

use read_process_memory::*;
use std::env;
use libc::pid_t;

fn bytes_to_hex(bytes: &[u8]) -> String {
    let hex_bytes: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b)).collect();
    hex_bytes.join("")
}

fn main() {
    let pid = env::args().nth(1).unwrap().parse::<usize>().unwrap() as pid_t;
    let addr = usize::from_str_radix(&env::args().nth(2).unwrap(), 16).unwrap();
    let size = env::args().nth(3).unwrap().parse::<usize>().unwrap();
    let process = Process::new(pid).unwrap();
    copy_address_raw(addr, size, &process)
        .map_err(|e| {
            println!("Error: {:?}", e);
            e
        })
        .map(|bytes| println!("{} bytes at address {:x}:
{}
", size, addr, bytes_to_hex(&bytes))).unwrap();
}
