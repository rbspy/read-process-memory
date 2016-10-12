// This test program is used in the tests in src/lib.rs.
use std::io::{self, Read};

fn main() {
    let data = (0..32).collect::<Vec<u8>>();
    println!("{:p} {}", data.as_ptr(), data.len());
    // Wait to exit until stdin is closed.
    let mut buf = vec!();
    io::stdin().read_to_end(&mut buf).unwrap();
}
