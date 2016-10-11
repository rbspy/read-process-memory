// This test program is used in the tests in src/lib.rs.
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let data = (0..32).collect::<Vec<u8>>();
    println!("{:p} {}", data.as_ptr(), data.len());
    sleep(Duration::from_secs(600));
}
