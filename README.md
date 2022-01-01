[![GitHub Actions Build status](https://github.com/rbspy/read-process-memory/actions/workflows/build.yml/badge.svg)](https://github.com/rbspy/read-process-memory/actions/workflows/build.yml) ![Cirrus CI Build status](https://api.cirrus-ci.com/github/luser/read-process-memory.svg) [![crates.io](https://img.shields.io/crates/v/read-process-memory.svg)](https://crates.io/crates/read-process-memory) [![](https://docs.rs/read-process-memory/badge.svg)](https://docs.rs/read-process-memory)

A crate to read memory from another process. Code originally taken from the [rbspy](https://github.com/rbspy/rbspy/) project. This crate has now returned home to the `rbspy` GitHub organization. :)

# Example

This example re-executes itself as a child process in order to have a separate process to use for demonstration purposes. If you need to read memory from a process that you are spawning, your usage should look very similar to this:

```rust
use std::convert::TryInto;
use std::env;
use std::io::{self, BufReader, BufRead, Read, Result};
use std::process::{Command, Stdio};

use read_process_memory::{
  Pid,
  ProcessHandle,
  CopyAddress,
  copy_address,
};

fn main() -> Result<()> {
    if env::args_os().len() > 1 {
      // We are the child.
      return in_child();
    }
    // Run this executable again so we have a child process to read.
    let mut child = Command::new(env::current_exe()?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .arg("child")
        .spawn()?;

    // Get a ProcessHandle to work with.
    let handle: ProcessHandle = (&child).try_into().unwrap();

    // The child process will print the address to read from on stdout.
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut addr_string = String::new();
    stdout.read_line(&mut addr_string)?;
    let address = usize::from_str_radix(addr_string.trim(), 16).unwrap();

    // Try to read 10 bytes from that address
    let bytes = copy_address(address, 10, &handle)?;
    println!("Read: {:?}", bytes);

    // Tell the child to exit by closing its stdin.
    drop(child.stdin.take());
    // And wait for it to exit.
    child.wait()?;
    Ok(())
}

fn in_child() -> Result<()> {
    // Allocate a 10-byte Vec for the parent to read.
    let readable_bytes: Vec<u8> = vec![
        0xc0, 0x72, 0x80, 0x79, 0xeb, 0xf1, 0xbc, 0x87, 0x06, 0x14,
    ];
    // Print the address of the Vec to stdout so the parent can find it.
    println!("{:x}", readable_bytes.as_ptr() as usize);
    // Now wait to exit until the parent closes our stdin, to give
    // it time to read the memory.
    let mut buf = Vec::new();
    // We don't care if this succeeds.
    drop(io::stdin().read_to_end(&mut buf));
    Ok(())
}

```
