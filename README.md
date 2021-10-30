[![Build Status](https://travis-ci.org/luser/read-process-memory.svg?branch=master)](https://travis-ci.org/luser/read-process-memory) [![Build status](https://ci.appveyor.com/api/projects/status/9x0yse13l060659f/branch/master?svg=true)](https://ci.appveyor.com/project/luser/read-process-memory/branch/master) [![Build status](https://api.cirrus-ci.com/github/luser/read-process-memory.svg)] [![crates.io](https://img.shields.io/crates/v/read-process-memory.svg)](https://crates.io/crates/read-process-memory) [![](https://docs.rs/read-process-memory/badge.svg)](https://docs.rs/read-process-memory) [![Coverage Status](https://coveralls.io/repos/github/luser/read-process-memory/badge.svg?branch=master)](https://coveralls.io/github/luser/read-process-memory?branch=master)

A crate to read memory from another process. Code originally taken from Julia Evans' excellent [ruby-stacktrace](https://github.com/jvns/ruby-stacktrace/) project.

# Example

```rust, no_run
extern crate read_process_memory;

use std::convert::TryInto;
use std::io;
use read_process_memory::{Pid, ProcessHandle, CopyAddress, copy_address};

// Try to read `size` bytes at `address` from the process `pid`.
fn read_some_memory(pid: Pid, address: usize, size: usize) -> io::Result<()> {
    let handle: ProcessHandle = pid.try_into()?;
    let _bytes = copy_address(address, size, &handle)?;
    println!("Read {} bytes", size);
    Ok(())
}

fn main() {
    read_some_memory(123 as Pid, 0x100000, 100).unwrap();
}
```

# Documentation

[https://docs.rs/read-process-memory](https://docs.rs/read-process-memory)
