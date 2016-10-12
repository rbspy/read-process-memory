[![Build Status](https://travis-ci.org/luser/read-process-memory.svg?branch=master)](https://travis-ci.org/luser/read-process-memory) [![Build status](https://ci.appveyor.com/api/projects/status/9x0yse13l060659f/branch/master?svg=true)](https://ci.appveyor.com/project/luser/read-process-memory/branch/master)

A crate to read memory from another process. Code originally taken from Julia Evans' excellent [ruby-stacktrace](https://github.com/jvns/ruby-stacktrace/) project.

# Example

```rust,no_run
extern crate read_process_memory;

use std::io;
use read_process_memory::{Pid, TryIntoProcessHandle, CopyAddress, copy_address};

// Try to read `size` bytes at `address` from the process `pid`.
fn read_some_memory(pid: Pid, address: usize, size: usize) -> io::Result<()> {
 let handle = try!(pid.try_into_process_handle());
 let _bytes = try!(copy_address(address, size, &handle));
 println!("Read {} bytes", size);
 Ok(())
}
```
