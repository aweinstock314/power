In one console:
```
$ RUSTFLAGS='-g' cargo build --release
    Finished release [optimized] target(s) in 0.0 secs
$ gdb ./target/release/power
GNU gdb (Debian 7.7.1+dfsg-5) 7.7.1
Copyright (C) 2014 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./target/release/power...done.
warning: Missing auto-load scripts referenced in section .debug_gdb_scripts
of file /home/avi/Documents/github_repos/power/target/release/power
Use `info auto-load python-scripts [REGEXP]' to list them.
(gdb) r 3000
Starting program: /home/avi/Documents/github_repos/power/target/release/power 3000
Dwarf Error: wrong version in compilation unit header (is 0, should be 2, 3, or 4) [in module /usr/lib/debug/.build-id/09/5935d2da92389e2991f2b56d14dab9e6978696.debug]
Dwarf Error: wrong version in compilation unit header (is 0, should be 2, 3, or 4) [in module /usr/lib/debug/.build-id/e4/8bb27b88670405041a12eefef9ef586f6e1533.debug]
Dwarf Error: wrong version in compilation unit header (is 0, should be 2, 3, or 4) [in module /usr/lib/debug/.build-id/93/5f7cac8894edac152c05cf83b2decf1097920e.debug]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Dwarf Error: wrong version in compilation unit header (is 0, should be 2, 3, or 4) [in module /usr/lib/debug/.build-id/4b/9cc30ba41f027a0dca6cd877f59f0db38f4025.debug]
[New Thread 0x7ffff65ff700 (LWP 21293)]
[New Thread 0x7ffff63fe700 (LWP 21294)]
[New Thread 0x7ffff5dff700 (LWP 21295)]
[New Thread 0x7ffff57ff700 (LWP 21296)]
current_num_threads: 4
openssl version info: "compiler: gcc -I. -I.. -I../include  -fPIC -DOPENSSL_PIC -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN -DTERMIO -g -O2 -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -Wl,-z,relro -Wa,--noexecstack -Wall -DMD32_REG_T=int -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM"
Err(Error { repr: Custom(Custom { kind: WouldBlock, error: StringError("would block") }) })
e.kind WouldBlock
Ok(163)
"/sha256?mask=000000000000000000000000000000000000000000000000000000000fffffff&goal=00000000000000000000000000000000000000000000000000000000deadbeef"
{}
mask: Some("000000000000000000000000000000000000000000000000000000000fffffff")
goal: Some("00000000000000000000000000000000000000000000000000000000deadbeef")
Ok(84)
Interleave::poll(StreamStep)
progress ping
returning Ok(NotReady)
Interleave::poll(StreamStep)
sent
flushed
returning Ok(NotReady)
Ok(6)
^C
Program received signal SIGINT, Interrupt.
0x00007ffff6c87fb3 in epoll_wait () from /lib/x86_64-linux-gnu/libc.so.6
(gdb) bt
#0  0x00007ffff6c87fb3 in epoll_wait () from /lib/x86_64-linux-gnu/libc.so.6
#1  0x00005555555dd834 in select (awakener=..., self=<optimized out>, evts=<optimized out>, timeout=...) at /home/avi/.cargo/registry/src/github.com-1ecc6299db9ec823/mio-0.6.6/src/sys/unix/epoll.rs:81
#2  poll2 (self=<optimized out>, events=<optimized out>, timeout=...) at /home/avi/.cargo/registry/src/github.com-1ecc6299db9ec823/mio-0.6.6/src/poll.rs:1086
#3  mio::poll::{{impl}}::poll (self=0x7ffff662d660, events=0x7fffffffcdf0, timeout=...) at /home/avi/.cargo/registry/src/github.com-1ecc6299db9ec823/mio-0.6.6/src/poll.rs:1050
#4  0x00005555555d6d10 in tokio_core::reactor::{{impl}}::poll (self=0x7fffffffcdf0, max_wait=...) at /home/avi/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-core-0.1.6/src/reactor/mod.rs:284
#5  0x00005555555b00c7 in run<futures::stream::for_each::ForEach<tokio_core::net::tcp::Incoming, closure, core::result::Result<(), std::io::error::Error>>> (self=<optimized out>, f=...)
    at /home/avi/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-core-0.1.6/src/reactor/mod.rs:249
#6  power::main () at /home/avi/Documents/github_repos/power/src/main.rs:397
#7  0x000055555560061b in panic_unwind::__rust_maybe_catch_panic () at /buildslave/rust-buildbot/slave/nightly-dist-rustc-linux/build/src/libpanic_unwind/lib.rs:98
#8  0x00005555555f9e17 in try<(),fn()> () at /buildslave/rust-buildbot/slave/nightly-dist-rustc-linux/build/src/libstd/panicking.rs:436
#9  catch_unwind<fn(),()> () at /buildslave/rust-buildbot/slave/nightly-dist-rustc-linux/build/src/libstd/panic.rs:361
#10 std::rt::lang_start () at /buildslave/rust-buildbot/slave/nightly-dist-rustc-linux/build/src/libstd/rt.rs:57
#11 0x00007ffff6bbf2b1 in __libc_start_main () from /lib/x86_64-linux-gnu/libc.so.6
#12 0x0000555555583faa in _start ()
(gdb) quit
A debugging session is active.

        Inferior 1 [process 21289] will be killed.

Quit anyway? (y or n) y
```

In another console:
```
$ time echo -e 'GET /sha256?mask='$(python -c 'print "00"*28+"0f"+"ff"*3')\&goal=$(python -c 'print "00"*28+"deadbeef"')' HTTP/1.0\n\n' | nc 0 3000
HTTP/1.1 200 OK
Date: Thu, 13 Apr 2017 01:56:37 GMT
Transfer-Encoding: chunked

1
x

real    0m9.472s
user    0m0.028s
sys     0m0.008s
```
