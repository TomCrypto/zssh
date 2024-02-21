# zssh

[![Documentation](https://docs.rs/zssh/badge.svg)](https://docs.rs/zssh)
[![Crates.io](https://img.shields.io/crates/v/zssh.svg)](https://crates.io/crates/zssh)

This crate contains a minimal SSH **server** implementation written in safe Rust targeted towards embedded devices. The distinguishing feature of this library is that it is simultaneously `no_std`, `no_alloc` and `async` and implements a useful subset of the SSH specification with very low memory usage. As of now I am not aware of any other public Rust implementation with these characteristics.

 - `#![no_std]`
 - `#![forbid(unsafe_code)]`
 - Zero heap allocations
 - Uses asynchronous I/O
 - Compiles on `stable`

This library is still in early development. Features may be added and the API may change in breaking ways! Pull requests and issues are welcome.

## Protocol Features

| Feature           | Status                | Details                               |
| ---:              | :---:                 | ---:                                  |
| Key Exchange      | :heavy_check_mark:    | `curve25519-sha256`                   |
| Host Key          | :heavy_check_mark:    | `ssh-ed25519`                         |
| Encryption        | :heavy_check_mark:    | `aes128-ctr`                          |
| Integrity         | :heavy_check_mark:    | `hmac-256`                            |
| Compression       | :x:                   | `none`                                |
| Authentication    | :heavy_check_mark:    | Currently single-user.                |
| Public-Key Auth   | :heavy_check_mark:    | `ssh-ed25519`                         |
| Password Auth     | :x:                   | Could be added later.                 |
| Client Env-vars   | :x:                   | Currently ignored.                    |
| Exec Requests     | :heavy_check_mark:    | You must parse the command.           |
| Shell Requests    | :heavy_check_mark:    | You must implement the shell.         |
| PTY, X11, TCP     | :x:                   | **Will not be implemented.**          |
| Multiplexing      | :heavy_check_mark:    | Open channels are serialized.         |
| Rekeying          | :heavy_check_mark:    | As initiated by the client.           |

## Compatibility

The goal of the library is to achieve SSH connectivity with a minimally low memory and code footprint, thus it implements a small yet modern suite of cryptographic algorithms which will be understood by most clients from the past decade or so.

## Usage

The example in `examples/demo.rs` will set up a local SSH server running on localhost on port 2222. You can connect to it using the `zssh` username with the private key in `examples/zssh.priv` as an SSH identity. The example supports three commands, demonstrating different aspects of the API:

 1. `sha256sum` computes the SHA-256 digest of stdin and returns it on stdout;
 2. `echo` sends stdin back to stdout unchanged;
 3. `sum` prints out the sum of all numbers passed on the command-line;

The example uses Tokio only for the purposes of running on any operating system.

## Design Notes

The API has been guided by certain design constraints, some of which are described in this section.

### Reading

Because of the no-allocation requirement, it is not possible for a channel to have a non-zero recv window without forcing you to read from the channel. This is because receiving a data message prevents making any further progress until that message is processed, or its payload lost.

This constraint implies that you must specify an exact read length for all channel reads unless you are willing to never read again from the channel after you write to it. In the API, this manifests as `Channel::reader` taking an optional size, with the following semantics:

 - if a size is provided, the reader object will read up to that much, and you can still read and write on the channel afterwards;
 - otherwise, it will read up to EOF, but you can **never** call `Channel::reader` again on the channel once you drop the reader.

Also note the possible performance implications due to how the recv window is advertised to the client. If a size is provided to the reader, we will advertise that size as our recv window, so the client may not submit more than that many bytes at a time. If no size is provided to the reader, we will maintain a recv window of 2^32 - 1 bytes, the maximum allowed by the protocol, allowing the client to send unlimited amounts of data.

### Writing

Because of the no-allocation requirement, it is not possible for the transport to buffer writes internally, as it would have no way to service non-channel-related messages (such as periodic rekeying requests from the client) without trashing the packet buffer. Therefore, in the API, any individual call to `Channel::write_all_stdout` or `Channel::write_all_stderr` translates to at least one SSH protocol-level message.

The API offers a zero-copy feature in the form of `Channel::writer` which allows the caller to directly write data into the packet buffer for sending. This both avoids copies and allows the caller to buffer as much data as it can to fit into a single SSH protocol-level message as desired.

However, please note that:

 - the `Writer::write_all` method consumes the writer, this is by design as once the data is ready to be sent, it is encrypted in-place by the transport; this is to avoid an API footgun and has no performance implications since `Channel::writer` does no work;
 - as a corollary to the previous point, callers must assume that `Writer::buffer` contains garbage, it is **not** zeroed out by the crate!

## Performance

The library depends on the async I/O traits from [`embedded-io-async`](https://crates.io/crates/embedded-io-async) and is written in an essentially zero-copy fashion. It is expected the main performance bottleneck will simply be the transport-layer encryption overhead. In terms of memory usage, the transport borrows an externally-provided byte slice which it will use as a packet buffer, while its internal state machine requires around 2-3kB of memory (most of it consisting of cryptographic key material) with low stack usage.

While the SSH specification mandates a minimum packet buffer size of around 32kB, in practice most clients will work out of the box with sizes as low as 4kB, and even smaller packet buffers can be made to work with suitably configured clients; in general, the limiting factor is the size of the client's initial KEXINIT message.

This makes `zssh` usable on the vast majority of embedded targets where running an SSH server would make sense to begin with.

## Multiplexing

The library supports the ability to handle multiple concurrent channels on the same connection. It does this by only processing one channel at a time and delaying responding to further channel open requests. This is done so that clients can use multiplexing for better end-user experience even if the server only supports a single TCP connection. Currently, the transport is hardcoded such that up to four channels can be pending while one is active. Additional channel open requests beyond this limit will be rejected by the transport.
