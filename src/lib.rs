//! This crate implements a minimal SSH server for embedded targets; please refer to
//! the project repository README.md for more information and for examples of usage.
//!
//! The library works in the following way:
//!
//!  1. Write a type implementing the `Behavior` trait as desired;
//!  2. Instantiate a `Transport` backed by some async I/O stream;
//!  3. Loop, receiving new client requests via `Channel` objects;
//!  4. Handle each request, reading or writing into the channel.
//!
//! The API is designed to be minimal and simple to use.

#![no_std]
#![forbid(missing_docs)]
#![forbid(unsafe_code)]

mod channel;
mod codec;
mod error;
mod transport;
mod types;
mod wire;

pub use channel::{Channel, Pipe, Reader, Writer};
pub use error::{Error, ProtocolError};
pub use transport::Transport;
pub use types::{AuthMethod, Behavior, PublicKey, Request, SecretKey, TransportError};
pub use wire::DisconnectReason;

fn unwrap_unreachable<T>(value: Option<T>) -> T {
    value.unwrap_or_else(|| unreachable!())
}

pub extern crate ed25519_dalek;
