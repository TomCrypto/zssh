use crate::error;
use crate::wire;

use ed25519_dalek::{SigningKey, VerifyingKey};
use embedded_io_async::{ErrorType, Read, Write};
use rand::{CryptoRng, Rng};

/// Secret key associated with a host server.
#[derive(Debug)]
pub enum SecretKey {
    Ed25519 { secret_key: SigningKey },
}

/// Public key associated with a user identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicKey {
    Ed25519 { public_key: VerifyingKey },
}

impl<'a> From<&'a PublicKey> for wire::PublicKey<'a> {
    fn from(value: &'a PublicKey) -> Self {
        match value {
            PublicKey::Ed25519 { public_key } => Self::Ed25519 {
                public_key: public_key.as_bytes(),
            },
        }
    }
}

/// Authentication method that a user may choose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMethod {
    None,
    PublicKey(PublicKey),
}

/// Request associated with an SSH channel.
#[derive(Clone, Copy, Debug)]
pub enum Request<T> {
    /// User requested a shell.
    Shell,
    /// User requested the execution of a command.
    Exec(T),
}

/// Description of aspects of the server's behavior.
pub trait Behavior {
    type Stream: Read + Write;

    /// The underlying stream type to be used.
    fn stream(&mut self) -> &mut Self::Stream;

    type Random: CryptoRng + Rng;

    /// The underlying random type to be used.
    fn random(&mut self) -> &mut Self::Random;

    /// The secret key advertised by the server.
    fn host_secret_key(&self) -> &SecretKey;

    /// The server's identification string.
    ///
    /// This will be sent to the client during the initial version handshake. It must
    /// comply with RFC4253 section 4.2 except it should not contain the final CR LF.
    fn server_id(&self) -> &'static str {
        "SSH-2.0-zssh_0.2.0"
    }

    /// Allow a given user to authenticate with a given auth method.
    ///
    /// Returns None if the user's auth method is not acceptable (e.g. public key does
    /// not match a whitelist), otherwise returns a type representing a user identity.
    ///
    /// This may be called more than once if the client uses probe requests.
    fn allow_user(&mut self, username: &str, auth_method: &AuthMethod) -> Option<Self::User>;

    type User: Clone;

    /// Whether to allow shell channel requests.
    ///
    /// Note that if this returns true, the server code must be prepared to handle shell
    /// requests by accepting interactive input in ways similar to a real shell process.
    fn allow_shell(&self) -> bool {
        false
    }

    type Command: Clone;

    /// Parse a user-supplied command string into a command.
    ///
    /// It is not permitted to "fail" to parse a command, instead just represent invalid
    /// commands as a "print usage" command variant so as to handle all possible inputs.
    fn parse_command(&mut self, command: &str) -> Self::Command;
}

/// Convenience type alias describing the transport error type for a given behavior type.
pub type TransportError<T> = error::Error<<<T as Behavior>::Stream as ErrorType>::Error>;
