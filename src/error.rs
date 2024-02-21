use crate::wire::DisconnectReason;

use embedded_io_async::ReadExactError;

/// Set of possible protocol errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// The packet buffer was too small to hold a packet.
    BufferExhausted,
    /// The client sent an invalid identification string.
    BadIdentificationString,
    /// A string was not supplied in the required encoding.
    BadStringEncoding,
    /// A name list was found to contain an invalid name.
    BadNameList,
    /// A string had a length different than was expected.
    BadStringLength,
    /// There were some bytes left after object decoding.
    TrailingPayload,
    /// A malformed client packet was seen by the server.
    MalformedPacket,
    /// The channel's window overflowed during transfer.
    WindowOverflow,
}

impl From<core::str::Utf8Error> for ProtocolError {
    fn from(_: core::str::Utf8Error) -> Self {
        Self::BadStringEncoding
    }
}

/// Set of possible transport errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error<E> {
    /// The transport's stream reached EOF unexpectedly.
    UnexpectedEof,
    /// The transport's stream encountered an I/O error.
    IO(E),
    /// The transport encountered a fatal protocol error.
    Protocol(ProtocolError),
    /// The server ended communication by disconnecting.
    ServerDisconnect(DisconnectReason),
    /// The client ended communication by disconnecting.
    ClientDisconnect(DisconnectReason),
}

impl<E: embedded_io_async::Error> From<E> for Error<E> {
    fn from(value: E) -> Self {
        Self::IO(value)
    }
}

impl<E> From<ProtocolError> for Error<E> {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl<E: embedded_io_async::Error> From<ReadExactError<E>> for Error<E> {
    fn from(value: ReadExactError<E>) -> Self {
        match value {
            ReadExactError::UnexpectedEof => Self::UnexpectedEof,
            ReadExactError::Other(other_err) => other_err.into(),
        }
    }
}
