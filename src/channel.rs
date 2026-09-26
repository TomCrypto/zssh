use crate::transport::Transport;
use crate::types::{Behavior, Request, TransportError};
use crate::wire::into_u32;

/// Destination of data written to a channel.
#[derive(Debug, Clone, Copy)]
pub enum Pipe {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Channel associated with an SSH transport.
pub struct Channel<'a, 'b, T: Behavior> {
    transport: &'b mut Transport<'a, T>,
}

impl<'a, 'b, T: Behavior> Channel<'a, 'b, T> {
    pub(crate) fn new(transport: &'b mut Transport<'a, T>) -> Self {
        Self { transport }
    }

    /// Returns the request associated with this channel.
    pub fn request(&self) -> Request<T::Command> {
        self.transport.channel_request()
    }

    /// Returns the user associated with this channel.
    pub fn user(&self) -> T::User {
        self.transport.channel_user()
    }

    /// Returns the identification string of the client.
    pub fn client_ssh_id_string(&self) -> &str {
        self.transport.client_ssh_id_string()
    }

    /// Closes the channel with a given exit status.
    pub async fn exit(self, exit_status: u32) -> Result<(), TransportError<T>> {
        self.transport.channel_exit(exit_status).await
    }

    /// Obtains a reader over this channel.
    pub async fn reader(
        &mut self,
        len: Option<usize>,
    ) -> Result<Reader<'a, '_, T>, TransportError<T>> {
        self.transport.channel_adjust(len.map(into_u32)).await?;
        Ok(Reader::new(self.transport)) // must read until done
    }

    /// Convenience method for exact-or-until-EOF reads.
    ///
    /// This method reads up to an exact number of bytes from the channel, stopping early
    /// only in the case of EOF, and returns the number of bytes that were actually read.
    pub async fn read_exact_stdin(
        &mut self,
        mut bytes: &mut [u8],
    ) -> Result<usize, TransportError<T>> {
        if bytes.is_empty() {
            return Ok(0);
        }

        let read_len = bytes.len();

        let mut reader = self.reader(Some(read_len)).await?;

        while let Some(read) = reader.read().await? {
            let (dest, remaining) = bytes.split_at_mut(read.len());
            dest.copy_from_slice(read);
            bytes = remaining;
        }

        Ok(read_len - bytes.len())
    }

    /// Obtains a writer over this channel for the specified pipe.
    pub async fn writer(
        &mut self,
        pipe: Pipe,
        capacity: usize,
    ) -> Result<Writer<'a, '_, T>, TransportError<T>> {
        let writer = Writer::new(self.transport, pipe, capacity);
        let capacity = writer.capacity; // might have decreased!
        writer.transport.channel_write_window(capacity).await?;

        Ok(writer)
    }

    /// Obtains a writer over this channel for standard output.
    pub async fn stdout(
        &mut self,
        capacity: usize,
    ) -> Result<Writer<'a, '_, T>, TransportError<T>> {
        self.writer(Pipe::Stdout, capacity).await
    }

    /// Obtains a writer over this channel for standard error.
    pub async fn stderr(
        &mut self,
        capacity: usize,
    ) -> Result<Writer<'a, '_, T>, TransportError<T>> {
        self.writer(Pipe::Stderr, capacity).await
    }

    /// Convenience method that writes all bytes into standard output.
    pub async fn write_all_stdout(&mut self, bytes: &[u8]) -> Result<(), TransportError<T>> {
        Writer::new(self.transport, Pipe::Stdout, bytes.len())
            .write_all_internal(bytes)
            .await
    }

    /// Convenience method that writes all bytes into standard error.
    pub async fn write_all_stderr(&mut self, bytes: &[u8]) -> Result<(), TransportError<T>> {
        Writer::new(self.transport, Pipe::Stderr, bytes.len())
            .write_all_internal(bytes)
            .await
    }
}

/// Reader associated with an SSH channel.
pub struct Reader<'a, 'b, T: Behavior> {
    transport: &'b mut Transport<'a, T>,
}

impl<'a, 'b, T: Behavior> Reader<'a, 'b, T> {
    fn new(transport: &'b mut Transport<'a, T>) -> Self {
        Self { transport }
    }

    /// Reads data from the underlying channel.
    ///
    /// This method will never read more data than was originally requested upon
    /// construction of the reader object, or `Ok(None)` if no more data or EOF.
    pub async fn read(&mut self) -> Result<Option<&[u8]>, TransportError<T>> {
        self.transport.channel_read().await
    }

    /// Returns whether the channel's receiving half has reached EOF.
    pub fn is_eof(&mut self) -> bool {
        self.transport.channel_is_eof()
    }
}

/// Writer associated with an SSH channel.
pub struct Writer<'a, 'b, T: Behavior> {
    transport: &'b mut Transport<'a, T>,
    capacity: usize,
    pipe: Pipe,
}

impl<'a, 'b, T: Behavior> Writer<'a, 'b, T> {
    fn new(transport: &'b mut Transport<'a, T>, pipe: Pipe, capacity: usize) -> Self {
        let capacity = capacity.min(transport.channel_data_payload_buffer(pipe).len());

        Self {
            transport,
            capacity,
            pipe,
        }
    }

    /// Returns a byte slice into the packet buffer.
    pub fn buffer(&mut self) -> &mut [u8] {
        &mut self.transport.channel_data_payload_buffer(self.pipe)[..self.capacity]
    }

    /// Writes all requested bytes already present in the packet buffer.
    ///
    /// This will take the first `len` bytes in the byte slice returned
    /// by the `buffer()` method and send them as a single SSH message.
    pub async fn write_all(self, len: usize) -> Result<(), TransportError<T>> {
        assert!(len <= self.capacity, "write exceeds capacity");
        self.transport.channel_write_all(len, self.pipe).await?;

        Ok(())
    }

    async fn write_all_internal(mut self, bytes: &[u8]) -> Result<(), TransportError<T>> {
        if bytes.is_empty() {
            return Ok(());
        }

        for mut chunk in bytes.chunks(self.buffer().len()) {
            while !chunk.is_empty() {
                let window = self.transport.channel_write_window(1).await?;

                let len = chunk.len().min(window);
                self.buffer()[..len].copy_from_slice(&chunk[..len]);

                self.transport.channel_write_all(len, self.pipe).await?;
                chunk = &chunk[len..]; // write as many bytes as we can
            }
        }

        Ok(())
    }
}
