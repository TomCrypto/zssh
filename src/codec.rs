use crate::error::ProtocolError;
use crate::wire::{from_u32, into_u32, NameList};

use core::str::from_utf8;
use sha2::{digest::Output, Digest};

#[derive(Debug)]
pub struct ObjectWriter<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> ObjectWriter<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    pub fn write_byte(&mut self, value: u8) -> Result<(), ProtocolError> {
        self.write_byte_array(&[value])
    }

    pub fn write_byte_array(&mut self, value: &[u8]) -> Result<(), ProtocolError> {
        self.consume(value.len())?.copy_from_slice(value);

        Ok(())
    }

    pub fn write_boolean(&mut self, value: bool) -> Result<(), ProtocolError> {
        self.write_byte(if value { 1 } else { 0 })
    }

    pub fn write_uint32(&mut self, value: u32) -> Result<(), ProtocolError> {
        self.consume(4)?.copy_from_slice(&value.to_be_bytes());

        Ok(())
    }

    pub fn write_uint64(&mut self, value: u64) -> Result<(), ProtocolError> {
        self.consume(8)?.copy_from_slice(&value.to_be_bytes());

        Ok(())
    }

    pub fn write_string_len(&mut self, value: u32) -> Result<(), ProtocolError> {
        self.write_uint32(value)
    }

    pub fn write_string(&mut self, value: &[u8]) -> Result<(), ProtocolError> {
        self.write_string_len(into_u32(value.len()))?;
        self.write_byte_array(value)
    }

    pub fn write_name_list(&mut self, value: NameList) -> Result<(), ProtocolError> {
        self.write_string_utf8(value.as_str())
    }

    // Not an SSH data type, this is a "string" SSH type that has been validated
    // to be UTF-8 for convenience when interoperating with human-readable text.

    pub fn write_string_utf8(&mut self, value: &str) -> Result<(), ProtocolError> {
        self.write_string(value.as_bytes())
    }

    // Some objects contain nested objects which appear as ordinary string types
    // which themselves opaquely contain an (SSH) encoded object representation.

    pub fn write_nested<F>(&mut self, write_fn: F) -> Result<(), ProtocolError>
    where
        F: FnOnce(&mut ObjectWriter) -> Result<(), ProtocolError>,
    {
        if self.offset + 4 > self.buffer.len() {
            return Err(ProtocolError::BufferExhausted);
        }

        let mut writer = ObjectWriter::new(&mut self.buffer[self.offset + 4..]);
        write_fn(&mut writer)?; // let the lambda populate the buffer as desired

        let object_len = writer.into_written().len();

        self.write_string_len(into_u32(object_len))?;
        self.skip(object_len)?;

        Ok(())
    }

    pub fn skip(&mut self, len: usize) -> Result<(), ProtocolError> {
        let _ = self.consume(len)?;

        Ok(())
    }

    pub fn into_written(self) -> &'a [u8] {
        &self.buffer[..self.offset]
    }

    fn consume(&mut self, len: usize) -> Result<&mut [u8], ProtocolError> {
        if self.offset + len <= self.buffer.len() {
            let consumed = &mut self.buffer[self.offset..][..len];
            self.offset += len; // consider this slice as consumed

            Ok(consumed)
        } else {
            Err(ProtocolError::BufferExhausted)
        }
    }
}

#[derive(Debug)]
pub struct ObjectReader<'a> {
    buffer: &'a [u8],
}

impl<'a> ObjectReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    pub fn read_byte(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.consume(1)?[0])
    }

    pub fn read_byte_array<const N: usize>(&mut self) -> Result<&'a [u8; N], ProtocolError> {
        Ok(crate::unwrap_unreachable(self.consume(N)?.try_into()))
    }

    pub fn read_boolean(&mut self) -> Result<bool, ProtocolError> {
        Ok(self.read_byte()? != 0)
    }

    pub fn read_uint32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(*self.read_byte_array::<4>()?))
    }

    pub fn read_uint64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(*self.read_byte_array::<8>()?))
    }

    pub fn read_string(&mut self) -> Result<&'a [u8], ProtocolError> {
        let len = from_u32(self.read_uint32()?);
        self.consume(len) // read the bytes
    }

    pub fn read_string_fixed<const N: usize>(&mut self) -> Result<&'a [u8; N], ProtocolError> {
        let string = self.read_string()?; // and length check
        string
            .try_into()
            .map_err(|_| ProtocolError::BadStringLength)
    }

    // Not an SSH data type, this is a "string" SSH type that has been validated
    // to be UTF-8 for convenience when interoperating with human-readable text.

    pub fn read_string_utf8(&mut self) -> Result<&'a str, ProtocolError> {
        Ok(from_utf8(self.read_string()?)?)
    }

    // Not an SSH data type, this is a "string" SSH type that has been validated
    // to be US-ASCII with only printable characters, for use by internal names.

    pub fn read_internal_name(&mut self) -> Result<&'a str, ProtocolError> {
        let string = self.read_string_utf8()?;

        for &byte in string.as_bytes() {
            if byte >= 0x7F || byte <= 0x1F {
                return Err(ProtocolError::BadStringEncoding);
            }
        }

        Ok(string)
    }

    pub fn read_remaining(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.buffer)
    }

    fn consume(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        if self.buffer.len() >= len {
            let (consumed, remaining) = self.buffer.split_at(len);
            self.buffer = remaining; // advance to remaining bytes

            Ok(consumed)
        } else {
            Err(ProtocolError::BufferExhausted)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ObjectHasher<H> {
    hasher: H,
}

impl<H> ObjectHasher<H> {
    pub fn new(hasher: H) -> Self {
        Self { hasher }
    }
}

impl<H: Digest> ObjectHasher<H> {
    pub fn hash_byte(&mut self, value: u8) {
        self.hasher.update([value]);
    }

    pub fn hash_byte_array(&mut self, value: &[u8]) {
        self.hasher.update(value);
    }

    #[allow(dead_code)]
    pub fn hash_boolean(&mut self, value: bool) {
        self.hash_byte(if value { 1 } else { 0 })
    }

    pub fn hash_uint32(&mut self, value: u32) {
        self.hash_byte_array(&value.to_be_bytes());
    }

    #[allow(dead_code)]
    pub fn hash_uint64(&mut self, value: u64) {
        self.hash_byte_array(&value.to_be_bytes());
    }

    pub fn hash_string(&mut self, value: &[u8]) {
        self.hash_uint32(into_u32(value.len()));
        self.hash_byte_array(value);
    }

    pub fn hash_mpint(&mut self, value: &[u8]) {
        if value.is_empty() {
            self.hash_uint32(0);
        } else if value[0] & 0x80 != 0 {
            self.hash_uint32(into_u32(1 + value.len()));
            self.hash_byte(0x00);
            self.hash_byte_array(value);
        } else {
            let offset = value.iter().position(|&b| b != 0).unwrap_or(0);
            self.hash_uint32(into_u32(value.len() - offset));
            self.hash_byte_array(&value[offset..]);
        }
    }

    #[allow(dead_code)]
    pub fn hash_name_list(&mut self, value: NameList) {
        self.hash_string_utf8(value.as_str());
    }

    // Not an SSH data type, this is a "string" SSH type that has been validated
    // to be UTF-8 for convenience when interoperating with human-readable text.

    pub fn hash_string_utf8(&mut self, value: &str) {
        self.hash_string(value.as_bytes())
    }

    pub fn into_digest(self) -> Output<H> {
        self.hasher.finalize()
    }
}
