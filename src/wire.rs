use crate::codec::{ObjectReader, ObjectWriter};
use crate::error::ProtocolError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message<'a> {
    ServiceRequest {
        service_name: &'a str,
    },
    ServiceAccept {
        service_name: &'a str,
    },
    Disconnect {
        reason: DisconnectReason,
    },
    Ignore {
        data: &'a [u8],
    },
    Debug {
        always_display: bool,
        message: &'a str,
        language_tag: &'a str,
    },
    Unimplemented {
        sequence_number: u32,
    },
    KexInit {
        cookie: &'a [u8; 16],
        kex_algorithms: NameList<'a>,
        server_host_key_algorithms: NameList<'a>,
        encryption_algorithms_client_to_server: NameList<'a>,
        encryption_algorithms_server_to_client: NameList<'a>,
        mac_algorithms_client_to_server: NameList<'a>,
        mac_algorithms_server_to_client: NameList<'a>,
        compression_algorithms_client_to_server: NameList<'a>,
        compression_algorithms_server_to_client: NameList<'a>,
        languages_client_to_server: NameList<'a>,
        languages_server_to_client: NameList<'a>,
        first_kex_packet_follows: bool,
        reserved: u32,
    },
    NewKeys,
    KexEcdhInit {
        client_ephemeral_public_key: &'a [u8],
    },
    KexEcdhReply {
        server_public_host_key: PublicKey<'a>,
        server_ephemeral_public_key: &'a [u8],
        signature: Signature<'a>,
    },
    UserAuthRequest {
        user_name: &'a str,
        service_name: &'a str,
        auth_method: AuthMethod<'a>,
    },
    UserAuthFailure {
        authentications_that_can_continue: NameList<'a>,
        partial_success: bool,
    },
    UserAuthSuccess,
    UserAuthBanner {
        message: &'a str,
        language: &'a str,
    },
    UserAuthPkOk {
        public_key_algorithm_name: &'a str,
        public_key: PublicKey<'a>,
    },
    GlobalRequest {
        request_name: &'a str,
        want_reply: bool,
        payload: &'a [u8],
    },
    RequestSuccess {
        payload: &'a [u8],
    },
    RequestFailure,
    ChannelOpen {
        channel: ChannelType<'a>,
    },
    ChannelOpenConfirmation {
        recipient_channel: u32,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
        payload: &'a [u8],
    },
    ChannelOpenFailure {
        recipient_channel: u32,
        reason: ChannelOpenFailureReason,
    },
    ChannelWindowAdjust {
        recipient_channel: u32,
        bytes_to_add: u32,
    },
    ChannelData {
        recipient_channel: u32,
        data: Data<'a>,
    },
    ChannelExtendedData {
        recipient_channel: u32,
        data: ExtendedData<'a>,
    },
    ChannelEof {
        recipient_channel: u32,
    },
    ChannelClose {
        recipient_channel: u32,
    },
    ChannelRequest {
        recipient_channel: u32,
        request: Request<'a>,
    },
    ChannelSuccess {
        recipient_channel: u32,
    },
    ChannelFailure {
        recipient_channel: u32,
    },
    Unknown {
        message: u8,
        payload: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelType<'a> {
    Session {
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
    },
    Other {
        channel_type: &'a str,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
        payload: &'a [u8],
    },
}

impl<'a> ChannelType<'a> {
    pub fn decode_with(reader: &mut ObjectReader<'a>) -> Result<Self, ProtocolError> {
        let decoded = match reader.read_string_utf8()? {
            "session" => Self::Session {
                sender_channel: reader.read_uint32()?,
                initial_window_size: reader.read_uint32()?,
                maximum_packet_size: reader.read_uint32()?,
            },
            channel_type => Self::Other {
                channel_type,
                sender_channel: reader.read_uint32()?,
                initial_window_size: reader.read_uint32()?,
                maximum_packet_size: reader.read_uint32()?,
                payload: reader.read_remaining(),
            },
        };

        Ok(decoded)
    }

    pub fn encode_with(self, writer: &mut ObjectWriter) -> Result<(), ProtocolError> {
        match self {
            Self::Session {
                sender_channel,
                initial_window_size,
                maximum_packet_size,
            } => {
                writer.write_string_utf8("session")?;
                writer.write_uint32(sender_channel)?;
                writer.write_uint32(initial_window_size)?;
                writer.write_uint32(maximum_packet_size)?;
            }
            Self::Other {
                channel_type,
                sender_channel,
                initial_window_size,
                maximum_packet_size,
                payload,
            } => {
                writer.write_string_utf8(channel_type)?;
                writer.write_uint32(sender_channel)?;
                writer.write_uint32(initial_window_size)?;
                writer.write_uint32(maximum_packet_size)?;
                writer.write_byte_array(payload)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    Env {
        want_reply: bool,
        variable_name: &'a str,
        variable_value: &'a str,
    },
    Shell {
        want_reply: bool,
    },
    Exec {
        want_reply: bool,
        command: &'a str,
    },
    ExitStatus {
        want_reply: bool,
        exit_status: u32,
    },
    Other {
        request_type: &'a str,
        want_reply: bool,
        payload: &'a [u8],
    },
}

impl<'a> Request<'a> {
    pub fn decode_with(reader: &mut ObjectReader<'a>) -> Result<Self, ProtocolError> {
        let decoded = match reader.read_string_utf8()? {
            "env" => Self::Env {
                want_reply: reader.read_boolean()?,
                variable_name: reader.read_string_utf8()?,
                variable_value: reader.read_string_utf8()?,
            },
            "shell" => Self::Shell {
                want_reply: reader.read_boolean()?,
            },
            "exec" => Self::Exec {
                want_reply: reader.read_boolean()?,
                command: reader.read_string_utf8()?,
            },
            "exit-status" => Self::ExitStatus {
                want_reply: reader.read_boolean()?,
                exit_status: reader.read_uint32()?,
            },
            request_type => Self::Other {
                request_type,
                want_reply: reader.read_boolean()?,
                payload: reader.read_remaining(),
            },
        };

        Ok(decoded)
    }

    pub fn encode_with(self, writer: &mut ObjectWriter) -> Result<(), ProtocolError> {
        match self {
            Self::Env {
                want_reply,
                variable_name,
                variable_value,
            } => {
                writer.write_string_utf8("env")?;
                writer.write_boolean(want_reply)?;
                writer.write_string_utf8(variable_name)?;
                writer.write_string_utf8(variable_value)?;
            }
            Self::Shell { want_reply } => {
                writer.write_string_utf8("shell")?;
                writer.write_boolean(want_reply)?;
            }
            Self::Exec {
                want_reply,
                command,
            } => {
                writer.write_string_utf8("exec")?;
                writer.write_boolean(want_reply)?;
                writer.write_string_utf8(command)?;
            }
            Self::ExitStatus {
                want_reply,
                exit_status,
            } => {
                writer.write_string_utf8("exit-status")?;
                writer.write_boolean(want_reply)?;
                writer.write_uint32(exit_status)?;
            }
            Self::Other {
                request_type,
                want_reply,
                payload,
            } => {
                writer.write_string_utf8(request_type)?;
                writer.write_boolean(want_reply)?;
                writer.write_byte_array(payload)?;
            }
        }

        Ok(())
    }

    pub fn want_reply(self) -> bool {
        match self {
            Self::Env { want_reply, .. } => want_reply,
            Self::Shell { want_reply } => want_reply,
            Self::Exec { want_reply, .. } => want_reply,
            Self::ExitStatus { want_reply, .. } => want_reply,
            Self::Other { want_reply, .. } => want_reply,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Data<'a> {
    Borrowed { bytes: &'a [u8] },
    InPlace { len: u32 },
}

impl<'a> Data<'a> {
    pub fn decode_with(reader: &mut ObjectReader<'a>) -> Result<Self, ProtocolError> {
        let decoded = Self::Borrowed {
            bytes: reader.read_string()?,
        };

        Ok(decoded)
    }

    pub fn encode_with(self, writer: &mut ObjectWriter) -> Result<(), ProtocolError> {
        match self {
            Self::Borrowed { bytes } => {
                writer.write_string(bytes)?;
            }
            Self::InPlace { len } => {
                writer.write_string_len(len)?;
                writer.skip(from_u32(len))?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtendedData<'a> {
    Stderr { data: Data<'a> },
    Other { data_type_code: u32, data: Data<'a> },
}

impl<'a> ExtendedData<'a> {
    pub fn decode_with(reader: &mut ObjectReader<'a>) -> Result<Self, ProtocolError> {
        let decoded = match reader.read_uint32()? {
            1 => Self::Stderr {
                data: Data::decode_with(reader)?,
            },
            data_type_code => Self::Other {
                data_type_code,
                data: Data::decode_with(reader)?,
            },
        };

        Ok(decoded)
    }

    pub fn encode_with(self, writer: &mut ObjectWriter) -> Result<(), ProtocolError> {
        match self {
            Self::Stderr { data } => {
                writer.write_uint32(1)?;
                data.encode_with(writer)?;
            }
            Self::Other {
                data_type_code,
                data,
            } => {
                writer.write_uint32(data_type_code)?;
                data.encode_with(writer)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMethod<'a> {
    PublicKey {
        public_key_algorithm_name: &'a str,
        public_key: PublicKey<'a>,
        signature: Option<Signature<'a>>,
    },
    Unsupported {
        method_name: &'a str,
        payload: &'a [u8],
    },
    None,
}

impl<'a> AuthMethod<'a> {
    pub fn decode_with(reader: &mut ObjectReader<'a>) -> Result<Self, ProtocolError> {
        let decoded = match reader.read_string_utf8()? {
            "publickey" => {
                let has_signature = reader.read_boolean()?;

                let public_key_algorithm_name = reader.read_string_utf8()?;
                let public_key = PublicKey::decode_with(reader)?;

                let signature = if has_signature {
                    Some(Signature::decode_with(reader)?)
                } else {
                    None
                };

                AuthMethod::PublicKey {
                    public_key_algorithm_name,
                    public_key,
                    signature,
                }
            }
            "none" => AuthMethod::None,
            method_name => AuthMethod::Unsupported {
                method_name,
                payload: reader.read_remaining(),
            },
        };

        Ok(decoded)
    }

    pub fn encode_with(self, writer: &mut ObjectWriter) -> Result<(), ProtocolError> {
        match self {
            AuthMethod::PublicKey {
                public_key_algorithm_name,
                public_key,
                signature,
            } => {
                writer.write_string_utf8("publickey")?;
                writer.write_boolean(signature.is_some())?;
                writer.write_string_utf8(public_key_algorithm_name)?;
                public_key.encode_with(writer)?;

                if let Some(signature) = signature {
                    signature.encode_with(writer)?;
                }
            }
            AuthMethod::Unsupported {
                method_name,
                payload,
            } => {
                writer.write_string_utf8(method_name)?;
                writer.write_string(payload)?;
            }
            AuthMethod::None => {
                writer.write_string_utf8("none")?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicKey<'a> {
    Ed25519 {
        public_key: &'a [u8; 32],
    },
    Other {
        identifier: &'a str,
        payload: &'a [u8],
    },
}

impl<'a> PublicKey<'a> {
    pub fn decode_with(reader: &mut ObjectReader<'a>) -> Result<Self, ProtocolError> {
        let mut reader = ObjectReader::new(reader.read_string()?);

        let decoded = match reader.read_string_utf8()? {
            "ssh-ed25519" => Self::Ed25519 {
                public_key: reader.read_string_fixed::<32>()?,
            },
            identifier => Self::Other {
                identifier,
                payload: reader.read_remaining(),
            },
        };

        if reader.read_remaining().is_empty() {
            Ok(decoded)
        } else {
            Err(ProtocolError::TrailingPayload)
        }
    }

    pub fn encode_with(self, writer: &mut ObjectWriter) -> Result<(), ProtocolError> {
        writer.write_nested(|writer| {
            match self {
                Self::Ed25519 { public_key } => {
                    writer.write_string_utf8("ssh-ed25519")?;
                    writer.write_string(public_key)?;
                }
                Self::Other {
                    identifier,
                    payload,
                } => {
                    writer.write_string_utf8(identifier)?;
                    writer.write_string(payload)?;
                }
            }

            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Signature<'a> {
    Ed25519 {
        signature: &'a [u8; 64],
    },
    Other {
        identifier: &'a str,
        payload: &'a [u8],
    },
}

impl<'a> Signature<'a> {
    pub fn decode_with(reader: &mut ObjectReader<'a>) -> Result<Self, ProtocolError> {
        let mut reader = ObjectReader::new(reader.read_string()?);

        let decoded = match reader.read_string_utf8()? {
            "ssh-ed25519" => Self::Ed25519 {
                signature: reader.read_string_fixed::<64>()?,
            },
            identifier => Self::Other {
                identifier,
                payload: reader.read_remaining(),
            },
        };

        if reader.read_remaining().is_empty() {
            Ok(decoded)
        } else {
            Err(ProtocolError::TrailingPayload)
        }
    }

    pub fn encode_with(self, writer: &mut ObjectWriter) -> Result<(), ProtocolError> {
        writer.write_nested(|writer| {
            match self {
                Self::Ed25519 { signature } => {
                    writer.write_string_utf8("ssh-ed25519")?;
                    writer.write_string(signature)?;
                }
                Self::Other {
                    identifier,
                    payload,
                } => {
                    writer.write_string_utf8(identifier)?;
                    writer.write_string(payload)?;
                }
            }

            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NameList<'a> {
    string: &'a str,
}

impl<'a> NameList<'a> {
    pub fn new_from_string(string: &'a str) -> Result<Self, ProtocolError> {
        if !string.is_ascii() {
            return Err(ProtocolError::BadStringEncoding);
        }

        if string
            .as_bytes()
            .windows(2)
            .any(|window| window == [b','; 2])
        {
            Err(ProtocolError::BadNameList)
        } else {
            Ok(Self { string })
        }
    }

    pub fn is_empty(&self) -> bool {
        self.string.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.string.split(',')
    }

    pub fn as_str(&self) -> &'a str {
        self.string
    }

    pub fn find(&self, name: &str) -> Option<usize> {
        self.iter().position(|item| item == name)
    }

    pub fn decode_with(reader: &mut ObjectReader<'a>) -> Result<Self, ProtocolError> {
        Self::new_from_string(reader.read_string_utf8()?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelOpenFailureReason {
    AdministrativelyProhibited,
    ConnectFailed,
    UnknownChannelType,
    ResourceShortage,
    Other(u32),
}

impl ChannelOpenFailureReason {
    pub fn decode_with(reader: &mut ObjectReader) -> Result<Self, ProtocolError> {
        let reason_code = reader.read_uint32()?;
        let _description = reader.read_string_utf8()?;
        let _language_tag = reader.read_string_utf8()?;

        Ok(Self::from_reason_code(reason_code))
    }

    pub fn encode_with(self, writer: &mut ObjectWriter) -> Result<(), ProtocolError> {
        writer.write_uint32(self.into_reason_code())?;
        writer.write_string_utf8(self.description())?;
        writer.write_string_utf8("en-US")?;

        Ok(())
    }

    pub fn into_reason_code(self) -> u32 {
        match self {
            Self::AdministrativelyProhibited => 1,
            Self::ConnectFailed => 2,
            Self::UnknownChannelType => 3,
            Self::ResourceShortage => 4,
            Self::Other(reason_code) => reason_code,
        }
    }

    pub fn from_reason_code(reason_code: u32) -> Self {
        match reason_code {
            1 => Self::AdministrativelyProhibited,
            2 => Self::ConnectFailed,
            3 => Self::UnknownChannelType,
            4 => Self::ResourceShortage,
            _ => Self::Other(reason_code),
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::AdministrativelyProhibited => "Administratively prohibited",
            Self::ConnectFailed => "Connect failed",
            Self::UnknownChannelType => "Unknown channel type",
            Self::ResourceShortage => "Resource shortage",
            Self::Other(_) => "No description available",
        }
    }
}

/// Set of possible disconnection reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectReason {
    /// Standard RFC4253 disconnect reason.
    HostNotAllowedToConnect,
    /// Standard RFC4253 disconnect reason.
    ProtocolError,
    /// Standard RFC4253 disconnect reason.
    KeyExchangeFailed,
    /// Standard RFC4253 disconnect reason.
    Reserved,
    /// Standard RFC4253 disconnect reason.
    MacError,
    /// Standard RFC4253 disconnect reason.
    CompressionError,
    /// Standard RFC4253 disconnect reason.
    ServiceNotAvailable,
    /// Standard RFC4253 disconnect reason.
    ProtocolVersionNotSupported,
    /// Standard RFC4253 disconnect reason.
    HostKeyNotVerifiable,
    /// Standard RFC4253 disconnect reason.
    ConnectionLost,
    /// Standard RFC4253 disconnect reason.
    ByApplication,
    /// Standard RFC4253 disconnect reason.
    TooManyConnections,
    /// Standard RFC4253 disconnect reason.
    AuthCancelledByUser,
    /// Standard RFC4253 disconnect reason.
    NoMoreAuthMethodsAvailable,
    /// Standard RFC4253 disconnect reason.
    IllegalUserName,
    /// Some other disconnect reason.
    Other(u32),
}

impl DisconnectReason {
    /// Decodes an instance of this type from an object reader.
    pub fn decode_with(reader: &mut ObjectReader) -> Result<Self, ProtocolError> {
        let reason_code = reader.read_uint32()?;
        let _description = reader.read_string_utf8()?;
        let _language_tag = reader.read_string_utf8()?;

        Ok(Self::from_reason_code(reason_code))
    }

    /// Encodes this instance into an object writer.
    pub fn encode_with(self, writer: &mut ObjectWriter) -> Result<(), ProtocolError> {
        writer.write_uint32(self.into_reason_code())?;
        writer.write_string_utf8(self.description())?;
        writer.write_string_utf8("en-US")?;

        Ok(())
    }

    /// Retrieves the underlying reason code.
    pub fn into_reason_code(self) -> u32 {
        match self {
            Self::HostNotAllowedToConnect => 1,
            Self::ProtocolError => 2,
            Self::KeyExchangeFailed => 3,
            Self::Reserved => 4,
            Self::MacError => 5,
            Self::CompressionError => 6,
            Self::ServiceNotAvailable => 7,
            Self::ProtocolVersionNotSupported => 8,
            Self::HostKeyNotVerifiable => 9,
            Self::ConnectionLost => 10,
            Self::ByApplication => 11,
            Self::TooManyConnections => 12,
            Self::AuthCancelledByUser => 13,
            Self::NoMoreAuthMethodsAvailable => 14,
            Self::IllegalUserName => 15,
            Self::Other(reason_code) => reason_code,
        }
    }

    /// Constructs an instance of this type from a reason code.
    pub fn from_reason_code(reason_code: u32) -> Self {
        match reason_code {
            1 => Self::HostNotAllowedToConnect,
            2 => Self::ProtocolError,
            3 => Self::KeyExchangeFailed,
            4 => Self::Reserved,
            5 => Self::MacError,
            6 => Self::CompressionError,
            7 => Self::ServiceNotAvailable,
            8 => Self::ProtocolVersionNotSupported,
            9 => Self::HostKeyNotVerifiable,
            10 => Self::ConnectionLost,
            11 => Self::ByApplication,
            12 => Self::TooManyConnections,
            13 => Self::AuthCancelledByUser,
            14 => Self::NoMoreAuthMethodsAvailable,
            15 => Self::IllegalUserName,
            _ => Self::Other(reason_code),
        }
    }

    /// Retrieves a description message for this disconnect reason instance.
    pub fn description(self) -> &'static str {
        match self {
            Self::HostNotAllowedToConnect => "Host not allowed to connect",
            Self::ProtocolError => "Protocol error",
            Self::KeyExchangeFailed => "Key exchange failed",
            Self::Reserved => "Reserved",
            Self::MacError => "MAC error",
            Self::CompressionError => "Compression error",
            Self::ServiceNotAvailable => "Service not available",
            Self::ProtocolVersionNotSupported => "Protocol version not supported",
            Self::HostKeyNotVerifiable => "Host key not verifiable",
            Self::ConnectionLost => "Connection lost",
            Self::ByApplication => "By application",
            Self::TooManyConnections => "Too many connections",
            Self::AuthCancelledByUser => "Auth cancelled by user",
            Self::NoMoreAuthMethodsAvailable => "No more auth methods available",
            Self::IllegalUserName => "Illegal user name",
            Self::Other(_) => "No description available",
        }
    }
}

pub const MSG_SERVICE_REQUEST: u8 = 5;
pub const MSG_SERVICE_ACCEPT: u8 = 6;
pub const MSG_DISCONNECT: u8 = 1;
pub const MSG_IGNORE: u8 = 2;
pub const MSG_DEBUG: u8 = 4;
pub const MSG_UNIMPLEMENTED: u8 = 3;
pub const MSG_KEX_INIT: u8 = 20;
pub const MSG_NEW_KEYS: u8 = 21;
pub const MSG_KEX_ECDH_INIT: u8 = 30;
pub const MSG_KEX_ECDH_REPLY: u8 = 31;
pub const MSG_USERAUTH_REQUEST: u8 = 50;
pub const MSG_USERAUTH_FAILURE: u8 = 51;
pub const MSG_USERAUTH_SUCCESS: u8 = 52;
pub const MSG_USERAUTH_BANNER: u8 = 53;
pub const MSG_USERAUTH_PK_OK: u8 = 60;
pub const MSG_GLOBAL_REQUEST: u8 = 80;
pub const MSG_REQUEST_SUCCESS: u8 = 81;
pub const MSG_REQUEST_FAILURE: u8 = 82;
pub const MSG_CHANNEL_OPEN: u8 = 90;
pub const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const MSG_CHANNEL_DATA: u8 = 94;
pub const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const MSG_CHANNEL_EOF: u8 = 96;
pub const MSG_CHANNEL_CLOSE: u8 = 97;
pub const MSG_CHANNEL_REQUEST: u8 = 98;
pub const MSG_CHANNEL_SUCCESS: u8 = 99;
pub const MSG_CHANNEL_FAILURE: u8 = 100;

impl<'a> Message<'a> {
    pub fn decode(buffer: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut reader = ObjectReader::new(buffer);

        let decoded = match reader.read_byte()? {
            MSG_SERVICE_REQUEST => Self::ServiceRequest {
                service_name: reader.read_internal_name()?,
            },
            MSG_SERVICE_ACCEPT => Self::ServiceAccept {
                service_name: reader.read_internal_name()?,
            },
            MSG_DISCONNECT => Self::Disconnect {
                reason: DisconnectReason::decode_with(&mut reader)?,
            },
            MSG_IGNORE => Self::Ignore {
                data: reader.read_string()?,
            },
            MSG_DEBUG => Self::Debug {
                always_display: reader.read_boolean()?,
                message: reader.read_string_utf8()?,
                language_tag: reader.read_string_utf8()?,
            },
            MSG_UNIMPLEMENTED => Self::Unimplemented {
                sequence_number: reader.read_uint32()?,
            },
            MSG_NEW_KEYS => Self::NewKeys,
            MSG_KEX_INIT => Self::KexInit {
                cookie: reader.read_byte_array::<16>()?,
                kex_algorithms: NameList::decode_with(&mut reader)?,
                server_host_key_algorithms: NameList::decode_with(&mut reader)?,
                encryption_algorithms_client_to_server: NameList::decode_with(&mut reader)?,
                encryption_algorithms_server_to_client: NameList::decode_with(&mut reader)?,
                mac_algorithms_client_to_server: NameList::decode_with(&mut reader)?,
                mac_algorithms_server_to_client: NameList::decode_with(&mut reader)?,
                compression_algorithms_client_to_server: NameList::decode_with(&mut reader)?,
                compression_algorithms_server_to_client: NameList::decode_with(&mut reader)?,
                languages_client_to_server: NameList::decode_with(&mut reader)?,
                languages_server_to_client: NameList::decode_with(&mut reader)?,
                first_kex_packet_follows: reader.read_boolean()?,
                reserved: reader.read_uint32()?,
            },
            MSG_KEX_ECDH_INIT => Self::KexEcdhInit {
                client_ephemeral_public_key: reader.read_string()?,
            },
            MSG_KEX_ECDH_REPLY => Self::KexEcdhReply {
                server_public_host_key: PublicKey::decode_with(&mut reader)?,
                server_ephemeral_public_key: reader.read_string()?,
                signature: Signature::decode_with(&mut reader)?,
            },
            MSG_USERAUTH_REQUEST => Self::UserAuthRequest {
                user_name: reader.read_string_utf8()?,
                service_name: reader.read_string_utf8()?,
                auth_method: AuthMethod::decode_with(&mut reader)?,
            },
            MSG_USERAUTH_FAILURE => Self::UserAuthFailure {
                authentications_that_can_continue: NameList::decode_with(&mut reader)?,
                partial_success: reader.read_boolean()?,
            },
            MSG_USERAUTH_SUCCESS => Self::UserAuthSuccess,
            MSG_USERAUTH_BANNER => Self::UserAuthBanner {
                message: reader.read_string_utf8()?,
                language: reader.read_string_utf8()?,
            },
            MSG_USERAUTH_PK_OK => Self::UserAuthPkOk {
                public_key_algorithm_name: reader.read_string_utf8()?,
                public_key: PublicKey::decode_with(&mut reader)?,
            },
            MSG_GLOBAL_REQUEST => Self::GlobalRequest {
                request_name: reader.read_string_utf8()?,
                want_reply: reader.read_boolean()?,
                payload: reader.read_remaining(),
            },
            MSG_REQUEST_SUCCESS => Self::RequestSuccess {
                payload: reader.read_remaining(),
            },
            MSG_REQUEST_FAILURE => Self::RequestFailure,
            MSG_CHANNEL_OPEN => Self::ChannelOpen {
                channel: ChannelType::decode_with(&mut reader)?,
            },
            MSG_CHANNEL_OPEN_CONFIRMATION => Self::ChannelOpenConfirmation {
                recipient_channel: reader.read_uint32()?,
                sender_channel: reader.read_uint32()?,
                initial_window_size: reader.read_uint32()?,
                maximum_packet_size: reader.read_uint32()?,
                payload: reader.read_remaining(),
            },
            MSG_CHANNEL_OPEN_FAILURE => Self::ChannelOpenFailure {
                recipient_channel: reader.read_uint32()?,
                reason: ChannelOpenFailureReason::decode_with(&mut reader)?,
            },
            MSG_CHANNEL_WINDOW_ADJUST => Self::ChannelWindowAdjust {
                recipient_channel: reader.read_uint32()?,
                bytes_to_add: reader.read_uint32()?,
            },
            MSG_CHANNEL_DATA => Self::ChannelData {
                recipient_channel: reader.read_uint32()?,
                data: Data::decode_with(&mut reader)?,
            },
            MSG_CHANNEL_EXTENDED_DATA => Self::ChannelExtendedData {
                recipient_channel: reader.read_uint32()?,
                data: ExtendedData::decode_with(&mut reader)?,
            },
            MSG_CHANNEL_EOF => Self::ChannelEof {
                recipient_channel: reader.read_uint32()?,
            },
            MSG_CHANNEL_CLOSE => Self::ChannelClose {
                recipient_channel: reader.read_uint32()?,
            },
            MSG_CHANNEL_REQUEST => Self::ChannelRequest {
                recipient_channel: reader.read_uint32()?,
                request: Request::decode_with(&mut reader)?,
            },
            MSG_CHANNEL_SUCCESS => Self::ChannelSuccess {
                recipient_channel: reader.read_uint32()?,
            },
            MSG_CHANNEL_FAILURE => Self::ChannelFailure {
                recipient_channel: reader.read_uint32()?,
            },
            unknown_message => Self::Unknown {
                message: unknown_message,
                payload: reader.read_remaining(),
            },
        };

        if reader.read_remaining().is_empty() {
            Ok(decoded)
        } else {
            Err(ProtocolError::TrailingPayload)
        }
    }

    pub fn encode(self, buffer: &mut [u8]) -> Result<&[u8], ProtocolError> {
        let mut writer = ObjectWriter::new(buffer);

        match self {
            Self::Ignore { data } => {
                writer.write_byte(MSG_IGNORE)?;
                writer.write_string(data)?;
            }
            Self::Debug {
                always_display,
                message,
                language_tag,
            } => {
                writer.write_byte(MSG_DEBUG)?;
                writer.write_boolean(always_display)?;
                writer.write_string_utf8(message)?;
                writer.write_string_utf8(language_tag)?;
            }
            Self::KexInit {
                cookie,
                kex_algorithms,
                server_host_key_algorithms,
                encryption_algorithms_client_to_server,
                encryption_algorithms_server_to_client,
                mac_algorithms_client_to_server,
                mac_algorithms_server_to_client,
                compression_algorithms_client_to_server,
                compression_algorithms_server_to_client,
                languages_client_to_server,
                languages_server_to_client,
                first_kex_packet_follows,
                reserved,
            } => {
                writer.write_byte(MSG_KEX_INIT)?;
                writer.write_byte_array(cookie)?;
                writer.write_name_list(kex_algorithms)?;
                writer.write_name_list(server_host_key_algorithms)?;
                writer.write_name_list(encryption_algorithms_client_to_server)?;
                writer.write_name_list(encryption_algorithms_server_to_client)?;
                writer.write_name_list(mac_algorithms_client_to_server)?;
                writer.write_name_list(mac_algorithms_server_to_client)?;
                writer.write_name_list(compression_algorithms_client_to_server)?;
                writer.write_name_list(compression_algorithms_server_to_client)?;
                writer.write_name_list(languages_client_to_server)?;
                writer.write_name_list(languages_server_to_client)?;
                writer.write_boolean(first_kex_packet_follows)?;
                writer.write_uint32(reserved)?;
            }
            Self::Unimplemented { sequence_number } => {
                writer.write_byte(MSG_UNIMPLEMENTED)?;
                writer.write_uint32(sequence_number)?;
            }
            Self::KexEcdhInit {
                client_ephemeral_public_key,
            } => {
                writer.write_byte(MSG_KEX_ECDH_INIT)?;
                writer.write_string(client_ephemeral_public_key)?;
            }
            Self::KexEcdhReply {
                server_public_host_key,
                server_ephemeral_public_key,
                signature,
            } => {
                writer.write_byte(MSG_KEX_ECDH_REPLY)?;
                server_public_host_key.encode_with(&mut writer)?;
                writer.write_string(server_ephemeral_public_key)?;
                signature.encode_with(&mut writer)?;
            }
            Self::Disconnect { reason } => {
                writer.write_byte(MSG_DISCONNECT)?;
                reason.encode_with(&mut writer)?;
            }
            Self::NewKeys => {
                writer.write_byte(MSG_NEW_KEYS)?;
            }
            Self::ServiceAccept { service_name } => {
                writer.write_byte(MSG_SERVICE_ACCEPT)?;
                writer.write_string_utf8(service_name)?;
            }
            Self::ServiceRequest { service_name } => {
                writer.write_byte(MSG_SERVICE_REQUEST)?;
                writer.write_string_utf8(service_name)?;
            }
            Self::UserAuthRequest {
                user_name,
                service_name,
                auth_method,
            } => {
                writer.write_byte(MSG_USERAUTH_SUCCESS)?;
                writer.write_string_utf8(user_name)?;
                writer.write_string_utf8(service_name)?;
                auth_method.encode_with(&mut writer)?;
            }
            Self::UserAuthFailure {
                authentications_that_can_continue,
                partial_success,
            } => {
                writer.write_byte(MSG_USERAUTH_FAILURE)?;
                writer.write_name_list(authentications_that_can_continue)?;
                writer.write_boolean(partial_success)?;
            }
            Self::UserAuthSuccess => {
                writer.write_byte(MSG_USERAUTH_SUCCESS)?;
            }
            Self::UserAuthBanner { message, language } => {
                writer.write_byte(MSG_USERAUTH_BANNER)?;
                writer.write_string_utf8(message)?;
                writer.write_string_utf8(language)?;
            }
            Self::UserAuthPkOk {
                public_key_algorithm_name,
                public_key,
            } => {
                writer.write_byte(MSG_USERAUTH_PK_OK)?;
                writer.write_string_utf8(public_key_algorithm_name)?;
                public_key.encode_with(&mut writer)?;
            }
            Self::GlobalRequest {
                request_name,
                want_reply,
                payload,
            } => {
                writer.write_byte(MSG_GLOBAL_REQUEST)?;
                writer.write_string_utf8(request_name)?;
                writer.write_boolean(want_reply)?;
                writer.write_string(payload)?;
            }
            Self::RequestSuccess { payload } => {
                writer.write_byte(MSG_REQUEST_SUCCESS)?;
                writer.write_string(payload)?;
            }
            Self::RequestFailure => {
                writer.write_byte(MSG_REQUEST_FAILURE)?;
            }
            Self::ChannelOpen { channel } => {
                writer.write_byte(MSG_CHANNEL_OPEN)?;
                channel.encode_with(&mut writer)?;
            }
            Self::ChannelOpenConfirmation {
                recipient_channel,
                sender_channel,
                initial_window_size,
                maximum_packet_size,
                payload,
            } => {
                writer.write_byte(MSG_CHANNEL_OPEN_CONFIRMATION)?;
                writer.write_uint32(recipient_channel)?;
                writer.write_uint32(sender_channel)?;
                writer.write_uint32(initial_window_size)?;
                writer.write_uint32(maximum_packet_size)?;
                writer.write_byte_array(payload)?;
            }
            Self::ChannelOpenFailure {
                recipient_channel,
                reason,
            } => {
                writer.write_byte(MSG_CHANNEL_OPEN_FAILURE)?;
                writer.write_uint32(recipient_channel)?;
                reason.encode_with(&mut writer)?;
            }
            Self::ChannelWindowAdjust {
                recipient_channel,
                bytes_to_add,
            } => {
                writer.write_byte(MSG_CHANNEL_WINDOW_ADJUST)?;
                writer.write_uint32(recipient_channel)?;
                writer.write_uint32(bytes_to_add)?;
            }
            Self::ChannelData {
                recipient_channel,
                data,
            } => {
                writer.write_byte(MSG_CHANNEL_DATA)?;
                writer.write_uint32(recipient_channel)?;
                data.encode_with(&mut writer)?;
            }
            Self::ChannelExtendedData {
                recipient_channel,
                data,
            } => {
                writer.write_byte(MSG_CHANNEL_EXTENDED_DATA)?;
                writer.write_uint32(recipient_channel)?;
                data.encode_with(&mut writer)?;
            }
            Self::ChannelEof { recipient_channel } => {
                writer.write_byte(MSG_CHANNEL_EOF)?;
                writer.write_uint32(recipient_channel)?;
            }
            Self::ChannelClose { recipient_channel } => {
                writer.write_byte(MSG_CHANNEL_CLOSE)?;
                writer.write_uint32(recipient_channel)?;
            }
            Self::ChannelRequest {
                recipient_channel,
                request,
            } => {
                writer.write_byte(MSG_CHANNEL_REQUEST)?;
                writer.write_uint32(recipient_channel)?;
                request.encode_with(&mut writer)?;
            }
            Self::ChannelSuccess { recipient_channel } => {
                writer.write_byte(MSG_CHANNEL_SUCCESS)?;
                writer.write_uint32(recipient_channel)?;
            }
            Self::ChannelFailure { recipient_channel } => {
                writer.write_byte(MSG_CHANNEL_FAILURE)?;
                writer.write_uint32(recipient_channel)?;
            }
            Self::Unknown { .. } => unreachable!(),
        }

        Ok(writer.into_written())
    }
}

// The SSH protocol uses 32-bit integers for various size quantities; these conversion
// utilities will convert them to/from usize while avoiding silent integer truncation.

pub fn into_u32(value: usize) -> u32 {
    value.try_into().expect("failed to convert usize to u32")
}

pub fn from_u32(value: u32) -> usize {
    value.try_into().expect("failed to convert u32 to usize")
}
