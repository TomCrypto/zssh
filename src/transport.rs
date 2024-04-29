use crate::channel::{Channel, Pipe};
use crate::codec::{ObjectHasher, ObjectWriter};
use crate::error::{Error, ProtocolError};
use crate::types::{self, AuthMethod, Behavior, Request, SecretKey, TransportError};
use crate::wire;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128Enc;
use constant_time_eq::constant_time_eq;
use core::ops::Range;
use ctr::Ctr128BE;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use embedded_io_async::{Read, Write};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

const KEXINIT_KEX: &str = "curve25519-sha256";
const KEXINIT_HOST_KEY: &str = "ssh-ed25519";
const KEXINIT_ENCRYPTION: &str = "aes128-ctr";
const KEXINIT_MAC: &str = "hmac-sha2-256";
const KEXINIT_COMPRESSION: &str = "none";

struct KexState {
    discard_guessed: bool,
    exchange_hash_hasher: ObjectHasher<Sha256>,
}

struct PendingKeys {
    prefix_hash: ObjectHasher<Sha256>,
    session_id: [u8; 32],
}

struct KeyMaterial {
    client_enc_ctx: Ctr128BE<Aes128Enc>,
    client_mac_ctx: Hmac<Sha256>,
    server_enc_ctx: Ctr128BE<Aes128Enc>,
    server_mac_ctx: Hmac<Sha256>,
    session_id: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct PendingChannel {
    sender_channel: u32,
    initial_window_size: u32,
    maximum_packet_size: u32,
}

#[derive(Clone, Copy, Debug)]
enum HalfState {
    Window(u32),
    Eof,
    Close,
}

impl HalfState {
    pub fn increase_window(&mut self, amount: u32) -> Result<(), ProtocolError> {
        if let HalfState::Window(value) = self {
            *value = value
                .checked_add(amount)
                .ok_or(ProtocolError::WindowOverflow)?;
        }

        Ok(())
    }

    pub fn decrease_window(&mut self, amount: u32) -> Result<(), ProtocolError> {
        if let HalfState::Window(value) = self {
            *value = value
                .checked_sub(amount)
                .ok_or(ProtocolError::WindowOverflow)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
struct ChannelState {
    rx_channel_id: u32,
    tx_channel_id: u32,
    tx_max_packet: u32,
    rx_half: HalfState,
    tx_half: HalfState,
    rx_committed: bool,
}

/// Implementation of an SSH server's transport layer.
pub struct Transport<'a, T: Behavior> {
    buffer: &'a mut [u8],

    behavior: T,

    client_ssh_id_buffer: [u8; 255],
    client_ssh_id_length: usize,

    kex: Option<KexState>,

    next_keys: Option<PendingKeys>,
    curr_keys: Option<KeyMaterial>,

    client_sequence_number: u32,
    server_sequence_number: u32,

    userauth_enabled: bool,
    authenticated: bool,

    request: Option<Request<T::Command>>,
    current_user: Option<T::User>,

    channels: [Option<PendingChannel>; 4],
    active_channel: Option<ChannelState>,
}

impl<'a, T: Behavior> Transport<'a, T> {
    /// Creates a new transport from a packet buffer and behavior.
    pub fn new(buffer: &'a mut [u8], behavior: T) -> Self {
        Self {
            buffer,
            behavior,

            client_ssh_id_buffer: [0u8; 255],
            client_ssh_id_length: 0,

            kex: None,

            next_keys: None,
            curr_keys: None,

            client_sequence_number: u32::MAX,
            server_sequence_number: u32::MAX,

            userauth_enabled: false,
            authenticated: false,

            request: None,
            current_user: None,

            channels: [None; 4],
            active_channel: None,
        }
    }

    pub(crate) fn client_ssh_id_string(&self) -> &str {
        let slice = &self.client_ssh_id_buffer[..self.client_ssh_id_length];

        crate::unwrap_unreachable(core::str::from_utf8(slice).ok())
    }

    async fn perform_handshake(&mut self) -> Result<(), TransportError<T>> {
        let ssh_str = self.behavior.server_id().as_bytes();
        assert!(ssh_str.len() <= 253); // required by spec

        self.behavior.stream().write_all(ssh_str).await?;
        self.behavior.stream().write_all(b"\r\n").await?;

        // The client is not allowed to send arbitrary lines prior to sending its
        // identification string (the server can, but we don't). The parser below
        // checks that the input is well-formed according to RFC4253 section 4.2.

        for i in 0..255 {
            self.behavior
                .stream()
                .read(&mut self.client_ssh_id_buffer[i..i + 1])
                .await?;

            let curr = self.client_ssh_id_buffer[i];

            if !matches!(curr, b'\r' | b'\n' | 0x20..=0x7E) {
                Err(ProtocolError::BadIdentificationString)?;
            }

            if i == 0 {
                continue;
            }

            let prev = self.client_ssh_id_buffer[i - 1];

            if (prev, curr) == (b'\r', b'\n') {
                self.client_ssh_id_length = i - 1;
                break;
            }
        }

        if !self.client_ssh_id_string().starts_with("SSH-2.0-") {
            Err(ProtocolError::BadIdentificationString)?;
        }

        Ok(())
    }

    /// Accepts the next client request as a channel.
    pub async fn accept(&mut self) -> Result<Channel<'a, '_, T>, TransportError<T>> {
        assert!(self.request.is_none(), "channel request already active");

        loop {
            if self.request.is_some() {
                return Ok(Channel::new(self));
            } else {
                self.poll_client().await?;
            }
        }
    }

    pub(crate) fn channel_request(&self) -> Request<T::Command> {
        crate::unwrap_unreachable(self.request.clone())
    }

    pub(crate) fn channel_user(&self) -> T::User {
        crate::unwrap_unreachable(self.current_user.clone())
    }

    pub(crate) fn channel_data_payload_buffer(&mut self, pipe: Pipe) -> &mut [u8] {
        let max_packet_size = wire::from_u32(self.channel_state().tx_max_packet);

        // This is a little bit of a hack, we make an assumption on the representation of the
        // two ChannelData and ChannelExtendedData messages to retrieve the offset within our
        // packet buffer at which the caller may write its data so it could be sent in-place.

        let payload_offset = match pipe {
            Pipe::Stdout => 9,
            Pipe::Stderr => 13,
        };

        let slice = &mut self.buffer[payload_offset..];

        if slice.len() > max_packet_size {
            &mut slice[..max_packet_size]
        } else {
            slice
        }
    }

    fn maximum_channel_data_packet_size(&mut self) -> u32 {
        wire::into_u32(self.buffer.len() - 9) // see above
    }

    pub(crate) async fn channel_adjust(
        &mut self,
        amount: Option<u32>,
    ) -> Result<(), TransportError<T>> {
        if self.channel_state().rx_committed {
            panic!("can no longer read from channel!");
        }

        if amount.is_none() {
            self.channel_state().rx_committed = true;
        }

        let amount = amount.unwrap_or(u32::MAX);

        match self.channel_state().rx_half {
            HalfState::Window(0) => {
                let recipient_channel = self.channel_state().tx_channel_id;

                self.send(wire::Message::ChannelWindowAdjust {
                    recipient_channel,
                    bytes_to_add: amount,
                })
                .await?;

                self.channel_state().rx_half.increase_window(amount)?;

                Ok(())
            }
            HalfState::Window(_) => {
                panic!("channel reader did not read all data");
            }
            HalfState::Eof | HalfState::Close => Ok(()),
        }
    }

    pub(crate) fn channel_is_eof(&mut self) -> bool {
        matches!(
            self.channel_state().rx_half,
            HalfState::Eof | HalfState::Close
        )
    }

    pub(crate) async fn channel_read(&mut self) -> Result<Option<&[u8]>, TransportError<T>> {
        loop {
            match self.channel_state().rx_half {
                HalfState::Window(0) => {
                    return Ok(None);
                }
                HalfState::Window(amount) => {
                    if self.channel_state().rx_committed {
                        let bytes_to_add = u32::MAX - amount;

                        let recipient_channel = self.channel_state().tx_channel_id;

                        self.send(wire::Message::ChannelWindowAdjust {
                            recipient_channel,
                            bytes_to_add,
                        })
                        .await?;

                        self.channel_state().rx_half.increase_window(bytes_to_add)?;
                    } else if amount == 0 {
                        return Ok(None);
                    }

                    if let Some(payload) = self.poll_client().await? {
                        if let wire::Message::ChannelData {
                            data: wire::Data::Borrowed { bytes },
                            ..
                        } = wire::Message::decode(&self.buffer[payload])?
                        {
                            return Ok(Some(bytes));
                        } else {
                            unreachable!("expected channel data");
                        }
                    }
                }
                HalfState::Eof | HalfState::Close => {
                    return Ok(None);
                }
            }
        }
    }

    fn channel_state(&mut self) -> &mut ChannelState {
        crate::unwrap_unreachable(self.active_channel.as_mut())
    }

    pub(crate) async fn channel_exit(&mut self, exit_status: u32) -> Result<(), TransportError<T>> {
        let recipient_channel = self.channel_state().tx_channel_id;

        self.send(wire::Message::ChannelEof { recipient_channel })
            .await?;

        self.send(wire::Message::ChannelRequest {
            recipient_channel,
            request: wire::Request::ExitStatus {
                want_reply: false,
                exit_status,
            },
        })
        .await?;

        self.send(wire::Message::ChannelClose { recipient_channel })
            .await?;

        self.channel_state().tx_half = HalfState::Close;

        if let HalfState::Close = self.channel_state().rx_half {
            self.dequeue_pending_channel().await?;
        }

        self.request = None;

        Ok(())
    }

    pub(crate) async fn channel_write(
        &mut self,
        len: usize,
        pipe: Pipe,
    ) -> Result<(), TransportError<T>> {
        match self.channel_state().tx_half {
            HalfState::Window(amount) => {
                if wire::from_u32(amount) >= len {
                    let recipient_channel = self.channel_state().tx_channel_id;

                    self.send(match pipe {
                        Pipe::Stdout => wire::Message::ChannelData {
                            recipient_channel,
                            data: wire::Data::InPlace {
                                len: wire::into_u32(len),
                            },
                        },
                        Pipe::Stderr => wire::Message::ChannelExtendedData {
                            recipient_channel,
                            data: wire::ExtendedData::Stderr {
                                data: wire::Data::InPlace {
                                    len: wire::into_u32(len),
                                },
                            },
                        },
                    })
                    .await?;

                    self.channel_state()
                        .tx_half
                        .decrease_window(wire::into_u32(len))?;
                } else {
                    self.poll_client().await?;
                }
            }
            HalfState::Eof | HalfState::Close => {
                return Err(Error::UnexpectedEof);
            }
        }

        Ok(())
    }

    async fn poll_client(&mut self) -> Result<Option<Range<usize>>, TransportError<T>> {
        if self.client_ssh_id_length == 0 {
            self.perform_handshake().await?;
        }

        let mut reason = wire::DisconnectReason::ProtocolError;

        let payload = self.recv().await?; // we sometimes need the raw bytes
        let message = wire::Message::decode(&self.buffer[payload.clone()])?;

        match message {
            wire::Message::KexInit {
                kex_algorithms,
                server_host_key_algorithms,
                encryption_algorithms_client_to_server,
                encryption_algorithms_server_to_client,
                mac_algorithms_client_to_server,
                mac_algorithms_server_to_client,
                compression_algorithms_client_to_server,
                compression_algorithms_server_to_client,
                first_kex_packet_follows,
                ..
            } if self.kex.is_none() => {
                // We only have one algorithm for each name list, so the selection algorithm
                // boils down to "does the client have our algorithm in their list". Process
                // the kex and host_key algorithms specially if a guessed packet is sent.

                let kex_index = kex_algorithms.find(KEXINIT_KEX);
                let host_key_index = server_host_key_algorithms.find(KEXINIT_HOST_KEY);

                if kex_index.is_none() || host_key_index.is_none() {
                    return Err(Error::ServerDisconnect(
                        wire::DisconnectReason::KeyExchangeFailed,
                    ));
                }

                if encryption_algorithms_client_to_server
                    .find(KEXINIT_ENCRYPTION)
                    .is_none()
                {
                    return Err(Error::ServerDisconnect(
                        wire::DisconnectReason::KeyExchangeFailed,
                    ));
                }

                if encryption_algorithms_server_to_client
                    .find(KEXINIT_ENCRYPTION)
                    .is_none()
                {
                    return Err(Error::ServerDisconnect(
                        wire::DisconnectReason::KeyExchangeFailed,
                    ));
                }

                if mac_algorithms_client_to_server.find(KEXINIT_MAC).is_none() {
                    return Err(Error::ServerDisconnect(
                        wire::DisconnectReason::KeyExchangeFailed,
                    ));
                }

                if mac_algorithms_server_to_client.find(KEXINIT_MAC).is_none() {
                    return Err(Error::ServerDisconnect(
                        wire::DisconnectReason::KeyExchangeFailed,
                    ));
                }

                if compression_algorithms_client_to_server
                    .find(KEXINIT_COMPRESSION)
                    .is_none()
                {
                    return Err(Error::ServerDisconnect(
                        wire::DisconnectReason::KeyExchangeFailed,
                    ));
                }

                if compression_algorithms_server_to_client
                    .find(KEXINIT_COMPRESSION)
                    .is_none()
                {
                    return Err(Error::ServerDisconnect(
                        wire::DisconnectReason::KeyExchangeFailed,
                    ));
                }

                // If the kex or host key algorithms were not the client's preferred algorithm, their guess
                // will be wrong so we must discard the guessed key exchange packet they will have sent us.

                let mut discard_guessed = false;

                if first_kex_packet_follows {
                    if kex_index != Some(0) || host_key_index != Some(0) {
                        discard_guessed = true;
                    }
                }

                let mut cookie = [0u8; 16];

                self.behavior.random().fill_bytes(&mut cookie);

                // Note that we never need to guess since we reply to the client's KEXINIT, so we always
                // know whether our guess would have been correct or not; the client may guess, however.

                let kex_init_message = wire::Message::KexInit {
                    cookie: &cookie,
                    kex_algorithms: wire::NameList::new_from_string(KEXINIT_KEX)?,
                    server_host_key_algorithms: wire::NameList::new_from_string(KEXINIT_HOST_KEY)?,
                    encryption_algorithms_client_to_server: wire::NameList::new_from_string(
                        KEXINIT_ENCRYPTION,
                    )?,
                    encryption_algorithms_server_to_client: wire::NameList::new_from_string(
                        KEXINIT_ENCRYPTION,
                    )?,
                    mac_algorithms_client_to_server: wire::NameList::new_from_string(KEXINIT_MAC)?,
                    mac_algorithms_server_to_client: wire::NameList::new_from_string(KEXINIT_MAC)?,
                    compression_algorithms_client_to_server: wire::NameList::new_from_string(
                        KEXINIT_COMPRESSION,
                    )?,
                    compression_algorithms_server_to_client: wire::NameList::new_from_string(
                        KEXINIT_COMPRESSION,
                    )?,
                    languages_client_to_server: wire::NameList::default(),
                    languages_server_to_client: wire::NameList::default(),
                    first_kex_packet_follows: false,
                    reserved: 0,
                };

                let mut kex = KexState {
                    exchange_hash_hasher: ObjectHasher::new(Sha256::new()),
                    discard_guessed,
                };

                kex.exchange_hash_hasher
                    .hash_string_utf8(self.client_ssh_id_string());
                kex.exchange_hash_hasher
                    .hash_string_utf8(self.behavior.server_id());
                kex.exchange_hash_hasher.hash_string(&self.buffer[payload]);

                let payload = kex_init_message.encode(self.buffer)?;

                kex.exchange_hash_hasher.hash_string(payload);

                let payload_len = payload.len();

                self.send_preencoded_payload(payload_len).await?;

                self.kex = Some(kex);

                return Ok(None);
            }
            wire::Message::KexEcdhInit {
                client_ephemeral_public_key,
            } => {
                if let Some(mut kex) = self.kex.take() {
                    if core::mem::replace(&mut kex.discard_guessed, false) {
                        self.kex = Some(kex);
                        return Ok(None);
                    } else if let Ok(client_ephemeral_public_key) =
                        <&[u8] as TryInto<[u8; 32]>>::try_into(client_ephemeral_public_key)
                    {
                        let client_ephemeral_public_key: PublicKey =
                            client_ephemeral_public_key.into();

                        let server_ephemeral_secret_key =
                            EphemeralSecret::random_from_rng(self.behavior.random());

                        let server_ephemeral_public_key: PublicKey =
                            (&server_ephemeral_secret_key).into();

                        // Generate a keypair

                        let shared_secret = server_ephemeral_secret_key
                            .diffie_hellman(&client_ephemeral_public_key);

                        // Finish building up the exchange hash

                        match self.behavior.host_secret_key() {
                            SecretKey::Ed25519 { secret_key } => {
                                let public_key = secret_key.verifying_key();

                                let host_key = wire::PublicKey::Ed25519 {
                                    public_key: public_key.as_bytes(),
                                };

                                let mut host_key_writer = ObjectWriter::new(self.buffer);

                                host_key.encode_with(&mut host_key_writer)?;

                                kex.exchange_hash_hasher
                                    .hash_byte_array(host_key_writer.into_written());
                                kex.exchange_hash_hasher
                                    .hash_string(client_ephemeral_public_key.as_bytes());
                                kex.exchange_hash_hasher
                                    .hash_string(server_ephemeral_public_key.as_bytes());

                                let shared_secret = *shared_secret.as_bytes();

                                kex.exchange_hash_hasher.hash_mpint(&shared_secret);

                                let exchange_hash = kex.exchange_hash_hasher.into_digest();

                                let signature = secret_key.sign(&exchange_hash);

                                self.send(wire::Message::KexEcdhReply {
                                    server_public_host_key: wire::PublicKey::Ed25519 {
                                        public_key: public_key.as_bytes(),
                                    },
                                    server_ephemeral_public_key: server_ephemeral_public_key
                                        .as_bytes(),
                                    signature: wire::Signature::Ed25519 {
                                        signature: &signature.to_bytes(),
                                    },
                                })
                                .await?;

                                let mut prefix_hash = ObjectHasher::new(Sha256::new());

                                prefix_hash.hash_mpint(&shared_secret);
                                prefix_hash.hash_byte_array(&exchange_hash);

                                self.next_keys = Some(PendingKeys {
                                    session_id: match &self.curr_keys {
                                        Some(keys) => keys.session_id,
                                        None => exchange_hash.into(),
                                    },
                                    prefix_hash,
                                });

                                return Ok(None);
                            }
                        }
                    } else {
                        reason = wire::DisconnectReason::KeyExchangeFailed;
                    }
                }
            }
            wire::Message::NewKeys => {
                if let Some(keys) = self.next_keys.take() {
                    self.send(wire::Message::NewKeys).await?;

                    let mut iv_client_hash = keys.prefix_hash.clone();

                    iv_client_hash.hash_byte(b'A');
                    iv_client_hash.hash_byte_array(&keys.session_id);

                    let iv_client_tmp: [u8; 32] = iv_client_hash.into_digest().into();
                    let mut iv_client: [u8; 16] = [0u8; 16];
                    iv_client.copy_from_slice(&iv_client_tmp[..16]);

                    let mut iv_server_hash = keys.prefix_hash.clone();

                    iv_server_hash.hash_byte(b'B');
                    iv_server_hash.hash_byte_array(&keys.session_id);

                    let iv_server_tmp: [u8; 32] = iv_server_hash.into_digest().into();
                    let mut iv_server: [u8; 16] = [0u8; 16];
                    iv_server.copy_from_slice(&iv_server_tmp[..16]);

                    let mut enc_key_client_hash = keys.prefix_hash.clone();

                    enc_key_client_hash.hash_byte(b'C');
                    enc_key_client_hash.hash_byte_array(&keys.session_id);

                    let enc_key_client_tmp: [u8; 32] = enc_key_client_hash.into_digest().into();
                    let mut enc_key_client: [u8; 16] = [0u8; 16];
                    enc_key_client.copy_from_slice(&enc_key_client_tmp[..16]);

                    let enc_client =
                        Ctr128BE::<Aes128Enc>::new(&enc_key_client.into(), &iv_client.into());

                    let mut enc_key_server_hash = keys.prefix_hash.clone();

                    enc_key_server_hash.hash_byte(b'D');
                    enc_key_server_hash.hash_byte_array(&keys.session_id);

                    let enc_key_server_tmp: [u8; 32] = enc_key_server_hash.into_digest().into();
                    let mut enc_key_server: [u8; 16] = [0u8; 16];
                    enc_key_server.copy_from_slice(&enc_key_server_tmp[..16]);

                    let enc_server =
                        Ctr128BE::<Aes128Enc>::new(&enc_key_server.into(), &iv_server.into());

                    let mut mac_key_client_hash = keys.prefix_hash.clone();

                    mac_key_client_hash.hash_byte(b'E');
                    mac_key_client_hash.hash_byte_array(&keys.session_id);

                    let mac_key_client: [u8; 32] = mac_key_client_hash.into_digest().into();

                    let mut mac_key_server_hash = keys.prefix_hash.clone();

                    mac_key_server_hash.hash_byte(b'F');
                    mac_key_server_hash.hash_byte_array(&keys.session_id);

                    let mac_key_server: [u8; 32] = mac_key_server_hash.into_digest().into();

                    let mut padded = [0u8; 64];

                    padded[0..32].copy_from_slice(&mac_key_client);

                    let client_mac_ctx = Hmac::<Sha256>::new(&padded.into());

                    let mut padded = [0u8; 64];

                    padded[0..32].copy_from_slice(&mac_key_server);

                    let server_mac_ctx = Hmac::<Sha256>::new(&padded.into());

                    self.curr_keys = Some(KeyMaterial {
                        client_enc_ctx: enc_client,
                        server_enc_ctx: enc_server,
                        client_mac_ctx,
                        server_mac_ctx,
                        session_id: keys.session_id,
                    });

                    return Ok(None);
                }
            }
            wire::Message::ServiceRequest { service_name } if self.curr_keys.is_some() => {
                match service_name {
                    "ssh-userauth" => {
                        self.userauth_enabled = true;

                        self.send(wire::Message::ServiceAccept {
                            service_name: "ssh-userauth",
                        })
                        .await?;

                        return Ok(None);
                    }
                    _ => {
                        reason = wire::DisconnectReason::ServiceNotAvailable;
                    }
                }
            }
            wire::Message::UserAuthRequest {
                user_name,
                service_name: "ssh-connection",
                auth_method,
            } if self.userauth_enabled => {
                // Unfortunately we need to use the user name for signature verification, meaning we need
                // to store it outside the packet buffer. Rather than burden the crate user, we just copy
                // the user name into a temporary string, enforcing a reasonable 80-byte maximum length.

                let mut user_name_buffer = [0u8; 80];

                if user_name.len() > user_name_buffer.len() {
                    self.send(wire::Message::UserAuthFailure {
                        authentications_that_can_continue: wire::NameList::new_from_string(
                            "publickey",
                        )?,
                        partial_success: false,
                    })
                    .await?;

                    return Ok(None);
                }

                let user_name_slice = &mut user_name_buffer[..user_name.len()];
                user_name_slice.copy_from_slice(user_name.as_bytes());

                let Some(user_auth_method) = (match auth_method {
                    wire::AuthMethod::None => Some(AuthMethod::None),
                    wire::AuthMethod::PublicKey {
                        public_key_algorithm_name: "ssh-ed25519",
                        public_key: wire::PublicKey::Ed25519 { public_key },
                        signature: Some(wire::Signature::Ed25519 { .. }) | None,
                    } => {
                        if let Ok(public_key) = VerifyingKey::from_bytes(public_key) {
                            Some(AuthMethod::PublicKey(types::PublicKey::Ed25519 {
                                public_key,
                            }))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }) else {
                    self.send(wire::Message::UserAuthFailure {
                        authentications_that_can_continue: wire::NameList::new_from_string(
                            "publickey",
                        )?,
                        partial_success: false,
                    })
                    .await?;

                    return Ok(None);
                };

                if let Some(user) = self.behavior.allow_user(user_name, &user_auth_method) {
                    match user_auth_method {
                        AuthMethod::None => {
                            self.send(wire::Message::UserAuthSuccess).await?;
                            self.current_user = Some(user);
                            self.authenticated = true;
                        }
                        AuthMethod::PublicKey(types::PublicKey::Ed25519 { public_key }) => {
                            if let wire::AuthMethod::PublicKey {
                                public_key_algorithm_name: "ssh-ed25519",
                                public_key: wire::PublicKey::Ed25519 { .. },
                                signature: Some(wire::Signature::Ed25519 { signature }),
                            } = auth_method
                            {
                                let signed_public_key = wire::PublicKey::Ed25519 {
                                    public_key: public_key.as_bytes(),
                                };

                                let signature: Signature = signature.into();

                                let mut writer = ObjectWriter::new(self.buffer);

                                // TODO: feels like we could do a little better here

                                writer.write_string(
                                    &crate::unwrap_unreachable(self.curr_keys.as_ref()).session_id,
                                )?;
                                writer.write_byte(wire::MSG_USERAUTH_REQUEST)?;
                                writer.write_string(user_name_slice)?;
                                writer.write_string_utf8("ssh-connection")?;
                                writer.write_string_utf8("publickey")?;
                                writer.write_boolean(true)?;
                                writer.write_string_utf8("ssh-ed25519")?;
                                signed_public_key.encode_with(&mut writer)?;

                                if let Ok(()) = public_key.verify(writer.into_written(), &signature)
                                {
                                    self.send(wire::Message::UserAuthSuccess).await?;
                                    self.current_user = Some(user);
                                    self.authenticated = true;
                                } else {
                                    self.send(wire::Message::UserAuthFailure {
                                        authentications_that_can_continue:
                                            wire::NameList::new_from_string("publickey")?,
                                        partial_success: false,
                                    })
                                    .await?;
                                }
                            } else {
                                self.send(wire::Message::UserAuthPkOk {
                                    public_key_algorithm_name: "ssh-ed25519",
                                    public_key: wire::PublicKey::Ed25519 {
                                        public_key: public_key.as_bytes(),
                                    },
                                })
                                .await?;
                            }
                        }
                    }
                } else {
                    self.send(wire::Message::UserAuthFailure {
                        authentications_that_can_continue: wire::NameList::new_from_string(
                            "publickey",
                        )?,
                        partial_success: false,
                    })
                    .await?;
                }

                return Ok(None);
            }

            wire::Message::GlobalRequest { want_reply, .. } if self.authenticated => {
                if want_reply {
                    self.send(wire::Message::RequestFailure).await?;
                }

                return Ok(None);
            }

            wire::Message::ChannelOpen {
                channel:
                    wire::ChannelType::Session {
                        sender_channel,
                        initial_window_size,
                        maximum_packet_size,
                    },
            } if self.authenticated => {
                // check if sender_channel is already known, if so, die

                for channel in self.channels.into_iter().flatten() {
                    if channel.sender_channel == sender_channel {
                        self.send(wire::Message::Disconnect {
                            reason: wire::DisconnectReason::ProtocolError,
                        })
                        .await?;
                        return Err(Error::ServerDisconnect(
                            wire::DisconnectReason::ProtocolError,
                        ));
                    }
                }

                // then, pick an empty spot. if none found, return error...

                for channel in &mut self.channels {
                    if channel.is_none() {
                        // save it, but DO NOT confirm it yet!!!

                        *channel = Some(PendingChannel {
                            sender_channel,
                            initial_window_size,
                            maximum_packet_size,
                        });

                        // only confirm if there's no other active channel

                        if self.active_channel.is_none() {
                            self.dequeue_pending_channel().await?;
                        }

                        return Ok(None);
                    }
                }

                self.send(wire::Message::ChannelOpenFailure {
                    recipient_channel: sender_channel,
                    reason: wire::ChannelOpenFailureReason::ResourceShortage,
                })
                .await?;

                return Ok(None);
            }

            wire::Message::ChannelOpen {
                channel: wire::ChannelType::Other { sender_channel, .. },
            } if self.authenticated => {
                self.send(wire::Message::ChannelOpenFailure {
                    recipient_channel: sender_channel,
                    reason: wire::ChannelOpenFailureReason::UnknownChannelType,
                })
                .await?;

                return Ok(None);
            }

            wire::Message::ChannelWindowAdjust {
                recipient_channel,
                bytes_to_add,
            } if self.authenticated => {
                if let Some(channel_state) = &mut self.active_channel {
                    if channel_state.rx_channel_id == recipient_channel {
                        channel_state.tx_half.increase_window(bytes_to_add)?;
                        return Ok(None);
                    }
                }
            }

            wire::Message::ChannelData {
                recipient_channel,
                data: wire::Data::Borrowed { bytes },
            } if self.authenticated => {
                if let Some(channel_state) = &mut self.active_channel {
                    if channel_state.rx_channel_id == recipient_channel {
                        channel_state
                            .rx_half
                            .decrease_window(wire::into_u32(bytes.len()))?;
                        return Ok(Some(payload));
                    }
                }
            }

            wire::Message::ChannelEof { recipient_channel } if self.authenticated => {
                if let Some(channel_state) = &mut self.active_channel {
                    if channel_state.rx_channel_id == recipient_channel {
                        channel_state.rx_half = HalfState::Eof;
                        return Ok(None);
                    }
                }
            }

            wire::Message::ChannelClose { recipient_channel } if self.authenticated => {
                if self.active_channel.is_none() {
                    return Ok(None); // ignored
                }

                if let Some(channel_state) = &mut self.active_channel {
                    if channel_state.rx_channel_id == recipient_channel {
                        channel_state.rx_half = HalfState::Close;

                        if let HalfState::Close = channel_state.tx_half {
                            self.dequeue_pending_channel().await?;
                        }

                        return Ok(None);
                    }
                }
            }

            wire::Message::ChannelRequest {
                recipient_channel,
                request:
                    wire::Request::Exec {
                        want_reply,
                        command,
                    },
            } if self.authenticated && self.request.is_none() => {
                if let Some(channel_state) = &mut self.active_channel {
                    if channel_state.rx_channel_id == recipient_channel {
                        self.request = Some(Request::Exec(self.behavior.parse_command(command)));

                        if want_reply {
                            self.send(wire::Message::ChannelSuccess { recipient_channel })
                                .await?;
                        }

                        return Ok(None);
                    }
                }
            }

            wire::Message::ChannelRequest {
                recipient_channel,
                request: wire::Request::Env { want_reply, .. },
            } if self.authenticated => {
                if let Some(channel_state) = &mut self.active_channel {
                    if channel_state.rx_channel_id == recipient_channel {
                        if want_reply {
                            self.send(wire::Message::ChannelSuccess { recipient_channel })
                                .await?;
                        }

                        return Ok(None);
                    }
                }
            }

            wire::Message::ChannelRequest {
                recipient_channel,
                request: wire::Request::Shell { want_reply },
            } if self.authenticated && self.request.is_none() && self.behavior.allow_shell() => {
                if let Some(channel_state) = &mut self.active_channel {
                    if channel_state.rx_channel_id == recipient_channel {
                        self.request = Some(Request::Shell);

                        if want_reply {
                            self.send(wire::Message::ChannelSuccess { recipient_channel })
                                .await?;
                        }

                        return Ok(None);
                    }
                }
            }

            wire::Message::ChannelRequest {
                recipient_channel,
                request,
            } if self.authenticated => {
                if let Some(channel_state) = &mut self.active_channel {
                    if channel_state.rx_channel_id == recipient_channel {
                        if request.want_reply() {
                            self.send(wire::Message::ChannelFailure { recipient_channel })
                                .await?;
                        }

                        return Ok(None);
                    }
                }
            }

            wire::Message::Debug { .. }
            | wire::Message::Ignore { .. }
            | wire::Message::Unimplemented { .. } => {
                return Ok(None);
            }
            wire::Message::Unknown { .. } => {
                self.send(wire::Message::Unimplemented {
                    sequence_number: self.client_sequence_number,
                })
                .await?;

                return Ok(None);
            }
            wire::Message::Disconnect { reason, .. } => {
                return Err(Error::ClientDisconnect(reason));
            }

            _ => {}
        }

        self.send(wire::Message::Disconnect { reason }).await?;
        Err(Error::ServerDisconnect(reason))
    }

    fn block_size(&self) -> usize {
        if self.curr_keys.is_some() {
            16
        } else {
            8
        }
    }

    async fn send_preencoded_payload(
        &mut self,
        payload_len: usize,
    ) -> Result<(), TransportError<T>> {
        self.server_sequence_number = self.server_sequence_number.wrapping_add(1);

        if let Some(ctx) = &mut self.curr_keys {
            ctx.server_mac_ctx
                .update(&self.server_sequence_number.to_be_bytes());
        }

        // compute required padding length

        let mut padding_len = self.block_size() - (4 + 1 + payload_len) % self.block_size();

        if padding_len < 4 {
            padding_len += self.block_size();
        }

        // build up the header

        let packet_len = wire::into_u32(1 + payload_len + padding_len);

        let mut header = [0u8; 5];

        header[..4].copy_from_slice(&packet_len.to_be_bytes());
        header[4] = padding_len as u8;

        if let Some(ctx) = &mut self.curr_keys {
            ctx.server_mac_ctx.update(&header);
            ctx.server_enc_ctx.apply_keystream(&mut header);
        }

        self.behavior.stream().write_all(&header).await?;

        // send the payload

        if let Some(ctx) = &mut self.curr_keys {
            ctx.server_mac_ctx.update(&self.buffer[..payload_len]);
            ctx.server_enc_ctx
                .apply_keystream(&mut self.buffer[..payload_len]);
        }

        self.behavior
            .stream()
            .write_all(&self.buffer[..payload_len])
            .await?;

        // issue padding

        self.behavior
            .random()
            .fill_bytes(&mut self.buffer[..padding_len]);

        if let Some(ctx) = &mut self.curr_keys {
            ctx.server_mac_ctx.update(&self.buffer[..padding_len]);
            ctx.server_enc_ctx
                .apply_keystream(&mut self.buffer[..padding_len]);
        }

        self.behavior
            .stream()
            .write_all(&self.buffer[..padding_len])
            .await?;

        // finally, write out the MAC

        if let Some(ctx) = &mut self.curr_keys {
            let mac_tag: [u8; 32] = ctx.server_mac_ctx.finalize_reset().into_bytes().into();

            self.behavior.stream().write_all(&mac_tag).await?;
        }

        Ok(())
    }

    async fn send(&mut self, message: wire::Message<'_>) -> Result<(), TransportError<T>> {
        let payload_len = message.encode(self.buffer)?.len();
        self.send_preencoded_payload(payload_len).await
    }

    async fn recv(&mut self) -> Result<Range<usize>, TransportError<T>> {
        self.client_sequence_number = self.client_sequence_number.wrapping_add(1);

        if let Some(ctx) = &mut self.curr_keys {
            ctx.client_mac_ctx
                .update(&self.client_sequence_number.to_be_bytes());
        }

        // Since we know that we only use "aes128-ctr" which is a streaming mode
        // of encryption, we can unconditionally receive 5 bytes and decrypt it.

        let mut header = [0u8; 5];

        self.behavior.stream().read_exact(&mut header).await?;

        if let Some(ctx) = &mut self.curr_keys {
            ctx.client_enc_ctx.apply_keystream(&mut header);
            ctx.client_mac_ctx.update(&header);
        }

        let packet_length = wire::from_u32(u32::from_be_bytes([
            header[0], header[1], header[2], header[3],
        ]));

        if packet_length == 0 || (4 + packet_length) % self.block_size() != 0 {
            Err(ProtocolError::MalformedPacket)?;
        }

        // extract and verify padding length

        let padding_len: usize = header[4].into();

        if padding_len < 4 || padding_len >= packet_length {
            Err(ProtocolError::MalformedPacket)?;
        }

        // Figure out how long the payload is based on this

        let payload_len = packet_length - 1 - padding_len;

        // Ensure the buffer size is sufficient

        if payload_len > self.buffer.len() {
            Err(ProtocolError::BufferExhausted)?;
        }

        self.behavior
            .stream()
            .read_exact(&mut self.buffer[..payload_len])
            .await?;

        if let Some(ctx) = &mut self.curr_keys {
            ctx.client_enc_ctx
                .apply_keystream(&mut self.buffer[..payload_len]);
            ctx.client_mac_ctx.update(&self.buffer[..payload_len]);
        }

        // Finally, read and include the padding...

        let mut padding_buffer: [u8; 32] = [0u8; 32];

        let mut remaining_padding_bytes = padding_len;

        while remaining_padding_bytes != 0 {
            let to_read = usize::min(remaining_padding_bytes, padding_buffer.len());

            self.behavior
                .stream()
                .read_exact(&mut padding_buffer[..to_read])
                .await?;

            if let Some(ctx) = &mut self.curr_keys {
                ctx.client_enc_ctx
                    .apply_keystream(&mut padding_buffer[..to_read]);
                ctx.client_mac_ctx.update(&padding_buffer[..to_read]);
            }

            remaining_padding_bytes -= to_read;
        }

        // Then check the MAC, if one is present

        if let Some(ctx) = &mut self.curr_keys {
            let mut mac: [u8; 32] = [0u8; 32];

            self.behavior.stream().read_exact(&mut mac).await?;

            let mac_tag: [u8; 32] = ctx.client_mac_ctx.finalize_reset().into_bytes().into();

            // DO NOT report a MAC verification error to the client for security
            // reasons, just disconnect immediately and let it reinitiate later.

            if !constant_time_eq(&mac_tag, &mac) {
                Err(ProtocolError::MalformedPacket)?;
            }
        }

        Ok(0..payload_len)
    }

    /// Disconnects from the client with a given reason.
    pub async fn disconnect(
        mut self,
        reason: wire::DisconnectReason,
    ) -> Result<(), TransportError<T>> {
        if self.client_ssh_id_length == 0 {
            return Ok(());
        }

        self.send(wire::Message::Disconnect { reason }).await
    }

    async fn dequeue_pending_channel(&mut self) -> Result<(), TransportError<T>> {
        self.active_channel = None;

        for channel in &mut self.channels {
            if let Some(state) = channel.take() {
                self.active_channel = Some(ChannelState {
                    rx_half: HalfState::Window(0),
                    tx_half: HalfState::Window(state.initial_window_size),
                    tx_max_packet: state.maximum_packet_size,
                    rx_channel_id: 0,
                    tx_channel_id: state.sender_channel,
                    rx_committed: false,
                });

                let maximum_packet_size = self.maximum_channel_data_packet_size();

                self.send(wire::Message::ChannelOpenConfirmation {
                    recipient_channel: state.sender_channel,
                    sender_channel: 0,
                    initial_window_size: 0,
                    maximum_packet_size,
                    payload: &[],
                })
                .await?;

                break;
            }
        }

        Ok(())
    }
}
