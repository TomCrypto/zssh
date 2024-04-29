use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::ThreadRng, thread_rng};
use sha2::{Digest, Sha256};

use zssh::{AuthMethod, Behavior, PublicKey, Request, SecretKey, Transport, TransportError};

struct ExampleBehavior {
    stream: AsyncTcpStream,
    random: ThreadRng,

    host_secret_key: SecretKey,
    user_public_key: PublicKey,
}

#[derive(Clone, Debug)]
enum ExampleCommand {
    Sha256Sum,
    Echo,
    Sum(Vec<String>),
    Invalid,
}

impl Behavior for ExampleBehavior {
    type Stream = AsyncTcpStream;

    fn stream(&mut self) -> &mut Self::Stream {
        &mut self.stream
    }

    type Random = ThreadRng;

    fn random(&mut self) -> &mut Self::Random {
        &mut self.random
    }

    fn host_secret_key(&self) -> &SecretKey {
        &self.host_secret_key
    }

    type User = String;

    fn allow_user(&mut self, username: &str, auth_method: &AuthMethod) -> Option<Self::User> {
        match (username, auth_method) {
            ("zssh", AuthMethod::PublicKey(public_key)) if *public_key == self.user_public_key => {
                Some("zssh".to_owned())
            }
            ("guest", AuthMethod::None) => Some("guest".to_owned()),
            _ => None,
        }
    }

    type Command = ExampleCommand;

    fn parse_command(&mut self, command: &str) -> Self::Command {
        let args: Vec<&str> = command.split(' ').collect();

        match args.as_slice() {
            ["sha256sum"] => ExampleCommand::Sha256Sum,
            ["echo"] => ExampleCommand::Echo,
            ["sum", others @ ..] => {
                ExampleCommand::Sum(others.iter().map(|&s| s.to_owned()).collect())
            }
            _ => ExampleCommand::Invalid,
        }
    }
}

// Randomly created host identity.
const HOST_SECRET_KEY: [u8; 32] = [
    0xdf, 0x77, 0xbb, 0xf9, 0xf6, 0x42, 0x04, 0x40, 0x4c, 0x69, 0xe7, 0x1c, 0x7c, 0x6c, 0xda, 0x71,
    0x6c, 0xdc, 0x20, 0xa3, 0xe1, 0x2f, 0x78, 0x4a, 0x6d, 0xaa, 0x96, 0x3a, 0x1a, 0x51, 0xea, 0x4f,
];

// Matches examples/zssh.priv key.
const USER_PUBLIC_KEY: [u8; 32] = [
    0xa5, 0x34, 0xb0, 0xa8, 0x36, 0x95, 0x45, 0x22, 0xd2, 0x75, 0x46, 0xba, 0x6b, 0x17, 0xdc, 0xc9,
    0x18, 0xfb, 0x9d, 0xeb, 0xe2, 0xd5, 0x36, 0x5e, 0x1b, 0xdb, 0xca, 0x32, 0xb5, 0xbd, 0x90, 0xb4,
];

async fn handle_client(stream: TcpStream) -> Result<(), TransportError<ExampleBehavior>> {
    let behavior = ExampleBehavior {
        stream: AsyncTcpStream(stream),
        random: thread_rng(),
        host_secret_key: SecretKey::Ed25519 {
            secret_key: SigningKey::from_bytes(&HOST_SECRET_KEY),
        },
        user_public_key: PublicKey::Ed25519 {
            public_key: VerifyingKey::from_bytes(&USER_PUBLIC_KEY).unwrap(),
        },
    };

    let mut packet_buffer = [0u8; 4096]; // the borrowed byte buffer
    let mut transport = Transport::new(&mut packet_buffer, behavior);

    loop {
        let mut channel = transport.accept().await?;

        println!(
            "Request {:?} by user {:?} from client {:?}",
            channel.request(),
            channel.user(),
            channel.client_ssh_id_string()
        );

        match channel.request() {
            Request::Exec(ExampleCommand::Sha256Sum) => {
                // This shows how to read the channel to EOF and write to it afterwards.

                let mut reader = channel.reader(None).await?;

                let mut hasher = Sha256::new();

                while let Some(bytes) = reader.read().await? {
                    hasher.update(bytes);
                }

                let digest = hex::encode(hasher.finalize());

                // Use the simple convenience methods, each call emits one SSH packet.

                channel.write_all_stdout(digest.as_bytes()).await?;
                channel.write_all_stdout(b"\n").await?;

                channel.exit(0).await?;
            }

            Request::Exec(ExampleCommand::Echo) => {
                // This shows how you need to buffer yourself if you need to interleave
                // reads and writes to the channel because the packet buffer is shared.

                let mut buffer = [0u8; 512];

                loop {
                    let read_len = channel.read_exact_stdin(&mut buffer).await?;

                    if read_len == 0 {
                        break;
                    }

                    channel.write_all_stdout(&buffer[..read_len]).await?;
                }

                channel.exit(0).await?;
            }

            Request::Exec(ExampleCommand::Sum(arguments)) => {
                let mut sum = 0;

                let mut parse_error = false;

                for argument in arguments {
                    if let Ok(value) = argument.parse::<i64>() {
                        sum += value;
                    } else {
                        parse_error = true;
                        break;
                    }
                }

                // This shows how to return early with a meaningful exit status.

                if parse_error {
                    channel
                        .write_all_stderr(b"Some arguments were not valid numbers.\n")
                        .await?;
                    channel.exit(2).await?;
                    continue;
                }

                // A (somewhat contrived) example of a zero-copy write; you get the
                // packet buffer as a `&mut [u8]`, write to it via `writeln!`, then
                // tell the transport to send as much of the buffer as was written.

                let mut writer = channel.stdout();
                let mut buffer = writer.buffer();

                let bytes_available = buffer.len();

                // NOTE: there's an assumption here that the write fits in the packet
                // buffer, correct code might chunk as needed to ensure that it will.

                use std::io::Write;

                writeln!(&mut buffer, "Sum = {}", sum).unwrap();

                let bytes_written = bytes_available - buffer.len();

                writer.write_all(bytes_written).await?;

                channel.exit(0).await?;
            }

            Request::Exec(ExampleCommand::Invalid) => {
                channel
                    .write_all_stderr(b"Sorry, your command was not recognized!\n")
                    .await?;
                channel.exit(1).await?;
            }

            Request::Shell => unreachable!("shell requests not allowed"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:2222").await?;

    loop {
        let (stream, _) = listener.accept().await?;

        if let Err(error) = handle_client(stream).await {
            println!("Transport error: {:?}", error);
        }
    }
}

// ======================================================================
// ======= UNIMPORTANT CODE IMPLEMENTING EMBEDDED-IO-ASYNC TRAITS =======
// ======================================================================

use embedded_io_async::{Error, ErrorKind, ErrorType, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug)]
struct AsyncTcpStream(TcpStream);

#[derive(Debug)]
struct TokioError(tokio::io::Error);

impl Error for TokioError {
    fn kind(&self) -> ErrorKind {
        self.0.kind().into()
    }
}

impl ErrorType for AsyncTcpStream {
    type Error = TokioError;
}

impl Read for AsyncTcpStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.read(buf).await.map_err(TokioError)
    }
}

impl Write for AsyncTcpStream {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.write(buf).await.map_err(TokioError)
    }
}
