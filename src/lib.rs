use std::{
    fmt::Debug,
    io::Error,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_compression::tokio::{bufread::DeflateDecoder, write::DeflateEncoder};
use async_trait::async_trait;
use bytes::BytesMut;
use nom::{error::ErrorKind, Err, IResult, Needed};
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf, ReadHalf, WriteHalf,
    },
    time::timeout,
};
use tokio_native_tls::TlsAcceptor;
use tracing::{debug, error, info};

use crate::utils::{escape, escape_trace};

pub mod error;
pub mod filter;
pub mod imap;
pub mod log;
pub mod pop3;
pub mod predictor;
pub mod smtp;
pub mod utils;

pub enum SplitOffResult<O> {
    Ok((BytesMut, O)),
    Incomplete(Needed),
    LiteralAck,
    Failure,
}

fn split_off_message<P, O>(buffer: &mut BytesMut, parser: &P) -> SplitOffResult<O>
where
    P: Fn(&[u8]) -> IResult<&[u8], O>,
{
    match parser(buffer) {
        Ok((rem, out)) => {
            // https://github.com/rust-lang/rust/issues/59159
            let rem_len = rem.len();
            let consumed = buffer.split_to(buffer.len() - rem_len);

            SplitOffResult::Ok((consumed, out))
        }
        Err(e) => match e {
            Err::Incomplete(needed) => SplitOffResult::Incomplete(needed),
            Err::Failure(error) if error.code == ErrorKind::Fix => SplitOffResult::LiteralAck,
            Err::Error(_) | Err::Failure(_) => SplitOffResult::Failure,
        },
    }
}

#[async_trait]
pub trait Splitter {
    async fn run(self);

    async fn send_raw(&mut self, data: &[u8]) -> bool {
        match timeout(Duration::from_secs(1), self.stream().write_all(data)).await {
            Ok(result) => {
                if let Err(error) = result {
                    error!(?error, "send error");
                    return false;
                }
            }
            Err(_) => {
                error!(event = "send timeout", "send (metadata)");
                return false;
            }
        };

        // FIXME: This was introduced for COMPRESSION. Why is it necessary?
        self.stream().flush().await.unwrap();

        let msg = escape_trace(data).trim().to_string();
        info!(%msg, amt=data.len(), tls=self.stream().is_tls(), "send");

        true
    }

    async fn recv<P, O>(&mut self, parse: P) -> Result<O, Vec<u8>>
    where
        P: Fn(&[u8]) -> IResult<&[u8], O> + Sync + Send,
        O: Debug + Send + 'static,
    {
        let mut read_buffer = [0u8; 2048];

        loop {
            // Try to split off a full command from self.buffer first.
            match split_off_message(self.buffer(), &parse) {
                SplitOffResult::Ok((consumed, parsed)) => {
                    debug!(consumed=%escape(&consumed), remaining=%escape(self.buffer()), ?parsed, "Parsing successful");

                    if !self.buffer().is_empty() {
                        debug!(len = self.buffer().len(), "Buffer still has bytes");
                    }

                    return Ok(parsed);
                }
                SplitOffResult::Incomplete(needed) => {
                    debug!(?needed, "Parsing needs more data");
                }
                SplitOffResult::LiteralAck => {
                    self.incomplete().await;
                }
                SplitOffResult::Failure => {
                    error!(
                    remainder=%escape(self.buffer()),
                    "Parsing error/failure",
                    );

                    let flushed = self.buffer().to_vec();
                    self.buffer().clear();
                    debug!("Buffer cleared");

                    return Err(flushed);
                }
            }

            // FIXME: Make timeout configurable
            let res = timeout(Duration::from_secs(5), self.stream().read(&mut read_buffer)).await;

            let res = match res {
                Ok(res) => res,
                Err(_) => {
                    error!(event = "recv timeout", "read (metadata)");
                    return Err(vec![]);
                }
            };

            // If no command (and no error) was generated, e.g. parse was `Incomplete`, try to read more data...
            match res {
                Ok(0) => {
                    info!(event = "EOF", "read (metadata)");
                    error!("Connection was closed.");
                    return Err(vec![]);
                }
                Ok(amt) => {
                    let msg = escape_trace(&read_buffer[..amt]).trim_end().to_string();
                    info!(%msg, amt, tls=self.stream().is_tls(), "read");

                    // Got some bytes. Append them to the internal buffer.
                    // The next iteration of the loop could yield a command.
                    // If not, we will end up here again :-)
                    self.buffer().extend_from_slice(&read_buffer[..amt]);
                }
                Err(error) => {
                    info!(?error, event = "error", "read (metadata)");
                    panic!()
                }
            }
        }
    }

    async fn accept_tls(&mut self) {
        info!(identity = %self.pkcs12().file, "accept tls");

        if !self.buffer().is_empty() {
            error!(
                buffer=%escape(self.buffer()),
                "Protocol violation. There is remaining data in the buffer."
            );
            error!("Keep the command injection vulnerability for demonstration purposes.");
        }

        let file = self.pkcs12().file;
        let pass = self.pkcs12().password;

        self.stream().accept_tls(&file, &pass).await;
    }

    async fn accept_compression(&mut self) {
        info!("accept compression");

        self.stream().accept_compression().await;
    }

    fn buffer(&mut self) -> &mut BytesMut;

    fn stream(&mut self) -> &mut ConsolidatedStream;

    fn pkcs12(&self) -> PKCS12;

    async fn incomplete(&mut self) {}
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PKCS12 {
    pub file: String,
    pub password: String,
}

pub trait Stream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

impl<T> Stream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

// TODO: Is there a better way for transient replacements in Rust?
struct Dummy;

impl AsyncRead for Dummy {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        unimplemented!()
    }
}

impl AsyncWrite for Dummy {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        unimplemented!()
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context) -> Poll<Result<(), std::io::Error>> {
        unimplemented!()
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context) -> Poll<Result<(), std::io::Error>> {
        unimplemented!()
    }
}

#[pin_project]
struct DeflateStream<T> {
    #[pin]
    decoder: DeflateDecoder<BufReader<ReadHalf<T>>>,
    #[pin]
    encoder: DeflateEncoder<WriteHalf<T>>,
}

impl<T> AsyncRead for DeflateStream<T>
where
    T: AsyncRead + AsyncWrite,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<std::io::Result<()>> {
        self.project().decoder.poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for DeflateStream<T>
where
    T: AsyncRead + AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        self.project().encoder.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        self.project().encoder.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().encoder.poll_shutdown(cx)
    }
}

#[pin_project]
pub struct ConsolidatedStream {
    #[pin]
    stream: Box<dyn Stream>,
    is_tls: bool,
    is_compression: bool,
}

impl ConsolidatedStream {
    pub fn new(stream: Box<dyn Stream>) -> ConsolidatedStream {
        ConsolidatedStream {
            stream,
            is_tls: false,
            is_compression: false,
        }
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub async fn accept_tls(&mut self, pkcs12_path: &str, pkcs12_password: &str) {
        let stream = {
            let mut stream: Box<dyn Stream> = Box::new(Dummy {});
            std::mem::swap(&mut stream, &mut self.stream);
            stream
        };

        let identity = {
            let der_file = std::fs::read(pkcs12_path)
                .unwrap_or_else(|_| panic!("Could not open PKCS12 file \"{}\".", pkcs12_path));
            tokio_native_tls::native_tls::Identity::from_pkcs12(&der_file, pkcs12_password)
                .expect("Could not read pkcs12 file.")
        };

        let acceptor =
            TlsAcceptor::from(tokio_native_tls::native_tls::TlsAcceptor::new(identity).unwrap());
        let acceptor = Arc::new(acceptor);

        let mut tls_stream: Box<dyn Stream> = Box::new(acceptor.accept(stream).await.unwrap());

        std::mem::swap(&mut tls_stream, &mut self.stream);

        self.is_tls = true;
    }

    pub async fn accept_compression(&mut self) {
        let stream = {
            let mut stream: Box<dyn Stream> = Box::new(Dummy {});
            std::mem::swap(&mut stream, &mut self.stream);
            stream
        };

        let (read, write) = tokio::io::split(stream);

        let mut deflate: Box<dyn Stream> = Box::new(DeflateStream {
            decoder: DeflateDecoder::new(BufReader::new(read)),
            encoder: DeflateEncoder::new(write),
        });

        std::mem::swap(&mut deflate, &mut self.stream);

        self.is_compression = true;
    }
}

impl AsyncRead for ConsolidatedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl AsyncWrite for ConsolidatedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Smtp,
    Pop3,
    Imap,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Smtp => write!(f, "smtp"),
            Self::Pop3 => write!(f, "pop3"),
            Self::Imap => write!(f, "imap"),
        }
    }
}

pub fn parse_protocol(src: &str) -> Result<Protocol, Box<dyn std::error::Error>> {
    match src.to_lowercase().as_ref() {
        "smtp" => Ok(Protocol::Smtp),
        "pop3" => Ok(Protocol::Pop3),
        "imap" => Ok(Protocol::Imap),
        _ => Err("Protocol must be either `smtp`, `pop3`, or `imap`.".into()),
    }
}
