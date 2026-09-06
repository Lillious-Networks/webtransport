//! WebTransport streams over QUIC streams.
//!
//! A WebTransport stream is a QUIC stream prefixed with a header binding it to a
//! session (draft §4.2, §4.3). Everything after that header is application data.
//!
//! Stream error codes are 32-bit application values that travel as HTTP/3 error
//! codes in a reserved range, so every code crossing the wire is remapped.

use crate::error::{Error, Result};
use crate::send_scheduler::SendScheduler;
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use wt_proto::error_code;
use wt_proto::stream_header::{self, StreamKind};

/// How much to read from a QUIC stream in one call when the consumer has not
/// asked for a specific size.
const DEFAULT_READ_CHUNK: usize = 64 * 1024;

/// How much a scheduled stream may write per turn.
///
/// Small enough that ordering and group fairness are visible within a single
/// large write, large enough that the per-turn overhead stays negligible.
/// Measured: 16KiB costs about 20% of bulk throughput, while 64KiB matches an
/// unscheduled write and larger slices buy nothing further.
const SCHEDULER_SLICE: usize = 64 * 1024;

/// The send half of a WebTransport stream.
pub struct SendStream {
    inner: Mutex<quinn::SendStream>,
    /// Bytes handed to the transport, for `WebTransportSendStreamStats`.
    bytes_written: Arc<AtomicU64>,
    finished: Arc<std::sync::atomic::AtomicBool>,
    /// The scheduler governing this stream's turn to send, and the id it is
    /// known by. Absent for streams opened before a scheduler existed.
    scheduler: Option<(Arc<SendScheduler>, u64)>,
}

impl std::fmt::Debug for SendStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendStream")
            .field("bytes_written", &self.bytes_written.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SendStream {
    /// Wraps an already-accepted QUIC stream whose header has been read.
    pub fn from_quinn(inner: quinn::SendStream) -> Self {
        Self::new(inner)
    }

    fn new(inner: quinn::SendStream) -> Self {
        Self {
            inner: Mutex::new(inner),
            bytes_written: Arc::new(AtomicU64::new(0)),
            finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            scheduler: None,
        }
    }

    /// Places this stream under a scheduler, which decides when it may write.
    pub fn attach_scheduler(&mut self, scheduler: Arc<SendScheduler>, id: u64) {
        self.scheduler = Some((scheduler, id));
    }

    /// The scheduler id, if this stream is scheduled.
    pub fn scheduler_id(&self) -> Option<u64> {
        self.scheduler.as_ref().map(|(_, id)| *id)
    }

    /// Moves this stream into a different send group.
    ///
    /// The spec allows reassignment at any time, and a group is its own
    /// `sendOrder` numberspace, so this changes which streams it competes with.
    pub fn set_send_group(&self, group: Option<u64>) {
        if let Some((scheduler, id)) = &self.scheduler {
            scheduler.set_group(*id, group);
        }
    }

    /// Changes this stream's send order within its group.
    pub fn set_send_order(&self, send_order: Option<i64>) {
        if let Some((scheduler, id)) = &self.scheduler {
            scheduler.set_send_order(*id, send_order);
        }
    }

    /// Writes a chunk, resolving once the transport has accepted all of it.
    ///
    /// Resolving here is what gives the JS `WritableStream` real backpressure:
    /// a write that cannot fit the flow-control window stays pending.
    pub async fn write_all(&self, data: &[u8]) -> Result<()> {
        let Some((scheduler, id)) = &self.scheduler else {
            // No scheduler: write straight through.
            let mut stream = self.inner.lock().await;
            stream.write_all(data).await.map_err(map_write_error)?;
            self.bytes_written
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            return Ok(());
        };

        scheduler.enqueue(*id, data.len() as u64);

        // Write in bounded slices, taking a fresh turn for each. Writing the
        // whole buffer under one turn would let a single large write hold the
        // transport for its full duration, so send order would only decide who
        // *starts* first rather than who gets bandwidth, which is what the
        // spec's ordering and group fairness actually promise.
        let mut offset = 0usize;
        while offset < data.len() {
            scheduler.wait_for_turn(*id).await;

            let end = (offset + SCHEDULER_SLICE).min(data.len());
            let slice = &data[offset..end];

            let result = {
                let mut stream = self.inner.lock().await;
                stream.write_all(slice).await
            };
            scheduler.wrote(*id, slice.len() as u64);

            if let Err(e) = result {
                // Withdraw whatever is left; this stream is not sending again.
                scheduler.remove(*id);
                return Err(map_write_error(e));
            }

            self.bytes_written
                .fetch_add(slice.len() as u64, Ordering::Relaxed);
            offset = end;
        }
        Ok(())
    }

    /// Writes what fits in the current flow-control window without waiting.
    ///
    /// Returns how many bytes were accepted, which backs `atomicWrite`: a write
    /// that cannot be placed in its entirety must be reported rather than
    /// blocking behind the window.
    pub async fn write_some(&self, data: &[u8]) -> Result<usize> {
        let mut stream = self.inner.lock().await;
        let written = stream.write(data).await.map_err(map_write_error)?;
        self.bytes_written
            .fetch_add(written as u64, Ordering::Relaxed);
        Ok(written)
    }

    /// Finishes the stream cleanly, signalling end of data.
    pub async fn finish(&self) -> Result<()> {
        if self.finished.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        if let Some((scheduler, id)) = &self.scheduler {
            scheduler.remove(*id);
        }
        let mut stream = self.inner.lock().await;
        stream.finish().map_err(|_| Error::StreamClosed)
    }

    /// Aborts the stream with an application error code.
    pub async fn reset(&self, code: u32) -> Result<()> {
        self.finished.store(true, Ordering::SeqCst);
        if let Some((scheduler, id)) = &self.scheduler {
            scheduler.remove(*id);
        }
        let mut stream = self.inner.lock().await;
        let mapped = quinn::VarInt::from_u64(error_code::to_http(code))
            .map_err(|_| Error::Protocol("stream error code out of range".into()))?;
        // A stream already finished or reset cannot be reset again; that is not
        // an error worth surfacing.
        let _ = stream.reset(mapped);
        Ok(())
    }

    /// Waits for the peer to stop reading, reporting the code it sent.
    pub async fn stopped(&self) -> Result<Option<u32>> {
        let stream = self.inner.lock().await;
        match stream.stopped().await {
            Ok(Some(code)) => Ok(error_code::from_http(code.into_inner())),
            Ok(None) => Ok(None),
            Err(_) => Err(Error::StreamClosed),
        }
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    /// Sets the transport-level priority. Milestone 3 replaces this with the
    /// send scheduler, which can express 64-bit ordering and groups.
    pub async fn set_priority(&self, priority: i32) {
        let stream = self.inner.lock().await;
        let _ = stream.set_priority(priority);
    }
}

/// The receive half of a WebTransport stream.
pub struct RecvStream {
    inner: Mutex<quinn::RecvStream>,
    bytes_read: Arc<AtomicU64>,
}

impl std::fmt::Debug for RecvStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvStream")
            .field("bytes_read", &self.bytes_read.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl RecvStream {
    /// Wraps an already-accepted QUIC stream whose header has been read.
    pub fn from_quinn(inner: quinn::RecvStream) -> Self {
        Self::new(inner)
    }

    fn new(inner: quinn::RecvStream) -> Self {
        Self {
            inner: Mutex::new(inner),
            bytes_read: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Reads the next chunk, or `None` at end of stream.
    ///
    /// `max` bounds the read so a BYOB reader can ask for what it has room for.
    pub async fn read_chunk(&self, max: Option<usize>) -> Result<Option<Bytes>> {
        let limit = max.unwrap_or(DEFAULT_READ_CHUNK).max(1);
        let mut stream = self.inner.lock().await;
        let mut buf = BytesMut::zeroed(limit);
        match stream.read(&mut buf).await {
            Ok(Some(n)) => {
                self.bytes_read.fetch_add(n as u64, Ordering::Relaxed);
                buf.truncate(n);
                Ok(Some(buf.freeze()))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(map_read_error(e)),
        }
    }

    /// Asks the peer to stop sending, with an application error code.
    pub async fn stop(&self, code: u32) -> Result<()> {
        let mut stream = self.inner.lock().await;
        let mapped = quinn::VarInt::from_u64(error_code::to_http(code))
            .map_err(|_| Error::Protocol("stream error code out of range".into()))?;
        let _ = stream.stop(mapped);
        Ok(())
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }
}

/// Translates a quinn write failure, decoding the peer's application code.
fn map_write_error(e: quinn::WriteError) -> Error {
    match e {
        quinn::WriteError::Stopped(code) => match error_code::from_http(code.into_inner()) {
            Some(app) => Error::StreamStopped(app),
            // A code outside the WebTransport range did not come from the
            // application: the peer dropped the stream, or the HTTP/3 layer
            // stopped it. That is a closed stream, not a protocol violation.
            None => Error::StreamClosed,
        },
        quinn::WriteError::ConnectionLost(e) => Error::Io(e.to_string()),
        quinn::WriteError::ClosedStream => Error::StreamClosed,
        quinn::WriteError::ZeroRttRejected => Error::Io("0-RTT rejected".into()),
    }
}

/// Translates a quinn read failure, decoding the peer's application code.
fn map_read_error(e: quinn::ReadError) -> Error {
    match e {
        quinn::ReadError::Reset(code) => match error_code::from_http(code.into_inner()) {
            Some(app) => Error::StreamReset(app),
            // As above: a code outside the WebTransport range is not an
            // application error, so report the stream as closed.
            None => Error::StreamClosed,
        },
        quinn::ReadError::ConnectionLost(e) => Error::Io(e.to_string()),
        quinn::ReadError::ClosedStream => Error::StreamClosed,
        quinn::ReadError::IllegalOrderedRead => Error::Protocol("illegal ordered read".into()),
        quinn::ReadError::ZeroRttRejected => Error::Io("0-RTT rejected".into()),
    }
}

/// A bidirectional WebTransport stream.
#[derive(Debug)]
pub struct BidiStream {
    pub send: Arc<SendStream>,
    pub recv: Arc<RecvStream>,
}

/// Opens a unidirectional stream and writes its WebTransport header.
pub async fn open_uni(conn: &quinn::Connection, session_id: u64) -> Result<Arc<SendStream>> {
    Ok(Arc::new(open_uni_raw(conn, session_id).await?))
}

/// As [`open_uni`], but returns the stream unwrapped so a scheduler can be
/// attached before it is shared.
pub async fn open_uni_raw(conn: &quinn::Connection, session_id: u64) -> Result<SendStream> {
    let mut stream = conn
        .open_uni()
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;
    let mut header = Vec::with_capacity(stream_header::encoded_len(StreamKind::Uni, session_id));
    stream_header::encode(&mut header, StreamKind::Uni, session_id)
        .map_err(|e| Error::Protocol(e.to_string()))?;
    stream.write_all(&header).await.map_err(map_write_error)?;
    Ok(SendStream::new(stream))
}

/// Opens a bidirectional stream and writes its WebTransport header.
pub async fn open_bi(conn: &quinn::Connection, session_id: u64) -> Result<BidiStream> {
    let (send, recv) = open_bi_raw(conn, session_id).await?;
    Ok(BidiStream {
        send: Arc::new(send),
        recv: Arc::new(recv),
    })
}

/// As [`open_bi`], but returns the halves unwrapped so a scheduler can be
/// attached before they are shared.
pub async fn open_bi_raw(
    conn: &quinn::Connection,
    session_id: u64,
) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;
    let mut header = Vec::with_capacity(stream_header::encoded_len(StreamKind::Bidi, session_id));
    stream_header::encode(&mut header, StreamKind::Bidi, session_id)
        .map_err(|e| Error::Protocol(e.to_string()))?;
    send.write_all(&header).await.map_err(map_write_error)?;
    Ok((SendStream::new(send), RecvStream::new(recv)))
}

/// Reads the WebTransport header from an accepted stream.
///
/// Returns the session the stream belongs to. Reads one byte at a time: the
/// header is a handful of bytes and over-reading would consume application data
/// that belongs to the stream's consumer.
pub async fn read_header(stream: &mut quinn::RecvStream, kind: StreamKind) -> Result<u64> {
    let mut buf = BytesMut::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(Some(0)) => continue,
            Ok(Some(_)) => {
                buf.extend_from_slice(&byte);
                let mut probe = buf.clone().freeze();
                match stream_header::decode(&mut probe, kind) {
                    Ok(Some(session_id)) => return Ok(session_id),
                    // Not enough bytes yet.
                    Ok(None) => continue,
                    Err(e) => return Err(Error::Protocol(e.to_string())),
                }
            }
            Ok(None) => {
                return Err(Error::Protocol(
                    "stream ended before its WebTransport header".into(),
                ))
            }
            Err(e) => return Err(map_read_error(e)),
        }
    }
}

/// Accepts a unidirectional stream and reads its header.
pub async fn accept_uni(conn: &quinn::Connection) -> Result<(u64, Arc<RecvStream>)> {
    let mut stream = conn
        .accept_uni()
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    let session_id = read_header(&mut stream, StreamKind::Uni).await?;
    Ok((session_id, Arc::new(RecvStream::new(stream))))
}

/// Accepts a bidirectional stream and reads its header.
pub async fn accept_bi(conn: &quinn::Connection) -> Result<(u64, BidiStream)> {
    let (send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    let session_id = read_header(&mut recv, StreamKind::Bidi).await?;
    Ok((
        session_id,
        BidiStream {
            send: Arc::new(SendStream::new(send)),
            recv: Arc::new(RecvStream::new(recv)),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every application code must survive the trip through HTTP/3 encoding,
    /// which is what `reset` and `stop` rely on.
    #[test]
    fn error_codes_survive_the_http3_mapping() {
        for code in [0u32, 1, 0x1e, 0x1f, 1000, u32::MAX] {
            let http = error_code::to_http(code);
            assert_eq!(error_code::from_http(http), Some(code));
            assert!(
                quinn::VarInt::from_u64(http).is_ok(),
                "code {code} must fit a QUIC varint"
            );
        }
    }

    /// A stop carrying a code outside the WebTransport range did not come from
    /// the application (a dropped stream reports code 0), so it must read as a
    /// closed stream rather than a protocol violation.
    #[test]
    fn out_of_range_stop_codes_read_as_a_closed_stream() {
        for code in [0u32, 5, 0x21] {
            let err = map_write_error(quinn::WriteError::Stopped(quinn::VarInt::from_u32(code)));
            assert!(
                matches!(err, Error::StreamClosed),
                "code {code} gave {err:?}"
            );
            assert_eq!(err.stream_error_code(), None);
        }
    }

    #[test]
    fn out_of_range_reset_codes_read_as_a_closed_stream() {
        let err = map_read_error(quinn::ReadError::Reset(quinn::VarInt::from_u32(0)));
        assert!(matches!(err, Error::StreamClosed), "got {err:?}");
    }

    #[test]
    fn peer_stop_is_reported_with_its_application_code() {
        let http = error_code::to_http(42);
        let err = map_write_error(quinn::WriteError::Stopped(
            quinn::VarInt::from_u64(http).unwrap(),
        ));
        assert!(matches!(err, Error::StreamStopped(42)), "got {err:?}");
        assert_eq!(err.stream_error_code(), Some(42));
        assert_eq!(err.source_kind(), crate::ErrorSource::Stream);
    }

    #[test]
    fn peer_reset_is_reported_with_its_application_code() {
        let http = error_code::to_http(7);
        let err = map_read_error(quinn::ReadError::Reset(
            quinn::VarInt::from_u64(http).unwrap(),
        ));
        assert!(matches!(err, Error::StreamReset(7)), "got {err:?}");
        assert_eq!(err.stream_error_code(), Some(7));
    }

    #[test]
    fn a_closed_stream_is_not_a_peer_error() {
        assert_eq!(
            map_write_error(quinn::WriteError::ClosedStream).stream_error_code(),
            None
        );
        assert_eq!(
            map_read_error(quinn::ReadError::ClosedStream).stream_error_code(),
            None
        );
    }
}
