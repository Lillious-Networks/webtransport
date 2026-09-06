//! The CONNECT stream's capsule loop.
//!
//! draft §6: a WebTransport session lives exactly as long as its CONNECT
//! stream. Capsules on that stream carry close and drain signals, and the
//! stream ending closes the session whether or not a capsule said so.

use crate::session::Session;
use crate::CloseInfo;
use bytes::BytesMut;
use wt_proto::Capsule;

/// Reads capsules from a session's CONNECT stream until the session ends,
/// then removes it from its connection's registry.
///
/// The registry is what routes incoming streams and datagrams to a session, so
/// an entry left behind keeps the whole session alive for as long as the
/// connection lasts. On a pooled connection that is unbounded growth, so
/// deregistration happens here, on every path out of the loop.
pub async fn watch_connect_stream(
    stream: quinn::RecvStream,
    session: Session,
    connection: Option<crate::connection::Connection>,
) {
    let id = session.id();
    read_capsules(stream, session).await;

    let Some(connection) = connection else { return };
    connection.registry().remove(id);

    // A QUIC connection outlives its sessions on purpose: pooling puts several
    // on one connection. But once the last one ends nothing will use it again,
    // and quinn would hold it open until the idle timeout, retaining its state
    // the whole time. Closing here is what makes session churn cost nothing.
    if connection.registry().is_empty() {
        connection.quinn().close(0u32.into(), b"");
    }
}

async fn read_capsules(mut stream: quinn::RecvStream, session: Session) {
    let mut buf = BytesMut::new();
    let mut chunk = [0u8; 4096];

    loop {
        // Drain every capsule already buffered before waiting for more bytes.
        loop {
            let mut probe = buf.clone().freeze();
            match Capsule::decode(&mut probe) {
                Ok(Some(capsule)) => {
                    buf = BytesMut::from(&probe[..]);
                    match capsule {
                        Capsule::CloseSession { code, reason } => {
                            session.close(CloseInfo { code, reason });
                            return;
                        }
                        Capsule::DrainSession => session.drain(),
                        // Flow-control capsules are milestone 3 work; unknown
                        // capsules are skipped per RFC 9297.
                        _ => {}
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    session.fail(format!("malformed capsule: {e}"));
                    return;
                }
            }
        }

        match stream.read(&mut chunk).await {
            Ok(Some(0)) => continue,
            Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
            // A clean end of the CONNECT stream is equivalent to a close with
            // code 0 and no reason (draft §6).
            Ok(None) => {
                session.close(CloseInfo::default());
                return;
            }
            Err(e) => {
                session.fail(e.to_string());
                return;
            }
        }
    }
}

/// Encodes a capsule to send on a CONNECT stream.
pub fn encode(capsule: &Capsule) -> Result<Vec<u8>, wt_proto::CapsuleError> {
    let mut buf = Vec::new();
    capsule.encode(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    /// The bytes a close capsule puts on the wire must decode back to the same
    /// close information, since that is what the peer reports to its
    /// application.
    #[test]
    fn a_close_capsule_round_trips() {
        let capsule = Capsule::CloseSession {
            code: 42,
            reason: "bye".into(),
        };
        let encoded = encode(&capsule).unwrap();
        let mut bytes = Bytes::from(encoded);
        assert_eq!(Capsule::decode(&mut bytes).unwrap(), Some(capsule));
    }

    #[test]
    fn a_drain_capsule_round_trips() {
        let encoded = encode(&Capsule::DrainSession).unwrap();
        let mut bytes = Bytes::from(encoded);
        assert_eq!(
            Capsule::decode(&mut bytes).unwrap(),
            Some(Capsule::DrainSession)
        );
    }
}
