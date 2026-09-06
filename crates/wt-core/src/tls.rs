//! TLS configuration, including `serverCertificateHashes` pinning.
//!
//! The W3C spec lets a client bypass the usual web PKI trust evaluation by
//! pinning the hash of the server's leaf certificate. That is what makes local
//! development and self-signed servers usable without installing a CA.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// ALPN protocol identifier for HTTP/3 (RFC 9114 §3.1).
pub const ALPN_H3: &[u8] = b"h3";

/// A `WebTransportHash`: the digest of a server certificate to trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertHash {
    pub algorithm: HashAlgorithm,
    pub value: Vec<u8>,
}

/// Hash algorithms usable for certificate pinning.
///
/// The spec requires user agents to ignore hashes whose algorithm they do not
/// recognise, so unknown algorithms are dropped at parse time rather than
/// erroring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
}

impl HashAlgorithm {
    /// Parses an algorithm name, returning `None` for anything unrecognised.
    ///
    /// Matching is ASCII-case-insensitive, per the spec's normalisation.
    pub fn parse(name: &str) -> Option<Self> {
        name.eq_ignore_ascii_case("sha-256").then_some(Self::Sha256)
    }

    /// Length in bytes of a digest from this algorithm.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
        }
    }
}

/// Verifies a server by matching its leaf certificate against pinned hashes.
///
/// This deliberately replaces the whole web PKI evaluation: name checks, chain
/// building and expiry are all bypassed, exactly as the spec intends when hashes
/// are supplied. A hash of the wrong length can never match, so it is rejected
/// when the verifier is built rather than silently never matching.
#[derive(Debug)]
struct PinnedCertVerifier {
    hashes: Vec<CertHash>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let matches = self.hashes.iter().any(|pin| {
            let actual = pin.algorithm.digest(end_entity.as_ref());
            // Length is validated up front, so a constant-time compare over
            // equal-length digests is meaningful here.
            constant_time_eq(&actual, &pin.value)
        });
        if matches {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "server certificate does not match any serverCertificateHashes entry".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // QUIC mandates TLS 1.3; a 1.2 handshake cannot occur here.
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // The certificate is pinned, but the handshake signature must still be
        // valid: pinning attests to identity, not to possession of the key.
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Compares two byte strings without short-circuiting on the first difference.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error("a {algorithm:?} hash must be {expected} bytes, got {actual}")]
    BadHashLength {
        algorithm: HashAlgorithm,
        expected: usize,
        actual: usize,
    },
    #[error("no usable serverCertificateHashes were supplied")]
    NoUsableHashes,
    #[error("could not load the platform certificate store: {0}")]
    NativeCerts(#[source] std::io::Error),
    #[error(transparent)]
    Rustls(#[from] TlsError),
}

/// Builds the client TLS configuration.
///
/// With `hashes` empty the platform trust store is used; otherwise trust is
/// pinned to those certificates alone.
pub fn client_config(hashes: &[CertHash]) -> Result<rustls::ClientConfig, TlsConfigError> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));

    let mut config = if hashes.is_empty() {
        let mut roots = rustls::RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        for cert in loaded.certs {
            // A store may hold certificates rustls will not parse; skipping one
            // is normal and not a reason to fail the whole connection.
            let _ = roots.add(cert);
        }
        if let Some(err) = loaded.errors.into_iter().next() {
            if roots.is_empty() {
                return Err(TlsConfigError::NativeCerts(std::io::Error::other(err)));
            }
        }
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        for hash in hashes {
            let expected = hash.algorithm.digest_len();
            if hash.value.len() != expected {
                return Err(TlsConfigError::BadHashLength {
                    algorithm: hash.algorithm,
                    expected,
                    actual: hash.value.len(),
                });
            }
        }
        let verifier = PinnedCertVerifier {
            hashes: hashes.to_vec(),
            provider: provider.clone(),
        };
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    };

    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(config)
}

/// Builds the server TLS configuration from a certificate chain and key.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, TlsConfigError> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(config)
}

/// SHA-256 digest of a DER certificate, for reporting a server's own pin.
pub fn certificate_hash(cert: &CertificateDer<'_>) -> Vec<u8> {
    Sha256::digest(cert.as_ref()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_parsing_is_case_insensitive() {
        for name in ["sha-256", "SHA-256", "Sha-256"] {
            assert_eq!(HashAlgorithm::parse(name), Some(HashAlgorithm::Sha256));
        }
    }

    /// The spec says to ignore unrecognised algorithms rather than fail, so
    /// parsing must report them as absent.
    #[test]
    fn unknown_algorithms_are_not_recognised() {
        for name in ["sha-1", "sha256", "sha-512", "md5", ""] {
            assert_eq!(HashAlgorithm::parse(name), None, "{name} must be ignored");
        }
    }

    #[test]
    fn a_hash_of_the_wrong_length_is_rejected() {
        let err = client_config(&[CertHash {
            algorithm: HashAlgorithm::Sha256,
            value: vec![0; 16],
        }])
        .unwrap_err();
        assert!(
            matches!(
                err,
                TlsConfigError::BadHashLength {
                    expected: 32,
                    actual: 16,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn pinned_config_accepts_a_correctly_sized_hash() {
        let config = client_config(&[CertHash {
            algorithm: HashAlgorithm::Sha256,
            value: vec![0; 32],
        }])
        .expect("a 32-byte sha-256 pin is valid");
        assert_eq!(config.alpn_protocols, vec![ALPN_H3.to_vec()]);
    }

    #[test]
    fn constant_time_eq_matches_ordinary_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    /// Pinning compares the leaf certificate's own digest, so an identical
    /// certificate hashes equal and any other input does not.
    #[test]
    fn certificate_hash_is_a_sha256_of_the_der() {
        let cert = CertificateDer::from(vec![1, 2, 3, 4]);
        let hash = certificate_hash(&cert);
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, Sha256::digest([1, 2, 3, 4]).to_vec());
        assert_ne!(
            hash,
            certificate_hash(&CertificateDer::from(vec![1, 2, 3, 5]))
        );
    }
}
