//! Ed25519 signature verification for feed manifests.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tracing::{debug, warn};

use crate::error::{Result, ThreatIntelError};

/// Hex-encoded Ed25519 public key embedded at compile time.
/// This is the initial root-of-trust for feed verification.
/// In production, generate a real keypair and embed the public key here.
const EMBEDDED_PUBLIC_KEY_HEX: &str =
    "e9b20cb34831fe44c9fa5001b9226d75ab2805ffb576e5186a88a0645c575844";

/// Verifier that supports key rotation via `next_public_key` in manifests.
#[derive(Debug, Clone)]
pub struct FeedVerifier {
    /// The current (primary) verifying key.
    current_key: VerifyingKey,
    /// Optional next key announced for rotation.
    next_key: Option<VerifyingKey>,
}

impl FeedVerifier {
    /// Create a verifier using the compile-time embedded public key.
    pub fn from_embedded() -> Result<Self> {
        let key = parse_hex_key(EMBEDDED_PUBLIC_KEY_HEX)?;
        Ok(Self {
            current_key: key,
            next_key: None,
        })
    }

    /// Create a verifier with a specific hex-encoded public key.
    pub fn from_hex(hex_key: &str) -> Result<Self> {
        let key = parse_hex_key(hex_key)?;
        Ok(Self {
            current_key: key,
            next_key: None,
        })
    }

    /// Register a next key for rotation (hex-encoded).
    /// During transition, signatures from either key are accepted.
    pub fn set_next_key(&mut self, hex_key: &str) -> Result<()> {
        let key = parse_hex_key(hex_key)?;
        self.next_key = Some(key);
        debug!("registered next public key for rotation");
        Ok(())
    }

    /// Promote the next key to current and clear next_key.
    pub fn rotate(&mut self) -> Result<()> {
        match self.next_key.take() {
            Some(key) => {
                self.current_key = key;
                debug!("rotated to next public key");
                Ok(())
            }
            None => Err(ThreatIntelError::SignatureInvalid(
                "no next key available for rotation".into(),
            )),
        }
    }

    /// Verify a signature over the given message bytes.
    /// Accepts signatures from either the current or next key.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
        let sig = Signature::from_slice(signature_bytes).map_err(|e| {
            ThreatIntelError::SignatureInvalid(format!("invalid signature format: {e}"))
        })?;

        // Try current key first.
        if self.current_key.verify(message, &sig).is_ok() {
            debug!("signature verified with current key");
            return Ok(());
        }

        // Try next key if available.
        if let Some(ref next) = self.next_key {
            if next.verify(message, &sig).is_ok() {
                debug!("signature verified with next (rotated) key");
                return Ok(());
            }
        }

        warn!("signature verification failed with all available keys");
        Err(ThreatIntelError::SignatureInvalid(
            "signature does not match any known key".into(),
        ))
    }
}

/// Parse a hex-encoded 32-byte Ed25519 public key.
fn parse_hex_key(hex: &str) -> Result<VerifyingKey> {
    let bytes = hex_decode(hex)
        .map_err(|e| ThreatIntelError::SignatureInvalid(format!("invalid hex key: {e}")))?;
    if bytes.len() != 32 {
        return Err(ThreatIntelError::SignatureInvalid(format!(
            "key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| ThreatIntelError::SignatureInvalid(format!("invalid Ed25519 public key: {e}")))
}

/// Simple hex decoder (no external dependency needed).
fn hex_decode(hex: &str) -> std::result::Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd length hex string".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

/// Hex encode bytes.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    #[test]
    fn test_valid_signature_passes() {
        let (signing, verifying) = generate_keypair();
        let pub_hex = hex_encode(verifying.as_bytes());
        let verifier = FeedVerifier::from_hex(&pub_hex).unwrap();

        let message = b"hello feed manifest";
        let sig = signing.sign(message);
        verifier.verify(message, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn test_tampered_message_fails() {
        let (signing, verifying) = generate_keypair();
        let pub_hex = hex_encode(verifying.as_bytes());
        let verifier = FeedVerifier::from_hex(&pub_hex).unwrap();

        let message = b"hello feed manifest";
        let sig = signing.sign(message);

        let tampered = b"tampered feed manifest";
        let result = verifier.verify(tampered, &sig.to_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let (signing, _verifying) = generate_keypair();
        let (_other_signing, other_verifying) = generate_keypair();

        let pub_hex = hex_encode(other_verifying.as_bytes());
        let verifier = FeedVerifier::from_hex(&pub_hex).unwrap();

        let message = b"hello feed manifest";
        let sig = signing.sign(message);
        let result = verifier.verify(message, &sig.to_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_key_rotation() {
        let (signing1, verifying1) = generate_keypair();
        let (signing2, verifying2) = generate_keypair();

        let pub_hex1 = hex_encode(verifying1.as_bytes());
        let pub_hex2 = hex_encode(verifying2.as_bytes());

        let mut verifier = FeedVerifier::from_hex(&pub_hex1).unwrap();
        verifier.set_next_key(&pub_hex2).unwrap();

        let message = b"manifest data";

        // Signature from key1 should work.
        let sig1 = signing1.sign(message);
        verifier.verify(message, &sig1.to_bytes()).unwrap();

        // Signature from key2 should also work (next key).
        let sig2 = signing2.sign(message);
        verifier.verify(message, &sig2.to_bytes()).unwrap();

        // After rotation, key2 becomes current.
        verifier.rotate().unwrap();
        verifier.verify(message, &sig2.to_bytes()).unwrap();

        // Key1 should no longer work after rotation (it's neither current nor next).
        let result = verifier.verify(message, &sig1.to_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_without_next_key_fails() {
        let (_signing, verifying) = generate_keypair();
        let pub_hex = hex_encode(verifying.as_bytes());
        let mut verifier = FeedVerifier::from_hex(&pub_hex).unwrap();
        assert!(verifier.rotate().is_err());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "deadbeef");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
