use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// PKCE (Proof Key for Code Exchange) parameters for the OAuth 2.0 authorization code flow.
///
/// Matches the Python implementation:
/// - `state`: 32 random bytes, base64url encoded without padding
/// - `nonce`: 16 random bytes, base64url encoded without padding
/// - `code_verifier`: 32 random bytes, base64url encoded without padding
/// - `code_challenge`: SHA-256 hash of `code_verifier`, base64url encoded without padding
pub struct PkceParams {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub code_challenge: String,
}

impl PkceParams {
    /// Generates a new set of PKCE parameters with cryptographically secure random values.
    pub fn generate() -> Self {
        let state = generate_token(32);
        let nonce = generate_token(16);
        let code_verifier = generate_token(32);
        let code_challenge = compute_code_challenge(&code_verifier);

        Self {
            state,
            nonce,
            code_verifier,
            code_challenge,
        }
    }
}

/// Generates a base64url-encoded random token of the specified byte length (without padding).
fn generate_token(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(&buf)
}

/// Computes the S256 code challenge: SHA-256 hash of the verifier, base64url encoded without
/// padding. This matches the Python behavior:
/// ```python
/// base64.urlsafe_b64encode(hashlib.sha256(CODE_VERIFIER.encode('ascii')).digest())
///     .decode('ascii').rstrip('=')
/// ```
fn compute_code_challenge(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE;

    #[test]
    fn test_generate_produces_valid_lengths() {
        let params = PkceParams::generate();

        // 32 bytes base64url-encoded without padding = 43 characters
        assert_eq!(params.state.len(), 43);
        // 16 bytes base64url-encoded without padding = 22 characters
        assert_eq!(params.nonce.len(), 22);
        // 32 bytes base64url-encoded without padding = 43 characters
        assert_eq!(params.code_verifier.len(), 43);
        // SHA-256 digest is 32 bytes, base64url-encoded without padding = 43 characters
        assert_eq!(params.code_challenge.len(), 43);
    }

    #[test]
    fn test_code_challenge_matches_verifier() {
        let params = PkceParams::generate();

        let expected_digest = Sha256::digest(params.code_verifier.as_bytes());
        let expected_challenge = URL_SAFE_NO_PAD.encode(expected_digest);

        assert_eq!(params.code_challenge, expected_challenge);
    }

    #[test]
    fn test_code_challenge_no_padding() {
        let params = PkceParams::generate();
        assert!(!params.state.contains('='));
        assert!(!params.nonce.contains('='));
        assert!(!params.code_verifier.contains('='));
        assert!(!params.code_challenge.contains('='));
    }

    #[test]
    fn test_values_are_base64url_decodable() {
        let params = PkceParams::generate();

        // All values should be decodable as base64url (with or without padding)
        assert!(URL_SAFE.decode(pad_base64(&params.state)).is_ok());
        assert!(URL_SAFE.decode(pad_base64(&params.nonce)).is_ok());
        assert!(URL_SAFE.decode(pad_base64(&params.code_verifier)).is_ok());
        assert!(URL_SAFE.decode(pad_base64(&params.code_challenge)).is_ok());
    }

    #[test]
    fn test_each_call_produces_unique_values() {
        let a = PkceParams::generate();
        let b = PkceParams::generate();

        assert_ne!(a.state, b.state);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.code_verifier, b.code_verifier);
        assert_ne!(a.code_challenge, b.code_challenge);
    }

    /// Adds base64 padding to a no-pad encoded string so the standard decoder accepts it.
    fn pad_base64(s: &str) -> String {
        let remainder = s.len() % 4;
        if remainder == 0 {
            s.to_string()
        } else {
            format!("{}{}", s, "=".repeat(4 - remainder))
        }
    }
}
