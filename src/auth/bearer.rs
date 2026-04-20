use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!("drust_{encoded}")
}

pub fn hash_token(plaintext: &str) -> String {
    let digest = Sha256::digest(plaintext.as_bytes());
    hex::encode_lower(&digest)
}

pub fn verify_token_hash(plaintext: &str, expected_hex: &str) -> bool {
    let actual = hash_token(plaintext);
    actual.as_bytes().ct_eq(expected_hex.as_bytes()).unwrap_u8() == 1
}

pub fn token_hint(plaintext: &str) -> String {
    let prefix_end = "drust_".len();
    if plaintext.len() > prefix_end + 6 {
        format!("{}…", &plaintext[..prefix_end + 6])
    } else {
        format!("{}…", plaintext)
    }
}

mod hex {
    pub fn encode_lower(bytes: &[u8]) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}
