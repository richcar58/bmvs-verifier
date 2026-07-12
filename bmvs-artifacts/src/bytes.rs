// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! Byte strings that serialize as lowercase hex in JSON.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An owned byte string; the JSON encoding is a lowercase hex string.
///
/// Used for hashes (32 bytes), Ed25519 verifying keys (32 bytes) and
/// signatures (64 bytes), and opaque kernel-encoded cryptographic payloads
/// (variable length). Length constraints are enforced by the consuming
/// checks, not by the type, so that schema evolution never breaks decoding.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    /// Wraps a byte vector.
    #[must_use]
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// The contained bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Lowercase hex rendering (the JSON form).
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(self.0.len() * 2);
        for b in &self.0 {
            use std::fmt::Write as _;
            // Writing to a String cannot fail.
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Parses lowercase or uppercase hex.
    ///
    /// # Errors
    /// Returns a description of the first offending character or an odd
    /// length.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        if !s.len().is_multiple_of(2) {
            return Err(format!("odd-length hex string ({} chars)", s.len()));
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = hex_val(bytes[i]).ok_or_else(|| bad_char(s, i))?;
            let lo = hex_val(bytes[i + 1]).ok_or_else(|| bad_char(s, i + 1))?;
            out.push((hi << 4) | lo);
        }
        Ok(Self(out))
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn bad_char(s: &str, i: usize) -> String {
    format!("invalid hex character at offset {i} in {s:?}")
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes({})", self.to_hex())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let b = Bytes::new(vec![0x00, 0x01, 0xab, 0xff]);
        assert_eq!(b.to_hex(), "0001abff");
        assert_eq!(Bytes::from_hex("0001abff").expect("valid hex"), b);
        assert_eq!(Bytes::from_hex("0001ABFF").expect("valid hex"), b);
    }

    #[test]
    fn hex_rejects_bad_input() {
        assert!(Bytes::from_hex("abc").is_err(), "odd length must fail");
        assert!(Bytes::from_hex("zz").is_err(), "non-hex must fail");
    }

    #[test]
    fn json_round_trip() {
        let b = Bytes::new(vec![1, 2, 3]);
        let json = serde_json::to_string(&b).expect("serialize");
        assert_eq!(json, "\"010203\"");
        let back: Bytes = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, b);
    }
}
