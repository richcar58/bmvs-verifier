// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! # BMVS published election artifact schema
//!
//! This crate defines the **schema of everything a BMVS election publishes**:
//! the election configuration record, bulletin-board segments, chain-head
//! attestations, disposition records, tabulator reports, and the tally
//! transcript — plus the [`ElectionRecord`] bundle that ties one election's
//! artifacts together.
//!
//! ## Design rules
//!
//! - **Kernel-free.** This crate depends only on `serde`. Cryptographic
//!   *objects* (ciphertexts, proofs) appear as opaque [`Bytes`] payloads in
//!   the kernel's own serialization; cryptographic *checking* lives in
//!   `verifier-core` and in independent verifier implementations.
//! - **Versioned from the first field.** Every top-level artifact carries
//!   `schema_version`. Within a major version, changes are additive only:
//!   a verifier for schema `0.x` must accept any `0.y` record with `y >= x`
//!   for the fields it knows.
//! - **Canonical byte inputs are part of the schema.** Wherever an artifact
//!   is signed or hashed, the exact byte string is defined *here* (the
//!   `signing_input()` / hashing rules), never left to an implementation.
//!   JSON is the transport encoding; signatures and hashes are computed over
//!   these canonical inputs, not over JSON.
//!
//! ## Encoding
//!
//! Artifacts serialize to JSON via serde. Byte strings ([`Bytes`]) encode as
//! lowercase hex. Signatures are Ed25519 (64 bytes); verifying keys are
//! Ed25519 (32 bytes); hashes are SHA3-256 (32 bytes), matching the
//! `VoteSecure` kernel's `Hasher256`.

pub mod attestation;
pub mod board;
pub mod bytes;
pub mod config;
pub mod disposition;
pub mod instance;
pub mod record;
pub mod tabulator;
pub mod transcript;

pub use attestation::{ChainHeadAttestation, SiteCounts};
pub use board::{BoardSegment, BulletinEntry, BulletinKind, EntryFlags};
pub use bytes::Bytes;
pub use config::{ElectionConfigRecord, NamedSignature, TrusteePublic};
pub use disposition::{DispositionDecision, DispositionRecord};
pub use instance::InstanceDescriptor;
pub use record::ElectionRecord;
pub use tabulator::{ContestTotals, OptionTotal, TabulatorReport};
pub use transcript::{MixRound, PartialDecryptionSet, TallyTranscript};

/// The schema version written by this crate.
///
/// Verifiers accept any record whose version has the same major component
/// and a minor/patch not older than the fields they require.
pub const SCHEMA_VERSION: &str = "0.1.0";

/// Returns true when `version` is acceptable to a verifier built against
/// this crate: same major version. (Within a major version the schema is
/// additive-only, so newer minors remain readable.)
#[must_use]
pub fn version_compatible(version: &str) -> bool {
    let major = |v: &str| v.split('.').next().map(str::to_owned);
    major(version) == major(SCHEMA_VERSION)
}

/// Domain-separation tags for the canonical byte inputs defined by this
/// schema. Each signed or hashed artifact input begins with its tag so that
/// bytes valid in one role can never verify in another.
pub mod ds_tags {
    /// Bulletin entry hash input.
    pub const BULLETIN_ENTRY: &[u8] = b"bmvs/v0/bulletin-entry";
    /// Board segment signing input.
    pub const BOARD_SEGMENT: &[u8] = b"bmvs/v0/board-segment";
    /// Chain-head attestation signing input.
    pub const ATTESTATION: &[u8] = b"bmvs/v0/attestation";
    /// Disposition record signing input.
    pub const DISPOSITION: &[u8] = b"bmvs/v0/disposition";
    /// Tabulator report signing input.
    pub const TABULATOR_REPORT: &[u8] = b"bmvs/v0/tabulator-report";
    /// Election configuration signing input.
    pub const CONFIG: &[u8] = b"bmvs/v0/election-config";
    /// Tally transcript signing input.
    pub const TRANSCRIPT: &[u8] = b"bmvs/v0/tally-transcript";
}

/// Length-prefixed field concatenation used by every canonical input in this
/// schema: `tag || (len_u64_le || field)*`. Length prefixes prevent field
/// boundary ambiguity (two different field lists can never concatenate to
/// the same byte string).
#[must_use]
pub fn canonical_input(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + fields.iter().map(|f| f.len() + 8).sum::<usize>());
    out.extend_from_slice(tag);
    for f in fields {
        out.extend_from_slice(&(f.len() as u64).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compatibility_same_major() {
        assert!(version_compatible("0.1.0"));
        assert!(version_compatible("0.9.7"));
        assert!(!version_compatible("1.0.0"));
        assert!(!version_compatible(""));
    }

    #[test]
    fn canonical_input_is_boundary_unambiguous() {
        // ["ab", "c"] and ["a", "bc"] must produce different byte strings.
        let a = canonical_input(b"t", &[b"ab", b"c"]);
        let b = canonical_input(b"t", &[b"a", b"bc"]);
        assert_ne!(a, b);
    }
}
