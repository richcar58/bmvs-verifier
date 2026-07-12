// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! Chain-head attestations: the printed, publicly posted close-out records
//! that bind each site's local board to the later central publication
//! (architecture flow F9.1).

use crate::bytes::Bytes;
use crate::{canonical_input, ds_tags};
use serde::{Deserialize, Serialize};

/// Entry counts at a site close, as printed on the attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SiteCounts {
    /// Ballot submissions recorded this day (all kinds).
    pub submitted: u64,
    /// Non-provisional casts recorded this day.
    pub cast: u64,
    /// Spoil entries recorded this day (Benaloh checks and voids).
    pub spoiled: u64,
    /// Provisional casts recorded this day (pending disposition at close).
    pub provisional_pending: u64,
}

/// A chain-head attestation for one site and day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHeadAttestation {
    /// Schema version of this artifact.
    pub schema_version: String,
    /// The election hash.
    pub election_hash: Bytes,
    /// Site identifier.
    pub site_id: String,
    /// Voting day (ISO-8601 date).
    pub day: String,
    /// The board head at close — must equal the matching segment's
    /// `segment_head`.
    pub head: Bytes,
    /// Counts at close.
    pub counts: SiteCounts,
    /// SHA3-256 hashes of each tabulator's signed end-of-day report
    /// (over the report's canonical signing input).
    pub tabulator_report_hashes: Vec<Bytes>,
    /// The controller's (DBB) Ed25519 verifying key.
    pub dbb_verifying_key: Bytes,
    /// DBB Ed25519 signature over [`Self::signing_input`].
    pub signature: Bytes,
}

impl ChainHeadAttestation {
    /// The canonical byte input the DBB signature covers: election hash,
    /// site, day, head, the four counts (u64 LE each), and each tabulator
    /// report hash in listed order.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let submitted = self.counts.submitted.to_le_bytes();
        let cast = self.counts.cast.to_le_bytes();
        let spoiled = self.counts.spoiled.to_le_bytes();
        let pending = self.counts.provisional_pending.to_le_bytes();
        let mut fields: Vec<&[u8]> = vec![
            self.election_hash.as_slice(),
            self.site_id.as_bytes(),
            self.day.as_bytes(),
            self.head.as_slice(),
            &submitted,
            &cast,
            &spoiled,
            &pending,
        ];
        for h in &self.tabulator_report_hashes {
            fields.push(h.as_slice());
        }
        canonical_input(ds_tags::ATTESTATION, &fields)
    }
}
