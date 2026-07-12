// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! Tabulator end-of-day reports: the paper-derived running totals and card
//! accounting that anchor the reconciliation identity (architecture flow
//! F15.2).

use crate::bytes::Bytes;
use crate::{canonical_input, ds_tags};
use serde::{Deserialize, Serialize};

/// Totals for one option within one contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionTotal {
    /// Option identifier (manifest-defined).
    pub option_id: String,
    /// Vote count.
    pub count: u64,
}

/// Totals for one contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestTotals {
    /// Contest identifier (manifest-defined).
    pub contest_id: String,
    /// Per-option counts.
    pub options: Vec<OptionTotal>,
}

/// One tabulator's signed report for one site and day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabulatorReport {
    /// Schema version of this artifact.
    pub schema_version: String,
    /// The election hash.
    pub election_hash: Bytes,
    /// Site identifier.
    pub site_id: String,
    /// Tabulator identifier within the site.
    pub tab_id: String,
    /// Voting day (ISO-8601 date).
    pub day: String,
    /// Per-contest running totals from scanned cards (regular ballots only —
    /// provisional cards are stored unscanned pending disposition).
    pub totals: Vec<ContestTotals>,
    /// Regular cards accepted and stored.
    pub cards_regular: u64,
    /// Provisional cards stored (excluded from `totals`).
    pub cards_provisional: u64,
    /// Cards rejected (spoiled, duplicate, forged, malformed).
    pub cards_rejected: u64,
    /// The tabulator's Ed25519 verifying key.
    pub tab_verifying_key: Bytes,
    /// Tabulator Ed25519 signature over [`Self::signing_input`].
    pub signature: Bytes,
}

impl TabulatorReport {
    /// The canonical byte input the tabulator signature covers: election
    /// hash, site, tabulator id, day, each contest id with each option id
    /// and count (u64 LE) in listed order, then the three card counters
    /// (u64 LE each).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let mut fields: Vec<Vec<u8>> = vec![
            self.election_hash.0.clone(),
            self.site_id.as_bytes().to_vec(),
            self.tab_id.as_bytes().to_vec(),
            self.day.as_bytes().to_vec(),
        ];
        for contest in &self.totals {
            fields.push(contest.contest_id.as_bytes().to_vec());
            for option in &contest.options {
                fields.push(option.option_id.as_bytes().to_vec());
                fields.push(option.count.to_le_bytes().to_vec());
            }
        }
        fields.push(self.cards_regular.to_le_bytes().to_vec());
        fields.push(self.cards_provisional.to_le_bytes().to_vec());
        fields.push(self.cards_rejected.to_le_bytes().to_vec());
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        canonical_input(ds_tags::TABULATOR_REPORT, &refs)
    }
}
