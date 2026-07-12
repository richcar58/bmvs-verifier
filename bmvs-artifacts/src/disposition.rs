// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! Disposition records: signed decisions that include or exclude specific
//! cryptograms from the tally, making the mix-input arithmetic publicly
//! checkable (architecture flows F6.2, F8.2, F12.2; constraint X8).

use crate::bytes::Bytes;
use crate::config::NamedSignature;
use crate::{canonical_input, ds_tags};
use serde::{Deserialize, Serialize};

/// The decision a disposition record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DispositionDecision {
    /// A provisional cryptogram is included in the tally (eligibility
    /// confirmed).
    IncludeProvisional,
    /// A provisional cryptogram is excluded (eligibility denied or deadline
    /// passed).
    ExcludeProvisional,
    /// A logic-and-accuracy test cryptogram is excluded.
    ExcludeTest,
    /// A cryptogram was spoiled by a ballot check (never castable).
    SpoiledByCheck,
    /// A cryptogram was voided by a misprint/jam procedure.
    VoidMisprint,
}

impl DispositionDecision {
    /// Stable single-byte tag used in the signing input.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::IncludeProvisional => 1,
            Self::ExcludeProvisional => 2,
            Self::ExcludeTest => 3,
            Self::SpoiledByCheck => 4,
            Self::VoidMisprint => 5,
        }
    }

    /// Whether this decision adds the subject to the mix input (`true`),
    /// removes it (`false`).
    #[must_use]
    pub fn includes(self) -> bool {
        matches!(self, Self::IncludeProvisional)
    }
}

/// A signed disposition for one cryptogram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispositionRecord {
    /// Schema version of this artifact.
    pub schema_version: String,
    /// The election hash.
    pub election_hash: Bytes,
    /// The subject cryptogram's tracker (its submission entry hash).
    pub subject: Bytes,
    /// The decision.
    pub decision: DispositionDecision,
    /// Reason category (statutory codes; free of personal data).
    pub reason_category: String,
    /// Election-authority (and, for provisional decisions, adjudicator)
    /// signatures over [`Self::signing_input`].
    pub signatures: Vec<NamedSignature>,
}

impl DispositionRecord {
    /// The canonical byte input the signatures cover: election hash,
    /// subject, decision tag, reason category.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        canonical_input(
            ds_tags::DISPOSITION,
            &[
                self.election_hash.as_slice(),
                self.subject.as_slice(),
                &[self.decision.tag()],
                self.reason_category.as_bytes(),
            ],
        )
    }
}
