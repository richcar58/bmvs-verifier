// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! The complete published election record: the bundle a verifier consumes.

use crate::attestation::ChainHeadAttestation;
use crate::board::BoardSegment;
use crate::config::ElectionConfigRecord;
use crate::disposition::DispositionRecord;
use crate::tabulator::TabulatorReport;
use crate::transcript::TallyTranscript;
use serde::{Deserialize, Serialize};

/// Everything one election publishes, gathered for verification.
///
/// On disk (the CLI's input) this is a directory:
/// `config.json`, `segments/*.json`, `attestations/*.json`,
/// `dispositions/*.json`, `tabulator-reports/*.json`, and optionally
/// `transcript.json` (absent until the trustee ceremony completes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectionRecord {
    /// The trustee-endorsed configuration (the root of trust).
    pub config: ElectionConfigRecord,
    /// All board segments, all sites and days.
    pub segments: Vec<BoardSegment>,
    /// All chain-head attestations.
    pub attestations: Vec<ChainHeadAttestation>,
    /// All disposition records.
    pub dispositions: Vec<DispositionRecord>,
    /// All tabulator reports.
    pub tabulator_reports: Vec<TabulatorReport>,
    /// The tally transcript, once published.
    pub transcript: Option<TallyTranscript>,
}
