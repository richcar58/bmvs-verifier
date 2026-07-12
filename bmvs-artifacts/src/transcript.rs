// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! The tally transcript: the complete verifiable output of the trustee
//! ceremony (architecture flow F10.2).
//!
//! Cryptographic objects (ciphertext lists, shuffle proofs, partial
//! decryptions and their proofs) appear as opaque kernel-encoded payloads at
//! schema level; `verifier-core` decodes and checks them with the `VoteSecure`
//! kernel (checks staged for milestone M1).

use crate::bytes::Bytes;
use crate::config::NamedSignature;
use crate::tabulator::ContestTotals;
use crate::{canonical_input, ds_tags};
use serde::{Deserialize, Serialize};

/// One trustee's mix round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixRound {
    /// The mixing trustee's name (from the configuration roster).
    pub trustee: String,
    /// Kernel-encoded shuffled ciphertext list (opaque).
    pub ciphertexts: Bytes,
    /// Kernel-encoded Terelius-Wikström proof of shuffle (opaque).
    pub proof: Bytes,
}

/// One trustee's partial decryptions for the final mixed list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialDecryptionSet {
    /// The decrypting trustee's name.
    pub trustee: String,
    /// Kernel-encoded decryption factors (opaque).
    pub factors: Bytes,
    /// Kernel-encoded Chaum-Pedersen proofs (opaque).
    pub proofs: Bytes,
}

/// The published tally transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyTranscript {
    /// Schema version of this artifact.
    pub schema_version: String,
    /// The election hash.
    pub election_hash: Bytes,
    /// The trackers (submission entry hashes) of the cryptograms that
    /// entered the mix — the committed mix input, checkable against the
    /// board segments and dispositions.
    pub input_trackers: Vec<Bytes>,
    /// Kernel-encoded initial (stripped) ciphertext list (opaque).
    pub input_ciphertexts: Bytes,
    /// Mix rounds in execution order.
    pub mix_rounds: Vec<MixRound>,
    /// Partial decryption sets from the participating quorum.
    pub partial_decryptions: Vec<PartialDecryptionSet>,
    /// Kernel-encoded decrypted plaintext ballots (opaque).
    pub plaintexts: Bytes,
    /// The computed tallies (regular ballots; included-provisional ballots
    /// reported within, per the reconciliation rules).
    pub tallies: Vec<ContestTotals>,
    /// Trustee signatures over [`Self::signing_input`].
    pub trustee_signatures: Vec<NamedSignature>,
}

impl TallyTranscript {
    /// The canonical byte input the trustee signatures cover: election
    /// hash, each input tracker in order, the input ciphertext payload,
    /// each round's trustee/ciphertexts/proof, each partial-decryption
    /// set's trustee/factors/proofs, the plaintext payload, and each
    /// contest tally (contest id, then option id + count u64 LE, in order).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let mut fields: Vec<Vec<u8>> = vec![self.election_hash.0.clone()];
        for t in &self.input_trackers {
            fields.push(t.0.clone());
        }
        fields.push(self.input_ciphertexts.0.clone());
        for round in &self.mix_rounds {
            fields.push(round.trustee.as_bytes().to_vec());
            fields.push(round.ciphertexts.0.clone());
            fields.push(round.proof.0.clone());
        }
        for pd in &self.partial_decryptions {
            fields.push(pd.trustee.as_bytes().to_vec());
            fields.push(pd.factors.0.clone());
            fields.push(pd.proofs.0.clone());
        }
        fields.push(self.plaintexts.0.clone());
        for contest in &self.tallies {
            fields.push(contest.contest_id.as_bytes().to_vec());
            for option in &contest.options {
                fields.push(option.option_id.as_bytes().to_vec());
                fields.push(option.count.to_le_bytes().to_vec());
            }
        }
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        canonical_input(ds_tags::TRANSCRIPT, &refs)
    }
}
