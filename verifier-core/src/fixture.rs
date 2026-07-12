// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! Hand-built micro-election fixtures with real cryptographic material
//! (Ed25519 keys and signatures, real chain hashes), used by this crate's
//! tests, the committed `fixtures/mini` directory, and — until the product
//! simulator exists — anyone needing a valid record to develop against.
//!
//! The mini election: one site (`site-1`), one day, one contest (`c1`,
//! options `A`/`B`), four voters. Voters 1–3 submit and cast (A, A, B);
//! voter 4 submits, takes the Benaloh challenge (spoil + disposition), and
//! leaves without revoting. One tabulator report (3 regular cards, totals
//! A=2/B=1) and a transcript whose input is the three cast cryptograms with
//! matching tallies. Cryptographic payloads (ciphertexts, proofs) are
//! placeholder bytes at this stage — their kernel encodings are fixed at
//! milestone M1 when proof verification is wired; every hash, signature,
//! and arithmetic relationship in the fixture is real.

use crate::kernel;
use bmvs_artifacts::{
    BoardSegment, BulletinEntry, BulletinKind, Bytes, ChainHeadAttestation, ContestTotals,
    DispositionDecision, DispositionRecord, ElectionConfigRecord, ElectionRecord, EntryFlags,
    InstanceDescriptor, MixRound, NamedSignature, OptionTotal, PartialDecryptionSet,
    SCHEMA_VERSION, SiteCounts, TabulatorReport, TallyTranscript, TrusteePublic,
};
use cryptography::context::Context as _;
use cryptography::utils::serialization::FSerializable as _;
use cryptography::utils::signatures::Signer as _;

/// A deterministic-structure (random-key) mini election record that passes
/// every implemented check.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn mini_record() -> ElectionRecord {
    let trustee_keys: Vec<kernel::SigningKey> =
        (0..3).map(|_| kernel::Ctx::gen_signing_key()).collect();
    let ea_key = kernel::Ctx::gen_signing_key();
    let dbb_key = kernel::Ctx::gen_signing_key();
    let tab_key = kernel::Ctx::gen_signing_key();

    // Keys and signatures use the kernel's fixed-length serialization
    // (raw 32/64 bytes), matching the `deser_f` calls in the checks.
    let vk_bytes = |sk: &kernel::SigningKey| Bytes::new(sk.verifying_key().ser_f());
    let sign = |sk: &kernel::SigningKey, msg: &[u8]| Bytes::new(sk.sign(msg).ser_f());

    // --- Configuration ---
    let mut config = ElectionConfigRecord {
        schema_version: SCHEMA_VERSION.to_owned(),
        election_hash: Bytes::default(), // filled after hashing below
        manifest: "mini election: contest c1, options A and B".to_owned(),
        threshold: 2,
        trustees: trustee_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| TrusteePublic {
                name: format!("trustee-{}", i + 1),
                verifying_key: vk_bytes(sk),
            })
            .collect(),
        authorities: vec![TrusteePublic {
            name: "election-authority".to_owned(),
            verifying_key: vk_bytes(&ea_key),
        }],
        election_public_key: Bytes::new(b"placeholder-election-public-key".to_vec()),
        instance: InstanceDescriptor {
            schema_version: SCHEMA_VERSION.to_owned(),
            product: "bmvs".to_owned(),
            mode: "bmvs".to_owned(),
            crypto_suite: "ristretto255-ed25519-sha3".to_owned(),
            features: vec!["provisional-ballots".to_owned(), "early-voting".to_owned()],
            anonymity_floor: 1, // mini fixture; production floors are much higher
        },
        signatures: Vec::new(),
    };
    config.election_hash = Bytes::new(kernel::hash256(&config.signing_input()).to_vec());
    // NOTE: the election hash is over the *unsigned* configuration content
    // (signing_input excludes the signatures), so endorsements can be added
    // after hashing without changing the hash.
    let config_input = config.signing_input();
    config.signatures = trustee_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| NamedSignature {
            signer: format!("trustee-{}", i + 1),
            signature: sign(sk, &config_input),
        })
        .collect();
    let election_hash = config.election_hash.clone();

    // --- Board entries: submissions, authorizations, casts, one spoil ---
    let mut entries: Vec<BulletinEntry> = Vec::new();
    let mut prev = election_hash.clone();
    let mut push_entry = |kind: BulletinKind,
                          flags: EntryFlags,
                          payload: &[u8],
                          subject: Bytes,
                          prev: &mut Bytes|
     -> Bytes {
        let mut e = BulletinEntry {
            kind,
            flags,
            payload: Bytes::new(payload.to_vec()),
            subject,
            previous_hash: prev.clone(),
            entry_hash: Bytes::default(),
        };
        e.entry_hash = Bytes::new(kernel::hash256(&e.hash_input()).to_vec());
        *prev = e.entry_hash.clone();
        let tracker = e.entry_hash.clone();
        entries.push(e);
        tracker
    };

    let flags = EntryFlags::default();
    let mut trackers = Vec::new();
    for voter in 1..=4u8 {
        let payload = format!("placeholder-cryptogram-voter-{voter}");
        let tracker = push_entry(
            BulletinKind::Submission,
            flags,
            payload.as_bytes(),
            Bytes::default(),
            &mut prev,
        );
        trackers.push(tracker);
    }
    // Voters 1..=3 cast (authorization + cast marker each).
    for (voter, tracker) in trackers.iter().take(3).cloned().enumerate() {
        push_entry(
            BulletinKind::VoterAuthorization,
            flags,
            format!("placeholder-authorization-{}", voter + 1).as_bytes(),
            Bytes::default(),
            &mut prev,
        );
        push_entry(BulletinKind::Cast, flags, b"cast", tracker, &mut prev);
    }
    // Voter 4 takes the Benaloh challenge: spoil entry + disposition.
    push_entry(
        BulletinKind::Spoil,
        flags,
        b"spoiled-by-check",
        trackers[3].clone(),
        &mut prev,
    );

    let mut segment = BoardSegment {
        schema_version: SCHEMA_VERSION.to_owned(),
        election_hash: election_hash.clone(),
        site_id: "site-1".to_owned(),
        day: "2026-07-12".to_owned(),
        previous_segment_head: election_hash.clone(),
        segment_head: prev.clone(),
        entries,
        dbb_verifying_key: vk_bytes(&dbb_key),
        signature: Bytes::default(),
    };
    segment.signature = sign(&dbb_key, &segment.signing_input());

    // --- Tabulator report ---
    let mut report = TabulatorReport {
        schema_version: SCHEMA_VERSION.to_owned(),
        election_hash: election_hash.clone(),
        site_id: "site-1".to_owned(),
        tab_id: "tab-1".to_owned(),
        day: "2026-07-12".to_owned(),
        totals: vec![ContestTotals {
            contest_id: "c1".to_owned(),
            options: vec![
                OptionTotal {
                    option_id: "A".to_owned(),
                    count: 2,
                },
                OptionTotal {
                    option_id: "B".to_owned(),
                    count: 1,
                },
            ],
        }],
        cards_regular: 3,
        cards_provisional: 0,
        cards_rejected: 0,
        tab_verifying_key: vk_bytes(&tab_key),
        signature: Bytes::default(),
    };
    report.signature = sign(&tab_key, &report.signing_input());

    // --- Attestation (covers the report hash) ---
    let report_hash = Bytes::new(kernel::hash256(&report.signing_input()).to_vec());
    let mut attestation = ChainHeadAttestation {
        schema_version: SCHEMA_VERSION.to_owned(),
        election_hash: election_hash.clone(),
        site_id: "site-1".to_owned(),
        day: "2026-07-12".to_owned(),
        head: segment.segment_head.clone(),
        counts: SiteCounts {
            submitted: 4,
            cast: 3,
            spoiled: 1,
            provisional_pending: 0,
        },
        tabulator_report_hashes: vec![report_hash],
        dbb_verifying_key: vk_bytes(&dbb_key),
        signature: Bytes::default(),
    };
    attestation.signature = sign(&dbb_key, &attestation.signing_input());

    // --- Disposition for the checked ballot ---
    let mut disposition = DispositionRecord {
        schema_version: SCHEMA_VERSION.to_owned(),
        election_hash: election_hash.clone(),
        subject: trackers[3].clone(),
        decision: DispositionDecision::SpoiledByCheck,
        reason_category: "benaloh-challenge".to_owned(),
        signatures: Vec::new(),
    };
    disposition.signatures = vec![NamedSignature {
        signer: "election-authority".to_owned(),
        signature: sign(&ea_key, &disposition.signing_input()),
    }];

    // --- Transcript ---
    let mut transcript = TallyTranscript {
        schema_version: SCHEMA_VERSION.to_owned(),
        election_hash: election_hash.clone(),
        input_trackers: trackers[0..3].to_vec(),
        input_ciphertexts: Bytes::new(b"placeholder-stripped-ciphertexts".to_vec()),
        mix_rounds: (1..=2)
            .map(|i| MixRound {
                trustee: format!("trustee-{i}"),
                ciphertexts: Bytes::new(format!("placeholder-mix-{i}").into_bytes()),
                proof: Bytes::new(format!("placeholder-tw-proof-{i}").into_bytes()),
            })
            .collect(),
        partial_decryptions: (1..=2)
            .map(|i| PartialDecryptionSet {
                trustee: format!("trustee-{i}"),
                factors: Bytes::new(format!("placeholder-factors-{i}").into_bytes()),
                proofs: Bytes::new(format!("placeholder-cp-proofs-{i}").into_bytes()),
            })
            .collect(),
        plaintexts: Bytes::new(b"placeholder-plaintexts".to_vec()),
        tallies: vec![ContestTotals {
            contest_id: "c1".to_owned(),
            options: vec![
                OptionTotal {
                    option_id: "A".to_owned(),
                    count: 2,
                },
                OptionTotal {
                    option_id: "B".to_owned(),
                    count: 1,
                },
            ],
        }],
        trustee_signatures: Vec::new(),
    };
    let transcript_input = transcript.signing_input();
    transcript.trustee_signatures = trustee_keys
        .iter()
        .take(2)
        .enumerate()
        .map(|(i, sk)| NamedSignature {
            signer: format!("trustee-{}", i + 1),
            signature: sign(sk, &transcript_input),
        })
        .collect();

    ElectionRecord {
        config,
        segments: vec![segment],
        attestations: vec![attestation],
        dispositions: vec![disposition],
        tabulator_reports: vec![report],
        transcript: Some(transcript),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{CheckStatus, Overall};

    #[test]
    fn mini_record_passes_all_implemented_checks() {
        let record = mini_record();
        let report = crate::verify_record(&record);
        for r in &report.results {
            assert!(
                !matches!(r.status, CheckStatus::Fail { .. }),
                "check {} failed: {:?}",
                r.name,
                r.status
            );
        }
        // Proof verification is staged for M1, so the overall outcome is
        // Partial, never Pass — fail-closed reporting.
        assert_eq!(report.overall(), Overall::Partial);
    }

    #[test]
    fn tampered_entry_payload_breaks_the_chain() {
        let mut record = mini_record();
        record.segments[0].entries[0].payload = Bytes::new(b"tampered".to_vec());
        let report = crate::verify_record(&record);
        let chain = report
            .results
            .iter()
            .find(|r| r.name == "chain-integrity")
            .expect("chain check present");
        assert!(matches!(chain.status, CheckStatus::Fail { .. }));
    }

    #[test]
    fn tampered_tally_fails_reconciliation() {
        let mut record = mini_record();
        let transcript = record.transcript.as_mut().expect("fixture has transcript");
        transcript.tallies[0].options[0].count += 1;
        // Re-sign so the failure isolates to reconciliation (otherwise the
        // signature check would also fire — which is itself correct
        // behavior, but this test targets the arithmetic).
        transcript.trustee_signatures.clear();
        let report = crate::verify_record(&record);
        let recon = report
            .results
            .iter()
            .find(|r| r.name == "reconciliation")
            .expect("reconciliation check present");
        assert!(matches!(recon.status, CheckStatus::Fail { .. }));
    }

    #[test]
    fn dropped_mix_input_fails_completeness() {
        let mut record = mini_record();
        let transcript = record.transcript.as_mut().expect("fixture has transcript");
        transcript.input_trackers.pop();
        let report = crate::verify_record(&record);
        let disp = report
            .results
            .iter()
            .find(|r| r.name == "dispositions")
            .expect("dispositions check present");
        assert!(matches!(disp.status, CheckStatus::Fail { .. }));
    }

    #[test]
    fn wrong_signature_fails_signature_check() {
        let mut record = mini_record();
        // Swap the segment signature for the attestation's — both by the
        // DBB key, but over different canonical inputs.
        record.segments[0].signature = record.attestations[0].signature.clone();
        let report = crate::verify_record(&record);
        let sigs = report
            .results
            .iter()
            .find(|r| r.name == "signatures")
            .expect("signatures check present");
        assert!(matches!(sigs.status, CheckStatus::Fail { .. }));
    }

    #[test]
    fn json_round_trip_preserves_the_record() {
        let record = mini_record();
        let json = serde_json::to_string(&record).expect("serialize");
        let back: ElectionRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, record);
    }
}
