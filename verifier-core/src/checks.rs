// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! The verification checks, mirroring architecture flow F13.2.
//!
//! Every check is independent and read-only over the record; each reports
//! precise, per-problem findings rather than a bare boolean, because a
//! verifier's value is exactly the quality of its error output.

use crate::kernel;
use crate::report::CheckStatus;
use bmvs_artifacts::{
    BulletinKind, Bytes, DispositionDecision, ElectionRecord, version_compatible,
};
use std::collections::{BTreeMap, BTreeSet};

/// A verification check.
pub trait Check {
    /// Stable check identifier (appears in reports).
    fn name(&self) -> &'static str;
    /// Runs the check against a record.
    fn run(&self, record: &ElectionRecord) -> CheckStatus;
}

/// All checks, in reporting order.
#[must_use]
pub fn all_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(Structure),
        Box::new(ChainIntegrity),
        Box::new(Attestations),
        Box::new(Signatures),
        Box::new(Dispositions),
        Box::new(Accounting),
        Box::new(Reconciliation),
        Box::new(CryptographicProofs),
    ]
}

fn status_from(problems: Vec<String>) -> CheckStatus {
    if problems.is_empty() {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail { problems }
    }
}

/// Verifies an Ed25519 signature via the kernel; returns a finding on any
/// failure (malformed key, malformed signature, or verification failure).
fn verify_sig(context: &str, key: &Bytes, message: &[u8], signature: &Bytes) -> Option<String> {
    use cryptography::utils::serialization::FDeserializable as _;
    use cryptography::utils::signatures::Verifier as _;
    let vk = match kernel::VerifyingKey::deser_f(key.as_slice()) {
        Ok(vk) => vk,
        Err(e) => return Some(format!("{context}: malformed verifying key: {e:?}")),
    };
    let sig = match kernel::Signature::deser_f(signature.as_slice()) {
        Ok(s) => s,
        Err(e) => return Some(format!("{context}: malformed signature: {e:?}")),
    };
    match vk.verify(message, &sig) {
        Ok(()) => None,
        Err(e) => Some(format!("{context}: signature verification failed: {e:?}")),
    }
}

/// R1 — structural validity: schema versions, election-hash consistency,
/// election hash binds to the configuration, roster sanity, in-band device
/// key consistency.
pub struct Structure;

impl Check for Structure {
    fn name(&self) -> &'static str {
        "structure"
    }

    // Enumeration-style check: splitting it would scatter one artifact
    // sweep across helpers without aiding review.
    #[allow(clippy::too_many_lines)]
    fn run(&self, r: &ElectionRecord) -> CheckStatus {
        let mut problems = Vec::new();
        let eh = &r.config.election_hash;

        // Schema versions.
        let mut versions: Vec<(&str, &str)> = vec![("config", r.config.schema_version.as_str())];
        versions.extend(
            r.segments
                .iter()
                .map(|s| ("segment", s.schema_version.as_str())),
        );
        versions.extend(
            r.attestations
                .iter()
                .map(|a| ("attestation", a.schema_version.as_str())),
        );
        versions.extend(
            r.dispositions
                .iter()
                .map(|d| ("disposition", d.schema_version.as_str())),
        );
        versions.extend(
            r.tabulator_reports
                .iter()
                .map(|t| ("tabulator-report", t.schema_version.as_str())),
        );
        if let Some(t) = &r.transcript {
            versions.push(("transcript", t.schema_version.as_str()));
        }
        for (what, v) in versions {
            if !version_compatible(v) {
                problems.push(format!("{what}: unsupported schema version {v:?}"));
            }
        }

        // The election hash is the hash of the configuration's canonical
        // signing input — the binding that makes the whole record refer to
        // one endorsed configuration.
        let computed = kernel::hash256(&r.config.signing_input());
        if computed.as_slice() != eh.as_slice() {
            problems.push(format!(
                "config: election_hash {} does not match SHA3-256 of the configuration ({})",
                eh.to_hex(),
                Bytes::new(computed.to_vec()).to_hex()
            ));
        }

        // Roster sanity.
        if r.config.threshold == 0 || (r.config.threshold as usize) > r.config.trustees.len() {
            problems.push(format!(
                "config: threshold {} invalid for {} trustees",
                r.config.threshold,
                r.config.trustees.len()
            ));
        }

        // Election-hash consistency across artifacts.
        let mut mismatch = |what: &str, got: &Bytes| {
            if got != eh {
                problems.push(format!(
                    "{what}: election_hash {} differs from config",
                    got.to_hex()
                ));
            }
        };
        for s in &r.segments {
            mismatch(
                &format!("segment {}/{}", s.site_id, s.day),
                &s.election_hash,
            );
        }
        for a in &r.attestations {
            mismatch(
                &format!("attestation {}/{}", a.site_id, a.day),
                &a.election_hash,
            );
        }
        for d in &r.dispositions {
            mismatch(
                &format!("disposition {}", d.subject.to_hex()),
                &d.election_hash,
            );
        }
        for t in &r.tabulator_reports {
            mismatch(
                &format!("tabulator-report {}/{}/{}", t.site_id, t.tab_id, t.day),
                &t.election_hash,
            );
        }
        if let Some(t) = &r.transcript {
            mismatch("transcript", &t.election_hash);
        }

        // In-band device keys must be consistent per device (schema 0.1
        // carries them in-band; provenance binding is a planned additive
        // config extension).
        let mut dbb_keys: BTreeMap<&str, &Bytes> = BTreeMap::new();
        for s in &r.segments {
            if let Some(prev) = dbb_keys.insert(s.site_id.as_str(), &s.dbb_verifying_key)
                && prev != &s.dbb_verifying_key
            {
                problems.push(format!(
                    "segment {}/{}: DBB key differs from earlier segment of the same site",
                    s.site_id, s.day
                ));
            }
        }
        for a in &r.attestations {
            if let Some(expected) = dbb_keys.get(a.site_id.as_str())
                && *expected != &a.dbb_verifying_key
            {
                problems.push(format!(
                    "attestation {}/{}: DBB key differs from the site's segments",
                    a.site_id, a.day
                ));
            }
        }
        let mut tab_keys: BTreeMap<(&str, &str), &Bytes> = BTreeMap::new();
        for t in &r.tabulator_reports {
            if let Some(prev) = tab_keys.insert(
                (t.site_id.as_str(), t.tab_id.as_str()),
                &t.tab_verifying_key,
            ) && prev != &t.tab_verifying_key
            {
                problems.push(format!(
                    "tabulator-report {}/{}/{}: tabulator key differs from an earlier report",
                    t.site_id, t.tab_id, t.day
                ));
            }
        }

        status_from(problems)
    }
}

/// R2 — bulletin-board chain integrity: entry hash recomputation, entry
/// linkage, day-to-day segment chaining per site, head correctness.
pub struct ChainIntegrity;

impl Check for ChainIntegrity {
    fn name(&self) -> &'static str {
        "chain-integrity"
    }

    fn run(&self, r: &ElectionRecord) -> CheckStatus {
        let mut problems = Vec::new();
        // Group segments by site, ordered by day (ISO dates sort lexically).
        let mut by_site: BTreeMap<&str, Vec<&bmvs_artifacts::BoardSegment>> = BTreeMap::new();
        for s in &r.segments {
            by_site.entry(s.site_id.as_str()).or_default().push(s);
        }
        for (site, mut segments) in by_site {
            segments.sort_by(|a, b| a.day.cmp(&b.day));
            let mut expected_prev_head = r.config.election_hash.clone();
            for s in segments {
                let seg = format!("segment {}/{}", site, s.day);
                if s.previous_segment_head != expected_prev_head {
                    problems.push(format!(
                        "{seg}: previous_segment_head {} does not chain from {}",
                        s.previous_segment_head.to_hex(),
                        expected_prev_head.to_hex()
                    ));
                }
                let mut prev_hash = s.previous_segment_head.clone();
                for (i, e) in s.entries.iter().enumerate() {
                    if e.previous_hash != prev_hash {
                        problems.push(format!(
                            "{seg} entry {i}: previous_hash {} breaks the chain (expected {})",
                            e.previous_hash.to_hex(),
                            prev_hash.to_hex()
                        ));
                    }
                    let recomputed = kernel::hash256(&e.hash_input());
                    if recomputed.as_slice() != e.entry_hash.as_slice() {
                        problems.push(format!(
                            "{seg} entry {i}: entry_hash {} does not match its recomputed hash",
                            e.entry_hash.to_hex()
                        ));
                    }
                    prev_hash = e.entry_hash.clone();
                }
                if s.segment_head != prev_hash {
                    problems.push(format!(
                        "{seg}: segment_head {} does not equal the last entry hash {}",
                        s.segment_head.to_hex(),
                        prev_hash.to_hex()
                    ));
                }
                expected_prev_head = s.segment_head.clone();
            }
        }
        status_from(problems)
    }
}

/// R3 — attestation consistency: every attestation matches a segment, its
/// head equals the segment head, and its counts recount from the entries.
pub struct Attestations;

impl Check for Attestations {
    fn name(&self) -> &'static str {
        "attestations"
    }

    fn run(&self, r: &ElectionRecord) -> CheckStatus {
        let mut problems = Vec::new();
        let mut segments: BTreeMap<(&str, &str), &bmvs_artifacts::BoardSegment> = BTreeMap::new();
        for s in &r.segments {
            segments.insert((s.site_id.as_str(), s.day.as_str()), s);
        }
        for a in &r.attestations {
            let att = format!("attestation {}/{}", a.site_id, a.day);
            let Some(seg) = segments.get(&(a.site_id.as_str(), a.day.as_str())) else {
                problems.push(format!("{att}: no matching board segment was published"));
                continue;
            };
            if a.head != seg.segment_head {
                problems.push(format!(
                    "{att}: attested head {} differs from the published segment head {}",
                    a.head.to_hex(),
                    seg.segment_head.to_hex()
                ));
            }
            let mut submitted = 0u64;
            let mut cast = 0u64;
            let mut spoiled = 0u64;
            let mut pending = 0u64;
            for e in &seg.entries {
                match e.kind {
                    BulletinKind::Submission => submitted += 1,
                    BulletinKind::Cast if e.flags.provisional => pending += 1,
                    BulletinKind::Cast => cast += 1,
                    BulletinKind::Spoil => spoiled += 1,
                    BulletinKind::VoterAuthorization => {}
                }
            }
            let expected = (submitted, cast, spoiled, pending);
            let attested = (
                a.counts.submitted,
                a.counts.cast,
                a.counts.spoiled,
                a.counts.provisional_pending,
            );
            if attested != expected {
                problems.push(format!(
                    "{att}: counts {attested:?} differ from the segment's entries {expected:?} \
                     (submitted, cast, spoiled, provisional-pending)"
                ));
            }
        }
        // Every segment must be attested — the paper trail covers the whole
        // record, not a subset.
        let attested: BTreeSet<(&str, &str)> = r
            .attestations
            .iter()
            .map(|a| (a.site_id.as_str(), a.day.as_str()))
            .collect();
        for s in &r.segments {
            if !attested.contains(&(s.site_id.as_str(), s.day.as_str())) {
                problems.push(format!(
                    "segment {}/{}: no chain-head attestation was published",
                    s.site_id, s.day
                ));
            }
        }
        status_from(problems)
    }
}

/// R7 — signature verification over the schema's canonical signing inputs:
/// trustee endorsements on the configuration, DBB signatures on segments and
/// attestations, authority signatures on dispositions, tabulator signatures
/// on reports, trustee signatures on the transcript.
pub struct Signatures;

impl Check for Signatures {
    fn name(&self) -> &'static str {
        "signatures"
    }

    // Enumeration-style check over every signed artifact class.
    #[allow(clippy::too_many_lines)]
    fn run(&self, r: &ElectionRecord) -> CheckStatus {
        let mut problems = Vec::new();
        let mut named_keys: BTreeMap<&str, &Bytes> = BTreeMap::new();
        for t in &r.config.trustees {
            named_keys.insert(t.name.as_str(), &t.verifying_key);
        }
        for a in &r.config.authorities {
            named_keys.insert(a.name.as_str(), &a.verifying_key);
        }

        // Configuration: every roster trustee must have endorsed.
        let config_input = r.config.signing_input();
        let mut endorsers = BTreeSet::new();
        for sig in &r.config.signatures {
            let Some(key) = named_keys.get(sig.signer.as_str()) else {
                problems.push(format!(
                    "config: endorsement by unknown signer {:?}",
                    sig.signer
                ));
                continue;
            };
            if let Some(p) = verify_sig(
                &format!("config endorsement by {}", sig.signer),
                key,
                &config_input,
                &sig.signature,
            ) {
                problems.push(p);
            }
            endorsers.insert(sig.signer.as_str());
        }
        for t in &r.config.trustees {
            if !endorsers.contains(t.name.as_str()) {
                problems.push(format!("config: trustee {:?} has not endorsed", t.name));
            }
        }

        for s in &r.segments {
            if let Some(p) = verify_sig(
                &format!("segment {}/{}", s.site_id, s.day),
                &s.dbb_verifying_key,
                &s.signing_input(),
                &s.signature,
            ) {
                problems.push(p);
            }
        }
        for a in &r.attestations {
            if let Some(p) = verify_sig(
                &format!("attestation {}/{}", a.site_id, a.day),
                &a.dbb_verifying_key,
                &a.signing_input(),
                &a.signature,
            ) {
                problems.push(p);
            }
        }
        for d in &r.dispositions {
            if d.signatures.is_empty() {
                problems.push(format!("disposition {}: no signatures", d.subject.to_hex()));
            }
            for sig in &d.signatures {
                let Some(key) = named_keys.get(sig.signer.as_str()) else {
                    problems.push(format!(
                        "disposition {}: unknown signer {:?}",
                        d.subject.to_hex(),
                        sig.signer
                    ));
                    continue;
                };
                if let Some(p) = verify_sig(
                    &format!("disposition {} by {}", d.subject.to_hex(), sig.signer),
                    key,
                    &d.signing_input(),
                    &sig.signature,
                ) {
                    problems.push(p);
                }
            }
        }
        for t in &r.tabulator_reports {
            if let Some(p) = verify_sig(
                &format!("tabulator-report {}/{}/{}", t.site_id, t.tab_id, t.day),
                &t.tab_verifying_key,
                &t.signing_input(),
                &t.signature,
            ) {
                problems.push(p);
            }
        }
        if let Some(t) = &r.transcript {
            let input = t.signing_input();
            let mut signers = BTreeSet::new();
            for sig in &t.trustee_signatures {
                let Some(key) = named_keys.get(sig.signer.as_str()) else {
                    problems.push(format!("transcript: unknown signer {:?}", sig.signer));
                    continue;
                };
                if let Some(p) = verify_sig(
                    &format!("transcript signature by {}", sig.signer),
                    key,
                    &input,
                    &sig.signature,
                ) {
                    problems.push(p);
                }
                signers.insert(sig.signer.as_str());
            }
            if signers.len() < r.config.threshold as usize {
                problems.push(format!(
                    "transcript: {} distinct trustee signatures, below threshold {}",
                    signers.len(),
                    r.config.threshold
                ));
            }
        }
        status_from(problems)
    }
}

/// R4 — disposition arithmetic and mix-input completeness (constraint X8):
/// dispositions reference real subjects and the right kinds; when the
/// transcript is present, its input set equals cast cryptograms adjusted by
/// the signed dispositions — exactly.
pub struct Dispositions;

impl Check for Dispositions {
    fn name(&self) -> &'static str {
        "dispositions"
    }

    // Validity sweep plus the mix-input set comparison; one narrative.
    #[allow(clippy::too_many_lines)]
    fn run(&self, r: &ElectionRecord) -> CheckStatus {
        let mut problems = Vec::new();
        // Index every entry by hash, and casts/spoils by their subject.
        let mut submissions: BTreeMap<&Bytes, &bmvs_artifacts::BulletinEntry> = BTreeMap::new();
        let mut casts: BTreeMap<&Bytes, &bmvs_artifacts::BulletinEntry> = BTreeMap::new();
        let mut spoiled_subjects: BTreeSet<&Bytes> = BTreeSet::new();
        for s in &r.segments {
            for e in &s.entries {
                match e.kind {
                    BulletinKind::Submission => {
                        submissions.insert(&e.entry_hash, e);
                    }
                    BulletinKind::Cast => {
                        if casts.insert(&e.subject, e).is_some() {
                            problems.push(format!(
                                "board: submission {} is cast more than once",
                                e.subject.to_hex()
                            ));
                        }
                    }
                    BulletinKind::Spoil => {
                        spoiled_subjects.insert(&e.subject);
                    }
                    BulletinKind::VoterAuthorization => {}
                }
            }
        }
        // A ballot is either cast or spoiled, never both.
        for subject in &spoiled_subjects {
            if casts.contains_key(*subject) {
                problems.push(format!(
                    "board: submission {} is both cast and spoiled",
                    subject.to_hex()
                ));
            }
        }
        // Cast/spoil markers must reference real submissions.
        for subject in casts.keys() {
            if !submissions.contains_key(*subject) {
                problems.push(format!(
                    "board: cast of unknown submission {}",
                    subject.to_hex()
                ));
            }
        }
        for subject in &spoiled_subjects {
            if !submissions.contains_key(*subject) {
                problems.push(format!(
                    "board: spoil of unknown submission {}",
                    subject.to_hex()
                ));
            }
        }

        // Dispositions reference real subjects and appropriate kinds; at
        // most one provisional decision per subject.
        let mut provisional_decisions: BTreeMap<&Bytes, DispositionDecision> = BTreeMap::new();
        for d in &r.dispositions {
            let subj = &d.subject;
            let label = format!("disposition {}", subj.to_hex());
            if !submissions.contains_key(subj) {
                problems.push(format!("{label}: subject is not a published submission"));
                continue;
            }
            match d.decision {
                DispositionDecision::IncludeProvisional
                | DispositionDecision::ExcludeProvisional => {
                    let is_provisional_cast = casts.get(subj).is_some_and(|e| e.flags.provisional);
                    if !is_provisional_cast {
                        problems.push(format!(
                            "{label}: provisional decision for a subject that is not a provisional cast"
                        ));
                    }
                    if provisional_decisions.insert(subj, d.decision).is_some() {
                        problems.push(format!(
                            "{label}: multiple provisional decisions for one subject"
                        ));
                    }
                }
                DispositionDecision::ExcludeTest => {
                    let is_test_cast = casts.get(subj).is_some_and(|e| e.flags.test);
                    if !is_test_cast {
                        problems.push(format!("{label}: test exclusion for a non-test subject"));
                    }
                }
                DispositionDecision::SpoiledByCheck | DispositionDecision::VoidMisprint => {
                    if !spoiled_subjects.contains(subj) {
                        problems.push(format!(
                            "{label}: spoil/void decision without a matching board spoil entry"
                        ));
                    }
                }
            }
        }

        // Mix-input completeness — only decidable once the transcript
        // exists. Without one, report what was checkable: failures fail,
        // and a clean result is a *skip* (not a pass), because the
        // completeness half of this check has not run.
        let Some(t) = &r.transcript else {
            return if problems.is_empty() {
                CheckStatus::Skipped {
                    reason: "disposition validity passed; mix-input completeness \
                             deferred until a transcript is published"
                        .to_owned(),
                }
            } else {
                CheckStatus::Fail { problems }
            };
        };
        let mut expected: BTreeSet<&Bytes> = BTreeSet::new();
        for (subject, e) in &casts {
            let include = if e.flags.test {
                false
            } else if e.flags.provisional {
                matches!(
                    provisional_decisions.get(*subject),
                    Some(DispositionDecision::IncludeProvisional)
                )
            } else {
                true
            };
            if include {
                expected.insert(subject);
            }
            // Every provisional cast must be decided before tally.
            if e.flags.provisional && !provisional_decisions.contains_key(*subject) {
                problems.push(format!(
                    "mix-input: provisional cast {} has no disposition but the transcript is published",
                    subject.to_hex()
                ));
            }
        }
        let actual: BTreeSet<&Bytes> = t.input_trackers.iter().collect();
        if actual.len() != t.input_trackers.len() {
            problems.push("transcript: duplicate input trackers".to_owned());
        }
        for missing in expected.difference(&actual) {
            problems.push(format!(
                "mix-input: cast cryptogram {} is missing from the transcript input",
                missing.to_hex()
            ));
        }
        for extra in actual.difference(&expected) {
            problems.push(format!(
                "mix-input: transcript input {} is not a validly included cast cryptogram",
                extra.to_hex()
            ));
        }
        status_from(problems)
    }
}

/// R5 — card accounting closure: tabulator card counters equal the board's
/// cast counts, per site and day.
pub struct Accounting;

impl Check for Accounting {
    fn name(&self) -> &'static str {
        "card-accounting"
    }

    fn run(&self, r: &ElectionRecord) -> CheckStatus {
        let mut problems = Vec::new();
        // Board-side counts per (site, day).
        let mut board: BTreeMap<(&str, &str), (u64, u64)> = BTreeMap::new();
        for s in &r.segments {
            let counts = board
                .entry((s.site_id.as_str(), s.day.as_str()))
                .or_default();
            for e in &s.entries {
                if e.kind == BulletinKind::Cast {
                    if e.flags.provisional {
                        counts.1 += 1;
                    } else {
                        counts.0 += 1;
                    }
                }
            }
        }
        // Tabulator-side counters per (site, day), summed over tabulators.
        let mut tabs: BTreeMap<(&str, &str), (u64, u64)> = BTreeMap::new();
        for t in &r.tabulator_reports {
            let counts = tabs
                .entry((t.site_id.as_str(), t.day.as_str()))
                .or_default();
            counts.0 += t.cards_regular;
            counts.1 += t.cards_provisional;
        }
        for (key, board_counts) in &board {
            let tab_counts = tabs.get(key).copied().unwrap_or_default();
            if *board_counts != tab_counts {
                problems.push(format!(
                    "site {}/{}: board casts (regular, provisional) = {board_counts:?} but tabulator cards = {tab_counts:?}",
                    key.0, key.1
                ));
            }
        }
        for key in tabs.keys() {
            if !board.contains_key(key) {
                problems.push(format!(
                    "site {}/{}: tabulator report without a matching board segment",
                    key.0, key.1
                ));
            }
        }
        status_from(problems)
    }
}

/// R6 — the reconciliation identity: the cryptographic tally equals the sum
/// of the tabulators' paper-derived totals (regular ballots).
pub struct Reconciliation;

impl Check for Reconciliation {
    fn name(&self) -> &'static str {
        "reconciliation"
    }

    fn run(&self, r: &ElectionRecord) -> CheckStatus {
        let Some(t) = &r.transcript else {
            return CheckStatus::Skipped {
                reason: "no transcript published yet".to_owned(),
            };
        };
        if r.dispositions
            .iter()
            .any(|d| d.decision == DispositionDecision::IncludeProvisional)
        {
            // Included provisional ballots enter the cryptographic tally but
            // not the tabulator totals; the provisional-inclusive statement
            // of the identity is defined with the M1 fixture work.
            return CheckStatus::Skipped {
                reason: "record contains included provisional ballots; the \
                         provisional-inclusive reconciliation statement is staged for M1"
                    .to_owned(),
            };
        }
        let mut problems = Vec::new();
        // Sum tabulator totals per contest/option.
        let mut summed: BTreeMap<(&str, &str), u64> = BTreeMap::new();
        for report in &r.tabulator_reports {
            for contest in &report.totals {
                for option in &contest.options {
                    *summed
                        .entry((contest.contest_id.as_str(), option.option_id.as_str()))
                        .or_default() += option.count;
                }
            }
        }
        let mut crypto: BTreeMap<(&str, &str), u64> = BTreeMap::new();
        for contest in &t.tallies {
            for option in &contest.options {
                *crypto
                    .entry((contest.contest_id.as_str(), option.option_id.as_str()))
                    .or_default() += option.count;
            }
        }
        let keys: BTreeSet<_> = summed.keys().chain(crypto.keys()).collect();
        for key in keys {
            let s = summed.get(key).copied().unwrap_or(0);
            let c = crypto.get(key).copied().unwrap_or(0);
            if s != c {
                problems.push(format!(
                    "contest {:?} option {:?}: cryptographic tally {} != tabulator sum {}",
                    key.0, key.1, c, s
                ));
            }
        }
        status_from(problems)
    }
}

/// R8 — cryptographic proof verification (Naor-Yung ballot proofs, the
/// Terelius-Wikström shuffle proofs, and the Chaum-Pedersen decryption
/// proofs), staged for milestone M1.
pub struct CryptographicProofs;

impl Check for CryptographicProofs {
    fn name(&self) -> &'static str {
        "cryptographic-proofs"
    }

    fn run(&self, _record: &ElectionRecord) -> CheckStatus {
        CheckStatus::Skipped {
            reason: "proof verification (Naor-Yung, shuffle, decryption) is staged for \
                     milestone M1: the opaque transcript payloads are decoded and checked \
                     against the kernel once the product's fixture round-trip fixes the \
                     kernel-object encodings"
                .to_owned(),
        }
    }
}
