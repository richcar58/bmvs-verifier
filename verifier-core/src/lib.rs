// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! # BMVS verifier core
//!
//! Check implementations over published BMVS election records
//! ([`bmvs_artifacts::ElectionRecord`]), organized to mirror the
//! architecture's full-verification flow (F13.2): structural validity,
//! bulletin-board chain integrity, attestation consistency, signatures,
//! disposition arithmetic (mix-input completeness), card accounting,
//! the paper/cryptographic reconciliation identity, and — staged for
//! milestone M1 — cryptographic proof verification (`Naor-Yung`, shuffle,
//! decryption) via the `VoteSecure` kernel.
//!
//! ## Fail-closed reporting
//!
//! [`verify_record`] returns a [`report::VerificationReport`] whose overall
//! outcome is [`report::Overall::Pass`] only when **every** check passes.
//! Checks that are not yet implemented, or not applicable to the record's
//! state, report as *skipped with a reason* and cap the outcome at
//! [`report::Overall::Partial`] — a partial verification is never presented
//! as a full one.

pub mod checks;
pub mod fixture;
pub mod loader;
pub mod report;

use bmvs_artifacts::ElectionRecord;
use report::VerificationReport;

/// Kernel type bindings used by the checks (the baseline Ristretto255
/// context's signature scheme and 256-bit hasher).
pub mod kernel {
    use cryptography::context::Context;
    use cryptography::utils::signatures::SignatureScheme;

    /// The cryptographic context fixed by the baseline instance descriptor.
    pub type Ctx = cryptography::context::RistrettoCtx;
    /// The context's RNG (used by fixture generation).
    pub type Rng = <Ctx as Context>::Rng;
    /// The signature scheme.
    pub type Scheme = <Ctx as Context>::SignatureScheme;
    /// Ed25519 verifying key.
    pub type VerifyingKey = <Scheme as SignatureScheme<Rng>>::Verifier;
    /// Ed25519 signing key (fixtures only).
    pub type SigningKey = <Scheme as SignatureScheme<Rng>>::Signer;
    /// Ed25519 signature.
    pub type Signature = <Scheme as SignatureScheme<Rng>>::Signature;

    /// SHA3-256 over `data`, matching the kernel's `Hasher256`.
    #[must_use]
    pub fn hash256(data: &[u8]) -> [u8; 32] {
        use sha3::Digest as _;
        let mut hasher = cryptography::utils::hash::Hasher256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

/// Runs every check against the record and returns the report.
///
/// # Examples
/// ```
/// let record = verifier_core::fixture::mini_record();
/// let report = verifier_core::verify_record(&record);
/// // The mini fixture passes all implemented checks; cryptographic proof
/// // verification is staged for M1, so the overall outcome is Partial.
/// assert_eq!(report.overall(), verifier_core::report::Overall::Partial);
/// ```
#[must_use]
pub fn verify_record(record: &ElectionRecord) -> VerificationReport {
    let mut report = VerificationReport::default();
    for check in checks::all_checks() {
        let status = check.run(record);
        report.push(check.name(), status);
    }
    report
}
