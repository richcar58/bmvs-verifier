// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! End-to-end CLI test: generate a record on disk, run the real binary,
//! check the report and exit code.

use std::process::Command;

#[test]
fn cli_verifies_a_generated_record_as_partial() {
    let dir = std::env::temp_dir().join(format!("bmvs-verifier-cli-test-{}", std::process::id()));
    let record = verifier_core::fixture::mini_record();
    verifier_core::loader::write_record_dir(&record, &dir).expect("write fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_bmvs-verifier"))
        .arg("verify")
        .arg(&dir)
        .output()
        .expect("run bmvs-verifier");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // All implemented checks pass; proof verification is staged, so the
    // outcome is Partial with exit code 2 — fail-closed, never a false PASS.
    assert!(stdout.contains("PASS  structure"), "stdout was:\n{stdout}");
    assert!(
        stdout.contains("PASS  chain-integrity"),
        "stdout was:\n{stdout}"
    );
    assert!(stdout.contains("PASS  signatures"), "stdout was:\n{stdout}");
    assert!(
        stdout.contains("SKIP  cryptographic-proofs"),
        "stdout was:\n{stdout}"
    );
    assert!(stdout.contains("overall: PARTIAL"), "stdout was:\n{stdout}");
    assert_eq!(output.status.code(), Some(2), "stdout was:\n{stdout}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_rejects_a_tampered_record() {
    let dir = std::env::temp_dir().join(format!(
        "bmvs-verifier-cli-tamper-test-{}",
        std::process::id()
    ));
    let mut record = verifier_core::fixture::mini_record();
    // Flip one tally digit: reconciliation and the transcript signature
    // must both catch it.
    if let Some(t) = record.transcript.as_mut() {
        t.tallies[0].options[0].count += 10;
    }
    verifier_core::loader::write_record_dir(&record, &dir).expect("write fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_bmvs-verifier"))
        .arg("verify")
        .arg(&dir)
        .output()
        .expect("run bmvs-verifier");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("FAIL"), "stdout was:\n{stdout}");
    assert!(stdout.contains("overall: FAIL"), "stdout was:\n{stdout}");
    assert_eq!(output.status.code(), Some(1), "stdout was:\n{stdout}");

    std::fs::remove_dir_all(&dir).ok();
}
