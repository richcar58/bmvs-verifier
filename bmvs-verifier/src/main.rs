// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! # bmvs-verifier
//!
//! Command-line verifier for published BMVS election records.
//!
//! ```text
//! bmvs-verifier verify <election-record-dir> [--json]
//! ```
//!
//! Exit codes: `0` full pass; `1` verification failure; `2` partial
//! verification (no failures, but skipped checks — **not** a full
//! verification); `64` usage or input error.
//!
//! Argument parsing is deliberately hand-rolled: this binary's supply chain
//! is part of the election's trust story, and two flags do not justify a
//! dependency.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;
use verifier_core::report::Overall;

/// Usage/input-error exit code (BSD `EX_USAGE`).
const EXIT_USAGE: u8 = 64;
/// Partial-verification exit code.
const EXIT_PARTIAL: u8 = 2;

fn usage() -> ExitCode {
    eprintln!("usage: bmvs-verifier verify <election-record-dir> [--json]");
    ExitCode::from(EXIT_USAGE)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut json = false;
    let mut positional: Vec<&str> = Vec::new();
    for a in &args {
        match a.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("usage: bmvs-verifier verify <election-record-dir> [--json]");
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') => {
                eprintln!("unknown option: {other}");
                return usage();
            }
            other => positional.push(other),
        }
    }
    let [command, dir] = positional.as_slice() else {
        return usage();
    };
    if *command != "verify" {
        eprintln!("unknown command: {command}");
        return usage();
    }

    let record = match verifier_core::loader::load_record_dir(&PathBuf::from(dir)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let report = verifier_core::verify_record(&record);
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: cannot render report as JSON: {e}");
                return ExitCode::from(EXIT_USAGE);
            }
        }
    } else {
        print!("{}", report.to_text());
    }
    match report.overall() {
        Overall::Pass => ExitCode::SUCCESS,
        Overall::Partial => ExitCode::from(EXIT_PARTIAL),
        Overall::Fail => ExitCode::FAILURE,
    }
}
