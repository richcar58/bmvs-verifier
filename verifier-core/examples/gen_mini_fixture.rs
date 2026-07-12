// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! Regenerates the committed `fixtures/mini` election record.
//!
//! ```text
//! cargo run -p verifier-core --example gen_mini_fixture -- fixtures/mini
//! ```
//!
//! Keys are freshly generated on every run, so regenerating changes the
//! fixture bytes (but never its structure or validity).

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: gen_mini_fixture <output-dir>");
        return ExitCode::from(64);
    };
    let record = verifier_core::fixture::mini_record();
    match verifier_core::loader::write_record_dir(&record, &PathBuf::from(&dir)) {
        Ok(()) => {
            println!("wrote mini fixture to {dir}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
