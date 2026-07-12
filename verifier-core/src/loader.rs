// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! Loads a published election record from its on-disk directory layout.

use bmvs_artifacts::{
    BoardSegment, ChainHeadAttestation, DispositionRecord, ElectionConfigRecord, ElectionRecord,
    TabulatorReport, TallyTranscript,
};
use std::path::{Path, PathBuf};

/// Errors from loading an election-record directory.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// A required file or directory was missing or unreadable.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The offending path.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// A file did not parse as its expected artifact type.
    #[error("cannot parse {path}: {source}")]
    Parse {
        /// The offending path.
        path: PathBuf,
        /// The underlying JSON error.
        source: serde_json::Error,
    },
}

fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, LoadError> {
    let data = std::fs::read(path).map_err(|source| LoadError::Io {
        path: path.to_owned(),
        source,
    })?;
    serde_json::from_slice(&data).map_err(|source| LoadError::Parse {
        path: path.to_owned(),
        source,
    })
}

/// Loads every `.json` file in `dir` (sorted by file name for deterministic
/// ordering) as artifact type `T`. A missing directory yields an empty list,
/// because several artifact classes are legitimately absent early in an
/// election's lifecycle.
fn load_dir<T: serde::de::DeserializeOwned>(dir: &Path) -> Result<Vec<T>, LoadError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(dir).map_err(|source| LoadError::Io {
        path: dir.to_owned(),
        source,
    })?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    paths.iter().map(|p| load_json(p)).collect()
}

/// Loads a complete election record from `dir`.
///
/// Expected layout: `config.json` (required), `segments/*.json`,
/// `attestations/*.json`, `dispositions/*.json`,
/// `tabulator-reports/*.json`, and `transcript.json` (optional — absent
/// until the trustee ceremony completes).
///
/// # Errors
/// Returns [`LoadError`] naming the exact file that was unreadable or
/// unparseable.
pub fn load_record_dir(dir: &Path) -> Result<ElectionRecord, LoadError> {
    let config: ElectionConfigRecord = load_json(&dir.join("config.json"))?;
    let segments: Vec<BoardSegment> = load_dir(&dir.join("segments"))?;
    let attestations: Vec<ChainHeadAttestation> = load_dir(&dir.join("attestations"))?;
    let dispositions: Vec<DispositionRecord> = load_dir(&dir.join("dispositions"))?;
    let tabulator_reports: Vec<TabulatorReport> = load_dir(&dir.join("tabulator-reports"))?;
    let transcript_path = dir.join("transcript.json");
    let transcript: Option<TallyTranscript> = if transcript_path.exists() {
        Some(load_json(&transcript_path)?)
    } else {
        None
    };
    Ok(ElectionRecord {
        config,
        segments,
        attestations,
        dispositions,
        tabulator_reports,
        transcript,
    })
}

/// Writes a record to `dir` in the layout [`load_record_dir`] expects.
/// Used by fixture generation and by product-side publication tooling.
///
/// # Errors
/// Returns [`LoadError::Io`] naming the exact path that failed. (JSON
/// serialization of schema types cannot fail.)
pub fn write_record_dir(record: &ElectionRecord, dir: &Path) -> Result<(), LoadError> {
    let io = |path: &Path, source: std::io::Error| LoadError::Io {
        path: path.to_owned(),
        source,
    };
    let write_json = |path: &Path, value: &dyn erased_ser::ErasedSer| -> Result<(), LoadError> {
        let data = value.to_json_pretty();
        std::fs::write(path, data).map_err(|e| io(path, e))
    };
    std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
    write_json(&dir.join("config.json"), &record.config)?;
    for (sub, count) in [
        ("segments", record.segments.len()),
        ("attestations", record.attestations.len()),
        ("dispositions", record.dispositions.len()),
        ("tabulator-reports", record.tabulator_reports.len()),
    ] {
        if count > 0 {
            std::fs::create_dir_all(dir.join(sub)).map_err(|e| io(&dir.join(sub), e))?;
        }
    }
    for (i, s) in record.segments.iter().enumerate() {
        write_json(&dir.join(format!("segments/{i:04}.json")), s)?;
    }
    for (i, a) in record.attestations.iter().enumerate() {
        write_json(&dir.join(format!("attestations/{i:04}.json")), a)?;
    }
    for (i, d) in record.dispositions.iter().enumerate() {
        write_json(&dir.join(format!("dispositions/{i:04}.json")), d)?;
    }
    for (i, t) in record.tabulator_reports.iter().enumerate() {
        write_json(&dir.join(format!("tabulator-reports/{i:04}.json")), t)?;
    }
    if let Some(t) = &record.transcript {
        write_json(&dir.join("transcript.json"), t)?;
    }
    Ok(())
}

/// Minimal object-safe serialization helper so [`write_record_dir`] can
/// treat heterogeneous artifact types uniformly.
mod erased_ser {
    /// Object-safe "serialize to pretty JSON" for artifact types.
    pub trait ErasedSer {
        /// Pretty-printed JSON with a trailing newline.
        fn to_json_pretty(&self) -> Vec<u8>;
    }
    impl<T: serde::Serialize> ErasedSer for T {
        fn to_json_pretty(&self) -> Vec<u8> {
            // Schema types serialize infallibly (no maps with non-string
            // keys, no floats); a failure here would be a schema bug caught
            // by round-trip tests, so fall back to an empty object rather
            // than panicking in a verifier.
            let mut v = serde_json::to_vec_pretty(self).unwrap_or_else(|_| b"{}".to_vec());
            v.push(b'\n');
            v
        }
    }
}
