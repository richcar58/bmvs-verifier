// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! Verification report structures and rendering.

use serde::Serialize;

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CheckStatus {
    /// The check ran and everything it examined was correct.
    Pass,
    /// The check found problems; each string pinpoints one.
    Fail {
        /// Human-readable findings, one per problem.
        problems: Vec<String>,
    },
    /// The check did not run; the reason says why (not yet implemented, or
    /// not applicable to the record's current state).
    Skipped {
        /// Why the check was skipped.
        reason: String,
    },
}

/// One named check's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    /// Check name (stable identifier).
    pub name: String,
    /// Outcome.
    #[serde(flatten)]
    pub status: CheckStatus,
}

/// Overall verification outcome. Fail-closed: `Pass` requires every check
/// to pass; any skip caps the outcome at `Partial`; any failure is `Fail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Overall {
    /// Every check passed: a full verification.
    Pass,
    /// No failures, but at least one check was skipped: **not** a full
    /// verification.
    Partial,
    /// At least one check failed.
    Fail,
}

/// The complete report.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VerificationReport {
    /// Per-check results, in execution order.
    pub results: Vec<CheckResult>,
}

impl VerificationReport {
    /// Appends one check's result.
    pub fn push(&mut self, name: &str, status: CheckStatus) {
        self.results.push(CheckResult {
            name: name.to_owned(),
            status,
        });
    }

    /// The overall outcome (see [`Overall`]).
    #[must_use]
    pub fn overall(&self) -> Overall {
        let mut skipped = false;
        for r in &self.results {
            match &r.status {
                CheckStatus::Fail { .. } => return Overall::Fail,
                CheckStatus::Skipped { .. } => skipped = true,
                CheckStatus::Pass => {}
            }
        }
        if skipped {
            Overall::Partial
        } else {
            Overall::Pass
        }
    }

    /// Plain-text rendering for terminals.
    #[must_use]
    pub fn to_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for r in &self.results {
            match &r.status {
                CheckStatus::Pass => {
                    let _ = writeln!(out, "PASS  {}", r.name);
                }
                CheckStatus::Skipped { reason } => {
                    let _ = writeln!(out, "SKIP  {} — {}", r.name, reason);
                }
                CheckStatus::Fail { problems } => {
                    let _ = writeln!(out, "FAIL  {}", r.name);
                    for p in problems {
                        let _ = writeln!(out, "      - {p}");
                    }
                }
            }
        }
        let overall = match self.overall() {
            Overall::Pass => "PASS — full verification",
            Overall::Partial => {
                "PARTIAL — no failures, but skipped checks mean this is NOT a full verification"
            }
            Overall::Fail => "FAIL — the published record did not verify",
        };
        let _ = writeln!(out, "overall: {overall}");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overall_is_fail_closed() {
        let mut r = VerificationReport::default();
        r.push("a", CheckStatus::Pass);
        assert_eq!(r.overall(), Overall::Pass);
        r.push(
            "b",
            CheckStatus::Skipped {
                reason: "staged".into(),
            },
        );
        assert_eq!(r.overall(), Overall::Partial);
        r.push(
            "c",
            CheckStatus::Fail {
                problems: vec!["boom".into()],
            },
        );
        assert_eq!(r.overall(), Overall::Fail);
    }
}
