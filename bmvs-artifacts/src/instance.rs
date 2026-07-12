// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! The product-line instance descriptor.

use serde::{Deserialize, Serialize};

/// Declares exactly which product-line instance ran an election: the casting
/// model, cryptographic suite, and enabled features.
///
/// The descriptor is embedded in the signed election configuration, so the
/// feature selection itself is trustee-endorsed and publicly committed — a
/// verifier knows precisely which protocol instance (and which constraint
/// set) it must check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceDescriptor {
    /// Schema version of this artifact (see [`crate::SCHEMA_VERSION`]).
    pub schema_version: String,
    /// Product identifier, e.g. `"bmvs"`.
    pub product: String,
    /// Casting model, e.g. `"bmvs"` (ballot-marking + tabulator). The
    /// baseline architecture's electronic-cast model would be `"e2ev-base"`.
    pub mode: String,
    /// Cryptographic suite identifier, e.g. `"ristretto255-ed25519-sha3"`.
    pub crypto_suite: String,
    /// Enabled product-line features, by feature-catalog identifier
    /// (e.g. `"provisional-ballots"`, `"early-voting"`, `"write-ins"`).
    pub features: Vec<String>,
    /// Minimum anonymity-set size for published per-group results
    /// (constraint X4).
    pub anonymity_floor: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() {
        let d = InstanceDescriptor {
            schema_version: crate::SCHEMA_VERSION.to_owned(),
            product: "bmvs".into(),
            mode: "bmvs".into(),
            crypto_suite: "ristretto255-ed25519-sha3".into(),
            features: vec!["provisional-ballots".into(), "early-voting".into()],
            anonymity_floor: 30,
        };
        let json = serde_json::to_string(&d).expect("serialize");
        let back: InstanceDescriptor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, d);
    }
}
