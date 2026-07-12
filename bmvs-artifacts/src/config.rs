// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! The published election configuration record — the root of trust of the
//! public election record.

use crate::bytes::Bytes;
use crate::instance::InstanceDescriptor;
use crate::{canonical_input, ds_tags};
use serde::{Deserialize, Serialize};

/// A trustee's public identity as published in the configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrusteePublic {
    /// Human-readable trustee name.
    pub name: String,
    /// Ed25519 verifying key (32 bytes).
    pub verifying_key: Bytes,
}

/// A signature attributed to a named signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedSignature {
    /// The signer's name (must resolve against the record's key material).
    pub signer: String,
    /// Ed25519 signature (64 bytes).
    pub signature: Bytes,
}

/// The trustee-endorsed election configuration, published before any ballot
/// is cast (architecture flow F12.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectionConfigRecord {
    /// Schema version of this artifact.
    pub schema_version: String,
    /// The election hash — SHA3-256 over this configuration's canonical
    /// signing input. Every other artifact carries this value; it binds the
    /// whole record to one endorsed configuration.
    pub election_hash: Bytes,
    /// The election manifest (contests, styles; encoding governed by the
    /// product's manifest format, opaque at schema level).
    pub manifest: String,
    /// DKG threshold `T`.
    pub threshold: u32,
    /// Trustee roster with verifying keys, in protocol order.
    pub trustees: Vec<TrusteePublic>,
    /// Non-trustee signing authorities (election authority, adjudicators)
    /// whose keys authenticate disposition records. Device keys (per-site
    /// controllers and tabulators) are carried in-band by their artifacts in
    /// schema 0.1 and cross-checked for intra-record consistency; binding
    /// them here is a planned additive extension backed by the provisioning
    /// evidence of architecture flow F6.1.
    pub authorities: Vec<TrusteePublic>,
    /// Kernel-encoded election public key (opaque bytes).
    pub election_public_key: Bytes,
    /// The product-line instance descriptor (feature selection).
    pub instance: InstanceDescriptor,
    /// One endorsement signature per trustee over [`Self::signing_input`].
    pub signatures: Vec<NamedSignature>,
}

impl ElectionConfigRecord {
    /// The canonical byte input that trustee endorsement signatures cover,
    /// and whose SHA3-256 hash is the `election_hash`.
    ///
    /// Fields, in order: manifest, threshold (u32 LE), each trustee's name
    /// and verifying key (in roster order), the election public key, and the
    /// instance descriptor's fields (product, mode, crypto suite, each
    /// feature in listed order, anonymity floor as u32 LE). JSON is
    /// deliberately not part of any canonical input — field bytes are
    /// concatenated with length prefixes via [`canonical_input`].
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let threshold = self.threshold.to_le_bytes();
        let floor = self.instance.anonymity_floor.to_le_bytes();
        let mut fields: Vec<Vec<u8>> = vec![self.manifest.as_bytes().to_vec(), threshold.to_vec()];
        for t in &self.trustees {
            fields.push(t.name.as_bytes().to_vec());
            fields.push(t.verifying_key.0.clone());
        }
        for a in &self.authorities {
            fields.push(a.name.as_bytes().to_vec());
            fields.push(a.verifying_key.0.clone());
        }
        fields.push(self.election_public_key.0.clone());
        fields.push(self.instance.product.as_bytes().to_vec());
        fields.push(self.instance.mode.as_bytes().to_vec());
        fields.push(self.instance.crypto_suite.as_bytes().to_vec());
        for f in &self.instance.features {
            fields.push(f.as_bytes().to_vec());
        }
        fields.push(floor.to_vec());
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        canonical_input(ds_tags::CONFIG, &refs)
    }
}
