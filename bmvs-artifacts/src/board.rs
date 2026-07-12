// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Richard Cardone

//! Bulletin-board segments: the hash-chained, signed public record kept by
//! each polling place controller and published after close (architecture
//! flows F7.1 and F3.x).

use crate::bytes::Bytes;
use crate::{canonical_input, ds_tags};
use serde::{Deserialize, Serialize};

/// The kind of a bulletin entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BulletinKind {
    /// A submitted (committed, not yet cast) ballot cryptogram.
    Submission,
    /// Publication of a session authorization at cast time.
    VoterAuthorization,
    /// A cast marker referencing an earlier submission.
    Cast,
    /// A spoil marker (Benaloh challenge or misprint void).
    Spoil,
}

impl BulletinKind {
    /// Stable single-byte tag used in the entry hash input.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Submission => 1,
            Self::VoterAuthorization => 2,
            Self::Cast => 3,
            Self::Spoil => 4,
        }
    }
}

/// Flags qualifying an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EntryFlags {
    /// The entry belongs to a provisional voting session (pended cryptogram).
    pub provisional: bool,
    /// The entry was produced during logic-and-accuracy testing.
    pub test: bool,
}

impl EntryFlags {
    /// Stable single-byte encoding used in the entry hash input.
    #[must_use]
    pub fn tag(self) -> u8 {
        u8::from(self.provisional) | (u8::from(self.test) << 1)
    }
}

/// One entry on a polling place's bulletin board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulletinEntry {
    /// Entry kind.
    pub kind: BulletinKind,
    /// Entry flags.
    pub flags: EntryFlags,
    /// Kernel-encoded entry payload (opaque at schema level): the signed
    /// ballot message for submissions, the authorization for voter-auth
    /// entries, the cast/spoil marker bodies otherwise.
    pub payload: Bytes,
    /// For `Cast` and `Spoil` entries: the tracker (entry hash) of the
    /// `Submission` they refer to. Empty for other kinds.
    pub subject: Bytes,
    /// The previous entry's hash (chain linkage); for a site's first entry
    /// of the election this is the election hash.
    pub previous_hash: Bytes,
    /// This entry's hash — SHA3-256 over [`Self::hash_input`]. For
    /// submissions, this value **is the voter's tracker**.
    pub entry_hash: Bytes,
}

impl BulletinEntry {
    /// The canonical byte input whose SHA3-256 hash is `entry_hash`:
    /// kind tag, flags tag, payload, subject, previous hash — length-prefixed
    /// under the bulletin-entry domain tag.
    #[must_use]
    pub fn hash_input(&self) -> Vec<u8> {
        canonical_input(
            ds_tags::BULLETIN_ENTRY,
            &[
                &[self.kind.tag()],
                &[self.flags.tag()],
                self.payload.as_slice(),
                self.subject.as_slice(),
                self.previous_hash.as_slice(),
            ],
        )
    }
}

/// One site's bulletin-board segment for one voting day, as uploaded after
/// close (F7.1). A site's segments chain day to day via
/// `previous_segment_head`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardSegment {
    /// Schema version of this artifact.
    pub schema_version: String,
    /// The election hash (binds the segment to the configuration).
    pub election_hash: Bytes,
    /// Site (polling place) identifier.
    pub site_id: String,
    /// Voting day, ISO-8601 date (early voting yields one segment per day).
    pub day: String,
    /// The previous day's segment head for this site; the election hash for
    /// the site's first segment.
    pub previous_segment_head: Bytes,
    /// Entries in board order.
    pub entries: Vec<BulletinEntry>,
    /// The segment head: the last entry's hash, or `previous_segment_head`
    /// if the segment is empty.
    pub segment_head: Bytes,
    /// The controller's (DBB) Ed25519 verifying key (32 bytes).
    pub dbb_verifying_key: Bytes,
    /// DBB Ed25519 signature over [`Self::signing_input`].
    pub signature: Bytes,
}

impl BoardSegment {
    /// The canonical byte input the DBB signature covers: election hash,
    /// site, day, previous head, entry count (u64 LE), segment head.
    ///
    /// The entries themselves are covered transitively: `segment_head`
    /// commits to the full chain (each entry hash commits to its
    /// predecessor), so signing the head signs the history.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let count = (self.entries.len() as u64).to_le_bytes();
        canonical_input(
            ds_tags::BOARD_SEGMENT,
            &[
                self.election_hash.as_slice(),
                self.site_id.as_bytes(),
                self.day.as_bytes(),
                self.previous_segment_head.as_slice(),
                &count,
                self.segment_head.as_slice(),
            ],
        )
    }
}
