# bmvs-verifier

The **independent public verifier** for BMVS (Ballot Marking Voting System) elections, and the
owner of the **published election artifact schema**.

## Purpose

An end-to-end verifiable election is only as credible as the tooling that lets *anyone* check it.
This repository is deliberately separate from the BMVS product repository so that third parties
can clone, audit, and build the verifier alone, with the minimum possible trust surface:

- **`bmvs-artifacts`** (arrives in bootstrap Phase 2) — the versioned schema of everything a BMVS
  election publishes: the tally transcript, bulletin-board segments, disposition records,
  chain-head attestations, tabulator reports, and the product-line instance descriptor. The
  *product depends on this crate; this repository never depends on the product.*
- **`verifier-core`** (Phase 2) — the check implementations: bulletin-board chain integrity,
  configuration and trustee signatures, ballot cryptogram proofs, mix (shuffle) proofs,
  decryption proofs, disposition arithmetic, tally recomputation, the paper/cryptographic
  reconciliation identity, and card accounting closure.
- **`bmvs-verifier`** (Phase 2) — a thin command-line interface over `verifier-core`.

The only external dependency is the verification surface of the
[VoteSecure](https://github.com/FreeAndFair/VoteSecure) cryptographic kernel, consumed by pinned
git tag.

## Status

**Phase 0 bootstrap.** This repository currently contains conventions and configuration only; the
cargo workspace is scaffolded in Phase 2 of the bootstrap plan
(`docs/onsite-e2ev-bootstrap-plan.md` in the VoteSecure fork, migrating to the `bmvs` product
repository).

## Governing decisions (bootstrap plan Phase 0)

| Decision | Value |
|---|---|
| License (D2) | Apache-2.0 for code, CC BY-SA 4.0 for standalone documentation — see [LICENSE.md](./LICENSE.md) |
| Kernel consumption (D3) | Pinned git tag of the VoteSecure kernel; verification surface only |
| Toolchain (D4) | Pinned stable Rust — see [rust-toolchain.toml](./rust-toolchain.toml) |
| Versioning (D5) | Independent semver; artifact schema changes are additive-only within a major version; the verifier must remain able to verify older published elections |
| Conventions (D6) | See [CONTRIBUTING.md](./CONTRIBUTING.md) |
| Remote governance (D9) | Only the repository owner pushes to or modifies remotes |
