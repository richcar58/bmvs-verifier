# bmvs-verifier

The **independent public verifier** for [BMVS](https://github.com/richcar58/bmvs)
(Ballot Marking Voting System) elections, and the
owner of the **published election artifact schema**.

## Purpose

An end-to-end verifiable election is only as credible as the tooling that lets *anyone* check it.
This repository is deliberately separate from the BMVS product repository so that third parties
can clone, audit, and build the verifier alone, with the minimum possible trust surface:

- **`bmvs-artifacts`** — the versioned schema of everything a BMVS election publishes: the
  election configuration (with the product-line instance descriptor), bulletin-board segments,
  chain-head attestations, disposition records, tabulator reports, and the tally transcript —
  including the **canonical signing/hashing byte inputs**, which are part of the schema, never an
  implementation detail. Kernel-free by design. The *product depends on this crate; this
  repository never depends on the product.*
- **`verifier-core`** — the check implementations, mirroring the architecture's
  full-verification flow: structure and election-hash binding, bulletin-board chain integrity,
  attestation consistency, Ed25519 signatures over the canonical inputs, disposition arithmetic
  with mix-input completeness, card-accounting closure, the paper/cryptographic reconciliation
  identity, and (staged for milestone M1) the cryptographic proof checks. Reporting is
  **fail-closed**: skipped or staged checks cap the outcome at *Partial* — never a false full
  pass.
- **`bmvs-verifier`** — the command-line interface:
  `bmvs-verifier verify <election-record-dir> [--json]` (exit 0 full pass, 1 fail, 2 partial).

The only external dependency is the verification surface of the
[VoteSecure](https://github.com/FreeAndFair/VoteSecure) cryptographic kernel, consumed by pinned
git tag (`kernel-v1.4-fork.1`, corresponding to upstream VoteSecure v1.4). This pin is kept in
lockstep with the one in the product repository: Cargo keys git sources by URL *including* the
tag, so divergent pins would place two incompatible copies of an identical crate in that
workspace's dependency graph.

## Try it

```bash
cargo run -p bmvs-verifier -- verify fixtures/mini
```

`fixtures/mini` is a committed micro-election (one site, one contest, four voters, one Benaloh
challenge) with real hashes and Ed25519 signatures; regenerate it with
`cargo run -p verifier-core --example gen_mini_fixture -- fixtures/mini`.

## Status

**Phase 2 scaffolded.** The workspace builds and tests on pinned stable Rust; seven of eight
check families are implemented and exercised positively and negatively; cryptographic proof
verification is staged for milestone M1, when the product's fixture round-trip fixes the
kernel-object encodings inside the opaque transcript payloads. The governing plan is
`docs/onsite-e2ev-bootstrap-plan.md` in the [`bmvs` repository](https://github.com/richcar58/bmvs).

## Governing decisions (bootstrap plan Phase 0)

| Decision | Value |
|---|---|
| License (D2) | Apache-2.0 for code, CC BY-SA 4.0 for standalone documentation — see [LICENSE.md](./LICENSE.md) |
| Kernel consumption (D3) | Pinned git tag of the VoteSecure kernel; verification surface only |
| Toolchain (D4) | Pinned stable Rust — see [rust-toolchain.toml](./rust-toolchain.toml) |
| Versioning (D5) | Independent semver; artifact schema changes are additive-only within a major version; the verifier must remain able to verify older published elections |
| Conventions (D6) | See [CONTRIBUTING.md](./CONTRIBUTING.md) |
| Remote governance (D9) | Only the repository owner pushes to or modifies remotes |
