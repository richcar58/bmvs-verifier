# Contributing

This repository follows the development conventions of the
[VoteSecure](https://github.com/FreeAndFair/VoteSecure) kernel repository (bootstrap plan
decision D6), so that all three BMVS repositories — kernel, product, and verifier — are governed
identically.

## Commit conventions

- **Conventional Commits** are required and enforced by the `commitlint` pre-commit hook. The
  accepted types are the conventional set plus two project additions: `build`, `chore`, `ci`,
  `cosmetics` (cosmetic-only changes), `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`,
  `style`, `test`, and `wip` (draft-PR work expected to be squashed).
- **Signed commits** are required for anything that lands on `main` or a release branch.

## Branch and merge workflow

- **Linear history** on `main` and release branches: PR branches are rebased and merged
  fast-forward (`git merge --ff-only` from the command line — the GitHub UI cannot do this).
- Use `git pull --rebase` on shared branches and `--force-with-lease` (never `--force`) when
  rewriting a PR branch.

## Remote governance

Only the repository owner pushes to or otherwise modifies remote repositories — including remote
creation, tags, and branch operations (bootstrap plan decision D9). All other contribution work
is local and lands via reviewed pull requests that the owner merges and pushes.

## Local setup

Install the pre-commit hooks once per clone:

```bash
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg
```

The hooks enforce text hygiene (UTF-8, LF line endings, no trailing whitespace, final newline)
and commit-message format at commit time. CI re-runs the same hooks authoritatively.

## Toolchain

Rust code in this repository targets **pinned stable Rust** (see `rust-toolchain.toml`), which
`rustup` selects automatically. Toolchain bumps are ordinary reviewed commits.

## Context

This repository is part of the BMVS (Ballot Marking Voting System) three-repository organization.
The governing plan is `docs/onsite-e2ev-bootstrap-plan.md` in the
[`bmvs` product repository](https://github.com/richcar58/bmvs), which per decision D7 holds all
product documentation. The product depends on this repository's `bmvs-artifacts` schema crate;
this repository never depends on the product.
