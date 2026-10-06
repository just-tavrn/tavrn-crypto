# GitHub setup of tavrn-crypto

The repository is prepared so that nothing runs on GitHub until the owner switches it on. This page lists
what is configured in the repository and what has to be set by hand.

## Workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push to `main`, pull requests, by hand | the organization's `rust-ci.yml` (`cargo fmt`, `cargo clippy` native and `wasm32`, `cargo test` incl. the protocol test vectors, `cargo deny`) and `js-ci.yml` (fresh WebAssembly build, SPDX and JS license checks, typecheck and Vitest against the new `pkg/dist`, `cargo publish --dry-run`, `npm pack --dry-run`) |
| `release.yml` | tag `v*.*.*`, or by hand with a version | tests the release, builds and commits `pkg/dist` (manual run), tags, attaches the `.crate` and the npm tarball to a GitHub release, publication dry runs; real publishing only with `PUBLISH_ENABLED` |
| `gitleaks.yml` | push to `main`, pull requests | the organization's `gitleaks.yml`: secret scan of the full history |
| `dependency-review.yml` | pull requests | refuses vulnerable dependencies and licenses outside the allow-list |
| `cla.yml` | pull requests, comments | the organization's `cla.yml` (CLA bot) |

The reusable workflows live in [`just-tavrn/.github`](https://github.com/just-tavrn/.github); its
`docs/GITHUB.md` describes the organization settings and how to create the tokens below.

Every job carries `if: ${{ vars.CI_ENABLED == 'true' }}`.

## Variables and secrets (Settings → Secrets and variables → Actions)

| Name | Kind | Purpose |
|---|---|---|
| `CI_ENABLED` | variable | `true` switches all workflows on. Unset or anything else: every job is skipped. |
| `TAVRN_READ_PAT` | secret | Private phase only: fine-grained PAT with `contents: read` on `tavrn-protocol`, `tavrn-crypto` and `tavrn-js`, passed to the reusable workflows as `READ_TOKEN` so they can fetch the private `protocol/` submodule. Delete it once the repositories are public. |
| `PUBLISH_ENABLED` | variable | `true` lets the release workflow publish to crates.io and npm (after the dry runs). Leave unset until the repositories are public and the release train starts. |
| `CARGO_REGISTRY_TOKEN` | secret | crates.io API token with publish rights for `tavrn-crypto` (only with `PUBLISH_ENABLED`). |
| `NPM_TOKEN` | secret | npm automation token with publish rights for the `@tavrn` scope (only with `PUBLISH_ENABLED`). |
| `CLA_PAT` | organization secret | the CLA bot's token (`contents: write` on `just-tavrn/cla-signatures`). Organization secrets do not reach private repositories on the free plan: until the repository is public, add it as a repository secret as well. |

## Release process (private phase)

`pkg/dist` (the built WebAssembly package) is committed so that other repositories can consume
`@tavrn/crypto` as a git dependency (`github:just-tavrn/tavrn-crypto#v0.1.0&path:pkg`) without a Rust
toolchain. `v0.1.0` was built locally and committed. Once `CI_ENABLED` is on, releases are made by running
`release.yml` by hand with the new version (after bumping `Cargo.toml` and `pkg/package.json` on `main`); the
workflow builds and commits `pkg/dist` in the release commit. When the packages are published to npm and
crates.io, `pkg/dist` is removed from `main` (add it back to `.gitignore`) and consumers switch to version
ranges.

## Settings applied through the API

Default branch `main`, delete branches on merge, squash merges allowed, issues on, wiki off, projects off.

## Settings the owner flips by hand

- [ ] `CI_ENABLED` and the secrets above when CI should run.
- [ ] Secret scanning with push protection (Settings → Code security; free for public repositories).
- [ ] Private vulnerability reporting (Settings → Code security), so "Report a vulnerability" works.
- [ ] Dependency graph and Dependabot alerts (needed by `dependency-review.yml`; on private repositories
      only with GitHub Advanced Security).
- [ ] Discussions: questions are routed to the organization's Discussions (`ISSUE_TEMPLATE/config.yml`).
- [ ] Labels: `scripts/github-labels.sh` (needs `gh` with write access).
- [ ] Once public: branch protection or a ruleset for `main` (require pull requests, the CI checks `Rust`,
      `cargo deny`, `WebAssembly package`, `gitleaks`, `Dependency review`, `CLA`, linear history, no force
      pushes) and tag protection for `v*`. Not available for private repositories on the free plan.
