# GitHub setup of tavrn-crypto

The repository is prepared so that nothing runs on GitHub until the owner switches it on. This page lists
what is configured in the repository and what has to be set by hand.

## Workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push to `main`, pull requests, by hand | the job `Publication hygiene` (`scripts/publish-check.sh`: no private files, domains or secrets), the organization's `rust-ci.yml` (`cargo fmt`, `cargo clippy` native and `wasm32`, `cargo test` incl. the protocol test vectors, `cargo deny`) and `js-ci.yml` (fresh WebAssembly build, SPDX and JS license checks, typecheck and Vitest against the new `pkg/dist`, `cargo publish --dry-run`, `npm pack --dry-run`) |
| `release.yml` | tag `v*.*.*`; by hand with a version (prepares a release) | a tag: job `build` (no publishing credential) tests the committed package, packs the `.crate` and the npm tarball and runs the publication dry runs; `release` attaches both to a GitHub release; `publish` (only with `PUBLISH_ENABLED`, environment `release`, after the owner's approval) publishes them without installing or building anything, after comparing both with what the tag packs (`npm pack --ignore-scripts`, `cargo package --no-verify`). By hand: builds `pkg/dist` from `main`, tests it and uploads it as the artifact `pkg-dist` for the release commit |
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
| `PUBLISH_CHECK_PRIVATE` | secret (repository or organization) | comma-separated private domains, hosts and addresses that must never appear in the tree (`Publication hygiene`). Without it the check fails on purpose. Locally the same list lives in an untracked `.publish-check.private` (in the repository or its parent directory). Dependabot pull requests need it as a Dependabot secret as well. |
| `TAVRN_READ_PAT` | secret | Private phase only: fine-grained PAT with `contents: read` on `tavrn-protocol`, `tavrn-crypto` and `tavrn-js`, passed to the reusable workflows as `READ_TOKEN` so they can fetch the private `protocol/` submodule. Delete it once the repositories are public. |
| `PUBLISH_ENABLED` | variable | `true` lets the release workflow publish to crates.io and npm (after the dry runs). Leave unset until the repositories are public and the release train starts. |
| `CARGO_REGISTRY_TOKEN` | secret of the environment `release` (never a repository secret) | crates.io API token with publish rights for `tavrn-crypto` (only with `PUBLISH_ENABLED`). |
| `NPM_TOKEN` | secret of the environment `release` | npm automation token with publish rights for the `@tavrn` scope (only with `PUBLISH_ENABLED`). |
| environment `release` | Settings → Environments | deployment only from tags `v*`, required reviewer the owner; holds the two tokens (`gh secret set <name> --env release`). Only the job `publish` declares it. |
| `CLA_PAT` | organization secret | the CLA bot's token (`contents: write` on `just-tavrn/cla-signatures`). Organization secrets do not reach private repositories on the free plan: until the repository is public, add it as a repository secret as well. |

## Release process (private phase)

`pkg/dist` (the built WebAssembly package) is committed so that other repositories can consume
`@tavrn/crypto` as a git dependency (`github:just-tavrn/tavrn-crypto#v0.1.0&path:pkg`) without a Rust
toolchain. `v0.1.0` was built locally and committed. A release: bump `Cargo.toml` and `pkg/package.json` on
`main`, build `pkg/dist` (locally with `./build-wasm.sh`, or by running `release.yml` by hand with the new version
and downloading its artifact `pkg-dist`), commit it as the release commit, tag it `vX.Y.Z` and push the tag. Only
organization owners may create `v*` tags, so the workflow no longer pushes one itself. When the packages are published to npm and
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
- [ ] Discussions: questions are routed to the Discussions of the umbrella repository `just-tavrn/tavrn`
      (`ISSUE_TEMPLATE/config.yml`); nothing to switch on here.
- [ ] Labels: `scripts/github-labels.sh` (needs `gh` with write access).
- [ ] Once public: branch protection or a ruleset for `main` (require pull requests, the CI checks `Rust`,
      `cargo deny`, `WebAssembly package`, `Publication hygiene`, `gitleaks`, `Dependency review`, `CLA`, linear history, no force
      pushes) and tag protection for `v*`. Not available for private repositories on the free plan.
