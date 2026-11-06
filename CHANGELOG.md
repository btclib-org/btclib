# Changelog

<!-- markdownlint-configure-file
  {
    // MD024/no-duplicate-heading - a group heading repeats under every
    // release with an entry in that group ("Packaging, linting and CI",
    // "Tests", "Repository"), which is what keeps the page readable
    // scrolling down it; only a duplicate under the same release heading
    // would be the accident this rule looks for
    "MD024": { "siblings_only": true }
  }
-->

Every change of a release, in full: what changed, why, and what it cost.
The release notes, which say what a user has to *act* on, are in
[RELEASE_NOTES.md](./RELEASE_NOTES.md); this file is the record behind
them.

A release's own pull request writes the release's section, from the squash
subjects since the previous tag, and no other pull request adds an entry
(sections 9 and 12 of the
[organization's standard](https://github.com/btclib-org/.github)).

Only v2026.8.7 and what follows it are recorded in the changelog at all.
The releases before it were documented at release-notes length in the
first place, and are still in [RELEASE_NOTES.md](./RELEASE_NOTES.md)
rather than duplicated here.

This file carries the most recent release, and a `(work in progress…)`
section where one remains; every release before it has a file of its own
under `changelog/`, holding that release's section and nothing of any
other. Past a size ceiling GitHub's contents API answers a file with an
empty `content` at HTTP 200, which reads as an empty file rather than as
an error, and one file per release is what keeps each of them under it.

- [v2026.11.2](./changelog/v2026.11.2.md)
- [v2026.10.30](./changelog/v2026.10.30.md)
- [v2026.10.28](./changelog/v2026.10.28.md)
- [v2026.10.24](./changelog/v2026.10.24.md)
- [v2026.10.17](./changelog/v2026.10.17.md)
- [v2026.10.16](./changelog/v2026.10.16.md)
- [v2026.10.9](./changelog/v2026.10.9.md)
- [v2026.10.8](./changelog/v2026.10.8.md)
- [v2026.10.7](./changelog/v2026.10.7.md)
- [v2026.10.5](./changelog/v2026.10.5.md)
- [v2026.10.4](./changelog/v2026.10.4.md)
- [v2026.10.3](./changelog/v2026.10.3.md)
- [v2026.10.2](./changelog/v2026.10.2.md)
- [v2026.9.30](./changelog/v2026.9.30.md)
- [v2026.9.29](./changelog/v2026.9.29.md)
- [v2026.9.24](./changelog/v2026.9.24.md)
- [v2026.9.13](./changelog/v2026.9.13.md)
- [v2026.9.10](./changelog/v2026.9.10.md)
- [v2026.9.3](./changelog/v2026.9.3.md)
- [v2026.8.29](./changelog/v2026.8.29.md)
- [v2026.8.27](./changelog/v2026.8.27.md)
- [v2026.8.21](./changelog/v2026.8.21.md)
- [v2026.8.9](./changelog/v2026.8.9.md)
- [v2026.8.7](./changelog/v2026.8.7.md)

## v2026.11.7

### ScriptFlag

`DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` is bit 18 and
`DISCOURAGE_UPGRADABLE_PUBKEYTYPE` bit 20, as in Bitcoin Core, where each
carried the other's bit (closes #2770).

### btclib requires ecc 2026.11.2

SECURITY.md links ecc's lines at its v2026.11.2 tag, and the ecc floor rises
to it (closes #2896).

### Refusals

`obfuscation.obfuscate` describes a negative offset `str()` cannot write
instead of raising `ValueError` (closes #2874).

### Homepage

`pyproject.toml`'s homepage is <https://btclib.org/btclib/> (closes #2893).

### Tests

`strategies_test` takes the block-payload branch on every run (closes #2839),
and `imports_test` keeps btclib free of `bip32_descriptors` imports
(closes #2887).

### Documentation

`conf.py`'s `BLOB` names `main` (closes #2911), and the prose names
btclib-org/functional-tests where bitcoin-node-tests stood (closes #2903).

### Workflows

The calls into btclib-org/.github move to v2026.11.5 (issue
btclib-org/.github#1988), Sourcery runs on every pull request (issue
btclib-org/.github#2005), and macOS runs on arm64 alone.

### Repository

RELEASING.md shares btclib-org/.github's text up to its own section (issue
btclib-org/.github#1855), names the lint jobs a tag run skips (closes #2900),
and lets a dependent adapt after the release (closes #2889).

### Shared files

CONTRIBUTING.md and REVIEWING.md take btclib-org/.github's shared parts, and
`.coderabbit.yaml` is carried (issue btclib-org/.github#1998).

### Dependencies

The dev-tooling group, setup-uv and the pinned pre-commit hooks move.
