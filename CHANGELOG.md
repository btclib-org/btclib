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

## v2026.10.9

### `Tx.parse` caps the input and output counts only with `check_validity`

Without `check_validity`, `Tx.parse`, `Tx.parse_without_witness` and
`Block.parse` bound each count by `var_int.MAX_SIZE`, as Core's
`ReadCompactSize` does, and leave a transaction too large for a block to
`assert_valid`, which refuses it as oversize. With `check_validity` the counts
are still capped by `MAX_TX_IN_COUNT` and `MAX_TX_OUT_COUNT` (closes #2592).

### Strategies for the transaction types check their round trips

Hypothesis strategies for `OutPoint`, `TxOut`, `TxIn`, `Witness` and `Tx`
check that each serializes and parses back to itself (issue #2582).

### `RELEASING.md` runs the dependents' suites before the tag

It also reads the tag's signature back from the API once the tag is pushed
(issue btclib-org/.github#1647, issue btclib-org/.github#1660).

### The documents take the organization's shared text

`CONTRIBUTING.md` and `REVIEWING.md` take `btclib-org/.github`'s shared halves
(issue btclib-org/.github#1620, issue btclib-org/.github#1634).
`REPOSITORY.md` says that `tag-integrity` refuses an unsigned commit, not an
unsigned tag (issue btclib-org/.github#1635).

### CI

The fuzz build's `oss-fuzz-base/base-builder-python` image is bumped.
`claude-review.yml` puts the caller's paragraph after the findings paragraph.
