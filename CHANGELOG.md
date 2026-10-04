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

Only v2026.8.7 and what follows it are recorded in the changelog at all.
The releases before it were documented at release-notes length in the
first place, and are still in [RELEASE_NOTES.md](./RELEASE_NOTES.md)
rather than duplicated here.

This file carries the cycle in progress and the most recent release;
every release before those has a file of its own under `changelog/`,
holding that release's section and nothing of any other. Past a size
ceiling GitHub's contents API answers a file with an empty `content` at
HTTP 200, which reads as an empty file rather than as an error, and one
file per release is what keeps each of them under it.

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

## v2026.11 (work in progress, not released yet)

### The forms set a type, and the history files lose `merge=union`

Forms set a type, not a kind label (issue btclib-org/.github#1584). A rebase
over a new entry stops on a conflict here (issue btclib-org/.github#1582). A
release reviews the bestpractices.dev answers (issue btclib-org/.github#1589).

### CodeQL runs the `security-extended` suite

`codeql.yml` passes `queries: security-extended` to the shared analysis for a
one-month trial (issue btclib-org/.github#1505).

## v2026.10.5

### `README.md` names SEC 2 for the curves

`README.md` says SEC 2, not SEC 1, defines the elliptic curves.

### Verifying a transaction takes time linear in its inputs

`PrecomputedTxData` validates every prevout once, when built, and refuses a
script_pub_key naming an unknown network. A sig_hash given one validates only
the prevout it reads (GHSA-9r97-9x22-2pp4).

### Repeated signature checks of an input share one hash

The script engine keeps, per class of hash type, the SHA256 midstate of an
input's legacy or segwit v0 signature hash and the script code it is for, as
Bitcoin Core's `SigHashCache` does. A check whose hash type class and script
code match the previous check of that class in the same input hashes only the
hash type, where it built the whole preimage again (GHSA-rw95-w37r-537w). A
script code that differs at every check, as one with an `OP_CODESEPARATOR`
before each, still builds the whole preimage at each.
