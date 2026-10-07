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

## v2026.10.7

### The forms set a type, and the history files lose `merge=union`

Forms set a type, not a kind label (issue btclib-org/.github#1584). A rebase
over a new entry stops on a conflict here (issue btclib-org/.github#1582). A
release reviews the bestpractices.dev answers (issue btclib-org/.github#1589).

### CodeQL runs the `security-extended` suite

`codeql.yml` passes `queries: security-extended` to the shared analysis for a
one-month trial (issue btclib-org/.github#1505).

### The post-release install refreshes the index

RELEASING.md installs the release with `--refresh-package btclib`, because uv
can answer from a cached index and miss a version just published
(issue btclib-org/.github#1595).

### `--admin` waits for no required check

`CONTRIBUTING.md`'s emergency paragraph says `--admin` skips the
required checks too, and `REVIEWING.md`'s "hold the merge" excepts it
(issue btclib-org/.github#1597).

### RELEASING.md names a change to the release assets

RELEASING.md asks that a release's notes name every change to its assets or to
how they are verified. RELEASE_NOTES.md names the bundle's file name
(issue btclib-org/.github#1596).

### `check-changelog` refuses an entry added to an older release

`check-changelog` refuses a `###` heading under a release older than the
newest, absent from the file at the merge base with `origin/main`
(issue btclib-org/.github#1614).

### Three vendored pins follow upstream's tip

`script_tests.json` is Core's file at `b47ec7c6e1`, `tx_valid.json` at
`6cd2fa5fb4`, and `secp256k1_symbols.txt` is re-extracted at `186eec1c1b`
(closes #2549).

### A long BIP324 message type holding 0x7F is refused

`bip324.message_from_contents` raises `BTClibValueError` for a long type with
a 0x7F byte, as Core does since bitcoin/bitcoin#35958 (closes #2553).

### `btclib.hashes` checks its ripemd160 at import

Importing `btclib.hashes` raises `BTClibRuntimeError` if the selected ripemd160
backend does not return the published digest of `b"abc"` (closes #2554).

### `btclib.obfuscation` reads and writes Core's file obfuscation

`obfuscate(data, key, offset)` XORs data found at byte `offset` of a file with
the repeating 8-byte key, as Core's `Obfuscation` does for a v2 `mempool.dat`;
`parse_key` and `serialize_key` handle the key (closes #2559).

### `btclib.compressor` reads and writes Core's coin compression

It has Core's `VARINT`, which is not CompactSize, and Core's amount and script
compression, both ways. `compress_amount` also refuses an amount above
`MAX_MONEY`, which Core does not (closes #2558).

### Dependencies are refreshed, and no floor moves

`uv lock --upgrade` moves aiohttp, bitcoin-core-rpc, filelock, hypothesis,
iniconfig, platformdirs and tomli, none across a major version. btclib calls
nothing that bitcoin-core-rpc 2026.10.4 changed.
