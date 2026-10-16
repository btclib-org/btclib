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

## v2026.10.16

### btclib requires btclib-ecc 2026.10.16

btclib imports `point_from_octets_var` and `point_from_bip340pub_key_var`,
btclib-ecc 2026.10.16's names for its point parsers, and SECURITY.md cites that
release's lines (issue btclib-org/.github#1742, closes #2595, closes #2603).

### `hex_string`, `str_from_string` and `base58.decode` quote less

`hex_string` does not quote a negative integer. `str_from_string` and
`base58.decode` name the position of a non-ASCII character, not the character,
as btclib-ecc does (issue #2625).

### `int_from_integer` refuses an empty input

It read an empty string or empty bytes as 0 (closes #2671).

### Transaction and header serializers check int fields and the header's time

With `check_validity=False`, `Tx`, `TxIn`, `OutPoint`, `TxOut` and
`BlockHeader` refuse an int field, or a header's time, of the wrong type or
range (closes #2644, closes #2654, closes #2655, closes #2658, closes #2666).

### The p2p serializers check every int field

With `check_validity=False`, a non-int is a `BTClibTypeError` and an int its
width does not hold a `BTClibValueError`; a bool is still written as 0 or 1
(closes #2656, closes #2663, closes #2664, closes #2665).

### The signature hashes refuse a bool or a float in an int field

`legacy`, `segwit_v0` and the taproot `from_tx` refuse one in the sequence,
vout, version, lock time and amount. A float amount never returned
(closes #2627, closes #2640).

### `script.parse` and `taproot.parse` return `OP_0` for every empty push

`4c00`, `4d0000` and `4e00000000` parse as `00` does, so a parsed script
round-trips. A script_sig ending in `00` gives the empty redeem script
(closes #2607).

### `verify_amounts` bounds the prevout values

Each prevout value and their running total must be in 0..MAX_MONEY, as Core's
`Consensus::CheckTxInputs` requires (closes #2670).

### The Electrum request builders check their arguments

They raise `BTClibTypeError` or `BTClibValueError` for a malformed argument,
and `encode_request` takes only a list or a tuple as `params` (closes #2629).

### `btclib.electrum` reads `blockchain.block.headers`

`block_headers_request` and `block_headers_response` read the response shape
from before protocol 1.6, for btclib-wallet's Floresta fetcher (closes #2628).

### Fuzz harnesses check round trips and run in the suite

What a parser accepts serializes back (closes #2585). The suite runs each
harness on its seeds (closes #2624), and the stored corpora take every seed of
`fuzz/corpus` (closes #2614).

### The parsers replay the qa-assets corpora

Bitcoin Core's and rust-bitcoin's qa-assets fuzz corpora replay through the
btclib parser that reads the same bytes (closes #2586, closes #2631).

### Differential checks against btcd, libbitcoinkernel and the last release

btclib is compared with btcd's wire decoder over the fuzz corpora
(closes #2584), its script engine with libbitcoinkernel's (closes #2588), and
its parsers with the last release's (closes #2587).

### Property tests

Hypothesis strategies check the round trips of scripts, output scripts, headers,
blocks and the p2p payloads (issue #2582). The retarget, median time past and
timewarp bound are tested as properties (closes #2583).

### Vectors and cases

`script_tests.json` is Bitcoin Core's 6b8a5524f7 (closes #2609), and
rust-bitcoin's huge-witness transaction is a test and a fuzz seed
(closes #2591). NULLFAIL is tested on a signature or a key that cannot verify.

### Flaky tests

The test node starts again on fresh ports when one is taken (closes #2673). The
tapscript scaling tests take the best of more timed pairs (issue #2613). The
script strategies draw on PyPy (closes #2636).

### The refusal tests use the shared `assert_secret_free`

It is stricter than the local helper it replaces (closes #2659).

### CI

Workflows are linted with the kjanat actionlint fork; `release.yml` calls its
reusable workflows as `$/` (closes #1563). The review job names `cache-mode:
none` in place of `.github/actionlint.yaml` (closes #2633).

### `api-break.yml` labels a pull request that breaks the public API

It calls btclib-org/.github's `reusable-api-break.yml`
(issue btclib-org/.github#1674).

### Scripts and dependencies

`check_vendored_vectors.py` and `check_py_arm_authority.py` print a failed `gh`
call's stderr and retry a server error (closes #2600, closes #2605). uv.lock
moves bitcoin-core-rpc to 2026.10.8. Actions, hooks and the fuzz image move.

### Documents

An owner commits the uv export on a Dependabot uv pull request (closes #2596).
REPOSITORY.md records strict off on `main` (issue btclib-org/.github#1712). The
maintainer's bypass is everyday practice (issue btclib-org/.github#1695).
