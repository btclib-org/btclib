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

## v2026.11.2

### Wallet-only code leaves btclib

`btclib.exceptions` drops the exceptions only btclib-wallet raises, and
`btclib.electrum` goes, with its tests and fuzz harness; btclib-wallet declares
them (closes #2709).

### btclib.alias

`btclib.alias` imports `BinaryData`, `Integer`, `Octets`, `Point` and `String`
from `ecc.alias`, and no longer defines the names ecc defines (closes #2710).

### Networks

The address, WIF and xkey-version decoders take an optional `Network`, and
accept only its prefixes, hrp and versions, so an application decodes another
chain's addresses with a `Network` it built (closes #2714).

### btclib.testing

`btclib.testing` ships the blocks btclib-wallet's tests read and, under the new
`testing` extra, the hypothesis strategies (issue #2708).

### Utreexo

`btclib.utreexo` is a roots-only Utreexo accumulator, checked against
rustreexo (issue #2590).

### Core v32.1

`btclib.consensus` moves to Core v32.1, and `integration-bitcoind.yml` to
bitcoind 32.1 (closes #2850, closes #2845).

### Block

`Block.assert_valid_contextual_block` checks a block's contextual rules without
its header's (closes #2836).

### Refusals

`verify_input` refuses an index naming no input (closes #2672), and
`var_int.parse`, `var_int.serialize` and `obfuscation.obfuscate` describe a
value `str()` cannot write instead of raising `ValueError` (closes #2863).

### Segwit refusals

`assert_p2wpkh` and `assert_p2wsh` name the witness version op code in hex
(closes #2842), and a test pins the refusal of a 35-byte script opening with
OP_0 0x20 (closes #2890).

### OpenTimestamps

The suite replays OpenTimestamps proofs against btclib's block headers
(closes #2742).

### Vendored data

python-bitcoinlib's licence ships beside the vectors vendored from it
(closes #2760).

### pip commands

The docstrings of `btclib.p2p.bip324` and `btclib.testing.strategies` render
their `pip install` commands with straight quotes, and a test refuses one in
single backticks (closes #2872).

### Tests

A witness sig-op count row covers an empty script_sig spending P2SH
(closes #2859), and the tapscript script ratio test is bounded at 900 s
(closes #2868).

### Mutation

The low-work headers sync is mutated in a scope of its own (closes #2832).

### Shebang hooks

`check-executables-have-shebangs` runs (issue #2852), and so does its converse
once `fuzz/btcd_oracle.py` has no shebang (closes #2877).

### bip32_descriptors

The prose names `bip32_descriptors` for BIP32 and descriptors (closes #2882).

### Repository

SECURITY.md links what changed since the security review (issue
btclib-org/.github#1795), and the dependency groups' comments say `uv_build`
carries a ceiling (closes btclib-org/.github#1848).

### CONTRIBUTING.md

Its shared part matches btclib-org/.github's: a comment's word limits, the
`Sign-off` check and `--admin`, the advisory exception, and the reopen's merge.

### Dependencies

The dev-tooling group moves bitcoin-core-rpc, coverage, hypothesis and ruff in
`uv.lock`.
