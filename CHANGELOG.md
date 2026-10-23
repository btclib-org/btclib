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

## v2026.10.23

### btclib moves to `ecc`

btclib requires `ecc` 2026.10.23 and calls the bindings only through it (issue
btclib-org/ecc#306, closes #2724, closes #2717, closes #2726).

### The `secp256k1` extra installs `ecc[secp256k1]`

btclib no longer imports `btclib_secp256k1`, and the script engine verifies
through `ecc`'s `dsa.verify_` and `ssa.verify_`.

### Taproot follows `ecc`'s names and refusals

`output_pubkey_from_merkle_root` and `_tweaked_pubkey` take `_var`. A point not
on the curve and a tweak that sums to infinity or zero raise `BTClibValueError`.

### Names that run in variable time take `_var`

`PubKeyData.point`, `assert_p2pk`, `is_p2pk`, `assert_p2ms`, `is_p2ms`,
`p2ms_m_and_keys`, `MuHash3072.digest` and `CoinStats.digest`, with no alias
(closes #2687).

### `Block.assert_valid_contextual` checks the height-dependent rules

It asks what Core's `ContextualCheckBlockHeader` and `ContextualCheckBlock`
ask, the timewarp rule apart, and `BlockContext` takes a `ConsensusParams`
(issue #2705).

### `btclib.p2p` holds the message start

`btclib.p2p.magic` holds Core's message start per network, and btclib no longer
depends on bitcoin-core-rpc (issue #2707).

### `btclib.p2p.headers_sync` is Core's low-work headers sync

With `consensus.HEADERS_SYNC_PARAMS`, Core's `HeadersSyncParams` per network
(issue #2706).

### Electrum reads balances

The codec asks for a script hash's balance, singly or in a batch (issue
btclib-org/btclib-wallet#458).

### Tests

The `sig_ops` boundaries are tested (closes #2775), and so is each field of a
payment (closes #2704). Feature data of length 253 is drawn every time
(closes #2698).

### Tapscript ratio tests

They time sixteen small runs against one large (closes #2613).

### Secret-free refusals

`assert_secret_free` finds a secret printed in groups (issue
btclib-org/.github#1697).

### Test packages

`tests/ecc/` is `tests/schemes/`: a test package named `ecc` shadows the import
package.

### Dependencies

GitPython is 3.2.1 (issue btclib-org/.github#1835) and virtualenv 21.14.13
(issues btclib-org/.github#1824 and btclib-org/.github#1844) in `uv.lock`, with
the CA bundle at 2026.10.19. The build backend may be uv_build 0.13.

### CI

The py-arm-authority workflow is retired, btclib holding no arm.
`claude-review.yml` declines zizmor's dangerous-triggers (issue
btclib-org/.github#1813).

### Tooling moves off the compromised emSign roots

pypi-publish is v1.14.3 (GHSA-5xjx-3w67-w9x9) and uv-pre-commit 0.13.5.
`required-version` is `>=0.13.4`, which refuses a uv that trusts the
compromised emSign root (GHSA-hq85-5cpj-mr62; issue btclib-org/.github#1844).

### Documents

CONTRIBUTING.md states the `_var` criterion once, as `ecc`'s does
(issue #2687).

### AGENTS.md replaces CLAUDE.md

Instructions AGENTS.md does not hold move to CONTRIBUTING.md (issue
btclib-org/.github#1808).
