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

- [v2026.11.10](./changelog/v2026.11.10.md)
- [v2026.11.7](./changelog/v2026.11.7.md)
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

## v2026.11.12

### Headers

`Headers.parse` reads the transaction count after each header and ignores it,
as Core does, and the keyword-only `round_trip=True` refuses any count but
zero (closes #2992).

### Signature hashes

`sig_hash.from_tx` refuses a prevout, bare or wrapped in p2sh, that is a
witness v0 program of neither 20 nor 32 bytes (closes #2997).

### Script refusals

`script.read_op_code` refuses a negative start offset, and `read_push_data` an
op code outside 0 to 78 (closes #3034). The op count refusal names the bound
and not the count (closes #3037).

### Script engine type refusals

The script engine's counts and readers refuse a non-integer by its type with
`BTClibTypeError` before they compare it (closes #3023).

### Other type refusals

`op_int`, `push_int`, the signature hashes, `bms.Sig` and `build_coinbase`
refuse a non-integer by its type before they compare it (closes #3008).

### Script engine tests

The int refusals are held in one table (closes #3039), every walk over a
script runs with the checked readers refused (closes #3046), and the script
mutation profile runs that table (closes #3047).

### Test harness

A run that leaves `.github/scripts` unmeasured is refused (closes #3040), and a
run from `tests/` is asserted to reach the tree holding the conftest (issue
btclib-org/bip39-slip39#235).

### Shared tests

The shared `assert_secret_free` and its tests are taken (issue
btclib-org/.github#1950).

### Test prose

The shape census says no private nested function (closes #2987), the citations
docstring drops a stale example (closes #2955), and the integration tests name
no Core 31 release where the pin has moved on (closes #2894).

### btcd oracle

An addrv2 entry of a known network with the wrong length counts under a rule
of its own (closes #3024).

### Vendored vectors

`check_vendored_vectors.py` takes only an issue titled exactly as searched
(issue btclib-org/.github#2152) and reads every issue its title search answers
(issue btclib-org/.github#2185).

### Workflows

The workflows call btclib-org/.github's reusable workflows at its v2026.11.10
tag, and the actions and the pre-commit hooks move.

### bestpractices.dev

The tree holds its bestpractices.dev answers (issue btclib-org/.github#2153),
corrected (issue btclib-org/.github#2159).

### Shared files

RELEASING.md and CONTRIBUTING.md take btclib-org/.github's shared part again
(issue btclib-org/.github#2107) (issue btclib-org/.github#2145), and comments
and documents name the organization's standard as its section 11 asks.

### Documentation build

`docs/source/conf.py` carries section 14's RootFileLinks part verbatim (issue
btclib-org/.github#2166).

### Docs checker

CONTRIBUTING.md's setup of the docs checker stops at the first step that fails
(issue btclib-org/.github#2015).

### CONTRIBUTING.md and SECURITY.md

CONTRIBUTING.md states when fuzz and kernel-differential run (closes #2858),
and SECURITY.md drops the unscripted cost figure of an unblinded `mod_inv`
(closes #2886).
