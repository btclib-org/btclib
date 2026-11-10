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

## v2026.11.10

### btclib requires ecc 2026.11.8

btclib imports ecc's schemes from ecc's top level, as ecc 2026.11.8 removes
`ecc.ecc`, and the ecc floor is 2026.11.8 (closes #2954). An earlier change
raised it to 2026.11.7 (closes #2932).

### btclib.ecc leaves

`bms` and `ellswift` are top-level modules, and `btclib.ecc` goes
(closes #2937).

### btclib.base58 and btclib.bech32 leave

The codecs come from the new `base58-bech32` dependency, and `btclib.base58`
and `btclib.bech32` go (issue #2712) (closes #2725).

### Bitcoin Core v32.1

`policy.validate_inputs_standardness` replaces `are_inputs_standard`
(closes #2939), `MESSAGE_IDS` takes `feature` (closes #2938), `PROTOCOL_VERSION`
moves (closes #2995), and Core is cited at v32.1 (issue #2894).

### Signature hashes

`sig_hash.taproot` takes BIP460's aggregation mode as `agg_mode`
(closes #2774), and `sig_hash.from_tx` refuses a prevout of a witness program
it has no rule for (closes #2989).

### bms

`bms.sign` takes the WIF that `bms.gen_keys` returns (closes #2936).

### Refused values

A refusal describes an int a key could stand in for by its sign and bit
length, and any other such value by its type and its length where it has one
(closes #2998) (closes #3001) (closes #3002) (closes #3003) (closes #3009).

### Refused fields

A refused hash, root, field, count, key, push, prefix or xkey version is named
by which one it is, its size or its bound (closes #2975) (closes #2979)
(closes #2994) (closes #3005).

### Refused names

A refused name is quoted only up to 16 characters (closes #3014) (closes #3015).

### Reprs

`PrvKeyData`'s repr hides its key, and `PubKeyData`'s and `ScriptPubKey`'s
show `...` for a field without the shape it takes (closes #3006)
(closes #3017).

### Type refusals

`b32.bytes_from_witness_program` (closes #2965) and `network`'s xkey version
lookups (closes #2985) refuse a wrong type with `BTClibTypeError`.

### Address refusals

`ScriptPubKey.from_address`, given a network, refuses a string that starts
as a bech32 address and neither bech32 nor base58 reads with a new exception
with no chain of its own, the same on PyPy as on CPython (closes #3033).

### Name contract tests

`name_contract_test.py` holds `validate_` to `None` (closes #2953), keeps each
definition (closes #2962), and reads an `async def` (closes #2964), a class
body (closes #2966) (closes #2973) (closes #2974).

### Vocabulary walks

The vocabulary walks skip a function nested in a function (closes #2978).

### Public parameter tests

`public_parameter_test.py` holds the `_var` functions to ecc's `Public` rule
(closes #2928) and lists each definition (closes #2956).

### Tests

The coverage floor measures `.github/scripts` (closes #2906), Core's script
vectors move to PR bitcoin/bitcoin#36458 (closes #2923), the libsecp256k1
symbol pin moves (closes #2904), and `fuzz_bip324` rekeys (closes #2892).

### README

The README links its own files absolutely (issue btclib-org/.github#1851) and
ends with its status badges (issue btclib-org/.github#1856).

### Documentation

The docs read ecc's inventory at the version `uv.lock` pins (closes #2968),
and prose that describes a past tree is corrected (closes #2952).

### Workflows

`release.yml`'s post-publish job is `published`, as the shared RELEASING.md
names it (closes #2925).

### Repository

CONTRIBUTING.md takes btclib-org/.github's shared part (issue
btclib-org/.github#2088), and comments and documents name the organization's
standard as its section 11 asks.
