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

## v2026.10.30

### btclib requires ecc 2026.10.30

SECURITY.md links ecc's lines at its v2026.10.30 tag, where two of `curve.py`'s
cited lines moved, and the suite reads them from the installed ecc
(closes #2864).

### Witness

A `Witness` holds its serialization, and a parsed one builds its stack on
first access (closes #2748).

### Taproot

`tree_helper` refuses an odd leaf version and 0x50 (closes #2766), and
`taproot.parse` reads 0xff as `UNKNOWN_OP_CODE_255`, leaving its refusal to
execution (closes #2731).

### Taproot helpers

`taproot.tree_from_weights` builds the Huffman tree of weighted leaves, and
`taproot.tap_tweak`, `taproot.merkle_root_from_control_block` and
`sig_ops.last_push` are public (closes #2703, issue #2711).

### MINIMALIF_ALL

`ScriptFlag.MINIMALIF_ALL`, off by default, applies MINIMALIF to legacy and
P2SH scripts too (closes #2769).

### Segwit addresses

`witness_from_address` holds an address to BIP350's constant itself, whichever
constants the codec accepts (issue #2725).

### Refusals

`b32.power_of_2_base_conversion` refuses a width above 64 (closes #2720), and
`var_int.serialize` refuses a negative integer without printing it
(closes #2645).

### Release diff

`release-diff.yml` installs `cryptography` on both sides, so the report
compares `btclib.p2p.bip324`'s entry point, and it lists an entry point absent
from both (closes #2831).

### Dependencies

`uv.lock` moves uv-build, astral-sh/setup-uv moves to 10.3.2, and the
btclib-org/.github calls move to v2026.10.29.

### REVIEWING.md

It takes .github's sentence opening the own part's questions (issue
btclib-org/.github#1919).
