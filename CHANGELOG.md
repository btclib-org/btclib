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

## v2026.10.28

### No block version floor below the BIP34, BIP66 and BIP65 heights

`BlockContext.min_version` is `None` there, and `Block.assert_valid_contextual`
accepts any version, as Core does (closes #2833).

### BIP54

An `assert_bip54_*` function per rule, in `tx_context` and `header_context`,
each leaving activation to the caller, held to bip-0054's vectors
(closes #2799).

### Tapscript signature checks

A refused `OP_CHECKSIG` or `OP_CHECKSIGADD` leaves its operands on the stack,
and `OP_CHECKSIG` or `OP_CHECKSIGVERIFY` on a stack of fewer than two elements
names its op code (closes #2800).

### Stack size

A `STACK_SIZE` refusal raised while a script runs names the command after
which the stack and the altstack together are over `MAX_STACK_SIZE`, and the
legacy engine does not size the stack a script starts on (closes #2801).

### A step callback for the script engine

`verify_input` takes an optional `step` callback, called before each command
and once more where the script stops (closes #2803).

### Network hrp

`Network.assert_valid` refuses an hrp `bech32.encode` refuses, through
`bech32.assert_valid_hrp` (closes #2822).

### Refusal messages

`assert_p2tr` names the op code it read against OP_1, for a first byte other
than OP_1 (closes #2820), and `base58.decode` refuses a bad checksum quoting
neither checksum (closes #2727).

### Parse readers

The `utils.py` docstring names the readers that leave trailing octets
(closes #2790).

### Threshold page

`ScriptPubKey.p2ms` links ecc's where-the-threshold-lives page, and the docs
drop their copy (closes #2784).

### Fuzzing

`fuzz_interpreter` runs `eval_script` under ALL_FLAGS and NO_FLAGS
(closes #2787), and `fuzz_bip324` fuzzes `p2p.bip324`'s contents parser and
packet cipher (closes #2781).

### btcd oracle

`fuzz/btcd_decode` is at btcd wire v2.0.2 and golang.org/x/crypto v0.58.0
(closes #2797).

### Kernel differential

The free tapleaf runs the drawn script (closes #2802), and the `step` frames
are compared with the kernel's tracer where the kernel has one
(bitcoin/bitcoin#35641).

### Script tests

A pre-BIP66 mainnet signature whose DER s reads as negative is tested
(closes #2804), and OP_PICK and OP_ROLL are timed in a tapleaf (closes #2788).

### Vendored data

`script_tests.json` is Core's at 5a4cd705 (closes #2750), and the
libsecp256k1 symbol pin is upstream's 32099110d63a (closes #2729).

### Release verification

SECURITY.md's and RELEASING.md's verify commands compare the repository's id,
which a rename keeps (closes #2773).

### btclib requires ecc 2026.10.28

SECURITY.md links ecc's lines at its v2026.10.28 tag, where `musig2.py`'s and
`dh.py`'s cited lines sit, and the suite reads them from the installed ecc
(closes #2851).

### Pinned workflow calls

Every call of a btclib-org/.github reusable workflow names a tagged commit
(issue btclib-org/.github#1870).

### uv_build

The check-sdist hook's uv_build is `<0.14`, as `[build-system]` is
(closes #2764).

### Dependencies

`uv.lock` moves hypothesis, ruff and uv-build, the pre-commit hook pins move
forward, and the btclib-org/.github calls move to v2026.10.26.

### CONTRIBUTING.md

It says that development is LLM-based and a contribution must be understood
(issue btclib-org/.github#1846), and points the deprecation-window rule to
section 12 (closes #2844).

### Session hazards

CONTRIBUTING.md states the mutation-run, `VIRTUAL_ENV`, unsafe-fix and RUF100
hazards (closes #2835).

### Dependabot

CONTRIBUTING.md says that a pull request moving uv_build's range moves the
check-sdist hook by hand (closes #2809), and `dependabot.yml` names the
`uv.lock` exception (issue btclib-org/.github#1818).

### RELEASING.md

It says to open the next cycle once `version-check` is green and to rebuild a
re-pushed tag's docs by hand (closes #2834), and lists bitcoin-core-rpc among
btclib's dependents.

### REVIEWING.md

It takes the shared part of btclib-org/.github 72e0222 (issue
btclib-org/.github#1904).

### Comments

`.pre-commit-config.yaml` says how a zizmor finding is answered (issue
btclib-org/.github#1813), and an ignore whose reason was false goes
(closes #2794).
