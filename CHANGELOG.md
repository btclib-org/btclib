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

- [v2026.11.13](./changelog/v2026.11.13.md)
- [v2026.11.12](./changelog/v2026.11.12.md)
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

## v2026.11.14

### btclib requires base58-bech32 2026.11.12

The floor moves to the release whose refusals print no int passed as a
conversion width or value, the lock moves with it, and the suite matches its
refusal texts (closes #3086).

### Type tests read a value's own class

Every type test of `src/btclib` asks `utils._has_type`, so an object claiming a
type it is not is refused or read as the object it is (closes #3080).

### Type test docstrings

`_has_type`'s says a dataclass's generated `__eq__` is outside its rule
(closes #3091), and `assert_type`'s points to it (issue #3090).

### Script flags

`to_script_flags` refuses a value that is not an iterable, and a name that is
not a str, with `BTClibTypeError` (closes #3088).

### `TxOut.to_dict`

A network that is neither a str nor a `Network` is refused with
`BTClibTypeError` (closes #3093).

### `message_verify`

A strided memoryview, or one whose format is not `"B"`, is refused as the
address or the signature (closes #3085).

### Lock

soupsieve, which furo brings into the dev and docs groups, is relocked past
GHSA-mmhr-3c5m-f64f (closes #3094).

### Repository

AGENTS.md carries Code Review Rules and points at REVIEWING.md once (issue
btclib-org/.github#2009), and REPOSITORY.md says main-self-merge holds the
maintainer's standing bypass (issue btclib-org/.github#2212).

### pre-commit

prettier leaves `.pre-commit-config.yaml` to pre-commit.ci (issue
btclib-org/.github#2038).

### bestpractices.dev

The answers are re-measured at v2026.11.13, and osps_qa_07_01 says how long
the maintainer's bypass stands (issue btclib-org/.github#2212).
