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

## v2026.11.13

### btclib requires ecc 2026.11.11

The floor and the lock move to the release `SECURITY.md` cites, whose DER
size reader prints no refused size (closes #3065).

### `ellswift.xdh` refuses a non-integer party

A `bool` or a `float` party is refused with `BTClibTypeError` (closes #3073).

### The coercions read each argument by its real type

`btclib.utils` and `message_verify` copy a bytes or bytearray subclass by its
base type and test types with `type()` (closes #3076) (closes #3078)
(closes #3081).

### Workflows

The workflows call btclib-org/.github's reusable workflows at its v2026.11.12
tag, and the dev tooling moves.

### Sourcery

Every Sourcery rule is on but dont-import-test-modules, the code rewritten
keeping behaviour (issue btclib-org/.github#2162, btclib-org/.github#2190).

### bestpractices.dev

The answers are re-measured at v2026.11.12 (closes #3062), cite
main-self-merge by id, and record a save nobody can make as owed (issue
btclib-org/.github#2214, btclib-org/.github#2205).
