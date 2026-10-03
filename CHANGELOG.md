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

Only v2026.8.7 and what follows it are recorded in the changelog at all.
The releases before it were documented at release-notes length in the
first place, and are still in [RELEASE_NOTES.md](./RELEASE_NOTES.md)
rather than duplicated here.

This file carries the cycle in progress and the most recent release;
every release before those has a file of its own under `changelog/`,
holding that release's section and nothing of any other. Past a size
ceiling GitHub's contents API answers a file with an empty `content` at
HTTP 200, which reads as an empty file rather than as an error, and one
file per release is what keeps each of them under it.

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

## v2026.11 (work in progress, not released yet)

## v2026.10.4

### `dependabot.yml` does not say that every workflow passes `--locked`

- **`.github/dependabot.yml` says the workflows install from `uv.lock` with
  `--locked`, bar the exceptions `CONTRIBUTING.md` lists** (issue
  btclib-org/.github#1538).

### `REPOSITORY.md` reads back the web sign-off setting

- **`REPOSITORY.md` reads `web_commit_signoff_required` back** (issue
  btclib-org/.github#1540): section 11 of the standard states the
  organization setting.

### The `Sign-off` check is required

`CONTRIBUTING.md`'s shared half says a pull request whose commits lack the
`Signed-off-by:` trailer cannot merge, and `REPOSITORY.md` lists
`lint / Sign-off` among the required checks (issue btclib-org/.github#1550).

### The ack of record is a bot's

`CONTRIBUTING.md`'s shared half says the ack of record is a bot's, and the
maintainer lands their own pull requests through the bypass (issue
btclib-org/.github#452).

### The bypass is for emergencies

`CONTRIBUTING.md`'s shared half, `REPOSITORY.md` and `RELEASING.md` say every
pull request, the maintainer's included, lands with an approving review from
somebody else, the bypass being for emergencies (issue btclib-org/.github#1362).

### `REPOSITORY.md` reads the review switch as the organization's

`REPOSITORY.md` states only that this repository sets no
`CLAUDE_REVIEW_ENABLED` of its own (issue btclib-org/.github#1560).

### `REVIEWING.md` names the approval

`REVIEWING.md` says a pull request lands on the ack of record and an approving
review from somebody other than its author (issue btclib-org/.github#1362).

### Earlier entries on how a pull request lands

Entries above that have the maintainer landing without another person's
approval describe the rule before issue btclib-org/.github#1362 (issue
btclib-org/.github#1569).

### btclib requires btclib-secp256k1 0.8.0.10

btclib-secp256k1 0.8.0.10 fixes GHSA-8h6f-34jj-7p6c, an invalid-curve oracle
in `silentpayments.scan_outputs`, which btclib does not call. The `secp256k1`
extra and the `bindings` group require it.

### Tapscript validation time is linear in the size of the script

Each op code scanned every open `OP_IF`, and each signature check hashed the
whole leaf, the annex and the SIGHASH_SINGLE output. Branches are a depth and a
position, and the hashes are kept per input (GHSA-9fr5-46w5-5f9r).
