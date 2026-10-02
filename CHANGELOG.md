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

## v2026.10 (work in progress, not released yet)

### `Network.from_dict` refuses a non-string network type

- **A non-string `network_type` leaves as `BTClibTypeError`** (closes #2434).
  An array or an object leaked the built-in `TypeError`; a number, a bool or
  `null` left as `BTClibValueError`, which `except ValueError` no longer catches.

### `CLAUDE.md`'s primary-checkout section is the organization's shared text

The section is the same in every repository, and the rest of the file
drops what `CONTRIBUTING.md`, the standard and the tests already state
(issue btclib-org/.github#1494).

### `release.yml` audits the lock before it publishes

- **The `audit` job runs `uv audit` over what the wheel declares**, by calling
  btclib-org/.github's `reusable-audit.yml`, and both publish jobs wait for
  its success (closes btclib-org/.github#1466).

### `btclib.script.solver` is Bitcoin Core's `Solver`

- **`solver` and `get_txn_output_type`** (closes #2456) answer Core's eleven
  types and solutions, read at bitcoin/bitcoin@9be056a8a7 (v31.1).
  `type_and_payload` stays narrower (issue #211).

### `generate_sbom.py` is btclib-org/.github's

- **The `dist` job writes the bill of materials with btclib-org/.github's
  `generate_sbom.py`**, served from `main`, and the tree keeps no copy of it
  (issue btclib-org/.github#1478).

### `Dependency review` is a required check

- **`REPOSITORY.md` reads `lint / Dependency review` back with the other
  required checks** (issue btclib-org/.github#1465).

### `btclib.policy` is Bitcoin Core's relay policy

- **`assert_standard_tx`, `are_inputs_standard`, `is_witness_standard`,
  `spends_non_anchor_witness_prog`, `is_dust`, `dust_outputs`, `virtual_size`
  and `sig_ops_adjusted_weight`** (closes #2463) are Core's `policy.{h,cpp}`.

### `[tool.uv] required-version` is `>=0.12.18`

- **`required-version` reads `>=0.12.18`, not `>=0.12.19`** (issue
  btclib-org/.github#1482): the Dependabot service refused `0.12.19` with
  `tool_version_not_supported`.

### `SECURITY.md` names the latest security review

`SECURITY.md` gives the date of the latest security review and links the issue
that records it (issue btclib-org/.github#1362).

### A `Signed-off-by:` trailer on every commit of a pull request

*Pull requests* says every commit of a pull request carries a
`Signed-off-by:` trailer, and how to add it (issue
btclib-org/.github#1467).

### The primary-checkout section uses one form for the checkout

- **The section writes the checkout as `"${checkout:?}"` throughout, says
  what `<scratchpad>` is and names the pull** (issue
  btclib-org/.github#1500).

### The `python` inventory has a copy kept in the tree

- **`docs/source/_inventories/python.inv` is read when `docs.python.org`
  fails** (issue btclib-org/.github#1508), so an outage of that site no
  longer fails the `-n -W` docs build.

### `public-api` is red for a break `RELEASE_NOTES.md` does not name

`RELEASING.md` says that a red `public-api` means `RELEASE_NOTES.md`
misses a name (issue btclib-org/.github#1517).

### The release's attestation is signed by `reusable-build.yml`, at SLSA Build L3

`release.yml` calls `reusable-build.yml`, which signs the files before the
publish jobs wait for approval (issue btclib-org/.github#1506).

### The verification command pins the tag for every signer

SECURITY.md and RELEASING.md said a release signed by `reusable-attest.yml`
took no `--source-ref`; it takes the tag (closes #2447).

### CONTRIBUTING.md lists the jobs that do not install with `--locked`

CONTRIBUTING.md and `ASSURANCE_CASE.md` no longer say that every job passes
`--locked`: they list the exceptions, none of which installs the project's
dependencies unpinned in the job that builds the published files (closes #2440).

### The weekly vendored-vectors check compares bytes

`check_vendored_vectors.py` hashes each vendored file against the blob
`tests/_data/README.md` records and compares that blob with upstream's at the
pinned commit, failing the run on a mismatch (closes #2439).

### While the bot review is off, `CONTRIBUTING.md` says what stands in for the ack

*The review* says there is no ack of record while `claude-review.yml` is
off, and that a local review of a named sha by a reviewer other than the
author stands in for it (issue btclib-org/.github#1527) (closes #2445).

## v2026.9.30

### The libsecp256k1 symbol pin is upstream's tip again

- **`tests/_data/README.md` pins `b819a790f061`** (closes #2405), the latest
  upstream commit touching `src`; the re-extracted symbol list is
  byte-identical, so only the pin and its dates move.

### `btclib` stops re-exporting the names of `btclib_ecc` and `bitcoin_core_rpc`

`btclib.curves`, `btclib.kdf`, `btclib.number_theory`, `btclib.ecc`'s modules
but `bms` and `ellswift`, and every name of `btclib_ecc` or `bitcoin_core_rpc`
that another module bound are gone (closes #2404).

### `[tool.uv]`'s floor rises to the `uv` `dependabot-core` bundles

`required-version` reads `>=0.12.19`, the pin in `dependabot-core`'s
`uv/Dockerfile`: the old floor admitted a `uv` older than the one the updater
writes `uv.lock` with (issue btclib-org/.github#1438).

### `.clusterfuzzlite/.python-version` pins the fuzz image's interpreter

`.clusterfuzzlite/.python-version` names `3.11`, the fuzz image's interpreter,
so that the Dependency Graph's pip job there reads it rather than a root pin
Dependabot does not support yet (closes btclib-org/.github#1436).

### `pypi-install.yml` installs the version the release published

The install names `btclib==<version>` from the tag `release.yml` passes,
where a bare name let a lagging index serve the release before it
(issue btclib-org/.github#1456).

### `CONTRIBUTING.md` points a newcomer at `good first issue`

An issue carrying the label is small and self-contained: *The issue
tracker* says so, and links the organization-wide search for the open
ones (issue btclib-org/.github#1362).

### The OpenSSF Baseline badge

`README.md`'s badge row ends with the OpenSSF Baseline badge, beside the
Best Practices badge, section 2 of the organization standard admitting it
on the same property (issue btclib-org/.github#1460).

### `btclib.block.proof_of_work` gains `permitted_difficulty_transition`

A headers-only sync can check a retarget without the two timestamps
`next_bits` needs, matching Core's `PermittedDifficultyTransition`
(closes #2418).

### `pypi-install.yml` retries the install of the version the release published

Both install jobs, the `[secp256k1]` one included, install through
btclib-org/.github's `install_published_release.py`, which retries only while
the installer says the pin is not resolvable (issue btclib-org/.github#1458).

### The release's attestation bundle is attached as `*.intoto.jsonl`

`RELEASING.md`'s commands and `SECURITY.md`'s verification name the bundle
`<tag>.intoto.jsonl`, the name `reusable-github-release.yml` attaches it under
(issue btclib-org/.github#1468).

### `Block.parse` defers each transaction's own checks to `assert_valid_structure`

Each transaction now parses unchecked, and `assert_valid_structure` validates
it in its own pass rather than `Block.parse` checking it alone as it reads it
off the wire (closes #2422).

### `Tx.assert_valid` reports a multi-violation transaction under Core's own rule

The coinbase script length / null-prevout check now runs last in
`assert_valid`, and each output's value and the running total are checked in
one pass, matching `CheckTransaction`'s own order (closes #2417).

### `codeql.yml`'s aggregate runs `check_run_jobs.py`

The aggregate's step runs `check_run_jobs.py`, which reads the run's jobs
listing again up to a deadline while a row of `analyze` is unfinished
(issue btclib-org/.github#1463).

### `Tx.assert_valid` refuses an oversize transaction

The stripped size, weighed `WITNESS_SCALE_FACTOR` times against
`MAX_BLOCK_WEIGHT` -- CheckTransaction's `bad-txns-oversize`, which nothing
here checked before (closes #2420).

### `assert_valid_structure` checks the merkle root right after proof-of-work

`assert_valid_structure` checks the merkle root right after the header and its
proof-of-work, `CheckBlock`'s own position for it, rather than after every
transaction and the sigop bound (closes #2425).

### An empty transaction list's merkle root is the all-zero hash, not a raise

`merkle_root_and_mutated_from_hashes` now answers Core's own
`ComputeMerkleRoot([])`, so `assert_valid_length` refuses the empty list
itself, `bad-blk-length`'s own first question (closes #2427).

### `generate_sbom.py` carries a not-affected list into the bill of materials

- **`generate_sbom.py` reads `.github/vex.toml`**, where the tree lists the
  vulnerabilities its release is not affected by, into the document's
  `vulnerabilities`; no list, no key (issue btclib-org/.github#1469).

### `SECURITY.md` promises a response time

`SECURITY.md` says a report is acknowledged within 7 days, and a fix or a
published advisory within 90 (issue btclib-org/.github#1460).

### `urllib3` moves to 2.8.0 in the lock

- **`uv.lock` pins `urllib3` 2.8.0**, past GHSA-gh4c-6fx4-qh6g,
  GHSA-vxq7-64xx-v4gw and GHSA-8988-9cw3-xx77; it reaches the dev group
  alone, through `twine`, `sphinx` and `pyroma`, never the wheel.
