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

### `b58.prv_key_data_from_wif` does not quote the checksum

- **A WIF with a bad checksum is refused as `not a WIF (invalid checksum)`**
  (closes #2436). It quoted the checksum the key hashes to, which confirms a
  guess at a WIF mistyped in its last characters. Addresses still quote both.

### `ellswift.xdh` does not quote a bad `party`

- **The refusal of a `party` outside 0 and 1 does not print it** (closes #2435),
  so a swapped `prv_key` stays out of the message. `SECURITY.md` cites
  `xdh`'s delegated return by its text (closes #2437).

### `electrum.decode_response` refuses a nesting too deep to read

- **The line leaves as `BTClibValueError`** (closes #2432). `RecursionError`
  escaped, and `except BTClibException` does not catch it.

### `electrum.decode_response` refuses `NaN` and `Infinity`

- **`estimate_fee_response` takes a finite rate of at least 0, or `-1`**
  (closes #2433). It returned `nan`, `inf` and `-5`.

### `next_bits_required` leaves the timewarp bound to `assert_not_timewarp`

- **`next_bits_required` returns the target and never raises the BIP94 bound**
  (closes #2465). `assert_not_timewarp` is that check, so a caller can order
  it after bad-diffbits and time-too-old, as Core does.

### The documents name btclib_ecc's code as btclib_ecc's

- **`README.md` lists the curve schemes under btclib_ecc** (closes #2444),
  `SECURITY.md` routes a report on them to its advisory page, and
  `ASSURANCE_CASE.md` says btclib reads no environment variable (closes #2441).

### A script refusal carries Core's code

- **A script breaking two rules fails with the code Core gives it** (closes
  #2481): number operands follow the stack depth check, OP_CHECKSIGADD's number
  precedes its signature, OP_CHECKMULTISIG's dummy follows its signatures.

### `electrum.decode_response` refuses a line nested past 16 levels

- **A line nested deeper is refused before `json.loads` reads it**
  (closes #2498). From about 3000 levels it killed CPython 3.12 and 3.13 in
  a 512 KiB thread. The line is UTF-8 bytes; UTF-16, UTF-32 and `str` are refused.

### `bms.message_verify` is Bitcoin Core's `MessageVerify`

- **`message_verify` answers as Core's `verifymessage`** (closes #2487): p2pkh
  only, any first byte, canonical base64, one `MessageVerificationResult`
  member per answer. `verify` stays the Electrum and BIP137 scheme.

### `script_to_asm` renders a script as Core's `ScriptToAsmStr`

- **`script_to_asm(script, attempt_sighash_decode=False)` is Core's `asm`**
  (closes #2461): `0151` is `81`, and with `attempt_sighash_decode=True` a
  signature's hash type is `[ALL]`. `script_to_dict` keeps its own `asm`.

### `Tx.parse_without_witness` reads without the BIP144 marker

- **`Tx.parse_without_witness` reads `00 01` after the version as no input and
  one output** (closes #2462), Core's `TX_NO_WITNESS`. `Tx.parse` reads a marker
  and a flag. `check_validity=False` is what a transaction with no input needs.

### `Tx.parse` refuses a flag above 1 after no input

- **`Tx.parse` refuses `00` and a flag above 1 after the version** (closes
  #2503), Core's "Unknown transaction optional data". It read the flag as an
  output count. `Tx.parse_without_witness` does.

## v2026.10.2

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

### The release publishes the files the build job built

The publish jobs, `github-release` and `test.yml`'s `dist` job on a release
stop where the `dist` they download differs from the digests
`reusable-build.yml` outputs (closes #2449).

### CONTRIBUTING.md lists the fuzz build among the jobs without `--locked`

`fuzz.yml`'s ClusterFuzzLite build installs the exported lock with
`pip3 install --require-hashes`. The mypy hook's comment gives its reason
for `--locked` without calling it universal (closes #2484).

### btclib requires btclib-ecc 2026.10.2

btclib-ecc 2026.10.2 fixes GHSA-r5pw-9wrg-m3mj and GHSA-m38m-987v-j55h. The
tweak's bindings arm says `x-coordinate not in 0..p-1` for x >= p, where it
said `invalid x-coordinate: '...'`, and no taproot message quotes the x.
