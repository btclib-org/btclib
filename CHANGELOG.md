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

### `dependabot.yml` does not say that every workflow passes `--locked`

- **`.github/dependabot.yml` says the workflows install from `uv.lock` with
  `--locked`, bar the exceptions `CONTRIBUTING.md` lists** (issue
  btclib-org/.github#1538).

## v2026.10.3

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

### `eval_script` returns the stack where Core's `EvalScript` stops

- **`eval_script(script_bytes, stack, flags)` returns the stack and the error**
  (closes #2489). `verify_script` stops on that stack, a `*VERIFY` op code fails
  at its own index, and `op_checkmultisigverify` goes (RELEASE_NOTES.md).

### `STRICTENC` refuses hash type 0 as `SIG_HASHTYPE`

- **A legacy or segwit v0 signature ending in `00` fails with `SIG_HASHTYPE`**
  (closes #2510), Core's `IsDefinedHashtypeSignature`. `00` is
  SIGHASH_DEFAULT, taproot's alone.

### A tapscript op code fails at its own index

- **A tapscript `*VERIFY` op code and `OP_CHECKSIGADD` run as one op code**
  (closes #2509) (closes #2513). A failure inside one has that op code's own
  `ScriptError.index`; `op_equalverify` and its kin go (RELEASE_NOTES.md).

### `btclib.p2p.bip324` is BIP324's v2 transport cipher

- **`btclib.p2p.bip324` encrypts and decrypts BIP324 packets** (issue #2474)
  with `cryptography`, behind `pip install "btclib[bip324]"`, and passes the
  BIP324 packet vectors. A btclib without the extra answers as before.
