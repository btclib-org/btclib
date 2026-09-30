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

## v2026.9.29

### `requires-python` moves to `>=3.11`

3.10 reaches end of life on 2026-10-31. The classifiers and every
workflow matrix move with the floor.

### The attestation's signer is `reusable-attest.yml` from v2026.9.24 on

- **`RELEASING.md`, `SECURITY.md` and `sdist-rebuild.yml` name the
  called workflow as the signer**, the path of `release.yml` kept for
  v2026.9.13 and earlier, which it signed (issue btclib-org/.github#1301).

### The wallet side leaves btclib for `btclib-wallet`

- **The row-5 modules of issue #2129 are `btclib_wallet`'s, under the
  same names** (issue #2129): RELEASE_NOTES.md lists each, and the
  exception classes they raise stay in `btclib.exceptions`.

### `keywords` and the GitHub topics name what btclib still holds

`bip32`, `bip39`, `slip39`, `psbt`, `output-descriptors` and `hardware-wallet`
leave both lists, `mnemonic` and `bip44` leave `keywords`, and `rfc-6979`,
`merkle-proof` and `bitcoin-script` become topics (closes #2243).

### `sdist-rebuild.yml` stops passing `attest-signer`

The called workflow verifies against `reusable-attest.yml` alone, so the
input decides nothing (issue btclib-org/.github#1315).

### The suite the sdist ships runs from the unpacked sdist

`test.yml`'s `dist` job runs the suite from the sdist it built, unpacked,
where `pyproject.toml` is uv_build's normalized copy: the tests that copy
failed parse it with `tomllib` (closes #2252).

### `keywords` and the GitHub topics take `frost`, `bip324` and `bip158`

FROST threshold signatures, BIP324's ElligatorSwift and BIP158 compact block
filters are in btclib, and both lists name them (closes #2255).

### A private function's `_var` suffix states its timing, as a public one's does

`CONTRIBUTING.md` says so beside the convention, and `_mult_sec_var`
keeps its name (closes #2246).

### `btclib.alias` drops the type aliases only `btclib_wallet` used

`BIP44ScriptType`, `BlockCipherF`, `EmbeddedScriptType`, `KeyOrder`,
`MnemonicLang` and `ValidSigHashType`, which btclib-wallet defines itself,
and the unused `H160_Net` leave `btclib.alias` and `__all__` (closes #2244).

### `ARCHITECTURE.md` and `ASSURANCE_CASE.md` join the root

The architecture moves there from `CLAUDE.md` and `README.md`, which point
at it; the assurance case cites the tree for every claim (issue
btclib-org/.github#1321).

### More private helpers whose duration follows an operand gain `_var`

Private helpers in `curves.curve`, `curve_group`, `curve_group_2` and
`ecc.ellswift` that loop on a scalar's bits, call `pubkey_tweak_mul_sum`, or
wrap a `_var` function gain the suffix (closes #2259).

### `codeql-passed` and `test-passed` no longer skip while draft

A skipped required check reads as passing, so both aggregates now fail
a first step on `github.event.pull_request.draft` instead of skipping
on it (issue btclib-org/.github#1327).

### `.python-version` moves to 3.15, on its release candidate

The classifiers name 3.15, the platform sweeps and `pypi-install.yml` gain
`3.15` and `3.15t`, and `deps-latest.yml`'s upper end is 3.15 (issue
btclib-org/.github#1324).

### The rebuild of a release names the interpreter its tag pinned

`RELEASING.md`'s *Rebuild a release from its tag* reads it from the tag's
`.python-version`, not `main`'s (closes #2262). The workflow
`sdist-rebuild.yml` calls names one of its own (issue btclib-org/.github#1345).

### `sdist-rebuild.yml`'s comment names `setup-python`, not `python-version`

The comment above `uses:` named `python-version`, an input the called
workflow does not declare; it names `setup-python` and its `false` default
instead (issue btclib-org/.github#1346).

### `mult` of a point other than G is constant time on the bindings arm

So are `mult_pub_key`, `ecies.derive_keys` and `dh.diffie_hellman`, and
`_mult_sec_var` is `_mult_sec`: each calls the bindings' `ecdh.shared_point`,
the floor moving to the release adding it (closes #2257).

### pre-commit.ci skips `uv-lock`

Its image lacks the interpreter `.python-version` names, and the `lint`
workflow still runs the hook (issue btclib-org/.github#1348).

### `pedersen.commit` hands neither secret to `double_mult_var`

It sums a `mult` of each, where `double_mult_var`'s work followed the width
of both, and `rangeproof.rewind` rebuilds the commitment it checks the same
way (closes #2267).

### A drift line names both commits whole

`check_vendored_vectors.py` prints the pinned commit and upstream's tip as
full shas, in its output and in the tracking issue, so two commits alike in
their first twelve characters print as two (issue btclib-org/.github#1343).

### The rebuild of a release builds under the release's own uv

`RELEASING.md`'s *Rebuild a release from its tag* builds under the uv
the published wheel names and verifies the sdist first: a wheel that
disagrees stops the chain after it (issue btclib-org/btclib-node#1063).

### `RELEASING.md`'s environment reviewers are the organization's owners

`fametrano`, `giacomocaironi` and `pmazzocchi` are each a required
reviewer of the `pypi` and `testpypi` environments, and self-review
stays allowed (issue btclib-org/.github#1355).

### `CONTRIBUTING.md` and `README.md` link `GOVERNANCE.md` and `ROADMAP.md`

Both point a contributor at the organization's one copy of each, in
`btclib-org/.github` (issue btclib-org/.github#1359).

### The `_var` census names `ssa._assert_as_valid_` beside its `dsa` twin

`CONTRIBUTING.md` lists it among the functions that measure at the
floor and keep their plain name, at 1.07x (closes #2279).

### A zero scalar takes `mult`'s bindings arm like any other

The bindings multiply one in its place, and a Pedersen commitment's sum
crosses to them with a term at infinity too, so neither a commitment to
zero nor a range proof's zero digit takes the Python arithmetic (closes #2272).

### `pedersen.generator_from_seed` treats its seed and blinding factor as secrets

Its sums are the ones a Pedersen commitment makes, and the map forms
every candidate root before choosing one, as libsecp256k1-zkp does, at
the cost of the roots it does not keep (closes #2273).

### `btclib.ecc` imports nothing above the curve's layer, `bms` aside

`tagged_hash` and `reduce_to_hlen` are defined below `btclib.hashes`,
which names them still, and `ecc.bms` is imported on demand, so every
public import path resolves as before; a test holds it (issue #2282).

### The curve arithmetic and the schemes built on it are btclib_ecc's

`btclib.curves`, `number_theory`, `kdf` and `ecc` but `bms` bind that
package's objects again under the same paths, and the `secp256k1` extra
asks for its own; RELEASE_NOTES.md says what changes (issue #2282).

### `REVIEWING.md` lets a filed issue carry its fix

An issue filed from a review may now say the fix where one is known;
the filing bar stands as it was (issue btclib-org/.github#1378).

### `bech32._decode`'s HRP range matches BIP173's [33-126]

The check admitted characters 48..122 only; BIP173 puts the range at
33..126, so a correctly checksummed string with an HRP outside 48..122
was refused (closes #2287).

### `bech32.encode` validates the HRP before writing it

A mixed-case, empty, out-of-range or non-ascii HRP now raises
`BTClibValueError` or `BTClibTypeError`, rather than a string `decode`
refuses or a bare `UnicodeEncodeError` (closes #2286).

### `base58.decode` and `str_from_string` refuse a memoryview of the wrong shape

- **Both called `bytes()` on any memoryview directly, skipping
  `_assert_byte_shaped`** (closes #2295): `decode`'s length cap also
  counted a memoryview's elements, not its octets.

### `base58.encode` and `decode` docstrings state the length asymmetry

- **`encode` is uncapped and `decode` refuses past `MAX_LENGTH`
  characters** (closes #2296): a payload of roughly 80 bytes or more
  round-trips through neither on its own, and both docstrings now say so.

### `b58.prv_key_data_from_wif` and `h160_from_address` strip bytes input too

- **Both stripped whitespace only from a `str`** (closes #2297): both now
  coerce with `str_from_string(...).strip()` first, as
  `b32.witness_from_address` does.

### `decode_response` requires an integer id, and reads a null one's error first

`decode_response` requires `is_integer` on a reply's `id`, refusing `true` and
`1.0` for request id 1 (closes #2298), and reads a `null` id's `error` before
the id check, JSON-RPC 2.0's answer to an unparsable request (closes #2299).

### `valid_sats_amount` accepts the numeric string its comment admitted

The equality check after `int()` refused every `str` regardless of
value, `int("10") != "10"`, though a float of the same value passed; a
`str` is now exempt, refused instead for a `_` or a fraction (closes #2291).

### `valid_btc_amount` type-checks its `dust` threshold

A float `dust` tripped the `FloatOperation` trap around its own
comparison and leaked a bare `decimal.FloatOperation`; `dust` now has
to be a `Decimal`, matching `valid_sats_amount`'s own check (closes #2292).

### `valid_btc_amount` refuses digit grouping and a signed zero's sign

`Decimal(str(amount))` accepted Python's digit-grouping underscore, so
`"1_0"` read as ten BTC; a string amount carrying `_` is now refused,
and a zero result's sign is now cleared rather than kept (closes #2293).

### `var_bytes.parse` raises `BTClibValueError` for a truncated or a zero-size field

It raised `BTClibRuntimeError` for both, unlike `var_int.parse` and
`utils.read_exactly`'s `BTClibValueError` for the same truncation, and
the two-class catches this forced are narrowed (closes #2289).

### `test_p2wsh_p2sh` and `test_hash160_hash256` assert what they compute

The addresses are Bitcoin Core's `deriveaddresses` and the digests hashlib's,
where both tests called the function and discarded its answer (closes #2302).

### `check_vendored_vectors` does not read a removed pin as changed content

A pin whose file upstream deleted or renamed is reported as the commit that
removed it, which the report says may be a deletion or a rename; "no commit"
names a path the branch walked never held (closes #2312).

### `hashes.merkle_root`'s docstring says it hashes each item first

The docstrings of it and `merkle_root_and_mutated` gave the provided list
as the tree's bottom level, which is its items' hashes; a list of hashes
taken as given goes to `merkle_root_and_mutated_from_hashes` (closes #2300).

### A clone short of the release tags is told to `git fetch --tags`

`CONTRIBUTING.md` says so beside `uv run pytest`, and the skip reason of the
tag-reading tests names the same command (closes #2301).

### `b32.power_of_2_base_conversion` validates its widths and its values

A width that is not a positive integer, or a value that is not `is_integer`,
raises `BTClibValueError` or `BTClibTypeError`, where a zero `to_bits` looped
forever and a bool was taken as a digit (closes #2290).

### `tests/integration` bounds each test with pytest-timeout

A `bitcoind` that stops answering fails the test waiting on it instead of
hanging the run, and `pytest-timeout` joins the `harness` group (closes #2310).

### `BlockHeader.assert_valid` accepts every version an `int32_t` holds

A version of zero or below raised "invalid version", where Bitcoin Core refuses
it only as `bad-version`, a check keyed on the chain's activation heights and
not reached from the header alone (closes #2309).

### `NetworkAddressV2` takes a `TORV2` or `YGGDRASIL` address of any length

Core's `SetNetFromBIP155Network` has no case for either id, so Core drops one
of any length within `MAX_ADDRV2_SIZE` and keeps the message; `assert_valid`
holds one to that bound alone (closes #2308), not to BIP155's table.

### `PrvKeyData.pub` asks the key before deriving it

A `q` outside 1..n-1 or of no integer type raises as `assert_valid` does, where
a key built with `check_validity=False` derived the public key of `q` mod n
where that is nonzero, or of a hex string read as a number (closes #2294).

### `ecc.ellswift.xdh` is held to BIP324's packet encoding vectors

Each row of bitcoin/bips' `packet_encoding_test_vectors.csv` is asserted
through the bindings and through the Python arithmetic, whose arm then answers
to BIP324's reference code and not to libsecp256k1 alone (closes #2307).

### The address and script builders ask the `PubKeyData` they are handed

`b58.p2pkh`, `p2wpkh_p2sh`, `b32.p2wpkh` and `ScriptPubKey.p2pk`, `p2pkh`,
`p2wpkh` and `p2ms` refuse a key `assert_valid` refuses, which reached the
output unchecked, and a non-key, which raised `AttributeError` (closes #2329).

### `fix_signature` reads lax DER as Core's `ecdsa_signature_parse_der_lax`

With no flag asking for strict DER, the sequence length is skipped and a length
octet with its top bit set is read as X.690's long form, as in Core: a
signature Core verifies was refused, and one it refuses taken (closes #2283).

### The fuzz container is built from a pinned image and locked dependencies

`.clusterfuzzlite/Dockerfile` pins its base image by digest, a Dependabot
docker entry moving it (closes #2305), and `build.sh` installs the versions
uv.lock pins, exported with their hashes (closes #2306).

### `script.engine.sig_op_cost` is Bitcoin Core's `GetTransactionSigOpCost`

`script.sig_op_count` takes `accurate`, and `p2sh_sig_op_count` and
`witness_sig_op_count` count what an input adds given the output it spends
(closes #2313); the cost sums them with the legacy count, as Core weighs each.

### `ScriptPubKey.p2ms` and `nulldata` refuse a wrong type as `BTClibTypeError`

`p2ms` refuses an `m` that is not `is_integer`, `True` included, and `keys` that
are octets or no sequence (closes #2331), and `nulldata` data neither text nor a
buffer, each of which built a script or raised a `TypeError` or a value error.

### `ScriptError` names its failure by Bitcoin Core's `ScriptError_t`

Every refusal of `verify_input` carries a `ScriptErrorCode` as `code`, whose
`description` is Core's `ScriptErrorString` (closes #2314), and each vector of
`script_tests.json` is held to the error it expects, not to any failure.

### A p2sh witness input's script_sig is the push of its redeem script alone

Core's `WITNESS_MALLEATED_P2SH`, consensus with BIP141: a signed spend with a
push ahead of the redeem script verified (issue #2314).

### A taproot signature is 64 bytes, or 65 with a hash type

Core's `SCHNORR_SIG_SIZE`: a valid signature with bytes after its 64th verified
on those 64, on the key path and the script path alike (issue #2314).

### `fix_signature` asks strict DER of the encoding and not of the values

An r or an s no signature can have ended the script, where Core's
`IsValidSignatureEncoding` reads the encoding alone, its 73-byte cap included,
and the signature then fails to verify: DERSIG refused a spend (issue #2314).

### `op_checksig` asks an empty signature what it asks any other first

As Core's `EvalChecksigPreTapscript`: an empty one was a false check before
FindAndDelete and the key's encoding ran, so `CHECKSIG NOT` spent a script
CONST_SCRIPTCODE, STRICTENC or WITNESS_PUBKEYTYPE refuses (closes #2332).

### CONST_SCRIPTCODE refuses a signature check only where it runs

A signature check in the script_sig was refused wherever it sat, where Core's
error is FindAndDelete's in the executed op code, which `op_checksig` now runs
ahead of every other check: one in a branch not taken spends (issue #2332).

### An OP_SUCCESSx in a tapscript forgives an oversized witness element

Core's `ExecuteWitnessScript` scans for one before measuring the witness stack:
a spend with an element over 520 bytes was refused (issue #2314).

### The `install-bitcoind` action goes

`reusable-integration-bitcoind.yml` installs bitcoind itself (issue
btclib-org/.github#1373).

### `codeql-passed` accepts `analyze`'s rows listed unfinished

Where `needs.analyze.result` is `success` or `skipped`, the listing lagging
behind a job already concluded (issue btclib-org/.github#1395).

### `REPOSITORY.md` reads back classic signatures off and SHA pinning on

`allowed_actions` is read back beside them, section 11 having the reasons
(issue btclib-org/.github#1409).

### Dependabot's `pre-commit` ecosystem is named as unused, not as absent

pre-commit.ci's weekly autoupdate moves `rev:` instead (issue
btclib-org/.github#1391).

### The whole suite bounds each test with pytest-timeout

A test waiting on a `git` or Python child that never exits fails instead of
hanging the run, and `tests/integration` keeps its own bound (closes #2325).

### A script breaking two rules fails with the code Core gives it

CONST_SCRIPTCODE is asked of each op code as Core's `EvalScript` asks it, and a
tapscript's pre-scan asks only for an OP_SUCCESSx and a push past the end: a fault
met earlier answered OP_CODESEPARATOR, PUSH_SIZE or BAD_OPCODE (closes #2341).

### A tapscript with OP_INVALIDOPCODE in a branch not taken spends

Core's pre-scan reads 0xff as any op code that is not an OP_SUCCESSx, and its
interpreter refuses it only where it executes: btclib refused the spend
(issue #2341).

### `script.taproot` asks the internal key and the script tree it is handed

`output_pubkey`, `input_script_sig` and `ScriptPubKey.p2tr` refuse a key neither
None nor a `PubKeyData` (closes #2334), each name taking a tree a malformed one,
`[]` too (closes #2339), and `script.serialize` a command of no script type.

### `bech32.decode` refuses a string without quoting it

Each refusal says what is wrong, a missing separator or an invalid checksum,
where it repeated the whole string, so that a private key pasted where an
address goes came back in the exception (closes #2344).

### `bech32.decode` refuses a data part character outside 33..126

Ahead of the case check: `str.lower` maps U+212A KELVIN SIGN onto `k`, so an
uppercase address with it in place of `K` decoded as that address. Bitcoin
Core's `CheckCharacters` refuses the same range (closes #2347).

### `script_from_script_pub_key` refuses a string without quoting it

What is neither the hex of a script nor an address is refused as `neither a
script nor an address`, the decoder's refusal chained as the cause, where the
string was quoted, a private key pasted there included (closes #2350).

### Address, WIF, signature and ip decoders strip ASCII whitespace alone

`str.strip()` with no argument also takes U+00A0, U+3000 and the rest of what
`str.isspace` counts; `string.whitespace` is Bitcoin Core's `IsSpace`
(closes #2349).

### Script serializers match an op code name as `parse` writes it

Upper-case ASCII: `str.upper` maps U+0131 onto `I`, so `op_` U+0131 `f` was
OP_IF, and `taproot.serialize` wrote `op_success80` without refusing what
follows it. An OP_SUCCESS number is ASCII digits (closes #2352).

### `script.taproot` asks the internal key `assert_valid` above the arm split

A key built with `check_validity=False` on a network no name has is refused on
both arms, where the bindings took it (closes #2342), and a SEC prefix wrong for
its length is refused in `assert_valid`'s words, where each arm had its own.

### `script.taproot` refuses a script tree deeper than `MAX_TREE_DEPTH`

Every name taking a tree refuses one whose leaf no control block can prove, as
Core's `TaprootBuilder` does, where it built an output key (closes #2343).

### `ScriptPubKey.p2ms` takes up to 20 keys, as OP_CHECKMULTISIG does

A count above 16 is the one-byte push Core writes, and `p2ms_m_and_keys` reads
it back, so a p2wsh multisig of 17 to 20 keys, which Core creates, is built and
classified as p2ms (closes #2348); the bare and p2sh limits are the caller's.

### Script serializers read a string command exactly

`script.serialize` reads `UNKNOWN_OP_CODE_n` only as `parse` writes it, where
`int` read `UNKNOWN_OP_CODE_1_87` as 0xbb (closes #2361). Both serializers strip
`string.whitespace`, where `str.strip()` took U+001C to U+001F (closes #2363).

### Amount and fee-rate readers take ASCII digits and ASCII whitespace alone

A digit outside ASCII is refused and only `string.whitespace` stripped, as in
Bitcoin Core's `ParseMoney`, and both `FeeRate` readers refuse the underscore
(closes #2360). "1e1" stays an amount, as Core's `ParseFixedPoint` reads it.

### `utils.int_from_integer` reads only ASCII hex digits after `0x`

`int(s, 16)` read `0x1_0` and `0x` + fullwidth or Arabic-Indic digits as 16,
and `strip()` let non-ASCII whitespace pad either spelling. The refusal quotes
no part of the string, and `hex_string` inherits it (closes #2353).

### A network name is stripped of ASCII whitespace alone

`normalized_network_name` strips `string.whitespace`, where `str.strip()` also
took U+00A0, U+3000, U+001C and the rest of what `str.isspace` counts
(closes #2373).

### Dependabot's docker entry takes the seven-day cooldown

One rule for every ecosystem, though dependabot-core dates a docker tag only on
Docker Hub and the base image is on gcr.io (issue btclib-org/.github#1405).

### Amount and fee-rate readers refuse a leading `+`

Neither of Bitcoin Core's `ParseMoney` and `ParseFixedPoint` reads one; the `+`
of an exponent, "1e+1", stays (closes #2372).

### `int_from_json_number` takes a whole number, never its text

A str or bytes is refused by type, as `int` reads non-ASCII digits, an
underscore and padding in one (closes #2371); a fractional Decimal or Fraction
is refused where it truncated, and no refusal quotes the value.

### `ScriptPubKey.p2sh` refuses a redeem script over `MAX_SCRIPT_ELEMENT_SIZE`

A spend pushes the redeem script, and Bitcoin Core fails a push that long, so
the output it built could never be spent. The refusal quotes the length, not
the script (closes #2381).

### Amount and fee-rate readers take Bitcoin Core's `ParseFixedPoint` grammar

A leading zero before another digit and a point without a digit on both sides
are refused, "01", ".5", "1.", ".5e1" and "01e1" among them; "0", "0.5", "0e1"
and "-0" stay (closes #2378).

### `b58.p2sh` and the p2wsh builders refuse a script too long to spend

A redeem script over `MAX_SCRIPT_ELEMENT_SIZE` (closes #2383), a witness script
over the consensus `MAX_SCRIPT_SIZE`, not Core's relay limit (closes #2384).
Both are in `btclib.consensus`, and `btclib.script.limits` re-exports them.

### `codeql-passed` re-reads a lagging row and judges `analyze`'s own result

A lagging row is read again up to three times, 10 s apart, before it is
accepted (issue btclib-org/.github#1416), and a `needs.analyze.result` neither
`success` nor `skipped` fails the step (issue btclib-org/.github#1424).

### Amount arithmetic runs in btclib's own context, and sat/vB rates are bounded

A caller's decimal precision and traps change no amount or rate, and a dust
threshold outside zero to MAX_MONEY is refused (closes #2387). A rate above
MAX_MONEY sat/vB is refused, and no exponent builds a huge int (closes #2385).

### An amount or fee-rate refusal never raises while it quotes its value

A value `str()` cannot write, such as an int past its digit limit, is refused
as this library's error and named by bit length or type; `FeeRate` refuses a
rate above MAX_MONEY sat/vB, so its repr never meets one (closes #2389).

### `script.toml`'s header says which test file quotes which script-size limit

tests/b32_test.py quotes the witness-script message alone, where
tests/script and tests/b58_test.py quote both (closes #2395).

### A refusal outside amount and fee describes an int `str()` cannot write

Refusals name an int past `str()`'s digit limit by sign and bit length, and
`var_int.serialize` quotes as `hex()` does; amount and fee bounds use `int`'s
methods; `assert_valid_hash_type` refuses a non-int as a type (closes #2394).

### `taproot.leaf_hash` refuses a leaf version no control block carries

A non-integer is a type error, and a version outside a byte or odd, which
BIP341's `c[0] & 0xfe` never is, a value error (closes #2396).

### `taproot.serialize` refuses an OP_SUCCESS number of more than three digits

It is refused before `int` reads it, where one past `int`'s digit limit raised
a builtin `ValueError` (closes #2400).

### `utils.read_exactly` refuses a size that is no count of octets

A non-integer size, a bool included, is a type error, and one below zero or
past `sys.maxsize` is refused before `read` sees it (closes #2399).

### The sibling-package floors move onto their newest releases

- `btclib-ecc>=2026.9.28`, `btclib-ecc[secp256k1]>=2026.9.28`,
  `bitcoin-core-rpc>=2026.9.29` and `btclib-secp256k1>=0.8.0.9`: each is
  a btclib-org project whose new release this release depends on, not a
  stranger's drift (closes #2407).
