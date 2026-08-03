# Vendored test vectors

This file is about `tests/**/_data/`, plus the one shipped data file that
nothing else pins: `btclib/mnemonic/_data/wordlist.txt`, SLIP-0039's word
list. It is here because a word list is the most load-bearing vendored
file there is -- every share ever written with it decodes through it --
and because, unlike `english.txt`, it has no byte-identical copy under
`tests/` for an entry to name instead. The package's other word lists
have no entry because each is already pinned somewhere else or not at
all: `english.txt` through the test copy below,
`electrum_old_english.txt` and `electrum_portuguese.txt` through the
pins `btclib/mnemonic/electrum.py` carries beside the constants naming
them, and `italian.txt` and the eleven other BIP39 lists nowhere, which
is a gap rather than a statement about them.

The other directory holding json beside the tests,
`tests/**/_generated_files/`, is the opposite kind of thing and has no
entry here: those files are btclib's own output, `to_dict()`
over fixed input, committed as golden files so that a change to a
serialized form fails a test instead of passing unnoticed. Nothing
upstream to pin, and nothing to compare against but ourselves —
`BTCLIB_REGENERATE_GOLDEN=1 uv run pytest` rewrites them on purpose.

Where every file under a `tests/**/_data/` directory came from, and
whether our copy still matches it. The test modules already cite their
sources, but against `master`: a citation like
`bips/blob/master/bip-0340/test-vectors.csv` names a file that changes
under us and says nothing about the revision we copied. Here each
citation is pinned to a commit and the two blobs are compared.

Nothing in this file is a mirror of the citations in the test modules.
Those say what a vector *is*; this says which revision of it we hold —
and for the transcribed ones the answer is "no revision of it, byte for
byte", which the verdict then accounts for.

The two halves are kept in agreement in one direction only: a test module
names its upstream and points here for the revision, and this file does
not restate what a vector tests. A citation that names the wrong upstream
is corrected in the module; this file is not where that correction lives.

## Naming

A vendored file carries the name its upstream publishes it under, wherever
upstream publishes a file at all. That is not cosmetic: a btclib name has
no upstream name to be compared against, so the citation in the module
that loads it can drift to a path upstream never had and nobody catches
it — the byte comparison below is the only check the naming cannot fool.

The files that keep a btclib name do so deliberately, and the reason is
the same in each: there is no upstream file whose name they could take

- `bip32_test_vectors.json`, `bip32_invalid_keys.json`,
  `bip174_test_vectors.json`, `bip370_test_vectors.json`,
  `bip371_test_vectors.json`, `bip373_test_vectors.json` and
  `bip67_test_vectors.json` are transcribed from mediawiki prose. There is
  no upstream file, so the name is ours by necessity.
- `bip39_test_vectors.json` holds all twelve language arrays of trezor's
  `vectors.json`, plus one btclib case, and keeps the btclib name anyway:
  `vectors.json` is taken in the very same directory, by SLIP-0039's own
  file of that name, which is a different upstream's.
- `descriptor_checksums.json` and `rfc6979.json` are transcribed from
  prose, and `electrum_test_vectors.json`,
  `electrum_language_vectors.json`, `btclib_test_vectors.json` and
  `fakeenglish.txt` are btclib's own: no upstream file for any of them,
  so no upstream name to take.
- the seven under `tests/fetch/_data/` are response bodies, and a
  response has no name at all. Each takes the rpc method or the endpoint
  path that produces it, which is the closest thing to an upstream name
  they have and the one a re-check would type into `bitcoin-cli` or a
  url.

`btclib_test_vectors.json` is where that convention says the most, and it
is a naming rule of its own: the prefix of a psbt vector file names the
authority the cases answer to — `bip174_`, `bip370_`, `bip371_`,
`bip373_`, and `btclib_` for the ones btclib composed, which no BIP
publishes and no refresh will ever reach. A file so named cannot be
mistaken for a copy of something.

`taproot_test_vector.json` and `sig_hash_legacy_test_vectors.json` do have
an upstream file each -- bip-0341's `wallet-test-vectors.json` and Core's
`sighash.json` -- and keep the btclib name for now. They are the
outstanding half of this convention rather than an exception to it.

## Reading an entry

Each entry gives the upstream repository, the path in it, the commit the
citation is pinned to, the git blob SHA-1 that was compared, and a
verdict. The verdicts used:

- **identical** — our file and the upstream blob are the same bytes.
- **reformatted** — same parsed JSON value, different whitespace.
- **transcribed** — the upstream is prose (a BIP, an RFC), so there is no
  file to compare; the check is that every value in our copy appears
  verbatim in the pinned text.
- **extended**, **edited** — characterised in the entry.

`pulled` is the date of the btclib commit that put the current content in
the tree, from `git log --follow --diff-filter=A`. That is a fact in this
repository; someone's memory of the day they opened a browser is not.
Where a file was vendored earlier and later refreshed, both dates appear.

`behind` counts upstream revisions of that path since the pin. It is a
staleness figure, not a defect: a vector file is a fixed set of cases and
refreshing it is a decision, not a chore.

Every entry was last re-checked against its upstream on 2026-07-30, and
whatever had drifted was refreshed, so `behind` is 0 wherever a refresh
was possible at all. The files vendored since are the exception by date
alone, all of them taken at the tip of their path on 2026-08-02, which is
what their `pulled` says: the eight BIP327 files, the three Core files
`key_io_valid.json`, `key_io_invalid.json` and `base58_encode_decode.json`,
and the two python-bitcoinlib block files added here; Core's
`blockfilters.json` and the psbts of BIP370 and BIP373 followed on
2026-08-03, at the tip of their paths too.

A vector btclib fails is vendored anyway and marked `xfail`, never left
out: an absent vector hides the defect it would have shown, and
`xfail_strict` turns the marker red the day the defect is fixed.

## Re-checking a pin

```shell
git hash-object tests/script_engine/_data/script_tests.json
gh api repos/bitcoin/bitcoin/git/trees/<commit>:src/test/data \
    --jq '.tree[] | select(.path == "script_tests.json") | .sha'
```

The comparison is on git blob SHA-1, not sha256: it is what a tree entry
already carries, so nothing has to be downloaded, and `git hash-object`
reproduces it locally. Not the contents API, which is the obvious
alternative and caps out — `script_assets_test.json` is 9 MB.

The two hashes match for every file whose verdict is **identical**. Where
upstream is CRLF they cannot, this repository being LF throughout, and the
entry says so with our own blob alongside: `bip340_test_vectors.csv` is
the one case.

## bitcoin/bips

### `tests/mnemonic/_data/english.txt`

```text
repo    bitcoin/bips
path    bip-0039/english.txt
commit  ce1862ac6bcffa1dd20aad858380e51e66e949ea  2014-02-07
blob    942040ed50f7205cafc465496229128ba4f78e75
pulled  2018-06-01
behind  0 revisions; that commit is the only one to touch the path
```

Verdict: **identical**. The BIP39 English wordlist has never been
changed, so this is the one pin that cannot go stale.

### `tests/ecc/_data/bip340_test_vectors.csv`

```text
repo    bitcoin/bips
path    bip-0340/test-vectors.csv
commit  200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb  2023-04-20
blob    672339129a844a060591bb22f444158ff45438ed
pulled  2020-04-04, refreshed 2020-11-22 and 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings** — upstream is CRLF and this
repository is LF throughout, which `mixed-line-ending` enforces with
`--fix=lf`, so our blob is `aa317a3b` rather than the one above. All 19
vectors, all eight columns.

Four of the 19 are messages of 0, 1, 17 and 100 bytes: BIP340 accepts a
message of any size, the bindings still insist on a 32-byte hash, so
these four take the Python path (issue 169). All four pass: `verify_`
accepts each, and `sign_` reproduces each signature byte for byte.

### BIP327 (MuSig2): eight files under `tests/ecc/_data/`

The vectors of `bip-0327/vectors/`, all eight of them, vendored whole
and under upstream's own names: `key_sort_vectors.json`,
`key_agg_vectors.json`, `nonce_gen_vectors.json`,
`nonce_agg_vectors.json`, `sign_verify_vectors.json`,
`tweak_vectors.json`, `det_sign_vectors.json` and
`sig_agg_vectors.json`.

One pin serves all eight, the entries below differing only in the blob:

```text
repo    bitcoin/bips
path    bip-0327/vectors/<name>.json
commit  1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439  2024-07-19
pulled  2026-08-02
behind  0 revisions; that commit is the tip of the path, which has
        three revisions in all
```

Verdict for every one of them: **identical**. The eight blobs are

```text
de088a746e27953614b9f5394553911fb2c86d59  key_sort_vectors.json
b2e623de60f302c4004a6d656581bdba1f4e1e05  key_agg_vectors.json
ced946f3efd9f80cb1a3819939f2b39de2061e42  nonce_gen_vectors.json
1c04b8818f340a5fe2e10eaf73c17a2c9e020f46  nonce_agg_vectors.json
f71c8dd9d935c8c5f398e6a3888943e1e68b729d  sign_verify_vectors.json
d0a7cfe832bfe22375af0d64cd5d0dbb350592e0  tweak_vectors.json
261669ccd01cd4098fa97045f3d32654f64a48af  det_sign_vectors.json
519562c343b6e4bf686ba6e3eda8cee5c8e8b55d  sig_agg_vectors.json
```

56 cases between them, and `tests/ecc/musig2_test.py` runs every one:
1 sorting, 4 + 5 aggregations valid and failing, 4 nonce derivations,
2 + 3 nonce aggregations, 6 + 6 + 3 + 2 signatures (valid, refused at
signing, false on verification, refused on verification), 5 + 1
tweaked, 4 + 5 deterministic, 4 + 1 aggregated. An error case carries
what should be raised — which party contributed what, or the text of a
plain value error — and is checked against it, so the failing half of
each file is as load-bearing as the valid half.

What the files are measured against is `bip-0327/reference.py`, pinned
separately at `9297c12729670d09f9149ec6d8bad967d8161bfe` (2025-10-03,
the tip of that path): `btclib/ecc/musig2.py` follows it function for
function, and copies four of its error message strings verbatim
because the `error.message` field of a case is compared byte for byte.
That file is not vendored — it is an implementation, not data, and
btclib's is the one under test.

### `tests/script/_data/taproot_test_vector.json`

```text
repo    bitcoin/bips
path    bip-0341/wallet-test-vectors.json
commit  e35a46ecf3031c21dc7f7fdb694986789a3a8144  2021-11-12
blob    11261b00ba24afb90b62109505d9ca5ddd773b3b
pulled  2021-11-28
behind  0 revisions; that commit is the only one to touch the path
```

Verdict: **identical**.

### `tests/bip32/_data/bip32_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0032.mediawiki
commit  b0521f076c0b40208e82208f5476c48071aab785  2020-11-04
pulled  2020-05-08, vector 4 added 2021-08-25
behind  14 revisions, none of which touches the vectors
```

Verdict: **transcribed**. BIP32 ships its vectors as prose, so there is
no upstream file and no byte comparison to make. All four seeds and all
34 extended keys of test vectors 1 to 4 appear verbatim in the pinned
text, and the derivation counts match: 6, 6, 2, 3.

The pin is the commit that *added* test vector 4 rather than the one
current when btclib transcribed it: it is the earliest revision holding
all 34 keys, and the parent holds 28, which makes the pin checkable
rather than merely plausible.

Re-checked on 2026-07-30 against the tip of the path,
`c0644a054fd1568ecbfc9c2b656ad5200b16ff74` (2026-03-05): the BIP still
carries test vectors 1 to 5 and no sixth, and every extended key in it is
one of ours — 48 match the key pattern, our 34 valid plus 14 of the 16
invalid, the other 2 being the zero-prefix keys of test vector 5, which
serialize outside it. Nothing to refresh.

### `tests/bip32/_data/bip32_invalid_keys.json`

```text
repo    bitcoin/bips
path    bip-0032.mediawiki
commit  ee2e0598206b8b8a16555a14b8f0c0a70105f93e  2020-05-16
pulled  2020-05-16, error strings last changed 2026-07-30
behind  13 revisions; the 16 keys are unchanged on master
```

Verdict: **transcribed**. All 16 invalid extended keys are exactly the 16
of BIP32 test vector 5 — no omissions, no local additions — both at the
pinned commit and on master today.

btclib is the upstream here, not the consumer: commit ee2e0598, "added
invalid extended keys vectors", is Ferdinando Ametrano's. The second
column is btclib's own: it holds btclib error messages, which the BIP
does not and should not carry, and which change when the messages change.
Refreshing from upstream means refreshing the keys, never the messages.

### `tests/psbt/_data/bip174_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0174.mediawiki
commit  8c369ac8e60629ac6c032ffe21bb5ec5b35213d7  2026-07-16
pulled  2020-11-15, extended 2021-08-03, refreshed 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete for the cases. The BIP's Test Vectors
section is 34 `* Case:` entries — 20 invalid, 10 valid, 4 signer check
failures — and all 34 are here, each with the base64 the prose gives and
cross-checked against the hex the prose gives beside it. What is not
vendored, deliberately, is the role walk-through: the creator, updater,
signer, combiner, finalizer and extractor psbts of the worked example,
which are prose steps rather than cases. Five of them are the raw
material of `btclib_test_vectors.json` below, which is a different claim:
not that they are cases, but that a case can be built out of one.

The `description` and `encoded psbt` of each entry are upstream's. The
`error message` of a signer check failure is **not**: the BIP says only
that these four psbts must fail the check, so that field is btclib's own
expectation of btclib's own message, and correcting a message means
correcting it here too.

### `tests/psbt/_data/bip371_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0371.mediawiki
commit  4ab7faad749856bfc8178f9a12f4c1a8d40f632f  2023-02-15
pulled  2023-07-07
behind  8 revisions, none of which touches the cases
```

Verdict: **transcribed**, complete. All 17 psbts in the pinned text are
in our file and all 17 of ours are in the text — 11 invalid, 6 valid.
Re-checked on 2026-07-30 against the tip of the path,
`24e96e870fffaa257b465ce1f0370c14aac588e8` (2026-01-12): still 17 cases,
still the same 17. Nothing to refresh.

### `tests/psbt/_data/bip370_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0370.mediawiki
commit  e3874ca825bcd2d0975ffaffb97f1194b3661ad6  2026-04-07
pulled  2026-08-03
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete. Every psbt of the Test Vectors
section is here: 24 invalid, 14 valid, and the 10 of the timelock
determination algorithm, which keep the value that algorithm must
compute beside them — `null` for the one whose two kinds of locktime
cannot be reconciled. 48 base64 strings for 47 cases, one valid case
publishing two serializations of itself.

The base64 was taken and the hex checked against it, `b64decode(base64)
== bytes.fromhex(hex)` for all of them but one: the "1 input, 2 output
updated PSBTv2" case spells its label `Bytes in HEx`, so the pair cannot
be found by the name the other 46 use. A refresh should read the labels
case-insensitively rather than trust the count.

The `error message` of an invalid case is btclib's own, as in the two
files above, and here each names what the BIP says is wrong with the
case: half of the 24 are a version 0 psbt carrying one of BIP370's
twelve fields, refused by the name of the field, and the other half are
version 2 psbts refused for the unsigned transaction version 2 excludes,
for one of the seven fields it requires, or for a required locktime
outside the range that makes it one kind of locktime.

The valid ones are read and written back byte for byte, and the ten
locktime cases are asserted against the value the algorithm publishes
for each — the `null` one by the refusal it gets, its two kinds of
locktime having no single `nLockTime` to agree on.

### `tests/psbt/_data/bip373_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0373.mediawiki
commit  24e96e870fffaa257b465ce1f0370c14aac588e8  2026-01-12
pulled  2026-08-03
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete. Every psbt of the Test Vectors
section is here: 10 invalid and 14 valid, the valid ones being four
spend cases in three variants each — participant pubkeys only, then the
pubnonces, then the partial signatures — and two receiving cases, which
are the ones carrying the output field. The base64 was taken and the hex
checked against it, `b64decode(base64) == bytes.fromhex(hex)` for all
24.

Two of the ten invalid psbts are **the same bytes**: "PSBT with x-only
aggregate pubkey in output participant pubkeys keydata" and "PSBT with an
x-only output participant pubkey" both carry the x-only key in the key
data, so the second condition — an x-only key inside the value, which the
input pair does distinguish — is named upstream and carried by nothing.
Both are vendored as published, duplicate included, and
`test_an_output_participant_list_is_a_whole_number_of_keys` is the case
they do not make: the same shortening applied to the output map of the
BIP's own receiving psbt.

The `error message` of an invalid case is btclib's own, as in the three
files above. Each of the ten is a length — an x-only key where BIP373
requires a compressed one, or a nonce or partial signature whose value is
the wrong size — so a length is what each message names. Nothing here
pins the check Bitcoin Core makes beyond the length, `IsFullyValid` on
every key of every one of these fields: no vector of the BIP carries a
key of the right size that is on no curve, and
`test_a_musig2_key_must_be_a_point_and_not_merely_33_bytes` is where that
one is.

### `tests/script/_data/bip67_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0067.mediawiki
commit  b7090922b5e364409e4ddcd1558d85f2dd434c16  2020-04-28
pulled  2020-05-31
behind  10 revisions, none of which touches the vectors
```

Verdict: **transcribed**, complete. All five groups — their 15 public keys
and their five p2sh addresses — appear verbatim in the pinned text, and
re-checking against the tip `24e96e87` (2026-01-12) on 2026-07-30 found no
sixth group. Nothing to refresh.

## bitcoin/bitcoin

### `tests/script/_data/sig_hash_legacy_test_vectors.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/sighash.json
commit  43cb41859e910797510ef1117644fa2cd3c96fc9  2014-03-31
blob    d66a56ac35bdba08148bcb5db94c11a6df107097
pulled  2020-11-22
behind  0 revisions; that commit is the only one to touch the path
```

Verdict: **identical**, and still identical to Core's master. Renamed on
the way in; the content is Core's `sighash.json` untouched.

### `tests/script_engine/_data/script_tests.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/script_tests.json
commit  c4068cf37b6674417c77ce1f295b51dd49a57e81  2026-07-08
blob    b88c641547289b75f3dd760e73ba858f81ad5d85
pulled  2023-07-08, refreshed 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. 1288 entries, 1233 vectors once the comment lines
are dropped.

Five of the 1233 are TAPSCRIPT cases whose witness and output script are
placeholders — `#SCRIPT#`, `#CONTROLBLOCK#`, `#TAPROOTOUTPUT#` — that
Core's `script_tests.cpp` generates at run time. `taproot_placeholders`
in `tests/script_engine/script_test.py` generates them here, from the
BIP341 NUMS point rather than Core's `key0`, which no vector can tell
apart. The generation is load-bearing: parsed literally, three of the
five fail on `OP_#TAPROOTOUTPUT#`, and the two expecting a failure get
one for the wrong reason.

### `tests/script_engine/_data/tx_valid.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/tx_valid.json
commit  5fa81e239a39d161a6d5aba7bcc7e1f22a5be777  2025-07-08
blob    ac25f8149b4b39b4a82c2809e2d4b6f74a05c0e2
pulled  2023-07-08, renamed and refreshed 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, 121 vectors — Core's entire file, nothing
subsetted, and not only legacy: 2 of the 121 name WITNESS in their flags.
Core's name says what the file is; the directory it sits in already says
which engine the vectors feed (issue 168).

### `tests/script_engine/_data/tx_invalid.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/tx_invalid.json
commit  429ec1aaaaafab150f11e27fcf132a99b57c4fc7  2024-06-07
blob    486469ddefb36333c78cb8986508f98e31385a21
pulled  2023-07-08, renamed and refreshed 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, 93 vectors — Core's entire file, here too, with
14 of the 93 naming WITNESS in their flags.

### `tests/_data/key_io_valid.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/key_io_valid.json
commit  7c200ece80575d399a552f5757c07ac2c8c7ec6c  2025-03-26
blob    bff7ecff0993b7224301f07c8c624853832b61df
pulled  2026-08-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, 70 rows — 54 addresses and 16 WIFs, over the four
chains Core names in the metadata: `main`, `testnet4`, `signet`,
`regtest`, which are btclib networks under those very names but for
`mainnet`. The `test` of Core's older revisions is gone from the file:
the pinned commit is "test: use testnet4 in key_io_valid.json".

Eight of the 54 are witness versions 2, 3 and 16.
`ScriptPubKey.from_address` decodes each to Core's scriptPubKey and `b32`
re-encodes each from its witness, but `ScriptPubKey.address` answers `""`
for them: it renders the five types `type_and_payload` names and a future
version is not one of them. `tests/key_io_test.py` asserts that answer
rather than skipping the rows.

### `tests/_data/key_io_invalid.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/key_io_invalid.json
commit  fa506add25cbe5efbbabca647f5378c4128cf945  2022-04-06
blob    8f55abfec731bf2dec806804bb4dd903487294dc
pulled  2026-08-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, 70 strings, each a one-element array. All 70 are
refused by all four of the entry points that could be handed one —
`b58.h160_from_address`, `b32.witness_from_address`,
`ScriptPubKey.from_address` and `prv_keyinfo_from_prv_key` — every
refusal a `BTClibValueError`.

### `tests/_data/base58_encode_decode.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/base58_encode_decode.json
commit  5dd3a0d8a899e4c7263d5b999135f4d7584e1244  2025-01-04
blob    7255fd45c8003ad99ee95c507d8c54f49b50e4c2
pulled  2026-08-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, 21 rows of `[hex, base58]`. Core's
`EncodeBase58`/`DecodeBase58`, i.e. the codec with no checksum on it, so
what reads them is `base58._b58encode`/`_b58decode` and not the checked
`b58encode`/`b58decode` — one row is 256 bytes, 348 base58 characters,
which the checked decoder would refuse on `MAX_LENGTH` before looking at
it.

### `tests/block/_data/blockfilters.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/blockfilters.json
commit  c7efb652f3543b001b4dd22186a354605b14f47e  2019-04-06
blob    8945296a079b984d65b0aeb4a3e9b0798df075e0
pulled  2026-08-03
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Core's BIP158 vector file, vendored whole and
read in part: every row carries a height, a block hash and a full
serialized block before its filter columns, and `blockfilters_test.py`
reads those three. All ten blocks parse under the full validity check,
round-trip byte for byte, hash to the hash the row states, and the six at
or above testnet's BIP34 activation height commit the height the row
states — in the bytes Core builds, `assert_valid_coinbase_height`
comparing them. The four below it commit nothing, which is what makes the
file the vector for the activation gate as well.

btclib implements no block filter, so the filter columns are unread. The
file is here under its own name anyway rather than as a btclib-named
extract of the block column: a btclib name has no upstream name to be
compared against, which is what the naming section above is about, and
the whole file is 17,816 bytes.

The ten are testnet, where the four blocks of `tests/block/_data/` are
mainnet, and Core picked them for the shapes their scripts have: a
coinbase output script no parser can read, an output paying to an empty
script and a transaction spending from one, duplicate pushdata, witness
data, and genesis. None of them is invalid — every row is a block the
chain accepted.

### `tests/_data/descriptor_checksums.json`

```text
repo    bitcoin/bitcoin
path    doc/descriptors.md
commit  0f38524c31da4cf69d8e904569fe56292e4325b9  2022-10-30
pulled  2023-07-12
```

Verdict: **composed locally**, not vendored. All 18 descriptors appear
verbatim in the pinned document; none of the 18 checksums does, because
Core's document does not list them. They were computed with a third
implementation, `bdk`'s `descriptor::checksum::get_checksum`, as
`tests/descriptors_test.py` records — which is the point of the file: the
checksums are an independent oracle, so recomputing them with btclib
would void the test.

Nothing to refresh from upstream. A new descriptor needs a checksum from
somewhere other than btclib.

Checked again on 2026-07-30, against the current document rather than the
pin: all 18 of ours are still in it, and it still carries no checksum at
all — not one `descriptor#checksum` pair in the file. It has grown three
concrete descriptors we do not hold (a `tr(musig(...))`, a
`wsh(sortedmulti(...))` and a `wsh(thresh(...))`, the rest of what it shows
being syntax templates like `sh(SCRIPT)`), and each would need a checksum
computed by something that is not btclib. That is a decision to take with
a tool at hand, not a refresh.

## bitcoin-core/qa-assets

### `tests/script/_data/script_assets_test.json`

```text
repo    bitcoin-core/qa-assets
path    unit_test_data/script_assets_test.json
commit  b33d85102d169b54d966ea315ad81a636680aefa  2025-07-23
blob    6a69755a5e53f4212f265374e14f590dcbf86496
pulled  2021-08-03, refreshed 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** — our 9,243,521 bytes
are that blob's 9,243,520 plus the `\n` the `end-of-file-fixer` hook
added, so our blob is `601a40db`. 2244 vectors, in the same order.

Two caveats, and the second is the one that matters.

The file is not in bitcoin/bitcoin: it is *generated*, by
`test/functional/feature_taproot.py --dumptests`, and Core keeps the dump
in qa-assets rather than in tree. That is why the citation in
`tests/script/sig_hash_taproot_test.py` (bip-0341) does not lead to it.

The commit is a weak pin. The whole visible history of that path is three
commits, all stamped within a second of `2025-07-23T19:45:18Z`, which
cannot be when a 2021 dump was added: qa-assets prunes its history — the
visible commits are the prune, not the additions — and the SHA will not
survive the next prune. The blob SHA-1 above will, and it is what a
re-check should compare.

## Other projects

### `tests/curves/_data/pubkey.json`

```text
repo    rustyrussell/secp256k1-py
path    tests/data/pubkey.json
commit  ead56b92a8229e16941318d953c6444268beaa1a  2015-09-18
blob    8aaa0c59d182b126cfedc505473dbdc961aaea1a
pulled  2023-01-16
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 349 vectors, JSON-equal to the upstream blob;
ours is pretty-printed at four spaces. Re-checked on 2026-07-30: still
JSON-equal, and that blob is still the one on master.

### `tests/ecc/_data/ecdsa_sig.json`

```text
repo    rustyrussell/secp256k1-py
path    tests/data/ecdsa_sig.json
commit  ead56b92a8229e16941318d953c6444268beaa1a  2015-09-18
blob    af16179725c10c409c7929ac0576161c1f5e72ad
pulled  2023-01-16
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 199 vectors, JSON-equal.

### `tests/ecc/_data/ecdsa_custom_nonce_sig.json`

```text
repo    rustyrussell/secp256k1-py
path    tests/data/ecdsa_custom_nonce_sig.json
commit  3caf31d20c668cf54a1621e21b7f1d943f0db048  2016-03-30
blob    e9d61e267f2e8fcd21c660aab17fe5de44cae0f0
pulled  2023-01-16
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 199 vectors, JSON-equal.

### `tests/ecc/_data/signmessage.json`

```text
repo    petertodd/python-bitcoinlib
path    bitcoin/tests/data/signmessage.json
commit  0b8318cc36e86508a3153342290b31b614a1be7f  2015-06-30
blob    31d619867d1ab2dcd8358868ac501b35ebb9c129
pulled  2020-01-04
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 200 vectors, JSON-equal, and all 200 are
exercised by `tests/ecc/bms_test.py`.

### `tests/block/_data/checkblock_valid.json`

```text
repo    petertodd/python-bitcoinlib
path    bitcoin/tests/data/checkblock_valid.json
commit  46314961bd7d8d0d6069c766c9cb7bfc41c299f4  2014-02-22
blob    eeca0aa43d8c3cd75d3c98d497f39edb2f722dff
pulled  2026-08-02
behind  0 revisions; that commit is the only one to touch the path
```

Verdict: **identical**. Four blocks — genesis twice, 99,960 and 99,993 —
which `tests/block/checkblock_test.py` parses with the full validity
check. Genesis is the merkle tree btclib had no vector for: one leaf, so
the root is the coinbase txid and nothing is hashed.

The two genesis entries differ only in the `cur_time` beside them, and it
is read: it answers "is this timestamp too far in the future", which
`BlockContext` carries the clock for. The first is one second inside the
two-hour window and the second is the instant genesis was mined.

### `tests/block/_data/checkblock_invalid.json`

```text
repo    petertodd/python-bitcoinlib
path    bitcoin/tests/data/checkblock_invalid.json
commit  46314961bd7d8d0d6069c766c9cb7bfc41c299f4  2014-02-22
blob    16a9b3cafea17fb55057c1bb5eac572b524b27d5
pulled  2026-08-02
behind  0 revisions; that commit is the only one to touch the path
```

Verdict: **identical**. Seven blocks consensus refuses, and the only
vendored negative block vectors there are: what `block_test.py` rejects,
it rejects from blocks it mutates itself.

btclib rejects every one of them, and one of them for something
`assert_valid` cannot see: the genesis block two hours and one second
ahead of its `cur_time` is a valid block refused by
`assert_valid_contextual`, Core's `time-too-new`. Three of the rest are
rejected for the proof-of-work rather than the rule they name, upstream's
`fCheckPoW` being a switch `Block.assert_valid` does not have; each of
those three rules is asserted in `block_test.py` instead, from a block
mutated for the purpose.

One of the seven is misnamed, and the file is vendored with the name
anyway: "Duplicate transaction" is refused for its merkle root, the
duplicate never being reached, which is reported upstream along with
three other findings as petertodd/python-bitcoinlib#323. Renaming it
here would break the pin.

### Not vendored as files, from the same repository

Two blocks of values are cited inline instead, each small enough to read
where it is used, both pinned to `fbbe9245` (2023-04-27), the tip of both
paths:

- the five secp256k1 RFC6979 vectors of `Test_RFC6979`, in
  `bitcoin/tests/test_wallet.py`, read by `tests/ecc/rfc6979_test.py`.
  Private key, message, nonce and signature; the s values are the low
  ones, and four of the five differ from what RFC6979 arrives at before
  that normalization.
- the six nBits-to-difficulty pairs of
  `Test_CBlockHeader.test_calc_difficulty`, in
  `bitcoin/tests/test_core.py`, read by `tests/block/block_test.py`.
  btclib holds them as the hex the header field carries rather than the
  int upstream reads them as.

### `tests/mnemonic/_data/bip39_test_vectors.json`

```text
repo    trezor/python-mnemonic
path    vectors.json
commit  b57a5ad77a981e743f4167ab2f7927a55c1e82a8  2024-08-27
blob    d362a5d4eb1ba800a52aec30116915cd4576e1fd
pulled  2018-06-01, refreshed 2026-08-02
behind  0 revisions
```

Verdict: **extended**, and reformatted. All twelve language arrays are
ours, in order, value for value; ours has one vector upstream does not,
a 25th English case repeating the last with tabs, newlines and doubled
spaces sprinkled through the mnemonic, to exercise whitespace
normalisation. btclib's, not upstream's.

Held to the `english` array alone until 2026-08-02, when the other eleven
word-lists became languages btclib reads: the pin was the earliest
revision providing that array, since it has not changed in any of them,
and the pin is now the current revision because the arrays taken are all
of them.

The name is btclib's rather than upstream's, and stays so now that all
twelve arrays are here: `vectors.json` is taken in this very directory,
by SLIP-0039's own file of that name, which is a different upstream's.

### `tests/mnemonic/_data/test_JP_BIP39.json`

```text
repo    bip32JP/bip32JP.github.io
path    test_JP_BIP39.json
commit  360c05a6439e5c461bbe5e84c7567ec38eb4ac5f  2017-08-20
blob    6d8c40b19e5d4b899f9f3c2addbf994d150b245b
pulled  2026-08-02
behind  0 revisions
```

Verdict: **reformatted**. 24 vectors, JSON-equal; upstream's indentation
wanders by a space or two and ours is what `json.dumps(indent=4)` writes.

bip-0039 cites this file by URL in its own Test vectors section, beside
the reference implementation's, for the case that file does not cover:
"Japanese wordlist test with heavily normalized symbols as passphrase".
The passphrase is one string in NFC and another in NFKD, and the
sentences are published composed against word-lists published
decomposed, so these are the vectors that fail when normalisation is
skipped anywhere.

### `tests/mnemonic/_data/electrum_language_vectors.json`

btclib's own, and the second file here cross-checked against an
application rather than copied from a project. Electrum's `make_seed`
run with `randrange` patched to a constant, once per language, which is
the same starting point `mnemonic_from_entropy` takes: what it returned
is the mnemonic, and `mnemonic_to_seed` of it is the seed. Electrum
publishes no vector of that kind — its own `SEED_TEST_CASES` are
sentences to read, not entropies to generate from — so there is nothing
upstream to pin or to refresh against; regenerate them from electrum's
`mnemonic.py` if they are ever doubted.

The two Portuguese sentences beside them answer electrum's
`bip39_is_checksum_valid` yes and no, over its own 1626-word list.

In a file rather than inline like every other electrum vector in
`tests/mnemonic/electrum_test.py`, and the reason is this directory: the
lint gate's two spell checkers read a python source and skip `_data`, and
`typos` runs with `--write-changes`. Measured, it corrected a word of the
Portuguese sentence into the English word it is one letter away from.

Pulled 2026-08-02.

### `btclib/mnemonic/_data/wordlist.txt`

```text
repo    satoshilabs/slips
path    slip-0039/wordlist.txt
commit  1524583213f1392321109b0ff0a91330836ecb32  2019-03-02
blob    5673e7ca7f20ed7a5e70b3a7fa5e6df277ee29ab
pulled  2026-08-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. SLIP-0039's 1024 words, ten bits each, and the
only word list it defines: the SLIP supports no localization, so there
is no second language to leave out and no decision behind shipping one.

`tests/mnemonic/slip39_test.py` re-checks the criteria the SLIP states
for the list -- 1024 words, none shorter than four letters or longer
than eight, and all 1024 four-letter prefixes distinct -- which is what
turns a corrupted copy into a red test rather than into shares nobody
can read. Not the whole of `slip-0039/test_wordlist.sh`, which also
measures Damerau-Levenshtein distance: that is a property of the list
upstream chose, not of our copy of it.

### `tests/mnemonic/_data/vectors.json`

```text
repo    trezor/python-shamir-mnemonic
path    vectors.json
commit  1525df19df504b1f69b49179140119959f317f24  2024-05-14
blob    d98c387aa1feb32ca9e6e4410cff870dfc6fb358
pulled  2026-08-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- our 22,412 bytes
are that blob's 22,411 plus the `\n` the `end-of-file-fixer` hook added,
so our blob is `2e6da291`. 45 quadruples -- description, mnemonics,
master secret, BIP32 root extended private key -- of which 15 are valid
and 30 have an empty master secret, meaning combining those mnemonics
must fail. All 45 are exercised, the 30 included: an invalid vector left
out is a check nobody makes.

The reference implementation rather than the SLIP: SLIP-0039's own "Test
vectors" section carries no file, it links to this one. The pin is the
commit that added the extendable backup flag and the four vectors for
it, which is also the tip of the path.

Four of the 15 valid vectors are checked in both directions. They are
the 1-of-1 shares, whose value is the encrypted master secret itself and
therefore involves no randomness the vector does not record, so btclib
regenerates each of the four mnemonics word for word from the master
secret. The other 11 are recovery only, a 2-of-3 share being random by
construction.

## Chain data, not a repository

These are consensus bytes. There is no upstream repository to pin and no
commit to name: the authority is the chain, and any node or block
explorer settles a dispute. The identifier is the block hash or the txid,
which is what `Block.parse` and `Tx.parse` recompute from the bytes on
every run — so the first two entries verify themselves, and are the only
vendored vectors that do. The third holds parts of transactions rather
than whole ones, and says what that costs. The fourth is chain data
inside an envelope: bodies a node and an explorer send, carrying bytes
the first entry already holds, and it is the one entry here that needs no
node to re-derive.

### `tests/block/_data/block_*.bin`

```text
block_1.bin       height 1, 215 bytes
  00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
block_170.bin     height 170, 490 bytes
  00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
block_200000.bin  height 200000, 247,533 bytes
  000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf
block_481824.bin and block_481824_complete.bin
  height 481824, 988,519 and 989,323 bytes
  0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
```

Pulled 2020-06-08, except `block_200000.bin`, 2020-06-09.

`bitcoin-cli getblock <hash> 0` returns the first three and
`block_481824_complete.bin`. It does not return `block_481824.bin`: that
is the same block serialized *without* witness data, as a pre-segwit node
sees it, which no RPC hands over. It is derivable —
`Block.parse(complete).serialize(include_witness=False)` reproduces it
byte for byte, checked — and that is how to regenerate it.

### `tests/tx/_data/*.bin` — one segwit transaction

```text
txid   d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970
wtxid  fa54c948e34e30d4196a560036ff6ac7e306906d189760a066edd4caf571776b
size   4,740 bytes, vsize 1,471, 8 inputs, 1 output
pulled 2020-12-02
```

The file is named after the txid, and `Tx.parse` recomputes it, so a
corrupted copy announces itself. `bitcoin-cli getrawtransaction <txid>`
returns these bytes, given a node with the transaction index.

### `tests/script/_data/unspendable_script_pub_keys.json`

```text
251718  77822fd6663c665104119cb7635352756dfc50da76a92d417ec1a12c518fad69
        vout 0
265458  ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767
        vout 0 to 7
268060  d29c9c0e8e4d2a9790922af73f0b8d51f0bd4bb19940d9cf910ead8fbe85bc9b
        vout 0
293906  6f8a70aac37786b1f619d40250b8bca1a1f6da487146a7e81091f611068a23ef
        vout 0
299571  2ae22a393045a34ab634788117422607f092d061d39549c9b3e96259a5be0361
        vout 2
pulled  2026-08-01
```

The twelve `scriptPubKey`s reported in issue #123, the five transactions
that carry them being the five the issue lists. Each entry holds the
script, the height and vout it sits at, and what the decode must answer:
how many commands, and whether the last of them is the mark that says the
bytes stopped being a script.

This is the one file here that does not verify itself. A `scriptPubKey`
is a *part* of a transaction, so no txid can be recomputed from it; the
txid says where it came from, and re-deriving it is what checks the copy:

```shell
bitcoin-cli getrawtransaction <txid> 2 \
    | jq -r '.vout[<n>].scriptPubKey.hex'
```

Any explorer answers the same question — Esplora's
`api/tx/<txid>` carries the same hex under `vout[n].scriptpubkey`, which
is where this copy came from, no node with a transaction index being at
hand. The heights are the issue's own, and `getblockhash`/`getblock`
confirm them.

### `tests/fetch/_data/*` — seven response bodies

```text
getrawtransaction.json        594 bytes
getblockcount.json             48
getbestblockhash.json         108
getrawtransaction_error.json  216
esplora_tx_hex.txt            551
esplora_blocks_tip_height.txt   7
esplora_blocks_tip_hash.txt    65
pulled  2026-08-02
```

Verdict: **composed locally**, and the distinction between the envelope
and what it carries is the whole of the entry.

**The envelopes are not recorded.** They are what bitcoind and Esplora
send, written here from the source that writes them rather than captured
from a node: `JSONRPCReplyObj` in Core's `src/rpc/request.cpp` puts
`jsonrpc`, `result` and `id` in that order, compact, and `WriteReply`
appends the newline, which is why these files are one line each and why
`pretty-format-json` must not touch them — the exclusion by directory
already covers them. The error object of
`getrawtransaction_error.json` is Core's too, code `-5` with the message
`src/rpc/rawtransaction.cpp` builds for a node running without
`-txindex`, verbatim including the trailing sentence `JSONRPCError`
appends. Nothing here was invented; nothing here was captured either, and
a node's answer is what settles a disagreement.

**What they carry is chain data, and it verifies itself.** The hex in
`getrawtransaction.json` and in `esplora_tx_hex.txt` is transaction 1 of
block 170 —

```text
txid  f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
      275 bytes, 1 input, 2 outputs of 10 and 40 BTC
```

— the first bitcoin payment between two people, and it is not fetched
from anywhere: it is read out of `tests/block/_data/block_170.bin`,
already vendored above, so the two copies can be compared without a
network and `Tx.parse` recomputes the id from the bytes on every run. The
height and hash the other five carry are block 481824,

```text
0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
```

which is `tests/block/_data/block_481824_complete.bin`, so that pair is
checkable here too — `BlockHeader.parse(...).hash` against the hash, the
height against the BIP34 number in the coinbase.

The `.txt` files end in a newline that Esplora does not send: the
`end-of-file-fixer` hook adds it, as it did to `script_assets_test.json`
above, and `EsploraFetcher.text` strips whitespace for the same reason a
deployment behind a proxy may add some.

Regenerating any of the seven is reading the two block files and writing
the envelope around what comes out; nothing upstream will refresh them,
and nothing should.

## Not vendored from anywhere

### `tests/ecc/_data/rfc6979.json`

Appendix A.2 of RFC 6979, transcribed: 50 vectors, ten each for NIST
P-192, P-224, P-256, P-384 and P-521, as `tests/ecc/rfc6979_test.py`
says. An RFC number is already an immutable reference — there is no
commit to pin, and `rfc-editor.org/rfc/rfc6979` is the document.

Pulled 2020-05-08.

### `tests/mnemonic/_data/electrum_test_vectors.json`

**Unresolved, and probably unresolvable.** These 12-word mnemonics with
their root keys and addresses are in no upstream repository: a GitHub
code search for the first mnemonic returns btclib and one fork of btclib,
and they are not in spesmilo/electrum's `tests/`. They were produced by
running Electrum, and no record says which version.

So they are btclib's, cross-checked against an application rather than
copied from a project. Treat them as ours: nothing upstream will ever
refresh them.

They are no longer the only Electrum vectors, and that is what makes the
paragraph above bearable: `tests/mnemonic/electrum_test.py` now carries
spesmilo/electrum's own, inline — the `SEED_TEST_CASES` seeds and the
`Test_seeds` seed-type table of its `tests/test_mnemonic.py`, and the
`UNICODE_HORROR` passphrase of its `tests/test_wallet_vertical.py`. Not
vendored as files here: each block is small enough to read, and a
citation two lines above the values is one that gets checked.

The pre-2.0 scheme is the same arrangement and four more of upstream's
values, added for issue #208. The scheme has no specification — it
predates the BIPs — so a vector btclib generated would be testing btclib
against itself, and each of these is a value published by
spesmilo/electrum:

- the mnemonic-to-hex pair of `Test_OldMnemonic.test`, in
  `tests/test_mnemonic.py`, which is the only published pair and the only
  thing that pins the encoder;
- the mnemonic, hex seed and master public key of
  `test_electrum_seed_old`, and the mnemonic and master public key of
  `test_sending_offline_old_electrum_seed_online_mpk`, both in
  `tests/test_wallet_vertical.py`;
- the hex seed and `master_public_key` of the pre-2.0 wallet file in
  `tests/test_storage_upgrade.py`.

The word-list they run over has no entry here, and being outside
`tests/` is not the reason -- `wordlist.txt` is outside it and has one.
`btclib/mnemonic/_data/electrum_old_english.txt` is pinned where it is
used: it is shipped code, transcribed from the `_words` tuple of
`electrum/old_mnemonic.py`, and `btclib/mnemonic/electrum.py` carries
that pin beside the constant that names the file.

Pulled 2018-06-11; the pre-2.0 values 2026-08-02.

### `tests/mnemonic/_data/fakeenglish.txt`

btclib's own, and deliberately broken: `english.txt` with the first word,
`abandon`, deleted — 2047 words, so that `WORDLISTS.load_lang` raises
"invalid wordlist length". Not vendored, nothing to pin; regenerate it
from `english.txt` if that ever changes, which it has not since 2014.

Pulled 2018-06-01.

### `tests/psbt/_data/btclib_test_vectors.json`

**btclib's own, composed rather than copied.** Seven cases that no BIP
publishes: each is a psbt btclib must refuse, and what it must say. There
is no upstream URL to give, because there is no upstream — inventing one
is the failure mode this entry exists to prevent.

What they are made of is upstream, and it is the half of BIP174 the entry
above deliberately leaves out. The starting psbts are five steps of the
BIP's "2-of-3 Multisig Workflow" walk-through — prose steps rather than
`* Case:` entries, which is why `bip174_test_vectors.json` does not
vendor them — taken at the same pin as that file,
`8c369ac8e60629ac6c032ffe21bb5ec5b35213d7` (2026-07-16), where all five
appear verbatim; the two version 2 cases start instead from the first
valid psbt of `bip370_test_vectors.json`, at the pin recorded there.
Every case is one of those plus one edit:

- the **creator**'s psbt with a `PSBT_GLOBAL_VERSION` of 1, and with the
  `0xff` of its magic bytes replaced — the two `invalid psbts`, which
  `Psbt.b64decode` must refuse. The second is refused for the header and
  not for anything narrower, which is the case rather than a shortfall of
  it: that `0xff` is the fifth byte of `PSBT_MAGIC_BYTES` and not a field
  of its own, so losing it is the header being wrong;
- the **creator**'s psbt with a `script_sig` written into the first
  input of its unsigned transaction, which BIP174 requires to be
  unsigned. It is bytes like every other case here, where the three
  cases this replaces were a psbt plus the name of an edit: those
  described a psbt whose input maps and unsigned transaction disagreed,
  and under BIP370 the maps *are* the transaction, so dropping a map
  drops an input rather than leaving two counts to differ;
- two version 2 psbts, BIP370's first valid one with its
  `PSBT_GLOBAL_OUTPUT_COUNT` one too high and one too low. That count is
  how a version 2 parse knows how many maps follow, so a wrong one is a
  psbt that ends too early or has bytes left over — and it is the one
  place where those disagreeing counts *can* be written down;
- the **first signer**'s psbt with its `lock_time` flipped, beside the
  **second signer**'s unedited, as the one `invalid combination`;
- the **combiner**'s psbt with the partial signatures of its first input
  removed, as the one `unfinalizable psbt`. Its second input keeps its
  own, so what the case pins is that a Finalizer refuses the psbt for the
  one input it cannot finalize rather than finalizing what it can.

The `error message` of every case is btclib's own, as it is for the
signer check failures of `bip174_test_vectors.json`: the BIP says nothing
about the wording, so correcting a message means correcting it here too.
Nothing upstream will ever refresh this file, and a bumped BIP174 pin
does not touch it — the five psbts are fixed bytes, and the edits are
btclib's.

Composed 2026-08-02.

## What is not pinned, and why

- **`tests/mnemonic/_data/electrum_test_vectors.json`** has no upstream.
  Stated above rather than guessed at.
- **`tests/mnemonic/_data/electrum_language_vectors.json`** has none
  either, and for a reason that will not change: electrum publishes no
  vector for the sentence it *generates* from a given entropy. Ours were
  produced by running its code, which is a procedure to repeat rather
  than a revision to pin, and the entry above gives it.
- **`tests/script/_data/script_assets_test.json`** has a commit, but
  in a repository that rewrites its history. The blob SHA-1 is the pin
  that will still resolve next year.
- **The six transcribed files** are pinned to a prose revision, not to a
  blob, so "identical" is not a claim that can be made about them. What
  was checked instead is stated in each entry: every value present,
  verbatim, in the pinned text.
- **`tests/psbt/_data/btclib_test_vectors.json`** pins the prose revision
  its raw material came from, which is not the same as having an
  upstream: the cases are btclib's, so the pin says where the psbts were
  read and nothing about the cases built on them. A refresh of it is a
  contradiction in terms.
- **Nothing here is enforced.** No hook re-fetches an upstream and no
  test compares a blob, so this file goes stale silently. That is a
  deliberate stopping point: a network call in the test suite would trade
  a documented drift for a flaky one.

## Summary

No count here, and no count in front of the lists below. A count is a
line every open branch has to edit, so it is the one conflict a pull
request vendoring a file is guaranteed to have -- and two branches moving
it to the same new number merge with nothing to decide, into a number
that is wrong. `CHANGELOG.md` has a `union` driver to soften that; this
file cannot have one, union being right for a list of bullets and
nonsense for the prose around them. The lists *are* the fact the number
summarized, and the tree answers whenever the number is wanted:

```shell
git ls-files 'tests/_data/*' 'tests/*/_data/*' \
    btclib/mnemonic/_data/wordlist.txt | grep -cv 'README.md'
```

Against a pinned upstream blob:

- identical byte for byte: `english.txt`, `wordlist.txt`,
  `taproot_test_vector.json`, `sig_hash_legacy_test_vectors.json`,
  `script_tests.json`, `tx_valid.json`, `tx_invalid.json`,
  `key_io_valid.json`, `key_io_invalid.json`,
  `base58_encode_decode.json`, `blockfilters.json`,
  `checkblock_valid.json`, `checkblock_invalid.json`, and the eight
  BIP327 vector files.
- identical but for a trailing newline:
  `script_assets_test.json`, `vectors.json`.
- identical but for CRLF against LF: `bip340_test_vectors.csv`.
- JSON-equal, reformatted: `pubkey.json`, `ecdsa_sig.json`,
  `ecdsa_custom_nonce_sig.json`, `signmessage.json`,
  `test_JP_BIP39.json`.
- upstream plus one btclib case: `bip39_test_vectors.json`.

No upstream blob exists for the rest:

- transcribed from a pinned prose revision, every value matched:
  `bip32_test_vectors.json`, `bip32_invalid_keys.json`,
  `bip174_test_vectors.json`, `bip370_test_vectors.json`,
  `bip371_test_vectors.json`, `bip373_test_vectors.json`,
  `bip67_test_vectors.json`, `descriptor_checksums.json`.
- chain data, identified by block hash or txid: the blocks and
  transactions under `tests/block/_data/` and `tests/tx/_data/`, and
  `unspendable_script_pub_keys.json`, which is scripts rather than whole
  transactions and so is the one that cannot recompute its own
  identifier.
- response bodies under `tests/fetch/_data/`, whose envelopes are
  composed from Core's and Esplora's own source and whose payload is
  chain data two of the entries above already hold.
- not vendored: `rfc6979.json` (an RFC), `electrum_test_vectors.json`,
  `electrum_language_vectors.json`, `fakeenglish.txt` and
  `btclib_test_vectors.json` (btclib's own). The last is the only one
  composed rather than recorded: its cases were built here, out of psbts
  BIP174 prints as prose.

### Left for a maintainer to decide

- **Three descriptors of Core's `doc/descriptors.md` are not vendored**,
  and cannot be without a checksum from a third implementation. See that
  entry.
