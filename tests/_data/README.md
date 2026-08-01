# Vendored test vectors

This file is about `tests/**/_data/` only. The other directory holding json
beside the tests, `tests/**/_generated_files/`, is the opposite kind of
thing and has no entry here: those seventeen files are btclib's own output,
`to_dict()` over fixed input, committed as golden files so that a change to
a serialized form fails a test instead of passing unnoticed. Nothing
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
and for six files the answer is "no revision of it, byte for byte",
which the verdict then accounts for.

The two halves are kept in agreement in one direction only: a test module
names its upstream and points here for the revision, and this file does not
restate what a vector tests. Where a citation named the wrong upstream it
was corrected in the module — three of them so far, listed at the end —
and this file is not where that correction lives.

## Naming

A vendored file carries the name its upstream publishes it under, wherever
upstream publishes a file at all. That is not cosmetic: `bms.json` was
named after this project's `ecc.bms` module instead, and the citation in
the module that loads it drifted to a path upstream does not have --
nobody comparing the two names would have caught it, because neither was
upstream's. `tapscript_test_vector.json` was worse, describing what the
vectors are for rather than what they are, in a file that is a generated
Core dump.

Four files keep a btclib name deliberately, and the reason is the same in
each: there is no upstream file whose name they could take.

- `bip32_test_vectors.json`, `bip32_invalid_keys.json`,
  `bip174_test_vectors.json`, `bip371_test_vectors.json` and
  `bip67_test_vectors.json` are transcribed from mediawiki prose. There is
  no upstream file, so the name is ours by necessity.
- `bip39_test_vectors.json` holds only the `english` array of trezor's
  `vectors.json`, plus one btclib case. Taking the name `vectors.json`
  would claim twelve languages we do not vendor.
- `descriptor_checksums.json`, `rfc6979.json`,
  `electrum_test_vectors.json` and `fakeenglish.txt` have no upstream file
  either; the last two are btclib's own.

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

Every entry here was re-checked against its upstream on 2026-07-30 and
everything that had drifted was refreshed, so `behind` is 0 wherever a
refresh was possible at all. What that took, and the three btclib defects
it turned up, is in the entries and in the list at the end.

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

Four of the 19 are the arbitrary-size messages BIP340 gained in 2023-04
(0, 1, 17 and 100 bytes), and btclib refused all four: it took the message
as a `hf_len` array, as the bindings still do. They were held here and
marked `xfail` in `tests/ecc/ssa_test.py` rather than left out of the
file — which is what made issue 169 measured rather than described, and
what `xfail_strict` then turned red the day the support landed. All four
pass: `verify_` accepts each, and `sign_` reproduces each signature byte
for byte. The bindings are unchanged, so those four take the python path.

The 2026-07-30 refresh also reverted a local edit worth recording: the
comment column of vectors 11, 12 and 13 read `sig[:32]`, `sig[:32]`,
`sig[32:]` against upstream's `sig[0:32]`, `sig[0:32]`, `sig[32:64]`, not
because we held an older revision but because btclib commit ca48c151,
"replaced `[0:` with `[:`", was a repository-wide substitution that
reached into the vendored file. That column is only the test id, so
nothing had been asserted wrongly, and it is upstream's spelling again.

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
invalid extended keys vectors", is Ferdinando Ametrano's, and landed in
bitcoin/bips the same day btclib vendored the file. The second column is
btclib's own: it holds btclib error messages, which the BIP does not and
should not carry, and which change when the messages change — as on
2026-07-30. Refreshing from upstream means refreshing the keys, never the
messages.

### `tests/psbt/_data/bip174_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0174.mediawiki
commit  8c369ac8e60629ac6c032ffe21bb5ec5b35213d7  2026-07-16
pulled  2020-11-15, extended 2021-08-03, refreshed 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, and now complete for the cases. The BIP's Test
Vectors section is 34 `* Case:` entries — 20 invalid, 10 valid, 4 signer
check failures — and all 34 are here, each with the base64 the prose gives
and cross-checked against the hex the prose gives beside it. What is still
not vendored, deliberately, is the role walk-through: the creator,
updater, signer, combiner, finalizer and extractor psbts of the worked
example, which are prose steps rather than cases.

The `description` and `encoded psbt` of each entry are upstream's. The
`error message` of a signer check failure is **not**: the BIP says only
that these four psbts must fail the check, so that field is btclib's own
expectation of btclib's own message, and correcting a message means
correcting it here too. One of the four read `script type not it` for
`not in` until issue 149; a typo pinned in vendored-looking data is
exactly the hazard that made the pin worth writing down.

Until 2026-07-30 the file held 31 of the 34, and the gap was not upstream
drift: of the three missing, `PSBT with global unsigned tx that has 0
inputs and 0 outputs` and `PSBT with 0 inputs` were both in the revision
this file was transcribed from, and were simply not taken. Only `PSBT with
an invalid value data due to its size being not the stated size` is new
(`97885721`, 2025-09-18).

The two zero-input psbts are valid per the BIP and btclib refused both, so
they were `xfail` in `tests/psbt/psbt_test.py` for a day — issue 170, fixed:
the global unsigned transaction is checked as the template it is, not as a
complete transaction. Leaving them out had hidden that for five years, which
is the argument for holding a vector you fail.

Two `error message` fields changed with that fix, and both were recording
what btclib answered rather than what the vector is about, which is what
made them worth holding:

- *"PSBT with an invalid value data due to its size being not the stated
  size"* said `Missing inputs`. It says `wrong tx serialization format` now
  — the value is 51 bytes whose transaction re-serializes to 10, and
  `deserialize_tx` had always carried that comparison; validating on the way
  in is what made it unreachable.
- *"PSBT where inputs and outputs are provided but without an unsigned tx"*
  said `null transaction`, a check that also refused the two valid
  zero-input psbts. `Psbt.parse` now requires the
  `PSBT_GLOBAL_UNSIGNED_TX` key, as BIP174 does, and answers
  `malformed psbt: missing global unsigned tx`.

The earlier pin, `754b77a9` (2021-04-08), was not the revision current
when the file was first vendored either: two of our psbts are absent from
that one (`c12af49c`, 2020-11-15) and from every revision up to 2021-04-08,
when "BIP 174: Add test vectors for additional unsigned tx serialization"
landed; the btclib commit that added them is 8391925f, 2021-08-03.

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

The test module cites `en.bitcoin.it/wiki/BIP_0067`, a wiki page that is
neither versioned nor authoritative. The BIP itself is, so the pin is
against bitcoin/bips and the citation should follow.

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
are dropped, against 1254 and 1203 before the refresh.

Until 2026-07-30 this was Core's blob at `facd7dd3` (2020-07-11) — 19
revisions back, and already three years old on the day btclib committed
it, upstream having moved on to `34d0e07e` (2022-02-10) by then. It was
not taken from Core's tip at vendoring time; it came from an older
snapshot carried along in the branch that became PR #83.

Five of the 30 vectors the refresh brings are TAPSCRIPT cases whose
witness and output script are placeholders — `#SCRIPT#`,
`#CONTROLBLOCK#`, `#TAPROOTOUTPUT#` — that Core's `script_tests.cpp`
generates at run time. `taproot_placeholders` in
`tests/script_engine/script_test.py` generates them here, from the BIP341
NUMS point rather than Core's `key0`, which no vector can tell apart. The
refresh is not a data-only change without it: three of the five fail on
`OP_#TAPROOTOUTPUT#`, and the two expecting a failure get one for the
wrong reason.

### `tests/script_engine/_data/tx_valid.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/tx_valid.json
commit  5fa81e239a39d161a6d5aba7bcc7e1f22a5be777  2025-07-08
blob    ac25f8149b4b39b4a82c2809e2d4b6f74a05c0e2
pulled  2023-07-08, renamed and refreshed 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, 121 vectors. The 2026-07-30 refresh brought three
revisions: an `http` to `https` fix in a comment line, a vector spending
the shortest valid DER signature (`3006020101020101`, from testnet3
`c6c232a3`), and a CHECKSEQUENCEVERIFY vector with a negative transaction
version. Both new vectors pass.

It was vendored as `tx_valid_legacy.json`, and the `_legacy` claimed a
subsetting that never happened: the file is Core's entire, every vector of
it is collected, and 2 of the 121 name WITNESS in their flags, so the
content is not legacy either. Core's name says what the file is; the
directory it sits in already says which engine the vectors feed (issue
168).

### `tests/script_engine/_data/tx_invalid.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/tx_invalid.json
commit  429ec1aaaaafab150f11e27fcf132a99b57c4fc7  2024-06-07
blob    486469ddefb36333c78cb8986508f98e31385a21
pulled  2023-07-08, renamed and refreshed 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, 93 vectors. Same rename, and the WITNESS count is
14 of the 93 here. The one revision the refresh brought changes a comment
line and nothing else — "insufficient tx.nVersion" became "insufficient
tx.version" — so the vector set is the one vendored in 2023.

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
added, so our blob is `601a40db`. 2244 vectors, in the same order. The
2026-07-30 refresh was the append it was expected to be: the 2243 vectors
we held were upstream's first 2243, verbatim and in order, and
`output/invalid_x` is the 2244th.

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

Verdict: **reformatted**. 200 vectors, JSON-equal.

It was vendored as `bms.json`, named after this project's `ecc.bms` module
rather than after its source, and now carries upstream's own name. What
that cost while it lasted is on the record: the citation in
`tests/ecc/bms_test.py` drifted to `bitcoin/tests/test_data/bms.json`, a
path upstream has as neither the directory nor the file.

Only the first ten vectors are exercised
(`PYTHON_BITCOINLIB_VECTORS` slices `[:10]`), but all 200 are
vendored.

### `tests/mnemonic/_data/bip39_test_vectors.json`

```text
repo    trezor/python-mnemonic
path    vectors.json
commit  b502451a33a440783926e04428115e0bed87d01f  2015-12-24
blob    c15add0e28ead51eb0d41fd73273531cc7aab922
pulled  2018-06-01
behind  5 revisions, all adding languages
```

Verdict: **extended**, and reformatted. Upstream's 24 English vectors are
ours, in order, value for value; ours has a 25th, the last one repeated
with tabs, newlines and doubled spaces sprinkled through the mnemonic, to
exercise whitespace normalisation. btclib's, not upstream's.

Upstream has grown eleven more languages since, and its English array has
not changed in any revision — so the pin is the earliest revision that
provides it, and the five revisions of drift are irrelevant to us. Only
the English vectors were ever taken; `english.txt` is the only wordlist
`btclib/mnemonic/mnemonic.py` ships.

Re-checked on 2026-07-30 against the tip of the path, `b57a5ad7`
(2024-08-27, blob `d362a5d4`, and its message is "normalize the words in
the wordlist according to NFKD"): upstream's 24 English vectors are still
ours value for value, that normalisation having touched other languages
only. Nothing to refresh, and the eleven other languages stay out for as
long as one wordlist is shipped.

## Chain data, not a repository

These are consensus bytes. There is no upstream repository to pin and no
commit to name: the authority is the chain, and any node or block
explorer settles a dispute. The identifier is the block hash or the txid,
which is what `Block.parse` and `Tx.parse` recompute from the bytes on
every run — so these files verify themselves, and are the only vendored
vectors that do.

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
running Electrum — suggestively, `tests/mnemonic/electrum_test.py` used to
carry a FIXME asking whether a mnemonic written inline in `test_mnemonic`
had been obtained in Electrum. That marker was about a different value
than these, so it is evidence of the habit rather than of this file; it
was removed with the rest of the FIXME/TODO markers, and the evidence is
recorded here instead.

So they are btclib's, cross-checked against an application rather than
copied from a project, and the honest record is that we cannot say which
Electrum version produced them. Treat them as ours: nothing upstream will
ever refresh them.

Pulled 2018-06-11.

### `tests/mnemonic/_data/fakeenglish.txt`

btclib's own, and deliberately broken: `english.txt` with the first word,
`abandon`, deleted — 2047 words, so that `WORDLISTS.load_lang` raises
"invalid wordlist length". Not vendored, nothing to pin; regenerate it
from `english.txt` if that ever changes, which it has not since 2014.

Pulled 2018-06-01.

## What is not pinned, and why

- **`tests/mnemonic/_data/electrum_test_vectors.json`** has no upstream.
  Stated above rather than guessed at.
- **`tests/script/_data/script_assets_test.json`** has a commit, but
  in a repository that rewrites its history. The blob SHA-1 is the pin
  that will still resolve next year.
- **The six transcribed files** are pinned to a prose revision, not to a
  blob, so "identical" is not a claim that can be made about them. What
  was checked instead is stated in each entry: every value present,
  verbatim, in the pinned text.
- **Nothing here is enforced.** No hook re-fetches an upstream and no
  test compares a blob, so this file goes stale silently. That is a
  deliberate stopping point: a network call in the test suite would trade
  a documented drift for a flaky one.

## Summary

28 files. Against a pinned upstream blob:

- 6 identical byte for byte: `english.txt`,
  `taproot_test_vector.json`, `sig_hash_legacy_test_vectors.json`,
  `script_tests.json`, `tx_valid.json`, `tx_invalid.json`.
- 1 identical but for a trailing newline:
  `script_assets_test.json`.
- 1 identical but for CRLF against LF: `bip340_test_vectors.csv`.
- 4 JSON-equal, reformatted: `pubkey.json`, `ecdsa_sig.json`,
  `ecdsa_custom_nonce_sig.json`, `signmessage.json`.
- 1 upstream plus one btclib case: `bip39_test_vectors.json`.

No upstream blob exists for the rest:

- 6 transcribed from a pinned prose revision, every value matched:
  `bip32_test_vectors.json`, `bip32_invalid_keys.json`,
  `bip174_test_vectors.json`, `bip371_test_vectors.json`,
  `bip67_test_vectors.json`, `descriptor_checksums.json`.
- 6 chain data, identified by block hash or txid.
- 3 not vendored: `rfc6979.json` (an RFC),
  `electrum_test_vectors.json` and `fakeenglish.txt` (btclib's own).

### Left for a maintainer to decide

- **Three descriptors of Core's `doc/descriptors.md` are not vendored**,
  and cannot be without a checksum from a third implementation. See that
  entry.
Decided on 2026-08-01: **every vendored vector is now exercised**. Two
were not, and neither turned out to be hiding a failure — which is the
only way to find out.

- 190 of `signmessage.json`'s 200 were sliced away by a `[:10]` in
  `PYTHON_BITCOINLIB_VECTORS`; all 200 run now, and all 200 pass.
- 1016 of `script_assets_test.json`'s 3737 cases never reached the
  engine: `taproot_vectors` in
  `tests/script_engine/transactions_test.py` selected on `"TAPROOT" in
  x["flags"]`, which drops the copy of each spend that Core's
  `feature_taproot.py` dumps with the soft fork *off*. All 1016 run now,
  685 accepted and 331 refused, as their vectors ask.

### Refreshed on 2026-07-30, issues 168 to 170

Everything with an upstream is now at that upstream's tip. What the sweep
changed:

- `tx_valid_legacy.json` and `tx_invalid_legacy.json` took Core's names,
  which is what they hold, and then Core's current bytes: 119 vectors
  became 121.
- `script_tests.json`, 19 revisions back, is at Core's tip: 1203 vectors
  became 1233, and the five new TAPSCRIPT ones needed their placeholders
  generated rather than parsed.
- `bip340_test_vectors.csv`, four vectors back, is at the tip of the path:
  15 became 19, and the four new ones are `xfail` — issue 169.
- `script_assets_test.json` gained the one appended vector, 2243 to 2244.
- `bip174_test_vectors.json` gained the three `* Case:` entries it had
  never held, 31 to 34, two of which are `xfail` — issue 170.
- `bip32_test_vectors.json`, `bip32_invalid_keys.json`,
  `bip371_test_vectors.json`, `bip67_test_vectors.json`,
  `bip39_test_vectors.json`, `english.txt`, `taproot_test_vector.json`,
  `sig_hash_legacy_test_vectors.json`, `pubkey.json`, `ecdsa_sig.json`,
  `ecdsa_custom_nonce_sig.json` and `signmessage.json` were re-checked and
  needed
  nothing: each entry says against which revision.

Three btclib defects came out of it, all three of them things the missing
vectors had been hiding rather than new: issue 169 (BIP340 messages of
arbitrary size), issue 170 (a PSBT whose unsigned tx has no inputs), and
the note in issue 170 about the value-size check that does not exist. All
three are fixed, and no vector of this suite is `xfail` any more.

And three citations in the test modules named the wrong upstream, all now
corrected in the module that carries them:

- `tests/ecc/bms_test.py` named `bitcoin/tests/test_data/bms.json`, which
  is upstream's path for neither the directory nor the file: it is
  `bitcoin/tests/data/signmessage.json`.
- `tests/script/script_pub_key_test.py` cited `en.bitcoin.it/wiki/BIP_0067`,
  a wiki page that is neither versioned nor authoritative, for vectors
  transcribed from the BIP.
- `tests/script/sig_hash_taproot_test.py` and `tests/script/taproot_test.py`
  cited bip-0341 for both of the two files they load, and
  `script_assets_test.json` is not in any BIP: it is a Core dump kept in
  qa-assets. `tests/script_engine/transactions_test.py` loads it too and
  cited nothing.

Each of those modules now names its upstream and points here for the
revision, which is the division of labour the top of this file describes.

Each entry above records what changed; this list is the index, so a later
reader can tell a deliberate refresh from drift.
