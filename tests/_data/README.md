# Vendored test vectors

This file is about `tests/**/_data/`.

The other directory holding json beside the tests,
`tests/**/_generated_files/`, is the opposite kind of thing and has no
entry here: those files are btclib's own output, `to_dict()`
over fixed input, committed as golden files so that a change to a
serialized form fails a test instead of passing unnoticed. Nothing
upstream to pin, and nothing to compare against but ourselves —
`BTCLIB_REGENERATE_GOLDEN=1 uv run pytest` rewrites them on purpose.

Upstream prose that btclib *paraphrases* has no entry here either: a
BIP's reasoning, a Core comment, a C library header's rationale are
cited in the docstring or the comment that paraphrases them, and a
paraphrase admits no byte comparison, so there is nothing for the weekly
job to ask. What such a citation carries is decided by what it names. A
file needs no revision -- the repository and the path keep their names,
and a reader who opens it reads the reasoning upstream holds now, which
is what a paraphrase sends them for. A line needs one: a line number
is the one thing that moves under a file that keeps its name, so without
a revision the citation degrades into pointing at whatever now occupies
it. The revision sits in the citation or in the module docstring that
pins every citation in the module: `src/btclib/script/spendability.py`
names a range of Core's `script/script.h` and the released tag it read
them at, and `src/btclib/consensus.py` pins its tag once at the top and
says why a tag rather than a `master` tip.

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

- `bip67_test_vectors.json` is transcribed from mediawiki prose. There is
  no upstream file, so the name is ours by necessity.

`taproot_test_vector.json` and `sig_hash_legacy_test_vectors.json` do have
an upstream file each -- bip-0341's `wallet-test-vectors.json` and Core's
`sighash.json` -- and keep the btclib name for now. They are the
outstanding half of this convention rather than an exception to it.

## Reading an entry

Where an entry pins to a commit, it gives the upstream repository, the
path in it, and the commit. A `blob` line, where the entry carries one,
gives the git blob SHA-1 of what that entry pins; what it pins, and
whether it was compared byte for byte, is the entry's own to say. Most
entries close on a verdict; one with nothing upstream to compare
against says so in prose instead. The verdicts used:

- **identical** — our file and the upstream blob are the same bytes.
- **reformatted** — same parsed JSON value, different whitespace.
- **transcribed** — there is no file compared byte for byte. Over prose
  (a BIP, an RFC, a BOLT) the check is that every value in our copy
  appears verbatim in the pinned text; over a source file the check is
  the entry's own to state.
- **composed locally**, **recorded** — there is nothing upstream to
  compare, so the entry says what stands in for one. *composed locally*
  is a case this tree wrote, naming the third implementation that
  answered it; *recorded* is one reply a program gave, kept verbatim,
  naming the program and the calls that ask it again.
- **extended**, **edited** — characterised in the entry. No file here
  carries one, and that is the discipline rather than an accident: a case
  of btclib's own is written in the test module that reads the file,
  never inside the file, so refreshing a pin is a fetch and never a
  merge.

`pulled` is the date of the btclib commit that put the current content in
the tree, from `git log --follow --diff-filter=A`. That is a fact in this
repository; someone's memory of the day they opened a browser is not.
Where a file was vendored earlier and later refreshed, both dates appear.

`behind` counts upstream revisions of that path since the pin. It is a
staleness figure, not a defect: a vector file is a fixed set of cases and
refreshing it is a decision, not a chore.

`ref` names the branch a pin's path lives on, where that is not the
repository's own default branch -- a fork's pull-request branch, so
far the only case. `.github/scripts/check_vendored_vectors.py` reads it
as the `sha` parameter of GitHub's "commits touching a path" API, which
otherwise walks the default branch alone and finds no commit touching a
path that only exists elsewhere, reading as the file having been
deleted upstream regardless of whether the pin is current (ISS 2160).
Absent, as on every other entry here, the call is asked exactly as it
always was.

Every entry was last re-checked against its upstream on 2026-07-30, and
whatever had drifted was refreshed, so `behind` is 0 wherever a refresh
was possible at all. The files vendored since are the exception by date
alone, all of them taken at the tip of their path on 2026-08-02, which is
what their `pulled` says: the Core files `key_io_valid.json`,
`key_io_invalid.json` and `base58_encode_decode.json`, and the
python-bitcoinlib block files added here; Core's `blockfilters.json`
followed on 2026-08-03, at the tip of its path too, and Core's
`siphash.json` on 2026-08-20, Core's `chacha20_vectors.json` and
`muhash_vectors.json`, both transcribed from `crypto_tests.cpp`, on
2026-09-03, at the tip of that path, and
bitcoin-core/secp256k1's `src` for `secp256k1_symbols.txt` on 2026-09-10,
refreshed again on 2026-09-14, at the tip of its path that day too.

A vector btclib fails is vendored anyway and marked `xfail`, never left
out: an absent vector hides the defect it would have shown, and
`xfail_strict` turns the marker red the day the defect is fixed.

## Re-checking a pin

The commit stands in a fence of its own, sitting inside the API path
rather than at the end of the command; the fence below reads it as
`${commit:?}`, the shell's must-be-set form, so a paste of that fence
alone fails naming the variable.

```shell
commit=<the pin the entry gives>
```

```shell
git hash-object tests/script_engine/_data/script_tests.json
gh api "repos/bitcoin/bitcoin/git/trees/${commit:?}:src/test/data" \
    --jq '.tree[] | select(.path == "script_tests.json") | .sha'
```

The comparison is on git blob SHA-1, not sha256: it is what a tree entry
already carries, so nothing has to be downloaded, and `git hash-object`
reproduces it locally. Not the contents API, which is the obvious
alternative and caps out — `script_assets_test.json` is 9 MB.

The two hashes match for every file whose verdict is **identical**. Where
upstream is CRLF they cannot, this repository being LF throughout, and the
entry says so with our own blob alongside. A csv of bitcoin/bips is
written on Windows line endings often enough that it is worth expecting rather than
discovering -- `mixed-line-ending` rewrites the file with `--fix=lf` as it
is staged, so the blob to compare is never the one just fetched.

## bitcoin/bips

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

### `tests/script/_data/bip67_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0067.mediawiki
commit  24e96e870fffaa257b465ce1f0370c14aac588e8  2026-01-12
pulled  2020-05-31, re-pinned to the tip 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete. All five groups — their 15 public keys
and their five p2sh addresses — appear verbatim in the pinned text, and
re-checking against the tip on 2026-07-30 and again on 2026-08-06 found no
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
commit  4a12773f269742d2c655beb1b3f5ffe98e9beadb  2026-08-21
blob    2eb02c40ca8173f7c0ff044a7b8a3438e9724914
pulled  2023-07-08, refreshed 2026-09-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. 1292 entries, 1237 vectors once the comment lines
are dropped: four cases added since the previous pin, one of them a
DERSIG rejection of a non-compound signature type.

Five of the 1237 are TAPSCRIPT cases whose witness and output script are
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
`ScriptPubKey.from_address` and `b58.prv_key_data_from_wif` — every
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
`encode`/`decode` — one row is 256 bytes, 348 base58 characters,
which the checked decoder would refuse on `MAX_LENGTH` before looking at
it.

### `tests/_data/siphash.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/siphash.json
commit  3aea85411f61e8890b34e1de5fd348a4bcc85552  2026-07-18
blob    19b4aaadd4a71da46bfa25b82e309dfbbd1218e9
pulled  2026-08-20
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, 146 cases. Each carries a key, an input split
into blocks (so that a multi-block input and its byte-for-byte
concatenation are the same case, on purpose), and the expected output
of two constructions this library implements one of:
`expected.siphash24` is standard SipHash-2-4, what `hashes.siphash`
answers and what `tests/siphash_test.py` checks every row against, input
blocks joined back into one octet string first. `expected.siphash13uj`
is Core's unpadded, jumbo-block SipHash-1-3 variant
(`crypto/siphash.h`'s `SipHasher13UJ`), present on 64 of the 146 rows —
those whose blocks are each 8 or 32 bytes, the two Core evaluates that
variant on — and unread here: btclib has no hash-table use for it and
implements no jumbo-block hasher.

### `tests/_data/chacha20_vectors.json`

```text
repo    bitcoin/bitcoin
path    src/test/crypto_tests.cpp
commit  b388f9bd0d2bcc259d488638d479ba09a30ba040  2026-09-17
blob    2fdb83576e984dfaa19c17629f70bc425dc6d796
pulled  2026-09-21
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically. One json object per
`TestChaCha20(...)` call inside `BOOST_AUTO_TEST_CASE(chacha20_testvector)`
(21, RFC 7539/8439's own Appendix A.1/A.2/A.4 vectors among them, cited in
that test case's own comments), its five arguments read off as `message`,
`key`, `nonce_first`/`nonce_second` (`ChaCha20::Nonce96`), `seek` (the
block counter `Seek` starts from) and `keystream_or_ciphertext` --
ciphertext where `message` is non-empty, raw keystream where it is empty,
matching `TestChaCha20`'s own two modes. The regex that produced it is
not committed -- a one-off pass over C++ source is not a tool -- and what
re-derives the file is reading those calls again.

Not vendored as the file itself because there is no data file upstream:
the vectors are arguments to a C++ function call, so the blob above is
that source file, and the weekly re-check reports a case added to it.
The move from `dbbb780af02d` to `b388f9bd0d2b` adds lines to
`crypto_tests.cpp` inside `BOOST_AUTO_TEST_CASE(muhash_tests)` alone;
none of them touches `TestChaCha20`, so the ChaCha20 vectors above are
unchanged.

### `tests/_data/muhash_vectors.json`

```text
repo    bitcoin/bitcoin
path    src/test/crypto_tests.cpp
commit  b388f9bd0d2bcc259d488638d479ba09a30ba040  2026-09-17
blob    2fdb83576e984dfaa19c17629f70bc425dc6d796
pulled  2026-09-21
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically, off the same source file above.
`muhash_tests`' own three numeric checks: the
`FromInt(0)*FromInt(1)/FromInt(2)` cancellation (`insert`/`remove`,
`digest_uint256_hex`, a `uint256{"..."}` literal -- reversed relative to
the raw digest it is compared against, `uint256.h`'s own "Hex
representation" comment is where that convention is stated), the
serialization vector (`ser_exp`) and the overflow vector (`ss_max`'s
`DataStream` input, and `out4`'s digest read through `HexStr` directly
rather than `GetHex()` -- **not** reversed, the one place in this file the
two conventions differ, confirmed against `crypto_tests.cpp`'s own two
different assertion macros rather than assumed uniform). `FromInt(i)` is
expanded here to the full 32-byte element (`i` then 31 zero bytes) each
vector inserts or removes, rather than left as the bare integer
`crypto_tests.cpp` passes to its own local helper, since this file has no
such helper to call.

What `b388f9bd0d2b` adds to `muhash_tests` is a regression test for that
same commit, *crypto: Fix MuHash3072 division by itself*:
an aliasing defect in `MuHash3072::operator/=`, where `div.m_numerator`
read after the first `Multiply` call could already be the mutated value
whenever `div` aliased `*this`. `MuHash3072` in `src/btclib/muhash.py`
defines no `__mul__`, `__imul__`, `__truediv__` or `__itruediv__` and no
accumulator-by-accumulator arithmetic of any spelling, so there is no
operation in this tree the added case would be a vector for.

Both files are read by `tests/muhash_test.py`.

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
read whole: every row carries a height, a block hash and a full
serialized block before its filter columns, and `blockfilters_test.py`
reads all of them. All ten blocks parse under the full validity check,
round-trip byte for byte, hash to the hash the row states, and the six at
or above testnet's BIP34 activation height commit the height the row
states — in the bytes Core builds, `assert_valid_coinbase_height`
comparing them. The four below it commit nothing, which is what makes the
file the vector for the activation gate as well.

The filter columns are what `btclib.block.block_filter` is held to: the
previous output scripts a filter needs and a block does not carry, and
then the two answers, so every basic filter of the file is rebuilt from
its block and reproduced octet for octet, and every basic header is
chained onto the previous header the row states. Vendoring the file
whole is what made that possible without a second pull — and it is what
the naming section above asks for anyway, a btclib-named extract of the
block column having no upstream name to be compared against.

The ten are testnet, where the four blocks of `tests/block/_data/` are
mainnet, and Core picked them for the shapes their scripts have: a
coinbase output script no parser can read, an output paying to an empty
script and a transaction spending from one, duplicate pushdata, witness
data, and genesis. None of them is invalid — every row is a block the
chain accepted.

### Not vendored as a file: the message types of Core's `NetMsgType`

```text
repo    bitcoin/bitcoin
path    src/protocol.h
commit  fad753611b5c074f38120fd9c1a87e37cc44bf6a  2026-08-05
pulled  2026-09-03
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. `tests/p2p/core_commands_test.py` holds every
name that namespace declares, in the order it declares them, and asserts
the census both ways: a message type Core has is one `src/btclib/p2p/`
carries or one that module names under the issue deciding otherwise, and
a command this package carries is Core's or is named there as one Core
dropped.

Not vendored as a file because there is no file: the names are string
literals in a C++ header this project cannot compile, and the same header
declares the service flags and the inventory type codes, so its bytes
answer about far more than the message types. What the pin buys instead
is the upstream re-check: a message type added to that namespace moves
the commit, and the weekly run says so.

`test/functional/test_framework/p2p.py`'s `MESSAGEMAP` is the rejected
alternative, and it is the list a census here has been run against
before. The two hold the same names, compared on 2026-09-03, and the
header is what decides: `src/net_processing.cpp` reads the protocol off
`NetMsgType`, where the map is the Python functional test framework's own
dispatch and reads nothing.

Not carried, and named as such: `filterload`, `filteradd` and
`filterclear`, BIP37's bloom set. `merkleblock`, which is what a peer
sends back, is carried:
[ISS 1120](https://github.com/btclib-org/btclib/issues/1120) is where
that line is argued, and the transcription points at it rather than
restating it.

Carried and not Core's: BIP61's `reject`, of which Core removed both
directions in `bitcoin/bitcoin#15437`. `src/btclib/p2p/reject.py` says
why a codec for it is here anyway, and the pin is what would make Core
declaring the name again a red run rather than a stale sentence.

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

## bitcoin-core/secp256k1

### `tests/_data/secp256k1_symbols.txt`

```text
repo    bitcoin-core/secp256k1
path    src
commit  46db787112beabdb5e17e0dc35680716f1057e7b  2026-09-11
pulled  2026-09-10, refreshed 2026-09-14
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically: every `secp256k1_*` name the
pinned tree's own `src` spells, sorted and deduplicated. The pin stands
for a directory rather than for one upstream file, which is why the
block above carries no `blob` line and why what the weekly workflow
reports on it is a commit touching `src` — what a name added there or
taken away from it looks like from outside.

```shell
commit=<the pin this entry gives>
```

```shell
git grep -ohP '(?<![A-Za-z0-9_])secp256k1_[a-z0-9_]+' "${commit:?}" -- src \
    | sort -u
```

The names and not the headers holding them, because what reads the file
asks whether upstream has a name and never what its signature is:
`tests/upstream_symbols_test.py` refuses a docstring crediting
libsecp256k1 with a name that library does not have, `secp256k1_ecdsa_sign`
passing and secp256k1-zkp's `secp256k1_ecdsa_s2c_opening` failing. A copy
of the headers would answer that for the published part of the family and
leave C prototypes to be re-pinned for the rest of it.

`src` and not `include` for the same reason. `include` is what the
library publishes, where a credit names what is read: ellipticcurves'
`curves.curve` names `secp256k1_ge_x_on_curve_var` and its
`number_theory` names `secp256k1_ctz64_var`, which are that library's
own and are declared in no header of `include`, only in one under `src`.
Nothing is lost at the other end — every name `include` declares is
spelled in `src` too, the difference being names a header comment wraps
in prose rather than declares.

The revision is one of bitcoin-core/secp256k1's own, and not the one the
bindings vendor. `btclib-secp256k1` compiles the library a caller loads
from a submodule of that repository, so what the suite links is the
submodule of the release `uv.lock` resolves:

```shell
version=<the btclib-secp256k1 version `uv.lock` resolves>
```

```shell
gh api \
    "repos/btclib-org/btclib-secp256k1/contents/secp256k1?ref=v${version:?}" \
    --jq .sha
```

A name upstream has added since that revision is in this set and not in
the library the suite runs against, and a name upstream has renamed away
is in that library and not in this set. The names are what the entry's own
re-derivation prints when it is run again at the submodule's revision
and compared with the vendored set. `comm` compares byte for byte on
input it takes as already sorted, so the vendored side is sorted again
under the collation the left side is being built in rather than trusted
to be in it: with the file's own order, a `sort` of another collation
answers a longer difference, and the `comm` macOS ships prints nothing
to say so.

```shell
submodule=<the sha the call above prints>
symbols=<the path to `tests/_data/secp256k1_symbols.txt`>
```

```shell
git grep -ohP '(?<![A-Za-z0-9_])secp256k1_[a-z0-9_]+' "${submodule:?}" \
    -- src | sort -u | comm -3 - <(sort "${symbols:?}")
```

Upstream is what the set is of, because that is the read a credit asks
for: `tests/upstream_symbols_test.py` refuses a credit a reader cannot
follow, and following one is a read of bitcoin-core/secp256k1's source.
Pinning to the submodule would answer for the library the bindings ship
and give that up — a renamed-away name would stay in the set, so a
credit spelling it would pass and land its reader on a function upstream
does not have. What neither pin answers is whether the installed
bindings expose a name, that being a fact about their own surface.

## Other projects

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

A block of values is cited inline instead, small enough to read where
it is used, pinned to `fbbe9245` (2023-04-27), the tip of its path:

- the six nBits-to-difficulty pairs of
  `Test_CBlockHeader.test_calc_difficulty`, in
  `bitcoin/tests/test_core.py`, read by `tests/block/block_test.py`.
  btclib holds them as the hex the header field carries rather than the
  int upstream reads them as.

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

Verdict: **recorded**, except `block_481824.bin`, which is derived rather
than returned by any call (below).

`bitcoin-cli getblock <hash> 0` returns the first three and
`block_481824_complete.bin`. It does not return `block_481824.bin`: that
is the same block serialized *without* witness data, as a pre-segwit node
sees it, which no RPC hands over. It is derivable —
`Block.parse(complete).serialize(include_witness=False)` reproduces it
byte for byte, checked — and that is how to regenerate it.

### `tests/tx/_data/*.bin` — segwit transactions

```text
txid   d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970
wtxid  fa54c948e34e30d4196a560036ff6ac7e306906d189760a066edd4caf571776b
size   4,740 bytes, vsize 1,471, 8 inputs, 1 output
pulled 2020-12-02
```

Verdict: **recorded**. The file is named after the txid, and `Tx.parse`
recomputes it, so a corrupted copy announces itself. `bitcoin-cli
getrawtransaction <txid>` returns these bytes, given a node with the
transaction index.

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
txid says where it came from, and re-deriving it is what checks the copy.
The txid stands in a fence of its own, the verbosity argument having to
follow it; the fence below reads it as `${txid:?}`, the shell's
must-be-set form, so a paste of that fence alone fails naming the
variable.

```shell
txid=<the txid the entry gives>
```

```shell
bitcoin-cli getrawtransaction "${txid:?}" 2 \
    | jq -r '.vout[<n>].scriptPubKey.hex'
```

Any explorer answers the same question — Esplora's
`api/tx/<txid>` carries the same hex under `vout[n].scriptpubkey`, which
is where this copy came from, no node with a transaction index being at
hand. The heights are the issue's own, and `getblockhash`/`getblock`
confirm them.

## Not vendored from anywhere

### `tests/_data/gettxoutsetinfo_regtest.json`

```text
program   bitcoind v31.1, the tag at bitcoin/bitcoin@9be056a8a7
chain     regtest, started with -coinstatsindex=1
calls     getblockhash <height>
          getblock <hash> 2
          gettxout <txid> <n> false
          gettxoutsetinfo muhash <height>
recorded  2026-09-04
```

Verdict: **recorded**. There is no upstream file and no repository: this
is one throwaway regtest chain, the outputs it left unspent, and what
`gettxoutsetinfo` reported about the set they are. Nothing upstream will
ever refresh it.

It is here because nothing in this tree can say `btclib.coinstats` is
right. `bogo_size` reproduces no wire size and `tx_out_ser` no storage
format, so an assertion written from btclib's own answer would say only
that the answer has not changed; a node's `gettxoutsetinfo` is the one
thing that says more, and a wrong byte in either shows up there as a
plausible number rather than as an error.

**What the node was asked.** The `gettxoutsetinfo` key is that reply
verbatim, taken at the tip height -- naming a height is what makes Core
answer from `coinstatsindex`, which maintains those numbers
incrementally, rather than by scanning the set. `utxos` is every output
`gettxout` answered for, which is Core's own set: the value and the
script are that reply's own, and the height and the coinbase bit come
from the `getblock` the transaction sits in. `unspendable_outputs` is
what `gettxout` answers null for and no transaction ever spent -- an
OP_RETURN output, and each block's own witness commitment -- read from
`getblock` alone, Core's set having never held either.

**The amounts are strings** because json carries no exact decimal: the
digits are the ones `bitcoin-cli` printed, and `tests/coinstats_test.py`
reads them through `Decimal` and `btclib.amount.sats_from_btc`.

**The genesis coinbase is in neither list**, Core excluding it from the
set by hand -- the recorded reply reports its value as
`total_unspendable_amount`.

**Recording another** is `tests/integration/coinstats_test.py`, which
builds a chain of this shape against a live `bitcoind`, walks it with
the calls above and makes the comparison the unit test makes against
this file: re-recording is that test writing down what it collected. So
the procedure is a test rather than a note here. The chain is not
reproducible byte for byte -- the addresses, and so the txids, are
whatever the node's wallet minted -- so a re-recording is a new file
rather than a refreshed one.

## What is not pinned, and why

- **`tests/script/_data/script_assets_test.json`** has a commit, but
  in a repository that rewrites its history. The blob SHA-1 is the pin
  that will still resolve next year.
- **The transcribed files** are pinned to a prose revision, or, where the
  upstream is a source file rather than a document, to that file's blob;
  neither makes "identical" a claim that can be made about them. What was
  checked is stated in each entry: matching every value verbatim against
  the pinned text, or a check the entry states on its own.
- **Nothing here is enforced by the suite.** No hook re-fetches an
  upstream and no test compares a blob, and that is a deliberate stopping
  point: a network call in the test suite would trade a documented drift
  for a flaky one. Where a pin goes stale is
  `.github/workflows/vendored-vectors.yml`'s to say instead, weekly and
  outside the suite, and it opens an issue rather than refreshing
  anything -- which vector to take next is a decision. What it does not
  reach is an entry whose `behind` already reads other than 0, a gap
  somebody has decided not to close being one it would report every week.

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
git ls-files 'tests/_data/*' 'tests/*/_data/*' | grep -cv 'README.md'
```

Against a pinned upstream blob:

- identical byte for byte: `taproot_test_vector.json`,
  `sig_hash_legacy_test_vectors.json`, `script_tests.json`,
  `tx_valid.json`, `tx_invalid.json`, `key_io_valid.json`,
  `key_io_invalid.json`, `base58_encode_decode.json`, `siphash.json`,
  `blockfilters.json`, `checkblock_valid.json`, `checkblock_invalid.json`.
- identical but for a trailing newline: `script_assets_test.json`.
- JSON-equal, reformatted: `signmessage.json`.

Not checked byte for byte against one:

- transcribed, every value matched either in the pinned text or, for a
  source file, by the check the entry itself states:
  `bip67_test_vectors.json`, `chacha20_vectors.json`,
  `muhash_vectors.json`, `secp256k1_symbols.txt`.
- chain data, identified by block hash or txid: the blocks and
  transactions under `tests/block/_data/` and `tests/tx/_data/`, and
  `unspendable_script_pub_keys.json`, which is scripts rather than whole
  transactions and so is the one that cannot recompute its own
  identifier.
- not vendored: `gettxoutsetinfo_regtest.json` (btclib's own).
