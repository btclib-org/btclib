# Vendored test vectors

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

## Re-checking a pin

```shell
git hash-object tests/ecc/_data/bip340_test_vectors.csv
gh api repos/bitcoin/bips/git/trees/<commit>:bip-0340 \
    --jq '.tree[] | select(.path == "test-vectors.csv") | .sha'
```

The comparison is on git blob SHA-1, not sha256: it is what a tree entry
already carries, so nothing has to be downloaded, and `git hash-object`
reproduces it locally. Not the contents API, which is the obvious
alternative and caps out — `script_assets_test.json` is 9 MB.

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
commit  afa13249ed45826c2d7086714026c9bc1ccbf963  2020-08-20
blob    a1a63e1283362255e84a36198d45f95c3e7c90ce
pulled  2020-04-04, refreshed 2020-11-22, edited 2020-12-08
behind  1 revision
```

Verdict: **edited**. Columns 1 to 7 — every value the test asserts on —
are identical to the pinned blob. Two things differ:

- line endings: upstream is CRLF, our copy LF.
- the comment column of vectors 11, 12 and 13, where our copy reads
  `sig[:32]`, `sig[:32]`, `sig[32:]` against upstream's `sig[0:32]`,
  `sig[0:32]`, `sig[32:64]`. Not an older upstream revision: btclib
  commit ca48c151, "replaced `[0:` with `[:`", was a repository-wide
  substitution that reached into the vendored file. The comment column is
  only the test id, so nothing is being asserted wrongly.

The one revision since, `200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb`
(2023-04-20), adds four vectors we do not have: 15 cases against 19.

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
behind  16 revisions, none of which touches the vectors
```

Verdict: **transcribed**. BIP32 ships its vectors as prose, so there is
no upstream file and no byte comparison to make. All four seeds and all
34 extended keys of test vectors 1 to 4 appear verbatim in the pinned
text, and the derivation counts match: 6, 6, 2, 3.

The pin is the commit that *added* test vector 4 rather than the one
current when btclib transcribed it: it is the earliest revision holding
all 34 keys, and the parent holds 28, which makes the pin checkable
rather than merely plausible.

### `tests/bip32/_data/bip32_invalid_keys.json`

```text
repo    bitcoin/bips
path    bip-0032.mediawiki
commit  ee2e0598206b8b8a16555a14b8f0c0a70105f93e  2020-05-16
pulled  2020-05-16, error strings last changed 2026-07-30
behind  the 16 keys are unchanged on master
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
commit  754b77a915007e96fca3b9440e7ddd4498ccae83  2021-04-08
pulled  2020-11-15, extended 2021-08-03
behind  53 revisions, mostly prose
```

Verdict: **transcribed**, subset. All 31 psbts we hold — 19 invalid, 8
valid, 4 signer check failures — appear verbatim in the pinned text,
which holds about 42 in all: the walk-through psbts of the creator,
updater, signer and finalizer roles are not vendored.

The pin is not the revision current when the file was first vendored.
Two of our psbts are absent from that one (`c12af49c`, 2020-11-15) and
from every revision up to 2021-04-08, which is when "BIP 174: Add test
vectors for additional unsigned tx serialization" landed; the btclib
commit that added them is 8391925f, 2021-08-03. So the file was
transcribed twice, and only the second pin covers all of it.

### `tests/psbt/_data/bip371_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0371.mediawiki
commit  4ab7faad749856bfc8178f9a12f4c1a8d40f632f  2023-02-15
pulled  2023-07-07
behind  8 revisions
```

Verdict: **transcribed**, complete. All 17 psbts in the pinned text are
in our file and all 17 of ours are in the text — 11 invalid, 6 valid.

### `tests/script/_data/bip67_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0067.mediawiki
commit  b7090922b5e364409e4ddcd1558d85f2dd434c16  2020-04-28
pulled  2020-05-31
behind  10 revisions
```

Verdict: **transcribed**. All five groups — their 15 public keys and
their five p2sh addresses — appear verbatim in the pinned text.

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
commit  facd7dd3d1f9d51e1133974ff69eeb48f5ae282b  2020-07-11
blob    724789bbf9f9cc08de0e92820b74468bc6213576
pulled  2023-07-08
behind  19 revisions
```

Verdict: **identical** to that blob — but note the three-year gap
between the upstream revision and the day btclib committed it. Upstream
had moved on to `34d0e07e` (2022-02-10) by then, so the copy was not
taken from Core's tip at vendoring time; it came from an older snapshot,
carried along in the branch that became PR #83.

### `tests/script_engine/_data/tx_valid_legacy.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/tx_valid.json
commit  8cac2923f57ac33848ff41b74c3be520b75936df  2021-03-31
blob    b874f6f26ca776f1e644e56637389d5d07ebe580
pulled  2023-07-08
behind  3 revisions
```

Verdict: **identical**. The `_legacy` in the name is not a subsetting:
the file is Core's `tx_valid.json` entire. It names the engine the
vectors feed — `tests/script_engine/test_transactions.py` filters by
flags at collection time — and reads as a promise about the contents that
the file does not keep.

### `tests/script_engine/_data/tx_invalid_legacy.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/tx_invalid.json
commit  fa80a11c3bb995ee15d4b0b9ad64148f6332ad42  2021-05-01
blob    a47bc8f3666d7bf5d14b704943d383f06040c657
pulled  2023-07-08
behind  1 revision
```

Verdict: **identical**. Same naming remark as above.

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
`tests/test_descriptors.py` records — which is the point of the file: the
checksums are an independent oracle, so recomputing them with btclib
would void the test.

Nothing to refresh from upstream. A new descriptor needs a checksum from
somewhere other than btclib.

## bitcoin-core/qa-assets

### `tests/script/_data/tapscript_test_vector.json`

```text
repo    bitcoin-core/qa-assets
path    unit_test_data/script_assets_test.json
commit  1af2e9ae7c80f2c91e94f08466f1356cc79a713f  2025-07-23
blob    b7428daa8fcc85cc3e7261c2fdc1425d00ad5c83
pulled  2021-08-03
```

Verdict: **identical but for a trailing newline** — our 9,242,563 bytes
are that blob's 9,242,562 plus the `\n` the `end-of-file-fixer` hook
added. 2243 vectors, in the same order.

Two caveats, and the second is the one that matters.

The file is not in bitcoin/bitcoin: it is *generated*, by
`test/functional/feature_taproot.py --dumptests`, and Core keeps the dump
in qa-assets rather than in tree. That is why the citation in
`tests/script/test_sig_hash_taproot.py` (bip-0341) does not lead to it.

The commit is a weak pin. The whole visible history of that path is three
commits, all stamped within a second of `2025-07-23T19:45:18Z`, which
cannot be when a 2021 dump was added: qa-assets prunes its history — the
visible commits are the prune, not the additions — and the SHA will not
survive the next prune. The blob SHA-1 above will. Current tip of the
path, `b33d85102d169b54d966ea315ad81a636680aefa`, holds our 2243 vectors
verbatim and in order plus one appended (`output/invalid_x`), so a
refresh is an append.

## Other projects

### `tests/ec/_data/pubkey.json`

```text
repo    rustyrussell/secp256k1-py
path    tests/data/pubkey.json
commit  ead56b92a8229e16941318d953c6444268beaa1a  2015-09-18
blob    8aaa0c59d182b126cfedc505473dbdc961aaea1a
pulled  2023-01-16
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 349 vectors, JSON-equal to the upstream blob;
ours is pretty-printed at four spaces.

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

### `tests/ecc/_data/bms.json`

```text
repo    petertodd/python-bitcoinlib
path    bitcoin/tests/data/signmessage.json
commit  0b8318cc36e86508a3153342290b31b614a1be7f  2015-06-30
blob    31d619867d1ab2dcd8358868ac501b35ebb9c129
pulled  2020-01-04
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 200 vectors, JSON-equal; renamed on the way in.
`tests/ecc/test_bms.py` cites `bitcoin/tests/test_data/bms.json`, which
is upstream's path for neither the directory nor the file: it is
`bitcoin/tests/data/signmessage.json`. The citation should be corrected.

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
P-192, P-224, P-256, P-384 and P-521, as `tests/ecc/test_rfc6979.py`
says. An RFC number is already an immutable reference — there is no
commit to pin, and `rfc-editor.org/rfc/rfc6979` is the document.

Pulled 2020-05-08.

### `tests/mnemonic/_data/electrum_test_vectors.json`

**Unresolved, and probably unresolvable.** These 12-word mnemonics with
their root keys and addresses are in no upstream repository: a GitHub
code search for the first mnemonic returns btclib and one fork of btclib,
and they are not in spesmilo/electrum's `tests/`. They were produced by
running Electrum, which is what `tests/mnemonic/test_electrum.py` implies
with its "FIXME is the following mnemonic obtained in Electrum".

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
- **`tests/script/_data/tapscript_test_vector.json`** has a commit, but
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
  `script_tests.json`, `tx_valid_legacy.json`, `tx_invalid_legacy.json`.
- 1 identical but for a trailing newline:
  `tapscript_test_vector.json`.
- 4 JSON-equal, reformatted: `pubkey.json`, `ecdsa_sig.json`,
  `ecdsa_custom_nonce_sig.json`, `bms.json`.
- 1 data-equal with a locally edited comment column and LF endings:
  `bip340_test_vectors.csv`.
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

- **Two citations in the test modules are wrong.**
  `tests/ecc/test_bms.py` names `bitcoin/tests/test_data/bms.json`; the
  file is `bitcoin/tests/data/signmessage.json`.
  `tests/script/test_script_pub_key.py` cites `en.bitcoin.it` for BIP67
  rather than the BIP.
- **`tx_valid_legacy.json` and `tx_invalid_legacy.json` are not
  subsets**, so their names mislead. Renaming them touches one test
  module, `tests/script_engine/test_transactions.py`.
- **`bip340_test_vectors.csv` is four vectors behind** and its comment
  column was altered by a repository-wide substitution. Refreshing from
  `200f9b26` fixes both and reverts the `sig[:32]` spelling.
- **`script_tests.json` is 19 revisions behind** and was already three
  years old when vendored.
- **`tapscript_test_vector.json` is one vector behind**, appended
  upstream.
