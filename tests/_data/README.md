# Vendored test vectors

This file is about `tests/**/_data/`, plus the one shipped data file that
nothing else pins: `src/btclib/mnemonic/_data/wordlist.txt`, SLIP-0039's word
list. It is here because a word list is the most load-bearing vendored
file there is -- every share ever written with it decodes through it --
and because, unlike `english.txt`, it has no byte-identical copy under
`tests/` for an entry to name instead. The package's other word lists
have no entry because each is already pinned somewhere else or not at
all: `english.txt` through the test copy below,
`electrum_old_english.txt` and `electrum_portuguese.txt` through the
pins `src/btclib/mnemonic/electrum.py` carries beside the constants naming
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
  `bip371_test_vectors.json`, `bip373_test_vectors.json`,
  `bip67_test_vectors.json` and `bip85_test_vectors.json` are transcribed
  from mediawiki prose. There is no upstream file, so the name is ours by
  necessity.
  `bip375_test_vectors.json` beside them is the exception that shows the
  rule holds: BIP375 does publish a file, and its name is that one, so
  there the convention below and the convention above agree.
- `bip39_test_vectors.json` is trezor's `vectors.json` byte for byte, and
  keeps the btclib name anyway: `vectors.json` is taken in the very same
  directory, by SLIP-0039's own file of that name, which is a different
  upstream's. The blob id in its entry is what the naming cannot fool
  here.
- `descriptor_checksums.json` and `rfc6979.json` are transcribed from
  prose, and `electrum_test_vectors.json`,
  `electrum_language_vectors.json`, `btclib_test_vectors.json` and
  `fakeenglish.txt` are btclib's own: no upstream file for any of them,
  so no upstream name to take.
- `WYCHEPROOF_COPYING` is upstream's `LICENSE`, renamed because a file
  of that name inside a directory of vendored vectors would read as
  licensing all of them. Its entry says so, and carries the upstream
  name.
- the seven under `tests/fetch/_data/` are response bodies, and a
  response has no name at all. Each takes the rpc method or the endpoint
  path that produces it, which is the closest thing to an upstream name
  they have and the one a re-check would type into `bitcoin-cli` or a
  url.

`btclib_test_vectors.json` is where that convention says the most, and it
is a naming rule of its own: the prefix of a psbt vector file names the
authority the cases answer to — `bip174_`, `bip370_`, `bip371_`,
`bip373_`, `bip375_`, and `btclib_` for the ones btclib composed, which no
BIP publishes and no refresh will ever reach. A file so named cannot be
mistaken for a copy of something — and `bip375_test_vectors.json` is the
one of the five that *is* a copy, upstream publishing a file of that very
name.

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

Every entry was last re-checked against its upstream on 2026-07-30, and
whatever had drifted was refreshed, so `behind` is 0 wherever a refresh
was possible at all. The files vendored since are the exception by date
alone, all of them taken at the tip of their path on 2026-08-02, which is
what their `pulled` says: the eight BIP327 files, the three Core files
`key_io_valid.json`, `key_io_invalid.json` and `base58_encode_decode.json`,
and the two python-bitcoinlib block files added here; Core's
`blockfilters.json`, the psbts of BIP370 and BIP373 and the two BIP324
csv files followed on 2026-08-03, at the tip of their paths too, the
two BIP322 files on 2026-08-08, and the Wycheproof files with the licence
beside them, the two BIP374 csv files, BIP352's
`send_and_receive_test_vectors.json` and BIP375's
`bip375_test_vectors.json` on 2026-08-13, and Core's `siphash.json` on
2026-08-20. BIP375's `bip375_test_vectors.json`, Core's
`miniscript_fixed_tests.json` pin and `descriptor_tests.cpp` pin, and
Wycheproof's `ecdsa_secp256k1_sha256_bitcoin_test.json` were pulled again
on 2026-08-25, each at the tip of its path that day, and Core's
`chacha20_vectors.json` and `muhash_vectors.json`, both transcribed from
`crypto_tests.cpp`, were pulled on 2026-09-03, at the tip of that path.

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
entry says so with our own blob alongside. Every csv file vendored from
bitcoin/bips is that case, and so far only those: `bip340_test_vectors.csv`,
the two BIP324 files and the two BIP374 files. A csv there is written on
Windows line endings often enough that it is worth expecting rather than
discovering -- `mixed-line-ending` rewrites the file with `--fix=lf` as it
is staged, so the blob to compare is never the one just fetched.

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
message of any size, and so do the bindings — `sign_custom` and `verify`
take one, and the 32-byte gate that used to send these four down the
Python path (issue 169) is gone. All four pass on either arithmetic:
`verify_` accepts each, and `sign_` reproduces each signature byte for
byte.

### BIP327 (MuSig2): eight files under `tests/ecc/_data/`

The vectors of `bip-0327/vectors/`, all eight of them, vendored whole
and under upstream's own names: `key_sort_vectors.json`,
`key_agg_vectors.json`, `nonce_gen_vectors.json`,
`nonce_agg_vectors.json`, `sign_verify_vectors.json`,
`tweak_vectors.json`, `det_sign_vectors.json` and
`sig_agg_vectors.json`. Each is pinned below in its own entry, one real
path per pin, rather than to one placeholder path shared by all eight:
a placeholder is not a path GitHub's own "commits touching a path" API
can be asked about, which is what kept every one of the eight out of
the weekly check. It also papered over a real difference between
them: six were untouched since the commit that added all eight,
`87394eaeb436d02e0a68b38a1e94bc526d50056e` (2023-03-27, "Add BIP327:
MuSig2 for BIP340-compatible Multi-Signatures"); `sign_verify_vectors.json`
was fixed once since, at `508e3a6a40a6e73c73cbfa8a33aa18a2bc7b9d91`
(2024-05-14, "Fix the four test vectors"); and `sig_agg_vectors.json`
once more again, at `1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439`
(2024-07-19, "bip327: minor fixes") -- the one commit the shared
placeholder cited as the tip of all eight paths, when it is the tip of
only that one.

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
the tip of that path): `src/btclib/ecc/musig2.py` follows it function for
function, and copies four of its error message strings verbatim
because the `error.message` field of a case is compared byte for byte.
That file is not vendored — it is an implementation, not data, and
btclib's is the one under test.

### `tests/ecc/_data/key_sort_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/key_sort_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    de088a746e27953614b9f5394553911fb2c86d59
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/ecc/_data/key_agg_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/key_agg_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    b2e623de60f302c4004a6d656581bdba1f4e1e05
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/ecc/_data/nonce_gen_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/nonce_gen_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    ced946f3efd9f80cb1a3819939f2b39de2061e42
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/ecc/_data/nonce_agg_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/nonce_agg_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    1c04b8818f340a5fe2e10eaf73c17a2c9e020f46
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/ecc/_data/sign_verify_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/sign_verify_vectors.json
commit  508e3a6a40a6e73c73cbfa8a33aa18a2bc7b9d91  2024-05-14
blob    f71c8dd9d935c8c5f398e6a3888943e1e68b729d
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/ecc/_data/tweak_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/tweak_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    d0a7cfe832bfe22375af0d64cd5d0dbb350592e0
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/ecc/_data/det_sign_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/det_sign_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    261669ccd01cd4098fa97045f3d32654f64a48af
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/ecc/_data/sig_agg_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/sig_agg_vectors.json
commit  1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439  2024-07-19
blob    519562c343b6e4bf686ba6e3eda8cee5c8e8b55d
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### BIP324 (ElligatorSwift): two files under `tests/ecc/_data/`

`ellswift_decode_test_vectors.csv` and `xswiftec_inv_test_vectors.csv`,
under upstream's own names, both genuinely tipped by the same commit --
unlike BIP327 above, there is no exception a shared pin would have
papered over here. Each is pinned below in its own entry, one real path
per pin, rather than to one placeholder path standing in for both: a
placeholder is not a path GitHub's own "commits touching a path" API can
be asked about, which is what kept the pair out of the weekly check.

### `tests/ecc/_data/ellswift_decode_test_vectors.csv`

```text
repo    bitcoin/bips
path    bip-0324/ellswift_decode_test_vectors.csv
commit  cc177ab7bc5abcdcdf9c956ee88afd1052053328  2023-01-11
blob    1bab96b721e2f3ab90142c318523551eb520f753
pulled  2026-08-03, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings** — upstream is CRLF and this
repository is LF throughout, which `mixed-line-ending` enforces with
`--fix=lf`, so our blob is `bcc5b319` rather than the one above, the
same exception `bip340_test_vectors.csv` above documents.

### `tests/ecc/_data/xswiftec_inv_test_vectors.csv`

```text
repo    bitcoin/bips
path    bip-0324/xswiftec_inv_test_vectors.csv
commit  cc177ab7bc5abcdcdf9c956ee88afd1052053328  2023-01-11
blob    138c4cf85c040785a45c6552c0169c8c12fd3cfc
pulled  2026-08-03, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the same exception, our
blob `135958f6` rather than the one above.

The two files test the two halves of the map, and both halves are
btclib's own Python: `tests/ecc/ellswift_test.py` runs the decode file
against `_xswiftec` and the inverse file against `_xswiftec_inv`, whose
eight `case` columns are eight assertions per row rather than one — an
empty cell is a case with no preimage, and asserting that it *has* none
is what keeps a permissive inverse from passing. The comment column of
each row names the branch it exercises (`valid_x(x1)`, `non_square(s)`,
`t>=p`, `info[v=0]`), which is what makes the two files a branch
inventory and not a sample.

Neither file covers `create` or `encode`: those pick one of up to eight
preimages at random, so there is no vector to hold them to, and what the
suite asserts instead is the round trip against the bindings — the
authority named in the entry that has no file to cite.

`bip-0324/packet_encoding_test_vectors.csv` is the third file of that
directory and is **not** vendored: it is the v2 transport's, which btclib
does not implement.

### BIP374 (DLEQ): two files under `tests/ecc/_data/`

`test_vectors_generate_proof.csv` and `test_vectors_verify_proof.csv`,
under upstream's own names, which is the whole of `bip-0374/`'s vector
set. The two are pinned separately below and their pins differ, which is
the reason a shared one is not offered: the verification file was
regenerated seven weeks after the generation file, and one pin would have
had to be wrong about one of them.

The names are unusually bare for a vendored file -- nothing in either
says BIP374 -- and they keep them anyway, the naming rule above being
that upstream's name is the one thing a citation cannot drift away from.

### `tests/ecc/_data/test_vectors_generate_proof.csv`

```text
repo    bitcoin/bips
path    bip-0374/test_vectors_generate_proof.csv
commit  24b4354e64e162ad0154d54f12b29602fe562d9f  2025-02-27
blob    f913508df1ed633e9dde3de30b49f3c8c4e595d1
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings** — upstream is CRLF and this
repository is LF throughout, which `mixed-line-ending` enforces with
`--fix=lf`, so our blob is `78d78704` rather than the one above, the same
exception `bip340_test_vectors.csv` above documents.

All 11 vectors, all eight columns: five over a generator that is not
secp256k1's, three over secp256k1's own, and three failure cases -- a zero
scalar, a scalar equal to n, and a B at infinity, which the file spells
`INVALID` in the proof column and `INFINITY` in the point column.

### `tests/ecc/_data/test_vectors_verify_proof.csv`

```text
repo    bitcoin/bips
path    bip-0374/test_vectors_verify_proof.csv
commit  6ceafc51b17665f7cb13c8e2b9ee6354b9d374bd  2025-04-16
blob    8076e8136ff1b5e03601ba7a339bb161029026ad
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the same exception, our blob
`4ffe455a` rather than the one above.

All 15 vectors: the eight successes are the eight proofs of the file
above, read back, and the seven failures are five permutations of A, B and
C, a bit flipped in the proof, and a bit flipped in the message -- so the
pair covers both directions over one set of keys, and a permutation the
challenge would have accepted is a defect the generation file alone could
not show.

Three BIP374 failure conditions have no vector in either file and are
covered by `tests/ecc/dleq_test.py` instead: `s >= n`, and R1 or R2
landing on infinity. None of the three is a proof anybody generates --
s is computed mod n, and an infinite R needs s == e over A == G or
B == C -- so upstream's generator produces none of them and the test
builds each.

### `tests/_data/send_and_receive_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0352/send_and_receive_test_vectors.json
commit  c2ac36f48f71615984087fd151f410457edfed72  2026-04-16
blob    3a189757ddbc90e5ec538d643f7ac238a51704e8
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. All 28 cases, both halves of each: one sending
sub-test and one receiving sub-test per case, except "use silent payments
for sender change", which has two receiving sub-tests -- the change output
and the payment.

The revision matters more here than the pin usually does. This file used
to publish the inputs and the final outputs and nothing between, and the
2026 revision added `input_private_key_sum`, `shared_secrets`, `tweak` and
`input_pub_key_sum`: an implementation can now be held to the value at
each step rather than told that its output was wrong.
`tests/silent_payments_test.py` asserts every one of them, which is why an
outpoint sorted wrongly, a missed taproot negation and a wrong label are
three different failures there instead of one.

Two of the 28 publish a null where a value would be: the sending half of
"input keys sum up to zero" has no private key sum, and the K_MAX case has
a sum and then a null shared secret, sending having failed before one was
derived. Both are the file saying that the step was never reached, and the
test reads them that way.

The K_MAX case is the largest by far and worth naming: 2324 recipients
sharing one scan key, which is one more than BIP352 allows, so sending
fails and the receiving half finds 2323 of the 2324 outputs -- the file
counting them with `n_outputs` rather than listing them, and it is the
only case that does.

Three BIP352 rules have no vector here and are covered by the test module
instead: the address versions (v31 refused, v1 through v30 read as far as
v0 defines them), the 1023-character bound, and the label range. The
vectors are all v0 addresses on mainnet.

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
commit  c0644a054fd1568ecbfc9c2b656ad5200b16ff74  2026-03-05
pulled  2020-05-08, vector 4 added 2021-08-25, re-pinned to the tip 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. BIP32 ships its vectors as prose, so there is
no upstream file and no byte comparison to make. All four seeds and all
34 extended keys of test vectors 1 to 4 appear verbatim in the pinned
text, and the derivation counts match: 6, 6, 2, 3.

The original pin was the commit that *added* test vector 4 rather than
the one current when btclib transcribed it: the earliest revision
holding all 34 keys, the parent holding 28, which made that pin checkable
rather than merely plausible. Re-checked against the tip on 2026-07-30
and again on 2026-08-06 — both times still test vectors 1 to 5 and no
sixth, every extended key in it one of ours, 48 matching the key
pattern: our 34 valid plus 14 of the 16 invalid, the other 2 being the
zero-prefix keys of test vector 5, which serialize outside it — the pin
above is now that tip, so the weekly automated check can carry it.

### `tests/bip32/_data/bip32_invalid_keys.json`

```text
repo    bitcoin/bips
path    bip-0032.mediawiki
commit  c0644a054fd1568ecbfc9c2b656ad5200b16ff74  2026-03-05
pulled  2020-05-16, error strings last changed 2026-07-30, re-pinned to
        the tip 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. All 16 invalid extended keys are exactly the 16
of BIP32 test vector 5 — no omissions, no local additions — both at the
pinned commit and on master today.

btclib is the upstream here, not the consumer: commit ee2e0598, "added
invalid extended keys vectors", is Ferdinando Ametrano's, and is what
first put these 16 keys into the BIP. The pin above is the tip of the
same path rather than that commit, so the weekly automated check can
carry it too; the second column of the file is btclib's own regardless —
it holds btclib error messages, which the BIP does not and should not
carry, and which change when the messages change. Refreshing from
upstream means refreshing the keys, never the messages.

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
commit  24e96e870fffaa257b465ce1f0370c14aac588e8  2026-01-12
pulled  2023-07-07, re-pinned to the tip 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete. All 17 psbts in the pinned text are
in our file and all 17 of ours are in the text — 11 invalid, 6 valid, the
same 17 on 2026-07-30 and again on 2026-08-06 when re-checked against the
tip. The two "PSBT_KEY_PATH_SIG" cases were renamed
"PSBT_IN_TAP_KEY_SIG" between the original pin and the tip, matching the
field's own name; the `description` of both is updated to match, the
`encoded psbt` of every case unchanged throughout.

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

### `tests/psbt/_data/bip375_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0375/bip375_test_vectors.json
commit  e726d13ade44e2184635935c84a83d4082da3a63  2026-08-13
blob    38511f65b4f100c4f56ac12371ebe4d8888f1e0d
pulled  2026-08-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical** -- upstream's file ends on a newline after its
closing brace, so `end-of-file-fixer` leaves it untouched as it is staged
and our blob matches the one above. `script_assets_test.json` and
`vectors.json` are the files that still document the "identical but for a
trailing newline" exception.

The only psbt vector file here that has an upstream file at all -- the
other five are transcribed from mediawiki prose -- so the `bip375_` prefix
is upstream's own name and this repository's naming rule at once, which is
the one place the two coincide. 42 psbts, 22 invalid and 20 valid, the
valid ones split between "can finalize" and "in progress".

Each case carries a `supplementary` object of private keys, public keys
and prevouts, and upstream's own notes say it is "for diagnostics and
should not be used for validation". `tests/psbt/bip375_test.py` does not
read it: what it reads is the psbt, and what it compares each field
against is the raw map entry the field came out of.

**Not compared byte for byte**, unlike every other psbt vector here, and
the reason is the file rather than btclib: the generator that produced it
writes the keys of a map in an order of its own -- PSBT_GLOBAL_VERSION
first where BIP370's psbts put it last, and an input map's outpoint fields
ahead of the rest -- while a psbt map has no normative order at all,
BIP174 requiring only that a key not repeat. So the comparison is one
level up: the maps read out of upstream's bytes and the maps read out of
btclib's hold the same set of pairs, and btclib's own bytes are stable
under a second parse. Measured on all 37 psbts that parse.

All 22 invalid psbts are refused and all 20 valid ones pass, and it takes
two test modules to say so: `tests/psbt/bip375_test.py` holds the codec to
the file -- the field shapes, which is five of the six "PSBT Structure"
cases -- and `tests/psbt/silent_payments_test.py` holds the two roles to
it, which is the other seventeen. Each invalid case's category is read off
its own description, so a psbt refused by the wrong check fails there
rather than counting as a pass; a valid case can carry a `checks` field of
its own instead, naming the one check it isolates itself to -- one case
does, "input eligibility: bare OP_2 script is not a segwit v2 witness
program".

**The file and the BIP disagree about one rule, and the file wins here.**
BIP375 says the codes of one scan key are sorted lexicographically to
determine the ordering of `k`; the vectors' output scripts are the ones
*output index* order derives. The case that decides it is published as
valid -- "two sp outputs - output 0 uses label=3 / output 1 uses label=1"
-- and its two spend keys are in descending order, so the two rules assign
`k` the other way round and only one of them reproduces the scripts the
file carries. Neither reading of "the codes" rescues the prose: sorting
the 66-byte info fields and sorting the bech32m address strings both order
that pair the same wrong way. Upstream's own
`bip-0375/validator/validate_psbt.py` walks index order too, so two of its
three artefacts agree and the prose is the outlier.
`test_the_k_ordering_is_the_output_index` pins that in both directions, so
a revision settling it the other way fails rather than passing quietly.

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

### BIP322 (signed messages): two files under `tests/_data/`

The two files of `bip-0322/`, vendored whole and under upstream's own
names: `basic-test-vectors.json` and `generated-test-vectors.json`. One
commit added both and one has touched them since — `3ab70c98`
(2026-04-10, "BIP-0322: turn test vectors into JSON, add more") and
`d77863fb` (2026-05-06, "BIP-0322: update test vectors"), which is the
tip of both paths — and each is pinned below in its own entry all the
same, a shared placeholder path being what kept eight BIP327 files out of
the weekly check.

Between them they are what `tests/bip322_test.py` runs: three
transaction hashes, eight *simple* signatures, ten *full*, three
*proof of funds*, and 36 error cases, with nothing left out and nothing
marked `xfail`. Two of the three proof-of-funds vectors were, until
issue 513: their psbts carry a funding transaction whose input is a null
tx_id with vout 0, which `OutPoint.assert_valid` refused and Bitcoin
Core's `CheckTransaction` accepts.

### `tests/_data/basic-test-vectors.json`

```text
repo    bitcoin/bips
path    bip-0322/basic-test-vectors.json
commit  d77863fb9e9be7829ad8bb51694b9ba80a786766  2026-05-06
blob    f32a5bf45ae8b19ca33d0763669f5718879c82f4
pulled  2026-08-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for the final newline** — upstream ends without
one and `end-of-file-fixer` adds it, so our blob is `2aefe430` rather
than the one above. The same case as `bip340_test_vectors.csv` and its
line endings: a hook that fixes in place makes the byte comparison
disagree in a way the entry has to record rather than hide.

The file is UTF-8 rather than ASCII, one of its three messages running
from Latin-1 accents through CJK to an astral-plane emoji, and
`tests/__init__.py`'s `load` is asked for that encoding.

### `tests/_data/generated-test-vectors.json`

```text
repo    bitcoin/bips
path    bip-0322/generated-test-vectors.json
commit  d77863fb9e9be7829ad8bb51694b9ba80a786766  2026-05-06
blob    4677eea4544b9fef4814c85640ff109a4d887264
pulled  2026-08-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for the final newline**, as above: our blob is
`1c061893`. Generated by
[btcd's BIP322 implementation](https://github.com/btcsuite/btcd/pull/2521),
which the BIP names as their source.

### `tests/_data/bip85_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0085.mediawiki
commit  6209768676bf85d7ef5ffb4055543d6286d79b96  2026-08-03
pulled  2026-08-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete. Every value in our copy appears
verbatim in the pinned text, and every vector the BIP publishes is in
our copy: the master root key, the two entropy cases of the
specification's own section with the derived key of each, the 80-byte
BIP85-DRNG read, the three BIP39 mnemonics, the hdseed WIF, the xprv,
the 64 hex bytes, the base64 and base85 passwords, the ten dice rolls,
and the three Nostr nsecs of application 128002'. `tests/bip85_test.py`
runs all of them.

RSA (828365') is the one application with no vector here, because the
BIP publishes none for it: it defines the path and says the key
generator should read BIP85-DRNG, leaving how the primes are found to
whatever library generates the key. `btclib.bip85` stops at the same
place, so there is nothing further to compare against.

Two of the BIP's fields are not what their name reads as, and
`tests/bip85_test.py` asserts them as the BIP prints them rather than as
the name reads: the DERIVED ENTROPY of application 32' is the second half
of the 64 bytes, the private key of the xprv, and that of 39' is already
truncated to what the sentence encodes.

### Not vendored as a file: BIP387's `multi_a()` vectors

```text
repo    bitcoin/bips
path    bip-0387.mediawiki
commit  24e96e870fffaa257b465ce1f0370c14aac588e8  2026-01-12
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, and cited inline rather than vendored: they are
descriptors and scripts read where they are used, in
`tests/descriptors_test.py`'s `BIP387_VECTORS` and `BIP387_INVALID`. Every
descriptor of the BIP's Test Vectors section is there with the
scriptPubKey it produces, at each index the BIP lists, and every invalid
one with the message btclib refuses it with — two of those refusals
answering the uncompressed key before the threshold the BIP was
illustrating, which the entries say. Each value was matched against the
pinned text on 2026-08-06.

### Not vendored as a file: BIP390's `musig()` vectors

```text
repo    bitcoin/bips
path    bip-0390.mediawiki
commit  7517a8b2ac8fdb13e586d0e139a7f5b87ceab994  2026-08-06
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete for both lists and cited inline, in
`tests/descriptors_test.py`'s `BIP390_VECTORS` and `BIP390_INVALID`: the
six valid descriptors with the scripts they produce at each index listed,
and all fourteen invalid ones with the message each is refused with. Five
further invalid cases there are btclib's own, for what the BIP states in
prose rather than listing — no nesting, no key origin in front of one, at
least one participant, no x-only participant, and a `musig()` where a tree
leaf belongs.

The pin is the tip and it is the day it was taken: that commit is
`bip390: fix missing parenthesis in test vector`, which closed the last
invalid descriptor's brackets, so a copy taken a day earlier would hold a
descriptor upstream no longer publishes. Ours is the fixed one.

One of the fourteen is refused for a reason of btclib's own rather than
the BIP's, and the entry in the module says so: a multipath `musig()`
holding multipath participants is refused because `parse` takes no `<a;b>`
step at all, `multipath_descriptors` being what expands them textually as
BIP389 defines.

### Not vendored as a file: BIP388's wallet-policy vectors

```text
repo    bitcoin/bips
path    bip-0388.mediawiki
commit  cfff9719405fa35113cab637958809824873750f  2026-04-15
pulled  2026-09-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete and cited inline in
`tests/descriptors/descriptors_test.py`'s `BIP388_VECTORS`: every valid
policy of the Test Vectors section, its template, its key-information
vector and the multipath descriptor the two compile to, checked branch by
branch against `wallet_policy_descriptor` and `wallet_policy_address`
rather than restated as an address of its own -- `multipath_descriptors`
and `parse` already answer for what a branch of that descriptor is. The
same vectors are read the other way too, in
`test_wallet_policy_reconstructs_bip388s_own_vectors`: `wallet_policy`,
given the receive and change `Descriptor` `multipath_descriptors` splits
that same descriptor into, rebuilds the vector's own template and
key-information vector, byte for byte. Four
of the Invalid policies section's nine are checked too, in
`test_bip388_invalid_templates`: the no-path, explicit-path,
cardinality-above-two and derivation-before-aggregation ones, each a
property of the template text alone. The other five are not:
out-of-order and skipped placeholders are a canonicalization
`wallet_policy_descriptor` does not need to enforce to compute one
address correctly; repeated keys and non-disjoint multipath steps for the
same placeholder need the two occurrences compared against each other,
which nothing here does across an `re.subn` callback; and a non-KP key
present in a template position is refused anyway, but by `parse`'s own
"use multipath_descriptors first" -- a coincidence of the raw `<0;1>`
text reaching it unconsumed, not a check this module makes. That one is
in the module too, as what it is.

### Not vendored as a file: BIP328's synthetic xpub vectors

```text
repo    bitcoin/bips
path    bip-0328.mediawiki
commit  24e96e870fffaa257b465ce1f0370c14aac588e8  2026-01-12
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete: all three aggregate keys, the
synthetic xpub each becomes and the participant keys each aggregates, in
`tests/bip32/bip32_test.py`'s `BIP328_VECTORS`. The keys of those vectors
aggregate **as written**, unsorted, which is what makes them worth holding
beside BIP390's: sorting before aggregation is BIP390's rule and not
BIP328's, and a `key_sort` applied here reaches none of the three
published keys. Matched against the pinned text on 2026-08-06.

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
commit  9be056a8a72b624dae9623b2f7bded92c2a21c91  2026-07-06
blob    b348793bfb6397ebde806961b6783b1540a33804
pulled  2026-09-03
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

### `tests/_data/muhash_vectors.json`

```text
repo    bitcoin/bitcoin
path    src/test/crypto_tests.cpp
commit  9be056a8a72b624dae9623b2f7bded92c2a21c91  2026-07-06
blob    b348793bfb6397ebde806961b6783b1540a33804
pulled  2026-09-03
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

### `tests/_data/miniscript_fixed_tests.json`

```text
repo    bitcoin/bitcoin
path    src/test/miniscript_tests.cpp
commit  e8691056c0140f8fa850fc6837dde915ebeb22cc  2026-08-03
blob    d593fc3bf813ac27dce422d596ae9bf4b8b9e777
pulled  2026-08-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically. One json object per `Test()` call
of the `fixed_tests` case, with the fields that call passes: the
miniscript, the script it compiles to under P2WSH and under tapscript, the
`TESTMODE_*` flags split into booleans, and the ops, stack, witness-size
and execution-stack numbers where the call gives them. The regex that
produced it is not committed -- a one-off pass over C++ source is not a
tool -- and what re-derives the file is reading those calls again.

The pin between here and the commit this file was previously pinned to
(`128456b62d5e`) touches none of those calls: every changed line is
`BOOST_CHECK(a && b && c)` split into one `BOOST_REQUIRE`/`BOOST_CHECK` per
condition, inside the "Misc unit tests" block below `fixed_tests`'s own
vectors, not inside a `Test(...)` call. The vendored JSON is unchanged.

Not vendored as the file itself because there is no data file upstream:
the vectors are arguments to a C++ function. The blob above is that source
file, so the weekly re-check still reports a case added to it.

Four of the calls are not here, being loops rather than literals: the
`multi_a()` of twenty-one keys, the three `and_b()` chains that pass the
p2wsh ops, stack and script-size limits, and the two nestings that reach a
thousand elements on the stack. `tests/descriptors/miniscript_test.py`
builds those from Core's own key set instead, and asserts the same
formulas its calls pass -- which is why they are missing here rather than
untested.

Also not here: `random_tests`, which generates expressions from a seeded
RNG and checks the satisfier against the script interpreter. Satisfaction
is not implemented (issue #187), so there is nothing yet for those to
measure.

### Not vendored as a file: Core's descriptor derivation vectors

```text
repo    bitcoin/bitcoin
path    src/test/descriptor_tests.cpp
commit  994c17d6c0a1453a1d7cc44ee2bbc49afa2d1155  2026-08-24
pulled  2026-08-25, rawtr() added 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, a subset by design. `tests/descriptors_test.py`
holds the `Check(prv, pub, ...)` cases of the `descriptor_test` case as
`CORE_VECTORS` — the descriptor in both spellings and the scriptPubKey
each expands to, at every index the case lists — plus the public spellings
of the four Core expands from the private form alone, and the two
`rawtr()` cases, which no BIP publishes and only this file has.

Not vendored as a file because there is no file: the values are literals
in C++ source, so a copy of it would be a copy of a test program. What
this pin buys instead is the upstream re-check: a case added to that
function moves the commit, and the weekly run says so.

The subset is deliberate and is what a refresh would revisit: Core's file
also holds `CheckUnparsable` cases, which this module has as `UNPARSABLE`
with btclib's own messages, and the `musig()` cases of BIP390, which are
transcribed from the BIP itself above rather than from here. Matched
against the pinned file on 2026-08-06.

Not matched since: the commit above adds five cases -- a `musig()`
duplicate-key check fix and a PSBT origin-path doubling fix, neither a
refactor -- which
[ISS 1334](https://github.com/btclib-org/btclib/issues/1334) tracks,
including whether btclib's own musig derivation shares either defect.

## bitcoin-core/HWI

Nothing is vendored from HWI and nothing is imported from it: `btclib.hwi`
runs its JSON command line as a subprocess, which is what keeps its
`hidapi`, `libusb1`, `cbor2`, `pyserial`, `noiseprotocol` and `protobuf`
out of btclib's dependencies. What is pinned here is therefore not a file
but an *interface*, and the two entries are the two halves of it: the
commands and flags a caller sends, and the numbers it gets back.

Which makes these pins do something the others do not. A vector file is
refreshed or it is not; an interface that moves is code here that stops
working against the next release somebody installs — so the weekly
re-check is the alignment, and `tests/hwi_test.py` carries the
transcription it is checked against.

Both pins are read against `master`, and
`.github/workflows/integration-hwi.yml` installs release 3.2.0, so two
interfaces are in play and each entry below says what the release does
not carry. `tests/hwi_test.py` answers from a stand-in it writes itself
and is green against either; the weekly jobs are what run the release.

### Not vendored as a file: the commands and flags of HWI's JSON CLI

```text
repo    bitcoin-core/HWI
path    hwilib/_cli.py
commit  6f44e48980bf610a57195f43a74027f4dc20e385  2026-08-24
pulled  2026-09-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, and a subset by design. `tests/hwi_test.py`
holds the commands `btclib.hwi` runs — `enumerate`, `getxpub`,
`signtx`, `signmessage`, `displayaddress`, `registerdescriptor` — with
the positional arguments of each, the global flags it passes
(`--chain`, `--fingerprint`, `--emulators`), the `--desc` of
`displayaddress`, the chains `--chain` takes, and the keys read out of
each answer. Not every chain it transcribes is one btclib sends:
testnet4 goes out as `test`, and `btclib.hwi`'s `_HWI_CHAIN` says why.

What the parser declares and `btclib.hwi` leaves alone, under the reason
each is left alone for. `setup`, `wipe`, `restore`, `backup`,
`promptpin`, `togglepassphrase` and `sendpin` are the device lifecycle,
which issue #381 keeps out of the signing surface deliberately.
`getdescriptors`, `getkeypool` and `getmasterxpub` are what btclib
computes for itself, on its own types, in
`descriptors.account_descriptors` and `btclib.core_import`.
`installudevrules` talks to no device -- it copies HWI's udev rules onto
the host -- and it is the one subcommand of the pin above that the
parser registers behind a platform guard,
`sys.platform.startswith("linux")`.

`displayaddress`'s BIP388 policy mode -- `--registration`, `--index`,
`--multipath-index` -- is `HwiSigner.display_policy_address`
(`btclib.hwi`'s module docstring, "Wallet policies", issue #1588), and
`psbt_signer.WalletPolicyAddressDisplay`/`display_policy_address` are
the protocol and the check beside `AddressDisplay`/`display_address`:
`descriptors.wallet_policy_address` computes the address a policy
describes at an index and a multipath index, and `display_policy_address`
compares it with what the device answers. Its own argv is checked in
`tests/hwi_test.py` directly rather than through the shared
`HWI_COMMAND_FLAGS` table above, `displayaddress`'s two modes taking
disjoint flags.

Not transcribed on purpose: `--change`, `displayaddress`'s alias for
`--multipath-index 1` -- `HwiSigner.display_policy_address` always
sends `--multipath-index` and never reaches for the alias -- and
`--registration` on `signtx`, which nothing here sends: a registration
travels with `displayaddress`'s policy mode only, and `signtx`'s answer
keys (`psbt`, `signed`) are unaffected by one being passed alongside
the transaction regardless.

Not in a release: `registerdescriptor` and its `registration` answer
key, and the BIP388 policy arguments named above -- `--index`,
`--multipath-index`/`--change`, and `--registration` on either command.
All of them entered upstream in 2026-08, after 3.2.0 shipped, so the
weekly jobs cannot reach `HwiSigner.register_descriptor` at all and
would refuse those flags. Raising `HWI_VERSION` to the first release
whose `hwilib/_cli.py` adds them is what makes the two interfaces one.

The parser has only ever grown, and only additively, since 2021:
`--emulators` in 2024, `--chain` and `--expert` on enumerate in 2022,
`registerdescriptor` and the BIP388 policy arguments on `displayaddress`
in 2026-08, and `--registration` on `signtx` in this pin. `signtx`
gained a second answer key, `signed`, in 2021 — which is how this pin
earned itself: btclib read only `psbt` until the surface was written
down, and now checks the two against each other.

### Not vendored as a file: HWI's error codes

```text
repo    bitcoin-core/HWI
path    hwilib/errors.py
commit  bbbc8a65db960bcd08be63362657dfcac72359dd  2026-08-20
pulled  2026-09-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. The pin now carries the same commit
`INVALID_POLICY` (-19) had already been checked in from ahead of, and the
`UNKNWON_DEVICE_TYPE` misspelling this commit fixes upstream — keeping
the old name as a compat alias with the same code, -4 — is why
`tests/hwi_test.py`'s table now reads `UNKNOWN_DEVICE_TYPE`;
`pyproject.toml`'s typos exception for the old spelling stays, for
`CHANGELOG.md`'s own narration of it. Every number `master` defines,
under the name it gives, in `tests/hwi_test.py`, and one test per number
that a `{"error": …, "code": …}` answer arrives as an
`exceptions.SignerError` carrying it. The numbers are what a caller acts
on — -14 is somebody pressing the button that says no, -3 is a cable, -9
is a model that will never do it — so an adapter that dropped them would
leave a caller matching on the text of a message.

Not in a release: `INVALID_POLICY` (-19). The rest of the table is in
3.2.0, where -4 carries the misspelling this pin's commit corrects — a
name that differs and a number that does not, and the number is what
`tests/hwi_test.py` asserts on.

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

Verdict: **identical**. All twelve language arrays, in order and value
for value, at the indentation upstream writes them with, so
`git hash-object` on our copy answers the blob id above and a refresh is
the fetch itself:

```shell
gh api -H 'Accept: application/vnd.github.raw' \
    '/repos/trezor/python-mnemonic/contents/vectors.json?ref=master' \
    > tests/mnemonic/_data/bip39_test_vectors.json
```

Upstream generates the file with its own `tools/generate_vectors.py`
rather than maintaining it by hand, which is what makes that one command
the whole of a refresh -- and why nothing of btclib's is inside it. The
one case that is ours, the last English vector with tabs, newlines,
doubled spaces and a form feed through the mnemonic, is a `pytest.param`
in `tests/mnemonic/bip39_test.py` beside the ones the file feeds: in the
array it would have to be re-added by hand at every refresh, and would
go missing the once nobody remembered.

Two `pulled` dates because the `english` array was here on its own for
as long as english was the only BIP39 language btclib read; that array
has not changed in any revision, so the earlier pull and this one hold
the same file for it, and `behind 0 revisions` is now about the whole of
the file rather than about one array of it.

The name is btclib's rather than upstream's, which the naming rule above
allows for one reason and this is it: `vectors.json` is taken in this
very directory, by SLIP-0039's own file of that name, which is a
different upstream's. The blob id is what checks the file behind the
name.

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

### `src/btclib/mnemonic/_data/wordlist.txt`

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

### C2SP/wycheproof: the ECDSA and ECDH files under `tests/ecc/_data/`

The adversarial vectors, and the one upstream here published under a
licence that is not MIT: Apache-2.0, whose condition on redistribution
is a copy of the licence, so `WYCHEPROOF_COPYING` is vendored beside
them and has its own entry below. There is no `NOTICE` file at the pin
to carry with it.

All are pinned to the same commit, `5722833c` of 2026-08-11, and all
live in `testvectors_v1/`. Not `testvectors/`, which upstream removed
on 2025-09-02 and which no refresh can reach again. They are read by
`tests/ecc/wycheproof_test.py`, which is also where the split between
the two ECDSA profiles is explained, and where the difference the files
under a hash other than sha256 make is: `_libsecp256k1_serves`
admits sha256 alone, so those reach the Python arithmetic without the
dispatch being switched off, and are run once rather than twice.

The SHAKE files need one thing the others do not, and it is a type
rather than a reader: `hashlib.shake_128` is not a `HashF`, an
extendable-output function having no output length of its own, so
`_PinnedXof` in that module pins one and `src/btclib/alias.py` says why the
library does not. The pinned length is `n_size` and any length above it
is the same test, `challenge_` reading the leftmost `nlen` bits of a
digest whose longer forms have these very bytes as their prefix --
measured, all four files verify identically at 32 and at 64.

`ecdsa_secp256k1_sha256_bitcoin_test.json` names its own schema now,
`ecdsa_bitcoin_verify_schema.json`, which upstream added beside it;
upstream's own README still lists the file as missing one, unrenewed in
the same commit. No longer frozen at `generatorVersion 0.9rc5` either:
that top-level field is gone, replaced by a `source: {name, version}`
object per test group, `version` carrying the same string. Vendored
regardless of the schema's presence or absence, which is what
bitcoin-core/secp256k1 and secp256k1lab both do with it.

### `tests/ecc/_data/ecdsa_secp256k1_sha256_bitcoin_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha256_bitcoin_test.json
commit  234d9689d0cbb77a21fd603d6055ab47498bff69  2026-08-17
blob    88097c48ba49f358179ac3aa6c6a64562d0f4e65
pulled  2026-08-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The bitcoin profile, `EcdsaBitcoinVerify`: the
strict DER encoding, and the low-s rule, under which the malleable high-s
twin of a valid signature is `invalid`. btclib's parser is the strict one
and its verifier no longer applies that rule, so two of these verdicts
are exempted rather than asserted — `wycheproof_test.py` reads which two
out of the file below.

The pin between here and the file's previous commit (`5722833ca004`)
replaces the top-level `generatorVersion` with a `source` object per test
group and adds the file's own `schema` field; every test group and every
case is otherwise the same 463 cases, `numberOfTests` included.

### `tests/ecc/_data/ecdsa_secp256k1_sha256_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha256_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    48797ce3b697f47175bdf4dc93976c2dc94438c5
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The same algorithm, curve and hash as the file
above, without the bitcoin profile's two extra rules: what a
general-purpose ECDSA verifier must accept. It is therefore also the
oracle for the exemption named above — a key and a signature `valid` here
and `invalid` there differ by the low-s rule and by nothing else.

### `tests/ecc/_data/ecdsa_secp256k1_sha256_p1363_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    3c59b142ede26ecbafecf83341e907dd3bfda40f
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. IEEE P1363 encoding, raw `r` and `s` side by
side, which reaches `Sig` with no DER in front of it.

### `tests/ecc/_data/ecdsa_secp256k1_sha512_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha512_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    612e1912bfb5e523fbe8183e0d12f468e8309a08
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. A digest wider than the order, so `challenge_`'s
truncation to the leftmost `nlen` bits is under adversarial input here
and nowhere else.

### `tests/ecc/_data/ecdsa_secp256k1_sha3_256_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha3_256_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    5c6c5901f4d41af8a992cafc4aa31b6bc7b87163
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. A Keccak digest of the order's own width, which
is the pair to the file above: same width as sha256, different function,
so what it varies is the dispatch and not the arithmetic.

### `tests/ecc/_data/ecdsa_secp256k1_sha3_512_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha3_512_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    2a5770e00be1c4d1218b79e8a805f52a0a1c7f26
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Wide digest and Keccak both, the fourth corner
of the two the files above vary one at a time.

### `tests/ecc/_data/ecdsa_secp256k1_sha512_p1363_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha512_p1363_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    089040205b9d99313d284154cdcdc646079d1d43
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The wide digest without DER around it, which is
what says the P1363 size rule is the encoding's and not the hash's: r
and s stay `n_size` each while the message hash doubles.

### `tests/ecc/_data/ecdsa_secp256k1_shake128_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake128_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    bffa63ed0097e4910a5d99381f88a4b1c12db757
pulled  2026-08-13
behind  0 revisions; last changed at e0df04e0, 2025-10-07
```

Verdict: **identical**. An extendable-output function read as a hash of
fixed size, which is the one thing here that needed something built for
it: `_PinnedXof` in the test module, because `HashF` is a constructor of
digests that report their own length and a SHAKE's is 0.

### `tests/ecc/_data/ecdsa_secp256k1_shake256_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake256_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    5bfb394cf971b3c9a68862f23b1251f3d3e7b1c0
pulled  2026-08-13
behind  0 revisions; last changed at e0df04e0, 2025-10-07
```

Verdict: **identical**. The same stream read at the same `n_size`, over
a sponge of a different rate. Its tcId 425 is upstream's
`Untruncatedhash` case, a signature made over the whole digest instead
of its leftmost `nlen` bits and therefore `invalid` -- which is also the
evidence that upstream generated this file at a length wider than the
order, and that reading the stream at `n_size` reads the leftmost bits
it read.

### `tests/ecc/_data/ecdsa_secp256k1_shake128_p1363_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake128_p1363_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    3f63208d4cbeaed6a8c46c430678199bd52d0e50
pulled  2026-08-13
behind  0 revisions; last changed at e0df04e0, 2025-10-07
```

Verdict: **identical**. The XOF with no DER around it: `Sig` answers for
r and s alone, as under sha256 and sha512, the adapter changing what the
message hashes to and nothing about the encoding.

### `tests/ecc/_data/ecdsa_secp256k1_shake256_p1363_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake256_p1363_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    c2b431b5d76016a8da19fdc1aab1ecaa5cfe12f1
pulled  2026-08-13
behind  0 revisions; last changed at e0df04e0, 2025-10-07
```

Verdict: **identical**. The fourth corner, and it carries the
`Untruncatedhash` case of the pair as tcId 190.

### `tests/ecc/_data/ecdh_secp256k1_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdh_secp256k1_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    3ed5207460f29a270e024d0f3c0e1b57d1fa52a9
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Key agreement, with the public key X.509-encoded
rather than a bare point: the invalid-curve, twist and wrong-curve cases
`btclib.ecc.dh` has no other vectors for.

### `tests/ecc/_data/ecdh_secp256k1_webcrypto_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdh_secp256k1_webcrypto_test.json
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    a675c5378e8d10aad7ae241ef5460f4aefa10d0b
pulled  2026-08-25
behind  0 revisions; last changed at e0df04e0, 2025-10-07
```

Verdict: **identical**. The same key agreement as `ecdh_secp256k1_test.json`
above with the keys JWK-encoded (RFC 7517) rather than X.509: `WrongCurve`
here attacks the JWK `crv` field where that file's attacks the DER OID,
and its valid cases' shared secrets are exactly that file's own.

### `tests/ecc/_data/WYCHEPROOF_COPYING`

```text
repo    C2SP/wycheproof
path    LICENSE
commit  5722833ca004983abd1a91bcb6c24596d50ac0f9  2026-08-11
blob    7a4a3ea2424c09fbe48d455aed1eaa94d9124835
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- upstream ends
without one and the `end-of-file-fixer` hook added it, so our blob is
`d6456956`, which is the Apache-2.0 text as most repositories carry it.
The stock text, with no copyright line filled in and no `NOTICE` beside
it, so this file is the whole of what the licence asks a redistributor
to carry.

Renamed, against the naming rule above, and the reason is what the rule
is for. Upstream calls it `LICENSE`, and a file of that name inside
`tests/ecc/_data/` would read as licensing the directory it sits in --
which is false, the BIP and rustyrussell files beside it having their
own terms and btclib's own `LICENSE` being at the root. The upstream
name is in the entry above instead, where the pin already is. It is the
name bitcoin-core/secp256k1 gives its copy for the same reason.

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

`SEED_VECTORS`' five passphrase-bearing rows each carry the
`passphrase_hex` field upstream's own `SeedTestCase` publishes beside
them where it publishes one — `spesmilo/electrum`'s
`300b986782c754be462788a30e0355301683c0ed` (2024-06-10, the tip of
`tests/test_mnemonic.py`) and, for the japanese row's
`UNICODE_HORROR_HEX`, `b57327fb3e6d62941b833f8ce9b3b91c34c9ec76`
(2026-07-01, the tip of `tests/test_wallet_vertical.py`) — and
`test_seed_vectors` asserts `passphrase.encode("utf8") ==
bytes.fromhex(passphrase_hex)` before either reaches the seed
computation, the way upstream's own `test_mnemonic_to_seed` does.
`english_with_passphrase` publishes no such field upstream, its
passphrase being plain ASCII, so that row's stays `None`. The check
found the spanish row's passphrase composed rather than decomposed — a
precomposed ñ, í, ó, é and á where upstream's own literal holds the
accent as a separate combining character — invisible to the seed
assertion, since `_seed_from_mnemonic` normalizes either form to the
same NFKD before hashing, and caught only by comparing raw bytes. The
fix was to match upstream's bytes, not to drop the check.

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
`src/btclib/mnemonic/_data/electrum_old_english.txt` is pinned where it is
used: it is shipped code, transcribed from the `_words` tuple of
`electrum/old_mnemonic.py`, and `src/btclib/mnemonic/electrum.py` carries
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
    src/btclib/mnemonic/_data/wordlist.txt | grep -cv 'README.md'
```

Against a pinned upstream blob:

- identical byte for byte: `english.txt`, `wordlist.txt`,
  `taproot_test_vector.json`, `sig_hash_legacy_test_vectors.json`,
  `script_tests.json`, `tx_valid.json`, `tx_invalid.json`,
  `key_io_valid.json`, `key_io_invalid.json`,
  `base58_encode_decode.json`, `siphash.json`, `blockfilters.json`,
  `checkblock_valid.json`, `checkblock_invalid.json`,
  `bip39_test_vectors.json`, the eight BIP327 vector files,
  `send_and_receive_test_vectors.json`, `bip375_test_vectors.json`, and
  the Wycheproof vector files.
- identical but for a trailing newline:
  `script_assets_test.json`, `vectors.json`, `WYCHEPROOF_COPYING`.
- identical but for CRLF against LF: `bip340_test_vectors.csv`, the two
  BIP324 vector files and the two BIP374 vector files -- every csv
  vendored from bitcoin/bips, so far.
- JSON-equal, reformatted: `pubkey.json`, `ecdsa_sig.json`,
  `ecdsa_custom_nonce_sig.json`, `signmessage.json`,
  `test_JP_BIP39.json`.

No upstream blob exists for the rest:

- transcribed from a pinned prose revision, every value matched:
  `bip32_test_vectors.json`, `bip32_invalid_keys.json`,
  `bip174_test_vectors.json`, `bip370_test_vectors.json`,
  `bip371_test_vectors.json`, `bip373_test_vectors.json`,
  `bip67_test_vectors.json`, `bip85_test_vectors.json`,
  `descriptor_checksums.json`.
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
