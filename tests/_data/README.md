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
is what a paraphrase sends them for -- and `btclib.ecc.dsa`'s anti-exfil
docstrings cite `include/secp256k1_ecdsa_s2c.h` of
BlockstreamResearch/secp256k1-zkp that way. A line needs one: a line number
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
- `rfc6979.json` is transcribed from prose: no upstream file, so no
  upstream name to take.
- `WYCHEPROOF_COPYING` is upstream's `LICENSE`, renamed because a file
  of that name inside a directory of vendored vectors would read as
  licensing all of them. Its entry says so, and carries the upstream
  name.

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
what their `pulled` says: the BIP327 files, the Core files
`key_io_valid.json`, `key_io_invalid.json` and `base58_encode_decode.json`,
and the python-bitcoinlib block files added here; Core's
`blockfilters.json` and the BIP324 csv files followed on 2026-08-03, at
the tip of their paths too, the Wycheproof files with the licence beside
them and the BIP374 csv files on 2026-08-13, and Core's `siphash.json` on
2026-08-20. Wycheproof's `ecdsa_secp256k1_sha256_bitcoin_test.json` was
pulled again on 2026-08-25, at the tip of its path that day, Core's
`chacha20_vectors.json` and `muhash_vectors.json`, both transcribed from
`crypto_tests.cpp`, on 2026-09-03, at the tip of that path, and
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
entry says so with our own blob alongside. Every csv file vendored from
bitcoin/bips is that case, and so far only those: `bip340_test_vectors.csv`,
the BIP324 files and the BIP374 files. A csv there is written on
Windows line endings often enough that it is worth expecting rather than
discovering -- `mixed-line-ending` rewrites the file with `--fix=lf` as it
is staged, so the blob to compare is never the one just fetched.

## bitcoin/bips

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

### BIP327 (MuSig2): files under `tests/ecc/_data/`

The vectors of `bip-0327/vectors/`, vendored whole
and under upstream's own names: `key_sort_vectors.json`,
`key_agg_vectors.json`, `nonce_gen_vectors.json`,
`nonce_agg_vectors.json`, `sign_verify_vectors.json`,
`tweak_vectors.json`, `det_sign_vectors.json` and
`sig_agg_vectors.json`. Each is pinned below in its own entry, one real
path per pin, rather than to one placeholder path shared by all of them:
a placeholder is not a path GitHub's own "commits touching a path" API
can be asked about, which is what kept every one of them out of
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

### BIP445 (FROST signing): files under `tests/ecc/_data/bip445/`

The signing-algorithm vectors of `bip-0445/python/vectors/`, vendored
whole and under upstream's own names, in a subdirectory rather than
flat under `tests/ecc/_data/`: BIP327 above already publishes files of
these same names there, and a vendored file keeps the name upstream
gave it rather than losing it to that collision. `ValidateThresholdInfo`
ships no vector file, `bip-0445/python/vectors/test_vectors_summary.md`
giving the reason RFC 9591 gives for shipping none over `vss_verify`: it
checks key material a key generation protocol produced, and this BIP
specifies no key generation.

The BIP is a draft: `bitcoin/bips#2070`, not on that repository's
`master`, at version 0.10.0. The version and the pull request go in the
citation because a path that has never landed on the default branch has
no commit there for a reader to find otherwise. The files below live on
the pull request's own branch, `siv2r:bip-frost-signing`, so `repo`
below names that fork rather than `bitcoin/bips`. Most are pinned at
the pull request's own head,
`8e25d57911c33f1daadcadb0161a60a56ef7145a` (2026-08-26);
`nonce_gen_vectors.json` and `nonce_agg_vectors.json` were last touched
earlier on that branch and are pinned instead to the commit that
touched each -- `f0cc3aec157f9a0a1a290e8b835b242312a9ee53` (2026-07-27)
and `4343f72cbccc3a6b032279c5ac1dc4a46672c87c` (2026-06-10) respectively
-- the same distinction the BIP327 entry above draws for
`sign_verify_vectors.json` and `sig_agg_vectors.json`.

266 cases between them, and `tests/ecc/frost_test.py` runs every one: 5
nonce derivations, 2 + 3 nonce aggregations valid and failing, 29 + 52 +
12 + 8 signatures (valid, refused at signing, false on verification,
refused on verification), 28 + 16 tweaked, 37 + 48 deterministic, 18 + 8
aggregated. An error case carries what should be raised -- which party
contributed what, or the text of a plain value error -- and is checked
against it, the same discipline the BIP327 entry above states.

Each entry below carries a `ref` line, `bip-frost-signing`: GitHub's
"commits touching a path" API answers against a repository's *default*
branch alone unless told otherwise, and `bip-0445/` exists on that
branch and not on `siv2r/bips`' own default, `master`. Asked with no
ref the weekly job's call would find no commit touching any of these
paths regardless of whether the pin below is current, and would report
every one of them as upstream having deleted the file -- which is what
it did before `ref` was a field `check_vendored_vectors.py` knew to
send (ISS 2160, closed by the same change that added it). With the
branch named, the pins below are checked exactly as a default-branch
pin is.

`src/btclib/ecc/frost.py` follows `bip-0445/python/frost_ref/signing.py`
function for function, checked against it rather than assumed from the
BIP327 ancestry the reference's own header claims: several shapes that
read alike are not the same function, the tweak-range error message
among them. That file is not vendored -- it is an implementation, not
data, and btclib's is the one under test.

### `tests/ecc/_data/bip445/nonce_gen_vectors.json`

```text
repo    siv2r/bips
path    bip-0445/python/vectors/nonce_gen_vectors.json
ref     bip-frost-signing
commit  f0cc3aec157f9a0a1a290e8b835b242312a9ee53  2026-07-27
blob    2ba04502ebd28a839d12bb787f5ea093a9125005
pulled  2026-09-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- our 4,613 bytes
are that blob's 4,612 plus the `\n` the `end-of-file-fixer` hook added,
so our blob is `a5ebaa65`.

### `tests/ecc/_data/bip445/nonce_agg_vectors.json`

```text
repo    siv2r/bips
path    bip-0445/python/vectors/nonce_agg_vectors.json
ref     bip-frost-signing
commit  4343f72cbccc3a6b032279c5ac1dc4a46672c87c  2026-06-10
blob    92a223927318b18681ec269a5735b07692094147
pulled  2026-09-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- our 2,768 bytes
are that blob's 2,767 plus the `\n` the `end-of-file-fixer` hook added,
so our blob is `3b5e5f57`.

### `tests/ecc/_data/bip445/sign_verify_vectors.json`

```text
repo    siv2r/bips
path    bip-0445/python/vectors/sign_verify_vectors.json
ref     bip-frost-signing
commit  8e25d57911c33f1daadcadb0161a60a56ef7145a  2026-08-26
blob    622d859bcd742e9caf37e1541bf2409aa7c6c333
pulled  2026-09-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- our 88,802 bytes
are that blob's 88,801 plus the `\n` the `end-of-file-fixer` hook
added, so our blob is `ead53ab1`.

### `tests/ecc/_data/bip445/tweak_vectors.json`

```text
repo    siv2r/bips
path    bip-0445/python/vectors/tweak_vectors.json
ref     bip-frost-signing
commit  8e25d57911c33f1daadcadb0161a60a56ef7145a  2026-08-26
blob    ed876b4eeca7ee18e9918cd18f59141870670f12
pulled  2026-09-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- our 48,941 bytes
are that blob's 48,940 plus the `\n` the `end-of-file-fixer` hook
added, so our blob is `6451ef70`.

### `tests/ecc/_data/bip445/det_sign_vectors.json`

```text
repo    siv2r/bips
path    bip-0445/python/vectors/det_sign_vectors.json
ref     bip-frost-signing
commit  8e25d57911c33f1daadcadb0161a60a56ef7145a  2026-08-26
blob    57ce53754a413b4087486bbbe16c641b5edfc245
pulled  2026-09-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- our 88,987 bytes
are that blob's 88,986 plus the `\n` the `end-of-file-fixer` hook
added, so our blob is `a6def920`.

### `tests/ecc/_data/bip445/sig_agg_vectors.json`

```text
repo    siv2r/bips
path    bip-0445/python/vectors/sig_agg_vectors.json
ref     bip-frost-signing
commit  8e25d57911c33f1daadcadb0161a60a56ef7145a  2026-08-26
blob    4f20b42562a79b4443736269184ebec7870a7e0c
pulled  2026-09-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- our 30,915 bytes
are that blob's 30,914 plus the `\n` the `end-of-file-fixer` hook
added, so our blob is `a9b9140d`.

### BIP324 (ElligatorSwift): files under `tests/ecc/_data/`

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

The files test the two halves of the map, and both halves are
btclib's own Python: `tests/ecc/ellswift_test.py` runs the decode file
against `_xswiftec` and the inverse file against `_xswiftec_inv`, whose
eight `case` columns are eight assertions per row rather than one — an
empty cell is a case with no preimage, and asserting that it *has* none
is what keeps a permissive inverse from passing. The comment column of
each row names the branch it exercises (`valid_x(x1)`, `non_square(s)`,
`t>=p`, `info[v=0]`), which is what makes the files a branch
inventory and not a sample.

Neither file covers `create` or `encode`: those pick one of up to eight
preimages at random, so there is no vector to hold them to, and what the
suite asserts instead is the round trip against the bindings — the
authority named in the entry that has no file to cite.

`bip-0324/packet_encoding_test_vectors.csv` is the third file of that
directory and is **not** vendored: it is the v2 transport's, which btclib
does not implement.

### BIP374 (DLEQ): files under `tests/ecc/_data/`

`test_vectors_generate_proof.csv` and `test_vectors_verify_proof.csv`,
under upstream's own names, which is the whole of `bip-0374/`'s vector
set. They are pinned separately below and their pins differ, which is
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
commit  fc874dd5d34239e070c0fdb8c4ed6a1dd2a94147  2026-08-19
blob    1368013b03521c97984b65ba0586b99dd8818564
pulled  2026-09-21
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the same exception, our blob
`2d4acdf1` rather than the one above.

All 17 vectors: the eight successes are the eight proofs of the file
above, read back, and the nine failures are five permutations of A, B and
C, a bit flipped in the proof, a bit flipped in the message, an `e` equal
to the curve order and an `s` equal to the curve order -- so the pair
covers both directions over one set of keys, and a permutation the
challenge would have accepted is a defect the generation file alone could
not show.

Three BIP374 failure conditions have no vector in either file and are
covered by `tests/ecc/dleq_test.py` instead: `s >= n`, and R1 or R2
landing on infinity. None of the three is a proof anybody generates --
s is computed mod n, and an infinite R needs s == e over A == G or
B == C -- so upstream's generator produces none of them and the test
builds each.

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

`src` and not `include` for the same reason. `include` is what the library
publishes, where this tree names what it reads: `curves.curve`'s
`secp256k1_ge_x_on_curve_var` and `number_theory`'s `secp256k1_ctz64_var`
are that library's own and are declared in no header of `include`, only
in one under `src`. Nothing is lost at the other end — every name
`include` declares is spelled in `src` too, the difference being names a
header comment wraps in prose rather than declares.

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

### C2SP/wycheproof: the ECDSA and ECDH files under `tests/ecc/_data/`

The adversarial vectors, and the one upstream here published under a
licence that is not MIT: Apache-2.0, whose condition on redistribution
is a copy of the licence, so `WYCHEPROOF_COPYING` is vendored beside
them and has its own entry below. There is no `NOTICE` file at the pin
to carry with it.

Each entry below is pinned to its own path's last commit rather than to
one commit shared by all of them, since the files do not all move
together. All live in `testvectors_v1/`. Not `testvectors/`, which
upstream removed on 2025-09-02 and which no refresh can reach again.
They are read by `tests/ecc/wycheproof_test.py`, which is also where
the split between the two ECDSA profiles is explained, and where the
difference the files under a hash other than sha256 make is:
`_libsecp256k1_serves` admits sha256 alone, so those reach the Python
arithmetic without the dispatch being switched off, and are run once
rather than twice.

The SHAKE files need one thing the others do not, and it is a type
rather than a reader: `hashlib.shake_128` is not a `HashF`, an
extendable-output function having no output length of its own, so
`_PinnedXof` in that module pins one and `src/btclib/alias.py` says why the
library does not. The pinned length is `n_size` and any length above it
is the same test, `challenge_` reading the leftmost `nlen` bits of a
digest whose longer forms have these very bytes as their prefix --
measured, all files verify identically at 32 and at 64.

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
commit  878e5366008753df2064d40c49f8e2f50f9c6af7  2026-05-12
blob    48797ce3b697f47175bdf4dc93976c2dc94438c5
pulled  2026-09-08
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
commit  878e5366008753df2064d40c49f8e2f50f9c6af7  2026-05-12
blob    3c59b142ede26ecbafecf83341e907dd3bfda40f
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. IEEE P1363 encoding, raw `r` and `s` side by
side, which reaches `Sig` with no DER in front of it.

### `tests/ecc/_data/ecdsa_secp256k1_sha512_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha512_test.json
commit  878e5366008753df2064d40c49f8e2f50f9c6af7  2026-05-12
blob    612e1912bfb5e523fbe8183e0d12f468e8309a08
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. A digest wider than the order, so `challenge_`'s
truncation to the leftmost `nlen` bits is under adversarial input here
and nowhere else.

### `tests/ecc/_data/ecdsa_secp256k1_sha3_256_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha3_256_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    5c6c5901f4d41af8a992cafc4aa31b6bc7b87163
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. A Keccak digest of the order's own width, which
is the pair to the file above: same width as sha256, different function,
so what it varies is the dispatch and not the arithmetic.

### `tests/ecc/_data/ecdsa_secp256k1_sha3_512_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha3_512_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    2a5770e00be1c4d1218b79e8a805f52a0a1c7f26
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Wide digest and Keccak both, the fourth corner
of the two the files above vary one at a time.

### `tests/ecc/_data/ecdsa_secp256k1_sha512_p1363_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha512_p1363_test.json
commit  878e5366008753df2064d40c49f8e2f50f9c6af7  2026-05-12
blob    089040205b9d99313d284154cdcdc646079d1d43
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The wide digest without DER around it, which is
what says the P1363 size rule is the encoding's and not the hash's: r
and s stay `n_size` each while the message hash doubles.

### `tests/ecc/_data/ecdsa_secp256k1_shake128_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake128_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    bffa63ed0097e4910a5d99381f88a4b1c12db757
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. An extendable-output function read as a hash of
fixed size, which is the one thing here that needed something built for
it: `_PinnedXof` in the test module, because `HashF` is a constructor of
digests that report their own length and a SHAKE's is 0.

### `tests/ecc/_data/ecdsa_secp256k1_shake256_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake256_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    5bfb394cf971b3c9a68862f23b1251f3d3e7b1c0
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
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
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    3f63208d4cbeaed6a8c46c430678199bd52d0e50
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The XOF with no DER around it: `Sig` answers for
r and s alone, as under sha256 and sha512, the adapter changing what the
message hashes to and nothing about the encoding.

### `tests/ecc/_data/ecdsa_secp256k1_shake256_p1363_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake256_p1363_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    c2b431b5d76016a8da19fdc1aab1ecaa5cfe12f1
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The fourth corner, and it carries the
`Untruncatedhash` case of the pair as tcId 190.

### `tests/ecc/_data/ecdh_secp256k1_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdh_secp256k1_test.json
commit  78898104021ebd2cd98820e4112da89b1531d999  2026-03-11
blob    3ed5207460f29a270e024d0f3c0e1b57d1fa52a9
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Key agreement, with the public key X.509-encoded
rather than a bare point: the invalid-curve, twist and wrong-curve cases
`btclib.ecc.dh` has no other vectors for.

### `tests/ecc/_data/ecdh_secp256k1_webcrypto_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdh_secp256k1_webcrypto_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    a675c5378e8d10aad7ae241ef5460f4aefa10d0b
pulled  2026-09-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The same key agreement as `ecdh_secp256k1_test.json`
above with the keys JWK-encoded (RFC 7517) rather than X.509: `WrongCurve`
here attacks the JWK `crv` field where that file's attacks the DER OID,
and its valid cases' shared secrets are exactly that file's own.

### `tests/ecc/_data/WYCHEPROOF_COPYING`

```text
repo    C2SP/wycheproof
path    LICENSE
commit  31387e2cd596587c859c611027b6a44d2e2b65ff  2018-04-04
blob    7a4a3ea2424c09fbe48d455aed1eaa94d9124835
pulled  2026-09-08
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

### `tests/ecc/_data/rfc6979.json`

Verdict: **transcribed**. Appendix A.2 of RFC 6979 gives 50 vectors, ten each
for NIST P-192, P-224, P-256, P-384 and P-521, as `tests/ecc/rfc6979_test.py`
says. An RFC number is already an immutable reference — there is no commit to
pin, and `rfc-editor.org/rfc/rfc6979` is the document.

Pulled 2020-05-08.

### `tests/ecc/_data/zkp_rangeproof_fixed_vectors.json`

```text
repo    BlockstreamResearch/secp256k1-zkp
path    src/modules/rangeproof/tests_impl.h
commit  72867fd682279ff2c79cf13f4f8d8484048d2527  2026-08-17
blob    19c83ecbd84ae318d8eccf9336638238d3a29826
pulled  2026-09-09
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically. One json object per `vector_<n>`
array of `test_rangeproof_fixed_vectors` and
`test_rangeproof_fixed_vectors_reproducible`, which is where
libsecp256k1-zkp publishes fixed rangeproofs: `proof` and `commitment`
are that array and the `commit_<n>` beside it, `blind` is the `blind_<n>`
of the first function and the `vector_blind` the second shares, `nonce`
is the `nonce_3` the first rewinds its `vector_3` under and the
`vector_nonce` the second shares, and
`value` and `verify` are what those functions' own `CHECK`s state about
the octets -- the value a rewind answers, and the range
`secp256k1_rangeproof_verify` answers. `id` is the function and the array
upstream names each by. The pass that produced the file is not committed
-- a one-off read of C source is not a tool -- and what re-derives it is
reading those arrays again.

Not vendored as the file itself because there is no data file upstream
and none anywhere: this format has no published vector file, which is
what the entry below says of it too, so the blob above is that C source
and the weekly re-check reports a proof added to it. The bindings
`uv.lock` resolves vendor a fork of that repository: their
`secp256k1-zkp` submodule is `a8f6b86a804cdfd455dfb943937d254ec6ccc70a`
of `fametrano/secp256k1-zkp`, which exposes
`secp256k1_borromean_verify` as public API, so the blob at this path
there is `02276b1b8745b90c7b6a50a0e3a89b9438e30397` and not the one
above. Both functions this entry transcribes read the same in the fork's
blob, byte for byte, as do the `vector_blind` and `vector_nonce`
declared between them, so the transcription's source is the code the
bindings run.

`vector_1` and `vector_2` of `test_rangeproof_fixed_vectors` carry no
`nonce` field because upstream declares no array for them: it rewinds
those under `pc.data`, and `secp256k1_pedersen_commitment_parse` ends by
copying its input into `commit->data` verbatim, so what a rewind reads
there is the leading octets of the `commitment` above, one scalar wide.
The message a rewind also answers is left out,
`tests/ecc/rangeproof_fixed_vectors_test.py` holding what upstream
signed each entry with instead.

That module asks for the octets back out, the range the header proves,
the rings the value's digits index, `ecc.rangeproof.verify` against the
commitment published beside each proof, and a rewind of every entry.
The entries of
`tests/ecc/_data/zkp_rangeproof_vectors.json` record a nonce of their
own, and `tests/ecc/rangeproof_test.py` is where those are rewound.

### `tests/ecc/_data/zkp_generator_vectors.json`

```text
repo    BlockstreamResearch/secp256k1-zkp
path    src/modules/generator/tests_impl.h
commit  d111d31293b479832c767946145702151897785d  2026-03-03
blob    14ec95dc94780126a796866b05eeafa2093bf22f
pulled  2026-09-11
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically. One json object per element of
each `secp256k1_ge_storage results[]` array upstream declares in that
file, `x` and `y` being the halves of a `SECP256K1_GE_STORAGE_CONST`.
`shallue van de woestijne` is `test_shallue_van_de_woestijne`'s array
and `t` the field element that function maps -- its loop counter, then
that counter negated, which is the order the array is indexed in;
`generator generate` is `test_generator_generate`'s and `seed` the `v`
that function fills with its own counter. `id` names the argument rather
than the position. The pass that produced the file is not committed -- a
one-off read of C source is not a tool -- and what re-derives it is
reading those arrays again.

Not vendored as the file itself for the reason the entry above gives:
this map has no published vector file anywhere, upstream stating its own
against the sage program it keeps beside the code. The bindings
`uv.lock` resolves vendor a fork of that repository,
`fametrano/secp256k1-zkp` at
`a8f6b86a804cdfd455dfb943937d254ec6ccc70a`; the blob at this path there
is the one above, where the entry above has to name its own, so the
transcription's source is the code the bindings run.

`tests/ecc/pedersen_test.py` is what reads it: the first array against
`ecc.pedersen._shallue_van_de_woestijne` and the second against
`generator_from_seed`, at no blinding factor and at a zero one, which is
the pair of calls upstream's own loop makes of each entry.

### `tests/ecc/dsa_anti_exfil_test.py`

```text
repo    BlockstreamResearch/secp256k1-zkp
path    src/modules/ecdsa_s2c/tests_impl.h
commit  72867fd682279ff2c79cf13f4f8d8484048d2527  2026-08-17
blob    ea0b650d829c87c39908903abe7a5b164e06063c
pulled  2026-08-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, off `ecdsa_s2c_tests`, the array
`test_ecdsa_s2c_fixed_vectors` and `test_ecdsa_anti_exfil_signer_commit`
both walk: `_ZKP_VECTORS` is its rows, column for column -- `s2c_data`,
`expected_s2c_opening` and `expected_s2c_exfil_opening` -- and
`_PRV_KEY` and `_MSG_HASH` are the key and the message both functions
run those rows against. There is no blob to compare, the values
being `0x` arrays inside C source, so what is checked is that each of
them is in the pinned blob when those arrays are read as octets rather
than as text:

```shell
blob=<the blob this entry gives>
value=<a hex string the module transcribes>
```

```shell
gh api -H 'Accept: application/vnd.github.raw' \
    "repos/BlockstreamResearch/secp256k1-zkp/git/blobs/${blob:?}" \
    | python3 -c "import re,sys
h = ''.join(re.findall(r'0x([0-9a-fA-F]{2})', sys.stdin.read()))
print(sys.argv[1].lower() in h.lower())" "${value:?}"
```

Source rather than a data file, and pinned here for what the columns
settle: a row's openings are one `anti_exfil_host_commit` apart, so the
module holds the R the device promises and the R its signature carries
to libsecp256k1-zkp's own octets rather than to btclib run twice. A row
upstream regenerates is one this tree would go on asserting, which is
what the pin is read for. The module points here for the revision
and carries none of its own, which is what puts the pin where the weekly
workflow reads it.

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

### `tests/ecc/_data/zkp_rangeproof_vectors.json`

```text
program   btclib-secp256k1 0.8.0.5, built from its sdist with
          BTCLIB_LIBSECP256K1_ZKP=true; its secp256k1-zkp submodule is
          037cc6d74cbb4a89e443117459b577d56a582e54
calls     zkp.generator.pedersen_commit(blind, value)
          zkp.rangeproof.sign(commitment, blind, nonce, value, **args)
          zkp.rangeproof.info(proof)
          zkp.rangeproof.verify(commitment, proof)
recorded  2026-09-09
```

Verdict: **recorded**. There is no upstream vector file, which is what
[ISS 1072](https://github.com/btclib-org/btclib/issues/1072) says of
this format too. What libsecp256k1-zkp publishes instead is inside a C
test source, `src/modules/rangeproof/tests_impl.h` -- blob
`19c83ecbd84ae318d8eccf9336638238d3a29826` at the submodule commit
above -- where `test_rangeproof_fixed_vectors` and
`test_rangeproof_fixed_vectors_reproducible` hold proofs as C arrays,
beside the commitments and the ranges they assert. Those are the entry
`zkp_rangeproof_fixed_vectors.json` has above, and are not what this
file holds: each entry below is one proof
libsecp256k1-zkp signed for this tree, kept verbatim, beside the
arguments that produced it and what that library then said about it.

It is here because `tests/ecc/rangeproof_test.py` would otherwise
measure nothing in an unflagged build: the flagged extension those
calls need is what a btclib-secp256k1 installed from its sdist with
`BTCLIB_LIBSECP256K1_ZKP` has, and `btclib.ecc.rangeproof` reads a
format no other vector file in this tree carries.

**Recording another is this file's own arguments.** A rangeproof draws
nothing -- its nonces are the hash chain `rangeproof_genrand` derives
from the caller's -- so `sign` called again with an entry's `blind`,
`nonce`, `value` and `sign arguments` answers that entry's `proof`,
byte for byte. `test_the_vectors_are_what_zkp_signs_today` is that
check, so the procedure is a test rather than a note here, and it runs
wherever the extension does. The same determinism makes the entries an
oracle for what btclib writes: `ecc.rangeproof.sign` builds a proof
from an entry's own `blind`, `value`, `nonce` and `sign arguments`, and
`test_sign_writes_the_octets_zkp_signed` holds it to these octets
wherever the suite runs, extension or not.
`test_sign_public_value_writes_the_octets_zkp_signed` asks the same of
the spelling that fixes the exponent for a value stated in the clear,
and both shapes that proof has are recorded, `public value` carrying a
`min_value` field and `public value, zero` carrying none, so neither is
left to the weekly sentinel.

**The `info` key is why a run without the extension still compares
against something.** Those are `zkp.rangeproof.info`'s own answers for
the same octets, so btclib's reading of a header is held to
libsecp256k1-zkp's rather than to btclib's own; what `info` says
nothing about -- the sign bits, the ring commitments and the borromean
signature -- is held by the proof going back out byte for byte.

### `tests/ecc/_data/der_length_vectors.json`

```text
program   cryptography (pyca/cryptography)
calls     encode_dss_signature(r, s)
recorded  2026-09-14
```

Verdict: **recorded**. There is no upstream vector file and no
repository: an outside DER encoder's own bytes, recorded once for a
fixed `(r, s)` on each of `bpp512r1`, `nistp521` and `secp521r1` -- the
catalogued curves whose signature reaches DER's long length form -- and
for a scalar pair on `secp256k1` wide enough that no catalogued curve's
own element does
([ISS 2130](https://github.com/btclib-org/btclib/issues/2130)).

It is here because nothing else in this tree can hold `Sig.serialize`'s
length octets to a parser it did not write: `libsecp256k1_dsa` answers
for `secp256k1` alone, and a decoder or a copy of the encoder written
beside the fix would share its author and the same reading of the
standard, proving nothing about whether that reading is the standard's
own. `tests/ecc/der_test.py`'s `test_der_matches_a_vendored_der_oracle`
compares `serialize()` to each entry's `der` field, byte for byte.

**Recording another** is `dsa.sign`'s own deterministic nonce for each
curve entry, and a synthetic scalar pair for the wide-element one:

```shell
uv run --locked --with cryptography python - <<'EOF'
from btclib.curves.curve import CURVES
from btclib.ecc import dsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature)

for name in ("bpp512r1", "nistp521", "secp521r1"):
    sig = dsa.sign(b"msg", 0x1234567890ABCDEF, ec=CURVES[name])
    print(name, hex(sig.r), hex(sig.s),
          encode_dss_signature(sig.r, sig.s).hex())

r = s = (1 << 1023) + 1
print("secp256k1", hex(r), hex(s), encode_dss_signature(r, s).hex())
EOF
```

Nothing upstream will ever refresh this file: `cryptography`'s encoder
is the fixed point being checked against, not a moving target.

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
  `blockfilters.json`, `checkblock_valid.json`, `checkblock_invalid.json`,
  the BIP327 vector files, and the Wycheproof vector files.
- identical but for a trailing newline: `script_assets_test.json`,
  `WYCHEPROOF_COPYING`, and the BIP445 vector files.
- identical but for CRLF against LF: `bip340_test_vectors.csv`, the
  BIP324 vector files and the BIP374 vector files -- every csv
  vendored from bitcoin/bips, so far.
- JSON-equal, reformatted: `pubkey.json`, `ecdsa_sig.json`,
  `ecdsa_custom_nonce_sig.json`, `signmessage.json`.

Not checked byte for byte against one:

- transcribed, every value matched either in the pinned text or, for a
  source file, by the check the entry itself states:
  `bip67_test_vectors.json`, `chacha20_vectors.json`,
  `muhash_vectors.json`, `rfc6979.json`, `zkp_rangeproof_fixed_vectors.json`,
  `zkp_generator_vectors.json`,
  `dsa_anti_exfil_test.py`, `secp256k1_symbols.txt`.
- chain data, identified by block hash or txid: the blocks and
  transactions under `tests/block/_data/` and `tests/tx/_data/`, and
  `unspendable_script_pub_keys.json`, which is scripts rather than whole
  transactions and so is the one that cannot recompute its own
  identifier.
- not vendored: `gettxoutsetinfo_regtest.json`,
  `zkp_rangeproof_vectors.json` and `der_length_vectors.json` (btclib's
  own).
