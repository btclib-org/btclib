# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `tests/_data/README.md` must not say about itself.

The same claim `release_notes_test.py` forbids CHANGELOG.md, for the same
reason and one more. A stated count is a line every open branch has to
edit, so a pull request vendoring a vector file is guaranteed to conflict
on it -- measured: the summary read 46, 47, 48, 49 and 50 across the
branches open on one afternoon, and each of those numbers was a rebase
conflict for the others. Worse, two branches moving it to the *same* new
number merge with nothing to decide, into a number that is wrong.

The one more is that this file has no `merge=union` driver to fall back
on, and cannot have one: union keeps both sides' added lines, which is
right for a list of bullets and nonsense for the prose around them. So
the number goes, the lists stay -- they are the fact the number
summarized -- and the Summary carries the `git ls-files` command that
derives it on demand.

CLAUDE.md states the rule this module enforces: "Never state how many of
anything a file holds." Its one exception is "a count of what upstream
published -- `tests/_data/README.md`'s '121 vectors, Core's entire
file' -- which pins a vendored file rather than measuring this tree".
Everything below is an application of that sentence, not a paraphrase of
it: a numeral -- a digit run, or a spelled-out numeral as a word -- is
forbidden anywhere in this README unless `_NOT_A_COUNT` accounts for it,
or the line it sits on is named in `_EXEMPT` with the reason beside it.

The guard used to be a shape match: "N files." opening a line, and a
bullet under `## Summary` opening with a digit. Both had a gap a widened
pattern would only have moved -- the noun ("response bodies", "vectors",
a spelled-out "seven") and the section (a `###` heading or the
Provenance prose are not `## Summary` and were never checked) -- and the
general form of "a count in prose" is not regular, so a pattern loose
enough to catch every wrong shape also catches sentences that are not
wrong (issue #1633). What is enumerated instead is what is *permitted*:
every line below was found by running the pattern above against this
file as it stands and reading what it caught, not by predicting the
shape a violation would take.

The carve-outs are mechanical rather than semantic, and none of them is
the section-scoping this module used to do:

- **A fenced block is not scanned, whatever its language.** The
  ` ```text ` ones are the pin metadata -- `repo`, `path`, `commit`,
  `blob`, `pulled`, `behind` -- which this README's own "Reading an
  entry" section already defines as facts of a pin, on every entry;
  scanning them would repeat that one justification once per entry for
  nothing a reader learns twice. The ` ```shell ` ones are commands, and
  a digit in a command is an argument.
- **"one" and "zero" are matched as digits, never as spelled words.** As
  words they are pronouns and articles ("one of them", "not one", "no
  one") far more often than counts in this file's prose, and a pattern
  that treated every "one" as a numeral would flag most of its sentences
  for no reason connected to this guard.
- **A numeral naming something is subtracted before `_NUMERAL` runs.**
  `_NOT_A_COUNT` takes out an ISO date, a `bip-`/`slip-` or NIST `P-`
  number, an `issue #N` or an `ISS N`, a Wycheproof `tcId N` and a
  dotted version, each of which names a thing rather than counting one.
  A hyphen is what puts a specification number in front of the pattern
  at all: a digit run is matched between word boundaries, which
  `bip-0327` offers and a fused `BIP0327` does not, so such a number is
  caught or missed according to how upstream spells its own path. Exempting
  such a line records a decision nobody made, where an entry of
  `_EXEMPT` is meant to record one (issue #1684).

An exemption pins its line verbatim, so editing a line that carries one
means editing its entry too. That cost is one line and not a paragraph:
nothing here rewraps markdown -- `markdownlint`'s MD013 has no fixer and
prettier's own hook does not take markdown -- so a correction is
surgical, and the guards below name the line they are unhappy about.

A test rather than a hook, for the reasons `docs_test.py` gives: no
environment the suite does not already have, every interpreter of the
matrix rather than one runner, and `tests-passed` gates it without a line
in any `needs` list.
"""

import re
from pathlib import Path

_README = Path(__file__).parents[1] / "tests" / "_data" / "README.md"

# a digit run, or a spelled-out cardinal as a whole word ("one" and "zero"
# excepted -- see the module docstring)
_NUMERAL = re.compile(
    r"(?i)\b(?:\d+|two|three|four|five|six|seven|eight|nine|ten|eleven|"
    r"twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|"
    r"nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|"
    r"hundred|thousand)\b"
)

# the numerals that name something rather than count it, subtracted before
# _NUMERAL runs: an ISO date at day or month precision, a specification
# identifier as the bips and slips repositories spell one in a path and as
# NIST names a curve, an issue of this tracker in either form the prose
# uses, a Wycheproof test-case identifier, and a dotted version -- three
# shapes rather than one, a version appearing here after a name, in three
# components, and with a pre-release suffix. The first takes the version
# and never the name in front of it, which is what keeps subtracting able
# only to leave a numeral visible and never to hide one. A decimal is not
# among them on purpose: a size in megabytes or a percentage is a
# measurement, which is a count and wants a line of its own.
# No `rfc-`: an RFC is cited here with a space rather than a hyphen, and
# subtracting `RFC \d+` as well empties no line that the shapes below do
# not already empty
_NOT_A_COUNT = re.compile(
    r"\b\d{4}-\d{2}(?:-\d{2})?\b"
    r"|(?i:\b(?:bip|slip)-\d+)|\bP-\d+"
    r"|(?i:\bissues?[ /]#?\d+)|\bISS \d+"
    r"|\btcId \d+"
    r"|(?<=[a-zA-Z]-)\b\d+(?:\.\d+)+"
    r"|\b\d+\.\d+\.\d+\b"
    r"|\b\d+(?:\.\d+)+(?=(?i:rc|a|b|dev|post)\d)"
)

# the reason an exempted line carries, named once and reused: what reaches
# _EXEMPT is CLAUDE.md's own exception, "a count of what upstream
# published", and a numeral that is not one is a numeral the README drops
_UPSTREAM_FACT = (
    "a fact of the upstream specification or vendored artefact,"
    " not a count of this tree"
)

# built by running _NUMERAL against tests/_data/README.md's prose, past
# _NOT_A_COUNT (every line outside a fenced ```text``` block, see
# _prose_lines) and classifying every hit: each is named here with its
# reason, or the README no longer states it (issue #1633)
_EXEMPT: dict[str, str] = {
    "them, and `italian.txt` and the eleven other BIP39 lists nowhere, which": _UPSTREAM_FACT,
    "`BTCLIB_REGENERATE_GOLDEN=1 uv run pytest` rewrites them on purpose.": _UPSTREAM_FACT,
    "citation is pinned to a commit and the two blobs are compared.": _UPSTREAM_FACT,
    "The two halves are kept in agreement in one direction only: a test module": _UPSTREAM_FACT,
    "one of the five that *is* a copy, upstream publishing a file of that very": _UPSTREAM_FACT,
    "citation is pinned to, the git blob SHA-1 that was compared, and a": _UPSTREAM_FACT,
    "whatever had drifted was refreshed, so `behind` is 0 wherever a refresh": _UPSTREAM_FACT,
    "The comparison is on git blob SHA-1, not sha256: it is what a tree entry": _UPSTREAM_FACT,
    "alternative and caps out — `script_assets_test.json` is 9 MB.": _UPSTREAM_FACT,
    "The two hashes match for every file whose verdict is **identical**. Where": _UPSTREAM_FACT,
    "`--fix=lf`, so our blob is `aa317a3b` rather than the one above. All 19": _UPSTREAM_FACT,
    "vectors, all eight columns.": _UPSTREAM_FACT,
    "Four of the 19 are messages of 0, 1, 17 and 100 bytes: BIP340 accepts a": _UPSTREAM_FACT,
    "take one, and the 32-byte gate that used to send these four down the": _UPSTREAM_FACT,
    "Python path (issue 169) is gone. All four pass on either arithmetic:": _UPSTREAM_FACT,
    "them: six were untouched since the commit that added all eight,": _UPSTREAM_FACT,
    '(2024-05-14, "Fix the four test vectors"); and `sig_agg_vectors.json`': _UPSTREAM_FACT,
    "placeholder cited as the tip of all eight paths, when it is the tip of": _UPSTREAM_FACT,
    "56 cases between them, and `tests/ecc/musig2_test.py` runs every one:": _UPSTREAM_FACT,
    "1 sorting, 4 + 5 aggregations valid and failing, 4 nonce derivations,": _UPSTREAM_FACT,
    "2 + 3 nonce aggregations, 6 + 6 + 3 + 2 signatures (valid, refused at": _UPSTREAM_FACT,
    "signing, false on verification, refused on verification), 5 + 1": _UPSTREAM_FACT,
    "tweaked, 4 + 5 deterministic, 4 + 1 aggregated. An error case carries": _UPSTREAM_FACT,
    "function, and copies four of its error message strings verbatim": _UPSTREAM_FACT,
    "The files test the two halves of the map, and both halves are": _UPSTREAM_FACT,
    "eight `case` columns are eight assertions per row rather than one — an": _UPSTREAM_FACT,
    "`t>=p`, `info[v=0]`), which is what makes the files a branch": _UPSTREAM_FACT,
    "Neither file covers `create` or `encode`: those pick one of up to eight": _UPSTREAM_FACT,
    "regenerated seven weeks after the generation file, and one pin would have": _UPSTREAM_FACT,
    "All 11 vectors, all eight columns: five over a generator that is not": _UPSTREAM_FACT,
    "secp256k1's, three over secp256k1's own, and three failure cases -- a zero": _UPSTREAM_FACT,
    "All 15 vectors: the eight successes are the eight proofs of the file": _UPSTREAM_FACT,
    "above, read back, and the seven failures are five permutations of A, B and": _UPSTREAM_FACT,
    "Three BIP374 failure conditions have no vector in either file and are": _UPSTREAM_FACT,
    "landing on infinity. None of the three is a proof anybody generates --": _UPSTREAM_FACT,
    "Verdict: **identical**. All 28 cases, both halves of each: one sending": _UPSTREAM_FACT,
    'for sender change", which has two receiving sub-tests -- the change output': _UPSTREAM_FACT,
    "2026 revision added `input_private_key_sum`, `shared_secrets`, `tweak` and": _UPSTREAM_FACT,
    "three different failures there instead of one.": _UPSTREAM_FACT,
    "Two of the 28 publish a null where a value would be: the sending half of": _UPSTREAM_FACT,
    "The K_MAX case is the largest by far and worth naming: 2324 recipients": _UPSTREAM_FACT,
    "fails and the receiving half finds 2323 of the 2324 outputs -- the file": _UPSTREAM_FACT,
    "Three BIP352 rules have no vector here and are covered by the test module": _UPSTREAM_FACT,
    "v0 defines them), the 1023-character bound, and the label range. The": _UPSTREAM_FACT,
    "no upstream file and no byte comparison to make. All four seeds and all": _UPSTREAM_FACT,
    "34 extended keys of test vectors 1 to 4 appear verbatim in the pinned": _UPSTREAM_FACT,
    "text, and the derivation counts match: 6, 6, 2, 3.": _UPSTREAM_FACT,
    "The original pin was the commit that *added* test vector 4 rather than": _UPSTREAM_FACT,
    "holding all 34 keys, the parent holding 28, which made that pin checkable": _UPSTREAM_FACT,
    "and again on 2026-08-06 — both times still test vectors 1 to 5 and no": _UPSTREAM_FACT,
    "sixth, every extended key in it one of ours, 48 matching the key": _UPSTREAM_FACT,
    "pattern: our 34 valid plus 14 of the 16 invalid, the other 2 being the": _UPSTREAM_FACT,
    "zero-prefix keys of test vector 5, which serialize outside it — the pin": _UPSTREAM_FACT,
    "Verdict: **transcribed**. All 16 invalid extended keys are exactly the 16": _UPSTREAM_FACT,
    "of BIP32 test vector 5 — no omissions, no local additions — both at the": _UPSTREAM_FACT,
    "first put these 16 keys into the BIP. The pin above is the tip of the": _UPSTREAM_FACT,
    "section is 34 `* Case:` entries — 20 invalid, 10 valid, 4 signer check": _UPSTREAM_FACT,
    "failures — and all 34 are here, each with the base64 the prose gives and": _UPSTREAM_FACT,
    "which are prose steps rather than cases. Five of them are the raw": _UPSTREAM_FACT,
    "that these four psbts must fail the check, so that field is btclib's own": _UPSTREAM_FACT,
    "Verdict: **transcribed**, complete. All 17 psbts in the pinned text are": _UPSTREAM_FACT,
    "in our file and all 17 of ours are in the text — 11 invalid, 6 valid, the": _UPSTREAM_FACT,
    "same 17 on 2026-07-30 and again on 2026-08-06 when re-checked against the": _UPSTREAM_FACT,
    'tip. The two "PSBT_KEY_PATH_SIG" cases were renamed': _UPSTREAM_FACT,
    "section is here: 24 invalid, 14 valid, and the 10 of the timelock": _UPSTREAM_FACT,
    "compute beside them — `null` for the one whose two kinds of locktime": _UPSTREAM_FACT,
    "cannot be reconciled. 48 base64 strings for 47 cases, one valid case": _UPSTREAM_FACT,
    "publishing two serializations of itself.": _UPSTREAM_FACT,
    '== bytes.fromhex(hex)` for all of them but one: the "1 input, 2 output': _UPSTREAM_FACT,
    "be found by the name the other 46 use. A refresh should read the labels": _UPSTREAM_FACT,
    "The `error message` of an invalid case is btclib's own, as in the two": _UPSTREAM_FACT,
    "case: half of the 24 are a version 0 psbt carrying one of BIP370's": _UPSTREAM_FACT,
    "twelve fields, refused by the name of the field, and the other half are": _UPSTREAM_FACT,
    "version 2 psbts refused for the unsigned transaction version 2 excludes,": _UPSTREAM_FACT,
    "for one of the seven fields it requires, or for a required locktime": _UPSTREAM_FACT,
    "The valid ones are read and written back byte for byte, and the ten": _UPSTREAM_FACT,
    "for each — the `null` one by the refusal it gets, its two kinds of": _UPSTREAM_FACT,
    "section is here: 10 invalid and 14 valid, the valid ones being four": _UPSTREAM_FACT,
    "spend cases in three variants each — participant pubkeys only, then the": _UPSTREAM_FACT,
    "pubnonces, then the partial signatures — and two receiving cases, which": _UPSTREAM_FACT,
    "24.": _UPSTREAM_FACT,
    'Two of the ten invalid psbts are **the same bytes**: "PSBT with x-only': _UPSTREAM_FACT,
    "The `error message` of an invalid case is btclib's own, as in the three": _UPSTREAM_FACT,
    "files above. Each of the ten is a length — an x-only key where BIP373": _UPSTREAM_FACT,
    "other five are transcribed from mediawiki prose -- so the `bip375_` prefix": _UPSTREAM_FACT,
    "the one place the two coincide. 42 psbts, 22 invalid and 20 valid, the": _UPSTREAM_FACT,
    "under a second parse. Measured on all 37 psbts that parse.": _UPSTREAM_FACT,
    "All 22 invalid psbts are refused and all 20 valid ones pass, and it takes": _UPSTREAM_FACT,
    "two test modules to say so: `tests/psbt/bip375_test.py` holds the codec to": _UPSTREAM_FACT,
    'the file -- the field shapes, which is five of the six "PSBT Structure"': _UPSTREAM_FACT,
    "cases -- and `tests/psbt/silent_payments_test.py` holds the two roles to": _UPSTREAM_FACT,
    "it, which is the other seventeen. Each invalid case's category is read off": _UPSTREAM_FACT,
    'valid -- "two sp outputs - output 0 uses label=3 / output 1 uses label=1"': _UPSTREAM_FACT,
    "-- and its two spend keys are in descending order, so the two rules assign": _UPSTREAM_FACT,
    "the 66-byte info fields and sorting the bech32m address strings both order": _UPSTREAM_FACT,
    "`bip-0375/validator/validate_psbt.py` walks index order too, so two of its": _UPSTREAM_FACT,
    "three artefacts agree and the prose is the outlier.": _UPSTREAM_FACT,
    "Verdict: **transcribed**, complete. All five groups — their 15 public keys": _UPSTREAM_FACT,
    "and their five p2sh addresses — appear verbatim in the pinned text, and": _UPSTREAM_FACT,
    "Between them they are what `tests/bip322_test.py` runs: three": _UPSTREAM_FACT,
    "transaction hashes, eight *simple* signatures, ten *full*, three": _UPSTREAM_FACT,
    "*proof of funds*, and 36 error cases, with nothing left out and nothing": _UPSTREAM_FACT,
    "marked `xfail`. Two of the three proof-of-funds vectors were, until": _UPSTREAM_FACT,
    "tx_id with vout 0, which `OutPoint.assert_valid` refused and Bitcoin": _UPSTREAM_FACT,
    "The file is UTF-8 rather than ASCII, one of its three messages running": _UPSTREAM_FACT,
    "from Latin-1 accents through CJK to an astral-plane emoji, and": _UPSTREAM_FACT,
    "[btcd's BIP322 implementation](https://github.com/btcsuite/btcd/pull/2521),": _UPSTREAM_FACT,
    "our copy: the master root key, the two entropy cases of the": _UPSTREAM_FACT,
    "specification's own section with the derived key of each, the 80-byte": _UPSTREAM_FACT,
    "BIP85-DRNG read, the three BIP39 mnemonics, the hdseed WIF, the xprv,": _UPSTREAM_FACT,
    "the 64 hex bytes, the base64 and base85 passwords, the ten dice rolls,": _UPSTREAM_FACT,
    "and the three Nostr nsecs of application 128002'. `tests/bip85_test.py`": _UPSTREAM_FACT,
    "RSA (828365') is the one application with no vector here, because the": _UPSTREAM_FACT,
    "Two of the BIP's fields are not what their name reads as, and": _UPSTREAM_FACT,
    "the name reads: the DERIVED ENTROPY of application 32' is the second half": _UPSTREAM_FACT,
    "of the 64 bytes, the private key of the xprv, and that of 39' is already": _UPSTREAM_FACT,
    "one with the message btclib refuses it with — two of those refusals": _UPSTREAM_FACT,
    "six valid descriptors with the scripts they produce at each index listed,": _UPSTREAM_FACT,
    "and all fourteen invalid ones with the message each is refused with. Five": _UPSTREAM_FACT,
    "One of the fourteen is refused for a reason of btclib's own rather than": _UPSTREAM_FACT,
    "vector and the multipath descriptor the two compile to, checked branch by": _UPSTREAM_FACT,
    "key-information vector, byte for byte. Four": _UPSTREAM_FACT,
    "of the Invalid policies section's nine are checked too, in": _UPSTREAM_FACT,
    "cardinality-above-two and derivation-before-aggregation ones, each a": _UPSTREAM_FACT,
    "property of the template text alone. The other five are not:": _UPSTREAM_FACT,
    "same placeholder need the two occurrences compared against each other,": _UPSTREAM_FACT,
    '"use multipath_descriptors first" -- a coincidence of the raw `<0;1>`': _UPSTREAM_FACT,
    "Verdict: **transcribed**, complete: all three aggregate keys, the": _UPSTREAM_FACT,
    "BIP328's, and a `key_sort` applied here reaches none of the three": _UPSTREAM_FACT,
    "Verdict: **identical**. 1292 entries, 1237 vectors once the comment lines": _UPSTREAM_FACT,
    "are dropped: four cases added since the previous pin, one of them a": _UPSTREAM_FACT,
    "Five of the 1237 are TAPSCRIPT cases whose witness and output script are": _UPSTREAM_FACT,
    "apart. The generation is load-bearing: parsed literally, three of the": _UPSTREAM_FACT,
    "five fail on `OP_#TAPROOTOUTPUT#`, and the two expecting a failure get": _UPSTREAM_FACT,
    "Verdict: **identical**, 121 vectors — Core's entire file, nothing": _UPSTREAM_FACT,
    "subsetted, and not only legacy: 2 of the 121 name WITNESS in their flags.": _UPSTREAM_FACT,
    "Verdict: **identical**, 93 vectors — Core's entire file, here too, with": _UPSTREAM_FACT,
    "14 of the 93 naming WITNESS in their flags.": _UPSTREAM_FACT,
    "Verdict: **identical**, 70 rows — 54 addresses and 16 WIFs, over the four": _UPSTREAM_FACT,
    "Eight of the 54 are witness versions 2, 3 and 16.": _UPSTREAM_FACT,
    "for them: it renders the five types `type_and_payload` names and a future": _UPSTREAM_FACT,
    "Verdict: **identical**, 70 strings, each a one-element array. All 70 are": _UPSTREAM_FACT,
    "refused by all four of the entry points that could be handed one —": _UPSTREAM_FACT,
    "Verdict: **identical**, 21 rows of `[hex, base58]`. Core's": _UPSTREAM_FACT,
    "`encode`/`decode` — one row is 256 bytes, 348 base58 characters,": _UPSTREAM_FACT,
    "Verdict: **identical**, 146 cases. Each carries a key, an input split": _UPSTREAM_FACT,
    "of two constructions this library implements one of:": _UPSTREAM_FACT,
    "`expected.siphash24` is standard SipHash-2-4, what `hashes.siphash`": _UPSTREAM_FACT,
    "is Core's unpadded, jumbo-block SipHash-1-3 variant": _UPSTREAM_FACT,
    "(`crypto/siphash.h`'s `SipHasher13UJ`), present on 64 of the 146 rows —": _UPSTREAM_FACT,
    "those whose blocks are each 8 or 32 bytes, the two Core evaluates that": _UPSTREAM_FACT,
    "(21, RFC 7539/8439's own Appendix A.1/A.2/A.4 vectors among them, cited in": _UPSTREAM_FACT,
    "that test case's own comments), its five arguments read off as `message`,": _UPSTREAM_FACT,
    "matching `TestChaCha20`'s own two modes. The regex that produced it is": _UPSTREAM_FACT,
    "`muhash_tests`' own three numeric checks: the": _UPSTREAM_FACT,
    "`FromInt(0)*FromInt(1)/FromInt(2)` cancellation (`insert`/`remove`,": _UPSTREAM_FACT,
    "two conventions differ, confirmed against `crypto_tests.cpp`'s own two": _UPSTREAM_FACT,
    "expanded here to the full 32-byte element (`i` then 31 zero bytes) each": _UPSTREAM_FACT,
    "reads all of them. All ten blocks parse under the full validity check,": _UPSTREAM_FACT,
    "round-trip byte for byte, hash to the hash the row states, and the six at": _UPSTREAM_FACT,
    "comparing them. The four below it commit nothing, which is what makes the": _UPSTREAM_FACT,
    "then the two answers, so every basic filter of the file is rebuilt from": _UPSTREAM_FACT,
    "The ten are testnet, where the four blocks of `tests/block/_data/` are": _UPSTREAM_FACT,
    "Four of the calls are not here, being loops rather than literals: the": _UPSTREAM_FACT,
    "`multi_a()` of twenty-one keys, the three `and_b()` chains that pass the": _UPSTREAM_FACT,
    "p2wsh ops, stack and script-size limits, and the two nestings that reach a": _UPSTREAM_FACT,
    "thousand elements on the stack. `tests/descriptors/miniscript_test.py`": _UPSTREAM_FACT,
    "of the four Core expands from the private form alone, and the two": _UPSTREAM_FACT,
    "Not matched since: the commit above adds five cases -- a `musig()`": _UPSTREAM_FACT,
    "before. The two hold the same names, compared on 2026-09-03, and the": _UPSTREAM_FACT,
    "directions in `bitcoin/bitcoin#15437`. `src/btclib/p2p/reject.py` says": _UPSTREAM_FACT,
    "but an *interface*, and the two entries are the two halves of it: the": _UPSTREAM_FACT,
    "`.github/workflows/integration-hwi.yml` installs release 3.2.0, so two": _UPSTREAM_FACT,
    "`HWI_COMMAND_FLAGS` table above, `displayaddress`'s two modes taking": _UPSTREAM_FACT,
    "`--multipath-index 1` -- `HwiSigner.display_policy_address` always": _UPSTREAM_FACT,
    "whose `hwilib/_cli.py` adds them is what makes the two interfaces one.": _UPSTREAM_FACT,
    "The parser has only ever grown, and only additively, since 2021:": _UPSTREAM_FACT,
    "`--emulators` in 2024, `--chain` and `--expert` on enumerate in 2022,": _UPSTREAM_FACT,
    "gained a second answer key, `signed`, in 2021 — which is how this pin": _UPSTREAM_FACT,
    "down, and now checks the two against each other.": _UPSTREAM_FACT,
    "`INVALID_POLICY` (-19) had already been checked in from ahead of, and the": _UPSTREAM_FACT,
    "the old name as a compat alias with the same code, -4 — is why": _UPSTREAM_FACT,
    "on — -14 is somebody pressing the button that says no, -3 is a cable, -9": _UPSTREAM_FACT,
    "Not in a release: `INVALID_POLICY` (-19). The rest of the table is in": _UPSTREAM_FACT,
    "3.2.0, where -4 carries the misspelling this pin's commit corrects — a": _UPSTREAM_FACT,
    "Verdict: **identical but for a trailing newline** — our 9,243,521 bytes": _UPSTREAM_FACT,
    "are that blob's 9,243,520 plus the `\\n` the `end-of-file-fixer` hook": _UPSTREAM_FACT,
    "added, so our blob is `601a40db`. 2244 vectors, in the same order.": _UPSTREAM_FACT,
    "Two caveats, and the second is the one that matters.": _UPSTREAM_FACT,
    "The commit is a weak pin. The whole visible history of that path is three": _UPSTREAM_FACT,
    "commits, all stamped within a second of `2025-07-23T19:45:18Z`, which": _UPSTREAM_FACT,
    "cannot be when a 2021 dump was added: qa-assets prunes its history — the": _UPSTREAM_FACT,
    "survive the next prune. The blob SHA-1 above will, and it is what a": _UPSTREAM_FACT,
    "Verdict: **reformatted**. 349 vectors, JSON-equal to the upstream blob;": _UPSTREAM_FACT,
    "ours is pretty-printed at four spaces. Re-checked on 2026-07-30: still": _UPSTREAM_FACT,
    "Verdict: **reformatted**. 199 vectors, JSON-equal.": _UPSTREAM_FACT,
    "Verdict: **reformatted**. 200 vectors, JSON-equal, and all 200 are": _UPSTREAM_FACT,
    "Verdict: **identical**. Four blocks — genesis twice, 99,960 and 99,993 —": _UPSTREAM_FACT,
    "The two genesis entries differ only in the `cur_time` beside them, and it": _UPSTREAM_FACT,
    "two-hour window and the second is the instant genesis was mined.": _UPSTREAM_FACT,
    "Verdict: **identical**. Seven blocks consensus refuses, and the only": _UPSTREAM_FACT,
    "`assert_valid` cannot see: the genesis block two hours and one second": _UPSTREAM_FACT,
    "`assert_valid_contextual`, Core's `time-too-new`. Three of the rest are": _UPSTREAM_FACT,
    "those three rules is asserted in `block_test.py` instead, from a block": _UPSTREAM_FACT,
    "One of the seven is misnamed, and the file is vendored with the name": _UPSTREAM_FACT,
    "three other findings as petertodd/python-bitcoinlib#323. Renaming it": _UPSTREAM_FACT,
    "Two blocks of values are cited inline instead, each small enough to read": _UPSTREAM_FACT,
    "- the five secp256k1 RFC6979 vectors of `Test_RFC6979`, in": _UPSTREAM_FACT,
    "  ones, and four of the five differ from what RFC6979 arrives at before": _UPSTREAM_FACT,
    "- the six nBits-to-difficulty pairs of": _UPSTREAM_FACT,
    "Verdict: **identical**. All twelve language arrays, in order and value": _UPSTREAM_FACT,
    "Two `pulled` dates because the `english` array was here on its own for": _UPSTREAM_FACT,
    "the same file for it, and `behind 0 revisions` is now about the whole of": _UPSTREAM_FACT,
    "Verdict: **reformatted**. 24 vectors, JSON-equal; upstream's indentation": _UPSTREAM_FACT,
    "wanders by a space or two and ours is what `json.dumps(indent=4)` writes.": _UPSTREAM_FACT,
    "The two Portuguese sentences beside them answer electrum's": _UPSTREAM_FACT,
    "`bip39_is_checksum_valid` yes and no, over its own 1626-word list.": _UPSTREAM_FACT,
    "lint gate's two spell checkers read a python source and skip `_data`, and": _UPSTREAM_FACT,
    "Verdict: **identical**. SLIP-0039's 1024 words, ten bits each, and the": _UPSTREAM_FACT,
    "for the list -- 1024 words, none shorter than four letters or longer": _UPSTREAM_FACT,
    "than eight, and all 1024 four-letter prefixes distinct -- which is what": _UPSTREAM_FACT,
    "Verdict: **identical but for a trailing newline** -- our 22,412 bytes": _UPSTREAM_FACT,
    "are that blob's 22,411 plus the `\\n` the `end-of-file-fixer` hook added,": _UPSTREAM_FACT,
    "so our blob is `2e6da291`. 45 quadruples -- description, mnemonics,": _UPSTREAM_FACT,
    "master secret, BIP32 root extended private key -- of which 15 are valid": _UPSTREAM_FACT,
    "and 30 have an empty master secret, meaning combining those mnemonics": _UPSTREAM_FACT,
    "must fail. All 45 are exercised, the 30 included: an invalid vector left": _UPSTREAM_FACT,
    "commit that added the extendable backup flag and the four vectors for": _UPSTREAM_FACT,
    "Four of the 15 valid vectors are checked in both directions. They are": _UPSTREAM_FACT,
    "the 1-of-1 shares, whose value is the encrypted master secret itself and": _UPSTREAM_FACT,
    "regenerates each of the four mnemonics word for word from the master": _UPSTREAM_FACT,
    "secret. The other 11 are recovery only, a 2-of-3 share being random by": _UPSTREAM_FACT,
    "the two ECDSA profiles is explained, and where the difference the files": _UPSTREAM_FACT,
    "measured, all files verify identically at 32 and at 64.": _UPSTREAM_FACT,
    "and its verifier no longer applies that rule, so two of these verdicts": _UPSTREAM_FACT,
    "are exempted rather than asserted — `wycheproof_test.py` reads which two": _UPSTREAM_FACT,
    "case is otherwise the same 463 cases, `numberOfTests` included.": _UPSTREAM_FACT,
    "above, without the bitcoin profile's two extra rules: what a": _UPSTREAM_FACT,
    "of the two the files above vary one at a time.": _UPSTREAM_FACT,
    "digests that report their own length and a SHAKE's is 0.": _UPSTREAM_FACT,
    "Verdict: **identical**. Key agreement, with the public key X.509-encoded": _UPSTREAM_FACT,
    "above with the keys JWK-encoded (RFC 7517) rather than X.509: `WrongCurve`": _UPSTREAM_FACT,
    "feature 100\" included: what refuses that one is `btclib.bolt9`'s": _UPSTREAM_FACT,
    "every run — so the first two entries verify themselves, and are the only": _UPSTREAM_FACT,
    "`bitcoin-cli getblock <hash> 0` returns the first three and": _UPSTREAM_FACT,
    "The twelve `scriptPubKey`s reported in issue #123, the five transactions": _UPSTREAM_FACT,
    "that carry them being the five the issue lists. Each entry holds the": _UPSTREAM_FACT,
    "`getrawtransaction_error.json` is Core's too, code `-5` with the message": _UPSTREAM_FACT,
    "`getrawtransaction.json` and in `esplora_tx_hex.txt` is transaction 1 of": _UPSTREAM_FACT,
    "block 170 —": _UPSTREAM_FACT,
    "— the first bitcoin payment between two people, and it is not fetched": _UPSTREAM_FACT,
    "already vendored above, so the two copies can be compared without a": _UPSTREAM_FACT,
    "The height and hash the rest carry are block 481824,": _UPSTREAM_FACT,
    "and `esplora_block_header.txt` carry the first eighty bytes of that same": _UPSTREAM_FACT,
    "is the same 275 bytes as the hex in `getrawtransaction.json` and": _UPSTREAM_FACT,
    "`rest_headers.bin` the same eighty bytes as `getblockheader.json` and": _UPSTREAM_FACT,
    "Regenerating one of these is reading the two block files: the Core and": _UPSTREAM_FACT,
    "Appendix A.2 of RFC 6979, transcribed: 50 vectors, ten each for NIST": _UPSTREAM_FACT,
    "**Unresolved, and probably unresolvable.** These 12-word mnemonics with": _UPSTREAM_FACT,
    "citation two lines above the values is one that gets checked.": _UPSTREAM_FACT,
    "`SEED_VECTORS`' five passphrase-bearing rows each carry the": _UPSTREAM_FACT,
    "The pre-2.0 scheme is the same arrangement and four more of upstream's": _UPSTREAM_FACT,
    "`abandon`, deleted — 2047 words, so that `WORDLISTS.load_lang` raises": _UPSTREAM_FACT,
    "from `english.txt` if that ever changes, which it has not since 2014.": _UPSTREAM_FACT,
    "above deliberately leaves out. The starting psbts are five steps of the": _UPSTREAM_FACT,
    'BIP\'s "2-of-3 Multisig Workflow" walk-through — prose steps rather than': _UPSTREAM_FACT,
    "`8c369ac8e60629ac6c032ffe21bb5ec5b35213d7` (2026-07-16), where all five": _UPSTREAM_FACT,
    "appear verbatim; the two version 2 cases start instead from the first": _UPSTREAM_FACT,
    "- the **creator**'s psbt with a `PSBT_GLOBAL_VERSION` of 1, and with the": _UPSTREAM_FACT,
    "  `0xff` of its magic bytes replaced — the two `invalid psbts`, which": _UPSTREAM_FACT,
    "  unsigned. It is bytes like every other case here, where the three": _UPSTREAM_FACT,
    "  drops an input rather than leaving two counts to differ;": _UPSTREAM_FACT,
    "- two version 2 psbts, BIP370's first valid one with its": _UPSTREAM_FACT,
    "  how a version 2 parse knows how many maps follow, so a wrong one is a": _UPSTREAM_FACT,
    "does not touch it — the five psbts are fixed bytes, and the edits are": _UPSTREAM_FACT,
    "  in a repository that rewrites its history. The blob SHA-1 is the pin": _UPSTREAM_FACT,
    "  reach is an entry whose `behind` already reads other than 0, a gap": _UPSTREAM_FACT,
    "request vendoring a file is guaranteed to have -- and two branches moving": _UPSTREAM_FACT,
    "  chain data two of the entries above already hold.": _UPSTREAM_FACT,
}


def _countable(line: str) -> str:
    """`line` with the numerals that name rather than count removed."""
    return _NOT_A_COUNT.sub(" ", line)


def _prose_lines() -> list[str]:
    """Every line of the README outside a fenced ```text``` block."""
    in_fence = False
    lines = []
    for line in _README.read_text(encoding="utf-8").split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    return lines


def test_every_numeral_outside_the_allowlist_is_a_count_of_this_tree() -> None:
    """Enforces CLAUDE.md's "Never state how many of anything a file holds".

    A numeral on a line `_EXEMPT` does not name is either a count of what
    this tree holds -- drop it, the way "the eight BIP327 files" became
    "the BIP327 files" -- or it is CLAUDE.md's own exception, "a count of
    what upstream published", and belongs in `_EXEMPT` with the reason
    beside it.
    """
    offenders = sorted(
        {
            line
            for line in _prose_lines()
            if _NUMERAL.search(_countable(line)) and line not in _EXEMPT
        }
    )
    assert not offenders, (
        "tests/_data/README.md states a numeral CLAUDE.md's"
        ' "Never state how many of anything a file holds" forbids,'
        f" on a line _EXEMPT does not name: {offenders!r}"
    )


def test_every_exemption_is_still_a_line_that_needs_one() -> None:
    """An exemption outliving its line is dormant, not gone.

    The discipline `tests/p2p/core_commands_test.py`'s
    `test_every_name_left_out_is_a_name_the_other_side_has` already
    applies to its own exemptions: each of `_EXEMPT`'s lines must still be
    in the file, verbatim, and must still match `_NUMERAL` once
    `_NOT_A_COUNT` has run over it -- a line the README no longer carries,
    or whose every numeral is a date or an identifier, is an exemption
    nothing needs and nothing here would otherwise notice.
    """
    lines = set(_prose_lines())
    missing = sorted(line for line in _EXEMPT if line not in lines)
    assert not missing, f"exempted, and no longer in the README: {missing!r}"
    stale = sorted(line for line in _EXEMPT if not _NUMERAL.search(_countable(line)))
    assert not stale, f"exempted, and states no numeral any more: {stale!r}"


def test_the_pattern_still_matches() -> None:
    """The guard above passes for free if `_NUMERAL` matches nothing.

    Which is the failure mode of every assertion written in the negative,
    and the one the file it reads cannot reveal: a pattern reworded past
    the text it forbids leaves a green test guarding an empty set. The
    first four are the strings issue #1633 measured the old, shape-based
    patterns missing; the other two are what the module's own guard
    caught before the rewrite and must go on catching after it.
    """
    for text in (
        "### `tests/fetch/_data/*` — seven response bodies",
        "- the seven under `tests/fetch/_data/` are response bodies",
        "7 files.",
        "- 7 files here",
        "49 files. Against a pinned blob:",
        "Fifty files. Against a pinned blob:",
    ):
        assert _NUMERAL.search(_countable(text)), text


def test_a_numeral_that_names_something_is_subtracted_and_a_count_is_not() -> None:
    """`_NOT_A_COUNT` fails in two directions, and only one of them is loud.

    A shape that stops matching puts its lines back in front of `_NUMERAL`,
    and the guard above says which; a shape that reaches past what it names
    swallows the count beside it and the guard goes quiet. The second group
    is that half: each line states a count *and* carries a date, an
    identifier or a version, and each is exempted for the count alone.
    """
    for named in (
        "Pulled 2020-06-08, except `block_200000.bin`, 2020-06-09.",
        "All of them entered upstream in 2026-08, after 3.2.0 shipped, so the",
        "BIP322 files on 2026-08-08, and the Wycheproof files with the licence",
        "The vectors of `bip-0327/vectors/`, vendored whole",
        "P-192, P-224, P-256, P-384 and P-521, as `tests/ecc/rfc6979_test.py`",
        "which engine the vectors feed (issue 168).",
        "is not implemented (issue #187), so there is nothing yet for those to",
        "[ISS 1120](https://github.com/btclib-org/btclib/issues/1120) is where",
        "`Untruncatedhash` case of the pair as tcId 190.",
        "licence that is not MIT: Apache-2.0, whose condition on redistribution",
    ):
        assert not _NUMERAL.search(_countable(named)), named
    for counted in (
        '(2024-05-14, "Fix the four test vectors"); and `sig_agg_vectors.json`',
        "The twelve `scriptPubKey`s reported in issue #123, the five transactions",
        "Verdict: **identical**. SLIP-0039's 1024 words, ten bits each, and the",
        "`.github/workflows/integration-hwi.yml` installs release 3.2.0, so two",
    ):
        assert _NUMERAL.search(_countable(counted)), counted
