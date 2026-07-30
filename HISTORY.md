# Release notes

Notable changes to the codebase are documented here.

Release names follow *[calendar versioning](https://calver.org/)*:
full year, short month, short day (YYYY-M-D)

## v2026.8 (work in progress, not released yet)

Major changes includes:

- dropped python 3.7 and 3.8 support, added 3.13 and 3.14
- development and CI now track the btclib_libsecp256k1 bindings under
  development (built from source), instead of the released ones; the
  published btclib still depends on btclib_libsecp256k1 from PyPI
- the script engine treats a signature or public key that libsecp256k1
  refuses to parse as a failed verification: the new bindings raise a
  ValueError where the old ones returned false
- removed btclib.ec.libsecp256k1 and btclib.ecc.libsecp256k1, the two
  hand-written cffi wrappers: signing, verification, and generator
  multiplication now call the bindings, whose context is created once
  with SECP256K1_CONTEXT_NONE and randomized, as libsecp256k1 asks
  (issue #125)
- btclib_libsecp256k1 is a required dependency, as pyproject.toml has
  always declared: the import is no longer guarded, and secp256k1
  signing, verification, and generator multiplication always go through
  the bindings. The python implementation is not going anywhere: it
  serves every other curve, a hash function other than sha256, and a
  caller-imposed nonce, and the test suite keeps validating it against
  the bindings, libsecp256k1 being the authority on the answer
- `borromean.assert_as_valid` raises BTClibRuntimeError("signature
  verification failed") and returns None, as its `dsa`, `ssa`, and `bms`
  counterparts do; it used to return a bool, so a caller following the
  library's own convention and calling it as a statement accepted forged
  ring signatures in silence
- new `pedersen.assert_as_valid`, raising BTClibRuntimeError("commitment
  verification failed"): `pedersen` was the one module with a `verify`
  and no assert_as_valid beside it, leaving no way to learn why opening
  a commitment failed
- importing btclib no longer traps decimal FloatOperation in the
  process-wide context: `btclib.amount` used to do it at import time,
  changing the Decimal semantics of the unrelated code of any application
  merely importing, say, `btclib.tx`. The two functions doing Decimal
  algebra now trap it in a `decimal.localcontext()` of their own, which
  also makes them behave the same in a thread created elsewhere: the
  current context is thread-local, so the process-wide trap was absent
  there
- a hand-built BlockHeader no longer serializes differently on machines
  in different time zones: the `time` default is now the epoch as an
  aware datetime (it was naive, i.e. read back as local time by the
  `timestamp()` call in `serialize`), and `assert_valid` rejects a naive
  datetime instead of guessing its instant. `parse` was already correct,
  producing UTC
- the third BlockHeader parameter is named `merkle_root`, as the field
  is: it was `merkle_root_`, which made `BlockHeader(merkle_root=...)`
  a TypeError
- a default-constructed `TxIn` no longer shares its `prev_out` and
  `script_witness` with every other one, nor a `PsbtIn` its
  `final_script_witness`: the defaults were `OutPoint()` and `Witness()`
  calls in the signature, evaluated once at definition time, so
  appending to the witness stack of one input added that element to
  inputs built later, and assigning `prev_out.vout` left the constructor
  raising BTClibValueError("invalid OutPoint") for every subsequent
  default-constructed TxIn in the process. They are now built per call,
  the `None` sentinel spelling the library already used for `Tx.vin`,
  `Tx.vout`, and `Witness.stack`, and ruff's B008 is no longer ignored,
  so the pattern cannot come back (issue #139)
- `sig_hash.from_tx` and the script engine no longer strip the annex from
  the transaction they are handed: `taproot_annex_and_ext` and
  `taproot_get_annex` assigned the trimmed stack back to the caller's
  witness, so a second sighash of the same input hashed a different
  preimage, and `tx.serialize()` and `tx.hash` changed under the caller —
  `verify_transaction` rewrote the very transaction it was validating.
  The two now work on a local copy, `taproot_get_annex` returning the
  trimmed stack instead of writing it; the p2wpkh and p2wsh branches of
  `verify_input` hand the interpreter a copy too, it popping what it
  consumes. `taproot_annex_and_ext` also loses its unused `prevouts`
  parameter (issue #140)
- `OutPoint`, `TxOut`, and `Witness` are frozen dataclasses, as the FIXME
  on the first two asked. Assigning to a field raises FrozenInstanceError
  now, where it used to corrupt whatever else held the same object: the
  two entries above are both that bug, and the second one —
  `witness.stack = witness.stack[:-1]` on the caller's transaction — is
  the assignment freezing would have refused. Code doing
  `out_point.tx_id = ...`, `tx_out.value = ...`, or `witness.stack = ...`
  must build a new instance instead; `TxIn.prev_out` and
  `TxIn.script_witness` stay settable, TxIn not being frozen, and
  `sig_hash.from_tx` rebuilds the outputs SIGHASH_SINGLE blanks rather
  than assigning into them. Freezing a dataclass is shallow, though, so it
  is not by itself the fix for issue #139: `script_pub_key.script` can
  still be rebound through a frozen TxOut, Script not being frozen. An
  OutPoint is immutable all the way down, both its fields being immutable
  too, so the generated `__hash__` works and it can serve as the dict key
  or set member an utxo set wants; a TxOut holds a ScriptPubKey, which is
  unhashable, so hashing one raises TypeError (issue #139)
- `Witness.stack` is a `tuple[bytes, ...]`, no longer a `list[bytes]`,
  which is what makes a frozen Witness immutable all the way down rather
  than only on the surface: `witness.stack.append(...)` used to reach
  every holder of that witness, the shared default of issue #139
  included, and there is no in-place mutation left to reach them with.
  A Witness is hashable now, alone among these dataclasses. Code
  appending to a stack must build a new Witness — `Witness([*w.stack,
  element])` — and code comparing one against a list must compare against
  a tuple; the constructor still accepts any sequence, so `Witness([...])`
  and `Witness.from_dict` are unchanged, and `to_dict` still yields a
  list, being json. The script interpreter pops from a list of its own,
  which `verify_input` and `taproot_get_annex` hand it (issue #139)
- `var_int.parse` rejects what Bitcoin Core rejects. It used to accept a
  non-shortest encoding (`fd0100` read as 1), which gave the same
  transaction two serializations and so two txids, and it did not check
  that its reads returned the announced number of bytes, so a truncated
  `fd01` read as 1 and a bare `fd` as 0 — `int.from_bytes(b"")` being 0,
  and `stream.read` returning short without raising. Both are
  BTClibValueError now, as is the end of the stream, which used to escape
  the library's own exception contract as IndexError. There is also a
  `MAX_SIZE` cap of 32 MiB, the range check of Core's `ReadCompactSize`
  and the reason a nine-byte var_int can no longer ask a parser for 2^64-1
  elements; the new `max_size` parameter raises it for a var_int that is
  neither a length nor a count (issue #135)
- `Block.assert_valid` rejects the CVE-2012-2459 block mutation, as Core
  does. Duplicating the trailing subtree of any level of the merkle tree
  leaves the root unchanged — appending a copy of the last four
  transactions of block 200,000 yields its very own merkle root — so the
  header of an honest block commits to the mutated list too, and btclib
  accepted both while the network accepts one. The new
  `hashes.merkle_root_and_mutated` returns the root together with Core's
  `mutated` flag, set when two *distinct* siblings are equal at any
  level, and the block raises BTClibValueError("duplicate transaction"),
  Core's bad-txns-duplicate, after the root comparison. Padding an odd
  level by hashing its last value with itself is the algorithm, not a
  mutation, and is not flagged: flagging it would reject almost every
  block. `merkle_root` is unchanged for every other use, beyond raising
  on an empty list instead of looping forever (issue #134)
- `Block.assert_valid` checks the BIP141 witness commitment. The merkle
  root of a header commits to txids, which by segwit's design leave every
  witness out, and nothing else looked at the `aa21a9ed` coinbase output:
  the witnesses of a block — every signature in it — could be replaced
  wholesale, header and merkle root untouched, and btclib said the block
  was valid. It now computes the witness merkle root over wtxids, hashes
  it with the nonce of the coinbase witness, and compares, raising
  BTClibValueError on a mismatch (Core's bad-witness-merkle-match), on a
  coinbase witness that is not one 32-byte element (bad-witness-nonce-size)
  and on witness data in a block carrying no commitment
  (unexpected-witness). A block with no witness data at all is still
  accepted with no commitment: that is what a legacy node sees, and there
  is nothing left in it to be taken on trust. `merkle_root_and_mutated`
  gained a `_from_hashes` variant, the tree over leaves that are hashes
  already (issue #163)
- a script verification failure says what went wrong, and where. The 76
  bare `BTClibValueError()` raises — 70 of them under `script/engine/` —
  carried an empty message, so a wrong public key encoding, an unbalanced
  OP_IF, and a stack underflow were one exception with one (empty) text.
  Each carries a short message now, and the two interpreter loops re-raise
  it as the new `ScriptError(BTClibValueError)`, adding the command index
  and the stack depth that an op code implementation, handed the stack
  alone, cannot know: `OP_RETURN (command 2, stack depth 2)`. Code
  catching BTClibValueError keeps catching these, ScriptError being one.
  A stack underflow used to escape the library's exception contract as
  IndexError, and an op code with no name as KeyError, from the legacy
  engine and from `taproot.parse` alike: all are BTClibValueError now
  (issue #141)
- the "consider using OP_x instead" warning `script.serialize` emits for a
  number in [-1, 16] pushed as data is a new `BTClibUserWarning`, not a
  bare UserWarning: an application could not silence it, or promote it to
  an error, without naming btclib's module or the message text. It stays a
  UserWarning, so a filter on that still catches it. The test suite is the
  first beneficiary: `filterwarnings = ["error"]` used to be defeated by
  six blanket `simplefilter("ignore")` blocks — wrapped around the
  1254-vector script loop, among others — which hid any *other* warning
  raised in there, a new interpreter's DeprecationWarning included. Those
  are gone: a test that provokes the warning deliberately now asserts it
  with `pytest.warns`, and the vector loops silence that one category at
  the single call that provokes it incidentally (issue #153)
- `parse_taproot_bip32` bounds its allocation by the data it was handed
  rather than by the count a counterparty declared: five bytes of a
  hostile PSBT used to cost gigabytes, reachable from `Psbt.parse` and
  `Psbt.b64decode` through `PSBT_IN_TAP_BIP32_DERIVATION` and
  `PSBT_OUT_TAP_BIP32_DERIVATION`, because `stream.read` past the end of
  the stream returns `b""` without raising and the comprehension ran the
  full count regardless. The var_int cap alone would not have closed it, a
  count under 32 MiB still being an expensive list (issue #133)
- `parse_taproot_bip32` reads a 32-byte leaf hash, the length BIP-371
  gives it, instead of 4 bytes. The BIP-371 test vectors exercise this,
  and the four bytes silently split every leaf hash they contain: the
  remaining 28 were parsed as the master fingerprint and seven more
  derivation indexes, so a script-path input reported a fingerprint taken
  from the middle of a hash and a twelve-element path where the wallet had
  derived `m/86h/1h/2h/0/0`. Re-serialization concatenated the same bytes
  back, which is why a roundtrip test never saw it
- `dsa.assert_as_valid_` and `ssa.assert_as_valid_` raise "signature
  verification failed" whichever of the two implementations verified: the
  message used to name an internal helper (`libsecp256k1.ecdsa_verify_
  failed`), telling the caller which backend ran instead of what went
  wrong
- the low-s rule is decided by integer division. `dsa._sign_` and
  `dsa._assert_as_valid_` compared `s` against `ec.n / 2`, which rounds
  the order to the 53 significant bits of a float: for secp256k1 that
  threshold sits 2^127 *above* the true midpoint, so signing left an `s`
  in that window unflipped and verification accepted it as low — and
  accepted `ec.n - s` too, the malleable pair the canonical encoding
  exists to rule out. Landing in the window by chance takes some 2^129
  signatures, so nothing in the wild was affected; the comparison is now
  exact for every curve, whatever the size of its order
- the shuffles that hide which input pays which output draw from
  `secrets.SystemRandom` instead of the `random` module: `tx.join_txs`
  (`shuffle_inp`, `shuffle_out`) and psbt's `_sort_or_shuffle_together`
  used the Mersenne Twister, whose state — and with it every permutation
  it has produced and will produce — is recoverable from enough observed
  output. Being unable to undo those shuffles is the whole point of them
- no more private key material in exception messages and reprs. A
  routine network mismatch used to put the full xprv — master private
  key plus chain code — into the BTClibValueError text, which is where
  it ends up in logs and bug reports; a WIF on the wrong network, the
  seed, an out-of-range scalar, and an xprv handed to a function
  expecting public material were echoed the same way, and the generated
  BIP32KeyData repr printed `key` and `chain_code` in the clear. The
  messages now carry the non-secret part that is actually wrong — the
  version or prefix bytes, or just the size — and the repr masks `key`
  and `chain_code` when the key is private (an xpub stays in the clear,
  it is public material). The internal derivation subclass opts out of
  the generated repr too, which would have printed its cached private
  scalar (issue #137)
- `dsa.verify`, `dsa.verify_`, `dsa.assert_as_valid`, and
  `dsa.assert_as_valid_` take a `PubKey`, not a `Key`: a private key is no
  longer accepted where a public one is expected. `verify(msg, prv_key,
  sig)` used to silently derive the public key from the secret handed in
  and return True, checking a signature against a key the caller had just
  proved it owns — which proves nothing about the signer, and put a secret
  through a code path documented as public. It now returns False, and
  assert_as_valid raises BTClibValueError, for an int scalar, a WIF, and
  an xprv alike: the narrowing is a runtime one, mypy having no way to
  tell a WIF string from a SEC hex-string. The `Key` union and its
  `point_from_key` / `pub_keyinfo_from_key` helpers are unchanged, and so
  are the address and script builders that take one, where deriving from
  one's own private key is what the caller means (issue #143)
- `sig_hash.from_tx` dispatches a p2sh input on its redeem script, not on
  the script_sig that carries it. It used to test the whole script_sig for
  p2wpkh and p2wsh, and the push opcode alone makes those tests false — a
  p2sh-p2wpkh redeem script is 23 bytes on the wire where p2wpkh wants
  exactly 22 — so a wrapped segwit input silently fell through to the
  legacy branch and the caller signed a hash committing to no amount, the
  very thing BIP-143 introduced. Legacy p2sh was wrong in the same way,
  its script code being the script_sig rather than the redeem script. The
  new `sig_hash.redeem_script` takes the last data push of the script_sig
  and checks it against the hash in the script_pub_key, so a script_sig
  disagreeing with the output it spends now raises BTClibValueError
  instead of returning a hash no verifier will reproduce; code that used
  to hand `from_tx` a bare redeem script as script_sig must push it —
  `serialize([redeem_script])` (issue #136)
- moved the project management to [uv](https://docs.astral.sh/uv/):
  dependencies, dependency groups, and packaging metadata are declared in
  pyproject.toml (setup.py, requirements.txt, requirements-dev.txt, and
  tox.ini are gone), with uv.lock pinning the development environment
- replaced autoflake, bandit, black, docformatter, flake8, isort,
  pydocstringformatter, pydocstyle, pylint, pyupgrade, and yesqa
  with [ruff](https://docs.astral.sh/ruff/)
- the lint workflow runs .pre-commit-config.yaml itself, instead of a
  second list of the same tools: CI now enforces exactly what a commit
  enforces, hooks that only pre-commit.ci used to run included. The mypy
  hook is a local one, running the strict check against the project
  environment: the mirrors-mypy hook injects `--ignore-missing-imports`,
  which turned every btclib_libsecp256k1 import into `Any`
- every action is pinned to a commit SHA and every workflow declares a
  read-only token; the release pipeline checks the declared versions (and
  that uv.lock is in sync) before the test matrix rather than beside it,
  and validates what it built with twine, check-wheel-contents, and
  pyroma on the sdist, before an upload consumes the version
- the matrix covers 3.14t, the free-threaded interpreter, and pytest is
  stricter: a warning is an error, an unregistered marker and a typo in
  the pytest configuration are errors, and an xfail that passes is a
  failure
- the packaging metadata is validated on every pull request rather than
  only on the tag that ships it: twine, check-wheel-contents and pyroma
  moved from the release workflow to a job of the test workflow, which
  the release workflow calls
- a scheduled workflow runs the test suite against the *published*
  btclib_libsecp256k1, resolved from PyPI by the declared pin, where every
  other job follows tool.uv.sources to the bindings under development: what
  it watches for is not a change here but a release there
- `hashes.magic_message` prefixes the message length as a var_int, as
  Bitcoin Core and Electrum do, instead of as a single byte: a Bitcoin
  message signature over 252 bytes now agrees with every other
  implementation. It used to diverge silently from 253 bytes on, so
  `bms.sign` produced (and `bms.verify` accepted) signatures nobody else
  agreed with while rejecting the valid ones, and from 256 bytes on
  signing raised OverflowError instead of signing
- the version is declared once, in pyproject.toml: `btclib.__version__`
  reads it back from the installed metadata (so it reports the version
  that is installed, not the one a source tree carries) and the
  documentation reads it from the file. It used to be a literal in
  btclib/\_\_init\_\_.py that setuptools imported, repeated by
  docs/source/conf.py, with the release workflow comparing the two.
  `btclib.__version__` is `"unknown"` where there is no metadata to read
  it from, instead of the import raising PackageNotFoundError: cloning
  the repository and importing works again, as it did before the version
  moved (issue #150)
- `dsa.Sig.parse` no longer raises IndexError on a one-byte DER scalar:
  `3006020100020100` is r = s = 0, each written in the single byte that
  is minimal DER for zero, and the "highest bit set" padding test read
  the second byte of a value having none. `strict` being the last of its
  three conditions did not spare it, so the IndexError escaped whatever
  the flags. A DER length overrunning its buffer is now a
  BTClibValueError too, where var_bytes calls it a BTClibRuntimeError:
  `psbt_in._assert_valid_partial_sigs` filters parse failures on
  BTClibValueError, so both used to escape `Psbt.parse` (issue #138)
- `psbt_utils.deserialize_map` checks that its reads returned the number
  of bytes announced. They can come back short, so a truncated psbt used
  to yield short keys and values: distinct inputs deserialized to the
  same object and serialized back to only one of them. Running out of
  buffer before a map's 0x00 separator is a "malformed psbt: unterminated
  map" as well, where it used to be an IndexError (issue #138)
- `b58decode` refuses more than 112 characters, the longest a legitimate
  payload takes — a 78-byte BIP32 extended key plus its 4-byte checksum.
  Decoding is quadratic and the checksum is verified only once it has
  been paid for: 160k characters of an address field cost 3.3 seconds
  before being rejected. `b58encode` is deliberately left uncapped, what
  it is handed being data the caller already holds (issue #138)
- `bms.Sig.parse` checks the 65-byte length whatever `check_validity`
  says: it is not an opinion about the signature but what makes the
  `[rf][r][s]` slices mean anything, and skipped it let every input
  sharing a prefix collapse onto one signature. `bms.Sig.b64decode`
  requires the canonical base64 encoding, so a signature is reachable
  from exactly one string: it used to discard anything outside the
  alphabet, and `validate=True` alone would not do, both because the
  padding it accepts varies with the interpreter and because the bits a
  non-final group leaves over are discarded everywhere. Surrounding
  whitespace stays tolerated, now for bytes as well as str (issue #138)
- BIP32 derivation raises on the three children the specification calls
  invalid — `parse256(IL) >= n`, a zero private child, a public child at
  infinity — instead of returning a key no other wallet derives. It says
  so rather than deriving the next index silently, as Core's CKDpriv
  does: the caller asked for one index, and the choice of another is
  theirs. At odds of about 2^-127 this is a defined answer, not a
  reachable one (issue #138)
- `sig_hash.legacy` compares `hash_type & 0x1F` to SIGHASH_NONE with
  `==`, not `is`. It worked only through CPython's small-integer
  interning, and pypy is supported; were the identity ever to fail,
  SIGHASH_NONE would be hashed with SIGHASH_ALL semantics (issue #138)
- a curve is now compared by its parameters. `CurveGroup`, `CurveSubGroup`
  and `Curve` define `__eq__` and `__hash__` over `(p, a, b)`, the
  generator, and `(n, cofactor)` — the name is not one of them, so SEC 2's
  secp256r1 equals NIST's nistp256 — where they used to inherit the
  identity comparison of `object`. That comparison is what dispatches to
  libsecp256k1, and `ec/curve.py` itself built *two* secp256k1 objects,
  one per SEC 2 catalogue: code holding `SEC2v2["secp256k1"]` got the pure
  python path, twelve times slower and silent about it, and
  `to_prv_key`/`to_pub_key` raised "curve mismatch" between two objects
  describing the same curve. The eight curves shared by the two
  catalogues are now one object each, and the five hand-written dispatch
  predicates are one `_libsecp256k1_applicable(ec, hf)`. `hf` is still
  compared by identity, deliberately: nothing short of running them tells
  sha256 from a look-alike, so a wrapper such as
  `functools.partial(sha256)` keeps taking the python path — slower, never
  wrong (issue #142)
- importing btclib is 140 ms faster: `Curve` takes a new `order_check`
  argument, and the 27 catalogued curves pass `order_check=False` and
  `weakness_check=False`. The n\*G ≟ INF check the first one gates is a
  python double-and-add over the bit length of the order, 118 ms of the
  168 ms importing `btclib.ec.curve` used to take; the 99 modular
  exponentiations of the second are another 5 ms. Both were paid to
  re-derive, at every interpreter start, a property of the constants
  standardized by SEC 2, FIPS 186-4 and RFC 5639. `btclib.ec.curve` now
  imports in ~29 ms. Both checks default to on, because what they reject —
  a curve whose n is not the order of its generator, one whose embedding
  degree carries the discrete logarithm into a field where it is easy — is
  accepted by every other check and then misbehaves where nothing is
  looking; for the catalogue, the new `test_catalogued_curves` rebuilds
  each curve from the same json data with both checks on
- the test suite is property-based as well as vector-based: `hypothesis`
  generates the input nobody wrote down, and `tests/test_fuzz.py` asserts
  that every parse entry point answers it within the exception contract
  of btclib/exceptions.py rather than with an IndexError or an
  OverflowError. Round-trip and checksum properties come with it, for
  base58, bech32, b32, b58, var_int, var_bytes and the descriptor
  checksum, and algebraic invariants for number_theory. The vectors are
  what conformance needs and are going nowhere; what they cannot cover is
  the malformed input that never makes it into a specification's test
  section, which is where issues #133, #135 and #138 all came from
  (issue #159)
- `b58decode` and `bech32.decode` answer a character outside ascii with
  BTClibValueError, not with the UnicodeEncodeError and UnicodeDecodeError
  that used to come out of the codec: a character that is not in ascii is
  not in the base58 or bech32 alphabet either, so it is an invalid
  character like any other, and an address carrying a smart quote or an
  accented letter used to escape every caller written to catch
  BTClibValueError (issue #159)
- `psbt_utils.parse_leaf_script` rejects an empty value instead of raising
  IndexError: BIP-371 writes a PSBT_IN_TAP_LEAF_SCRIPT as the script
  followed by the one byte of its leaf version, so an empty one is a
  record missing the only field it must carry (issue #159)
- `Block.assert_valid` rejects a block carrying no transaction instead of
  raising IndexError on `transactions[0]`: every block has a coinbase, so
  an empty list is not a block that happens to be empty, and a var_int of
  zero where the transaction count goes is all it takes to serialize one
  (issue #159)
- `BlockHeader.target` raises BTClibValueError for a compact `bits` that
  denotes more than 32 bytes can hold, where `to_bytes` used to raise
  OverflowError out of `assert_valid`; Core rejects the same headers,
  through the fOverflow flag its SetCompact sets and CheckProofOfWork
  tests. The power term is also computed by shifting, as SetCompact does:
  `pow(256, -1)` is a float in python, so an exponent below 3 used to send
  a 256-bit target through float arithmetic (issue #159)

## v2023.7.12

This is the last release supporting py37.

Major changes include:

- added first draft implementation of descriptors
- added first draft implementation of script engine
- added taproot psbt fields
- improved bip32 derivation (speeded-up, added one more test)
- supported py3.12 with btclib_libsecp256k1
- updated toolchain

## v2023.5.30

Major changes include:

- Fix circular import between ``script`` and ``b32``

## v2023.2.3

Major changes include:

- enabled libsecp256k1 by default
- improved documentation
- used generic containers (Sequence instead of list, Mapping instead of dict)
  where possible

## v2023.1.17

Major changes include:

- exported names per module (bip32, block, ec, ecc, mnemonic, psbt, script, tx)
- added join_psbts and join_txs
- refactored bip340_nonce
- improved integration of libsecp256k1
- added secp256k1-py test vectors
- improved typing
- added SECURITY, CONTRIBUTING, bug report and feature request templates
- added pre-commit hooks
- adopted *mypy --strict* and *from \_\_future\_\_ import annotations*

## v2022.12.31

Major changes include:

- add support for PSBT's taproot fields (bip370)
- added support for Python 3.11
- fixed the OpenSSL 3.x RIPEMD160 issue in btclib/hashes.py
- added CONTRIBUTING and SECURITY
- solved issue #73
  [Re-import Tx subclasses into btclib.tx](https://github.com/btclib-org/btclib/issues/73)

## v2022.7.20

Major changes include:

- by default ssa, dsa and point multiplication are now sped up
  using btclib_libsecp256k1; this provides an 8 times speed up
  in benchmarks and 3 times in real world applications.

## v2022.5.3

Major changes includes:

- dropped python 3.6 support
- added support for btclib_libsecp256k1
- the hashes.fingerprint function, removed in the previous version,
  has been reinstated in the to_pub_key module
- encode_num and decode_num have been moved from script.op_codes to utils
- op_pushdata and op_str have been renamed to
  serialize_bytes_command and serialize_str_command
- script.op_codes has been removed and its functions merged in script
- script serialization is now more consistent: all integers, even small
  ones, are now considered like bytes. To put small integers on the stack
  OP_X must be used explicitly. Using integers directly will lead to larger
  scripts that will be likely to be rejected by the network as not standard
- check_validity is now correctly propagated inside each function

## v2022.2.9

This is the latest release to support python 3.6

Major changes includes:

- added bech32m
- added Taproot support
- introduced ScriptPubKey class
- used script_type instead of prefix/wit_ver for b58/b32 address functions
- split up op_int in op_num and op_int
- prevented bip32 account derivation with arbitrarily high index
- ensured der.Sig.r is congruent to a valid x-coordinate
- renamed ScriptToken as Command
- moved witness and script_pub_key into script folder
- removed dataclasses_json dependency
- introduced submodules
- renamed Tx.tx_id as Tx.id
- renamed deserialize as parse
- renamed signature functions: trailing underscore marks hash-reduced versions
- updated BIP32 test vectors
- moved continuous testing from TravisCI to Github Actions
- simplified configuration files
- fixed pylint and flake8 warnings

## v2020.12.19

Major changes includes:

- added secp256k1 point multiplication based on efficient endomorphism
- fixed ssa batch verification functions' logic
- enforced snake_case variable naming convention,
  e.g. 'script_pub_key', etc.
- added BIP32KeyOrigin, BIP32KeyPath, and BIP32KeyPaths
- adopted str instead of bytes as default type
  for BIP32 keys, bms sigs, PSBTs, addresses, and WIFs;
  base58 and bech32 encodings keep returning bytes, like base64
- cleaned up and refactored all dataclasses,
  now using serialize/deserialized and
  possibly b58encode/b58decode, b64encode/b64decode, etc.
- renamed TxIn.witness as TxIn.script_witness
- fixed Witness management in TxIn and Tx, including equality operator
- consolidated sig_hash code into sig_hash module
- added more script_pub_key functions: assert_p2pkh, is_p2pkh, etc.

## v2020.11.23

Major changes includes:

- updated BIP340 (Schnorr signature) implementation
  as per the latest changes in bitcoin core
- refactored PsbtIn, PsbtOut, and Psbt
- added legacy sighash
- made btclib compatible with python 3.6
- ssa.det_nonce now returns an int
- moved tagged_hash from ssa into hashes module
- added CurveGroup._y_aff_from_jac and removed unused methods
- discontinued y_odd in favor of y_even as y-simmetry tiebreaker criterium
- removed nonce input from dsa.sign and ssa.sign (only available from _sign functions)
- cleaned up Exception handling, avoided bare/broad except
- introduced btclib Exceptions that can be discriminated from regular Exceptions

## v2020.11.10

Major changes includes:

- removed TypedDict in favor of dataclass;
  this also restored the ability of using btclib with python 3.7
- introduced dataclasses_json as requirement, used to
  serialize to file the json representation of dataclasses
- Network is now a dataclass
- bip32: BIP32KeyData is now a dataclass instead of dict, its data member
  have to be accessed accordingly. Consequently, where previously it was
  bip32.deserialize(xkey), now it is bip32.BIP32KeyData.deserialize(xkey)
- bip32: added str_from_bip32_path and bytes_from_bip32_path
- bip3: made bip32 index an int (not bytes) to avoid byteorder ambiguity.
  Consequently, where previously it was xkey_dict\["index"\][0] < 0x80,
  now it is xkey_dict.index < 0x80000000
- bip32: local "./" derivation, opposed to absolute "m/" derivation,
  is not available anymore
- bip32: indexes_from_bip32_path now returns list[int] instead of
  Tuple[list[bytes], bool] losing the "absolute derivation" bool
- bms: serialize/deserialize have been renamed encode/decode as they
  include the base64 (de)encoding, not jut the plain (de)serialization
- Block: fixed bug in difficulty calculation
- introduced first beta version of HdKeyPaths, PartialSigs, PsbtIn,
  PsbtOut, and Psbt data classes and their associated helper functions
- refactored Diffie-Hellman and ANSI-X9.63-KDF
- introduced assorted elliptic curve point multiplication
  algorithms
- script: renamed Token as ScriptToken
- script: encode/decode have been renamed as serialize/deserialize
  as they were not encoding at all; the previous serialize/deserialize
  which had varint(len()) before serialized data are not available anymore
- alias: few definitions have moved in their relevant modules from which
  they can be imported
- pytest: enforced pytest > 6
- pytest: using as many processes as the available CPU cores

## v2020.8.21

Major changes includes:

- added BlockHeader and Block data classes
- added OutPoint, TxIn, TxOut, and TX data classes
- added segwit_v0 sighash
- added PsbtIn, PbstOut, and Psbt data classes for
  partially signed bitcoin transactions (BIP174)
- moved from unitest to pytest, including revision
  of error messages and tests' logic

## v2020.5.11

Major changes includes:

- switched to tox testing, gradually moving to pytest testing
  (while discontinuing unittest)
- adopted black formatter and added compatible flake8 and isort
  configurations
- added Integer as hex-string or bytes representation of an int
- adopted the function signature of dsa.sign for rfc6979.rfc6979 too
- added CURVES dictionary of all elliptic curves, e.g.:
  from btclib.curve import CURVES; ec = CURVES['secp256k1']
- renamed prvkey_info_xyz as prvkey_info_xyz
- renamed pubkey_info_xyz as pubkey_info_xyz
- renamed bytes_from_key as pubkeyinfo_from_key
- renamed network_from_xpub as network_from_xkeyversion
  extending its functionality to xprv too
- redundant spaces (and also tabs, newlines, returns, formfeeds, etc.)
  are removed from mnemonic phrases using " ".join(mnemonic.split())
  before any encoding of the mnemonic
- moved the WordLists class into the mnemonic module and
  removed the wordlist module
- moved all entropy functions into the entropy module
- entropy.generate has been renamed as entropy.randbinstr

## v2020.5.3

Major changes includes:

- Fixed Schnorr MuSig and Threshold Signature
- Generic public/private key accepted wherever PubKey is expected
  (except for Schnorr where a public key cannot be discriminated as
  different from a private key)
- P2PK and P2MS now handle also compressed public keys
- added gen_keys to dsa, ssa, bms, so that now all the standard
  gen_keys, sign, and verify functions are available
- Wherever an input/output parameter sequence had
  'compressed: bool, network: str', the order has been
  inverted resulting in 'network: str, compressed: bool'.
  Affected functions: base58address.p2pkh, base58wif.wif_from_prvkey,
  to_prvkey.prvkey_info_from_prvkey, to_pubkey._bytes_from_xpub,
  to_pubkey.bytes_from_key, to_pubkey.pubkey_info_from_prvkey,
  hashes.hash160_from_pubkey, secpoint.bytes_from_point,
- renamed mxprv_from_bip39_mnemonic and mxprv_from_electrum_mnemonic
- made entropy the first input parameter of mnemonic_from_entropy
- improved size checks for bytes_from_octets
- entropy.generate_entropy has been renamed as entropy.generate

## v2020.4.21

Major changes includes:

- The Bitcoin Message Signing module btcmsg.py has been rename bms.py
- refactored address/scriptPubKey
- consolidated wif_from_* in wif_from_prvkey
- removed ambigous functions going from prv_key to address
- refactored to_pub and to_prv functions
- added network <-> prefix <-> curve functions in network module
- removed trailing _scriptPubKey suffix from the function names
  in the scriptPubKey module
- tests are now distributed as btclib.tests subpackage
- removed p2pkh_from_xpub, p2wpkh_p2sh_from_xpub, and p2wpkh_from_xpub
  (use p2pkh, p2wpkh, and p2wpkh instead)
- introduced CurveGroup and CurveSubGroup as grand-parent and parent
  of Curve. Also, renamed ec._p as ec.p and removed default parameters
  from double_mult
- renamed ec.opposite(P) as ec.negate(P)
- the usage of DER (de)serialization is advocated through
  dsa.(de)serialize, similarly to ssa.(de)serialize
  and bms.(de)serialize; therefore, the corresponding
  der.py functions have been renamed with leading underscore
- introduced XXXSig and XXXSigTuple for XXX = DSA, BTCMSG, and SSA

## v2020.4.7

This is a major release that complete the far-reaching refactoring
initiated with v2020.3.20; it requires python>=3.8 as we use TypedDict.

Chances are this release might break most projects using btclib,
but the changes were long overdue and should be stable in time.
Functions and modules have been renamed to better reflect
the library design; anyway, because of the clearer logic,
it should not be hard to find the new versions.
The module alias.py might be a good entry point
to familiarize with the new design.

Most notably the library is now able to accept
any representation of private keys as input,
with all the WIF/BIP32/bytes/integer conversion
auto-magically being taken care of.
The same apply to public key BIP32/SEC-bytes/tuple conversion.
As usual, whenever bytes are accepted, hex-string or
text string are accepted too, as appropriate.

Moreover, major changes include:

- updated the Schnorr implementation to BIP340 proposed standard
- refactored BIP32 for increased derivation efficiency
- improved documentation
- extended functional test case coverage (as usual tests cover 100% of
  the code base)
- removed all mypy warnings (but one)
