# Changelog

Every change of a release, in full: what changed, why, and what it cost.
[HISTORY.md](./HISTORY.md) has the release notes, which say what a user has
to act on; this file is the record behind them, and is where a claim in
those notes can be checked.

Only v2026.8 is here. The releases before it were documented at
release-notes length in the first place, and are still in
[HISTORY.md](./HISTORY.md) rather than duplicated here.

## v2026.8 (work in progress, not released yet)

A hundred and thirty-two entries, grouped. The order runs from what breaks a
caller to what only maintainers see; [HISTORY.md](./HISTORY.md) lists the
fifteen source-breaking changes on their own.

### Repository

- `TODO.md` is gone, and every one of its lines is accounted for. Eighteen
  became issues (#184 to #194, #196 to #202): the feature requests the file
  had carried for years — a full-node RPC client, descriptors beyond the
  checksum, miniscript, toy mining with difficulty and hash-rate arithmetic,
  wallet infrastructure, MuSig and threshold primitives, Edwards curves, BLS —
  plus the four BIP340 questions and the three "report upstream" items, which
  carry a new `upstream-report` label saying that each needs verifying before
  anything is sent anywhere. Two lines were already done and two were
  superseded: "generalize ec, hf in borromean" landed with the module's
  parameters, "refactor Psbt" is #173, and the two on making the network a
  global variable are superseded by #149, which took configuration *out* of
  module globals for the reason those lines would have put it back.
  The optimization links moved into `curve_group_2`'s docstring as further
  improvements with the material for each, and the borromean references into
  that module's docstring, both next to the code they are about rather than in
  a file nobody opened.

### Security

- `borromean.assert_as_valid` raises BTClibRuntimeError("signature
  verification failed") and returns None, as its `dsa`, `ssa`, and `bms`
  counterparts do; it used to return a bool, so a caller following the
  library's own convention and calling it as a statement accepted forged
  ring signatures in silence
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
- `Curve` rejects an anomalous curve, one whose order equals the field
  prime, whatever the type the prime is spelled with. SEC 1's step 8
  compared `n` against the still unconverted `p` parameter rather than
  against `self.p`, so `Curve(13, 1, 6, (2, 9), 13, 1)` raised while
  `Curve("0x0d", ...)` — the hex string every catalogued curve and every
  json datum uses — was accepted, and nothing else caught it: the MOV
  check computes `p^i mod n`, which for n = p is 0 and never 1. The
  discrete logarithm on such a curve transfers to addition in F_p and is
  polynomial-time, so what got through was a curve on which signing is
  worthless. Nothing shipped is affected, none of the 27 catalogued curves
  being anomalous (issue #166)

### Consensus rules

- **btclib can check a Merkle proof, not only compute a root.** It had
  the builder's side, `merkle_root_and_mutated_from_hashes`, and no
  entry point for the verifier's: from a txid, a branch of siblings and
  a leaf position, recompute the root and compare it with a header's
  `merkle_root`. That is the arithmetic behind `gettxoutproof` /
  `verifytxoutproof`, and behind every light client. It lands in two
  pieces, on the one layering decision the feature poses. The arithmetic
  is `hashes.merkle_root_from_branch`, beside the root functions it is
  the inverse of; the hardening that has to know what a transaction
  looks like is `btclib.block.merkle_proof`, because `hashes` must not
  import `tx`. The seam between them is a `check_inner_node` callback,
  so the loop is written once: `hashes` walks the branch and hands over
  each 64-byte pair, `block` refuses the ones that parse.
  What is refused, beyond the arithmetic: **CVE-2017-12842**, an inner
  node that deserializes as a whole transaction — 64 bytes is a
  reachable transaction size, and presented as a leaf it gets a proof
  one level shorter than the tree really is, for a transaction that was
  never in the block; **CVE-2012-2459** from the verifier's side, a
  right-child step whose sibling equals the running hash, which is the
  duplicated subtree the root does not commit to — the library already
  flagged exactly this when *building* a tree, so it now knows the fact
  from both directions, and the odd-level padding is not an instance of
  it because padding duplicates a *left* child; and the three cheap
  ones, a branch item that is not 32 bytes, a negative position, and a
  position with bits still unspent once the branch is consumed, a branch
  too short proving nothing at all. `assert_as_valid` says why it
  refused and `verify` answers a bool, as the signature modules do.
  Every transaction of blocks 1, 170 and 200000 is proved against the
  real header, the branch built by the test rather than by the code
  under test, plus eight positions of the segwit block 481824 — where
  the tree is over txids, so a wtxid does not verify (issue #204)
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
- `hashes.magic_message` prefixes the message length as a var_int, as
  Bitcoin Core and Electrum do, instead of as a single byte: a Bitcoin
  message signature over 252 bytes now agrees with every other
  implementation. It used to diverge silently from 253 bytes on, so
  `bms.sign` produced (and `bms.verify` accepted) signatures nobody else
  agreed with while rejecting the valid ones, and from 256 bytes on
  signing raised OverflowError instead of signing
- `sig_hash.legacy` compares `hash_type & 0x1F` to SIGHASH_NONE with
  `==`, not `is`. It worked only through CPython's small-integer
  interning, and pypy is supported; were the identity ever to fail,
  SIGHASH_NONE would be hashed with SIGHASH_ALL semantics (issue #138)
- an amount is bounded by MAX_MONEY, 2_100_000_000_000_000 satoshi and
  inclusive, where `valid_sats_amount` and `valid_btc_amount` used to
  bound it by 2_099_999_997_690_000, the supply the halving schedule
  actually issues. The 2_310_000 satoshi between the two are what the
  subsidy loses to integer division, a fact about issuance and not a
  validity rule, and the difference was not academic: `TxOut.assert_valid`
  runs from the constructor, so `Tx.parse` refused the two `MAX_MONEY
  output` transactions of Bitcoin Core's tx_valid.json outright, and a
  transaction the network considers valid was one btclib could not so
  much as read (issue #167)
- `Tx.assert_valid` bounds the sum of the outputs by MAX_MONEY too, as
  CheckTransaction does: the per-output check does not imply it, every
  output being able to sit inside MoneyRange while the total is twice the
  money there will ever be. Only the outputs, as there — what the inputs
  are worth is not in the transaction, and comparing the two is
  `verify_amounts`' job (issue #167)
- **`BlockHeader.assert_valid` no longer requires a valid proof of work**,
  structural and consensus validity being different questions. It used to
  end in `assert_valid_pow`, so a header *being mined* — well-formed, no
  work found yet — could not be built, serialized, or hashed through the
  ordinary API, and hashing it is what mining is. `assert_valid_pow` is
  still there and still asserts the work; `Block.assert_valid` calls it, as
  Bitcoin Core's `CheckBlock` calls `CheckProofOfWork` with `fCheckPOW`
  defaulted to true — a Block carries the transactions the work commits to
  — which is also what keeps the vendored `block_*.bin` files
  self-verifying. The nonce bound drops to `0 <= nonce <= 0xFFFFFFFF`:
  consensus places no lower bound on it, Core does not look at it at all,
  mining starts at zero, and btclib could not read a consensus-valid block
  that happened to have one. That bound was doubling as `parse`'s
  truncation check, a short read being zero, so `parse` now checks that it
  read 80 bytes, the way `BIP32KeyData.parse` does. Truncation is reported
  as truncation for it: eight bytes short used to be "invalid nonce", four
  short "invalid bits length", and twelve short "invalid timestamp (before
  genesis)" — a time read from no bytes at all
- **OP_VERIF and OP_VERNOTIF are invalid in a branch nothing takes**, and
  the tapscript engine used to accept one: `OP_0 OP_IF OP_VERIF OP_ENDIF
  OP_1` verified. Core reads an op code sitting in OP_IF..OP_ENDIF whether
  or not the branch executes — `fExec || (OP_IF <= opcode && opcode <=
  OP_ENDIF)` — and gives these two no case of their own, so they reach
  `default: BAD_OPCODE` from a branch never taken. Both engines had that
  range written out as the four conditionals in it and skipped the other
  two; they now share Core's range, which is also the whole of the rule:
  the legacy engine's separate pass over the parsed script is gone, one
  rule instead of two, in the place Core has it. That placement is what
  keeps `OP_VERIF OP_SUCCESS80` valid, as it is for Core, whose pre-scan
  returns success at the first OP_SUCCESS whatever precedes it — the same
  reason both op codes keep their names in the tapscript tables, which is
  what Core's own `GetOpName` does (issue #182)
- **the fifteen op codes disabled for CVE-2010-5137 are refused**, where
  a script could carry one and still be spent. OP_CAT, OP_SUBSTR, OP_LEFT,
  OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR, OP_2MUL, OP_2DIV, OP_MUL,
  OP_DIV, OP_MOD, OP_LSHIFT and OP_RSHIFT had no name in btclib's tables,
  so an executed one failed as "unknown op code: 0x7e" and an unexecuted
  one was skipped outright: `OP_0 OP_IF OP_CAT OP_ENDIF OP_1` verified.
  Core refuses them above the fExec test, earlier still than OP_VERIF —
  one of them anywhere in a script, in a branch never taken or past an
  OP_RETURN, makes it unspendable, and its error DISABLED_OPCODE rather
  than BAD_OPCODE. They are named now, as Core names them in script.h and
  GetOpName, and the legacy engine refuses them by name in that position;
  tapscript needs no rule of its own, BIP342 having turned every one of
  those bytes into an OP_SUCCESSx. Naming them also lets a script carrying
  one round trip through `parse` and `serialize`, which the engine's
  FindAndDelete depends on.
  Bitcoin Core's vectors had covered this all along — twenty-four
  DISABLED_OPCODE cases, seventeen of them in a branch never taken — and
  not one of them ran: the harness cannot build a script whose op code has
  no name, `pytest.raises(Exception)` took the resulting KeyError for the
  expected failure, and all twenty-four passed against a rule that was not
  there. A vector expecting a failure now has to get a BTClibValueError,
  which is what the engine raises and what a broken harness does not
  (issue #182)

### Malformed input and the exception contract

- **a WIF is checked against the network the caller named**, not against
  the reverse lookup's answer. `_prv_keyinfo_from_wif` compared the
  network *name* the prefix mapped back to, and the four test networks
  share `0xef`, which maps back to "testnet": so a signet WIF asked for
  as signet raised `InvalidPrvKeyError("not a signet wif: prefix 0xef")`
  — naming the very prefix signet asks for — and the same for regtest
  and testnet4. The check is now membership, the forward direction
  `_prv_keyinfo_from_xprv` has always used, which is why the xprv path
  took signet correctly all along; the returned tuple carries the
  network the caller declared. Wrong-network WIFs are refused exactly as
  before, mainnet's `0x80` against a test network and back (issue #207)
- **`dsa.Sig.parse` rejects bytes after the DER sequence** under `strict`,
  which is the default. It read the sequence and silently dropped whatever
  followed, so `Sig.parse(der + b"\x01")` answered with the `Sig` of `der`
  — which is how a two-byte hash type reached verification as a valid
  signature. Core checks the whole element with one size equation,
  `(lenR + lenS + 7) != sig.size()` in `IsValidSignatureEncoding`, and only
  under the flags asking for canonical DER: hence `strict`, so the lenient
  parse the script engine uses when DERSIG is off still takes it. A script
  signature and a PSBT partial signature carry a sighash type byte and are
  therefore not DER encodings — strip it, as `psbt_in` now does: that call
  site worked only because of the laxity, and 29 PSBT tests fail without
  the strip (issue #129)
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
- `BlockHeader.assert_valid` rejects a timestamp the header field cannot
  hold: it bounded the time below, at the genesis block, and not above,
  where four unsigned bytes end (2106-02-07 06:28:15Z is the last instant
  one can carry). A later time passed validation and failed in `serialize`,
  as `OverflowError: int too big to convert` — which names neither the
  field nor the header the caller had just been told was valid. The bound
  is on `int(time.timestamp())`, the value `serialize` writes, and the
  message renders `time` itself rather than reading it back through
  `fromtimestamp`: `datetime.max.timestamp()` rounds up to year 10000, so
  rendering *that* would have raised the very kind of exception the check
  replaces (issue #177)
- `BlockHeader.target` raises BTClibValueError for a compact `bits` that
  denotes more than 32 bytes can hold, where `to_bytes` used to raise
  OverflowError out of `assert_valid`; Core rejects the same headers,
  through the fOverflow flag its SetCompact sets and CheckProofOfWork
  tests. The power term is also computed by shifting, as SetCompact does:
  `pow(256, -1)` is a float in python, so an exponent below 3 used to send
  a 256-bit target through float arithmetic (issue #159)
- **The boolean APIs no longer answer a caller error with `False`.** All
  seven `except Exception` blocks behind a `verify`-style bool are narrowed:
  `dsa.verify`/`verify_`, `ssa.verify`/`verify_`/`batch_verify_`,
  `bms.verify`, `pedersen.verify`, `borromean.verify`, and the `_is_funct`
  behind every `is_p2*`. An input that is not a valid signature is still
  `False`, and so is a verification that failed, but a `TypeError` is
  neither: `dsa.verify(msg, Q, sig, hf=sha256())` — a digest object where a
  constructor goes — used to be reported as an invalid signature, and
  `is_p2sh(None)` as "not a p2sh script". The catch is `(ValueError,
  BTClibRuntimeError)`, naming `BTClibRuntimeError` rather than
  `RuntimeError` **because `RecursionError` is a `RuntimeError`** and is not
  an answer about a signature. Two latent `IndexError`s the broad catch was
  hiding had to be fixed first, both reachable and both outside the
  library's exception contract: `assert_nulldata(b"\x6a")`, a lone
  OP_RETURN with no data length marker to read, and `assert_segwit(b"")`,
  an empty script with no witness version byte. `is_nulldata(b"\x6a")` and
  `is_segwit(b"")` are still `False`
- **`borromean.sign` refuses ring inputs of mismatched length** instead of
  signing a subset. `ks`, `sign_key_idx` and `pubk_rings` take one entry per
  ring and nothing validated that, so both loops zipped them and stopped at
  the shortest: a short `ks` returned a signature over fewer rings than the
  caller asked for, silently, which is the one thing a ring signature must
  not do. `zip(..., strict=True)` raises `ValueError`, and
  `BTClibValueError` is a `ValueError`, so a caller already catching this
  package's errors catches this too. Every other `zip` in the library took
  `strict=True` in the same pass — fourteen of them, where an explicit
  length check or construction already guaranteed the pairing, so there the
  argument documents an invariant rather than changing an outcome. Available
  because `strict` is python 3.10
- an empty P2WSH witness stack raises BTClibValueError("empty p2wsh witness
  stack") rather than an `IndexError` out of `stack[-1]`, the witness script
  being the last element of a stack that has none. Core calls it
  WITNESS_PROGRAM_WITNESS_EMPTY and the taproot branch beside it already had
  the guard. The vector that exercises it, `P2WSH with empty witness`, was
  green throughout: `pytest.raises(Exception)` counts an IndexError as the
  refusal it was waiting for (issue #182)

### Immutability and shared state

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
- **`Script` and `ScriptPubKey` are frozen, and `Script.asm` is cached.**
  `Script` was the one dataclass left unfrozen after issue #139, which is
  what let `tx_out.script_pub_key.script = b""` reach *through* a frozen
  `TxOut` and rebind the script of whatever else held that ScriptPubKey —
  the shallow-freeze hole that issue records. It raises `FrozenInstanceError`
  now, and `Script` gains a generated `__hash__`, so it can be a dict key or
  a set member; `ScriptPubKey` cannot, defining `__eq__`. Freezing is also
  what makes the second half correct: `asm` was a plain property, so every
  read re-parsed `self.script` — 57.9 µs for a 16.5 kB script, every time,
  for a value that cannot change. A `functools.cached_property` makes the
  second read 0.02 µs. The cache is deliberately *not* warmed by
  `assert_valid`, so building a Script and then reading `.asm` still parses
  twice: an instance holding the parse of that 16.5 kB script costs 55.4 kB
  against 0.2 kB without it, 277 times the script's own bytes, and nothing
  inside the library reads `.asm` at all (issue #165)
- **`assert_valid` no longer rewrites what it validates.**
  `BIP32KeyData.assert_valid` coerced six fields in place — `bytes()` over
  `version`, `parent_fingerprint`, `chain_code` and `key`, `int()` over
  `index` and `depth` — and `BlockHeader.assert_valid` coerced `nonce`; both
  are called from `serialize()`, `to_dict()` and `b58encode()`, so reading a
  key or a header rewrote it. The coercion is in `__init__` now, which is
  where the input that needs it arrives: `from_dict` is handed a json
  object, and json has no integer type, so a whole number can reach the
  constructor as a float. What is left in `assert_valid` is the *report*: a
  field that is not an `int` raises `BTClibTypeError("invalid nonce type:
  float")` instead of being silently repaired, and instead of the
  `AttributeError` from `to_bytes` that simply dropping the coercion would
  have produced — an exception from outside the library's contract. The
  `bytes()` calls stay as the type check they also were, minus the
  write-back. An `assert_valid` mutating `self` is now nothing the package
  does anywhere: checked over every `assert_valid*` in it with `ast`

### Process-wide state and thread safety

- importing btclib no longer dies with OSError where hashlib has no
  RIPEMD-160, and no longer re-enables OpenSSL's deprecated algorithms
  process-wide to avoid it. `btclib.hashes.ripemd160` falls back to a pure
  python RIPEMD-160 (`btclib._ripemd160`, vendored from Bitcoin Core),
  which is what makes the library importable on a host linking an OpenSSL
  between 3.0.0 and 3.0.6 — Ubuntu 22.04 still ships 3.0.2 — or one in
  FIPS mode, where no provider offers RIPEMD-160 and bitcoin addresses
  need it anyway. `btclib.hashes` used to load OpenSSL's legacy provider
  at import time through `ctypes.CDLL("libssl.so")`, an unversioned name
  that only the dev package installs, so the fallback raised OSError on
  the very hosts that reached it — a server, a container, a venv built
  from wheels — and changed the algorithms available to every other
  library in the interpreter when it did work. Where hashlib has the
  algorithm nothing changes: it is still what computes the digest
  (issue #144)
- importing btclib no longer traps decimal FloatOperation in the
  process-wide context: `btclib.amount` used to do it at import time,
  changing the Decimal semantics of the unrelated code of any application
  merely importing, say, `btclib.tx`. The two functions doing Decimal
  algebra now trap it in a `decimal.localcontext()` of their own, which
  also makes them behave the same in a thread created elsewhere: the
  current context is thread-local, so the process-wide trap was absent
  there
- **`SEC2v1` holds the SEC 2 v.1 curves, and nothing else.** `CURVES =
  SEC2v1` bound the same dict, so the two `update()` calls that followed
  poured NIST and Brainpool into it: `SEC2v1` had 27 entries instead of its
  own 15, and `SEC2v1["nistp256"]` answered a curve that is not in SEC 2 v.1
  at all. Found by acting on the stale `# with python>=3.9 use dictionary
  union operators` beside it — 3.9 is the minimum this package supports, and
  `SEC2v1 | NIST | Brainpool` builds a new dict, which is what keeps the
  catalogues apart. `CURVES` is unchanged in content
- **`borromean.sign`, `verify` and `assert_as_valid` take `ec` and `hf`**, with
  the same defaults and in the same position as `dsa`, `ssa` and `pedersen`,
  which is what the module's two FIXMEs ("any hf", "any curve") asked for.
  They were module globals — `ec = secp256k1` and `from hashlib import
  sha256 as hf` — so selecting either meant rebinding an attribute of
  `btclib.ecc.borromean`, i.e. changing the algorithm for every other caller
  in the process
- **`btclib.bip32.bip32.ec` is gone**, `secp256k1` being written out at each
  of the seven uses. BIP32 is defined for secp256k1 and for nothing else, so
  the alias was never configuration — but rebinding it changed BIP32 key
  validation process-wide
- **`WordLists.load_lang` holds a lock**, and the bug it closes is not the
  double file read. It recorded the word count before the words, and treats
  a non-zero count as "already loaded", so a second thread arriving between
  the two assignments skipped the load and got back the **empty** list the
  constructor had put there. Forcing that interleaving, the second caller
  saw 0 words where 2048 were expected; there is now a test that does
  exactly that. The two assignments are also ordered the other way round, so
  the published count is never ahead of the words it counts, and the
  docstring says that the module-level `WORDLISTS` is a singleton whose
  `load_lang` is a process-wide decision

### What an error says

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
- `bms.sign` answers an uncompressed key and an address that is not its
  own with "mismatch between private key and address", the message the
  symmetric case has always given. It used to raise "not a private or
  compressed public key for mainnet", which names neither what was passed
  — a private key, for mainnet — nor what failed: the error came out of
  `p2wpkh_p2sh`, tried on the way to BIP137 with a key segwit has no
  spelling for. Both BIP137 addresses are segwit, so an uncompressed key
  can own a p2pkh address and nothing else, and the two comparisons are
  now guarded by that (issue #178)
- `dsa.assert_as_valid_` and `ssa.assert_as_valid_` raise "signature
  verification failed" whichever of the two implementations verified: the
  message used to name an internal helper (`libsecp256k1.ecdsa_verify_
  failed`), telling the caller which backend ran instead of what went
  wrong
- `psbt_utils.serialize_hd_key_paths` raises "invalid type marker
  length", where the last word used to be misspelled — and was pinned
  verbatim by the test asserting it, which is what made the typo an
  interface: code matching on the old message needs updating.
  A codespell hook now guards the prose, having found 63 typos, four of
  them in the README — misspellings of *bitcoin*, *symmetry*,
  *commitment* and *development* — which is the btclib.org homepage and
  the PyPI long description at once. The BIP-39 wordlists and the
  vendored vectors are skipped rather than corrected, being normative:
  one English wordlist entry is a misspelling upstream, and correcting
  it would change every mnemonic derived from that list
- **Typos in visible surfaces.** `_REQUIRED_LENGHT` is `_REQUIRED_LENGTH` in
  `bip32` and `bms`, `bitlenght` is `bit_length`, and the `BIP32KeyData.parse`
  docstring says 78 bytes, where it said 73 and the constant is 78. Five
  exception messages read `implausibile signature failure`. One read
  `generator must a be a sequence[int, int]` and one `script type not it
  ('p2wpkh', 'p2wsh')`; both were pinned verbatim, the first by a test and the
  second by the `error message` field of `bip174_test_vectors.json` — which
  `tests/_data/README.md` now records as btclib's own annotation and not
  upstream's, the BIP specifying no messages. `exceptions.py`, the file a user
  reads first about error handling, no longer opens with "This are only meant
  to discriminate ... from those raised by other codebase". `multiples`'
  docstring closes its set with a brace rather than a parenthesis.
  The `codespell` hook of #161 caught none of these, and the reason is worth
  recording: it matches whole words, so a misspelling inside an identifier —
  `_REQUIRED_LENGHT`, `bitlenght` — is invisible to it, and `implausibile` is
  simply not in the `clear` dictionary. Splitting every identifier in the
  package into words and spell-checking those, 592 distinct words, now finds
  nothing
- **`Network.assert_valid` checks the hrp.** It was `str(self.hrp)` with the
  result discarded, which cannot fail: `str()` accepts every object there is.
  It now raises `BTClibTypeError` for a field that is not a `str`, which is
  what the `bytes()` calls beside it have always done for the rest
- **A private key in a recognised format that is wrong is reported, not
  retried.** `int_from_prv_key` and `prv_keyinfo_from_prv_key` work out
  which of WIF, BIP32 xprv, octets and int they were handed by trying them
  in turn, and they swallowed every failure of the earlier attempts: a WIF
  with one wrong character was not reported as the bad checksum it is, it
  was retried as a hex-string and the caller told "not a private key". Two
  new `BTClibValueError` subclasses draw the line the FIXMEs asked for —
  `NotAPrvKeyError` (wrong format, keep guessing) and `InvalidPrvKeyError`
  (format recognised, content wrong, stop) — so a WIF whose `0x80` prefix
  and checksum are right now reports its own fault: `private key not in
  1..n-1`, `not a compressed WIF: missing trailing 0x01`, `wrong WIF size:
  35`, and an xpub reports `not a private key: prefix 0x03`. When the format
  really is unrecognised the reasons are accumulated rather than discarded,
  so the mistyped WIF above raises `not a private key: not a WIF (invalid
  checksum: 0xa62019d3 instead of 0xa62019d2); not a BIP32 xkey (invalid
  checksum: ...); not octets (non-hexadecimal number ...)`. The input itself
  is still never echoed, being candidate key material; a checksum, a prefix
  and a size are not secret. Both classes are `BTClibValueError`s, so code
  catching that is unaffected. `to_pub_key` still guesses the same way and
  is untouched

### Curves, signatures and keys

- **`mult_endomorphism_secp256k1` answers correctly, and is now the
  fastest python multiplication in the package** (issue #215). Its
  `multiplier_decomposer` did Hankerson–Menezes–Vanstone's algorithm 3.74
  modulo `ec.p` where the congruence only holds modulo the group order —
  secp256k1's p and n share their top 128 bits, so every scalar above
  ~2^127 decomposed to a wrong answer: 300 of 300 random scalars,
  measured, while the handful of small values the old test pinned all
  passed. It also rounded with `ceil` where balance needs
  round-to-nearest, and reduced the signed results `% p`, handing
  `_double_mult` two 256-bit multipliers for an 8-bit m — wrong *and*
  slower than the `_mult` it exists to beat, 2.63 ms against 1.48 ms.
  The decomposition is now 3.74 as written (mod n, nearest, signed, both
  halves ≤ 128 bits, `multiplier_decomposer` losing the `ec` parameter it
  no longer reads), the sign goes into the point as one y-negation, and
  the double multiplication is the new `double_mult_w_NAF` — algorithm
  3.51, interleaved per-scalar wNAFs over tables of odd multiples —
  which completes what the FIXME asking for algorithm 3.77 meant.
  Measured over 30 random 256-bit scalars: 1.00 ms at the default w=4,
  against 1.30 ms feeding the same halves to `_double_mult` and 1.50 ms
  for `_mult`. Nothing in the library calls this function — `mult`
  dispatches to libsecp256k1 or `_mult`, and `btclib.curves` stopped
  exporting the experimental multiplications (#148) — so no signature,
  key or address was ever affected; the module exists to measure such
  implementations against each other, which is how the bug was found
- **`multi_mult` terminates on every scalar it accepts**, and is faster on
  the small batches (issue #175). Bos-Coster's step subtracted the second
  largest scalar from the largest and re-heaped, which is Euclid by
  repeated subtraction, so a pair of distant magnitude cost `n1/n2` turns
  of the heap: `multi_mult([10**6, 1], [G, H])` took 10.6 s and
  `multi_mult([n-1, 1], [G, H])` never finished, on scalars a caller has
  every right to pass. A mixed sign was the worst instance rather than the
  cause — `-1` reduces mod n to `n-1`, which parks it next to `1` — and it
  is how the test suite met it, as two assertions commented out under a
  "FIXME it loop for negative coefficients". The step is now the whole of
  Euclid, `q, r = divmod(n1, n2)` under
  `n1*P1 + n2*P2 = r*P1 + n2*(q*P1 + P2)`: `r < n2 <= n1` makes the largest
  scalar strictly decrease, so the loop terminates, and `q == 1` is
  literally the step it replaces. It is not slower for being general.
  Measured against the old step, interleaved call by call over random
  256-bit scalars: 2.4x faster at 2 scalars, 1.3x at 3, 1.2x at 4, and
  within 1% from 16 up, where the quotient is nearly always 1 and only the
  `divmod` is new. End to end, BIP340 batch verification of 2 signatures
  is 19% faster, of 4 3%, and of 8 or more unchanged. Two negative results
  behind the five lines: `q*P1` uses `mult_jac` and not the faster `_mult`,
  which would rebuild its 16-entry table of multiples at every step and
  measured 10x slower over 128 scalars; and there is no threshold under
  which the subtractive step is kept, because keeping it for q up to 4 or
  up to 16 measured 3% and 11% *slower* — one binary multiplication beats
  q point additions and their heap traffic for every q above 1, and at
  q == 1 the two coincide, `mult_jac(1, P)` being P. Bos-Coster stays,
  Strauss-wNAF and Pippenger (#212) or not: the library is didactic, and
  the algorithm is worth reading
- **borromean ring signatures work on a curve other than secp256k1**, which
  is what the `ec` parameter has been offering since it stopped being a
  module global. It reached the encodings and the order — `bytes_from_point`,
  `ec.nlen`, `ec.n`, `ec.G` — and not the arithmetic: `mult(k)` and
  `double_mult(-e, Q, s, ec.G)` take the curve as a *last* argument
  defaulted to secp256k1, so both type check, read as if they honoured
  `ec`, and computed on secp256k1. Every point was then encoded against
  `ec`, so the first `bytes_from_point` raised "y-coordinate not in
  1..p-1" with a 256-bit coordinate in the message and no other curve
  could sign at all. All eight low-cardinality test curves now sign and
  verify, the cofactor-2 and the n > p ones included, and the corner case
  the marker asked about is reachable rather than merely untested: a zero
  `e` is one message in n where on secp256k1 it is one in 2^255, so three
  of the four "implausible signature failure" guards lose their
  `no cover` pragma, and `s*G - e*Q = INF` — the neighbour corner, which
  has no hash input and so no guard — is pinned too (issue #183)
- **`point_from_octets` takes the hybrid 0x06 and 0x07 prefixes when asked**:
  `point_from_octets(key, hybrid=True)`. They are SEC 1 v.2 section 2.3.4 like
  the other three, carry both coordinates as 0x04 does, and repeat the parity
  of y in the prefix — which is checked, a prefix disagreeing with its own
  coordinate being no point at all, exactly as libsecp256k1's
  `ec_pubkey_parse` decides it. Off by default because an address, a WIF and
  a descriptor have no hybrid form to render and nothing in bitcoin produces
  one; the script engine is the caller that needs them, Core rejecting hybrid
  keys only under STRICTENC (issue #129)
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
- new `pedersen.assert_as_valid`, raising BTClibRuntimeError("commitment
  verification failed"): `pedersen` was the one module with a `verify`
  and no assert_as_valid beside it, leaving no way to learn why opening
  a commitment failed
- **a `key_id` of 2 or 3 recovers the key SEC 1 says it does.** In ECDSA
  public key recovery a key_id is a y_K-coordinate parity bit with the
  section 4.1.6 index `j` above it, and `dsa._recover_pub_key_` read
  those bits *in place* — `key_id & 0b110`, making `j` 2, 4 or 6 where
  the specification counts 1, 2, 3. So a key_id of 2 asked for
  `x_K = r + 2n` and skipped the `r + n` that is the whole reason a
  second candidate exists; libsecp256k1 spells the same two bits
  `recid & 2` for the order to add and `recid & 1` for the parity, which
  is the shift now used. Reaching it takes `r + n < p`, about 2^-127 of
  secp256k1 signatures and never a signer's own output — `key_id =
  pub_keys.index(Q)` cannot name a candidate that failed — but a key_id
  also arrives from outside, in the recovery flag of a message
  signature. `_recover_pub_keys_` is now that function over the range of
  key_ids rather than a second copy of the arithmetic, which is what the
  disagreement was hiding: the plural iterated `j` in `range(cofactor +
  1)` correctly all along, and the two could not be folded together
  until they agreed. Its output is unchanged, checked over the 116808
  (curve, challenge, r, s, lower_s) combinations the eight
  low-cardinality test curves admit; the mod_inv it no longer hoists out
  of the loop costs 1.8 us against the 2600 us of the `_double_mult`
  each candidate already runs (issue #183)
- BIP32 derivation raises on the three children the specification calls
  invalid — `parse256(IL) >= n`, a zero private child, a public child at
  infinity — instead of returning a key no other wallet derives. It says
  so rather than deriving the next index silently, as Core's CKDpriv
  does: the caller asked for one index, and the choice of another is
  theirs. At odds of about 2^-127 this is a defined answer, not a
  reachable one (issue #138)
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
- **BIP340 messages of arbitrary size**, which the BIP allowed in 2023-04
  ("the restriction to 32-byte messages has been lifted") and btclib refused:
  the four vectors `bitcoin/bips` added for it — 0, 1, 17 and 100 bytes, all
  four `TRUE` — were `xfail`. All four verify now, and `ssa.sign_` reproduces
  each signature byte for byte. Nothing about the algorithm changed: the nonce
  and challenge tagged hashes absorb any length unambiguously, `x_K` and `x_Q`
  being fixed at `p_size` each, so what changed is five size checks and what
  the two spellings mean. `ssa.sign_`, `verify_`, `assert_as_valid_`,
  `challenge_`, `batch_verify_` and `bip340_nonce_` take the BIP340 message
  itself, of any size, and their `msg_hash`/`m_hashes` parameters are `msg`
  and `msgs`; `sign`, `verify` and `assert_as_valid` reduce with `hf` first
  and are unchanged, which is what btclib's trailing underscore has always
  distinguished. The bindings still answer "the message hash must be 32
  bytes", so the delegation condition gains a length clause: 32 bytes go to
  libsecp256k1 as before, anything else takes the python path — the pattern
  already in place for a caller-supplied nonce and for every other curve, and
  now the only path that can verify four of BIP340's own vectors. Two tests
  changed with it, both for the better: truncating a message by one byte is no
  longer `invalid size: 31 bytes instead of 32` but a *different message*,
  which the signature does not sign (issue #169)

### Script

- **`ScriptPubKey` is a dataclass**, as the `Script` it extends is. It was a
  plain subclass of one, so `network` was a bare annotation rather than a
  field: `dataclasses.fields` reported only `script`, and
  `dataclasses.replace(testnet_spk)` rebuilt the instance through
  `ScriptPubKey(script=...)` alone — returning a **mainnet** ScriptPubKey,
  and a mainnet `.address`, in silence. `dataclasses.replace(spk,
  network=...)` now works too, which was not expressible at all, and the
  generated `__repr__` names the network where it used to render a testnet
  and a mainnet ScriptPubKey identically. `__init__` and `__eq__` stay
  written out (`init=False, eq=False`)
- **`Script.assert_valid` is a parse, and says so.** It was
  `serialize(self.asm)` with the result discarded, which looks like a
  round-trip check and is not one. A round-trip check would be wrong rather
  than merely absent: a non-minimal push is consensus-legal and does not
  survive one — `4c01ff`, an OP_PUSHDATA1 of a single byte, comes back as
  `01ff`, and over 200k random byte strings a strict comparison rejects 16.
  The `serialize` call was also redundant: it writes back every command
  shape `parse` can produce, `UNKNOWN_OP_CODE_n` included, by an explicit
  branch, and over those 200k strings plus all 256 one-byte scripts it
  raised for nothing `parse` had accepted
- the script verification flags are a `ScriptFlag`, an `enum.Flag` of the
  new `btclib.script.engine.flags`, where they were a list of plain
  strings the engine tested with `"P2SH" in flags`: a misspelled name was
  a *disabled* consensus rule, silently, in a script verification engine.
  `verify_input` and `verify_transaction` still take the names — a
  `ScriptFlag`, Bitcoin Core's comma-separated spelling, or any iterable
  of them, `None` still meaning the default set — but an unknown one now
  raises instead of being ignored, and the engine's own checks are
  `ScriptFlag.X in flags`, which a typo cannot make quietly false. The
  twelve commented-out entries of `ALL_FLAGS`, one of them the
  never-enablable `"MINMALIF"`, are members like the rest, and the
  module-level list that had to be copied at every use is a value that
  cannot be mutated at all. `SIG_HASH_TYPES` is a `frozenset` for the
  same reason: it is a membership test in all of its uses, one of them
  what the engine accepts as a signature's hash type (issue #145)

### Transactions, blocks and PSBT

- **A psbt can carry a taproot signature with its sig_hash type.** BIP341
  spends with 64 bytes of signature, or 65 when the sig_hash type is not
  the default one — the extra byte being that type — and BIP371 says "64
  or 65 bytes" of both `PSBT_IN_TAP_KEY_SIG` and `PSBT_IN_TAP_SCRIPT_SIG`.
  btclib required exactly 64, so a signature Bitcoin Core accepts had no
  psbt to travel in, while btclib's *own* script engine reads the 65-byte
  form (`get_hashtype`). The appended byte is checked, as BIP341 and that
  engine check it: `0x00` is refused, being what the 64-byte form already
  means, and so is anything outside `SIG_HASH_TYPES` — `0x80`,
  ANYONECANPAY with DEFAULT, is the one that looks valid and is not. Every
  BIP371 invalid vector stays invalid: the two "too short" carry 63 bytes
  and the two "too long" 66. The second argument of
  `psbt_utils.assert_valid_taproot_signatures` is now the *name* of what
  is being validated rather than the whole message, there being three
  things to report about one signature; the messages carry the length or
  the offending type, where they used to be a bare "invalid ... length"
  (issue #122)
- a hand-built BlockHeader no longer serializes differently on machines
  in different time zones: the `time` default is now the epoch as an
  aware datetime (it was naive, i.e. read back as local time by the
  `timestamp()` call in `serialize`), and `assert_valid` rejects a naive
  datetime instead of guessing its instant. `parse` was already correct,
  producing UTC
- the third BlockHeader parameter is named `merkle_root`, as the field
  is: it was `merkle_root_`, which made `BlockHeader(merkle_root=...)`
  a TypeError
- **A PSBT whose unsigned transaction has no inputs is accepted**, as BIP174
  says it must be: two of its valid vectors are such PSBTs and btclib refused
  both. The unsigned transaction is incomplete by construction, so
  `Tx.assert_valid` takes an `unsigned_template` flag that drops the two rules
  it cannot satisfy — at least one input, at least one output — and only
  those; everything else still applies, and a plain `Tx` is unchanged. Four
  places were applying them: `deserialize_tx` on the way in,
  `Psbt.assert_valid`'s `null transaction`, `Tx.serialize` on the way back
  out, and `Psbt.from_dict`. Two consequences worth naming. `Psbt.parse` now
  requires the `PSBT_GLOBAL_UNSIGNED_TX` key, which BIP174 does too: the
  dropped `null transaction` check was doing that job as well, since a
  missing key left an empty `Tx` indistinguishable from a parsed zero-input
  one, and it answers `malformed psbt: missing global unsigned tx`. And the
  vector named "an invalid value data due to its size being not the stated
  size" is now reported as `wrong tx serialization format`: `deserialize_tx`
  had always compared the re-serialized transaction against the value it came
  from — 51 bytes whose transaction is 10 — and validating on the way in was
  what made that comparison unreachable. `assert_signable` answers the other
  question and refuses it: `nothing to sign: no inputs`. Every check in it is
  per input, so without that line an empty `vin` passed the loop vacuously
  and a caller signed nothing while being told nothing (issue #170)

### The public API and the module layout

- **`btclib.ec` is now `btclib.curves`**, which is a breaking rename and the
  only one here: every name the package exports is the name it exported
  before, and the split between curve arithmetic and the schemes built on it
  is unchanged. What was wrong was the name — `btclib.ec` and `btclib.ecc`
  differ by one character, and `from btclib.ec import mult` against
  `from btclib.ecc import dsa` is a coin flip for anyone who has not read
  both. Code importing `btclib.ec` has to be updated; that is the whole cost.
  The three pairs that are one idea split in two now each say so, in a
  "Module layout" table in the README and in all six docstrings:
  `curves`/`ecc`, `base58`/`b58`, `bech32`/`b32`, the codec or the arithmetic
  on the left and the bitcoin semantics on the right, importing rightwards
  only. `bech32.py` also stops citing `segwitaddress.py`, a file renamed to
  `b32.py` several releases ago (issue #148)
- `btclib.b58` no longer imports `btclib.script`: importing an address
  encoding stops pulling the whole script package in, and the cycle b58 ->
  btclib.script -> script.script_pub_key -> b58 is gone. Importing any
  script submodule executes the package `__init__`, which pulls
  script_pub_key in, and script_pub_key imports b58 to render an address;
  the library survived that only because it imported the modules rather
  than their names, so the partially initialized b58 was never asked for
  an attribute at import time. Nothing in the file said so, and a single
  name import anywhere along the cycle was an ImportError. `serialize` was
  all b58 wanted from there, for the p2sh-wrapped SegWit v0 redeem script
  `[OP_0, witness program]`, which it now spells out — a test checks the
  two agree, over both witness program sizes v0 admits. The new
  tests/test_imports.py imports every module of the package first, with no
  other in sys.modules: that is the order no other test reaches, and the
  one a cycle hides behind (issue #147)
- **`btclib.ec` exports the curve API, not a benchmark.** Its `__all__` held
  24 names, fourteen of which were one operation written fourteen ways: the
  eleven `mult_*` variants of `curve_group` and `curve_group_2` — `mult_aff`,
  `mult_jac`, `mult_base_3`, `mult_mont_ladder`, the two `mult_recursive_*`,
  the two `mult_fixed_window*`, `mult_sliding_window`, `mult_w_NAF`,
  `mult_endomorphism_secp256k1` — plus the `multiples`, `cached_multiples`
  and `jac_from_aff` they are built on. They are kept side by side to be
  measured against each other, and exporting them made a menu out of it,
  with nothing to say that `mult` is the one to use, that it dispatches to
  libsecp256k1 for secp256k1 and the generator, or that `mult_jac` is not
  the faster alternative its name suggests. `__all__` is now `Curve`,
  `CurveGroup`, `secp256k1`, `mult`, `double_mult`, `multi_mult`,
  `bytes_from_point`, `point_from_octets`, `find_all_points`,
  `find_subgroup_points`; each variant is still importable from the module
  that defines it, which is where the four affected test modules now take
  them from
- **`btclib.ecc` exports the signature schemes.** `__all__` was
  `ansi_x9_63_kdf`, `bip340_nonce_`, `diffie_hellman`, `second_generator` —
  four helpers, and not one of the schemes behind them — so `import
  btclib.ecc` followed by `btclib.ecc.dsa.sign(...)` raised AttributeError
  until something else in the process happened to import the submodule. It
  now exports `dsa`, `ssa`, `bms`, `borromean`, `pedersen` and
  `sign_to_contract` beside the four
- **`btclib.mnemonic` exports `bip39` and `electrum`**, its two schemes,
  which were reachable on the same accidental terms
- **`NETWORKS` describes signet and testnet4**, where it had mainnet,
  testnet and regtest and a caller working on either of the other two
  had to build a `Network` by hand. Signet has been in Core since 0.21
  and is where most protocol work is demonstrated; testnet4 shipped in
  28.0 and is what "testnet" increasingly means. The two JSON files
  differ from `testnet.json` in the genesis block and the p2p magic and
  in nothing else — the wif, p2pkh, p2sh, `tb` hrp and `tprv`/`tpub`
  version bytes are testnet's, which a test asserts field by field.
  Signet's magic is not a constant to copy: Core derives it as the first
  four bytes of the sha256d of the length-prefixed signet challenge, so
  the test derives it too, from the challenge in `kernel/chainparams.cpp`
  — which also records the limitation, that a *custom* signet has a
  different challenge and so a different magic, and is a `Network` the
  caller builds. `XPRV_VERSIONS_ALL` and `XPUB_VERSIONS_ALL` are now
  built by iterating `NETWORKS` instead of spelling out `testnet * 2`,
  which said "three networks" in two places and in neither of them said
  why. The ambiguity that five networks behind one set of version bytes
  creates is the entry below (issue #207)
- **a network has a type, `"main"` or `"test"`**, and three new lookups
  answer with it: `network_type_from_key_value`,
  `network_type_from_xkeyversion` and `network_type_from_network`. This
  is what a version prefix can still say now that five networks are
  known, and the answer to "should the reverse lookups exist at all".
  Measured first, both ways. The name they return feeds only fields the
  test networks share — curve, wif, p2pkh, p2sh, hrp, xkey versions —
  and nothing in the package reads `magic_bytes` or `genesis_block`, so
  an ambiguous name never produced a wrong *byte*; and no prefix of any
  test network equals any prefix of mainnet, on any field against any
  field, which a test now asserts. So main-versus-test always has an
  answer where "which chain" does not — it is the distinction the
  version bytes were designed to draw, Satoshi's `0x6f`, BIP32's
  `tpub`, SLIP132, and SLIP44 giving every test chain one coin type —
  and it is the one that matters for funds. `"main"` is Core's own name
  for the chain; `"test"` is SLIP44's testnet *family*, deliberately not
  Core's `chain=test`, which names testnet3 alone.
  The type is a `Network` field, declared in each `_data/*.json` and
  defaulting to `"test"` in `from_dict`, so a caller building a custom
  signet by hand — what issue #207 says callers do — cannot let a
  forgotten argument claim the real chain; `assert_valid` refuses a
  third value, `NetworkType` being a mypy `Literal` and not a runtime
  check. A `Literal` and not an `Enum`: network names are `str`
  throughout this library, so an enum here would be an island, and
  strict mypy already rejects the typo. Whether btclib should move to
  enums wholesale is a real question and a separate one.
  `network_from_key_value` and `network_from_xkeyversion` keep their
  names, signatures and answers, and their docstring warnings become a
  contract: they return the *oldest* network carrying the prefix —
  "testnet" for the shared ones, "regtest" for the `bcrt` hrp that is
  regtest's alone — which is the right network to encode and re-encode
  *with*, every candidate agreeing on every prefix, and is not an answer
  to "which chain is this". New `networks_from_key_value` and
  `networks_from_xkeyversion` return every candidate, oldest first: the
  list is the ordinal the singular lookups hide, `[0]` the canonical
  answer and `[n]` the nth network, and its length says how many there
  are, which "testnet" alone could never say. What none of them
  replaces is the forward check — a version among
  `xprvversions_from_network(net)`, a prefix equal to
  `NETWORKS[net].wif` — which is exact for all five networks and is what
  a caller who *knows* the chain should use.
  Removing the reverse lookups instead was evaluated and rejected:
  Electrum can require the network of every call because it picks one at
  startup, and btclib deliberately has no such global. The cost would
  have been a mandatory `network` argument across `h160_from_address`,
  `witness_from_address`, `ScriptPubKey.from_address`, `Bip21`,
  `bms.sign` and the keyinfo functions, plus the functional end of
  `slip132.address_from_xkey`, whose whole point is that the version
  bytes encode the script type — a price paid mostly by mainnet users,
  for whom the inference is sound, mainnet's prefixes being unique.
  `n_versions` and `_REPEATED_NETWORKS` are gone with the index
  arithmetic they served: the lookups ask each network whether it holds
  the version, the position of a repeated entry having meant nothing. An
  unknown xkey version now raises `BTClibValueError("unknown xkey
  version: 0x...")` where `list.index` leaked a bare `ValueError` naming
  the list; `BTClibValueError` is a `ValueError`, so an `except
  ValueError` caller is unaffected (issue #207)
- **`ScriptPubKey` equality compares the network type**, not the network
  name. Four test networks share one set of address prefixes, so
  `from_address` answers "testnet" for a signet address — and comparing
  names made a signet `ScriptPubKey` unequal to the very address it
  renders, identical script bytes and all. Regtest hid this before
  signet and testnet4 arrived: its `bcrt` hrp is unique, so a bech32
  regtest address round-tripped to the name it came from. Mainnet is
  still not equal to any test network, which is the funds-relevant half;
  `ScriptPubKey` has no `__hash__` to keep consistent with this, `Script`
  defining `__eq__` without one, and `TxOut` equality inherits the fix
  through its `script_pub_key` field (issue #207)
- **new `btclib.bip21`**, the `bitcoin:` payment URI: the gap between
  what a user pastes or scans and the typed surface the library offers.
  `Bip21.parse`, `.serialize` and `.assert_valid`, with `address`,
  `amount`, `label`, `message` and a `network_type` read off the address
  — `"main"` or `"test"`, which is what an address carries: a `tb1` one
  is testnet, signet and testnet4 at once, so the property cannot name a
  chain, and a payer's question is whether the request is for real
  bitcoin. It adds no edge to the dependency graph the README draws — it
  imports `b58`, `b32`, `amount` and `network`, and nothing in the
  library imports it.
  The four rules an implementation gets wrong are the content: an
  unknown `req-` parameter invalidates the URI and an unknown one
  without the prefix is ignored, which is the whole
  forward-compatibility story of the scheme (and the prefix is read
  case-insensitively and after percent-decoding, so `REQ-foo` and
  `%72eq-foo` fail closed too); `amount` is decimal BTC and is held to
  BIP21's own grammar of digits and at most one dot, so the `1e5`,
  `+1`, `Infinity` and ` 1 ` that `Decimal` would otherwise accept are
  refused before `valid_btc_amount` sees them; a repeated key is an
  error, two amounts being two requests; and nothing lowercases the
  address, a bech32 one being legally uppercase in the QR-code case
  while a base58 one uppercased is a broken checksum. `label` and
  `message` are percent-decoded with `unquote` and not `unquote_plus`,
  a payment URI not being an HTML form, so `Alice+Bob` is two names.
  Along the way: **the address BIP21 prints in every one of its
  examples does not checksum.** Its payload is a sound mainnet p2pkh
  hash160 and hash256 of it begins `8a9c6111` where the address carries
  `8a9c6129`, so the last base58 character should be `6` where the BIP
  writes `W`. The tests use the corrected address and pin the
  divergence rather than paper over it (issue #203)
- **`btclib.script` exports `is_p2pkh`**, which was the one missing from the
  eight assert/is pairs — `assert_p2pkh` was there, and so were the other
  seven of each
- `op_codes_tapscript` no longer re-exports `op_int`. The import at the top
  of the module was the name's only occurrence in it, and the `# noqa: F401`
  on the block is what kept ruff from saying so; nothing anywhere took the
  name from there, every consumer using `btclib.script.script`, where it is
  defined, or `btclib.script`, which declares it in `__all__`. It came to
  light next to a neighbour that went first: turning mypy `strict` on made
  `_serialize_int_command` dead in the same block and it was removed with
  the change that killed it, where `op_int` had been dead before and was
  left alone rather than folded into an unrelated commit. The surviving
  import of `_serialize_bytes_command` is a real one, so the `noqa` goes
  too. `from btclib.script.op_codes_tapscript import op_int` was legal on
  v2023.7.12 and stops working, which is why it is written down here; it is
  not in HISTORY.md's breaking list, because the public surface is what
  `__all__` declares and this module is not in it (issue #130)
- **`check_validity` is keyword-only**, in all 91 signatures that take it.
  It was positional-or-keyword and forwarded by hand from one signature to
  the next, often *positionally* — 100 call sites inside the package alone —
  which is precisely how a flag ends up in another parameter's slot after a
  signature grows a parameter in front of it, silently and with a plausible
  value. `Tx(1, 0, vin, vout, False)` is a TypeError now; `Tx(1, 0, vin,
  vout, check_validity=False)` is unchanged, so a caller already using the
  keyword needs no edit. The 100 forwardings read better for it: a bare
  `tx_in.to_dict(False)` said nothing about which flag it was setting.
  `dsa.Sig`, `ssa.Sig`, and `bms.Sig` spell it as a written-out `__init__`
  rather than the `InitVar[bool]` field and `__post_init__` they used to
  share with the rest of the library, a dataclass field being made
  keyword-only by `field(kw_only=True)`, which is python 3.10 where this
  package supports 3.9; `dataclasses.fields`, `replace`, `==`, `hash`, and
  `repr` are unaffected, and the three stay frozen. `dsa.Sig.parse` is the
  one signature with a parameter *after* the flag, so `strict` becomes
  keyword-only too: moving it in front of the star instead would have made
  `Sig.parse(data, False)` mean `strict=False` where it used to mean
  `check_validity=False`, which is the silent failure the whole change is
  against. The new tests/test_check_validity.py asserts the rule over the
  package's own source, so a new signature cannot reintroduce the hazard

### Types

- `alias.TaprootScriptTree` is a type. It was `Any`, behind a TODO citing
  mypy issue 731 — recursive type aliases — which mypy closed in 0.990 and
  has had on by default since 1.0, so the whole taproot script-tree
  surface was unchecked: `output_pubkey`, `output_prvkey`,
  `input_script_sig`, and `ScriptPubKey.p2tr` accepted anything at all.
  It is now the recursive `list[Union[TaprootLeaf, TaprootScriptTree]]`,
  with the leaf pair named as `TaprootLeaf` beside it and exported from
  `btclib.script`, and `tree_helper` returns the new `TaprootLeafPaths`
  rather than `tuple[Any, bytes]`. `list` and not the `Sequence` mypy's
  variance note suggests: `str` is a `Sequence[str]`, so under `Sequence`
  the recursion admits any string as an entire tree —
  `output_pubkey(None, "hello")` type checks — and a `(leaf_version,
  script)` tuple whose version is a string passes as a branch of two
  subtrees. Measured over five malformed trees, `list` rejects five and
  `Sequence` three. The cost of invariance is that a tree built into a
  variable rather than passed as a literal wants the annotation, which is
  the documentation anyway
- **mypy is aimed at python 3.10**, not at whatever interpreter runs it.
  `[tool.mypy]` set no `python_version`, so the strict check used the 3.14 of
  `.python-version` while `requires-python` says `>=3.9`, and a typing
  construct absent from an older interpreter was invisible: `typing.Self`,
  3.11 and later, type checked. Ruff was already targeted correctly, inferring
  py39 from `requires-python`. Not 3.9, which is what would have matched:
  mypy refuses it outright, having followed 3.9 out of support, and
  `d284d0b7` had already recorded that. What covered the rest was the test
  matrix — a type *alias* is an ordinary assignment, so `ScriptList | None`
  at module level is a TypeError before 3.10 and every 3.9 runner died
  collecting, which is how that commit's bug was found (issue #155).
  Dropping 3.9 closed the gap from the other end: the floor is 3.10 now, so
  the pin says exactly what `requires-python` says, and that class of bug is
  the type checker's again
- **the public type aliases are PEP 604 unions**: `Octets = bytes | str`,
  and the same for `String`, `BinaryData`, `Integer`, `Command`, `BIP32Key`,
  `BIP32DerPath`, `BIP340PubKey`, `Entropy`, `OneOrMoreInt`, `ScriptFlags`,
  `PrvKey`, `PubKey`, `Key` and `NoneOneOrMoreInt`. Fifteen of them, and they
  were `Union[...]` for one reason: a type alias is an ordinary assignment,
  not an annotation, so `from __future__ import annotations` does not reach
  it and `bytes | str` at module level was a TypeError until 3.10 — the very
  trap `d284d0b7` fell into. `typing.Union` and `|` compare equal, so
  `get_args` and every annotation built on these aliases answer as before,
  and `isinstance(x, Octets)` now works where `Union` refused it.
  `TaprootScriptTree` keeps its `Union`, being recursive: the forward
  reference is a string, and a string has no `|`
- **The library's two notions of "hash function" have two names.** `HashF` is
  a hashlib-style *constructor*, called with no argument and fed through
  `update()`; the merkle functions of `btclib.hashes` take a *one-shot
  digest* instead — `hash256`, not `hashlib.sha256` — and spelled it out
  inline as `Callable[[bytes | str], bytes]` while everything else in the
  library called its parameter `hf` too. That second notion is
  `alias.HashDigestF` now, so the distinction is stated where the aliases
  live rather than reinvented at three call sites, and the stale
  commented-out `# HashF = Callable[[Any], Any]` beside it is gone
- **`HashF` returns a `HashObject` Protocol, not `Any`**, which was the real
  gap: `hf().digest()` and `hf().digest_size` were `Any`, so every
  expression downstream of a hash function went unchecked in a mypy-strict
  code base — eleven sites read `digest_size` and nine build a digest
  through `update()`. Measured over four probe functions, mypy went from
  four `Returning Any` complaints — one of them against the **correct**
  function, and none naming the actual mistake — to naming each fault:
  `"HashObject" has no attribute "digets"; maybe "digest"?`, `got "bytes",
  expected "int"`. It caught a real one on the spot: `borromean` bound `h`
  to a digest inside its loops and to a hash object after them. Only
  `update`'s parameter stays `Any`, because `hmac.new`'s `digestmod` wants a
  buffer union python 3.9 cannot spell and `rfc6979` passes `hf` to it eight
  times
- `alias.py` says at the top that `Octets` and `String` are the same type
  to mypy, both being `Union[bytes, str]`, so the hex-string versus text
  string distinction the file documents is enforced at run time by the
  converter each function calls and by nothing else. `NewType` would let a
  checker separate them at the cost of every caller wrapping its literals,
  which is a different library

### Performance

- signing or verifying a transaction is linear in the number of its
  inputs, where it was Θ(N²). `segwit_v0` and `taproot` rebuilt, for
  every input, the hashes that depend on the whole transaction — its
  prevouts, its sequences, its outputs, plus the amounts and
  script_pub_keys being spent — so a transaction with N inputs hashed
  each of them N times, and the cost *per input* grew with N: 15 µs at
  one input against 414 µs at four hundred, where verifying the same 400
  taproot signatures costs 98 ms through libsecp256k1. A consolidation
  transaction is the ordinary case there, not a pathological one. The new
  `sig_hash.PrecomputedTxData` computes them once, as Bitcoin Core's
  PrecomputedTransactionData does, and `script_engine.verify_transaction`
  builds one for its loop over the inputs; `sig_hash.from_tx`, `segwit_v0`
  and `taproot` take one as an optional last argument, for a caller
  driving the loop itself. Measured over 400 inputs: 57 ms to 1.9 ms for
  p2wpkh, 164 ms to 0.4 ms for p2tr, and 5 µs and 1 µs per input
  whichever N. It is a frozen snapshot holding no reference to the
  transaction, deliberately: `Tx` is mutable, and caching on it is issue
  #140 — a sig_hash that changed under the caller between two calls — so
  it must be built for a loop and dropped with it. `taproot` also stops
  re-validating every OutPoint and TxOut of the transaction once per
  input, as `segwit_v0` and the rest of the library already did in an
  inner loop, and builds its preimage with `b"".join` instead of `+=`:
  that is most of the 164 ms to 81 ms the un-precomputed taproot path
  gained. The legacy sig_hash stays quadratic, its preimage being the
  transaction itself, blanked and re-serialized per input — there is no
  transaction-wide part of it to share, here or in Core (issue #164)
- **`bms.sign` is twice as fast**, and its recovery flag now names a
  key_id rather than a position in a list. It read
  `dsa.recover_pub_keys(magic_msg, dsa_sig).index(Q)`: every candidate
  recovered, then searched. On secp256k1 the recovery set is key_ids 0 and
  1 — a signer's own key has j = 0 — so key_ids 2 and 3 were computed only
  to be dropped, each a python `_double_mult` whenever `r + ec.n - ec.p`
  lands on the curve, about half the time. The search now runs one
  candidate at a time and stops at the match: 18.7 ms to 9.0 ms, measured
  over 40 random (key, msg) pairs. `.index` was also the wrong question by
  a hair — it answers the key_id only while no earlier candidate has
  dropped out, and the j = 1 case is exactly one that drops two, so a
  signature with `r + ec.n < ec.p` and `r` not a coordinate on the curve
  would have been flagged 0 or 1 where 2 or 3 recovers the key. That takes
  some 2^-127 of signatures, and is now unreachable rather than unlikely
  (issue #183)
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
- **A `ScriptPubKey` parses its script once**, not twice. `__init__` called
  `assert_valid()` after `super().__init__` had already done so: `Script.
  __init__` calls `self.assert_valid()`, which dispatches to the override,
  which runs Script's check *and* the network one — the whole validation.
  Counted through the module: two parses and two serializations per
  ScriptPubKey before, one parse and no serialization now
- **A public key from a private key no longer builds the point**, and the
  new `curves.bytes_from_prv_key_int` is what does it: 8.90 µs to 7.75 µs
  per call, best of nine over 2000 random keys. For secp256k1 the bindings
  answer `0x04 || x || y`, so the compressed form is the first 33 bytes of
  that with the prefix rewritten to the parity of the y being dropped —
  where the `bytes_from_point(mult(q))` it replaces turned 64 of those
  bytes into two ints, re-proved on curve a point libsecp256k1 had just
  created, and serialized it again. It serves the four sites that did the
  composition: BIP32 neutering, non-hardened private derivation, the parent
  fingerprint of the last derivation step, and
  `to_pub_key.pub_keyinfo_from_prv_key`, i.e. every address and WIF from a
  private key. `derive m/0/1/2/3` 66.1 µs to 61.8 µs,
  `pub_keyinfo_from_prv_key` 8.9 µs to 7.9 µs, and the uncompressed form,
  which used to pay the same round trip, is now the bindings' answer
  verbatim. Every other curve still composes the two functions, and a zero
  scalar still raises from `bytes_from_point`: the answer is the same
  answer, the edges included. The alternative was a `pubkey_from_prvkey` of
  the bindings' own (btclib_libsecp256k1#41), one
  `secp256k1_ec_pubkey_create` plus one compressed serialize; dropped into
  this same function it measures 7.67 µs, 0.8% below the slice, so what
  argues for it upstream is the bindings' API convention that public keys
  come out compressed, and not btclib's speed (issue #127)

### Tests

- **coverage is 100% and the ratchet is 99.99%**, where it was 99.9% and
  the measured total 99.92%. That gap was not a rounding allowance being
  used up: it was 12 uncovered statements, and 15 of slack is what let
  them accumulate unremarked while both `CONTRIBUTING.md` and the
  `fail_under` comment claimed "0 uncovered". Six were in
  `tests/conftest.py` — the golden-file check's own regenerate,
  missing-file and mismatch paths, which are the three that matter and
  the only lines of `tests/` a passing suite never runs. They were
  unreachable from a test because they lived in a closure over
  `request`: the body is now `conftest.check_golden(path, name, value,
  module)` and `tests/test_conftest.py` drives all three against a
  `tmp_path`, hermetically, which is what that fixture exists to have
  stopped doing to the source tree. Two more were
  `engine.script.dsa_verify`'s `except ValueError`, the wrapper that
  turns a signature libsecp256k1 refuses to parse into a failed
  CHECKSIG rather than an exception — never reached by the vectors,
  because `fix_signature` rules on the encoding first, and now tested
  directly against both refusals the bindings raise. Two were
  `Network.assert_valid`'s hrp type check. One was the `return None` of
  `test_bms._recovers`, i.e. the recovery candidate that drops out of the
  set, now asserted for key_ids 2 and 3. And one was `if r == 0:
  continue` in `test_key_id_is_the_j_zero_pair_when_n_is_above_p`, a
  branch no input can take: on ec13_19 the r values are
  {1,2,3,4,5,6,9,10,12}, which is the n > p property the test's own
  docstring names, so it is `assert r` now — a checked claim instead of a
  possibility the curve does not have. 99.99 rather than 100 because
  coverage special-cases 100 to mean exactly 100.00%, which would make
  one version-gated line a red build; the comparison is
  `round(total, precision) < fail_under`, so 99.99 allows two of the
  15205 statements the coverage job measures
- **`tests/ecc/test_bms.py` imports on python 3.9 again.** It annotates a
  helper `-> Point | None` without `from __future__ import annotations`,
  which 3.9 evaluates at def time and has no `|` for: the module was ten
  collection errors on the oldest supported interpreter and passed on
  every other, so the `test-py` matrix was red for 3.9 alone. The future
  import is what the rest of the tree uses
- **a curve whose order is above its field prime is covered**, the
  neighbour of the n == p check issue #166 found never fired (issue #183).
  Hasse puts p and n within 2\*sqrt(p) of each other, so which is the
  larger is a property of the curve: four of the eight low-cardinality test
  curves have n > p, and so do six of the 27 catalogued ones —
  `secp112r1`, `secp128r1`, `secp160k1`, `secp160r1`, `secp160r2`,
  `secp224k1`. `test_curves_with_n_above_p` pins that spread, which was
  nothing but an accident of the test data before, and
  `test_key_id_is_the_j_zero_pair_when_n_is_above_p` draws the consequence
  for key recovery: `r = x_K % ec.n` cannot reduce while p < n, so the
  signer is always named by key_id 0 or 1 and the j >= 1 candidates are
  spurious rather than merely unlikely — over the 5832 signatures ec13_19
  admits, every one of them. It is the mirror of the cofactor-2 case
  beside it, where n < p and only a j of 1 recovers the key
- **`TxIn.assert_valid` not looking at `script_sig` is now a decision with
  a test**, where it was a `# TODO check script_sig` (issue #183). An input
  whose script does not parse is a valid input — evaluation is
  `script_engine`'s answer to give — the 1650 bytes and push-only of Core's
  `IsStandardTx` are relay policy rather than validity, and the one
  consensus rule at this level, the coinbase's 2..100 bytes, is
  `Tx.assert_valid`'s: it takes a coinbase *transaction*, while a lone
  `TxIn` with the null prev_out is the placeholder a builder starts from.
  `test_script_sig_is_not_validated_and_that_is_the_answer` pins all four
- **the vendored consensus vectors are judged by the python implementation
  too**, in `tests/script_engine/test_python_path.py`: the two symbols the
  engine imports from the bindings are replaced by `btclib.ecc`, and
  `script_tests.json`, `tx_valid.json`, `tx_invalid.json` and the taproot
  vectors — 4168 of them — run again through it. Until 23041e4b the engine
  fell back to python when the bindings were absent, two vectors failed in
  that configuration, and making the bindings mandatory turned the tests
  green without fixing either defect: they had become unreachable.
  Reintroducing either one now fails four vectors, two of which no issue had
  named. A CI job installing without the bindings would have been the other
  way, and it is not a job but a partial revert — all five bindings imports
  are plain imports, so `import btclib` itself fails without them. Measured
  cost: the suite goes from 11 s to 27 s, the eight `bigmulti` tapscript
  vectors being most of it (issue #129)
- **BIP341's key path spending vectors are signed, not only hashed.** Its
  seven `inputSpending` cases pinned the `sigHash` and stopped there, so
  `expected.witness` — the signature the BIP says that hash produces — went
  unchecked, and the suite verified taproot signatures without ever making
  one. Each case is signed now, with the vector's tweaked private key and an
  aux_rand of 32 zero bytes (what those signatures were made with, and what
  makes a BIP340 signature reproducible at all), and the witness element is
  compared byte for byte, appended hash-type byte included; for the one
  input that commits to no script, `output_prvkey` is checked against the
  BIP's own tweak. A second test builds the spend instead of reading it —
  tweak, sig_hash, signature, witness encoding and `verify_transaction`
  with every flag on, over five sig_hash spellings with and without a
  script tree — and pins the two mistakes issue #124 walked into: `sign`
  reduces its argument with `hf` where `sign_` does not, and the key the
  script carries is the *tweaked* one (issue #124)
- the two deterministic nonce derivations are compared, in
  tests/ecc/test_rfc6979.py, which is what TODO.md's "compare of
  dsa.rfc6979_and ssa.det_nonce_" asked for. Four tests, over the same
  inputs: that they never agree, which nothing in either scheme forces;
  what each *reads*, which is the substantive difference — RFC6979 takes
  the challenge, so two messages colliding modulo n get one nonce, and
  it takes no auxiliary randomness, where BIP340 absorbs the whole
  message, the public key and 32 bytes of aux, and then returns only the
  k whose K has an even y-coordinate, half of [1, n-1] being unreachable
  by construction; that neither reduces a candidate modulo n, which is
  observable because the rejection loop costs another round and can be
  counted through the `hf` both take as a parameter; and what each
  costs, 12 sha256 objects against 6 on secp256k1, where the loop never
  fires. A chi-square is deliberately *not* what settles the bias
  question, and the test says why: RFC6979's whole input space on the
  test curve is 342 (challenge, private key) pairs, and at that sample
  size the statistic for a mod-n reduction sits inside the noise of an
  unbiased derivation (issue #194)
- three tests say what the code only did. `Curve.__repr__` renders every
  integer above `HEX_THRESHOLD` in `hex_string`'s `DEADBEEF 00000000`
  grouping and never `0xdeadbeef00000000`, which the round-trip test
  quietly depended on — a `0x` prefix would be a *number* in the repr
  where the constructor is handed a string, and `Curve` takes it either
  way — and is now asserted, decimal below the threshold included. The
  500 legacy sig_hash vectors are parsed with validation *on*: they are
  Core's randomly generated transactions, random and not malformed, and
  all 500 are valid, where `check_validity=False` for the whole file
  said the opposite without checking it. And what those vectors do not
  cover is now asserted too — Core draws each hash type from
  `InsecureRand32()`, so not one of the 500 is in `SIG_HASH_TYPES`, and
  the defined types are covered by the hand-written tests beside them
  (issue #183)
- tests/_data/README.md records where each of the 28 vendored vector
  files came from, pinned to an upstream commit and, where an upstream
  file exists, compared blob by blob: 7 are byte-identical, 6 diverge
  in ways the file characterizes, and 15 have no upstream file to
  compare -- 6 transcribed from a BIP's prose, 6 chain data identified
  by block hash or txid, 3 btclib's own. The citations in the test
  modules named mutable `blob/master` paths, so "which revision of
  BIP-341 does this match" had no answer. Two of them were also wrong,
  and are corrected
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
- **The test suite writes nothing.** Eleven modules serialized a dataclass to
  `tests/**/_generated_files/*.json` on every run, and the point of committing
  those files was to notice a change to a serialized form. The check ran the
  wrong way round for that: the suite was not hermetic, so it failed on a
  read-only checkout or from an installed sdist — measured, nine
  `PermissionError` failures — and it depended on a human running the suite
  and then looking at `git status`, which **CI never does**: no workflow
  inspects the working tree after pytest, so in CI the file was rewritten and
  discarded and the drift was invisible exactly where it mattered. The files
  are read and compared now, by a `json_golden` fixture that fails with a
  unified diff, so a change to `to_dict` is a red test. Regenerating one is
  deliberate and asked for: `BTCLIB_REGENERATE_GOLDEN=1 uv run pytest`, which
  the failure message names. The on-disk round trip those tests did — dump,
  load, compare to the dict just dumped — is gone with it: it could only fail
  if `json.dump` and `json.load` were not each other's inverse, and each of
  those tests already asserted `from_dict(to_dict()) == obj` in memory beside
  it. So are the twelve `file_.write("\n")  # end-of-file-fixer` lines, tests
  shaped to placate a lint hook (issue #154)

### Supported interpreters and dependencies

- dropped python 3.7 and 3.8 support, added 3.13 and 3.14
- **dropped python 3.9**, so `requires-python` is `>=3.10` and the matrix
  runs 42 jobs instead of 48. 3.9 went end-of-life in 2025-10, and it was
  costing more than a column: a fresh resolve at `>=3.9` split 35 of 132
  locked packages into a current version and an older one reachable only
  from 3.9 — mypy 1.19 beside 2.3, pytest 8.4 beside 9.1, hypothesis 6.141
  beside 6.164, coverage 7.10 beside 7.15 — so the 3.9 jobs were the only
  ones not testing against what everybody else runs, and the one generating
  its hypothesis inputs with an engine nobody else had. At `>=3.10` the lock
  holds 99 packages and 4 splits, all four at the 3.11 docs boundary. No
  interpreter gained a newer dependency: what went away is the second
  toolchain. `published.yml` and `latest.yml` sample 3.10 and 3.14 as the
  ends of the supported range, where they sampled 3.9 and 3.14
- dropped pypy3.10 from the test matrix; pypy3.11 stays, so PyPy is still
  covered. hypothesis ships compiled wheels from 6.160 on and publishes
  none for pypy3.10, whose sdist build needs a PyO3 requiring PyPy 3.11 or
  newer
- development and CI now track the btclib_libsecp256k1 bindings under
  development (built from source), instead of the released ones; the
  published btclib still depends on btclib_libsecp256k1 from PyPI

### Packaging, linting and CI

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
- `version-check` refuses a tag whose release notes were not retitled: the
  GitHub release notes are HISTORY.md's `## v<version>` section, and the
  extraction matches a heading that carries anything *after* the version
  too, so `## v2026.8 (work in progress, not released yet)` would have been
  published as the notes of v2026.8 — silently, the release job's fallback
  firing only on an *empty* section. An empty section is refused as well,
  and CHANGELOG.md's heading is checked beside HISTORY.md's, the two being
  retitled together and the first linking to the second (issue #157)
- the matrix covers 3.14t, the free-threaded interpreter, and pytest is
  stricter: a warning is an error, an unregistered marker and a typo in
  the pytest configuration are errors, and an xfail that passes is a
  failure
- **the two jobs that pin one interpreter pin 3.14**, where they pinned
  3.13 — `coverage-py` in `test.yml` and the TestPyPI version-suffix step
  in `release.yml`. 3.14 is what `.python-version` gives a bare `uv run`
  and what the lint and docs jobs therefore already used, so 3.13 was a
  version those two jobs alone singled out — the matrix tests it like
  every other. It matters most for coverage, whose gate is a ratio of a
  statement count that moves between interpreters, 15205 on 3.14 against
  15211 on 3.13: the threshold and the interpreter now agree with what a
  maintainer measures locally with a bare `uv run pytest --cov`. The
  release step only needs a `tomllib`, i.e. 3.11 or newer, and now asks
  for a version uv has already fetched for the other jobs
- the packaging metadata is validated on every pull request rather than
  only on the tag that ships it: twine, check-wheel-contents and pyroma
  moved from the release workflow to a job of the test workflow, which
  the release workflow calls
- a `links` workflow checks the documentation links weekly and on
  demand, and gates nothing: CONTRIBUTING.md carried six
  markdown-link-check-disable/enable comment pairs for a hook that does
  not exist, suppressing a tool that was not running around links that
  were fine, while the ones that had rotted were outside every pair.
  The tools.ietf.org citations now name rfc-editor.org, which is where
  they were redirecting
- a scheduled workflow runs the test suite against the *published*
  btclib_libsecp256k1, resolved from PyPI by the declared pin, where every
  other job follows tool.uv.sources to the bindings under development: what
  it watches for is not a change here but a release there
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
- **Dead code and stale markers.** `WordLists._bits_per_word`, written in two
  places and read in none, is gone; so are seven commented-out leftovers with
  nothing said about why they were kept (alternative `T = multiples(...)`
  lines in `curve_group`, a superseded `zip` in `multi_mult`, a stray
  `bytes_from_octets` in `Psbt.parse`, an unused conversion in
  `entropy.py`, and `# Integer = Union[Octets, int]` in `alias.py`). The
  commented-out code that *is* the explanation around it stays — the biased
  `nonce = int.from_bytes(t, 'big') % ec.n` of the three nonce modules, the
  `PSBT_*_PROPRIETARY` values deliberately not implemented, the
  `_pushdata(4, ...)` the 520-byte limit makes unnecessary. Sixteen
  load-bearing TODO/FIXME markers now name a tracked issue instead of a
  wish: #171 (the three point-addition special cases, on the inner loop of
  every scalar multiplication), #172 (rendering a script as `{"asm":
  ..., "hex": ...}`, seven identical markers), #173 (four unfinished PSBT
  behaviours — combining a witness, the Finalizer's sighash check, output
  merging, and a partial signature never checked against its key)

### Documentation and the website

- **CONTRIBUTING.md warns that `--python` rebuilds `.venv`.** Reproducing
  one cell of the matrix with the documented command — `uv run --locked
  --no-default-groups --group test --python 3.10 pytest` — removes and
  recreates the environment for that interpreter with the test group
  alone, 15 packages where `uv sync` leaves 84. pre-commit's git hook
  `exec`s `.venv/bin/python -mpre_commit` by absolute path, so that
  python exists, its "did you forget to activate your virtualenv"
  fallback never fires, and the next `git commit` dies with `No module
  named pre_commit` — which is a puzzle if the two facts are a hundred
  lines apart, and a footnote if they are not. `uv sync` restores it, and
  `UV_PROJECT_ENVIRONMENT` runs the command without touching `.venv`;
  both spellings are in the file, next to both commands that trigger it.
  Measured: without `--python` the same command prunes nothing, so it is
  the interpreter and not the groups
- **The release notes and the changelog are two files.** This one is the
  changelog, every entry of the release; HISTORY.md is the release notes,
  which say what an upgrader has to act on and point here for why. They
  used to be one file, and a v2026.8 section of 978 lines had made it
  unusable as either: the eleven changes that break a caller were
  indistinguishable from the ninety that do not, and the GitHub release
  notes the tag builds from that section would have been the whole thing.
  The older releases stay in HISTORY.md rather than being copied here,
  having been written at release-notes length in the first place
- the published documentation has an API in it again. Read the docs
  installed the sphinx of docs/requirements.txt and not btclib, so every
  `automodule` directive failed to import its module and rendered as a
  bare heading: btclib.readthedocs.io was 15 module titles with nothing
  under them, silently, a failed import being a warning nobody read.
  `.readthedocs.yaml` now drives uv, which is the only tool that can
  resolve the bindings (pip does not read tool.uv.sources), builds with
  `-W`, and retires docs/requirements.txt — the docs dependency group in
  pyproject.toml is the single declaration and uv.lock pins it, where
  that file was unpinned and kept in step by a header asking a human to
  do it
- `btclib.descriptors` is documented, the one top-level module missing
  from docs/source; `tests/test_docs.py` now compares the modules under
  btclib/ against the directives in docs/source and fails naming
  whichever is missing, in either direction
- `int_from_integer` documents that a `str` argument is read as a
  hex-string whatever it looks like: `int_from_integer("1234")` is 4660,
  and `"9"` raises for being of odd length rather than being nine. The
  behaviour is unchanged and deliberate — a decimal representation is what
  `int` itself is for — and now the docstring says so
- **CI builds the documentation**, which it never did: read the docs did, with
  `-W`, so invalid reStructuredText in a docstring failed after the merge on a
  service whose failure is not a check on the pull request. `lint.yml` gains a
  `Build the documentation` job running the same command `.readthedocs.yaml`
  runs and CONTRIBUTING.md documents. A second job rather than more steps in
  the first, because the branch rule names `Lint and type-check`: a new job
  gates nothing until someone adds it to the rule. It caught a defect the hour
  it was written, in the commit before it — a docstring naming
  `assert_as_valid_`, whose trailing underscore rst reads as a link reference.
  No hook can take this over: markdownlint does not read `.rst`, and ruff's
  pydocstyle rules check the form of a docstring rather than whether its body
  parses (issue #151)
- **btclib.org**, which GitHub Pages serves from this repository's `master`
  root, is now documented as such — CONTRIBUTING.md has a "The website"
  section naming the files that are website sources, and `_config.yml` says
  it too. Three defects came with the documenting. The page template asked
  for `/%20/assets/js/scale.fix.js` and got a 404, because a space inserted
  inside a Liquid string reached `relative_url`; the same space made the
  site serve `<html lang=" en-US">`; and `<img img height="80">` repeated the
  tag name as an attribute. `_config.yml` also gained the `exclude:` list it
  never had, so the root of the repository is no longer published wholesale:
  `btclib.org/TODO` was a live page carrying the open questions of
  `TODO.md`, and the site served the library itself —
  `btclib.org/pyproject.toml` and `btclib.org/btclib/alias.py` both answered
  with their own contents. The site footer credits the organization that
  owns the repository, the PyPI project and every URL in `pyproject.toml`,
  where it named a personal account. And `test.yml`'s `push` trigger carries
  a `paths-ignore` for the website files, so a website-only commit to
  `master` no longer runs the whole matrix (issue #160)
- **tests/README.md's "no `slow` marker" section is a measurement again.**
  Its numbers were taken when the suite was 7936 tests and it is 12449 now:
  21.9 s across the cores against the 10.6 it claimed, 85.3 s on one against
  21, and the slowest single test is a `tapscript-bigmulti` vector at 5 s
  rather than `test_low_cardinality` at 1.4. The conclusion moved with them.
  Bitcoin Core's vector files are still not the slow part — 7709 of those
  tests in 4.4 s — but `tests/script_engine/test_python_path.py` is: it holds
  the slowest six tests in the suite and half the wall clock, 4169 tests that
  `--ignore` takes out to leave 8280 running in 10.4 s. So a `slow` marker
  would now save something real, where the section said there was nothing to
  put behind one; none is registered still, and the reason is stated in
  today's numbers rather than in numbers that stopped being true
