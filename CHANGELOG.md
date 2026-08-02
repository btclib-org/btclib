# Changelog

Every change of a release, in full: what changed, why, and what it cost.
[HISTORY.md](./HISTORY.md) has the release notes, which say what a user has
to act on; this file is the record behind them, and is where a claim in
those notes can be checked.

Only v2026.8 is here. The releases before it were documented at
release-notes length in the first place, and are still in
[HISTORY.md](./HISTORY.md) rather than duplicated here.

## v2026.8 (work in progress, not released yet)

Grouped, and the order runs from what breaks a caller to what only
maintainers see; [HISTORY.md](./HISTORY.md) lists the source-breaking
changes on their own. Neither file counts its entries: `grep -c '^- '`
does that, whereas a stated number is a line every open branch has to
edit.

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
- **This file and HISTORY.md state no entry count, and `.gitattributes` marks
  both `merge=union`.** They are append-only lists that every branch appends
  to, so they were the one thing every pull request had to resolve by hand: a
  count is a line all of them edit, and the insertion point is shared by any
  two that add a bullet to the same group. `union` keeps both sides' added
  lines, so neither is a conflict any more. `grep -c '^- ' CHANGELOG.md`
  answers how many entries there are, on demand.

### Security

- **a sign-to-contract commitment reaches the nonce derivation, and not
  only the nonce.** `sign_to_contract` tweaked the nonce with the
  commitment and derived that nonce from the message and the key alone,
  as RFC6979 does when nothing is committed. Two signatures over one
  message under one key then shared their untweaked nonce, so the nonces
  actually used differed by `e2-e1` — a value the openings make public,
  the openings being what a commitment is *for*. Two ECDSA signatures
  over one message with a known nonce difference are two equations in
  the two unknowns `k` and the private key, and it is solved with a
  division: signing a message plainly and then committing to something
  over the same message handed the key to anyone holding both. The
  library's own `dsa.sign` was the first of those two signatures, since
  it derives the same RFC6979 nonce. libsecp256k1's `ecdsa_s2c` module
  states the attack where it refuses a custom nonce function — "an
  attacker can exfiltrate the secret key by signing the same message
  thrice with different commitments" — and two suffice. The committed
  value now enters the derivation as well: through RFC6979's section 3.6
  additional data for `dsa`, and through BIP340's auxiliary randomness
  for `ssa`, whose `aux` is hashed together with it so that both still
  count. A caller-supplied nonce is refused beside a commitment, because
  a nonce is the derivation's answer and leaves nowhere to put the
  commitment; `ssa` keeps taking its `aux`, which is an input to the
  derivation and not its answer. What the tests pin is the property
  itself, distinct receipts, the receipt being the untweaked nonce's
  point (issue #193)
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
- **the Jacobian group law does not shortcut the point at infinity**, so
  a scalar multiplication takes the same time whatever the bits of the
  scalar. `add_jac` returned early when an operand was infinity, and
  infinity is not an exotic input there: it is the identity, so every
  double-and-add starts its accumulator at it and the windowed ones hold
  it in the table of multiples as `0*Q`, which a zero digit indexes. Over
  2000 random secp256k1 scalars `_mult` reached it 3.98 times on average
  and only 23 of them never, and the count is not incidental to the
  secret — it *is* the number of zero base-16 digits of the scalar, and
  for `mult_jac` the number of its low zero bits. On the clock: `P +
  INFJ` answered in 0.03 us against the 3.7 us of a generic addition,
  `_mult` measured 0.93 ms on a scalar with no zero digit and 0.55 ms on
  one with 63, and `mult_jac` 1.56 ms on a random scalar against 0.79 ms
  on one whose low 192 bits are zero. Infinity now reaches neither a
  branch nor the arithmetic: a full-size stand-in takes its place and a
  four-entry table answers for it, because a Python integer costs what
  its size costs and the zero coordinates would time the case as well as
  the branch did — with the early returns gone but no stand-ins, `P +
  INFJ` still cost 1.8 us against 5.4. An addition with an infinity in it
  now measures within 1.4% of one without, and `mult_jac` 1.58 ms
  whichever scalar it is given, for 1.02x to 1.03x on every
  multiplication in the package and 1.22x on `_double_mult`, whose
  Shamir-Strauss loop adds infinity for a quarter of its digit pairs.
  What still branches is the other kind of special case, two points that
  coincide or are opposite: that one is geometry rather than
  bookkeeping, and reaching it inside a multiplication needs the
  accumulator to land on a table entry — 2^-250 on a curve with a real
  order, where the toy curves of the test suite take it constantly and
  keep it covered. What is left is out of reach from pure Python, and
  `SECURITY.md` now lists it: the loop runs once per bit, so a scalar's
  size is not hidden; the windowed variants index their table with a
  secret digit; Python arithmetic costs what its operand sizes cost; the
  affine law, `aff_from_jac` and the wNAF recoding each spend something
  whose iteration count is its input; and the wNAF loops skip the
  addition of a zero digit outright, which is the next thing to fix
  (issue #254)

### Consensus rules

- **A block carries one coinbase, and `Block.assert_valid` now says so.**
  It asked whether the first transaction is a coinbase and never asked
  the rest, where Bitcoin Core's `CheckBlock` asks both, the second as
  `bad-cb-multiple`. The answer is `more than one coinbase`, raised
  before the transaction is validated on its own terms: a second
  coinbase is a second claim on the subsidy, so what is wrong is the
  shape of the block rather than anything about that transaction. No
  vector can state the rule — the proof-of-work is checked first, and
  adding a coinbase to a real block moves the merkle root its header
  commits to, so a well-formed block with valid work and two coinbases
  cannot be built. That is the argument for the rule rather than
  against it: what has no work yet is a block being *assembled*, and a
  candidate-block path is exactly where nothing else refuses the shape
  (issue #250)
- **a hash equal to the target is a valid proof-of-work.**
  `BlockHeader.assert_valid_pow` rejected on `hash >= target`, where
  Core's `CheckProofOfWork` rejects on `hash > bnTarget`: the target is a
  bound the hash may reach, so the one hash that lands on it solved the
  block for every node on the network and for btclib alone did not. The
  error message says `>` rather than `>=` for the same reason. No vector
  can exhibit it — equality asks a 256-bit hash for one exact value, and
  the compact form cannot be nudged to meet a given hash either, its
  significand holding three bytes — which is precisely why the comparison
  has to be read off Core rather than tested against it
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
- **The script code a signature commits to is a slice of the script's own
  bytes**, where it was a re-serialization of part of a parse. The two
  differ wherever a push is not written minimally, `4c0105ac` coming back
  as `0105ac` — legal, a different script, and what `Script.assert_valid`
  already declines to round-trip for exactly this reason — so a legacy
  input whose script carried one was signed against a preimage no other
  implementation computes, with no OP_CODESEPARATOR needed anywhere. Three
  deviations, one cause. `legacy_script` and `witness_v0_script` built the
  script code by parsing, slicing the token list and serializing it back.
  The engine measured *where* to cut by serializing the op codes before the
  cut and taking their length, so a non-minimal push ahead of an executed
  OP_CODESEPARATOR moved the cut: `4c0105abac` gave the segwit v0 script
  code `abac` where Core gives `ac`, the separator byte itself left in.
  And FindAndDelete was a `bytes.replace` loop, which deletes a signature
  lying inside the *data* of a push — Core tests for a match only where its
  GetOp has arrived — and, re-run until nothing matches, deletes copies
  that exist only because an earlier deletion joined their halves. A
  34-byte push carrying a 33-byte signature push made btclib refuse a
  transaction Core accepts: the deletion left a length claiming bytes that
  were no longer there, and the script code stopped parsing.
  Core's pieces now, in Core's places. Truncation is a byte offset, its
  `pbegincodehash`, which the interpreter advances as it *executes* an
  OP_CODESEPARATOR; eliding the separators left after it belongs to the
  legacy serializer, `SerializeScriptCode`, so `sig_hash.legacy` does it
  and `segwit_v0` does not, BIP-143 keeping them; and FindAndDelete stays
  in the engine, Core having it in
  `interpreter.cpp` alone and never in `sign.cpp`, there being no signature
  to delete while signing. The walk all three need is `script.read_op_code`,
  Core's `GetOp` (issue #176)
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
- **a conditional closed before it was opened made a script verifiable**,
  where Core refuses it: `OP_ENDIF OP_1 OP_IF OP_1` verified. Core has the
  rule as two SCRIPT_ERR_UNBALANCED_CONDITIONAL checks — `vfExec.empty()`
  inside OP_ELSE and OP_ENDIF, `!vfExec.empty()` once the loop is over —
  and both engines had them replaced by one pass counting OP_IF, OP_NOTIF
  and OP_ENDIF over the parsed script. That sum is only the depth the
  script *ends* at, so it cannot see an OP_ENDIF arriving first, which
  popped the condition stack's sentinel and left `all([])` true: the rest
  of the script then ran as if the branch had been shut. The count is gone
  and both of Core's checks are in, in the positions Core has them. It was
  sound in the other direction — a nonzero sum is a script Core rejects
  too — so nothing spendable was being refused, and `check_balanced_if` is
  now the second of the two checks rather than the pass, in
  `script.engine.script_op_codes` beside the OP_IF it is about
- **OP_CHECKMULTISIG accepted a negative number of keys or signatures**:
  `OP_0 OP_1NEGATE OP_1NEGATE OP_CHECKMULTISIG` pushed false and let the
  script carry on, so an OP_NOT after it verified an input Core ends with
  SCRIPT_ERR_PUBKEY_COUNT. Core bounds each count on both sides —
  `nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG` and
  `nSigsCount < 0 || nSigsCount > nKeysCount` — where btclib checked the
  upper bounds alone, and a negative count passes those: `range(-1)` is
  empty, so nothing was popped, nothing underflowed, and -1 keys also
  *credited* the 201 op-code budget by one. Both bounds are checked now,
  and each before anything is popped with it, which is Core's order and
  what makes the counts safe to build a `range` out of
- **OP_IFDUP duplicated a false element that was not empty**, which cost a
  spend rather than allowing one: `<00> OP_IFDUP` left two elements where
  Core leaves one, and every op code after it read a stack an element
  deeper, so btclib refused scripts Core accepts. Core's test is
  `CastToBool`, under which a one-byte zero and a negative zero are both
  false; btclib's was `!= b""`. It is `CastToBool`'s equivalent now, the
  `_to_bool` the rest of both engines already used for exactly this. No
  vector in either vendored set feeds OP_IFDUP a non-empty false element,
  which is the whole reason the suite was green
- **LOW_S and STRICTENC ask for strict DER too, not DERSIG alone.** Core's
  CheckSignatureEncoding gates IsValidSignatureEncoding on `flags &
  (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)`,
  one mask, and `fix_signature` gated it on DERSIG and then *disabled* it
  for STRICTENC: a non-canonical encoding was normalized and accepted
  under STRICTENC alone, under LOW_S alone, and under the two together.
  Three of Core's own vectors, rerun with those flags, verified where Core
  answers SCRIPT_ERR_SIG_DER. A high s is an error under LOW_S now instead
  of a signature that fails to verify, which is Core's
  SCRIPT_ERR_SIG_HIGH_S and matters because `CPubKey::Verify` normalizes s
  before verifying: leaving it to the bindings, which refuse it, reported
  a failed check where Core reports a passing one. Consensus is untouched,
  LOW_S and STRICTENC being standardness rules that ALL_FLAGS leaves off,
  and no vector could have caught either — script_tests.json names
  STRICTENC and DERSIG together in none of its cases
- **CONST_SCRIPTCODE watches all four signature-check op codes.** The
  engine refuses a signature check carried in the script_sig up front
  and as a class, its script code being the script_sig itself: the
  in-loop rule closes nothing else, `op_checksig` returning early on an
  empty signature and on two malformed ones before it builds a script
  code to delete from, where Core deletes and errors before reading the
  signature at all. The list behind that refusal named
  OP_CHECKSIGVERIFY twice and OP_CHECKMULTISIGVERIFY never, and no
  vector could say so: the tx_invalid cases put only OP_CHECKSIG in a
  script_sig under the flag. All four names now, each pinned by a test.
  Consensus is untouched, CONST_SCRIPTCODE being a policy flag
  ALL_FLAGS leaves off
- **A v0 script carrying OP_CODESEPARATOR is verified now.** Since the
  interpreter landed (#83), `verify_input` answered such a spend
  without running it — an early return, no reason recorded — while the
  legacy loop it delegates to has carried BIP143's codeseparator
  semantics all along: the script code is cut at the last *executed*
  separator, by an op-code index kept correct across the \*VERIFY
  stream rebuilds. The guard is gone, and the three BIP143 worked
  examples in tx_valid that carry a separator — executed, unexecuted,
  and beside an out-of-range SIGHASH_SINGLE — verify for real where
  they used to pass unexamined, through both signature backends. An
  invalid spend of that shape was accepted, and is refused now: no
  vector is one, all three of those being valid spends, so the p2wsh
  script whose OP_CHECKSIG cannot succeed is a test. The guard cut the
  other way as well, and that verdict moves too:
  it parsed *every* v0 witness script strictly, so an op-code byte no
  table names made the spend invalid wherever it sat, and it is now the
  interpreter that answers — unknown op codes refused when executed,
  skipped inside a branch nothing takes, which is what Core does and
  what the legacy engine already did everywhere else
- **CLEANSTACK means on a witness spend what it means in Core: nothing.**
  Core resizes the stack to one element after VerifyWitnessProgram, so
  the flag — policy, off in ALL_FLAGS — can only fail a pre-segwit
  script; the clean-stack rules that are consensus live inside the
  witness execution itself, BIP141's one-element rule in the v0 arm —
  where Core's sits, in ExecuteWitnessScript — and tapscript's in
  `verify_script_path_vc0`. btclib's reading was stricter: with the
  flag on, the leftover stack of an OP_SUCCESS spend and the untouched
  stack of a v1 program that is not 32 bytes were both refused,
  refusals Core never issues — the upgrade path is a success whatever
  the stack holds, and what refuses an upgradable program in Core is
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM. The witness arms hand no stack
  back at all now, and the two tests that pinned the stricter reading
  pin this one
- **DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM reaches every program Core
  aims it at**, the witness dispatch being Core's chain of arms now: v0
  of a defined size, the non-p2sh 32-byte v1, pay-to-anchor, and one
  `else` for everything after them. What the flag refused before was
  "a version higher than the flags enable", which is the same set only
  while TAPROOT is off: with it on, a v1 program that is not 32 bytes
  and a 32-byte v1 wrapped in p2sh reached no refusal at all, though to
  a node that does not know better all three are the same thing —
  valid, which is what makes them upgrade room. Standing beside them
  and *not* refused is pay-to-anchor, `OP_1 0x4e73`, standard and
  relayed since Core 28 and exempt there: the flag answers "would a
  node relay this", so an arm of its own here too.
  The other half of the rule came with the shape: a program of a
  *defined* shape spent by a caller not enforcing that BIP is the
  anyone-can-spend its script_pub_key makes it, so a taproot output
  without TAPROOT is Core's plain success and not a discouragement, and
  a witness program without WITNESS is not verified at all — where
  btclib used to run the v0 arm whenever TAPROOT alone was set, and to
  raise BIP141's two malleability rules whatever the flags said. Those
  now sit behind WITNESS as well, Core keeping them inside it. The
  refusal is spelled "upgradable witness program: version N" rather
  than "unsupported segwit version: N", the branch no longer being
  about the version alone. Two vendored vectors reach it, both with
  TAPROOT off; the shapes they miss are a test. No consensus verdict
  moves: every flag named here is outside ALL_FLAGS, save WITNESS and
  TAPROOT, which move nothing when both are on

### Malformed input and the exception contract

- **an empty witness element no longer reaches a caller as `IndexError`.**
  BIP-341 makes the last witness element the annex "if its first byte is
  0x50", and both readers of that rule tested it with `stack[-1][0]` — an
  empty element is legal on the wire and has no first byte, so
  `sig_hash.from_tx` answered a caller who catches `BTClibValueError`
  with a bare `IndexError`, on a 186-byte transaction `Tx.parse` accepts.
  Reachable from the network, and reachable through the public API: the
  spend is Bitcoin Core's own `spendpath/truncshortcontrol` vector, whose
  control block is truncated to nothing. Both sites take a slice now,
  which is also what the BIP says, and the leaf-version byte read just
  past the annex — `sig_hash` alone, the engine validating the control
  block first — raises `BTClibValueError("empty taproot control block")`
  rather than inventing the 33-byte minimum that is the engine's to
  enforce. What let it sit there was the test: `test_invalid_taproot`
  named `IndexError` in its `pytest.raises` tuple and counted the crash
  as the refusal it was asking for, which is the failure
  `script_test.py` narrowed its own tuple to stop. All three wide tuples
  are now the contract and nothing more, `test_invalid_legacy`'s included
  — measured, all 93 of its vectors leave through `BTClibValueError` — and
  `test_invalid_taproot_key_path` no longer lists `AssertionError`
  alongside a leading `assert` inside the block, which would have passed a
  vector without computing a sighash at all
- **`tests/fuzz_test.py` reaches past the parsers.** It held 24 binary
  parse entry points and the text ones to the exception contract, and
  stopped where the bytes became an object: the code that *reads* a Tx
  that parsed cleanly was not in it, which is why a fuzzer had not found
  the annex hole above. `sig_hash.from_tx`, `engine.verify_input` and
  `engine.verify_transaction` now take a hypothesis-generated witness
  stack on a fixed p2tr spend — empty elements included, that being the
  point. Reverted against the old code the new test fails, shrunk to
  `stack=[b'', b'']`
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
  `pow(256, -1)` is a float in Python, so an exponent below 3 used to send
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
  because `strict` is Python 3.10
- an empty P2WSH witness stack raises BTClibValueError("empty p2wsh witness
  stack") rather than an `IndexError` out of `stack[-1]`, the witness script
  being the last element of a stack that has none. Core calls it
  WITNESS_PROGRAM_WITNESS_EMPTY and the taproot branch beside it already had
  the guard. The vector that exercises it, `P2WSH with empty witness`, was
  green throughout: `pytest.raises(Exception)` counts an IndexError as the
  refusal it was waiting for. In the script engine, and in
  `sig_hash.from_tx`, which reads the witness script the same way and had
  the same hole — no vector reaches it there, a sig_hash being asked for
  rather than verified (issue #182)
- `Psbt.assert_valid` requires the outpoint to name an output the
  non-witness utxo has: `outpoint vout out of range for the non-witness
  utxo`, where the index was an `IndexError` out of every reader of the
  spent output — `assert_signable`, through `_signable_payload`, and the
  sig_hash the Finalizer now verifies against. The tx_id check beside it
  does not answer this: a psbt can carry the right transaction and name
  an output it has not got (issue #173)

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
  Python RIPEMD-160 (`btclib._ripemd160`, vendored from Bitcoin Core),
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
- **A second spell checker, and six more typos.** The identifier split the
  entry above did by hand is a hook now: `typos` splits hyphens, snake_case
  and camelCase where codespell matches whole words, and the two
  dictionaries differ as well, so neither subsumes the other and both run.
  Six misspellings survived the first hook and not the second — the README
  offered the `bitcon` elliptic curve, `amount` documented a `threshould`,
  `to_prv_key` an integer as a hex-`strin`, `curve_group` and HISTORY.md a
  `y-simmetry` tiebreaker, and `psbt_utils` read its leaf hashes into
  `leafs`. It corrects in place, which makes one thing a convention rather
  than a preference: a misspelling written on purpose, as this entry writes
  five, goes in backticks
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

- **`add_jac` no longer reads the point at infinity as a doubling**
  (issue #171). Its doubling test compares affine coordinates, and a
  Jacobian `Z == 0` leaves `X` and `Y` free to be anything: `INFJ` is
  `(7, 0, 0)` and `jac_from_aff(INF)` is `(5, 0, 0)`, x-coordinates picked
  for being invalid rather than for being zero, so on a curve of
  characteristic 7 or 5 they reduce to zero, the test read "same x, same
  y" and doubled. `P + INFJ` answered `2*P`, and with it eight of the ten
  scalar multiplications this package offers were wrong for most scalars
  on every `p == 7` curve — 6 of 13 scalars for `mult_jac`, 12 of 13 for
  the Montgomery ladder and for `mult_recursive_jac`, and 100 of the 169
  coefficient pairs for `_double_mult`, which `curves.double_mult`, `dsa`
  and `ssa` verification all reach. The all-zero triple, which
  `jac_equality` reads as infinity too, did it on every curve, secp256k1
  included. Infinity is read before the two coordinates that cannot hold
  it now, and answered from a table rather than from a branch, for the
  timing reason `Security` gives above. The tests gained every pair of points of
  every low-cardinality curve — the whole group, in two Jacobian frames
  and three infinity spellings, against a textbook group law written the
  other way round — and every multiplication of a `p == 7` curve
- **BIP39 normalizes NFKD, and every mnemonic path reads whitespace the
  same way** (issue #201). `bip39.seed_from_mnemonic` collapsed the
  whitespace of the sentence and normalized nothing, where BIP39 asks for
  the opposite: "a mnemonic sentence (in UTF-8 NFKD) used as the password
  and the string `mnemonic` + passphrase (again in UTF-8 NFKD) used as
  the salt". All twenty-four of BIP39's own Japanese vectors were wrong
  seeds, measured, and every English one passed throughout — `TREZOR` and
  `english.txt` are ASCII, which is NFKD already, so nothing in the suite
  could see it. The two are now both done, in the order the spec implies:
  the new `mnemonic.normalize_mnemonic` decomposes and *then* treats any
  run of unicode whitespace as one separator, so `abandon  abandon` and
  `abandon abandon` reach one seed, a mnemonic typed in fullwidth latin
  is read rather than refused, and U+3000 — the ideographic space those
  Japanese vectors separate words with — is a separator because NFKD says
  so and not because btclib says so. The passphrase is decomposed and
  otherwise untouched: its whitespace is content the user chose, so
  collapsing a doubled space there would open another wallet. Refusing
  anything but a single space is the other defensible answer and is what
  trezor's `python-mnemonic` reads, but only where it *checks* a
  mnemonic — its `to_seed` normalizes and stops, so a trailing newline
  there stretches into a different seed in silence, which is the one
  outcome worse than a refusal. `electrum.py` already collapsed
  whitespace and keeps its own stronger normalization, which cannot be
  shared: it drops the combining characters, undoing the very
  decomposition BIP39 requires
- **`btclib.mnemonic.electrum` is Electrum's scheme, both directions**
  (issue #196). The module named the scheme and implemented five things
  differently, and the worst of them was silent: the same entropy gave
  btclib and Electrum *different* mnemonics, each passing the other's
  version check, so a user who generated with one and restored with the
  other got another wallet without an error anywhere. Measured against
  `spesmilo/electrum` at master — `mnemonic.py`, `old_mnemonic.py`,
  `version.py` and the wordlists — and now equal to it on 510 cases:
  Electrum's whole published `calc_seed_type` table, its ten seed
  vectors, and 420 generations from entropies of 120 to 133 bits.
  Generating: the words run **least-significant first**, Electrum's
  order, where they ran BIP39's — the same words the other way round, so
  `entropy_from_mnemonic` returns a different integer too. The search
  starts at `entropy + 1`, never at the entropy itself, and skips a
  candidate that is a pre-2.0 Electrum seed or that is **also a valid
  BIP39 mnemonic**: one 12-word sentence in sixteen has a valid BIP39
  checksum by chance, so that skip alone moved one generated mnemonic in
  sixteen. It closes as Electrum closes, by asking what it would read
  the sentence back as, which is how a `"2fa"` request for 13 words'
  worth of entropy now fails instead of returning a sentence Electrum
  reads as nothing. With no entropy supplied the draw is **132 bits**
  redrawn below 2^121 — twelve words always, and the leading one
  uniformly distributed — where `secrets.randbits(128)` let the word
  count follow the bit length. Reading: a mnemonic is **normalized**
  before it is hashed and before it is stretched — NFKD, lower-case,
  accents dropped, whitespace collapsed, whitespace between CJK
  characters removed — where btclib only collapsed whitespace, so an
  upper-cased seed, an accented Spanish one and a Japanese one were all
  refused with "unknown electrum mnemonic version", measured, each of
  them a seed Electrum reads and derives a wallet from; the passphrase is
  normalized too, as Electrum normalizes it. And the
  **pre-2.0 scheme is recognized**: `version_from_mnemonic` answers
  `"old"` for a 12- or 24-word seed from Electrum's 1626-word list or
  for a 16- or 32-byte hex string, tested before the four prefixes
  because an old seed can match one by chance and be handed back as
  `"standard"` — the wrong derivation, in silence. Deriving from an old
  seed is not implemented (#208); it is refused by name. The old
  wordlist is vendored as `btclib/mnemonic/_data/electrum_old_english.txt`
  (`electrum/old_mnemonic.py`, MIT, "Copyright (C) 2011
  thomasv@gitorious"), and is not a `WORDLISTS` language: 1626 is not a
  power of two, an index into it not being a whole number of bits.
  Two things left alone on purpose. `entropy.py`'s index helpers still
  end in `list(reversed(indexes))`, which is right for `bip39.py` and
  what its vectors prove, so the reversal is `electrum.py`'s; and the
  weakness of Electrum's own old-seed test is copied rather than improved
  on, its comment saying it is deliberate (spesmilo/electrum#3149) — a
  stricter test here would accept a seed Electrum refuses, which is the
  divergence being closed. `test_electrum.py`'s round trip asserted
  `entr - entropy < 0xFFF`, pinning a loose relation rather than
  Electrum's answer; it is Electrum's vectors now, inline with the
  citation above each block, plus the two no upstream has — an old-seed
  collision and a BIP39 collision, each found by search because at one in
  thirty thousand and one in sixteen neither is reachable by generating
  and waiting
- **`mult_endomorphism_secp256k1` answers correctly, and is now the
  fastest Python multiplication in the package** (issue #215). Its
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
  the bindings. The Python implementation is not going anywhere: it
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
  Python path, twelve times slower and silent about it, and
  `to_prv_key`/`to_pub_key` raised "curve mismatch" between two objects
  describing the same curve. The eight curves shared by the two
  catalogues are now one object each, and the five hand-written dispatch
  predicates are one `_libsecp256k1_applicable(ec, hf)`. `hf` is still
  compared by identity, deliberately: nothing short of running them tells
  sha256 from a look-alike, so a wrapper such as
  `functools.partial(sha256)` keeps taking the Python path — slower, never
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
  libsecp256k1 as before, anything else takes the Python path — the pattern
  already in place for a caller-supplied nonce and for every other curve, and
  now the only path that can verify four of BIP340's own vectors. Two tests
  changed with it, both for the better: truncating a message by one byte is no
  longer `invalid size: 31 bytes instead of 32` but a *different message*,
  which the signature does not sign (issue #169)
- **`btclib.ecc.ecies` encrypts to a public key, with the block cipher
  supplied by the caller** (issue #210). BIE1 is the ECIES the bitcoin
  world converged on — Electrum's `encrypt` and `decrypt` commands,
  bitcore, bitcoinjs — and it is the end `dh.py` was missing: that module
  derived a shared secret and stopped there, with nothing in the library
  using it to encrypt anything. `encrypt` and `decrypt` take a pair of
  callables, `f(key, iv, data)`, and do everything on either side of them:
  the ephemeral key pair, the ECDH, the sha512 of the compressed shared
  point split `iv | key_e | key_m`, the `b"BIE1" + ephemeral pub key +
  ciphertext` framing, the HMAC-SHA256 over it, and the base64 armor.
  AES-128-CBC with PKCS#7 is the caller's to bring, which is the answer to
  the question the issue asked before the code was written: btclib's whole
  install story is "Python plus the bindings", AES is not in the standard
  library, and a pure-Python one shipped here would be a timing-vulnerable
  block cipher — a worse thing to ship than no block cipher at all. The
  layers that need no cipher stand on their own and are tested without
  one: `derive_keys` is the ECDH and the sha512 split, and `Envelope`
  parses, validates, MAC-checks and re-serializes a message it cannot
  read. Nothing is parameterized by curve or hash function, unlike the
  rest of `btclib.ecc`, because interoperability is the only reason the
  scheme exists and every implementation of it is secp256k1. BIE1 has no
  specification either — its definition is Electrum's `crypto.py` — so the
  tests decrypt three real ciphertexts from Electrum's own suite and
  rebuild all three armors byte for byte, under an AES-128 that lives in
  the test file and is shipped to nobody
- **MuSig2, one primitive per round** (issue #190). `btclib.ecc.musig2`
  implements BIP327: many signers aggregate into one X-only key and their
  partial signatures into one BIP340 signature, which `ssa.verify_` accepts as
  it accepts any other — a verifier, and the chain, see a single-key Schnorr
  signature. Key sorting and aggregation with plain and x-only tweaking
  (`key_sort`, `key_agg`, `apply_tweak`, `key_agg_and_tweak`, answering a
  `KeyAggContext` that carries the accumulated negation and tweak), the nonce
  pair (`nonce_gen`, and `nonce_gen_` taking the randomness as an argument),
  nonce aggregation, the `SessionContext` and the values every party derives
  from it, partial signing (`sign`, and `deterministic_sign` for a signer with
  no entropy source), `partial_sig_verify` to hold one signer to what it sent,
  and `partial_sig_agg`. Primitives rather than a function that signs, which
  is what "interactive" in the issue means: the signers exchange nonces and
  then partial signatures, and each exchange is somebody else's network. All
  56 cases of BIP327's eight vector files pass, the error half included — an
  error case names which party contributed what, which is why an invalid
  contribution raises `InvalidContributionError` carrying the signer index and
  the field, a `BTClibRuntimeError` and deliberately not a `BTClibValueError`:
  the caller's own bad argument and a peer's misbehaviour are what the
  specification separates, and one base for both would put them beyond telling
  apart by `except`. secp256k1 and sha256 are not parameters, unlike elsewhere
  in `btclib.ecc`: BIP327 defines its tags and its serializations for that
  pair alone, so a `Curve` argument would advertise a genericity no vector
  could check. The message is of any size, which is what made #169 the
  precondition — two of BIP327's own vectors are an empty message and a
  38-byte one, and both take btclib's Python path. `sign` zeroes the secnonce
  bytearray it is given, because two signatures under one secret nonce hand
  out the private key. Threshold signing, the neighbouring half of #190, is
  not implemented and the issue stays open for it
- **the ECDSA Anti-Exfil Protocol**, which sign-to-contract is the
  primitive for. A signing device that picks its own nonce can leak the
  private key through the nonces themselves, a few bits per signature,
  and nothing in the signature says that it did; the protocol takes the
  choice away by having the host contribute randomness `rho` to the nonce
  derivation. That only holds if the device publishes the nonce's point
  `R` *before* it learns `rho` — otherwise it grinds `rho` against
  candidate nonces until one carries the bits it wants out — so
  `dsa.sign(msg, prv_key, commit=rho)`, which hands the device everything
  at once, is step 4 alone and cannot enforce the ordering step 2 exists
  for. The four functions that express the whole handshake are
  `dsa.anti_exfil_host_commit`, `dsa.anti_exfil_signer_commit`,
  `dsa.anti_exfil_sign` and `dsa.anti_exfil_host_verify`, one per step,
  and the second of them is the shape the API did not have: a nonce's
  point derived and published without signing anything. What lets the two
  ends meet was already in place — `commit_entropy_` hashes the committed
  value before it enters the derivation, so the nonce is reachable
  knowing only a hash of `rho`, and libsecp256k1 states the purpose in as
  many words: "it should be possible to derive nonces even if only a
  SHA256 commitment to the data is known. This is important in the ECDSA
  anti-exfil protocol". `anti_exfil_sign` drops the receipt instead of
  returning it, as libsecp256k1's does: the host holds that point from
  step 2, and taking the device's word for it after `rho` was revealed is
  the one thing the ordering rules out. Two obligations land on the
  caller and are written into the docstrings — restarting takes
  **exactly** the same `rho`, with the host checking that the device
  answers with exactly the same `R`, because selective aborting biases
  the nonces that reach real signatures; and the device keeps no state
  between step 2 and step 4, re-deriving the commitment from whatever
  `rho` arrives, so a mismatch costs a failed verification and never a
  reused nonce. Both of libsecp256k1-zkp's `expected_s2c_exfil_opening`
  vectors reproduce, and its `expected_s2c_opening` column is checked
  beside them as the `R` of step 2 under `anti_exfil_host_commit`: the
  two columns are one host commitment apart, which is upstream's own
  bytes saying that step 2 and step 4 reach one nonce. There is no
  schnorr counterpart upstream to extend this to (issue #222)

### Script

- **A witness program of version 2 or higher has an address, and btclib
  now renders it.** `type_and_payload` named five script types, none of
  which a v2..v16 program is, so `ScriptPubKey.type` answered
  `"unknown"` and `.address` the empty string — for a script built from
  a valid bech32m address btclib itself writes and reads. The round trip
  was broken in the middle, and broken with a value indistinguishable
  from "this script has no address", which is the right answer for a
  nulldata output and the wrong one here. The sixth answer is
  `"witness_unknown"`, Bitcoin Core's own name for the type
  (`TxoutType::WITNESS_UNKNOWN`), and `.address` is the bech32m one:
  `EncodeDestination` renders these too, its `WitnessUnknown` case. The
  line is Core's `Solver`'s — any version but 0 that is not p2tr,
  including a v1 program that is not 32 bytes; a *version 0* program of
  an unexpected length stays `"unknown"`, NONSTANDARD to Core, v0 having
  no upgrade room left for a spend to be defined in. The payload is the
  witness program, as it is for the three named witness types, and the
  version is not implied by the answer — it is the op code the program
  follows, which is where `address` reads it. Nothing changes for the
  script engine, which dispatches on the version and reaches the same
  upgrade-room arm it always did (issue #251)
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
- **A script no one can spend still decodes** (issue #123). Five
  transactions in blocks 251718 to 299571 carry a `scriptPubKey` btclib
  refused: two push more than 520 bytes, ten declare a push longer than
  the bytes that follow it. `Script`, `ScriptPubKey` and `.asm` raised
  `Invalid pushdata length` or `Not enough data for pushdata` on all
  twelve, where Bitcoin Core reads every one of them. The rule is now
  Core's — a script Core accepts is accepted here, and a script Core
  cannot execute fails here the way Core fails it, by being executed —
  so `parse` keeps the one refusal a decode has: a push running past the
  end of the script stops the walk and appends `"[error]"`, the literal
  Core's `ScriptToAsmStr` writes in the same place. The 520-byte limit is
  a bound on the stack, so it moved into the two interpreters, which
  refuse an oversized push and a truncated one where Core does, before
  the test for whether the branch executes. Twelve on-chain scripts are
  vendored as vectors
- **`Script.assert_valid` asks whether the script is bytes**, which is
  all a script is: Core has no validity notion for a `CScript` either,
  and no predicate on the bytes alone could have one — in tapscript an
  `OP_SUCCESSx` makes a script valid however malformed the rest of it is.
  It was a parse, and before that `serialize(self.asm)` with the result
  discarded, which looks like a round-trip check and is not one. A
  round-trip check would be wrong rather than merely absent: a
  non-minimal push is consensus-legal and does not survive one —
  `4c01ff`, an OP_PUSHDATA1 of a single byte, comes back as `01ff`, and
  over 200k random byte strings a strict comparison rejects 16
- **`serialize` writes all four push widths.** Above 65535 bytes it
  emits OP_PUSHDATA4, where it used to raise `too many bytes for
  OP_PUSHDATA`, because what `parse` reads it has to write back: the
  1443-byte push of issue #123 is a script nobody can spend, not one
  that cannot be encoded. The minimal-push rule is unchanged, and what
  is left to refuse is a length no length field can carry, which is
  Core's own bound. Two of Core's own `script_tests.json` vectors were
  passing for the wrong reason until this landed — "520 byte push" and
  the same in a branch nothing takes, which `serialize` refused to build,
  so the harness raised before any engine ran
- **`script.engine.validate_redeem_script` is `validate_push_only`, and
  walks the script_sig bytes** where it scanned parsed commands (issue
  #220). The rule is Core's `CScript::IsPushOnly`, a comparison of each
  op code against OP_16, and a scan of the command *names* cannot be
  that comparison: it answered 70 of the 256 bytes wrongly, in both
  directions. The 69 above OP_16 that no op-code table names parse as
  `UNKNOWN_OP_CODE_n`, which carries no `OP_` prefix to refuse, so they
  passed as pushes; `OP_RESERVED` carries one where 0x50 is *below*
  OP_16, so it was refused as an operator. No spend changed hands over
  either — the interpreter refuses every unnamed byte the moment it
  executes one, and putting one where it does not execute takes a
  conditional, which is named — so what differed is which rule refuses,
  Core's `SCRIPT_ERR_SIG_PUSHONLY` against btclib's "unknown op code",
  and the agreement was a coincidence between two modules that a soft
  fork naming one of those 69 would end. The function is public, and as
  a predicate in its own right it was giving the wrong answer. Taking
  the script_sig bytes — the script both SIGPUSHONLY and BIP16 are
  about, which is what the new name says — also buys `GetOp`'s half of
  Core's rule for nothing, a script_sig whose last push runs past the
  end being not push-only, and leaves `verify_input` parsing the
  script_sig only under CONST_SCRIPTCODE: one parse less per input. The
  error names the offending byte and its offset
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
- **`to_script_flags` takes every `SCRIPT_VERIFY_*` name Bitcoin Core
  spells** (issue #217). `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`,
  `DISCOURAGE_OP_SUCCESS` and `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` are
  members at Core's bit positions 18, 19 and 20, where they were the
  three holes in them and where a caller passing one of Core's own
  spellings got a `BTClibValueError` instead of an answer. Each is one
  `raise` in a branch the engine already had — a tapscript public key
  neither empty nor 32 bytes, an OP_SUCCESSx, a leaf version other than
  0xc0 — the three "unknown, therefore successful" cases BIP342 left open
  for a future soft fork, and what the flags ask is that such a spend not
  be relayed, so that the fork stays deployable. Consensus is untouched:
  all three are policy, off in `ALL_FLAGS`, and a spend refused under one
  is a spend a node still accepts in a block. The enum's own promise —
  that a flag means here what it means there — is what the omission cost,
  and it is now true of every member. None of the four vendored vector
  files names any of the three, so the test for each is written by hand
- `hashes.sha1`, the digest `OP_SHA1` computes, is taken with
  `usedforsecurity=False`. The algorithm is broken and the opcode is
  consensus, so the weakness is not a choice btclib makes: a script that
  hashes with SHA1 has exactly one correct answer, whatever a policy says
  about the algorithm. The flag states that where it has an effect, being
  hashlib's documented way to ask for a digest the caller is not relying
  on for security — which is what a build restricting the weak algorithms
  honours. It replaces a `# noqa: S324`, which said the same thing to the
  linter and to nothing else; the hash object faked in
  `tests/hashes_test.py` carried the second one

### Transactions, blocks and PSBT

- **`finalize_psbt` spends a single-key input the way it is spent.** It
  branched on the witness script alone, which no single-key input has, so
  a native p2wpkh got its signature written into the `final_script_sig`
  and no witness at all — and btclib's own script engine refused what
  btclib's own finalizer produced, "non-empty script_sig for a native
  segwit input". Nor could moving the signature have been the whole fix:
  `partial_sigs` is keyed by public key and only `.values()` was read, so
  the key a p2pkh or p2wpkh script hashes reached no stack. What decides
  the shape now is the script the input spends — the redeem script of a
  p2sh input, the script_pub_key of the utxo otherwise — and four shapes
  come out of it: p2wsh keeps the signatures and the witness script in
  the witness, p2wpkh is spent with `[signature, public key]` there,
  p2pkh with both in the script_sig, and everything else — p2pk, bare
  multisig, legacy p2sh — with the signatures and the redeem script in
  the script_sig. An input that says neither, having no utxo, is built as
  before. A *native* witness input now gets no script_sig rather than the
  one byte `serialize([b""])` writes, `OP_0` being non-empty in the eyes
  of the rule that forbids one. Two multisig shapes are all BIP174's own
  vectors exercise, which is why the common ones were the broken ones;
  the five are now finalized, extracted and run through the engine. A
  single-key input carrying more than one signature is refused rather
  than picked from (issue #249)
- **The difficulty retarget, the work behind a chain, the hash rate it
  implies, and a toy miner.** `btclib.block.proof_of_work` holds the first
  three as pure functions over the four `bits` bytes a header carries,
  because "which of two competing chains is best" is a question asked of
  both at once and answered by comparing their work, not their heights.
  `next_bits` is Bitcoin Core's `CalculateNextWorkRequired`: the factor of
  four clamped onto the measured timespan either way, the pow-limit clamp,
  the 256-bit ring the multiplication happens in, and the compact
  re-encoding, whose rounding down is part of the answer. Its window is
  the one `retarget_first_height` names, 2015 intervals between the
  timestamps of the 2016 blocks a period holds — the off-by-one Core keeps
  for compatibility, and the reason blocks come out 0.05% faster than the
  ten minutes aimed at. `bits_from_target` is the `GetCompact` that
  `BlockHeader.target` had no inverse for, including the rule that shifts
  a significand whose high bit would read as the sign; `block_work` and
  `chain_work` are `GetBlockProof` and `nChainWork`, and `hash_rate` is
  difficulty times 2^32 over the observed interval, with the variance that
  makes it an estimate — 1/sqrt(n), still 2% over a whole window — in its
  docstring. `btclib.block.mining` is the fourth:
  `candidate_block_header` computes the merkle root over a transaction
  list and leaves the nonce at zero, `mine` searches the four bytes up to
  a bound and answers `None` rather than hanging. A toy at one Python hash
  at a time, and not a toy about what it produces: the merkle root comes
  from the function `Block.assert_valid_merkle_root` checks against, now
  shared rather than written twice, and the tests mine a block and let
  `Block.assert_valid` have the last word. The retarget is tested against
  the four mainnet vectors of Core's `pow_tests.cpp` and the round trip
  against the bits of every vendored block (issue #188)
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
- **`Psbt.parse` reads a stream**, as every other parse in the library
  does: its parameter is `data: BinaryData`, where it was `psbt_bin:
  Octets`, so a `BytesIO` is accepted beside the bytes and the hex string
  that were. A psbt ends at the separator of its last map, and the stream
  is left right there — what follows belongs to the caller, which is what
  makes a psbt one record among others rather than the whole of a buffer,
  and what a caller reading a psbt out of a file or a socket needs.
  `psbt_utils.deserialize_map` hands the map back alone, where it returned
  the `(map, stream)` pair that slicing had needed: a caller passing a
  stream already holds it, and one passing octets has nothing left to read
  from anyway. Slicing is also what made the truncation defects of #138
  possible, a short read being indistinguishable from a full one
  (issue #179)
- **An input and an output of a psbt read and write their own map.**
  `PsbtIn.parse` and `PsbtOut.parse` take `BinaryData` and read one map
  from the stream, its terminator included, where they took a decoded
  `Mapping[bytes, bytes]`; `PsbtIn.serialize` and `PsbtOut.serialize`
  write that terminator, where `Psbt.serialize` appended it on their
  behalf. That is Bitcoin Core's shape: `PSBTInput::Serialize` ends with
  `s << PSBT_SEPARATOR` and `PSBTInput::Unserialize` refuses a map that
  arrives without one — "Separator is missing at the end of an input map",
  one message per kind of map — which is what leaves the container the
  `s >> input` loop it is there. It is also what makes the two inverses:
  `PsbtIn.parse(psbt_in.serialize())` is that `PsbtIn`, where there was no
  bytes-to-object parse to call at all. A psbt is unchanged byte for byte;
  what moved is which function writes the `0x00` (issue #179)
- **A psbt given as octets is a whole psbt.** `Psbt.parse` refuses what
  follows one — `malformed psbt: 3 bytes after the psbt` — where it read
  to the last output map and ignored the rest, and `Psbt.b64decode`
  refuses it through the same path. A tail is malleability rather than
  slack: two buffers deserialize to one object, which serializes back to
  only the shorter of them, and that is the same defect an unchecked read
  length was in #138. A `BytesIO` is the case that keeps the leniency,
  because there it means something else — the caller reads on from where
  the psbt ended. Bitcoin Core draws the line in that very place: "extra
  data after PSBT" is `DecodeRawPSBT`'s, the entry point taking a buffer,
  and not the `Unserialize` that reads a stream (issue #179)
- **A Finalizer refuses an input whose signatures ask for another
  sighash type.** BIP174 requires it of the role — "if the input has a
  `PSBT_IN_SIGHASH_TYPE` field, the Input Finalizer must fail to finalize
  that input if any signature does not match the specified sighash type"
  — and `finalize_psbt` did not look, so a psbt finalized into a
  transaction whose signatures commit to something other than the input,
  i.e. than what the other participants agreed to. The type a signature
  commits to is the byte appended to its DER encoding, and the answer is
  `mismatched sig_hash type: 0x1 vs 0x3`. The field's *presence* is what
  is tested, not its truthiness: `0` is SIGHASH_DEFAULT, a type an input
  may ask for and no ECDSA signature carries, so an input asking for it
  is one that no partial signature can finalize (issue #173)
- **A Finalizer checks each partial signature against the key it is
  filed under.** `PsbtIn.assert_valid` parses the DER and can do no more,
  a signature committing to the whole transaction that a per-field
  validator has not got; the Finalizer has it, and BIP174 charges that
  role with deciding "if the input has enough data to pass validation".
  Covered is every input kind a `PSBT_IN_PARTIAL_SIG` can belong to —
  legacy (p2pk, p2pkh, bare multisig), p2sh, p2wpkh, p2wsh, and either
  witness kind wrapped in p2sh. An input that does not say what is being
  signed is left alone rather than refused, that being a missing utxo or
  a missing script and not evidence against the signature: no utxo, a
  p2sh input with no redeem script, a p2wsh one with no witness script,
  and a taproot output, whose signatures are schnorr and travel in the
  taproot fields. `sig_hash.from_tx` could not serve, reading the redeem
  script off the input's script_sig and the witness script off its
  witness stack, which a psbt's unsigned transaction does not carry
  (issue #173)
- **A finalized input drops the preimages and the taproot fields too.**
  What a finalizer consumed is not serialized beside what it produced,
  and btclib dropped five of the fields BIP174 says so of; the set is now
  the whole of what Bitcoin Core's `PSBTInput::Serialize` writes inside
  its `if (final_script_sig.empty() && final_script_witness.IsNull())` —
  the four preimage maps and the six taproot fields as well. The utxo
  stays outside the condition, there and here, an Extractor needing it to
  check the transaction it builds; so do the unknown fields, which no
  role understands well enough to drop (issue #173)
- **The header is one constant and a separator is the `0x00`**, as in
  Bitcoin Core: `PSBT_MAGIC_BYTES` is the five bytes `b"psbt\xff"`, where
  it was the four of "psbt" with the `0xff` beside it as `PSBT_SEPARATOR`;
  `PSBT_SEPARATOR` is the byte that ends a map, which btclib called
  `PSBT_DELIMITER`; and `PSBT_DELIMITER` is gone, its constant living in
  `btclib.psbt.psbt_utils`, the one module all three kinds of map can
  reach. The word was doing two jobs because BIP174 uses it for both — it
  spells `<magic>` as the five bytes, then calls the `0xff` inside them a
  separator, next to the `0x00` separator of the maps — and Core resolves
  it the way `PSBT_MAGIC_BYTES[5] = {'p','s','b','t',0xff}` does. One
  header is one check, so `malformed psbt: missing separator` is gone with
  the constant: a psbt whose fifth byte is not `0xff` answers `malformed
  psbt: missing magic bytes`, which is Core's single "Invalid PSBT magic
  bytes" (issue #179)

### The public API and the module layout

- **`btclib.descriptors` reads a descriptor and derives its scripts**,
  where it used to compute the checksum and nothing else. `parse` returns
  a `Descriptor`, one class per grammar function, and
  `script_pub_keys(index)` answers with the `ScriptPubKey` set that the
  descriptor pays to at that index — with the address of each, where the
  script has one. The grammar is BIP 380 to BIP 386 and BIP 389 minus
  miniscript: `pk`, `pkh`, `wpkh`, `combo`, `sh`, `wsh`, `multi`,
  `sortedmulti`, `addr`, `raw`, and `tr` with a key path and a tree of
  `pk()` leaves; key expressions cover hex keys compressed, uncompressed
  and x-only, WIF, xpub/xprv with a derivation path, key origin, the `/*`
  and `/*h` wildcards and both hardened markers, and
  `multipath_descriptors` expands the BIP 389 `<a;b>` form into the
  descriptors it stands for. `strip_checksum` and `add_checksum` are the
  two halves of the checksum a caller needs, and `parse` verifies one
  that is there. Every position rule is enforced rather than assumed —
  `sh()` at the top level only, no uncompressed key inside a witness
  program, x-only only inside `tr()` — and what is not implemented raises
  NotImplementedError naming what it is: miniscript is issue #187,
  `multi_a` and `sortedmulti_a` are BIP 387, `rawtr` is BIP 386 and
  `musig` is BIP 390. The derivation is checked against Bitcoin Core's
  own `descriptor_tests.cpp` vectors, both spellings of each, so a WIF
  and an xprv are checked to reach the script their public halves reach
  (issue #186)
- **`btclib.fetch` is new, and is the one package that goes out to the
  network.** `Fetcher` is three questions the library cannot answer from
  bytes it was handed — the transaction with this id, the output an
  outpoint names, the chain tip — and it is implemented twice, so calling
  code takes a `Fetcher` and never branches on which one it got:
  `BitcoindFetcher` over a full node's JSON-RPC, and `EsploraFetcher`
  over a block explorer's HTTP api for anyone without a node. What comes
  back is `Tx` and `TxOut`, not the dicts the backends send, and the
  outputs are labelled with the fetcher's network, which `Tx.parse`
  cannot do — a serialization carries a script and no chain. It adds no
  dependency: `urllib.request`, `json` and `base64` are the whole client,
  because a cryptography library that pulls `certifi`, `urllib3` and
  `idna` in for an optional convenience has charged every other user for
  it. The
  JSON-RPC is 2.0 rather than python-bitcoinrpc's 1.0, so that a routine
  "no such transaction" is an HTTP 200 with an `error` member instead of
  the 500 a real server fault also sends; a 1.0 reply from a node older
  than v28 is still read. Credentials in the url are refused, and
  bitcoind's `.cookie` — re-read at every call, since a node restart
  rotates it — means there need be none. `AuthProxy` is the name the
  request used, python-bitcoinrpc's, and it calls any method, not only
  the three. `FetchError` and `RpcError`, the latter carrying the node's
  code, are in `btclib.exceptions` with the rest. No endpoint is a
  default: `BLOCKSTREAM_INFO` is a constant to pass, never a host btclib
  contacts on its own. Nothing here is tested against a live host —
  `HttpTransport` is the seam, and every test answers from a recorded
  body — and nothing below it imports it, so a user who never fetches
  never runs a line of it. `Tx.fee` and `OutPoint.value` were dropped
  pending this and are not restored by it (issue #185)
- **`script.parse` has lost its `accept_unknown` parameter**, with the
  answer fixed at what every caller in the library passed: a byte no
  table names is an op code all the same, refused by the interpreter that
  executes it, and named `UNKNOWN_OP_CODE_n` here so that `serialize`
  writes it back unchanged. `parse(script, accept_unknown=True)` becomes
  `parse(script)`; `parse(script)` used to raise `Unknown op code` for a
  byte Core reads without complaint (issue #123)
- **`psbt_utils.assert_valid_taproot_tree` is gone**, and `PsbtOut`
  validation no longer looks at a leaf script at all — Core's PSBT does
  not either. It parsed every leaf of the tap tree, so a leaf that cannot
  be executed made the whole `PsbtOut` invalid; with the parse refusing
  only truncation (issue #123) the check had nothing left to refuse, and
  a vacuous validator reads as a guarantee it does not give. What cannot
  execute is unspendable, which a signer learns by running it
- **`join_psbts` and `join_txs` have lost their `merge_out` parameter.**
  It was a fourth positional boolean whose only truthy value raised
  `output merge not implemented yet`, so what it offered was a choice
  between doing nothing and failing. Specifying it was the alternative,
  and it is the wrong answer twice over: coalescing two outputs that pay
  one script changes the output *set*, so every signature already made
  over the old one stops verifying, and both functions shuffle or sort
  the outputs first, which would make the result depend on the order the
  merge ran in. Summing two payments into one output is the caller's, and
  before signing is the only point at which it is safe. `merge_out=False`
  is an argument to delete at each call site; nothing else moves
  (issue #173)
- **Core's five script limits are `btclib.script.limits`**, under Core's
  own names: `MAX_SCRIPT_ELEMENT_SIZE`, `MAX_OPS_PER_SCRIPT`,
  `MAX_PUBKEYS_PER_MULTISIG`, `MAX_SCRIPT_SIZE`, `MAX_STACK_SIZE`. They
  were nine literals in five modules, and 520 alone was written four
  times — in the two interpreters, in `taproot.parse` and in
  `script.parse`, where reading an execution limit in a decoder is what
  issue #123 was about. A module of its own rather than the top of
  `script.py`, which is the encoding and has no reason to import them
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
- **`btclib.bip32.der_path`'s names drop the `bip32_` prefix**: the type
  alias `BIP32DerPath` is `DerPath`, and `indexes_from_bip32_path`,
  `str_from_bip32_path` and `bytes_from_bip32_path` are
  `indexes_from_der_path`, `str_from_der_path` and `bytes_from_der_path`,
  with `_indexes_from_bip32_path_str` and `_str_from_bip32_path` following
  them. The module is `der_path.py` and every parameter it takes is already
  called `der_path`, so the prefix was contradicted by the file it lives in
  and by the signatures it exports; inside `btclib.bip32` it also says
  nothing the import path does not, and `BIP32DerPath` reads as though a
  derivation path were a BIP32-specific notion rather than the one SLIP132
  and the PSBT key origins hand to this very module. No alias is kept, as
  the `btclib.ec` → `btclib.curves` rename kept none: an old spelling left
  reachable is a second name for one object, kept through release after
  release for the sake of code that one search and replace fixes once
  (issue #180)
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
  tests/imports_test.py imports every module of the package first, with no
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
- **`btclib.ecc.sign_to_contract` is gone, and the commitment is a
  parameter of `dsa.sign` and `ssa.sign`.**
  `dsa_commit_sign(commit, msg, prv_key, nonce, ec, hf)` is
  `dsa.sign(msg, prv_key, nonce, lower_s, ec, hf, commit=commit)`, and
  `dsa_verify_commit(commit, receipt, msg, key, sig, lower_s, hf)` is
  `dsa.verify(msg, key, sig, lower_s, hf, commit=commit, receipt=receipt)`;
  both return what they returned, the signature and the receipt from the
  first and a bool from the second. The module duplicated the signing flow
  to insert a commitment into the nonce, which is two paths that have to
  stay in step: `dsa_commit_sign_` derived the RFC6979 nonce itself, so a
  change to how a nonce is derived — or to which implementation derives
  it — had to be made twice, and the libsecp256k1 dispatch of `dsa.sign_`
  was not in the copy at all. What the commitment actually is, is an
  input to the nonce — to its derivation and then to its value — and the
  nonce is already a parameter of the one signing path: `commit_hash`
  sits beside it, keyword-only, as the only argument that changes what is
  returned. `btclib.ecc.commit_nonce` is what is left, and it is a nonce
  derivation beside the RFC6979 and BIP340 ones rather than a scheme
  beside dsa and ssa: `commit_entropy_` returns what the derivation takes,
  `commit_nonce_` the tweaked nonce and the receipt, `commit_point_` the
  point a verifier recomputes, and the scheme is documented in that
  module's docstring, which is where the name sign-to-contract now lives
  — a `commit=` keyword does not say it. **The dsa construction is
  libsecp256k1-zkp's `ecdsa_s2c`, byte for byte**, tags included:
  `s2c/ecdsa/point` for the tweak and `s2c/ecdsa/data` for the entropy,
  so a commitment made here opens under
  `secp256k1_ecdsa_s2c_verify_commit`. The two fixed vectors of that
  module's test suite are the test, and they pin the derivation of the
  untweaked nonce entire — the `s2c/ecdsa/data` tag, RFC6979's additional
  data, and the `key||msg||data` seed layout — because the opening they
  expect is that nonce's point and nothing else produces it. That
  replaces the vectors this library generated for itself, which could
  only say that the scheme had not changed, and the scheme *had* to
  change. The tweak happens after the opening, so no vector reaches
  `s2c/ecdsa/point`: mangle that tag and every vector still passes while
  nothing btclib signs opens under the reference any more. It is pinned
  instead by recomputing, from the tag strings themselves, the two SHA256
  midstates the C source hardcodes — with the data tag as the control,
  being the one the openings pin as well. ssa gains the commitment
  on the way, which the module never offered: BIP340 signs with the
  even-y nonce, so it is the *tweaked* point whose parity has to be
  settled, and the receipt stays the even-y point the tweak hashed. It is
  the one invented part — libsecp256k1 has an ecdsa s2c module and no
  schnorr one, and BIP340 says nothing about commitments — so its
  `s2c/bip340/point` and `s2c/bip340/data` are btclib's own, named for
  the standard rather than under `BIP0340/`, which would claim the BIP
  defines this. Both pairs are frozen: a different string is a different
  scheme, and every signature already made would stop opening. A
  commitment also keeps the bindings out, as a caller-supplied nonce
  does, for the same reason: the nonce is theirs to derive, and neither a
  tweak nor extra entropy is an argument their `sign` takes (issue #193)
- **`btclib.ecc` exports the signature schemes.** `__all__` was
  `ansi_x9_63_kdf`, `bip340_nonce_`, `diffie_hellman`, `second_generator` —
  four helpers, and not one of the schemes behind them — so `import
  btclib.ecc` followed by `btclib.ecc.dsa.sign(...)` raised AttributeError
  until something else in the process happened to import the submodule. It
  now exports `dsa`, `ssa`, `bms`, `borromean` and `pedersen` beside the
  four
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
- **`sig_hash.legacy_script` and `sig_hash.witness_v0_script` are gone**,
  and `from_tx` takes a `codesep_index`. The two returned a ladder — the
  script code for zero OP_CODESEPARATORs executed, then for one, then for
  two — of which `from_tx` took the first rung and nothing took the rest,
  so the one case a caller could not ask for was the one the ladder was
  built to answer. Their work is now where Core keeps it: the elision in
  `sig_hash.legacy`, the truncation in whoever knows which separator ran.
  For a signer that is `from_tx(..., codesep_index=k)`, keyword-only and 0
  by default, which is the previous behaviour spelled out. k counts
  *occurrences* in the script being signed for, because which one executes
  last depends on the branches the input takes and the signer is who knows
  them — `OP_IF OP_CODESEPARATOR OP_ENDIF OP_CODESEPARATOR` down its false
  branch executes the second and not the first. A verifier never needs the
  parameter, its interpreter carrying the offset. It is refused for a
  taproot input, BIP-341 committing to the position rather than truncating
  and `taproot_annex_and_ext` writing 0xffffffff, and for p2wpkh, whose
  script code is built rather than read — the two cases Core's signer
  declines as well, "Only support non-OP_CODESEPARATOR BIP342 signing for
  now". The p2wsh branch also stops asking what *type* the witness script
  resembles, an inherited habit that answered p2wpkh for a witness script
  of `0014` and twenty bytes and signed the p2pkh script for that hash
  instead of the witness script itself. `btclib.script` gains
  `read_op_code` and `op_code_spans`, the op-code-by-op-code walk over a
  script's bytes: Core's `GetOp`, and what a caller building a script code
  needs in order not to re-serialize a parse (issue #176)
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
  keyword-only by `field(kw_only=True)`, which is Python 3.10 where this
  package supports 3.9; `dataclasses.fields`, `replace`, `==`, `hash`, and
  `repr` are unaffected, and the three stay frozen. `dsa.Sig.parse` is the
  one signature with a parameter *after* the flag, so `strict` becomes
  keyword-only too: moving it in front of the star instead would have made
  `Sig.parse(data, False)` mean `strict=False` where it used to mean
  `check_validity=False`, which is the silent failure the whole change is
  against. The new tests/check_validity_test.py asserts the rule over the
  package's own source, so a new signature cannot reintroduce the hazard
- **`btclib.bip44` turns an extended key and a derivation path into an
  address**, which is the composition every caller had to write by hand:
  `address_from_der_path(xkey, "m/84h/0h/0h/0/0")` walks the path with
  `bip32.derive` and encodes with `b58`/`b32`, the purpose level choosing
  which — 44 p2pkh, 49 p2wpkh-p2sh, 84 p2wpkh, 86 p2tr. Every address
  entry point before it took a hash or a witness program, so "the third
  receiving address of account 0" meant deriving, hashing and picking the
  encoding, and picking it wrong is an address the wallet does not watch.
  The key may be the master or any key partway down the path — an account
  xpub, which is what a wallet exports — and its own index is checked
  against the path element at its depth. The mapping is
  `_data/bip44_purposes.json`, beside the network data: it is the
  canonical row of the wallet-format table electrum ships, and the
  per-wallet rows a seed-scanning recovery helper would want next are more
  of that file and no more of the module. A purpose the mapping does not
  name is refused rather than guessed at, with a `script_type` argument to
  say what it means — `alias.BIP44ScriptType`, the Literal that types the
  mapping and the argument alike, so the four encodings are named once;
  the coin type has to agree with the network of the
  key, which is where the address is minted, and that one has no override
  — encoding another chain's key as a bitcoin address is the mistake the
  level exists to prevent. The module sits above `script` and not beside
  `bip32.slip132` because a p2tr address is the *tweaked* output key of
  BIP341 and `bip32` may not import `script`. The vectors are BIP49's,
  BIP84's and BIP86's own, and SLIP132's for purpose 44, which publishes
  no address of its own (issue #197)
- **`btclib.fee` is the fee arithmetic**: `FeeRate`, `fee_from_vsize` and
  `dust_threshold`, which every spending path needed and none of which the
  library had — `amount.py` took `dust` as a *parameter* and carried no rule
  for it. A `FeeRate` holds an integer number of satoshi per kvB, Core's own
  unit and the only exact one, and it is keyword-only: `FeeRate(3000)` is the
  off-by-a-thousand the type exists to prevent and is a TypeError, where
  `FeeRate(sats_per_kvbyte=3000)` and `FeeRate.from_sats_per_vbyte("1.5")`
  both say which unit they were handed. The sat/vB constructor refuses a rate
  it could not hold rather than truncating one, and the sat/vB accessor
  answers a `Decimal`. Every argument that is not what it claims to be is
  refused with one of this library's exceptions rather than with whatever the
  arithmetic underneath would have raised: a rate `Decimal` cannot parse —
  `"1,2"`, the way half the world writes one — is a `BTClibValueError` and not
  a `decimal.InvalidOperation`, and a non-integer virtual size is a
  `BTClibTypeError` rather than a float fee, `141.5` vB otherwise passing
  straight through the arithmetic to answer `425.0`. `fee_from_vsize` rounds
  *up*, which is Core's
  `CFeeRate::GetFee`: a fee one satoshi short of the rate does not relay, and
  exact ceiling division on ints gives the one-satoshi floor that Core's
  float-era code needed a branch for. `dust_threshold` is Core's
  `GetDustThreshold` — the dust relay rate, 3000 sat/kvB and a defaulted
  parameter as `-dustrelayfee` is an option, over the output's own serialized
  size plus the input that will spend it. Computed and not tabulated, which
  is the whole point: p2tr answers 330 with taproot named nowhere in the
  module, and so will the next output type, where electrum's five
  `DUST_LIMIT_*` constants need an edit apiece. The tests check the computed
  answers against that table — 546 p2pkh, 540 p2sh, 330 p2wsh, 294 p2wpkh,
  354 unknown segwit — and against the 182 and 98 virtual bytes Core works
  out by hand above `GetDustThreshold`. Unspendability is Core's
  `IsUnspendable` and not btclib's narrower `is_nulldata` (issue #211), so a
  bare OP_RETURN gets the zero threshold a node gives it. What is *not* here
  is everything downstream of a network: mempool histograms, fee estimates
  for a confirmation target, ETAs. Those are policy fed by live data and
  belong to an application; the module docstring says so (issue #205)
- **`btclib.keystore` is the wallet infrastructure `bms` asks for**, and
  no more of it: `bms`'s own docstring says "at signing time, a wallet
  infrastructure is required to access the private key corresponding to a
  given address" and the library had none. A `KeyStore` holds a key
  source, hands out addresses, remembers the derivation path of each and
  answers which private key signs for one, which is what lets
  `keystore.sign(address, msg)` exist — a message signature addressed by
  *address*, delegated to `bms.sign` and signing nothing itself.
  `BIP32KeyStore(xkey, "m/84h/0h/0h")` takes an extended key anywhere on
  the account path and derives the two unhardened levels below it, the
  purpose choosing the encoding as BIP44/49/84/86 define it; `KeyStore`
  takes individual keys instead, one address each. The decisions worth
  knowing: an address the keystore has not handed out is a *raise* and
  not a None, because "no opinion" and "no key" deserve different answers
  and `address in keystore` is the question that wants a boolean;
  addresses are derived on demand rather than precomputed over a gap
  limit, a gap limit being a scanning parameter that means nothing
  without a chain to scan; an xpub or a public key is a first-class
  watch-only keystore, where `sign` raises naming the address rather than
  returning something falsy; and the script type follows the *path*, not
  the SLIP132 version bytes, so an xprv and a zprv holding one key cannot
  hand out two different addresses for one path. p2tr addresses are
  handed out and cannot be signed for: BMS recovers an ECDSA key against
  a hash160, a taproot output key is BIP341's tweaked x-only key, and the
  refusal says so rather than letting `bms` report the generic mismatch.
  Out of scope and stated in the module docstring: utxo tracking,
  balances, transaction building, persistence to disk, encryption at rest
  — the first three need a view of the chain btclib does not have, the
  last two a file format that would outlive the release choosing it
  (issue #189)
- **pre-2.0 Electrum seeds are read, and a dispatcher says which scheme a
  mnemonic belongs to** (issue #208). A wallet created before Electrum 2.0
  was recognized and nothing more: `version_from_mnemonic` answered
  `"old"` and every other function refused it. Four functions in
  `mnemonic.electrum` now read it — `old_mnemonic_from_hex_seed` and
  `hex_seed_from_old_mnemonic` for the encoding, three words to each
  32-bit group over the 1626-word list, and
  `old_master_prv_key_from_mnemonic` and
  `old_master_pub_key_from_mnemonic` for the stretch, which is a hundred
  thousand rounds of `sha256(digest + hex_seed)` over the hex
  *characters*, not PBKDF2 and not the versioned scheme's 2048
  iterations. **The passphrase is refused rather than defaulted**:
  nothing but the seed enters the stretch, so accepting one and ignoring
  it would hand back the wallet of a seed the caller did not ask for, and
  Electrum's `keystore.from_seed` refuses it the same way. `None` and the
  empty string are "no passphrase", as they are there. The scheme has no
  specification — it predates the BIPs — so Electrum's implementation is
  what correct means and every vector is Electrum's own: the
  mnemonic-to-hex pair of its `Test_OldMnemonic`, two wallets of its
  `test_wallet_vertical.py` with their master public keys, and a real
  pre-2.0 wallet file from its `test_storage_upgrade.py`. Two of them
  pin a weakness copied rather than fixed, because fixing it would
  accept or refuse what Electrum does not: three words can carry a group
  above `2**32`, so twelve words can decode to 33 or 34 hex characters
  instead of 32, and one of Electrum's own published seeds does — 34,
  still octets, so the master public key is derived and matches, while
  the encoder cannot write those twelve words back out and Electrum's
  `get_seed` cannot either.
  The dispatcher is the new `mnemonic.dispatch`:
  `seed_type_from_mnemonic` answers `"electrum_old"`,
  `"electrum_standard"`, `"electrum_segwit"`, `"electrum_2fa"`,
  `"electrum_2fa_segwit"`, `"bip39"`, `"bip39_wordlist"` — every word in
  the list but no valid reading — or `""`, and
  `all_seed_types_from_mnemonic` returns every scheme that claims the
  sentence, because the schemes overlap and the collision is worth
  seeing rather than resolving in silence. Within Electrum the order is
  `calc_seed_type`'s, old before the four prefixes, so a pre-2.0 seed
  that matches `"01"` by chance is not handed back as `"standard"`;
  Electrum before BIP39 is btclib's, Electrum's wizard asking the user
  which variant a sentence is instead of guessing, and the base rate is
  the reason — a version prefix is a deliberate marker present by chance
  in one sentence in 256, a valid BIP39 checksum in one in sixteen. The
  dispatcher normalizes nothing of its own, each scheme normalizing as it
  defines, which leaves issue #201 to decide that once for all of them.
  **`mnemonic.dispatch` answers `"slip39"` too**, and it answers it
  *first*, ahead of Electrum and BIP39. The order is measured rather than
  assumed, and it is the one place it changes an answer: Electrum's
  version check is an HMAC over the sentence and consults no word-list at
  all, so it claims a share whenever the HMAC happens to start `01` — 80
  of 20000 random 1-of-1 shares, one in 250. The reverse never happened,
  0 of 2000 Electrum seeds and 0 of 2000 BIP39 mnemonics reading as a
  share, because 1495 of BIP39's 2048 English words are absent from
  SLIP-0039's list; so a share is the rarer signal by orders of magnitude
  — 30 checksum bits over words that must every one of them be among
  SLIP-0039's 1024 — and last in the chain would report one share in 250
  as an Electrum seed. `"slip39"` says the sentence in hand is one
  well-formed share and nothing about the set it belongs to: of
  SLIP-0039's 30 invalid vectors, 8 carry a fault inside a share and are
  refused here, while 22 are unusable sets of individually sound shares
  and are reported `"slip39"` with `master_secret_from_mnemonics` left to
  refuse the set
- **`btclib.mnemonic.slip39` is the third mnemonic scheme**, SLIP-0039
  Shamir backup: the split-into-shares format every Trezor since 2019
  offers, and the one a hardware-wallet user is most likely to be
  holding. `master_secret_from_mnemonics` reads a set of shares back into
  the master secret, `mxprv_from_mnemonics` carries that to a BIP32 root
  key — the master secret *is* the seed, so there is no stretching step
  between them — `mnemonics_from_master_secret` produces the shares, and
  `share_from_mnemonic`/`mnemonic_from_share` are the two halves of the
  encoding, around a frozen `Share`. Underneath: Shamir's scheme over
  GF(256) applied byte by byte with the secret at `f(255)` and a digest
  of it at `f(254)`, an RS1024 checksum over the 10-bit word indexes, the
  two-level group/member threshold structure, and a four-round Feistel
  network over PBKDF2-HMAC-SHA256 encrypting the secret under the
  passphrase. All 45 of SLIP-0039's own vectors are exercised, the 30
  that must fail included, and the four 1-of-1 vectors are regenerated
  word for word rather than only read.
  Generation is here and not only recovery, which is where several
  implementations stop: a wallet needs to restore, a library is asked
  both questions, and generating is also what lets a round trip be
  checked against something other than btclib's own reading of it. Every
  random byte comes from one injectable `entropy_source`, defaulting to
  `os.urandom`, because nothing else about a 2-of-3 backup is
  reproducible enough to test against a fixed expectation. The extendable
  backup flag is supported in both states: it decides whether the
  identifier salts the Feistel rounds, so shares written before that
  revision of the SLIP and after it both decrypt. SLIP-0039's 1024-word
  list ships as `btclib/mnemonic/_data/wordlist.txt` and is a `WORDLISTS`
  language keyed `slip39` — a scheme rather than a language code, the
  SLIP supporting no localization at all.
  Sharing the one registry is what makes `lang="slip39"` a request
  `mnemonic.bip39` can be given, so **bip39 now refuses any word-list
  that is not 2048 words long**, where before it answered with a
  base-1024 sentence no BIP39 wallet reads. `load_lang`'s existing test
  does not catch it — it asks for a power of two, and 1024 is one — and
  the refusal reaches any custom list of the wrong length, not only
  SLIP-0039's (issue #206)

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
- **mypy is aimed at Python 3.10**, not at whatever interpreter runs it.
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
  `DerPath`, `BIP340PubKey`, `Entropy`, `OneOrMoreInt`, `ScriptFlags`,
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
  buffer union Python 3.9 cannot spell and `rfc6979` passes `hf` to it eight
  times
- `alias.py` says at the top that `Octets` and `String` are the same type
  to mypy, both being `Union[bytes, str]`, so the hex-string versus text
  string distinction the file documents is enforced at run time by the
  converter each function calls and by nothing else. `NewType` would let a
  checker separate them at the cost of every caller wrapping its literals,
  which is a different library
- **the closed vocabularies are `Literal` aliases**, and the open ones are
  named without being imposed (issue #216). `alias.ScriptType` is the ten
  values `type_and_payload` returns — `"unknown"` among them, an answer and
  not an absence, and `"witness_unknown"` beside it, which is Core's own
  name for a witness version this library cannot spend — and types that
  function, `ScriptPubKey.type`,
  `b58.address_from_h160`, `b58.h160_from_address` and the script engine's
  two witness helpers. `alias.NetworkField` is the eighteen field names of
  `Network` and types the `key` parameter of the three `*_from_key_value`
  lookups, the most fragile of the four vocabularies: a misspelled field
  name matches no network, so the lookup answers `None` — "no network
  carries this prefix" — where a misspelled network *name* at least raises
  `KeyError` at the indexing. `alias.NetworkName` and `alias.MnemonicLang`
  name the five networks and three word-lists btclib ships and type no
  parameter at all, because `NETWORKS` takes a caller's custom signet and
  `WordLists.load_lang` a caller's word-list: a `Literal` on `network: str`
  or `lang: str` would refuse a value the library itself accepts. No enum,
  and the measurement is the issue's: `class Net(str, Enum)` formats a
  member as `mainnet` on 3.10 and as `Net.MAINNET` on 3.11 and later, so the
  six error messages that interpolate a network name — text some tests match
  verbatim — would read differently on different interpreters, while
  `enum.StrEnum`, which formats as the value everywhere, is 3.11+ against a
  3.10 floor; and refusing strings breaks thirty-eight signatures. Nothing
  here exists at run time, so the two data-derived aliases are checked
  against the data instead: `network_test.py` against
  `dataclasses.fields(Network)` and `NETWORKS`, `mnemonic_test.py` against a
  fresh `WordLists`

### Performance

- **the point arithmetic reduces its intermediates as it forms them**,
  which is worth between 2.0 and 3.0 times on every scalar multiplication
  in the package: `_mult` 2.00x, the fixed window over cached multiples
  2.88x, `_double_mult` 2.32x, `double_mult_w_NAF` 2.45x, the GLV
  `mult_endomorphism_secp256k1` 2.42x, `mult_jac` 2.55x, all at 256 bits
  on secp256k1, and 2.13x to 2.82x on secp256r1; at 32 bits the same
  span. The formulas are the same ones and so is every answer: what
  changed is that `add_jac` and the doubling helper let `V3` and `M*V2`
  grow to `p^9`, and the products that close `X` and `Y` to `p^12` —
  three thousand bits for secp256k1 — before a single reduction at the
  end, and Python multiplies whatever it is handed. Reducing also makes
  the doubling test free, `V` and `W` being the differences the formula
  needs anyway: issue #171 counted four multiplications for that test,
  and they were never its cost. `add_aff` and `double_aff` take the same
  treatment for 6%, `mod_inv` being what dominates in affine coordinates,
  and the tiny curves of the test suite gain nothing at all, `p^9` of a
  five-bit prime being one machine word. Complete formulas were measured
  rather than assumed — Renes-Costello-Batina in homogeneous coordinates,
  no exceptional case at all, is 34% slower for `a == 0` and 59% slower
  for the `a == p-3` of most catalogued curves, and `JacPoint` is public.
  Every gain is a uniform one, so the comparisons the `curve_group_2`
  docstrings draw between the algorithms still hold as measured
- **BIP32 public derivation stays serialized throughout**:
  `keys.pubkey_tweak_add` adds the generator times the offset to the
  parent's 33 bytes and hands back the child's, where Python multiplied
  the generator, added the two points and serialized the sum — 12.4 µs
  against 33.4. The bindings answer uncompressed, deliberately: the
  cached point wants the y coordinate, and taking it back from a
  compressed key is the modular square root of `point_from_octets`, some
  74 µs to undo a serialization libsecp256k1 had just made. A child at
  infinity is still `invalid child index N`, and still refused before
  the key data is touched
- **BIP32 private derivation adds the offset in constant time**:
  `keys.prvkey_tweak_add`, where it was `(kpar + IL) % n` on Python
  integers — variable in time with the operands, and leaving an
  unzeroized copy of every intermediate behind. The parent key goes in
  as the 32 bytes it is stored as, so no arithmetic on the secret
  happens on this side of the call at all. It costs 0.55 µs against
  0.03, on a derivation whose hmac and public key are some 15 µs of
  their own. BIP32's three invalid children are unchanged, and still
  `invalid child index N`: the range check on `parse256(IL)` stays in
  Python, and the one sum libsecp256k1 refuses past it is the zero child
  BIP32 refuses too. Not gated on the curve, unlike the library's other
  delegations, there being no second curve BIP32 is defined over
- **ECDH computes the shared point in libsecp256k1**, and in constant
  time: `dh.diffie_hellman` calls `keys.pubkey_tweak_mul` on secp256k1,
  15.2 µs against the 0.55 ms of `mult(dU, QV)` — some thirty-six
  times, this being the multiplication of a point that is *not* the
  generator, the one case `mult` never delegated, with the private key
  as the scalar. The derivation is unchanged and still ANSI-X9.63-KDF,
  which is why the bindings' own `ecdh.shared_secret` is not a
  substitute: that one hashes the compressed shared point with SHA256.
  Every other curve keeps the Python multiplication, GEC 2's secp160r1
  vector now checked through `diffie_hellman` itself, and so does a
  scalar that is zero mod n — the infinity point, which the bindings
  have no scalar for and which is still `invalid (INF) key`
- **the taproot output *private* key is tweaked by libsecp256k1 too**, and
  in constant time: `taproot.output_prvkey` calls
  `xonly.prvkey_tweak_add`, which is BIP341's tweaking of an x-only
  private key — the negation of a key whose public point has an odd y
  included — where Python negated with `ec.n - q` and added with a `%`.
  Neither is constant time; the C one is, and it is a secret scalar. It
  is faster as well, 32.0 µs against 82.3 over 2000 tweaks,
  because the x-only public key the tweak commits to now comes from
  `bytes_from_prv_key_int` instead of a point built in Python and a
  square root taken to learn that point's parity. The Python arithmetic
  stays, and is compared against the bindings over both parities
- **the taproot output key is tweaked by libsecp256k1**, both where it is
  built and where a control block is checked against it:
  `taproot.output_pubkey` calls `xonly.tweak_add`, and
  `check_output_pubkey` calls `xonly.tweak_add_check`, the dedicated
  verification. Each of the two lifted the x-only key to a point with
  `ec.y_even` and added `mult(t)` to it in Python: 12.0 µs against 109.3
  for an output key over 2000 tweaks, of which the modular square
  root alone was 74. The Python arithmetic stays, and the tests compute
  every tweak twice to hold the two answers to each other — taproot has no
  second curve to reach that path with, a toy curve failing BIP341's range
  check on a 256-bit tweak before any arithmetic happens.
  `check_output_pubkey` keeps answering the Python comparison for a q that
  is not 32 bytes, which `tweak_add_check` refuses instead of answering
- **`mult` takes the GLV endomorphism on secp256k1** wherever the bindings
  cannot answer: `curve_group_2.mult_endomorphism_secp256k1`, 0.53 ms
  against the 0.84 of the generic `_mult`. The bindings take the generator
  and a non-zero scalar, so what reaches the Python path is every *other*
  secp256k1 point: any caller multiplying a point of its own gains that
  third. Not ECDH any more, which measured 0.56 ms against 0.87 until
  `dh.diffie_hellman` began asking libsecp256k1 for the shared point
  itself, and which reaches this only on another curve. The dispatch asks the
  same `_libsecp256k1_applicable` the bindings dispatch asks, so the two
  cannot drift apart, and every other curve still runs `_mult` untouched.
  The algorithm is not new either: m as m1 + m2*lambda with both halves
  short, the two multiplications interleaved by the wNAF above, in the
  tree with its own tests
- **signature verification takes the interleaved-wNAF double
  multiplication**, `curve_group_2.double_mult_w_NAF`, where it took the
  Shamir-Strauss binary loop of `curve_group._double_mult`: 1.03 ms against
  1.53 ms per double multiplication on secp256k1, best of seven over random
  256-bit coefficients. `curves.double_mult`, `dsa` and `ssa` verification
  and both public key recoveries reach it, so it is every signature the
  bindings do not answer — another curve, another hash function, a
  caller-supplied nonce — and the test suite's Python path, which drops from
  96.4 s to 79.3 s single-process, the module that holds it from 14.7 s to
  11.2 s. Neither algorithm is new and neither moves: the wNAF one has been
  in the tree with its own tests, and `_double_mult` stays as the reference
  they compare it against.
  It is not faster everywhere, and the docstring now carries the curve: the
  tables of odd multiples are built per call, so a coefficient too short to
  amortize them pays for them — 8 bits is 1.80x *slower*, 16 bits 1.20,
  32 bits 0.95, 256 bits 0.73. Every curve with a real order is past that
  crossover; what pays is the toy curves of the test suite, n = 11 and
  n = 31, some 2 us a call, and a size guard would have bought a fraction of
  a second back at the price of a branch inside signature verification
- **the multi multiplication behind batch verification picks its
  algorithm by size**, and the small sizes are the ones that got faster.
  `curve_group._multi_mult` was Bos-Coster whatever the batch; it is now
  Strauss' interleaved wNAF — `_multi_mult_w_NAF`, the many-point form of
  the double multiplication above — below fifty-six nonzero scalars, and
  Bos-Coster from there on. Sharing one doubling per bit among all the
  points is what wins on few scalars: on secp256k1, best of interleaved
  reps over random 256-bit scalars, 1.99 ms against 3.91 at two scalars,
  2.59 against 4.56 at three, 3.92 against 6.34 at five, 6.96 against
  10.02 at ten. `ssa.assert_batch_as_valid_` spends two scalars per
  signature and inherits the curve: 5.93 ms against 7.79 for two
  signatures, 7.32 against 9.65 for three, 10.01 against 12.77 for five,
  16.87 against 20.38 for ten, and the same 47.6 either way at
  thirty-two, which is where the dispatch has already changed hands.
  What does not win is the tail: the shared doublings amortize to nothing
  and the per-scalar cost is all that is left, 50 point operations against
  the 44.5 Bos-Coster settles at, so 56 is where the two measure the same
  and the dispatch changes hands. Nonzero scalars, because a zero is
  dropped before either algorithm sees it: 56 scalars of which 2 are
  nonzero is a batch of two, and dispatching it on its length would cost
  1.81 ms where the wNAF takes 1.02, against the 0.8 us of counting the
  zeros out. Both implementations stay, tested against each other and
  against the plain sum of scalar multiplications on every curve of the
  catalogue; the threshold is a measurement, not libsecp256k1's 88, whose
  algorithms and machine are not these. Pippenger is *not* in the tree
  for the same reason: prototyped with sparse buckets and the running-sum
  trick, best window per size, it lost at every size measured — 162 ms
  against Bos-Coster's 125 at 256 scalars, 284 against 225 at 512, 500
  against 406 at 1024 — because in Python its bucket sums are additions
  like any other, where in C they are the cheap part (issue #212)
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
  to be dropped, each a Python `_double_mult` whenever `r + ec.n - ec.p`
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
  Python double-and-add over the bit length of the order, 118 ms of the
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

- **a Combiner's union of the final witnesses is pinned by a test**: two
  psbts with a different input finalized in each, combined both ways
  round, keep both — which the marker beside `_combine_field` said they
  did not. They do, a `Witness` being sized, so the empty one is falsy
  and the finalized input is the one taken; what the marker's
  commented-out list branch would have added is the one wrong answer, a
  witness stack being positional, so two stacks for one input are two
  spends of it rather than the halves of one. A conflict is picked from
  and the psbt combined *into* keeps what it has, which is the arbitrary
  choice BIP174 allows and the one Bitcoin Core's `PSBTInput::Merge`
  makes; that is now a test too (issue #173)
- **the tree measures 100% again**, and the two statements that had gone
  uncovered were electrum's round-trip check on its own encoding — the
  one `_search_mnemonic` makes before it returns a candidate. Not
  reachable with the wordlists btclib ships, `en` and `it` being 2048
  distinct ASCII words each, so the test patches the decode to reach it,
  as the ripemd160 fallback test patches its flag; a `pragma: no cover`
  would have left the message unpinned. They had eaten the whole of the
  `fail_under` rounding step, which is what made the gate turn red for
  the next single uncovered line to appear anywhere in the tree —
  and turn red without warning, because pytest-cov prints its `FAIL
  Required test coverage ... not reached` on the *unrounded* total while
  the exit code follows the rounded one, so the run before was already
  printing FAIL and passing. pyproject.toml's comment now says so
- **the three consensus branches no vector reached are reached**, each
  by an input rather than by a reworded assertion (issue #252).
  **The taproot annex on the script path**: `sig_hash.from_tx` was
  never asked for a script path spend carrying one, so the branch that
  strips it ran only where there was nothing to strip — a key path
  spend cannot exercise it, its stack holding the signature alone once
  the annex is off, which makes the leaf hash the same either way. 58
  vectors of `script_assets_test.json` now go through it, 11 of them
  with an annex, selected as the spends of a `<pub_key> OP_CHECKSIG`
  leaf so that Core's own signature is the authority on the answer; and
  a round trip signs a script path spend from the shape no vector can
  carry, the signer's witness of script and control block with no
  signature on it yet, for btclib's script engine — which strips the
  annex in its own code and never calls `from_tx` — to accept.
  **SIGHASH_SINGLE past the last output**: BIP-143's own example signs
  an input whose index *equals* the output count, and so does every one
  of the seven such spends in `script_assets_test.json`, so a bound
  reading `!=` where it should read `<` passed everything there was.
  Both paths now sign at an index two past the last output: the segwit
  v0 one against a preimage the test builds from BIP-143's field list,
  itself checked against the preimage and sigHash the BIP publishes,
  and the taproot one against the refusal BIP341 requires, by the
  message it gives. **A script code no op code can be read from at
  all**: the walk that elides `OP_CODESEPARATOR` keeps whatever is left
  where the walk stopped, and where it stops at the very first byte
  that is the script code entire — reachable because 0xab can be in it
  as data of a push that overruns the end
- **the twelve on-chain scripts of issue #123 are vendored**, in
  `tests/script/_data/unspendable_script_pub_keys.json`: the real
  `scriptPubKey`s of the five transactions the issue lists, each with the
  height and vout it sits at and what the decode must answer. A synthetic
  equivalent would have exercised the same code without closing the
  report. It is the one vendored file that cannot verify itself, a
  `scriptPubKey` being a part of a transaction and no txid recomputable
  from it, and `tests/_data/README.md` says so next to the command that
  re-derives each one
- **a stated entry count in these two files is a failing test**, where
  CLAUDE.md and CONTRIBUTING.md answered it with a command to run by
  hand. Written as a habit it did not work: `f295aaaf` left CHANGELOG.md
  at 115 entries under a header reading "a hundred and eleven",
  `1142e97b` took it to 116 under the same header, and both survived
  review because a wrong number looks exactly like a right one. Comparing
  the number against the bullets answers that at the price of a line every
  open branch has to edit, so neither file states one, and
  `tests/release_notes_test.py` fails on an entry count, on a size for
  HISTORY.md's breaking-changes list and on a cross-reference to it from
  CHANGELOG.md — written by hand or restored by the `union` merge that
  keeps these files from conflicting, which would itself say nothing. The
  patterns are asserted against the lines they forbid, an assertion in the
  negative passing for free the moment it matches nothing
- **the suite runs in a random order**, `pytest-randomly` being in the
  test group; the seed is printed, and `-p no:randomly` puts the file
  order back to reproduce a failure against it. It guards the one thing a
  green suite cannot report about itself, whether a test passes because
  of what ran before it — which is not hypothetical here, issues #139,
  #140 and #165 having all been one object's mutation reaching another.
  Three seeds were measured green before it went in, so this is a ratchet
  and not a cleanup

- **the test suite runs on `--dist worksteal`**, xdist's work-stealing
  scheduler, where it ran on the default `load`: 17.2 s against 23.3 s,
  best of three runs each, same 14681 tests in the same order. The cost
  here is lopsided — the `tapscript-bigmulti` cases of
  `tests/script_engine/python_path_test.py` take 3 s each against a
  median test under a millisecond — and `load` hands the queue out in
  chunks, so a worker that draws several of them is still going when the
  others have run out of work. Two changes that look like they should help
  do not, and tests/README.md records both with their numbers: scheduling
  the slow module first is *worse* under either scheduler, and every `-n`
  other than `auto` is slower than `auto`
- **every vendored vector is exercised**, where two filters used to hold
  1206 of them back. `taproot_vectors` in
  `tests/script_engine/transactions_test.py` selected on `"TAPROOT" in
  x["flags"]`, which drops 1016 of `script_assets_test.json`'s 3737
  cases: Core's `feature_taproot.py` dumps each spend twice, once with
  the soft fork enforced and once without, and the second copy is what
  asserts that a taproot output stays anyone-can-spend to a node that
  does not know the rule — so the filter tested the new rule 2721 times
  and the upgrade path it is reached by never. The other was a `[:10]`
  on `signmessage.json`'s 200 vectors, kept on the reasoning that the
  ones after the tenth "prove the same thing again", which nothing had
  measured and nothing else was proving: that file is the only place
  those 190 addresses appear. Neither was hiding a failure — the 1016
  pass, 685 accepted and 331 refused as their vectors ask, and so do the
  190 — and neither was covered elsewhere: 943 of the 1016 were reached
  by no other test at all, the other 73 only by `test_valid_script_path`,
  which checks the taproot commitment and runs no script. 2222 more
  cases, and the wall
  clock does not move, xdist spreading them; the cost is the 190 extra
  signatures, about 19 s of CPU across the workers
- **coverage is 100% and the ratchet is 100%**, where it was 99.9% and
  the measured total 99.92%. That gap was not a rounding allowance being
  used up: it was 12 uncovered statements, and 15 of slack is what let
  them accumulate unremarked while both `CONTRIBUTING.md` and the
  `fail_under` comment claimed "0 uncovered". Six were in
  `tests/conftest.py` — the golden-file check's own regenerate,
  missing-file and mismatch paths, which are the three that matter and
  the only lines of `tests/` a passing suite never runs. They were
  unreachable from a test because they lived in a closure over
  `request`: the body is now `conftest.check_golden(path, name, value,
  module)` and `tests/conftest_test.py` drives all three against a
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
  possibility the curve does not have. 100 rather than a percentage
  below it, and coverage special-cases the value: the usual
  `round(total, precision) < fail_under` does not apply, so 99.999% is a
  red build where 99.99 passed everything above 99.985%. That is a
  deliberate loss of the one rounding step of slack it used to carry,
  because the slack cost more than it bought — it hid two uncovered
  statements for a whole release and handed the red build to the next
  pull request through, and pytest-cov's `FAIL` line fires on the
  unrounded total while the exit code follows the rounded one, so inside
  that step the report and the gate disagreed. At 100 both say "not
  exactly 100" and the report can be read again. What it costs is a line
  no run reaches: it is covered by patching what stands in the way, as
  the ripemd160 fallback and electrum's check are, or it carries a
  `pragma: no cover` with the reason, as borromean, bms and musig2 do.
  `CONTRIBUTING.md` and the `fail_under` comment both say it
- **`tests/ecc/bms_test.py` imports on Python 3.9 again.** It annotates a
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
- **the vendored consensus vectors are judged by the Python implementation
  too**, in `tests/script_engine/python_path_test.py`: the two symbols the
  engine imports from the bindings are replaced by `btclib.ecc`, and
  `script_tests.json`, `tx_valid.json`, `tx_invalid.json` and the taproot
  vectors — 4168 of them — run again through it. Until 23041e4b the engine
  fell back to Python when the bindings were absent, two vectors failed in
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
  tests/ecc/rfc6979_test.py, which is what TODO.md's "compare of
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
  generates the input nobody wrote down, and `tests/fuzz_test.py` asserts
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
- **Every test module is `<name>_test.py`**, where all 71 were
  `test_<name>.py`: the `name-tests-test` hook runs at its default now, with
  neither `args` nor `exclude`. The two conventions guard the same failure —
  a test file named so that pytest never collects it, which no test suite can
  report on itself — and pytest's default `python_files` collects both, so
  what the rename buys is one local carve-out fewer rather than a stronger
  check. That carve-out was `tests/vectors.py`, the loader the suite shares
  and the one file under `tests/` holding no test: the hook exempts
  `conftest.py` and `__init__.py` by basename, so `load`, `load_csv` and
  `vector_id` moved into `tests/__init__.py`, beside the helpers already in
  the `__init__` of `tests/script` and `tests/script_engine` — shared test
  code lives in the package `__init__` at all three levels now, where it did
  at two. Renaming it `vectors_test.py` was the alternative, and it is this
  hook's own failure mode written by hand: a name that says "test" to every
  reader, on the one module with none. The cost was 33 import lines and 53
  references in prose and comments, eight of them in `btclib/` itself
- **BIP-143's OP_CODESEPARATOR cut has an invalid twin** (issue #221).
  Its other script-code rule — no FindAndDelete of the signature — is
  cornered by Core's own "wrong sighash with FindAndDelete" vectors,
  which fail when the rule is not applied; the cut had three vectors,
  all of them valid spends, all native P2WSH, all from the same
  appendix, and nothing saying what a wrong cut looks like. Two spends
  are hand-rolled instead: a P2WSH witness script with two separators,
  signed by btclib at the second and verified by btclib's engine, and
  the same spend signed at the first — one push and one separator too
  early — which must fail, as must the whole-script cut of a spend
  executing no separator. The witness script carries a non-minimal push
  on each side of the second separator, so the one inside the script
  code tells a byte slice from a re-serialization of a parse, which is
  the hazard #176 fixed and which no signed spend exercised through the
  engine before. The second spend is p2sh-wrapped, the shape none of the
  three appendix vectors has: the cut is still the witness script's, and
  the redeem script is not in the v0 preimage at all, so the two spends
  commit to the same hash. What this buys is bounded and the test says
  so — that btclib's signer and verifier agree on where the cut falls,
  and that any other cut is refused. Whether the preimage is Bitcoin
  Core's is still the appendix vectors and #176's byte-slice property,
  and an independent oracle (#198) is what would settle it

### Supported interpreters and dependencies

- dropped Python 3.7 and 3.8 support, added 3.13 and 3.14
- **dropped Python 3.9**, so `requires-python` is `>=3.10` and the matrix
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

- **nine more mypy error codes**, surveyed the way the ruff sets were:
  every optional code `strict` leaves off, run over btclib and tests.
  These nine find nothing today, so each is a ratchet — and two carry
  weight beyond that, `ignore-without-code` making every `type: ignore`
  name the rule it silences, and `deprecated` reporting a stdlib API on
  its way out, which across 3.10 to 3.14 is the early warning
  `filterwarnings = ["error"]` already buys at runtime. Three codes are
  deliberately absent and the survey says why: `redundant-expr`,
  `warn_unreachable` and `possibly-undefined` all point at one idiom this
  code base chose on purpose — a runtime `isinstance` guard on a field
  mypy already believes is typed, because `from_dict` takes whatever the
  json says. RELEASING.md gains a `griffe check` step against the
  previous tag, which reads both revisions of the public API and answers
  the question the new count test cannot: whether the breaking-changes
  list is *complete*, not merely counted correctly

- **the code that was commented out instead of deleted is gone, and `ERA`
  is on to keep it that way.** 89 findings, and the split was almost even.
  About half was dead code: a second copy of `parse_script` in
  `tests/script_engine/__init__.py`, a `point_from_prv_key` marked
  "probably useless", a `hexstr_from_bytes` marked "not needed!!", an
  `is_witness` on `TxOut` calling a function that exists nowhere in
  btclib, three `PSBT_*_PROPRIETARY` constants each already explained in
  prose above itself, three `print("Q has been negated")` and a
  CryptoHack answer that computed a sha1 and asserted nothing. Where the
  dead lines carried the only copy of a reason, the reason stayed and
  became a sentence — that the `0x` branch slices its token because
  round-tripping through an int turns `0xbb` into `bb00`; that
  `bech32.decode` leaves the 90-character limit to `b32`, which was
  checked and does enforce it; that `TxOut.assert_valid` deliberately
  does not parse its script_pub_key, because one on chain need not parse.
  The other half was ERA reading prose as code, and none of it needed a
  `noqa`: a reworded comment reads as prose to it — `# p2pk: pub_key
  OP_CHECKSIG` where `# p2pk [pub_key, OP_CHECKSIG]` did not — and a
  diagram belongs in a docstring, which ERA does not inspect. Two small
  finds fell out on the way: a script-shape comment reading `p2wtr` for a
  branch returning `p2tr`, and a "must be prime" note that selected five
  low-cardinality curves out of eight whose orders are all prime, the
  real reason being a loop quadratic in `n`
- **six more ruff rule sets, chosen by running all of them**, and the
  counts for the ones not taken written down beside the ones that were.
  `A`, `BLE`, `RSE` and `TID` find nothing today and are ratchets: no
  cleanup, and no shadowed builtin, blind `except Exception`, or relative
  import can arrive unremarked — `BLE` is the one that would have caught
  the annex `IndexError` being swallowed, and `TID` keeps the import
  layering readable, `ecc` on `curves` and never the reverse. `T20` found
  three prints, two of them the interface of the dice-roll entropy
  collector, which prompts with `input()` and is ignored per file, and one
  a debugging leftover inside a `pytest.raises` block in
  `tests/b32_test.py` that printed an address on every invalid case and
  asserted nothing; it is gone. `C90` closes issue #184, which asked for
  C901 or for the decision not to have it: `max-complexity` is ruff's
  default 10, and the 2 functions over it — the script engine's
  interpreter loops, an op-code dispatch each — carry a
  `# noqa: C901` naming its reason, never its number, which nothing would
  check. No exemption is permanent: RUF100 fails a noqa as unused the
  moment a refactor brings its function under the line, so the list only
  shrinks; a bound at the tree's worst would have let new functions grow
  to it unremarked, and per-file-ignores would have unguarded every
  neighbour in the file. `PsbtIn.serialize` and `PsbtIn.parse` are two
  that left it, at 5 and 4 where they were 23 and 21: a branch per BIP174
  input key type is a table with an entry per type, the fields differing
  in the key type byte, the attribute and the codec and in nothing else,
  so the order of emission — which is what a psbt's bytes are compared
  against — is a list to read instead of eighty lines of `if` to trace,
  and a new key type is a line rather than a branch. Nothing about the
  bytes changed: every input map of the BIP174 and BIP371 vectors, the
  union of them with the four preimage types no vector carries, and a
  malformed key of every type, all serialize to the same bytes and answer
  with the same message as before. `verify_input` is a third, at 6 where
  it was 25: its reason named BIP16, BIP141 and BIP341 one branch each,
  which is accretion Core answers by splitting, so the witness arms now
  live behind a `VerifyWitnessProgram` of btclib's own and the residue
  reads as Core's VerifyScript — while the two interpreter loops mirror
  EvalScript, which Core itself keeps whole, and stay.
  The rejected sets are recorded with their counts in pyproject.toml, from
  `N` at 498 down to `PERF` at 3, and so is the reason the zero-finding
  ones for constructs this code base does not have — `DTZ` without
  datetime, `G` and `LOG` without logging — were left out: a rule that can
  never fire reads as an enforced invariant while enforcing nothing.
  `check-readthedocs` joins `check-dependabot` on the same argument,
  `.readthedocs.yaml` being 2.7 KB that nothing read as a build definition
- **80 columns on the prose, and the yaml measured for the first time.**
  `ruff-format` reflows code to its 88 columns and never touches a
  comment or a docstring, which is why `E501` is ignored and stays so:
  what it finds is 267 lines no width can break, almost every one a test
  vector, an extended key or a base64 signature. The half of a file the
  formatter cannot reach is the half that carries the reasoning, and
  `max-doc-length = 80` is what measures it — `W505` is already in the
  `W` set and inert without that line, ruff having no default doc
  length, so setting it is the whole of the switch. Fourteen lines were
  over, nine in btclib and five in tests, and each was rewrapped rather
  than exempted. Two of them are values no width holds: an uncompressed
  public key written with blanks in it and a BIP32 extended key, 111
  characters by construction, both in `alias.py`'s list of examples,
  where a second quoted line would read as a second example — so each is
  broken with its quotes left open, the one form that cannot be
  misread as two. A comment ending in a URL is exempt, the amnesty MD013
  gives an unbreakable link: the 20 comments still over 80 columns are
  every one of them a link
- **`yamllint`, and a limit of 100 rather than 80 for a measured
  reason.** It is the third width gate beside ruff and markdownlint, and
  the workflows were the one place a line could grow with nothing to say
  so — 117 columns at the worst. Eighty is what markdown and the Python
  prose get, and the yaml cannot have it: an action pinned to a
  40-character commit SHA with its tag in a trailing comment lands
  between 77 and 92 columns on the length of its name alone, and 31 of
  the 35 `uses:` lines here are at or past 80. That limit reports 27
  lines, 18 of them such a pin, and would be bought with 18 `yamllint
  disable-line` comments — a width rule does not get to break a security
  one, and 100 clears today's longest pin by enough that an action with
  a longer name cannot turn a dependabot pull request red for having no
  defect in it. Two lines were over 100, both shell in `release.yml`.
  `document-start` is on beside it, so every one of the 15 yaml files
  here opens with a `---` on line 1, above its header comment: one line
  each, and the files answer the question the same way instead of each
  beginning however its author left it. The fourteen whose only change
  is the marker parse to the value they parsed to before. The two rules
  of the twelve that fire and stay off are recorded in `.yamllint.yaml`
  with their counts, each reporting a convention rather than a defect:
  `comments` wants two spaces before the `#` on 33 pins where dependabot
  writes one, and `truthy` reads the 6 `on:` keys that open a workflow as
  the boolean they are in yaml 1.1
- **the six hooks commented out in `.pre-commit-config.yaml` are decided,
  four on and two off, and five more are added.** Each was measured
  against this tree rather than argued about. On: `name-tests-test`, at
  its default and with no `exclude`, which is what the rename in the
  Tests group above bought, guarding the one failure a test suite cannot
  report on itself — a file pytest never collects is not a red test, it
  is no test;
  `fix-byte-order-marker`, which finds nothing today and stops an editor
  on another platform adding three bytes tomorrow; and
  `pretty-format-json`, where the objection was its two defaults and not
  the hook. At `--indent=2` it fails on 44 of the 45 json files, the
  golden ones being written at `indent=4`, and with the key sort on it
  reorders a golden file against the insertion order `to_dict()` emits —
  which breaks the suite rather than churning a diff. At `--indent=4
  --no-sort-keys` 39 of the 45 already conform and turning it on rewrote
  nothing. It skips `tests/**/_data/`, the vendored directory, six of
  whose vectors `tests/_data/README.md` declares identical byte for byte
  against an upstream blob SHA that a reformat voids — excluded by
  directory so that the next file vendored in is safe unremembered, bar a
  lookahead for the three files in there that are btclib's own. Off, with
  the measurement written beside each:
  `check-shebang-scripts-are-executable`
  fails on 154 files, every module opening with `#!/usr/bin/env python3`
  as the house header and none of them a script;
  `fix-encoding-pragma` would *add* 155 dead `# -*- coding: utf-8 -*-`
  lines, UTF-8 being the default since Python 3 against a floor of 3.10.
  Added: pre-commit's own
  `check-hooks-apply` and `check-useless-excludes`, which are this file
  checking itself — a `files` pattern matching nothing is a rule that has
  stopped running, issue #145 one level up, and the first thing the hook
  did was reject `check-executables-have-shebangs` from this very entry,
  correctly, nothing here carrying that bit; `check-dependabot`, because
  `.github/dependabot.yml` was validated by nothing and a typo there
  updates nothing and says nothing, which is the whole of issue #158's
  answer failing silently; `check-added-large-files`, which measures only
  files being added, so the 9 MB already vendored passes and the next one
  does not; and `forbid-submodules`, a submodule being the one dependency
  that would be in neither uv.lock nor dependabot nor an sdist
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
  statement count that moves between interpreters: the threshold and the
  interpreter now agree with what a maintainer measures locally with a
  bare `uv run pytest --cov`. The release step only needs a `tomllib`,
  i.e. 3.11 or newer, and now asks for a version uv has already fetched
  for the other jobs
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
  `nonce = int.from_bytes(t, 'big') % ec.n` of the three nonce modules, and
  the `PSBT_*_PROPRIETARY` values deliberately not implemented. Sixteen
  load-bearing TODO/FIXME markers now name a tracked issue instead of a
  wish: #171 (the three point-addition special cases, on the inner loop of
  every scalar multiplication), #172 (rendering a script as `{"asm":
  ..., "hex": ...}`, seven identical markers), #173 (four unfinished PSBT
  behaviours — combining a witness, the Finalizer's sighash check, output
  merging, and a partial signature never checked against its key)

### Documentation and the website

- **The `bms` docstring says the message is signed byte-for-byte, and
  that Electrum's gui disagrees.** btclib does not strip whitespace
  from the message — a signature must commit to the exact bytes — and
  neither does Bitcoin Core, its gui included, nor the Electrum CLI;
  the Electrum gui deliberately strips leading and trailing blanks
  (spesmilo/electrum#4327, closed as intended), so a signature it
  produces over a padded message commits to the stripped text and
  never verifies elsewhere against the original. The docstring names
  the two mutually exclusive pull requests that put both resolutions
  in front of Electrum, spesmilo/electrum#10787 (strip in the one gui
  path that misses it, qml signing) and spesmilo/electrum#10788
  (never strip, matching Core and btclib)
- **Comments and documentation state the present rationale, not the
  story of how the code got here.** A comment that read "this used to be
  X, which broke Y" reads "not X: it breaks Y" now — the rejected
  alternative and its cost stay, the timeline goes, and pure change
  chronicles (old names, refresh sagas, dates of fixes) are deleted;
  regression tests say what they guard against rather than what once
  happened. The sweep also corrected facts that had drifted stale, the
  one a user should note being SECURITY.md's delegation conditions:
  `ssa.sign` reaches the bindings only for a 32-byte message, and the
  file now says so
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
  from docs/source; `tests/docs_test.py` now compares the modules under
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
  Its figures were taken when the suite was 7936 tests, and the suite has
  since nearly doubled: every one of them had stopped being true, the
  slowest test included, and the conclusion moved with them. Bitcoin Core's
  vector files are still not the slow part, but
  `tests/script_engine/python_path_test.py` is — it holds the slowest tests
  in the suite and, on its own, more than half the wall clock. So a `slow`
  marker would save something real, where the section said there was nothing
  to put behind one; none is registered still, and the reason is now stated
  in numbers the file carries and a run can check
- **`assert_nulldata` says which question it answers** (issue #211). The
  rule it applies — OP_RETURN and one minimal push, total length neither
  78 nor above 83 — is standardness policy, and narrower than the
  classification Bitcoin Core's `Solver` performs on every count: Core
  answers NULL_DATA for an OP_RETURN whose remaining bytes pass
  `IsPushOnly`, which refuses only an opcode above OP_16, so a bare
  OP_RETURN, `6a51`, two pushes and a nulldata of any size are all
  NULL_DATA there and `unknown` here. The 83-byte bound is
  `MAX_OP_RETURN_RELAY`, relay policy tested by `IsStandardTx` and never
  by that classifier. Nothing changed but the docstring and a test
  pinning the six divergent shapes, the narrowness being what lets
  `type_and_payload` return one payload at all — two pushes are two
  payloads and a bare OP_RETURN is none — and being the one shape
  `ScriptPubKey.nulldata` builds, so the classifier agrees with the
  constructor. `6a00` is the row that agrees with Core by arithmetic
  rather than by rule, the `00` read here as a zero-length push's marker
  and there as OP_0
- **A link from one root markdown file to another reaches the page that
  renders it** (issue #195). README.md, CONTRIBUTING.md, SECURITY.md,
  HISTORY.md and CHANGELOG.md are included into the documentation
  verbatim, and their `./FILE.md` links came out of the build as
  `href="#./FILE.md"` — an anchor to an id no page has, eleven of them.
  Neither tool that exists to find a broken link could see it: MyST turns
  a target it cannot resolve into that anchor instead of reporting one, so
  `sphinx -W` passed, and lychee reads the sources, where the path is
  right. `docs/source/conf.py` now resolves them against the repository
  rather than against a table — a file one of the `*_link.md` shims
  includes becomes a reference to that page, CODE_OF_CONDUCT.md and
  tests/README.md, which the documentation does not contain, become links
  to the files on GitHub, and a path that exists nowhere is left to MyST,
  whose `myst.xref_missing` suppression is gone, so `-W` fails on the next
  link with no target. The `./FILE.md` spelling in the root files is
  untouched, being what the GitHub file view, btclib.org and the PyPI long
  description need. `lint.yml`'s `Build the documentation` job then greps
  the built HTML for `href="#./`, which asks the same question where no
  suppression can hide the answer
- **Prose spells the language Python.** The name is a proper noun, and the
  tree had it lowercase in 125 lines of prose — docstrings, comments,
  README.md, SECURITY.md, CONTRIBUTING.md and this file — beside the two
  dozen lines that already capitalized it. What stays lowercase is what is
  typed rather than named: the `python` command and the
  `.venv/bin/python` it resolves to, the `python3` of a shebang, a yaml
  value a tool parses (`render:`, `language:`, `shell:`), and every
  identifier the spelling belongs to — `.python-version`,
  `requires-python`, `python_version`, `python_files`, the `python.org`
  host, and the packages whose own name carries it, `python-bitcoinlib`,
  `python-mnemonic` and `python-build-standalone`
