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

- **the Bitcoin Core rpc client is a package of its own**, and btclib
  depends on it rather than carrying it. `btclib/bitcoin_core_rpc.py` was
  one standard-library-only source file that a project could copy whole
  rather than depend on btclib for, which is a distribution shape and not
  a module of a bitcoin library: it is
  [bitcoin-core-rpc](https://github.com/btclib-org/btclib-bitcoin-core-rpc)
  now, and what left with it is the client, its bounded `urllib`
  transport, their tests, the live-node smoke script and workflow, and the
  mutation profile that measured them. What stays is `btclib.fetch`: the
  answers turned into btclib types, and `assert_network`.
  `btclib.fetch.transport` and `btclib.fetch.bitcoin_core` re-export the
  package's names, so every import path a caller had still resolves except
  `btclib.bitcoin_core_rpc` itself.
- **`btclib.exceptions` declares its own six classes again.** They were
  defined in the vendorable file and re-exported here, an exception
  wanting one identity; with the file gone the choice was to import
  btclib's three *base* classes from a protocol client -- which is what
  most of the library would then depend on -- or to declare them here and
  translate at the boundary. `btclib.fetch.fetcher.client_errors` is that
  translation, re-raising the package's `FetchError`, `HttpError` and
  `RpcError` as btclib's with the `status` and the `code` carried across,
  and `args[0]` rather than `str(e)` so a message composed in `__str__` is
  not composed twice. `EsploraFetcher.text` and
  `BitcoinCoreFetcher._call` are the two lines that cross. The package
  spells its own bases `BtcRpcValueError` and so on, where btclib spells
  its `BTClibValueError`: two same-named classes is an `except` that reads
  correct and catches the wrong one, which `assert_network` did until the
  package renamed its three.
- **`import btclib.exceptions` no longer loads `urllib.request`**, nor the
  `ssl` and `socket` under it. That cost was what the one bottom-upwards
  import in the package bought, and most of the library pays it: an
  exception is what most of the library raises. `tests/imports_test.py`
  measures it in a fresh interpreter now rather than pinning its extent.
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
- **Nothing names `TODO.md` any more**, this file excepted, which is where
  history belongs. Retiring it had left the name behind in the comments that
  absorbed its content, in `_config.yml`'s `exclude:` list, and in
  `_config.yml`'s and CONTRIBUTING.md's account of what `btclib.org/TODO`
  once served: each said how the tree got here rather than why it is as it
  is, and what any of them was load-bearing for — that a file in master's
  root is a URL under btclib.org unless `exclude:` says otherwise — is now
  stated in the present tense, with the package itself as the example, since
  `btclib.org/pyproject.toml` is what the list is actually holding back.
  `sphinx.ext.todo` went too: `todo_include_todos` was at its default, so a
  `.. todo::` rendered as nothing at all, and without the extension it is an
  unknown directive that the `-W` documentation build fails on.
- **This file and HISTORY.md state no entry count, and `.gitattributes` marks
  both `merge=union`.** They are append-only lists that every branch appends
  to, so they were the one thing every pull request had to resolve by hand: a
  count is a line all of them edit, and the insertion point is shared by any
  two that add a bullet to the same group. `union` keeps both sides' added
  lines, so neither is a conflict any more. `grep -c '^- ' CHANGELOG.md`
  answers how many entries there are, on demand.
- **The branch rules and the repository settings are in `REPOSITORY.md`**,
  which CLAUDE.md points at rather than carrying: the required checks, both
  branches' protection and why they differ, the read-only `GITHUB_TOKEN`
  default, the review-gated publishing environments and the secret-scanning
  settings that a paid plan gates. They are what a session changing a
  workflow needs first and dead weight in one fixing a bug in `ecc/`, and
  they live *outside* the repository, so that file is the whole record of
  them: nothing in it can be recovered by reading the tree.
  `_config.yml`'s `exclude:` lists it beside CLAUDE.md and RELEASING.md,
  since a file in master's root is a URL under btclib.org otherwise, and a
  branch rule's app ids are not a page a visitor wants.
- **The primary checkout is the maintainer's, and no session works in it.**
  It is their window on the tree — what is open in their editor, what they
  have half-staged, the branch they are looking at — and one working tree
  has one index and one HEAD to lose, so an edit, a `git add`, a branch
  switch, a rebase or a `pre-commit run` there is somebody else's work
  being rewritten. CLAUDE.md now says so, and says that a worktree per
  session is the whole of the alternative: reading the primary checkout
  stays fine, `git fetch` included, since it writes refs and leaves the
  work tree alone. What the advisory lock file it replaces could not do is
  bind a session that never read the file it was described in.
- **A pull request under review is corrected by a commit on top, never by
  an amend, and is merged with "Squash and merge"** (CONTRIBUTING.md's
  "Pull Request" section). An amend and a force-push replace the commits
  the review is attached to: the reviewer loses the diff they read,
  "changes since your last review" has nothing to compare against, and
  every check restarts from a commit nobody has seen. The squash is what
  makes that free — the branch lands as one commit whose subject is the
  pull request title with its number, so `dev` keeps one commit per change
  while the review keeps its own. The one force-push still right is the
  one carrying no new work, a `git rebase origin/dev` on a branch whose
  base has moved.
- **The squash is the merge into `dev`; `dev` goes into `master` with
  "Rebase and merge"**, which CONTRIBUTING.md's "Pull Request" section now
  says, having stated the squash for every pull request alike. A squash on
  that one would fold every change landed since the previous merge into a
  single commit, and the history of them would then be on `dev` alone; the
  rebase replays those commits onto `master`, which the branch rule wants
  linear as it wants `dev` — the same rule that bars a merge commit. All
  three methods are enabled on the repository and GitHub offers whichever
  was used last, so the button is read before it is clicked.
- `.gitignore`'s `btclib-*` pattern is gone. The comment above it named a
  tox process this repository has never run, and the glob matched nothing
  either tracked or produced by the current tooling — a rule matching
  nothing reads as still enforcing something, the same shape CLAUDE.md and
  `check-useless-excludes` already treat as worth removing elsewhere.

### Security

- **`btclib.fetch` follows no redirect, so an rpc credential reaches one
  host** (issue #358). `urlopen` uses urllib's default opener, whose
  `HTTPRedirectHandler` answered a 30x before this module saw a response,
  and it did three things nothing here asked for: `redirect_request`
  copies every header but `content-length` and `content-type`, so the
  `Authorization` built for a node travelled to whatever host the
  `Location` named — a JSON-RPC POST arriving there as a GET; a redirect
  target may be `http`, `https` or `ftp`, so an https request could be
  answered with an http one and the scheme check covered only the first
  url; and `fp.read()` with no argument read the whole intermediate body,
  so `max_body_size` bounded the final response and not the exchange.
  Measured against two local `http.server` instances, the second one
  received the request with `Authorization: Basic YWxpY2U6c2VjcmV0` on
  it verbatim. `urlopen_transport` now does its I/O through an opener
  built without that handler, so a 30x arrives as the `HTTPError` any
  other non-2xx does and comes back as a status with a bounded body,
  which both fetchers already turn into a `FetchError` naming it —
  `getblockcount at http://127.0.0.1:8332: HTTP 302`. Refused rather than
  policed, and the reason is what a policy would have to be: stripping
  credentials across origins, refusing a downgrade, bounding every
  intermediate body and counting hops is a redirect implementation inside
  a module whose subject is one bounded request, where what a same-origin
  redirect would buy is a base url the caller fixes once. `build_opener`
  and not `install_opener`, the default opener being process-wide: a
  library replacing it would decide this for every other user of
  `urlopen` in the program
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
- **the scalar no longer decides how many additions a multiplication
  makes, nor how many windows** (issue #254). Infinity had stopped costing
  less than a point inside the group law, which closed the leak *in* the
  addition; the loops above it still let the scalar say how many additions
  to do at all. `mult_regular_window` is the fixed window with both
  quantities taken away from it: `signed_odd_digits` recodes the scalar
  into digits of `{±1, ±3, …, ±(2^w − 1)}` — the regular recoding of
  Joye-Tunstall, which libsecp256k1's `ecmult_gen` uses too — so no digit
  is zero and every window is one addition and `w` doublings, and there
  are `ceil(ec.scalar_len / w)` windows whatever the scalar, where the
  fixed window has `ceil(m.bit_length() / w)` and so runs one short for a
  scalar one short. Measured over 200 random scalars on secp256k1: 71
  additions and 253 doublings for every one of them, against 68 to 70 and
  251 to 259, and 0.815 ms against 0.812 — uniformity for the price of
  nothing, which is why `_mult` is this now and the plain fixed window
  stays as the didactic one. `curves.mult` on secp256k1 goes through the
  GLV endomorphism, whose two halves now feed
  `double_mult_regular_window` rather than the interleaved wNAFs of
  algorithm 3.77: 79 additions and 126 doublings for every scalar and
  0.589 ms, against 51 to 64, 124 to 131 and 0.509 — 16% for a quarter of
  the work stopping to be a property of the secret. The wNAFs are still
  there and still the default of nothing but themselves: `double_mult`,
  `dsa` and `ssa` verification and public key recovery reach
  `double_mult_w_NAF` directly, their coefficients being a signature and a
  message hash, and `mult_endomorphism_secp256k1(…, regular=False)` is
  algorithm 3.77 as it is written. Two further consequences, one of them
  the point: the accumulator starts at a table entry instead of at
  infinity and no digit names infinity, so the identity is now unreachable
  from the loops rather than merely uniform inside them, and `add_jac`'s
  stand-ins have become belt and braces for callers rather than the thing
  holding a multiplication together; and a scalar's *size* stops being
  visible, which nothing addressed before. What is unchanged is the
  memory access pattern: the table is indexed by a secret digit, which is
  what the FLUSH+RELOAD recovery of OpenSSL's nonces read, and Python
  offers nothing to hide it with — scanning the whole table per window is
  the technique, and it costs the window. `SECURITY.md` said so and still
  does. `CurveGroup` gained `scalar_len`, the bits a scalar of the group
  can have, `p.bit_length() + 1` from Hasse's bound and narrowed to
  `nlen` by `Curve`: it is a count and not a limit, a scalar above it
  being multiplied in the digits it needs

- **a response body is bounded, and the bound is what the answer is**
  (issue #324). `urlopen_transport` read every response with a bare
  `response.read()`, and `EsploraFetcher`'s endpoint is allowed to be a
  public explorer — a host on the internet that says it validated the
  chain — so a malicious or misconfigured one decided how much memory this
  process spent before any parser of btclib's could refuse the answer. The
  socket timeout is no substitute: a peer delivering slowly but steadily
  resets it with every packet. The read is incremental now and stops at
  `max_body_size + 1`, which is the octet that tells a body at the limit
  from one over it; `Content-Length` refuses an over-announced response
  before a byte of it is read, and is never believed, the header being the
  sender's claim about the sender. `DEFAULT_MAX_BODY_SIZE` is twice Core's
  4,000,000-byte buffer bound on a serialized block plus room for a
  proxy's newline, a raw transaction in hex being the widest answer a
  fetcher asks for, and the narrow answers carry their own: 64 octets for
  a tip height, 128 for a tip hash, 1024 for a JSON-RPC reply that is a
  number or a hash. The body of a *failure* is bounded separately, by
  `MAX_ERROR_BODY_SIZE` and by truncation rather than refusal — an
  explorer explaining a 404 in a paragraph of html is worth reading even
  when what was asked for was a height. `HttpTransport` is unchanged, two
  positional arguments as before, which is why the limit is a keyword on
  `urlopen_transport` alone: a transport of a caller's own hands over
  bytes it has already read, so what `http_request` promises for one is
  that an oversized answer goes no further — a bound distinct from the
  one a transport of a caller's own applies to what it holds while
  reading, which it alone can enforce. `BitcoinCoreRpcClient.call` takes
  `max_body_size` too, for the caller invoking `getblock` on a large
  block. The body of an `HTTPError` is closed after that bounded read, a
  response left with octets in it being a `ResourceWarning` out of a
  deallocator later, and the limit itself is refused when it is no size: a
  float would otherwise reach `read` and leave through a bare `TypeError`,
  a negative one would report every body as too large, and zero is a limit
  like any other -- it says that only an empty body is an answer. The check
  is `is_integer`, the predicate of issue #326, so a bool is refused here
  for the reason it is refused everywhere else rather than by a second
  spelling of the rule. A total
  request deadline is a different mechanism and is deliberately not here

### Consensus rules

- **a block has a maximum size, and `Block.weight` is now the block's.**
  Nothing bounded either: `bad-blk-length` — the transaction count and the
  stripped size, each times `WITNESS_SCALE_FACTOR`, against
  `MAX_BLOCK_WEIGHT` — and `bad-blk-weight`, the weight itself, are now
  both checked, the second after the witness commitment because that is
  where Core checks it and for Core's reason: the coinbase witness is not
  covered by the block hash, so a block over the cap only because that
  witness was stuffed must not be refused before the commitment to it has
  been verified. The rules are also what made the property wrong.
  `Block.weight` was the sum of the transactions' weights, which is
  neither of the quantities they read; it is now Core's `GetBlockWeight`,
  the 80-byte header and the var_int holding the transaction count
  included, so 332 more than before for a block with hundreds of
  transactions — 3,954,880 for block 481,824 — and 324 more for a block
  holding one. `Block.stripped_size` is the other quantity, the
  serialization a legacy node relays, and it is the one real blocks sit
  against: 3,954,076 of 4,000,000, 98.9% of the cap. `Tx.weight` is
  unchanged, and `Block.vsize` moves with the weight (issue #278)
- **the signature check operations a block announces are counted, and
  bounded** (`bad-blk-sigops`). Nothing counted them at any level.
  `script.sig_ops.sig_op_count` is Core's `CScript::GetSigOpCount(false)`
  over the bytes of one script, `Tx.sig_op_count` is what
  `GetLegacySigOpCount` sums over every `script_sig` and every
  `script_pub_key`, `Block.sig_op_count` sums that over the transactions,
  and `assert_valid` bounds it by `MAX_BLOCK_SIGOPS_COST` — 20,000 legacy
  checks — last of `CheckBlock`'s own questions, where Core asks it. An
  `OP_CHECKMULTISIG` costs `MAX_PUBKEYS_PER_MULTISIG` however many keys it
  would check: the accurate count is one Core only asks under P2SH and
  segwit, where the script being counted comes from the output being
  spent, so that count and the witness one need the UTXO set and this one
  underestimates exactly as Core's comment on it says. The walk stops
  where the script stops parsing and raises nothing, as Core's `GetOp`
  loop breaks — the coinbase output script of testnet block 987,876 ends
  in an `OP_CHECKSIG` five bytes inside a push that runs past the end of
  the script, and neither implementation reaches it: 0 sigops on both
  sides. The largest count in the suite is block 481,824's 3,409, 17% of
  the cap, so a block that breaks the rule has to be built for the
  purpose (issue #278)
- **a block can be checked against a height and a clock**, which is what
  `BlockContext` carries and `Block.assert_valid_contextual` reads.
  `assert_valid` is Core's `CheckBlock`, what the bytes answer on their
  own, and `Block.parse` calls it with no context to pass — so the two
  rules of `ContextualCheckBlockHeader` and `ContextualCheckBlock` that
  need nothing but a caller now have a carrier rather than being absent.
  `bad-cb-height` is a byte comparison, as Core's is: the coinbase
  `script_sig` must *start with* `CScript() << nHeight`, which
  `bip34_commitment` builds, so a height pushed non-minimally is refused
  although `Block.height` decodes the right number out of it — and for the
  first seventeen heights that encoding is a one-byte op code (`OP_0`,
  `OP_1` to `OP_16`) where `script.serialize([height])` writes a data
  push, which makes them the mainline case rather than an edge: regtest
  has BIP34 in force from height 1. `time-too-new` is
  `BlockHeader.assert_valid_time(now)`, the timestamp against a clock the
  caller supplies and never `datetime.now()` read inside the library,
  which would have one machine accept what another refuses and would make
  the test depend on the day it ran on. BIP34's activation height is a
  field of the context, defaulting to mainnet's 227,931, because the
  activation is itself contextual: block 200,000 commits its height and is
  27,931 blocks below the height Core enforces it from, and four of the ten
  testnet blocks of `blockfilters.json` commit nothing at all. What stays
  out needs the chain and not merely a context — `time-too-old` and
  `bad-txns-nonfinal` are the median time past of eleven ancestors,
  `bad-diffbits` the target of a whole retarget period, `bad-version` two
  more activation heights — and each is a field of `BlockContext` away
  once the chain state it reads is there to put in one. The one `xfail` of
  `tests/block/checkblock_test.py` is a passing vector now:
  python-bitcoinlib's genesis block, two hours and one second ahead of the
  `cur_time` beside it (issue #278)
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
- **a proof-of-work is checked against the network's limit**, and against
  the three other range checks Core's `DeriveTarget` makes before it.
  `BlockHeader.assert_valid_pow` was that hash comparison and nothing
  else, where `CheckProofOfWork` refuses four targets without looking at
  the hash at all: a negative `nBits`, a zero target, one 32 bytes cannot
  hold, and one above `params.powLimit`. btclib made none of them at that
  site — `target_from_bits` raises on the overflow, the zero target was
  refused only by `block_work`, which this never called, and there was no
  pow limit in a function that took no arguments — so a header claiming
  regtest's `207fffff` on mainnet was a mainnet header for half a try's
  worth of work. `assert_valid_pow(pow_limit_bits)` and
  `Block.assert_valid(pow_limit_bits)` now take the network's easiest
  target, `MAINNET_POW_LIMIT_BITS` by default as `next_bits` already took
  it, and each refusal names which of the four it was where
  `DeriveTarget` returns a bare `nullopt` for all of them. The sign bit is
  `proof_of_work.is_negative_bits`, Core's `fNegative`, asked of the four
  bytes because the target is unsigned and cannot carry it. It is a
  parameter of `Block.assert_valid` and not of `__init__`, `parse` or
  `serialize`: those three call it to ask whether the bytes are a block,
  and a block of another network is built with `check_validity=False` and
  then asked, which is the pair of steps a header being mined already
  takes. The zero check is only as good as the target handed to it, which
  is what issue #402 was about: the two `nBits` Core reads as zero,
  `03800000` and `1d800000`, reach it as zero because the significand is
  masked before the value is computed, and
  `tests/block/block_test.py` carries both rows (issue #403)
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
  very thing BIP143 introduced. Legacy p2sh was wrong in the same way,
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
  and `segwit_v0` does not, BIP143 keeping them; and FindAndDelete stays
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
- **the sign bit of `nBits` is a sign, and `target_from_bits` no longer
  reads it as magnitude** (issue #402). The compact form is a float with
  a sign bit: Core's `SetCompact` takes the number out of `nCompact &
  0x007fffff` and reports the bit separately, through the `fNegative`
  out-parameter `DeriveTarget` refuses the header on. btclib read all
  three significand bytes, so every `nBits` with `0x00800000` set
  answered a number no node computes — `0x1d80ffff` put the sign bit
  *inside* the target's own bytes and made it 2^7 easier than the
  genesis one, and `0x03800000`, which Core reads as zero, came back as
  `0x800000`. The mask is Core's now, so `target_from_bits` still answers
  one target and every call site of it is left alone; the sign it hides
  is `is_negative_bits`, which `assert_valid_pow` refuses the header on.
  That predicate reads the magnitude after the exponent, as Core reads it
  for `nWord != 0 &&`, so a sign bit over a significand the exponent
  shifts away is not negative either: `0x018000ff` is zero, as
  `0x03800000` is. `BlockHeader.difficulty` stops redoing
  the compact arithmetic by hand and takes the ratio of two targets, so
  one header can no longer have a `target` and a `difficulty` that
  disagree about which number its `bits` denote; the difficulty of every
  real header is unchanged, and a zero target now answers the "zero
  proof-of-work target" of `block_work` instead of dividing by zero.
  A test walks every exponent against a transcription of `SetCompact`,
  value and both flags, rather than pinning a handful of numbers
- **`Tx.assert_standard` refuses a version outside Core v31.1's relay
  window, not outside the positive half of the four-byte range**
  (issue #387). It read the version as though standardness were "not
  the top bit", so 4 and every value up to 0x7FFFFFFF passed as
  standard where Core's `policy.h` relays 1 through 3 only —
  `TX_MIN_STANDARD_VERSION` and `TX_MAX_STANDARD_VERSION`, the second
  being v31.1's own addition over v27.2's 2, BIP431's TRUC. The window
  is closed on both sides now, `_TX_MIN_STANDARD_VERSION` and
  `_TX_MAX_STANDARD_VERSION` in `btclib/tx/tx.py`, and a test pins both
  accepted endpoints and the first refused value on either side; found
  while reviewing #386

### Malformed input and the exception contract

- **a psbt claiming a version that does not exist is refused as one.**
  `invalid non-zero version: 1` is `invalid psbt version: 1`, and the
  rule behind it is no longer "anything but 0": version 2 is read now,
  and version 1 was skipped by BIP370 rather than left free. The check
  runs on the way in and on the way out whatever `check_validity` says,
  which is new: which fields a psbt is written and read as *is* its
  version, so there is nothing left to defer. Two messages move with the
  unsigned transaction that stopped being a field:
  `mismatched number of psb.tx.vin and psb.inputs` and its `vout`
  counterpart named a disagreement a psbt can no longer hold — its maps
  *are* its transaction — and are now
  `mismatched number of tx.vin and psbt inputs`, raised by `from_tx`
  when the maps it is handed are not one per input and one per output.
  A version 2 psbt whose count and maps disagree is refused by the
  parse instead, for the map that is missing or the bytes left over
- **the last two psbt integer fields read without their width now have
  it** (issue #360). `PSBT_GLOBAL_VERSION` and `PSBT_IN_SIGHASH_TYPE` are
  both a little-endian uint32 in BIP174 and were both read by an unsized
  `deserialize_int`, so a value of no octets, one, two, three or four
  deserialized to the same number and was written back as four: one psbt
  with five encodings, which is the malleability every fixed-width field of
  BIP370 was already held away from and the canonical-serialization rule of
  #322 one level up. `deserialize_sized_int(..., 4)` reads them now, the
  length is refused whatever `check_validity` says — a width is not an
  opinion about what the psbt means — and `_serialize_sig_hash_type` is
  gone, `_serialize_uint32` beside it having written the same four octets
  all along. `psbt_utils.deserialize_int` goes with them: every call site it
  ever had was a fixed-width field read without its width, and the BIPs
  define no psbt integer field that has none, the two counts of BIP370
  being compact size and having `deserialize_count`
- **a version 0 psbt carrying a PSBT v2 field is refused, by name**
  (issue #265). BIP370 lists 0 under "Versions Requiring Exclusion" for
  each of the twelve fields it defines, and btclib filed all twelve
  under `unknown` and round-tripped them byte for byte: measured against
  BIP370's own vectors, twelve of its twenty-four invalid psbts were
  accepted, which is half of them. What made them invisible is what
  `unknown` is for — a type byte nobody has defined is kept and handed
  back — and these are type bytes somebody has defined and forbidden
  here: an input's `0x0e` is `PSBT_IN_PREVIOUS_TXID`, which in version 0
  is read from the unsigned transaction and must not be a field. Each of
  the three maps now carries the table of what its version 2 spelling
  would be, so the refusal names the field rather than the byte —
  `PSBT_IN_PREVIOUS_TXID is not allowed in a v0 psbt` — and `PsbtIn.parse`
  and `PsbtOut.parse` take the psbt version the map belongs to, defaulting
  to 0, the version btclib writes. A version 2 psbt is unaffected and
  still refused for the unsigned transaction it has no field for: reading
  it is the rest of #265, and BIP370's 24 valid psbts are vendored and
  `xfail` against the day it is read. Composed psbts using `0x0f` as a
  spare type byte are the one thing this breaks, `test_missing_script_pub_key`'s
  among them — it types its unknowns `0xf0` now, as the module's other
  fixtures already did
- **an empty witness element no longer reaches a caller as `IndexError`.**
  BIP341 makes the last witness element the annex "if its first byte is
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
- `parse_taproot_bip32` reads a 32-byte leaf hash, the length BIP371
  gives it, instead of 4 bytes. The BIP371 test vectors exercise this,
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
  IndexError: BIP371 writes a PSBT_IN_TAP_LEAF_SCRIPT as the script
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

- **a fixed-width field must hold its bytes, and complete octets must hold
  exactly one object** (issue #322). `btclib/utils.py` states the rule and
  holds the two helpers every `parse` reads it through: `read_exactly`
  refuses a short read and names the field it could not fill,
  `assert_no_trailing` refuses what is left over in an octet string and
  leaves a caller's stream alone. Both faces of the defect were
  malleability rather than a missing check — distinct buffers deserializing
  to one object that serializes back to only one of them. `Tx.version`,
  `Tx.lock_time`, `TxIn.sequence`, `TxOut.value`, `OutPoint.tx_id` and
  `OutPoint.vout` read `stream.read(size)` and took whatever came back, so
  a transaction three bytes short of its lock time parsed into a
  transaction with a lock time three bytes smaller, serializing back
  longer than the buffer it was read from; and `Tx.parse` on octets
  ignored everything after the transaction, so `Tx.parse(raw + b"junk")`
  was the transaction of `raw`. The length checks `BlockHeader.parse` and
  `BIP32KeyData.parse` already had are no longer gated on `check_validity`
  — 70 bytes of a header used to answer a header, its nonce read from no
  bytes at all — which is what `bms.Sig.parse` had right and what the
  comment beside it already said. `Psbt.parse`'s trailing check and
  `psbt_utils`'s private `_read_exactly` are those helpers now, which
  costs the `malformed psbt:` prefix on three messages: `not enough data
  for the psbt map key: 3 bytes instead of 5` and `37 bytes after the
  psbt`. Two codecs are deliberately outside the rule and say so:
  `var_int` and `var_bytes` read one element out of the middle of a
  buffer, which is how `Block.height` reads the BIP34 height out of a
  coinbase script that carries an extranonce after it.
  `tests/parse_contract_test.py` holds the parsers to the rule — every
  truncation of an encoding refused at every offset, under either
  `check_validity`, octets with anything after them refused, and a stream
  left on the byte after the object — and one BIP174 invalid-psbt vector
  is pinned to its own reason at last: the case whose value is not its
  stated size now answers `39 bytes after the transaction` rather than the
  `Missing inputs` that was true of it and not what was wrong with it
- **the three parsers the contract had missed are held to it, and the
  inventory now fails when one is left out** (issue #359).
  `Witness.parse(b"\x00junk")` was an empty witness and dropped the four
  octets, and `PsbtIn.parse` and `PsbtOut.parse` did the same with
  anything after their map's separator — one map with as many encodings as
  a caller cares to append to it, while `Psbt.parse` one level up refused
  exactly that. All three take the stream themselves now and call
  `assert_no_trailing`, so octets are one whole object and a stream is
  still the caller's, which is what leaves `Psbt.parse` reading its maps in
  sequence and a transaction reading a witness per input.
  `BIP32KeyOrigin.parse` requires its four fingerprint octets whatever
  `check_validity` says, the other half of that boundary having been
  unconditional already — `indexes_from_der_path` refuses a remainder that
  is not a whole number of 4-octet indexes. And the test file now walks
  `btclib` for every public class with a `parse` and fails unless each is
  either in the inventory or in a table of exclusions with the reason:
  `Bip21` is text rather than octets, `dsa.Sig` puts Bitcoin Core's
  `strict` flag in front of the rule and says so where it does it,
  `Envelope` writes BIE1's ciphertext between fixed offsets with no length
  in front of it, and `BIP32KeyOrigin` has a valid four-octet prefix and no
  length of its own, so two of the three properties are false of it by
  design
- **an amount validator raises what this library raises** (issue #339).
  `valid_btc_amount` converted with `Decimal(str(amount))` and let
  `decimal.InvalidOperation` out: an `ArithmeticError`, which `except
  BTClibValueError` does not catch and which nobody writes `except
  ArithmeticError` around an amount. The argument is `Any` on purpose, so
  the leak was reachable from ordinary input — `valid_btc_amount("abc")`
  and `valid_btc_amount("1,2")`, the way half the world writes a decimal.
  It answers `invalid BTC amount` now, as `FeeRate.from_sats_per_vbyte`
  already did for a rate. Catching the constructor is not the whole fix:
  `Decimal("nan")` is valid syntax and constructs without a word, and what
  raised for it was the *ordering comparison* in the range check, so every
  spelling of a NaN — `float("nan")`, `"nan"`, `"sNaN"`, `Decimal("NaN")`
  — left through the very line meant to bound the amount. `is_finite()`
  refuses those, which is what that method is there for in the fee rate
  too; an infinity does compare, and the range check refuses it. Beside
  it, `valid_sats_amount` let `int()`'s own refusals out unchanged — a
  bare `ValueError` for `"abc"` and `b"\x01"`, a bare `TypeError` for a
  list, and a bare `OverflowError` for an infinity, which is an
  `ArithmeticError` and so was never caught by `except ValueError` either
  — and each is now this library's counterpart of the builtin it was, so
  what a caller catches does not shrink. A NaN leaves `int()` as a
  `ValueError` where an infinity leaves it as an `OverflowError`; the
  asymmetry is `int()`'s, and both answer `invalid satoshi amount` now

- **a BIP340 signature is sixty-four octets, and no other number**
  (issue #323). `ssa.Sig.parse` read `r` and `s` with two 32-byte reads
  and checked nothing, so sixty-three octets parsed into a signature of
  their own — an `s` read out of thirty-one bytes is below the order, so
  it is a valid scalar — and sixty-five into the signature of the first
  sixty-four, the last byte read as part of nothing. `Sig.parse(b"")`
  under `check_validity=False` answered the `Sig` of `(0, 0)`: a
  signature out of no bytes at all. The length is now checked as
  `bms.Sig.parse` checks its own, whatever `check_validity` says, and
  `bms.Sig.parse` gains the trailing-octets half of the same rule, so
  sixty-six octets are no longer the signature of the first sixty-five.
  The one parser left with a flag in front of that rule is
  `dsa.Sig.parse`, whose `strict` is Core's own
  `IsValidSignatureEncoding` and is documented as the exception it is
  (issue #129). The 65-octet shape this refuses is the one a taproot
  witness carries: BIP341 appends the sighash type, which is a fact about
  the transaction rather than part of the signature, and stripping it is
  the caller's — `signature[:64]`, as `btclib.script.engine.tapscript`
  does once `get_hashtype` has read it
- **a boolean is not an integer quantity, anywhere** (issue #326).
  `bool` is a subclass of `int` in Python, so every field of this library
  whose contract is a whole number took `True` for the number one:
  `valid_sats_amount(True)` was 1, `FeeRate(sats_per_kvbyte=True)`
  constructed a one-sat/kvB rate, `fee_from_vsize(True, rate)` charged a
  virtual byte, and `int(True) == True` slipped through the
  conversion-and-equality check the satoshi validator makes on top of
  that. What makes it worth refusing rather than shrugging at is the json
  boundary: `true` decodes to `True`, so a schema mistake became one
  satoshi, one index or a one-sat/kvB fee rate instead of failing beside
  the input that caused it. `btclib.utils.is_integer` is the decision,
  stated once, and `int_from_json_number` is the same decision where a
  field is coerced rather than checked — `BlockHeader` and `BIP32KeyData`
  coerce, a whole number out of json being free to arrive as `1.0`, and a
  bool is the one thing they refuse instead. `isinstance(x, int) and not
  isinstance(x, bool)` rather than `type(x) is int`, so an `IntEnum` stays
  a number and issue #273 is not answered here in advance. The fields:
  satoshi amounts and the dust threshold they are compared against,
  `FeeRate.sats_per_kvbyte`, virtual sizes, `OutPoint.vout`,
  `TxIn.sequence`, `Tx.version` and `Tx.lock_time` — the last three
  type-checked before their range, as `BlockHeader.assert_valid` already
  checked its own two — a block header's version and nonce, a block
  context's heights, a bip32 key's depth and index, every derivation index
  (`indexes_from_der_path` turned `True` into the index one and
  `str_from_index_int` turned it into the path step `"True"`, `str()`
  rendering a bool as a word), and the output sizes of `bytes_from_octets`
  and `base58.b58decode`, where `out_size=True` accepted a single octet and
  reported a size as checked. The derivation-path sequence is no longer
  coerced with `int()` either: its contract is `Sequence[int]`, so a member
  that is no integer is refused rather than converted. Two things follow
  from accepting an `IntEnum`, and both are in: `str_from_index_int`
  normalizes with `int()` before formatting, `str()` of an `IntEnum` being
  its *name* up to Python 3.10 — a path step of `"Sighash.ALL"` there and
  `"1"` on every later interpreter, which is what the 3.10 cells of the
  matrix caught — and `bytes_from_octets` tells a scalar size from an
  iterable of them before taking `tuple()` of either, a float otherwise
  answering "not iterable", which complains about the wrong thing and from
  outside this library's exception contract. A BTC amount is a
  Decimal quote rather than an integer field, so `valid_btc_amount(True)`
  stays the value error it became in #339. `tests/integer_policy_test.py`
  holds all of them to it, and holds the refusal to the numbers it must
  not take with it

- **CompactSize is one of those integer fields too** (issue #361).
  `var_int.serialize(True)` was the one-octet count one and
  `var_int.serialize(False)` the length zero — the number saying how many
  of something there are, taken from a value that says whether — and
  `var_int.parse(..., max_size=True)` was a cap of one, so a caller who
  meant "no cap" got a `var_int too big` refusal for every count above
  one: a range error for what is a type error, and `true` is what a json
  configuration decodes to. Both entry points go through the `is_integer`
  of #326 and raise `BTClibTypeError`, which also puts a float, a string
  and an arbitrary object inside the exception contract, where
  `bytes([1.5])` and a comparison against a string used to answer from
  underneath the library. An `IntEnum` is still a count, the negative and
  overflow diagnostics are still `BTClibValueError` — both being about a
  value and not a type — and the check on `parse` is on `max_size` alone,
  the octets being read on the hottest path in the library

- **a key derivation function does not answer with an empty key**
  (issue #321). `ansi_x9_63_kdf` checked only that the requested size was
  not above what the hash function can derive, so a negative size made the
  loop empty and the final negative slice returned `b""` — keying material
  the caller never got, reported as success. Zero is refused with it: SEC 1
  3.6.1 states keydatalen as a positive integer, and a caller asking for no
  octets of key has a bug rather than an empty key. A size that is no
  integer reached that same slice and left through a bare `TypeError`
  about slice indices, from underneath the library rather than through its
  own exception contract; it is a `BTClibTypeError` now, `bool` included,
  through the `is_integer` of #326. The bound above is unchanged and its
  message with it
- **`TxOut`'s eight-byte value is read and written as `CAmount`, Core's
  signed `int64_t`, not as an unsigned integer** (issue #388). Every valid
  amount is below MAX_MONEY, hence below 2^63, where the two readings
  agree; `check_validity=False` is what makes the difference observable,
  and it now matches Core rather than a `signed=False` nobody had chosen
  on purpose: eight `ff` octets parse to `-1`, Core's own null-value
  sentinel for the field, instead of a satoshi count twice MAX_MONEY. The
  checked parse still refuses either reading, negative or merely too
  large, and a valid amount serializes exactly as before, the two
  readings not differing below 2^63. The three other places the same
  field goes on the wire move with it, so that one field has one
  reading: BIP143's `amount`, BIP341's `sha_amounts`, and the amount
  ANYONECANPAY writes inline. Each wrote the octets a caller had
  already been handed as a negative integer, so they answered a
  prevout of `TxOut.parse`'s own making with a bare `OverflowError`
  from `int.to_bytes` -- reachable through `sig_hash.taproot`,
  `sig_hash.segwit_v0` and `PrecomputedTxData`, and from outside the
  exception contract. What each commits to is unchanged, `-1` and
  `0xffffffffffffffff` being the same eight octets. Found while
  reviewing #386
- **the hash type the two pre-taproot preimages write is `int32_t
  nHashType`, Core's own parameter type, not an unsigned integer** (issue
  #405). `sig_hash.legacy` and `sig_hash.segwit_v0` are public and take it
  as a plain `int`, and wrote it `signed=False`: `-1` — `ffffffff`, the
  four octets Core's `ss << nHashType` puts there — was an
  `OverflowError` out of `int.to_bytes` rather than a preimage, and so was
  anything from 2^32 up, both from underneath the library rather than
  through its exception contract. Either spelling of a 32-bit word is
  hashed now, the two differing nowhere else either, `-1 & 0x1F` and
  `0xffffffff & 0x1F` being the same 31 that chooses the commitment; what
  the field cannot carry is a `BTClibValueError` naming it, refused before
  the transaction is copied so that the SIGHASH_SINGLE bug cannot answer
  with the constant 1 first. Core's sighash.json carries negative hash
  types among its vectors, `InsecureRand32()` filling the whole word, and
  they go in as Core wrote them where the test had been adding 2^32 to
  each by hand. The seven defined values commit to what they did, and
  `assert_valid_hash_type` stays out of both preimages: without STRICTENC
  the script engine hashes whatever byte a signature carries, so refusing
  an undefined hash type there would refuse preimages consensus asks for
  — that vector file is nothing but undefined ones. Found while auditing
  btclib's consensus types against Core v31.1
- **A version 2 psbt now holds every transaction version `Tx` accepts**
  (issue #404). BIP370 calls `PSBT_GLOBAL_TX_VERSION` a "32-bit little
  endian signed integer" and btclib read it that way, while `Tx.version`
  is unsigned, for the two mainnet transactions `Tx.parse`'s comment
  names; the two readings met in `to_v2`, where a version above
  `0x7fffffff` had no four-byte signed encoding and left through
  `int.to_bytes` as a bare `OverflowError`, from underneath the library
  rather than through its exception contract. The field is unsigned now,
  at the parse and at the serialization both, so `Tx`'s own
  `0 <= version <= 0xffffffff` is the only bound the version has and the
  same four octets mean one thing whichever version of the psbt carries
  them: `ffffffff` reads as `4294967295` where it used to read as `-1`
  and then be refused as `invalid version: -1`. A comment at both sites
  says why the BIP's word is not followed — Core declares
  `CTransaction::version` a `uint32_t` and implements no PSBTv2, so it
  has no counterpart for this field to be aligned with, and a psbt
  version `Tx` cannot hold is of no use whatever the BIP says.
  `PSBT_OUT_AMOUNT` is untouched, the BIP and Core agreeing on `int64_t`
  there. Found while auditing btclib's consensus types against Core
  v31.1, after #388
- **a script number is bounded by the `int64_t` it is**, so
  `utils.encode_num` and `script.serialize` refuse one outside
  `[-2^63, 2^63-1]` with `script number out of range` (issue #406).
  Core stores a `CScriptNum` in an `int64_t` and takes a number into a
  script through `CScript::operator<<(int64_t)`, which has no wider
  parameter; btclib's serializer took an unbounded Python int, so
  `serialize([2**100])` wrote a 13-octet push and `serialize([2**200])`
  a 26-octet one -- pushes no node can have built, and pushes the engine
  refuses on execution anyway, capping every operand at four bytes and
  five for CLTV and CSV. Both extremes still serialize, the most
  negative int64 taking the nine octets Core's `CScriptNum::serialize`
  gives it too, sign-magnitude having no room for its magnitude in
  eight. `utils.decode_num` is deliberately not bounded to match: it is
  the reader, the engine caps an operand before reaching it, and
  `Block.height` decodes whatever a coinbase pushed -- BIP34 in btclib
  being the byte comparison of `assert_valid_coinbase_height`, as it is
  in Core -- so a bound there would refuse a coinbase the network
  accepts. Found while auditing the consensus types against Core v31.1,
  after #388

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
- **`ScriptPubKey` is hashable, and the `TxOut` holding one with it.** The
  class is frozen, which is what makes a hash safe, but it writes its
  `__eq__` by hand — issue #207's comparison by network *type* — and
  Python sets `__hash__` to `None` for any class defining one without the
  other, so `hash(spk)` raised `TypeError: unhashable type`. It reached
  `TxOut` too: frozen, so it *has* a generated `__hash__`, which raised on
  the field it could not hash. An utxo set's key hashed and its value did
  not. `__hash__` is written out beside `__eq__` now, over the same pair
  that one compares — the script bytes and the network type, not the
  network name — so a signet ScriptPubKey and the equal testnet one land
  in the same bucket, and `Script`, which hashes its bytes alone, needs no
  agreement with it: a Script never equals a ScriptPubKey, the generated
  `__eq__` it inherits comparing by exact class. The comment that had
  explained the asymmetry said `Script` defines `__eq__` without
  `__hash__`, which the dataclass decorator makes false, and `tx_out.py`'s
  said Script is unfrozen, which issue #165 made false; both state what
  the code does. `# noqa: PLW1641` goes from the class, the rule finding
  nothing there any more (issue #416)
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
  the PyPI long description at once. The BIP39 wordlists and the
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
- **an exception carrying a field can be pickled and copied**, where
  `HttpError`, `RpcError`, `ScriptError` and `InvalidContributionError`
  answered a TypeError about their own constructor. Each composed its
  message in `__init__` and handed that one string to
  `BaseException.__init__`, so `args` held the message alone, and
  `BaseException.__reduce__` returns `(cls, self.args)`: a class taking
  two or three arguments is not rebuilt from one. `pickle`, `copy.copy`
  and `copy.deepcopy` failed on it alike, and so did a
  `ProcessPoolExecutor` — a fetch fanned out across processes, which is
  the reason `HttpError.status` exists, got a `BrokenProcessPool` and no
  status wherever the node answered 503 and a working pool wherever it
  answered. The four now hand every constructor argument to
  `BaseException.__init__` and compose their message in `__str__`, which
  is what `subprocess.CalledProcessError` and `UnicodeDecodeError` do;
  composing there is the half that keeps a round trip from adding a
  second `(rpc error code -5)` every time. `str(e)` is unchanged; `e.args`
  is the tuple of arguments now rather than a one-tuple of the composed
  message, and `repr(e)` names the fields with it (issue #391)
- `tests/exceptions_test.py`, added for the entry above, carried a
  shebang line and the pre-uv copyright header instead of the one every
  other file states, and its four `parametrize` calls passed the names
  as a tuple where `pyproject.toml` sets `parametrize-names-type = "csv"`
  for a reason: neither had been caught before merging, so `dev`'s lint
  job has been red since.

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
- a curve is now compared by its parameters. `CurveGroup` and `Curve`
  define `__eq__` and `__hash__` over `(p, a, b)` and over those with the
  generator and `(n, cofactor)` beside them — the name is not one of them,
  so SEC 2's secp256r1 equals NIST's nistp256 — where they used to inherit the
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
- **`CurveSubGroup` is gone and `Curve` is the whole of it**, so the two
  classes left are the two the algebra distinguishes. `CurveGroup` is
  every point of the curve: a group that needs be neither cyclic nor of
  prime order, that holds no distinguished point, and whose order is not
  among its data and not computable from them — it is p+1 minus the trace
  of Frobenius, which is point counting rather than arithmetic on `p`, `a`
  and `b`. `Curve` is the cyclic subgroup of prime order n generated by G,
  which is the group every multiplication in btclib happens in. What sat
  between them was a generator without an order, i.e. a cyclic group that
  cannot say how many elements it has, cannot reduce a scalar and cannot
  bound a private key: nothing here took one as an argument, and
  `btclib.curves` never exported the class. Both docstrings now carry the
  algebra, including why n is a parameter of the subgroup rather than a
  computed quantity, and why the constructor's `nG = INF` settles that the
  parameter is the order *only* because n is prime — in general it proves
  no more than that the order of G divides n, and pinning it to n asks for
  `(n/q)G ≠ INF` at every prime q dividing n, which is the factorization
  of n and not a number any curve publishes. A `CurveGroup` also names its
  own class in `str` and `repr`, where both answered `Curve`: eval'ing
  that repr back used to call a constructor four arguments short
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
- **ElligatorSwift, and the x-only ECDH on it** (issue #270).
  `btclib.ecc.ellswift` adds `create`, `encode`, `decode` and `xdh`: a
  public key as 64 bytes indistinguishable from random, which is what
  BIP324's v2 handshake carries so that a key on the wire is not
  recognizable as one. This is the item of issue #128 with no Python to
  delegate — a new capability rather than a replacement — so both halves
  are here, the SwiftEC map in Python and the libsecp256k1 `ellswift`
  bindings dispatched to for secp256k1 exactly as `mult` and `dsa.sign`
  are. The map is held to BIP324's own two vector files, vendored and
  pinned: 76 decode cases, and 32 rows of the inverse times its eight
  `case` selectors, where an empty cell asserts that a case has *no*
  preimage — the half a too-permissive inverse would pass. `create` and
  `encode` have no vector and can have none, one of up to eight preimages
  being chosen at random, and that randomness is the point: an encoding
  derived from the key alone would be recomputable by anyone. So there is
  no deterministic option the way `dsa.sign` takes a nonce — RFC6979
  specifies the nonce it derives and nothing specifies a derivation for
  this — and what the suite asserts instead is the round trip *across*
  the two implementations, each decoding what the other encoded. Two
  details are libsecp256k1's rather than BIP324's, whose reference
  implementation stops at an x-coordinate: the y a pair names is the
  parity of the reduced `t`, and `xdh` hashes both encodings in a fixed
  order with the caller's `party` saying which is its own. The `ec`
  parameter is not decoration — the map wants only `a == 0` and a square
  -3, so the Python path serves the catalogue's other three Koblitz
  curves, and `secp224k1` reaches it through Tonelli-Shanks; a curve with
  `a != 0` is refused by every entry point. Where this stops is
  deliberate: ElligatorSwift is not BIP324, whose transport also wants
  HKDF, ChaCha20-Poly1305 and the packet encoding, and btclib's position
  on shipping a cipher is already on record (issue #210)

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

- **a MuSig2 session is carried out over a psbt** (issue #266, the second
  half): `btclib.psbt.musig2` is BIP373's three roles over
  `btclib.ecc.musig2` — `add_participant_pub_keys` for an Updater,
  `nonce_gen` and `partial_sign` for the two rounds a Signer runs,
  `partial_sig_verify` for what BIP327 asks every signer to check, and
  `partial_sigs_agg` for a Finalizer, which writes the aggregate BIP340
  signature into `PSBT_IN_TAP_KEY_SIG` or `PSBT_IN_TAP_SCRIPT_SIG` and
  drops the session. **The secret nonce is returned to the caller and
  never held** — the `bytearray` `ecc.musig2.sign` consumes and zeroes —
  because a psbt is a file that gets copied and a secnonce that signs
  twice hands out the private key; the same answer serves the
  libsecp256k1 musig module and the threshold signing of issue #257.
  What the psbt says is how the aggregate key reaches the output, and all
  four of BIP373's ways are read off it: the aggregate key as the output
  key, as the internal key with the BIP341 tweak, as a key in a leaf
  script, and as the parent of an internal key derived per BIP328 — one
  plain tweak per step of `PSBT_IN_TAP_BIP32_DERIVATION`. The session is
  keyed as Bitcoin Core keys it, by the aggregate key *as tweaked*, which
  is what the four vectors show and is not the key the participants are
  filed under. Every partial signature BIP373 publishes verifies in the
  session btclib derives, aggregates, finalizes, and the extracted
  transaction passes btclib's own script engine.
- **`finalize_psbt` finalizes a taproot input**, which it never could:
  the witness of a key path spend is the signature, of a script path
  spend the signature, the leaf script and its control block, and each is
  verified against the hash it says it committed to before the witness is
  built. What it used to do with a p2tr input was build a legacy
  script_sig out of `PSBT_IN_PARTIAL_SIG`, which BIP341 gives no meaning
  to; such an input is now refused as "missing taproot signature". Two
  script path signatures are refused as well, the psbt not saying which
  leaf to spend, and so is a leaf script that is not a single key and
  OP_CHECKSIG — what else its witness would carry is not something a psbt
  records.
- `psbt.prevouts`, `psbt.taproot_sig_hash` and `psbt.leaf_script` are the
  three questions that took: the output every input spends, the BIP341 or
  BIP342 hash of an input, and the leaf script a tapleaf hash names. A
  missing utxo raises rather than answering None, which is the honest
  answer for taproot: the hash commits to the amount and script of every
  input, so one missing utxo leaves none of them signable.
- `bip32.pub_key_derivation_tweaks` returns the scalar each step of an
  unhardened public derivation adds. A public child is the parent plus
  `IL*G`, so a path is a list of tweaks — which is what a key with no
  private key needs: BIP328 derives from a MuSig2 aggregate key, and the
  signers apply the derivation as tweaks of the group key.
- **the four MuSig2 psbt fields of BIP373 are fields, in both psbt
  versions** (issue #266): `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS`,
  `PSBT_IN_MUSIG2_PUB_NONCE` and `PSBT_IN_MUSIG2_PARTIAL_SIG` on
  `PsbtIn`, `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS` on `PsbtOut`, each
  keyed as the BIP keys it and each checked for what the BIP says it
  holds — a compressed key of 33 bytes and not an x-only one of 32, a
  participant list that is a whole number of keys in the order
  aggregation used, a 66-byte public nonce, a 32-byte partial signature.
  Every key is parsed as a point besides, which is what Bitcoin Core asks
  of these fields (`IsFullyValid`) and what no vector of the BIP
  exercises. All 14 valid psbts the BIP publishes round trip byte for
  byte, where 12 of them used to come back in btclib's order for
  unknown keys, and all 10 invalid ones are refused, where every one of
  them used to be accepted: an unknown key is given back as it arrived,
  which is the right answer for a type byte nobody has defined and the
  wrong one for four the BIP defines and constrains. A MuSig2 session is
  not driven yet — the fields travel, `btclib.ecc.musig2` is not wired to
  them, and that half of #266 waits on where a secret nonce lives between
  the two rounds.
- **PSBT version 2 is read, written and validated** (BIP370, issue
  #265), and with it the fields that replace the unsigned transaction:
  the transaction version, the fallback locktime, the input and output
  counts and the modifiable flags of the global map; the previous txid,
  output index, sequence and two required locktimes of an input; the
  amount and script of an output. Every valid psbt the BIP publishes
  round trips byte for byte — the 14 of its valid section and 9 of the
  10 in its lock time section, the tenth being the one whose two kinds
  of lock time no single `nLockTime` can satisfy — each lock time case
  computes the value the BIP gives for it, and the 24 invalid ones are
  each refused for what the BIP says is wrong with them, where 11 used
  to be refused for the unsigned transaction btclib required.
- **The unsigned transaction is now computed, and the BIP370 fields are
  what a psbt holds** — in *both* versions, version 0 being a conversion
  at the two edges: `Psbt.parse` takes its `PSBT_GLOBAL_UNSIGNED_TX`
  apart into the input and output maps, and `Psbt.serialize` puts it
  back together. Which is the honest shape, version 2 having no such
  field to keep, and it is the shape that can hold both transactions the
  BIP defines: the one being signed, and the one that identifies the
  psbt, whose sequences are all zero (`Psbt.unique_id`). `Psbt.tx` is a
  property, so it is a copy: writing into it writes into nothing, and an
  outpoint or a sequence is set on the input that holds it.
- **`PSBT_GLOBAL_TX_MODIFIABLE` is honoured by the three helpers that
  change a transaction.** `sort_inputs`, `sort_outputs` and `join_psbts`
  reorder and add, which under BIP370 is a Constructor's work and needs
  the Inputs Modifiable or Outputs Modifiable bit set; the Has
  SIGHASH_SINGLE bit refuses both sides whatever the other two say,
  such a signature committing to the output at its own input's index. A
  version 0 psbt has no such field and no Constructor role, so it
  reorders as it always has. `combine_psbts` takes the AND of the two
  modifiable bits and the OR of the third, so a combine can never hand
  back permission a Signer took away.
- **`combine_psbts` compares BIP370's identifier for a version 2 psbt**
  rather than `psbt.tx.id`: the sequence is a field an Updater may set,
  so two psbts of one transaction can differ by it, and the txid would
  call them two. A version 0 psbt is still compared by the txid of the
  unsigned transaction every copy of it carries. Psbts of different
  versions are refused rather than converted, `to_v0` and `to_v2` being
  where that decision belongs.
- **`Psbt.to_v0` and `Psbt.to_v2` convert between the two versions.**
  To version 2 is the version number alone, every field it writes being
  held already; to version 0 is what version 0 cannot say — the computed
  lock time becomes the fallback, where a version 0 psbt keeps its
  `nLockTime`, and the inputs' required lock times and the modifiable
  flags go, the transaction unchanged by the going.
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
- **`finalize_psbt` writes BIP147's empty push when the script pops one,
  not when a second signature is there.** OP_CHECKMULTISIG pops one
  element more than it reads, whatever the threshold, and BIP147 is the
  rule that the extra element be empty rather than the rule that it be
  there: counting the signatures agreed with the script everywhere but a
  1-of-n, where one signature is a full satisfaction and the witness came
  out an element short of what the script consumes — bytes the psbt round
  trip carries happily and no node accepts. The kind of the script decides
  now, `is_p2ms` read over the witness script where the multisig is wrapped
  in a p2wsh and over the spent script otherwise, which answers a p2pk
  input carrying two signatures as well: that is caller error, and it used
  to get a dummy on top of it. The count survives as the fallback where the
  psbt says nothing, a bare multisig needing no script of its own to be
  finalized, so a missing utxo leaves the number of signatures the only
  evidence there is. All four positions a multisig script can sit in are
  finalized, extracted and run through the engine at both thresholds; and
  `Descriptor.satisfy`, which knows from the descriptor what the finalizer
  had to guess, is now compared against it for a 1-of-3 too — the
  disagreement that found this (issue #305)
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
- **`to_dict` renders a script as `{"asm": ..., "hex": ...}`**, where Bitcoin
  Core's RPC renders one: `TxIn`'s `scriptSig`, `TxOut`'s `scriptPubKey`,
  `PsbtIn`'s `redeem_script`, `witness_script` and `final_script_sig`, and
  `PsbtOut`'s `redeem_script` and `witness_script` — seven fields that each
  used to be the bare hex string. `script.script_to_dict` writes the pair and
  `script.script_from_dict` reads it, so the spelling is decided once:
  `asm` is `parse` joined by spaces, which is `Script.asm` with a space
  between its commands, and it is deliberately not Core's asm byte for byte —
  btclib prints a push as upper-case hex where Core prints one under five
  bytes as a decimal number, and neither spelling is invertible anyway, a
  non-minimal push coming back minimal from both. The round trip is settled
  the only way it can be: `hex` is the script and `asm` is derived from it, so
  `from_dict` reads the `hex` and reconstructs from that alone. It does not
  ignore the `asm`, though — one that the `hex` does not produce is refused,
  `asm does not match hex: 'OP_1' instead of 'OP_DUP OP_HASH160 ...'`, naming
  the one given and the one that would have been used. Ignoring it would let a
  hand-edited `asm` sit in a stored dict describing a script the bytes do not
  hold, and every consumer of the human-readable field — a diff, a review, an
  explorer — would read it as if they did; believing it instead is not on
  offer, asm being lossy. A bare hex string is still accepted on input, which
  is what `to_dict` wrote before, so a dict stored by an older btclib still
  loads: the emission is what changed, and the constructors downstream all
  take `Octets` already. `TxOut.to_dict` also loses `reqSigs`, which was a
  literal `None` in every case: Bitcoin Core removed it from every RPC
  reporting a script in v22 (bitcoin/bitcoin#20286) because it only ever
  answered for a bare multisig — the m of an m-of-n — so a consumer reading it
  as "signatures needed to spend this" read a number that could not know, and
  a p2sh or p2wsh output carries no script to count. `from_dict` never looked
  at the key, so a dict that still has it loads unchanged. Not restyled:
  `taproot_leaf_scripts`, which Core's `decodepsbt` reports as `script` and
  `leaf_ver` rather than as an asm/hex pair, and the `type`, `addresses` and
  `network` that `TxOut.to_dict` keeps beside `scriptPubKey` where Core nests
  them inside it — that flattening is a question of its own, and Core answers
  it with a singular `address` it introduced in the same v22 (issue #172)
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
- **`Psbt` takes the transaction's version where it took the
  transaction, and `Psbt.tx` is a property.** The BIP370 fields are what
  a psbt holds, in either version, so what the constructor takes is
  those: `Psbt(tx, inputs, outputs, version, hd_key_paths, unknown)` is
  now `Psbt(tx_version, inputs, outputs, version, hd_key_paths,
  unknown, fallback_lock_time, tx_modifiable)`, and `Psbt.from_tx` --
  which takes the input and output maps as well now, for a caller who
  already has them -- is the way in from a transaction. Reading
  `psbt.tx` is unchanged; writing into what it returns reaches nothing,
  it being built at every access, so an outpoint is set on the input
  that holds it. `PsbtIn` gains `previous_tx_id`, `output_index`,
  `sequence`, `required_time_lock_time` and `required_height_lock_time`
  and `PsbtOut` gains `amount` and `script_pub_key`, each after the
  fields that were there; both `serialize` methods take a keyword-only
  `psbt_version`, which decides whether those fields are written or
  folded into the unsigned transaction (issue #265)
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
- **A psbt says how large its transaction will be once it is signed.**
  `Psbt.estimated_weight` and `Psbt.estimated_vsize` are `Tx.weight` and
  `Tx.vsize` for a transaction whose signatures do not exist yet — the
  two a fee has to be computed from, and `estimated_vsize` is what
  Bitcoin Core's `analyzepsbt` calls the second. Per input, the cost is
  read off the utxo and the scripts the psbt carries: p2pk, p2pkh, bare
  and p2sh-wrapped m-of-n multisig, p2wpkh, p2wsh, p2sh-p2wpkh,
  p2sh-p2wsh, and a taproot key path whose signature is 64 bytes or 65
  by the sig_hash type the input asks for; an input a Finalizer has
  already been to is measured rather than estimated. Two rules are what
  make the answer honest. A signature is assumed to be 72 bytes, the
  largest a low-s DER signature and its sig_hash byte can be, because
  `r` needs a leading zero whenever its high bit is set — an estimator
  assuming 71 underpays the intended fee rate one transaction in two.
  And an input whose type cannot be read has no estimate at all: no
  utxo, a p2sh with no redeem script, a taproot input carrying three
  leaf scripts and no way to say which will be spent, each raises
  naming the input — `input 1: no witness script` — where guessing is
  guessing low. The arithmetic is checked against transactions that
  were really signed rather than against a table: BIP174's own example
  against the network serialization that BIP publishes, BIP371's key
  path psbt against the signature the next vector carries, and every
  spend of two whole blocks turned back into the psbt it was signed
  from, where the estimate of an input is exactly what the input took
  with each of its signatures at 72 bytes (issue #209)
- **`decode_from_bip32_derivs` takes `check_validity`**, which it used to
  drop: its `master_fingerprint` size check ran unconditionally, so
  `Psbt.from_dict(d, check_validity=False)` raised on a bad
  `master_fingerprint` while every other malformed field of the same
  `d` was accepted for the caller to inspect. `Psbt.from_dict`,
  `PsbtIn.from_dict` and `PsbtOut.from_dict` now pass
  `check_validity=False` into it, matching what they already pass into
  every other nested field they build from a dict; the fingerprint is
  checked, as they are, by `assert_valid_hd_key_paths` inside
  `Psbt.assert_valid` (issue #264)
- **`taproot_bip32_from_dict` checks a `pub_key` against 32 bytes**, where
  it checked it against 4: `master_fingerprint`'s size, copied onto the
  x-only key BIP371 gives as 32 bytes and
  `assert_valid_taproot_bip32_derivation` already checked as 32. So
  `PsbtOut.to_dict` wrote a `taproot_hd_key_paths` that
  `PsbtOut.from_dict` refused with `invalid size: 32 bytes instead of 4`
  — every real taproot output derivation, the json round trip being the
  only path through the function; the binary one goes through
  `parse_taproot_bip32` and was unaffected. It also takes
  `check_validity` now, as `decode_from_bip32_derivs` does since #264, so
  `PsbtOut.from_dict(d, check_validity=False)` defers both size checks to
  `PsbtOut.assert_valid` rather than raising where nothing else in the
  same dict does (issue #311)

### The public API and the module layout

- **Core's chain names are spoken in the module that speaks to Core**, and
  btclib's network names everywhere else (issue #379). The two vocabularies
  name one chain and two of the names differ -- Core's `main` and `test`
  against btclib's `mainnet` and `testnet` -- and nothing paired them, so a
  caller who asked a node which chain it was on could not compare the answer
  to the network they had asked btclib for. `btclib.bitcoin_core_rpc` now
  holds the pairing, `core_chain_from_network` and `network_from_core_chain`,
  each raising on a name it does not know rather than passing it through: a
  chain Core adds later is a failure that names itself instead of a string
  that reaches a node as a port lookup or a directory name. That module's
  own tables are keyed on Core's names too, so
  `BitcoinCoreRpcClient.from_network("mainnet")` is
  `BitcoinCoreRpcClient.from_chain("main")` -- the string `-chain=` takes and
  `getblockchaininfo` reports, which is what a project vendoring that one
  file already has, where btclib's registry is what it does not. The
  translation lives there and not in `btclib.network` because the two words
  are not synonyms: btclib's `network` names the encoding table to encode
  *with*, and answers `testnet` for a signet address on purpose, where
  Core's `chain` is an identity; and because that module imports nothing of
  btclib, `tests/key_io_test.py` reads the pairing for Core's own `key_io`
  vectors without a key-encoding test acquiring `btclib.fetch`. A
  translation of vocabulary and not a promise of availability: v31.1 warns
  that testnet3 is deprecated and will be removed, so `test` is a name Core
  still reads rather than a chain every node still serves.
- **`BitcoinCoreFetcher.assert_network()`** asks the node whether it serves
  the chain the fetcher labels outputs with, and raises when it does not.
  Explicit, and not part of every fetch: it costs an rpc round trip that a
  caller with one node and one chain has no use for, and the answer cannot
  change under a client that goes on pointing at the same node. Worth the
  one call because the failure it catches is silent -- a client built for a
  testnet node, an explicit url with no port default in the way, under a
  fetcher labelled `mainnet` renders a mainnet address for every output it
  fetches, for coins that are not there. Signet is the case a name cannot
  settle, Core reporting `signet` for the default one and for every custom
  one alike: the p2p magic derived from the reply's `signet_challenge` is
  compared with the network's own, which is also what makes a
  caller-registered custom signet checkable (issue #207). A malformed reply
  is a `FetchError` naming the method; a disagreement is a
  `BTClibValueError`, the node being the authority on which chain it serves.
- **`BitcoinCoreRpcClient` is one independently vendorable source file**
  (`btclib/bitcoin_core_rpc.py`), separate from the
  `BitcoinCoreFetcher` adapter that turns its answers into btclib `Tx`
  objects (issue #378). Copying that file now brings everything one call
  needs and nothing from btclib: cookie and Basic authentication, JSON-RPC
  2.0 requests and legacy 1.1 replies, `Decimal` decoding, correlated ids,
  structured `FetchError`/`HttpError`/`RpcError`, bounded urllib reads, and
  the opener that follows no redirect and consults no ambient proxy. The
  transport is not a second copy: `btclib.fetch.transport` re-exports the
  canonical implementation for Esplora and for its existing public seam,
  while `btclib.fetch.bitcoin_core` re-exports the client beside the fetcher,
  so both existing import paths name the same objects, and `btclib.__all__`
  publishes the new module at the root beside them. `btclib.exceptions`
  re-exports the client's exceptions rather than declaring parallel ones, so
  that `FetchError` is one class whichever of the paths a caller imports it
  by -- not across a copied file, whose exceptions are its own module's, and
  which is what a vendoring project catches. The price of that one identity
  is that every import reaching `btclib.exceptions` -- most of the library,
  though not `import btclib` itself -- now loads `urllib.request`, and `ssl`
  and `socket` under it, where before only a caller who fetched did.
  `from_chain` therefore derives the cookie path from the home directory
  **at the call** rather than from a value computed at import: this module
  is what `btclib.exceptions` imports, so an import-time answer would be
  the `HOME` as it stood whenever anything first imported btclib, and an
  unrelated early import is no way to decide which credentials a later
  call sends. Where no absolute home directory can be named -- a container
  run under an arbitrary uid, where `Path.home()` raises, or a relative
  `HOME`, where it does not -- it refuses, naming `cookie_path` as what to
  pass, rather than reading `~/.bitcoin/.cookie` against the working
  directory; and it derives nothing at all when a `user` or a `password`
  says who is calling, the constructor being where the pair is held
  together. `DEFAULT_DATADIR` stays as the location taken at import, for a
  caller who wants to name it, and is declared `Path | None` for the same
  host: the alternatives were a `Path` that lies or the relative one.

  Reviewing it turned up a set of refusals and normalizations, each of them
  a request this client used to build or an answer it used to let past.
  Neither half of the credential may be something other than a string: a
  `bytes` or an `int` user used to leave a bare `TypeError` from underneath
  the library, and a list passed every check and was formatted into the
  credential, reaching the node as a username nobody wrote. None of these
  refusals quotes back what it refused, which is the rule `_checked_url`
  already followed for a url carrying userinfo: the type is named, the value
  is not, and a rejected credential therefore stays out of the traceback and
  out of whatever log renders one. A
  colon in `user` is refused: the `Basic` credential is `user:password` and
  Core splits it at the first colon, so `user="alice:admin"` authenticated
  as `alice` with the password `admin:secret` -- a different rpc user and a
  different `-rpcwhitelist` than the caller wrote, and no error anywhere. A
  `method` that is not a string is refused, where `call(7)` used to send
  `"method": 7`. `data=b""` is a POST, the truth of the bytes not being what
  makes a body: an empty one built a GET, which Core answers with "method
  not allowed". `http.client.HTTPException` -- `IncompleteRead` from a
  chunked body that stopped early, `BadStatusLine` from a peer that is not
  speaking HTTP -- is a `FetchError` like every other failed exchange, where
  it used to escape `except OSError`, no relation of it; and a
  `decimal.InvalidOperation` from the exact-decimal parser, which is what
  `1e999999999999999999999999999` is, joins the bodies that cannot be read.
  A number in a reply is checked for being finite rather than trusted to
  raise, because `parse_float=Decimal` builds it in the *caller's* decimal
  context: with `InvalidOperation` untrapped that same exponent came back as
  `Decimal("NaN")` -- an amount comparing false against itself forever, past
  the refusal of NaN this client documents, with nothing raised anywhere to
  normalize. Size is deliberately not the question: a finite number is an
  answer however large, which is what leaves the pure-Python `decimal` of
  another interpreter free to build what libmpdec declines to.
  Finally, an object that is no reply keeps the status it arrived with: a
  `"jsonrpc": "1.0"` marker beside a 503, and a correlated legacy `error`
  that is not an error object, used to lose `HttpError.status` -- while a
  genuine legacy rpc error under Core's HTTP 500 is still `RpcError`, which
  is the precedence that matters.

  The standalone file
  carries its MIT notice and an
  update recipe based on release tags; a subprocess test copies it alone and
  imports it with site packages disabled before exercising a `Decimal`
  result and both RPC and HTTP error fields. Its module documentation also
  spells out the migration from python-bitcoinrpc's `AuthServiceProxy`:
  method attributes become explicit `call` arguments, credentials leave the
  URL, batches and notifications are deliberate non-goals, and a caller --
  not the client -- owns any retry.
- **`btclib.descriptors` reads a descriptor and derives its scripts**,
  where it used to compute the checksum and nothing else. `parse` returns
  a `Descriptor`, one class per grammar function, and
  `script_pub_keys(index)` answers with the `ScriptPubKey` set that the
  descriptor pays to at that index — with the address of each, where the
  script has one. The grammar is BIP380 to BIP386 and BIP389 minus
  miniscript: `pk`, `pkh`, `wpkh`, `combo`, `sh`, `wsh`, `multi`,
  `sortedmulti`, `addr`, `raw`, and `tr` with a key path and a tree of
  `pk()` leaves; key expressions cover hex keys compressed, uncompressed
  and x-only, WIF, xpub/xprv with a derivation path, key origin, the `/*`
  and `/*h` wildcards and both hardened markers, and
  `multipath_descriptors` expands the BIP389 `<a;b>` form into the
  descriptors it stands for. `strip_checksum` and `add_checksum` are the
  two halves of the checksum a caller needs, and `parse` verifies one
  that is there. Every position rule is enforced rather than assumed —
  `sh()` at the top level only, no uncompressed key inside a witness
  program, x-only only inside `tr()` — and what is not implemented raises
  NotImplementedError naming what it is: miniscript is issue #187,
  `multi_a` and `sortedmulti_a` are BIP387, `rawtr` is BIP386 and
  `musig` is BIP390. The derivation is checked against Bitcoin Core's
  own `descriptor_tests.cpp` vectors, both spellings of each, so a WIF
  and an xprv are checked to reach the script their public halves reach
  (issue #186)
- **`Descriptor.satisfy` spends what `script_pub_keys` receives into**:
  given a mapping from public key to signature — the shape
  `PsbtIn.partial_sigs` has — it returns the `script_sig` and the
  `Witness` an input spends with, one of the two always empty. Keyed by
  key and not a sequence because the order the signatures go in is the
  descriptor's knowledge and not the caller's: the key order for
  `multi()`, the sorted order for `sortedmulti()`. It is one method per
  fragment class over one notion of a satisfying stack, so `sh()` appends
  the redeem script to what its argument produced and `wsh()` appends the
  witness script to its argument's stack. `tr()` is satisfiable on both
  paths — the key path preferred where both are offered, as Bitcoin Core's
  finalizer prefers it, and the script path's control block computed from
  the tree the descriptor holds, which is the one thing satisfaction here
  knows that `finalize_psbt` has to be told. Three refusals, each a
  `BTClibValueError` and not the `NotImplementedError` the parser raises
  for what a later release adds: `addr()` and `raw()` name a script and
  not the key that spends it, and `combo()` is four scripts, so which one
  is being spent is the caller's to say. A signature short of what the
  script pops is an error too, `PsbtIn.partial_sigs` being where a spend
  waiting for its second signature belongs. `satisfy` assembles and does
  not verify, having no transaction and therefore no sig_hash to check
  against; the test suite checks it against `finalize_psbt`, which does
  have one, and the two build the same bytes for every shape both can
  express (issue #263)
- **`Descriptor.update_psbt` is BIP174's Updater**: it returns the psbt
  with one input told what the descriptor knows — the redeem script of a
  `sh()`, the witness script of a `wsh()`, the internal key, merkle root
  and leaf scripts of a `tr()`, and the origin of every key that carries
  one, which is what `KeyExpression.origin` is kept for and what nothing
  carried into a psbt before. A copy, the psbt handed in left alone, as
  `finalize_psbt` returns one. That completes the pipeline BIP174
  describes with a btclib call for each role: the descriptor updates,
  signers fill `partial_sigs` in any order and at their own pace, and
  `finalize_psbt` assembles — so a 2-of-3 waiting for its second
  signature is handled without `satisfy` having to answer with bytes that
  do not spend. The taproot half is the one an Updater is needed for
  rather than convenient: a control block holds the merkle path from its
  leaf to the root, so a psbt handed one leaf cannot work out another,
  and `TrDescriptor.taproot_leaf_scripts` and
  `TrDescriptor.taproot_merkle_root` are public for the same reason. The
  three `satisfy` refuses are refused here too, for a reason of their
  own: `addr()` and `raw()` hold no key and no script below the one the
  utxo already carries, so an Updater over either would fill nothing and
  report that it had, and `combo()` is four scripts of which only one is
  being spent. A key with no origin is skipped rather than refused, the
  field being keyed by key. `taproot.leaf_hash` is new beside it, the
  BIP341 tapleaf hash that `tree_helper`, `check_output_pubkey` and the
  psbt's own `leaf_script` each used to compute for themselves (issue
  #306)
- **`btclib.fetch` is new, and is the one package that goes out to the
  network.** `Fetcher` is three questions the library cannot answer from
  bytes it was handed — the transaction with this id, the output an
  outpoint names, the chain tip — and it is implemented twice, so calling
  code takes a `Fetcher` and never branches on which one it got:
  `BitcoinCoreFetcher` over a full node's JSON-RPC, and `EsploraFetcher`
  over a block explorer's HTTP api for anyone without a node. What comes
  back is `Tx` and `TxOut`, not the dicts the backends send, and the
  outputs are labelled with the fetcher's network, which `Tx.parse`
  cannot do — a serialization carries a script and no chain. It adds no
  dependency: `urllib.request`, `json` and `base64` are the whole client,
  because a cryptography library that pulls `certifi`, `urllib3` and
  `idna` in for an optional convenience has charged every other user for
  it. The JSON-RPC is 2.0 rather than the legacy 1.1 a node answers by
  default, so that a routine "no such transaction" is an HTTP 200 with an
  `error` member instead of the 500 a real server fault also sends; a 1.1
  reply from a node older than v28 is still read, and which of the two a
  reply is decides where an error may legitimately come from — under 2.0
  a non-200 is the HTTP exchange failing and never the node's answer.
  `BitcoinCoreRpcClient` calls any method, not only the three, and is an
  implementation of the protocol rather than a port of
  python-bitcoinrpc's `AuthServiceProxy`, whose lineage is LGPL where
  btclib is MIT. It takes either of json-rpc's two parameter structures —
  a sequence positionally, a mapping by name, which covers Core's `args`
  convention too — a distinct request id per call that the reply has to
  echo back, and a `request_timeout` of its own for the methods that run
  for minutes. Amounts never pass through binary floating point: a number
  in a reply decodes as a `Decimal`, a `Decimal` parameter is refused
  rather than rounded, and `NaN` and `Infinity` are refused in both
  directions. The parameters are checked whole and not at the top level
  only, because `json.dumps` *rewrites* a mapping key that is not a
  string — `{1: "a"}` would reach the node as `{"1": "a"}` — and reports
  a structure containing itself as the same kind of error a non-finite
  number is. `for_wallet` is the `/wallet/<name>` endpoint of a
  multi-wallet node, percent-encoded. Credentials in the url are refused,
  as are a query, a fragment and a missing host; credentials and a cookie
  path are mutually exclusive rather than silently ranked; and bitcoind's
  `.cookie` — re-read at every call since a node restart rotates it,
  bounded, and required to be one ascii line — means there need be no
  password at all. The client holds no chain, so
  `BitcoinCoreFetcher(client, network=...)` owns btclib's label and a signet
  of one's own is an explicit url rather than a name this package has to
  know. `FetchError`, `HttpError` with the HTTP status and `RpcError`
  with the node's code and optional `data` are in `btclib.exceptions`
  with the rest; the status is a field because btclib retries nothing on
  its own — `call` carries any method, so it cannot know that re-sending
  one is safe, and a timeout is not a deadline — and a caller's policy
  for a 503 from a full work queue wants the number rather than a message
  to match on. A body that is no reply keeps the status too — one that no
  parser can read, and one that parses into something which is not a
  reply object — since neither can be an answer the node computed: what
  is reported is the 401 or the 503, not the encoding of whatever
  answered in its place. No ambient proxy
  is consulted either — `urllib` would otherwise route the request, and
  with it the `Basic` credential, through whatever host `HTTP_PROXY` names
  in a shell that set it for something else. No endpoint is a
  default: `BLOCKSTREAM_INFO` is a constant to pass, never a host btclib
  contacts on its own. Nothing here is tested against a live host —
  `HttpTransport` is the seam, and every test answers from a recorded
  body — and nothing below it imports it, so a user who never fetches
  never runs a line of it. `Tx.fee` and `OutPoint.value` were dropped
  pending this and are not restored by it (issue #185)
- **`tx_or_psbt_from_any` parses whatever the caller has**: hex, base64
  or bytes, answering with a `Tx` or a `Psbt`. Which of `Tx.parse`,
  `Psbt.parse` and `Psbt.b64decode` applies was something a caller
  holding one of them had to know first, and it is a question with an
  unambiguous answer — BIP174's five-byte `<magic>` is what a psbt
  begins with and what a transaction cannot, which is the whole reason
  the `0xff` is in it. The new `btclib.tx_or_psbt` sniffs and delegates,
  reading no byte either parser reads: hex before base64, because a
  hex-string whose length is divisible by four is also base64 of
  something else, and bytes are text when they are ascii and decode as
  either, so that `Path.read_bytes` needs no encoding argument to go
  with it. A top-level module rather than one inside `psbt/`, its answer
  being one or the other and `tx` not being allowed to import `psbt`
  (issue #209)
- **twelve BIP39 word-lists ship, where two did.** `en` and `it` were the
  whole of it, so a Spanish or Japanese mnemonic — one every wallet reads
  — was a mnemonic btclib could not. The ten of
  `bip-0039/bip-0039-wordlists.md` are here, `cs`, `en`, `es`, `fr`,
  `it`, `ja`, `ko`, `pt`, `zh` and `zh_tw`, and beside them the `ru` and
  `tr` of `trezor/python-mnemonic`, which the BIP's own word-list page
  does not carry: they are in the reference implementation, so they are a
  way to *read* what it writes rather than a language to reach for when
  generating — the BIP strongly discourages generating in anything but
  English. `zh` is Simplified, which is also the Chinese electrum reads.
  All 288 vectors of the reference implementation pass, where only the
  24 English ones used to be run
- **a BIP39 mnemonic is NFKD-normalized, and so is its passphrase.** The
  BIP asks for it and `seed_from_mnemonic` did neither, which is a wrong
  *seed* rather than a rejected input: the accented spanish word a user
  types is precomposed, the word-list is decomposed, and PBKDF2 over the
  two is two different keys. The 24 japanese vectors bip-0039 cites
  beside its own — `bip32JP/bip32JP.github.io`, passphrase
  `㍍ガバヴァぱばぐゞちぢ十人十色`, the case the BIP calls "heavily
  normalized symbols" — now pass, and a japanese mnemonic is joined with
  the ideographic space U+3000 as the reference implementation joins it
- **the language of a BIP39 mnemonic can be read off its words.**
  `bip39.lang_from_mnemonic`, and `lang` defaults to `None` — meaning
  "work it out" — wherever a mnemonic is read rather than written.
  `seed_from_mnemonic` needed it: it verified the checksum against
  English whatever the sentence, so every non-English mnemonic was
  refused by a check that was reading the wrong word-list. Two steps,
  because neither settles every sentence on its own: the word-lists
  holding every word, then the checksum among those. English and french
  share a hundred words at different indexes, so a sentence over those
  alone is valid in both and spells a different entropy in each — that
  one is refused, the caller naming the language being the only honest
  answer. Simplified and Traditional Chinese share 1275 words and, unlike
  every other pair, share the *index* of each: an ambiguous chinese
  sentence spells one entropy either way, so it is answered rather than
  refused
- **electrum's five word-lists are all here, Portuguese included**, and
  that last one is why `electrum.py` has an `ELECTRUM_WORDLISTS` of its
  own rather than sharing `WORDLISTS`: electrum's Portuguese is Monero's
  list, 1626 words rather than 2048, so `pt` names one word-list in
  `bip39.py` and another in `electrum.py`. 1626 is not a power of two, so
  an index into it is not eleven bits and the entropy is a base
  conversion and nothing else — bits per word is 10.667 and the sentence
  is thirteen words, which is what makes a "2fa" mnemonic impossible in
  Portuguese and possible in every other language. Electrum's own
  `bip39_is_checksum_valid` is reproduced with it, arithmetic and all,
  rather than delegated to `bip39.py`: electrum hands that function
  whichever word-list the language has, and the candidates it makes
  electrum skip are what shape the sentence electrum returns. The other
  four are BIP39's files after NFKD, byte for byte, and the remaining
  seven languages stay available as btclib's extension, unreadable by
  electrum — which is what Italian already was
- **a word-list that fails to load is not registered.** `load_lang`
  recorded the language before reading the file, so a file it then
  refused — 2047 words, say — left a language behind that raised on every
  later call. Nothing noticed while the only reader named its language;
  `lang_from_mnemonic` asks every language in turn, and one such
  leftover made every mnemonic unreadable. The word count check is a
  policy of the registry now (`power_of_two`), not of the loader, which
  is what lets electrum's 1626 words load where BIP39's eleven bits per
  index cannot allow it
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
  The escapes are checked as syntax before they are decoded as text
  (issue #362), which is a second fault and not the one `errors="strict"`
  answers: that flag is the error handler of the utf-8 decode *after* the
  unescaping, so it refuses `%FF` — an escape of an octet that is no text
  — and says nothing about `%ZZ`, `%G0` or a trailing `%`, which `unquote`
  leaves as literal text. Left as text they would not round trip, a
  literal percent sign being written back as `%25`: `label=%ZZ` came out
  as `label=%25ZZ`, two URIs meaning one request with only one of them
  written. Every `%` must be followed by two hexadecimal digits, in a
  parameter name as in a value.
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
  taproot input, BIP341 committing to the position rather than truncating
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
- **`dsa.sign_recoverable` and `dsa.sign_recoverable_` are new**: the
  signature `sign` gives, and beside it the `key_id` that
  `recover_pub_key` takes to answer the signer's own public key — the
  value a message signature's recovery flag carries. A spelling of its own
  and not a `recoverable=True` on `sign`, as libsecp256k1 has
  `ecdsa_sign_recoverable` beside `ecdsa_sign`: a second argument changing
  what is returned would multiply into four return shapes with
  `commit_hash`, which is also why no commitment is taken here. Nothing
  stops one being added later — the commitment path of `sign_` tweaks the
  nonce and then calls the same signing body, so the key_id is already
  computed there — and a keyword-only argument can be added compatibly
  where removing one cannot. The key_id is public information either way,
  derivable from any signature by recovering the four candidates and
  seeing which is the signer's, so the recoverable spelling publishes
  nothing the plain one keeps. `docs/source/guide.rst` has the round trip
  as a worked example, next to `sign` and `verify` (issue #285)
- **`btclib.script` exports both halves of every pair it exports one of**:
  `addresses` beside the `address` that was there, and `is_segwit` with
  `assert_segwit`, which were the one missing pair of the nine
  `script_pub_key` defines — the file already carries a comment recording
  that this audit was run once, for `is_p2pkh`, and it caught eight of the
  nine. `tests/all_test.py` now asserts the pairing itself rather than a
  list of names, so a script type added to `script_pub_key` has to bring
  both halves, and `test_every_exported_name_exists` walks every package
  of the library rather than the four it named: a package added to btclib
  is a package it checks, and it is what found `btclib.script` outside the
  list.
- **`btclib.curves` exports `CURVES`**, the catalogue every curve other
  than secp256k1 is looked up in. `secp256k1` was exported by name and the
  dictionary it comes from was not, so the package's own docstring named
  the catalogued curves while a caller could reach exactly one of them
  without importing `btclib.curves.curve` — which is where the test suite
  takes `CURVES` from, that being the only place it was available. The
  four catalogues it is the union of, `SEC2v1`, `SEC2v2`, `NIST` and
  `Brainpool`, stay unexported: which standard a curve comes from is a
  question about a curve, not a way of finding one.
- **`btclib.ecc` names its three nonce modules and no longer exports
  `bip340_nonce_`.** The package docstring lists "the RFC6979, BIP340 and
  sign-to-contract nonces" among what it holds, and `__all__` carried one
  of the three, as a loose function — the very shape the docstring says
  the list is not for, since it advertises a helper instead of the scheme
  behind it. `bip340_nonce`, `rfc6979_nonce` and `commit_nonce` are now in
  it as modules, beside `dsa` and `ssa`, and so is `dh`, whose two
  functions were exported while the module they come from was not. What
  went is the trailing-underscore spelling: `bip340_nonce_`,
  `rfc6979_nonce_` and `commit_nonce_` take a message already reduced to a
  scalar and an explicit curve, which is the expert door of the module
  that defines them — `dsa.sign_` and `ssa.sign_` are not exported either
  — so `from btclib.ecc import bip340_nonce_` is now
  `from btclib.ecc.bip340_nonce import bip340_nonce_`, which is where the
  rest of the tree already took it from.
- **`btclib.block` exports
  `merkle_root_and_mutated_from_transactions`**, beside the
  `bip34_commitment` defined next to it: both are what a header commits
  to, and this one is the single implementation the builder and the
  validator share — `mining.candidate_block_header` builds a header from
  it and `Block.assert_valid` compares the header against it. A caller
  checking a block by hand needs that function and not a second one
  written from the BIP, which is what having to reach into
  `btclib.block.block` for it invited. The comment recording why
  `btclib.block.limits` stays out now records this too.
- **`btclib.bip32` records why `slip132` is not in its `__all__`.** It is
  the one submodule of that package that sits *above* the address
  encodings — it imports `b58` and `b32`, which import `to_pub_key`, which
  imports `btclib.bip32` — so naming it there means importing it there,
  and that is a cycle: every caller then gets `cannot import name
  'BIP32Key' from partially initialized module 'btclib.bip32'`, which
  `tests/imports_test.py` reports by importing each module with nothing
  else in `sys.modules`. `from btclib.bip32 import slip132` works
  regardless — a submodule does not need its parent's `__all__` to be
  importable — and is what every caller in the tree writes. What was
  missing is the reason, which is now beside the list, with the
  observation that `btclib.bip44` has the same shape and lives at the top
  level for the same cause.
- **`btclib.fetch` states what it exports and what it keeps out.** The
  docstring explained the design of the package and said nothing about its
  public surface, where `btclib.curves` and `btclib.block` each record
  theirs. `cookie_auth` stays out because `BitcoinCoreRpcClient` takes a
  `cookie_path` and reads that file at every call, the node rewriting the
  cookie whenever it restarts: a caller passes the path and never the
  credential, and a name for reading one is a way to hold it longer than
  the node does. `fetch_errors`, `tx_from_raw`, `tx_id_hex` and
  `tx_for_network` stay out because they are what an implementation of
  `Fetcher` is built out of, which is a third implementation's question
  rather than a caller's. The transport seam is in, and the reason is now
  written down: it is how calling code is tested without a node.
- **`btclib.mnemonic` names `entropy` and `mnemonic`**, the two modules the
  three schemes are built on: the first turns dice rolls, bytes, an int or
  a bit string into the entropy a sentence encodes, the second is the word
  list and the index codec over it. They were the two submodules of the
  six that the list left out — `bip39`, `electrum`, `slip39` and
  `dispatch` were named — so what they hold and the package does not
  re-export flat, `WordLists` and `data_file` among it, had no named way
  in. `tests/all_test.py` now finds the submodules rather than listing
  them, so one added to the package is one it asks about.
- **`btclib.psbt` exports the format and the roles, not the plumbing of
  the file format.** Nine names came from `psbt_utils` —
  `serialize_bytes`, `deserialize_int`, `deserialize_map`,
  `deserialize_tx`, `encode_dict_bytes_bytes`, `decode_dict_bytes_bytes`,
  `serialize_dict_bytes_bytes`, `serialize_hd_key_paths` and
  `assert_valid_unknown` — which is how one field of one map is written and
  read, called by `psbt_in`, `psbt_out` and `psbt` and by nothing outside
  the package: there were more of them in `__all__` than there were names
  for the psbt itself, `encode_dict_bytes_bytes` listed twice among them.
  Each is still importable from `btclib.psbt.psbt_utils`, which is where
  the test suite already took the other half of that module from — and one
  test file was importing `serialize_hd_key_paths` from the package and
  `deserialize_map` from the module, in the same import block.
  Two names arrive: `prevouts`, the outputs a psbt spends, and `musig2`,
  named as a module because BIP373 is a role rather than a function, the
  way `btclib.ecc` names `dsa`. The package docstring records both
  decisions, and `tests/all_test.py` pins the list and checks the nine are
  still where they are defined.
- **`btclib.base58` exports `encode` and `decode`**, where it exported
  `b58encode` and `b58decode`. The module name already carries the prefix,
  and `btclib.bech32` — the sibling codec, `btclib.b32`'s bitcoin semantics
  on top of it the same way `btclib.b58` sits on `base58` — defines `encode`
  and `decode` with no prefix at all; `base58.b58encode` was the one pair
  that stuttered. The two call sites where both codecs are in scope,
  `btclib/b58.py` and `btclib/to_prv_key.py`, import the pair aliased —
  `from btclib.base58 import decode as b58decode, encode as b58encode` —
  so the distinction is spelled where it is needed rather than at every
  use. `BIP32KeyData.b58encode`/`.b58decode`, `bms.Sig.b64encode`/
  `.b64decode` and `Psbt.b64encode`/`.b64decode` are methods and keep
  their prefix: on a class it says which encoding the object serializes
  to, distinguishing it from `serialize`, rather than repeating the
  module's own name (issue #335)
- **`btclib.descriptors` exports `checksum` and `from_address`**, where it
  exported `descriptor_checksum` and `descriptor_from_address`. The
  inconsistency was inside the one file: `add_checksum` and
  `strip_checksum` already take a descriptor and return one without
  repeating "descriptor" in their names, while the function that computes
  the checksum did. Qualified, the four now read `descriptors.checksum`,
  `descriptors.add_checksum`, `descriptors.strip_checksum`,
  `descriptors.from_address` — one vocabulary instead of two.
  `strip_checksum`'s local variable holding the parsed checksum is
  `given_checksum` now, `checksum` being the function's name (issue #336)
- **`tx.join_txs` is `tx.join`, and the psbt trio drops its suffix too**:
  `psbt.combine_psbts` is `combine`, `psbt.join_psbts` is `join`,
  `psbt.finalize_psbt` is `finalize`. Qualified, the suffix only repeated
  the package — `tx.join_txs(...)`, `psbt.finalize_psbt(...)` — and the
  package name is already the qualifier a reader needs.
  `psbt.extract_tx` keeps its name: it is the one of the four whose
  suffix names what comes *out* rather than what goes in, and
  `psbt.extract()` would leave a reader to guess whether a transaction
  or a signature comes back. `tests/tx/tx_test.py::test_join` and
  `tests/psbt/psbt_test.py::test_join` are the renamed test functions
  (issue #337)
- **`btclib.bip32.slip132` is `btclib.slip132`.** It is the one submodule
  of `bip32` that sits *above* the address encodings — it imports `b58`
  and `b32`, which import `to_pub_key`, which imports `btclib.bip32` for
  `BIP32Key` — so naming it in `bip32.__all__` closes an import cycle:
  `from btclib.bip32 import slip132` added to the package raises
  `ImportError: cannot import name 'BIP32Key' from partially initialized
  module 'btclib.bip32'`, which `tests/imports_test.py` is what reports.
  `btclib.bip44` has exactly the same shape for the same reason — it
  needs `script.taproot`, which `bip32` may not import either — and
  already lives at the top level; `slip132` now does too, which makes
  every remaining submodule of `bip32` sit below the address encodings,
  a rule rather than an exception. `from btclib.bip32 import slip132`
  is gone with the move; `from btclib import slip132` is the spelling
  this module's own test file, `docs/source/guide.rst` and every other
  caller in the tree now use (issue #340)
- **Every top-level module declares `__all__`**, where every package
  already did and no module did: `alias`, `amount`, `b32`, `b58`,
  `base58`, `bech32`, `bip21`, `bip44`, `descriptors`, `exceptions`,
  `fee`, `hashes`, `keystore`, `network`, `number_theory`, `slip132`,
  `to_prv_key`, `to_pub_key`, `tx_or_psbt`, `utils`, `var_bytes`,
  `var_int`, and `btclib` itself. In half the library "public" was
  declared and in the other half it was a leading character, which is a
  difference and not a style: `from btclib.b58 import *` handed out `Key`,
  `Octets`, `String`, `sha256` and `network_from_key_value` beside the
  seven names that module defines, and a helper growing into a name
  callers depend on did so silently, where in a package it takes an edit
  to a list. The lists hold what each module defines and nothing it
  imported — a caller wanting `Octets` wants `btclib.alias.Octets` — so
  `import *` and the sphinx pages both stop depending on an import
  section (issue #338)
- **`btclib.__all__` is the root of the library's public tree**: the
  packages and the top-level modules, so a walk that starts at the package
  name has an edge to follow and a declared surface at every node it
  reaches. That is what `docs/proposals/cli.md` reads to build the
  command tree of the out-of-repo command line, and the reason the list is
  written out rather than discovered: `pkgutil.iter_modules` would answer
  the file tree, and a module added to the directory would publish itself
  rather than be published. `name` and the metadata dunders are not in it
  — the first is the distribution's name and not a member of the tree, and
  a star import binding `__version__` would overwrite the importing
  module's own — and both are still attributes, `btclib.__version__` being
  how a caller reads the version.
- **A module `__getattr__` imports a published module on demand**, so
  `import btclib` costs the metadata lookup and nothing else, as it did:
  `getattr(btclib, "b58")` and `from btclib import *` work on a fresh
  interpreter, while eager imports here would put the whole library in
  `sys.modules` before any module of it could be imported first — which is
  the situation `tests/imports_test.py` exists to make impossible — and
  would route `btclib.b58` into `btclib.script` through this file. Its one
  cost is stated in the docstring: mypy reads a module `__getattr__` as a
  promise that any attribute may exist, so a misspelled `btclib.b59` is a
  runtime `AttributeError` rather than a checker error, where every import
  spelling a caller writes stays checked. A `__dir__` beside it answers
  with the published tree: `dir()` reads the namespace, so without it a
  module not yet imported is missing from what an interactive prompt
  completes — the same asymmetry, answered the same way, in `btclib` and in
  `btclib.script`
- **Every module below a package declares one too**, which is the rest of
  the same rule: the modules a caller reaches by name —
  `btclib.ecc.dsa`, `btclib.script.sig_hash`, `btclib.bip32.der_path` —
  said no more about their surface than the top-level ones did, and
  `from btclib.curves.curve import *` handed out `Point`, `sha256` and
  `libsecp256k1_mult` beside the curve. The lists are what each module
  defines, so the ones a package does not publish an edge to —
  `psbt.psbt_utils`, `curves.curve_group`, `script.engine.script_op_codes`
  — declare their own surface without becoming anybody's API: a module
  states what it offers, and its parent decides whether the offer is
  reachable.
- **Three modules record what they keep out**, which is the place a
  package has and a module did not: `network.datadir` and
  `curves.curve.datadir` are where those two packages keep their json
  files, a question about the installation rather than about a network or
  a curve, and `descriptors.INPUT_CHARSET`, `CHECKSUM_CHARSET` and
  `GENERATOR` are the three tables BIP380's checksum is computed from,
  which `checksum`, `add_checksum` and `strip_checksum` are what a caller
  asks. Each is still importable from the module that defines it, which is
  where the test suite takes them.
- **Two load loops and a type variable stop being public names.** A `for`
  target and a `with` target are module globals like any other, so
  `btclib.network` had `net`, `filename` and an open file, and
  `btclib.curves.curve` had `filename`, `file_` and `ec_name`: all six are
  underscored now, as `bip44` already spells `_purposes`. The
  `*_params2` beside them stay, being the standardized parameters
  `test_catalogued_curves` rebuilds every curve from. `psbt.psbt.TypeA` is
  `_TypeA`, a `TypeVar` of one private helper's signature and a name no
  caller can pass anything to.
- **`script.engine.PAY_TO_ANCHOR` is exported**, where the list beside it
  named every function that package defines and not the four bytes they
  compare a script against — Core's `MATCH_PAY_TO_ANCHOR`, which a caller
  reading a witness output for it needs by name.
- **`tests/all_test.py` enforces the lists** rather than leaving them to
  review, and finds the modules instead of listing them — the whole tree,
  packages and modules alike. Three checks: every one declares an
  `__all__` naming things that are there, empty only where there is
  nothing public to declare; no module exports a name it imported, which
  is the failure a package does the opposite of by design; and every
  public name a module defines is either exported or named in the file's
  `UNEXPORTED` table, so a new public helper fails the suite until
  somebody decides which it is. The import scan reads the module's own
  source and walks into a module-level `try`, `if`, `with`, `for`, `while`
  or `match`, those binding globals as much as a top-level import does,
  stopping at a function or a class
- **`btclib.script` publishes `sig_hash`, `taproot` and `engine`**, the
  three subgroups `docs/proposals/cli.md` promises as command groups and
  the one package whose list named none of the submodules behind its own
  tables. `taproot` was imported already, four of its names being
  re-exported flat; `sig_hash` and `engine` are imported on demand by a
  module `__getattr__`, and that is not a speed decision: `sig_hash`
  imports `btclib.tx`, whose `tx_in` and `tx_out` import `btclib.script`
  back, and `btclib.script.engine.script` asks this package for
  `sig_hash`, so an eager import of either would run on a half-initialized
  `btclib.script` — issue #147's shape, which `tests/imports_test.py` now
  measures from this side too: importing the package leaves both out of
  `sys.modules`, and asking for the attribute is what brings them in.
  `limits`, `op_codes_tapscript`, `script`, `script_pub_key`, `sig_ops`
  and `witness` stay unpublished, being where the flat names are defined
  and the tables the engine reads
- **A fourth test walks the export tree the way the command line will**:
  from `btclib`, into every module-valued export, transitively, checking
  that each node declares an `__all__` of its own and that an exported
  module is a submodule of the module exporting it — so the command path a
  walker reads off the tree is the import path, by construction rather
  than by convention. A fifth pins the root against the file tree, a
  module added to `btclib/` and not published there being a group the
  command line cannot reach, and a sixth pins the three subgroups of
  `btclib.script` by name — the walk follows the edges that exist, so a
  promised group nothing publishes is a walk that stops early and a test
  that passes
- **Every child module of every package is recorded on the side of the
  decision made about it**, published as a group or deliberately not, and
  the two sides together are asserted to be the package's whole directory.
  Both directions are needed and only the first is visible to the checks
  above: a submodule imported into an `__init__` for one name and left in
  `__all__` by habit is a group nobody decided on, while a child module
  added and left *out* of the list changes neither the list nor the edges —
  which is how `btclib.script` came to publish none of the three subgroups
  its own tables promise, and what the partition catches. The empty
  published sides are as deliberate as the rest — `curves`, `tx`, `bip32`,
  `fetch` and `script.engine` offer a flat surface and no group — and every
  package has to be in the table, so a new one is a decision rather than a
  silent pair of empty lists
- **`docs/proposals/cli.md` states the traversal contract** in place of
  the question it used to pose: the five points a walker depends on, with
  the one that makes the mirror implementable from outside this repository
  named as such — a module declares its surface whether or not its parent
  publishes an edge to it, so what the walk must not reach is exactly what
  nothing published, and no list of exceptions has to travel with it.
  Decision 3 of that file, "prerequisite or consequence", is answered:
  prerequisite, and done

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
- **the sighash byte gets a `Literal` too, narrower than #216's four**
  (issue #273). `alias.ValidSigHashType` names the seven values
  `sig_hash.SIG_HASH_TYPES` already enforces — the low bits' four values
  and each ORed with `ANYONECANPAY` — and types only `PsbtIn.sig_hash_type`,
  the one place this vocabulary is closed. Not an `IntFlag` over the whole
  byte: `SINGLE == ALL | NONE`, both 3, so a flag decomposition would make
  `SINGLE` an alias of `ALL | NONE`, a bit structure the protocol does not
  have. Not an `IntEnum` either, and on neither side of the boundary:
  `legacy` and `segwit_v0` mask a hash type rather than validate it, so a
  byte such as `0x05` must still hash, being a value a mined signature can
  carry, which is why `assert_valid_hash_type` keeps `hash_type: int` and
  is checked against all 256 possible bytes by
  `sig_hash_taproot_test.py`'s own `test_valid_sighash_type` — a call a
  `Literal`-typed parameter could not be given under mypy strict. The one
  cost: `psbt_test.py`'s out-of-range `sig_hash_type` assignment now reads
  `# type: ignore[assignment]`, the same way its neighbouring bad-value
  assignments already do. `psbt_in_test.py` checks `ValidSigHashType`
  against `SIG_HASH_TYPES`, the way `network_test.py` checks #216's two
  data-derived aliases
- **`network.datadir` and `curves.curve.datadir` are `Path`, not `str`.**
  Both mark where each package keeps its own json catalogue, and each
  docstring already promised "the path" to a caller who asks — a promise
  `pathlib.Path` keeps more precisely than the string ruff's new `PTH`
  rule set found underneath it. `str(btclib.network.datadir)` is the
  `v2023.7.12` value back; string concatenation and `.startswith` are not

### Performance

- **`pedersen.second_generator` is cached on `(ec, hf)`** (issue #287):
  `second_generator` is 0.02 µs against 74.4 for secp256k1 with sha256,
  and `commit` -- which calls it, as does every `assert_as_valid` and
  `verify` -- 13.7 µs against 89.5. The generator is a hash-to-curve of
  `ec.G` followed by a modular square root for each `x_H` the hash
  digest and its increments try, and the answer is a constant for a
  given `(ec, hf)`: recomputing it on every call had been 71% of a
  commitment's cost, `double_mult` -- the arithmetic a commitment
  actually is -- the rest. `functools.lru_cache` is the same tool
  `curve_group.cached_multiples` already puts on a per-curve table, and
  for the same reason `Curve.__hash__` exists: equal curves share a
  cache entry. `hf` is compared by identity, the same conservative
  choice `_libsecp256k1_applicable` makes for sha256. `maxsize` is 128
  rather than `None`: `ec` is caller-supplied, and an unbounded cache on
  it would be a memory leak, while 128 clears every curve in the
  catalogue paired with more than one hash function. The cached value is
  a `Point`, i.e. a tuple, so handing the same one to every caller is
  safe -- there is no mutable object to share by accident
- **verification takes no Python square root any more** (issue #284):
  `dsa.verify_` is 21.7 µs against 244, `ssa.verify_` 21.1 against 243,
  `bms.sign` 24 against the 102 the recovery module had left and
  `bms.verify` 25 against 97, `dsa.recover_pub_key` 22 against 95, and
  BIP340 batch verification of four signatures 158 µs against 739. None of
  it is new arithmetic. A compressed public key is "this x, and the y that
  goes with it", which is the question every one of those was asking
  `ec.y` in Python — one modular square root on a 256-bit modulus, 75 µs,
  where `ec_pubkey_parse` answers it of `0x02 || x` in 2.4 and hands the y
  back, serialized uncompressed, in 2.9. Two private functions of
  `curves.curve` hold the dispatch: `_is_x_coordinate` for a caller with
  no use for the y — the congruence check of `dsa.Sig`, where r is a
  scalar and every `x = r + j*ec.n` below `ec.p` is a candidate, so the
  loop stays btclib's and only the question inside it is delegated — and
  `_y_even` for the lift itself, which is `point_from_octets`'s compressed
  branch, `ssa`'s x-only keys and the r of its signatures, the candidate
  x of public key recovery, and taproot's internal key on the path an
  output key of any size but 32 bytes takes. `ec.y` and `ec.y_even` are
  untouched, and both functions fall back to them: for a curve that is not
  secp256k1, for an x outside the field, and to phrase the refusal, since
  "invalid x-coordinate" naming the value is what the bindings' bare
  `ValueError` cannot do. Two of the roots were not delegated but dropped:
  `Sig.serialize` validates before it writes and both `assert_as_valid_`
  have just validated, so they serialize with `check_validity=False`, 0.54
  µs against 3.1 for ECDSA and 0.14 against 3.1 for BIP340.
  `pub_keyinfo_from_pub_key` loses a round trip besides — for octets in,
  `compressed` is a filter on the form they may be in and not a conversion
  to it, so `bytes_from_point(point_from_octets(sec))` gave back the bytes
  it was handed and what the caller wanted of it was the proof that they
  are a key: `ec_pubkey_parse` and nothing else, 2.4 µs against 4.4, and
  the very call libsecp256k1 makes on those bytes if they go on to its
  `ecdsa_verify`. The refusals are what the tests hold the two
  implementations to, being half of the inputs: of the 400 smallest field
  elements 208 are not x-coordinates, and both refuse each of them with
  the same message. The uncompressed serialization BIP32 public
  derivation asks the bindings for is still the right one, but by 3.2 µs
  against 1.2 rather than by 74
- **message signing goes through libsecp256k1's recovery module** (issue
  #269): `bms.sign` is 102 µs against 4360, `bms.verify` 97 against 2782,
  both the mean over 40 random keys. The signing gain is not a faster
  search but no search at all. `recovery.sign` returns the recovery id
  beside r and s, and that id *is* the `key_id` the recovery flag carries
  — the parity of the nonce's point and whether its x-coordinate exceeded
  the group order, both of which the signer had in hand — where `sign`
  used to sign and then recover candidate after candidate until one
  equalled its own public key: 2977 µs where the signer's key was the
  first candidate, 5492 where it was the second and the first had been
  computed only to be discarded. Verification delegates the
  single-candidate `dsa.recover_pub_key` to `secp256k1_ecdsa_recover`,
  95 µs against 2330, so every caller of that function gains and not
  only bms; the plural `recover_pub_keys` has no single counterpart in the
  bindings, an enumeration being btclib's own loop, and is what the tests
  hold the singular against. bms takes the sec octets the recovery answers
  straight to `hash160`, an address being a hash of those bytes: no point
  is built on either side of the module any more, so the affine
  conversion of a recovered key and the multiplication behind
  `bytes_from_point(mult(q))` are both gone. The lower-s rule stays
  btclib's own, the recoverable parser taking any s in 1..n-1 as it must
  — a malleated signature recovers a key too, and `lower_s` is the caller
  saying whether that answer is wanted. What is left of those hundred
  microseconds is no longer curve arithmetic: 76 of them are
  `dsa.Sig.assert_valid` checking that r is congruent to a valid
  x-coordinate, which is one modular square root in Python. bms is
  secp256k1 only, so unlike taproot or ECDH no second curve keeps its
  Python implementation reached: it stays as the reference the delegation
  is measured against, and the tests reach it with both dispatches
  patched off — every published base64 vector in the file signed and
  verified twice, once each way
- **the two generator multiplications of `dsa` go through `mult`**, which
  is where the libsecp256k1 dispatch lives, instead of calling the `_mult`
  underneath it (issue #272). Both scalars are secret and neither was
  delegated: `gen_keys` multiplies the private key — 8.2 µs against 889,
  a hundred times, and its sibling `ssa.gen_keys` had been computing the
  same point through `mult` all along — and `_sign_` multiplies the
  nonce, 107 µs against 976. `_sign_` is what a signature falls to
  whenever the bindings decline the whole of it, so the second one is the
  cost of every sign-to-contract signature (991 µs to 124) and of every
  signature under another hash function (1049 to 111). Speed is not the
  whole of it: the Python fixed window is not constant time, `SECURITY.md`
  says so, and these two scalars are a private key and a nonce. The
  Jacobian coordinates the direct call kept are worth one `mod_inv`
  against those milliseconds, and the curve gate comes for free, `mult`
  testing it already: every other curve still runs the Python
  arithmetic, and the tests hold the two answers to each other with the
  dispatch patched off
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
  generator, with the private key as the scalar; it stays a call of its
  own past the entry below, which delegates that multiplication in
  `mult` as well, because the shared point never becomes a `Point` here.
  The derivation is unchanged and still ANSI-X9.63-KDF,
  which is why the bindings' own `ecdh.shared_secret` is not a
  substitute: that one hashes the compressed shared point with SHA256.
  Every other curve keeps the Python multiplication, GEC 2's secp160r1
  vector now checked through `diffie_hellman` itself, and so does a
  scalar that is zero mod n — the infinity point, which the bindings
  have no scalar for and which is still `invalid (INF) key`
- **`mult` multiplies any point in libsecp256k1, and `double_mult` and
  `multi_mult` sum them there**: the bindings served the generator alone,
  so every other multiplication of secp256k1 ran the Python arithmetic —
  0.55 ms against 13 µs for `mult(m, Q)`, 1.02 ms against 28 µs for
  `double_mult`, 2.4 ms against 122 µs for a `multi_mult` of eight
  scalars and 15.2 ms against 1.01 ms for one of sixty-four: 43x, 36x,
  20x and 15x. `pedersen.commit` and borromean's rings are `double_mult`
  callers and take it as it is. What the three reach is one
  bytes-in/bytes-out layer: a term is `keys.pubkey_tweak_mul`, the
  running total `keys.pubkey_combine`, and no intermediate becomes a
  `Point` again — uncompressed in both directions, a compressed answer
  costing the 73 µs modular square root that lifts an x coordinate back
  to a point and a compressed argument 2.1 µs of libsecp256k1's own.
  Their signatures and their answers are unchanged, infinity included: a
  libsecp256k1 public key is a point of the curve and never the identity,
  so a zero scalar, the point at infinity, and a sum that lands on
  infinity — `v = n - u` on the same point is the one-line case — are
  recognized before the call rather than caught from it. That last one
  costs a combine per term instead of one combine for all of them, 112 µs
  against 97 on eight terms and 925 against 774 on sixty-four, and buys a
  `ValueError` from those calls still meaning what it says; two terms,
  which is `double_mult` and the shape most callers have, pay nothing.
  BIP340 batch verification is where the many-scalar sum is, libsecp256k1
  exposing no batch verify of its own: it goes through the public `mult`
  and `multi_mult` in affine coordinates now, instead of the Jacobian
  functions under them and an equality of projective coordinates, 3.4 ms
  against 739 µs for four signatures — most of what is left being one
  modular square root per signature, to lift an `r` back to a point. The
  Python arithmetic stays, and stays the reference the bindings are held
  against: the dispatch is patched off and every one of these answers
  asserted again, with the bindings themselves replaced by a function
  that raises, so a path still reaching them cannot pass in silence.
  `mult` finds its GLV endomorphism there, which is why that arm is
  spelled `ec == secp256k1` rather than by the bindings predicate — the
  same test today, a different question. A `multi_mult` of a single
  scalar is still `not a multi_mult`
- **the verification a signature's own bindings decline still multiplies in
  libsecp256k1**: `dsa._assert_as_valid_` and `ssa._assert_as_valid_` are
  what answers when `ecdsa_verify` and BIP340's verify are not asked — a
  hash function that is not sha256, a commitment to check, a
  caller-imposed nonce, a BIP340 message of a size other than 32 bytes,
  which is issue #169 and four of BIP340's own vectors — and each paid a
  Python `double_mult` underneath whatever the reason. They now reach the
  dispatching one: ECDSA verification with sha512 is 128 µs against
  1.10 ms, BIP340 verification of a 30-byte message 183 µs against
  1.17 ms, and what is left of the second is mostly the modular square
  root that lifts the signature's `r` back to a point. Both keep their
  Jacobian shape rather than being rewritten in affine coordinates,
  because it is not only their arithmetic that is projective: so are the
  infinity test, the y parity and the x comparison each makes, and so is
  the `QJ` that public key recovery threads through `dsa`'s. What makes
  that exact is `jac_from_aff` answering `z == 0` for the infinity the
  other side of the boundary has no serialization for, so each function
  still raises what it raised before, from the same line — `invalid (INF)
  key` for the ECDSA `K` that is infinity, from the same `KJ[2] == 0`.
  The two conversions it costs are 0.39 µs each on the `z == 1` a parsed
  key arrives as; the shortcut that would skip them, the affine point
  being the same pair of coordinates, saves 0.75 µs of 28 and is not
  worth a branch. Every other curve is untouched, measured: secp256r1
  ECDSA verification is 1.21 ms either way. `tests/script_engine`'s
  bindings-less configuration patches the curve dispatch off as well now,
  which is what keeps it one: the verdict was already the Python
  implementation's, and now the multiplication under it is too
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
- **sign-to-contract's two tweaks go through libsecp256k1, one of them
  slower on purpose** (issue #271). `commit_point_`'s public half,
  `keys.pubkey_tweak_add`, computes the receipt plus the tweak times the
  generator directly on the serialized point: 5.9 µs against 33.9,
  serialization included. `commit_nonce_`'s secret half is the opposite
  trade, the one this issue is for and not for the clock: `(nonce +
  tweak) % n` on Python integers is 0.02 µs, variable in time with the
  operands and leaving an unzeroized copy of the sum behind, where
  `keys.prvkey_tweak_add` is 0.50 µs and constant time, the trade BIP32
  private derivation already took. Both are gated on the curve alone,
  as taproot, ECDH and BIP32 are, `_tweak`'s own loop keeping every
  tweak in range before either call is reached; the one sum
  `prvkey_tweak_add` refuses past that loop is the zero
  `commit_nonce_` has always refused, and the mapping to
  `BTClibRuntimeError("failed to sign: zero tweaked nonce")` is
  unchanged. `pubkey_tweak_add` refuses a result at infinity, where
  `ec.add` returns it — the one behaviour difference between the two
  bindings — so that refusal, and `bytes_from_point`'s own refusal of
  an infinite receipt, both fall through to the Python addition rather
  than propagating: the one-in-n edge answers what it always answered.
  Every Python path stays reached, on the low-cardinality curves the
  tests already used and, new here, with the dispatch patched off on
  secp256k1 itself, over both parities
- **a Python signature names its own key_id, and the search for it is
  gone** (issue #285). `_sign_` computed the nonce's point and kept `x_K`
  alone; the key_id is the two bits it threw away — how far `x_K` ran past
  the group order, SEC 1 v.2 section 4.1.6's `j`, and the parity of `y_K`,
  with the lower-s negation mirroring K and so flipping the parity bit.
  `_sign_recoverable_` returns them beside the signature and `_sign_` is
  its first element, which is one signing body and not a second copy of
  the arithmetic: over 40 random keys the Python path is 38.0 µs with the
  key_id and 37.9 µs without, the two bit operations being unmeasurable
  against a signature. What they replace is a recovery per candidate until
  one equalled the signer's own public key: 1867 µs, of which the search
  was all but 38 — a factor of 49, both numbers measured with the
  generator multiplication delegated as it is in production (issue #272),
  since a signature the bindings decline still has that one point from
  them. `bms.sign` is what pays
  it, and it **loses its dispatch entirely**: no `if
  _libsecp256k1_applicable` and no second branch to keep in step, because
  `dsa.sign_recoverable` answers the key_id whichever implementation signs
  — 1833 µs to 56.6 on the Python path, and 29.7 µs to 32.1 on the
  delegated one, the 2.4 being the `Sig` validation the module used to skip
  with `check_validity=False` and now leaves to the public function that
  hands the signature back. `bms.assert_as_valid` keeps its own dispatch,
  recovery having no Python counterpart to hide, so bms is one
  implementation of signing and two of verifying. `bms._search_key_id` is
  gone with the branch: its only caller was that branch, and the search is
  now spelled in the tests, which is where a cross-check of the key_id
  belongs
- **public key recovery multiplies in libsecp256k1** (issue #286): step
  1.6.1 of SEC 1 v.2 section 4.1.6 held the last two
  `double_mult_w_NAF` calls left in `ecc/`, one in each
  `_recover_pub_key_`, and both are now the `_jac_double_mult` of issue
  #281. ECDSA's is 2215 µs to 214 for one candidate and 6800 µs to 850
  for the enumeration that runs one per key_id; BIP340's x-only recovery
  3540 µs to 109. Then **`dsa.recover_pub_keys_` stops multiplying
  altogether on secp256k1 with sha256**, and is four
  `secp256k1_ecdsa_recover` calls: 83 µs against those 850. An
  enumeration is btclib's loop and not a function the bindings have --
  their recovery answers for the one recid it is given, which #282
  delegated as `recover_pub_key_` because that is what bms asks for --
  but every candidate in the loop *is* one of those recids, and a recid
  is two bits, i.e. every candidate a curve of cofactor 1 has. So
  `range(4)` there is the `range(2 * (ec.cofactor + 1))` of the Python
  enumeration, in the same order, and the dropped candidates drop the
  same way: `_libsecp256k1_recover_sec_` maps the bindings' refusal to
  the `BTClibValueError` the loop already suppressed, so a high-s
  signature under `lower_s` still enumerates to the empty list where the
  singular raises. x-only recovery had no such option — libsecp256k1's
  recovery module is ECDSA and its xonly module carries no recovery — so
  BIP340's delegated multiplication is the whole of its gain.
  What is left of a Python ECDSA candidate is the `_y_even` lift,
  delegated already, and a `mod_inv`, which delegating the multiplication
  has made measurable: 41 µs of the 214, where the same 41 sat inside
  2215. Still not hoisted out of the loop, because the plural being
  `_recover_pub_key_` over a range of key_ids and nothing else is what
  keeps the two from disagreeing (issue #183), so the paths that reach it
  pay 19% for the arithmetic being written once. On that Python path the
  recovered point comes back as `jac_from_aff`, i.e. `z == 1`, where the
  wNAF answered whatever projective representative its ladder reached:
  the same point either way, and every caller converts it with
  `aff_from_jac`. What the enumeration answers is now three
  implementations' answer and asserted to be one list — the four recover
  calls, the Python loop with its double_mult delegated, and the same
  with `curves.curve`'s dispatch patched off as well — because the list
  is dense and a position in it is what a caller reads a key_id from, so
  two implementations dropping differently would disagree about a
  recovery flag without disagreeing about any key. The `j = 1` pair that
  no signature of secp256k1 can reach (`r + ec.n < ec.p`, some 2^-127 of
  them) is asserted on a fabricated r instead: `r = 2` recovers all four
  candidates, `r = 7` only the pair, whose key_ids are 2 and 3 while
  their positions are 0 and 1

### Tests

- **the boundaries the first parser mutation session found unconstrained
  are tests now** (issue #327). Every one was a check the suite executed
  without pinning, so a wrong version of it would have gone unnoticed: a
  tx_id length refused from below only, where 33 bytes are an outpoint that
  serializes back to 37; the largest number a two- or four-byte `var_int`
  holds, which a canonical minimum one short of its value accepts;
  `MAX_SIZE`'s value, every test around the cap holding for whatever the
  constant is; the non-canonical message naming the width the number was
  written in; the four-byte range of a version, a lock time and a sequence
  at both ends rather than at one; the versions `assert_standard` refuses
  where `assert_valid` takes them, zero and every one whose top bit is set —
  and not where it puts the upper end, which is issue #387's to answer and
  no test's to pin; the coinbase script_sig's 2 to 100 bytes, both included;
  `assert_valid` asking every input and every output, which only a
  transaction whose sums are fine can reach; the legacy sigop count being
  the sum of both lists rather than a bitwise mix of them, one sigop on
  each side being the case that tells those apart; and an eight-byte output
  value surviving an unchecked round trip byte for byte while validation
  refuses it, which is the invariant either reading of the field satisfies
  — issue #388 has the reading itself
- **`check_validity`'s default is held to checking**, class by class over the
  wire format, and that is the shape 19 of the parser profile's survivors
  had: a `check_validity: bool = True` mutated to `False`, or an `if
  check_validity:` negated, changed nothing any test asked about, so what
  every caller who says nothing gets was the one thing the flag's
  91 signatures did not promise. `tests/check_validity_test.py` carries the
  table, in two columns, because a fixture invalid only in a nested object
  answers the *child's* guard: take `if check_validity:` out of
  `TxIn.serialize` and the `prev_out.serialize` under it raises in its place,
  a green suite about nothing. One column is therefore invalid at its own
  class's boundary — a sequence of `True`, a transaction without inputs —
  and holds `serialize`, `to_dict` and `from_dict`; the other is invalid in a
  nested outpoint and holds `parse`, which the first cannot: a `True`
  sequence reads back as the number one, and a transaction without inputs has
  no octets to read at all, the input count being where the segwit marker
  lives. Each accepts with the flag off, which is the half that says the flag
  still switches the check *off*, and every guard was removed one at a time
  to see the tests notice: eleven of the twelve go red, the twelfth being the
  one below. `TxOut` is out of the dict half
  and by name: its only validity question is the amount, `to_dict` puts that
  through `btc_from_sats` and `from_dict` through `sats_from_btc`, and each of
  those is `valid_sats_amount` — so the conversion asks what `assert_valid`
  would, and the flag has nothing left to switch. A test of that exclusion
  stands where the reason would otherwise be prose
- **the two keyword-only flags of `btclib/tx/tx.py` that are not
  `check_validity`** — `assert_valid`'s `unsigned_template` and
  `_assert_valid_coinbase`'s `is_coinbase` — are held to refusing a
  positional call, which is the hazard the star is there for and the one
  `tests/check_validity_test.py` states for the flag it is named after. The
  ast walk in that file only inspects signatures carrying `check_validity`,
  so these two were mutable from `*` to `/` with nothing red
- **`join` compares numbers and not objects**, which is what let three of its
  guards be mutated from `!=` to `is not` with nothing red: equal small
  integers are the same object in CPython, so every case a test built from
  literals passes either way. `int("1000")` builds a fresh object where the
  literal would be the cached one, and 257 distinct inputs put a count past
  the last cached integer, so transactions agreeing on version, on lock time
  and on inputs that are all distinct are joined by the code and refused by
  the mutant. What is left of that shape in the profile is one mutant in
  `var_int._parse_number`, where the sizes compared are 2, 4 and 8
- **validation asks even an empty witness to validate itself.** The base
  `Witness` has nothing to reject when its stack is empty, so the old truth
  guard changed none of its answers; a public subclass can still have an
  invariant of its own, and `TxIn.assert_valid` now dispatches to it without
  making non-emptiness stand in for validity. The test uses that falsey
  subclass, which is the case that distinguishes the two implementations
- **`join` flattens its inputs once**, then compares that list's length with
  the serialized-input set and hands the same list to the transaction. The
  duplicate check and the result therefore read one snapshot instead of
  traversing every transaction's inputs separately for the count, the set
  and the concatenation
- **a subclass is where the invariant a base class cannot have lives**, and
  eight mutants of `btclib/tx/` were reachable only through one: `Witness`,
  `TxOut` and `TxIn` are public and not final, `parse` and `from_dict` build
  `cls` on purpose, and the `check_validity=False` a parent hands a child is
  observable the moment that child has something of its own to refuse. So
  `tests/check_validity_test.py` holds the forwarded flag with a rejecting
  `Witness` inside a `TxIn` and a rejecting `TxOut` on its own and inside a
  `Tx`, and the amount-conversion exclusion beside it is narrowed to the base
  class, which is all it ever showed. Four of those eight were the ones that
  exclusion had covered
- **`Tx.__eq__`'s witness fallback is exercised rather than masked.** The
  branch runs only when `TX_IN_COMPARES_WITNESS` is false, and monkeypatching
  that global cannot reach `field(compare=...)`, which the dataclass read at
  class creation: the generated `TxIn` comparison went on reading the witness,
  answered the same way as the branch, and hid whatever the branch did — a
  deleted `not`, a doubled one, an `is` for `!=`, all three green. The input
  is now a `TxIn` subclass whose equality leaves the witness out, as the false
  setting makes the generated one, so the branch is the whole of the answer
- **three assertions that could not fail say something now.** `assert
  tx_in.nSequence == tx_in.nSequence` compared the property with itself in
  three places, so the alias it is there to check was never read; `assert
  tx_in == tx_in2 or TX_IN_COMPARES_WITNESS` passes whichever way that flag
  is set, and what replaces it is the inequality of the two inputs, which is
  behaviour rather than the flag behind it; and a non-shuffled `join` was
  held to equalling *another* non-shuffled join, which two shuffled ones
  satisfy every other attempt with two inputs — so `SystemRandom.shuffle` is
  monkeypatched to a known permutation, reversal, and each of the four flag
  combinations is one equality: the order a list comes back in says which
  branch ran, where a real shuffle can preserve the order it was given —
  once in 720 for six elements — and a run that draws it says nothing. The
  ten-attempt randomized assertion beside it is gone for that reason, its
  two inputs and four outputs making the odds 1 in 48 an attempt. `Tx`
  being a dataclass is a promise too, and `dataclasses.fields` is what
  reads it: the constructor, the comparison and every conversion are
  written out, so the decorator is left holding the field list and the
  repr, and nothing asked for either
- **a coinbase input in a non-coinbase transaction has a test of its own.**
  That refusal was the one statement of `btclib/tx` that no test under
  `tests/tx` reached: a script_engine vector did, which is a verdict on the
  engine and none on the transaction, and it left the parser profile's
  baseline one statement short of the scope it mutates
- **the ten blocks Bitcoin Core carries in `blockfilters.json` are
  vendored and parsed** (issue #274). Core publishes no block-validity
  vector file — `src/test/data/` holds no block, and the two suites that
  cover block validity, `validation_block_tests.cpp` and
  `feature_block.py`, *build* blocks against a node rather than reading
  them — but its BIP158 vector file opens every row with a height, a
  block hash and a whole serialized block, and the rows were chosen for
  the shapes their scripts have. All ten parse under the full validity
  check, round-trip byte for byte and hash to the hash the row states,
  and the six postdating BIP34 commit the height it states, which is the
  first check of `Block.height` against a number btclib did not compute.
  They are testnet and odd where `_data/block_*.bin` are mainnet and
  ordinary: an unparsable coinbase output script, an output paying to an
  empty script and a transaction spending from one, duplicate pushdata,
  witness data, genesis. What they do not add is an invalid block — every
  row is a block the chain accepted, so the negative vectors are still
  python-bitcoinlib's seven. The file is vendored whole under Core's own
  name, filter columns and all, btclib implementing no block filter: a
  btclib-named extract of the block column would have no upstream name to
  be compared against, which is what `tests/_data/README.md`'s naming
  convention is for, and the rest of the file costs 17,816 bytes
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
  **SIGHASH_SINGLE past the last output**: BIP143's own example signs
  an input whose index *equals* the output count, and so does every one
  of the seven such spends in `script_assets_test.json`, so a bound
  reading `!=` where it should read `<` passed everything there was.
  Both paths now sign at an index two past the last output: the segwit
  v0 one against a preimage the test builds from BIP143's field list,
  itself checked against the preimage and sigHash the BIP publishes,
  and the taproot one against the refusal BIP341 requires, by the
  message it gives. **A script code no op code can be read from at
  all**: the walk that elides `OP_CODESEPARATOR` keeps whatever is left
  where the walk stopped, and where it stops at the very first byte
  that is the script code entire — reachable because 0xab can be in it
  as data of a push that overruns the end
- **the three test-data files of Bitcoin Core that were never taken are
  vendored** — `key_io_valid.json`, `key_io_invalid.json` and
  `base58_encode_decode.json`, byte for byte in `tests/_data/`, which
  leaves nothing in Core's `src/test/data/` both applicable to btclib and
  missing here (issue #218). What they buy over the address tests already
  in the suite is an oracle btclib did not write: `tests/b58_test.py` and
  `tests/b32_test.py` carry values this project produced, and a round trip
  through one implementation agrees with itself by construction. The 70
  invalid strings are the half that had no equivalent at all, and each is
  now refused by all four entry points that could be handed one — `b58`,
  `b32`, `ScriptPubKey.from_address` and `to_prv_key` — because a string
  arrives without a label, and a refusal from one is worth nothing if
  another accepts the same bytes. All 70 valid rows pass as they stand:
  every address decodes to Core's scriptPubKey and every WIF to Core's key
  with Core's compression flag, over the four chains the metadata names.
  One thing the encodings do not carry is asserted rather than glossed
  over: a base58 test-network prefix belongs to four networks and the hrp
  `tb` to three, so btclib answers "testnet" for a testnet4 or signet
  string where Core answers with the chain its node was started on (issue
  #207). The eight rows whose witness version is 2, 3 or 16 render like
  the rest, `witness_unknown` being a type btclib names and `b32` writing
  any version 0 to 16 (issue #251); every one of the 54 addresses comes
  back from its scriptPubKey unchanged
- **the seven psbt cases built inline are vectors**, in
  `tests/psbt/_data/btclib_test_vectors.json`, where seven
  `# TODO add to test vectors` markers had asked for them (issue #181).
  The file name carries a convention rather than a label: the prefix of a
  psbt vector file names the authority its cases answer to, so `btclib_`
  beside `bip174_` and `bip371_` says these are ours, that no upstream
  URL exists for them, and that no refresh will ever reach them. Their
  raw material is upstream and pinned — five psbts of BIP174's 2-of-3
  walk-through, the prose steps `bip174_test_vectors.json` deliberately
  does not vendor — each carrying one edit that a parse, a serialize, a
  combine or a finalize must refuse. Three of the seven name an edit
  instead of holding invalid bytes, and that is a fact about the format
  rather than a shortcut: `Psbt.parse` reads one input map per `vin` and
  one output map per `vout`, so a psbt whose counts disagree has no
  encoding to be parsed from, and the global unsigned transaction is
  serialized without witnesses, so a witness on it survives no round
  trip. `tests/_data/README.md` says where the psbts were read and that
  the cases built on them are pinned to nothing
- **an input carrying both UTXO types is tested**, which BIP174 calls out
  twice and nothing exercised: "an input can have both
  `PSBT_IN_NON_WITNESS_UTXO` and `PSBT_IN_WITNESS_UTXO`", for the wallets
  that began requiring the full previous transaction after psbt was in
  use. Both records survive a round trip, and the precedence the BIP's
  signer algorithm states — `witness_utxo` first, `non_witness_utxo`
  second — is read off a psbt where the two branches disagree: adding the
  very output an outpoint already names, so that nothing about the psbt
  becomes untrue, sends the signer down the witness branch and a p2pkh
  output is not something a witness signature can spend
- **an unknown key-value map is read back**, where
  `tests/psbt/psbt_out_test.py` serialized one and dropped the result.
  The separator has to be appended for the read: an unknown is one field
  of a map among others, so the byte that ends the map belongs to
  whichever of `PsbtIn`, `PsbtOut` or `Psbt.serialize` assembles the whole
  of it
- **the BIP39 vectors are the whole of upstream's file**, all twelve
  language arrays of `trezor/python-mnemonic`'s `vectors.json` where the
  English one was taken alone. `bip39_test_vectors.json` keeps its btclib
  name even so: `vectors.json` is taken in that very directory, by
  SLIP-0039's own file of that name, and two upstreams publishing one
  name is exactly what a btclib name is for. Beside it,
  `test_JP_BIP39.json`, the japanese vectors bip-0039 cites in its own
  Test vectors section: 24 sentences published NFC against word-lists
  published NFKD, with a passphrase whose normalized form is another
  string entirely, which makes them the only vectors anywhere that fail
  when a passphrase goes unnormalized
- **electrum's generation is measured language by language**, against
  vectors produced by running electrum's own `mnemonic.py` with
  `randrange` patched to a constant — the same starting point
  `mnemonic_from_entropy` takes, electrum's search beginning at
  entropy + 1 as btclib's does. Electrum publishes no vector of that
  kind, and its `SEED_TEST_CASES` only reach the seed, which needs no
  word-list at all; the entropy field of those same cases is now checked
  too, and it could not be before. In
  `tests/mnemonic/_data/electrum_language_vectors.json` and not inline
  like every other electrum vector here, because the lint gate's two
  spell checkers read a python source and skip `_data`, and `typos` runs
  with `--write-changes`: measured, it corrected a word of the Portuguese
  sentence into the English word it is one letter away from
- **`test_wordlist_2` no longer adds a language to the singleton.** It
  used the module-level `WORDLISTS`, so every test that ran after it saw
  a thirteenth language — which nothing could observe while a reader had
  to name its language, and which `lang_from_mnemonic` turns into a
  wrong answer. A private `WordLists()` costs nothing and the suite runs
  in a random order, so the interference would have been a failure in one
  seed out of some
- **the twelve on-chain scripts of issue #123 are vendored**, in
  `tests/script/_data/unspendable_script_pub_keys.json`: the real
  `scriptPubKey`s of the five transactions the issue lists, each with the
  height and vout it sits at and what the decode must answer. A synthetic
  equivalent would have exercised the same code without closing the
  report. It is the one vendored file that cannot verify itself, a
  `scriptPubKey` being a part of a transaction and no txid recomputable
  from it, and `tests/_data/README.md` says so next to the command that
  re-derives each one
- **python-bitcoinlib's block-validity vectors are vendored**, in
  `tests/block/_data/checkblock_valid.json` and `checkblock_invalid.json`
  (issue #199): four real blocks and seven consensus refuses, byte for
  byte, and the only negative block vectors here that btclib did not build
  by mutating a block of its own. One of the seven is `xfail`, and it is a
  finding rather than bookkeeping: btclib takes no `cur_time`, so a block
  two hours ahead of the clock is accepted. The same survey took two
  blocks of values inline, upstream publishing no file for either: the
  five secp256k1 RFC6979 vectors, which pin the signature and not only the
  nonce btclib had for one of them, and six nBits-to-difficulty pairs.
  What was left upstream is in the issue — their bech32 vectors predate
  BIP350, and their script and transaction files are subsets of Core's,
  which this suite already holds at Core's tip. Four defects the survey
  found in their vectors are reported to them as
  petertodd/python-bitcoinlib#323
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
- **`tests/_data/README.md` states no count either**, and
  `tests/vendored_data_test.py` is the same guard for the same reason: the
  summary opened with a total and each of its bullets counted the names it
  then listed, so every branch vendoring a vector file had to edit the
  number — measured, it read 46, 47, 48, 49 and 50 across the branches
  open on one afternoon, each of those a rebase conflict for the others.
  The lists stay, being the fact the number summarized, and the Summary
  now carries the `git ls-files` command that derives it. Not solvable the
  way CHANGELOG.md's was: `union` keeps both sides' added lines, which is
  right for a list of bullets and nonsense for the prose describing them.
  The guard spares the numbers that are upstream's — BIP327's eight vector
  files, a vector file's 45 quadruples — by anchoring on the two shapes a
  self-count takes and reading the bullet shape in the Summary alone
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
  do not, and tests/README.md records both: scheduling
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
  BIP341 does this match" had no answer. Two of them were also wrong,
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
- **BIP143's OP_CODESEPARATOR cut has an invalid twin** (issue #221).
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
- **the two spellings of `dsa.recover_pub_keys` are held to being one
  function.** `recover_pub_keys_` takes the hash the other reduces, and
  `challenge_` does not hash it again, so the underscore spelling is the
  one a caller holding a sig_hash has to reach for — and it had no test
  naming it, only the lines the msg spelling covers through it. Nothing
  in btclib calls either since bms began naming its own key_id (issue
  #269), which is what makes the pairing the whole of their contract: the
  same keys from both, the signature passed as a `Sig` and as DER octets,
  under another hash function, and with the lower-s rule off. A high-s
  signature enumerates to the empty list where the singular raises "not a
  low s" — every candidate fails the rule and a failing candidate is
  dropped rather than reported
- **`bitcoin_core_rpc`'s three chain tables are held in step.** `_RPC_PORT`,
  `_DATADIR_SUBDIR` and `_CORE_CHAIN_FROM_NETWORK` agreed by construction and
  nothing checked it: a chain added to `_RPC_PORT` alone passed `from_chain`'s
  membership guard and then raised a bare `KeyError` at the
  `_DATADIR_SUBDIR` lookup, not the `BTClibValueError` this module raises
  everywhere else; added to both and not to `_CORE_CHAIN_FROM_NETWORK`, it
  stayed reachable through `from_chain` while `core_chain_from_network`
  refused to name it. One test now asserts all three keyed sets equal
  (issue #418)

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
  toolchain. `latest.yml` samples 3.10 and 3.14 as the ends of the
  supported range, where it sampled 3.9 and 3.14
- dropped pypy3.10 from the test matrix; pypy3.11 stays, so PyPy is still
  covered. hypothesis ships compiled wheels from 6.160 on and publishes
  none for pypy3.10, whose sdist build needs a PyO3 requiring PyPy 3.11 or
  newer

### Packaging, linting and CI

- **`tests/mutation_counts_test.py` skips its `?` filename case on
  Windows**, now that `test.yml`'s matrix runs `windows-latest` and
  `windows-11-arm` again. The case exists to show that `_read_only`'s URI
  construction treats `?` as an ordinary filename character rather than
  `file:{path}?mode=ro`'s query-string delimiter, and NTFS refuses that
  character in a filename outright, so there is no such file for the
  fixture to write there. `#`, the other delimiter the same parametrize
  covers, is ordinary on NTFS and keeps running everywhere, so the
  escaping stays covered on every platform the matrix tests.
- **mutation testing reaches the wire format**, a third configuration and a
  second job (issue #327). `.github/mutation/parsers.toml` mutates
  `btclib/tx/` with the `var_int` and `var_bytes` codecs under it: the
  transaction encodings are where two of the five defects that opened the
  issue lived — a fixed-width field that took a truncated read and
  normalized it on serialization, and an octet parser that ignored what
  followed the object (#322) — and both were inside a tree measuring 100%,
  which is #219's question again on a different boundary. One
  configuration and not three, `module-path` taking a list of paths as well
  as a path, because one test command judges all six modules; and it names
  `tests/parse_contract_test.py`, `tests/integer_policy_test.py` and
  `tests/check_validity_test.py` beside the module suites, each for a class
  of mutant the module suites cannot see. The last of those is the cheapest
  fourteen kills in the profile: cosmic-ray turns the `*` of a keyword-only
  marker into `/`, which moves `check_validity` into a positional slot, and
  the ast walk in that file is the only thing that fails on it. Measured
  before the budget was written, and the numbers are what the issue asked
  for rather than an estimate: 1034 mutants, 88 skipped, the 946 that ran
  taking minutes rather than hours, and 22 surviving once the tests the runs
  asked for were written — 127 in the original run, before the tests and the
  simplification above. Of those 22, 19 are equivalent mutants, one turns `!=`
  into `is not` where the sizes compared are 2, 4 and 8 and CPython interns
  all three, and two are the upper end of `assert_standard`'s version window,
  which issue #387 has to settle before a test may pin it. So this profile *finishes*,
  where the engine's five and a half hours are sampled — which is what
  makes a survival rate comparable with the week before. Its own job, in
  parallel with the consensus one, with a 30-minute budget under a
  45-minute ceiling, because the two sessions there already spend 180 of
  the 200 minutes that job has: the jobs are now a matrix over profiles,
  each cell naming its configurations and their budgets, so a scope added
  next takes nothing from the ones already measured. One artifact per
  profile, two uploads under one name being an error, so
  `mutation-sessions` is now `mutation-consensus-sessions` beside
  `mutation-parsers-sessions`
- **`cr-filter-operators` runs between `init` and `exec`** for every
  configuration, and is a no-op for one that excludes no operator, so the
  decision stays in the toml rather than in the workflow. What
  `parsers.toml` excludes is the `|` of a type annotation: all four modules
  open with `from __future__ import annotations`, so `Sequence[TxIn] | None`
  is an unevaluated string, and cosmic-ray's eleven replacements for that
  operator are 88 mutants — eight such `|`, on seven lines — that nothing
  can reach. Measured rather than argued: an unfiltered session over the same
  scope reports 110 survivors and every one of those 88 is among them, so
  filtering leaves the 22 that are worth reading and spends minutes less, a
  survivor costing the whole test command where most kills cost a fraction of
  one. Excluded by operator rather than with a `# pragma: no mutate`, and the
  collateral of a pragma is not the argument for it: grouped by the line
  `cr-filter-pragma` reads — the one a mutation *ends* on — six of the seven
  hold nothing but that annotation's eleven mutants, the multiline signatures
  putting the `*` and the `check_validity` default on lines of their own.
  `OutPoint.to_dict` is the exception, the only one of the seven written on a
  single line: 23 mutations end there and a pragma would skip 12 the filter
  does not — eleven replacements of its keyword-only `*`, `Mul_BitOr` among
  them and so past the anchored pattern, and the one of its default. What
  settles it is where the decision lives: one line in the file that already
  says what is mutated and what judges it, against a marker in each of seven
  library lines and again in
  every module a later `module-path` adds. The price is the same either way
  and is paid in the configuration instead of the library: a real `a | b`
  added to one of these modules would be skipped in silence, and the grep
  that re-derives the claim is beside the exclusion. So is what a skip does
  to the one number the workflow prints: `cr-rate` counts a result that is
  not SURVIVED as a kill, which a skip and a per-mutant timeout both are
- **the bindings dependency states its policy where the pin is** (issue
  #325). `btclib_libsecp256k1>=0.7.1` has no upper bound, and the
  absence of a ceiling is now written down as the decision it is:
  the bindings are a btclib-org project developed by the same people, so a
  breaking change there is coordinated with the release here — which is
  what a version ceiling substitutes for when it cannot be. `<0.8` would
  cost a btclib release for every bindings minor, the ones that break
  nothing included, and would make a published artifact refuse a version
  it works with; `<1` constrains nothing, pre-1.0 semver putting the
  breaking changes in the minor. CONTRIBUTING.md carries what the policy
  does *not* cover — metadata is baked into every wheel already published,
  so coordinating the two projects protects the supported pair and not an
  artifact that went out before — and what the bound is: the oldest final
  release supported, `0.7.1rc1` falling below it, where what a resolver
  does with prereleases is its own policy rather than something a
  specifier settles

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
- **`PTH` is selected too, the seventh of that survey's rejects to move.**
  130 `os.path` calls and bare `open()`s, 23 of them in the library, are
  now `pathlib.Path`: `curves.curve`'s four catalogue loaders and
  `network`'s five, `bip44`'s purposes table, `mnemonic.electrum`'s old
  wordlist, and every fixture loader in `tests/block`, `tests/tx`,
  `tests/mnemonic`, `tests/fuzz_test.py`, `tests/parse_contract_test.py`
  and the package's own `tests/__init__.py` loaders. `mnemonic.data_file`
  and `WordLists.load_lang` keep their `str`: a caller passes a filename
  of their own to register a language there, and narrowing what it hands
  back was not this rule's question to answer. `network.datadir` and
  `curves.curve.datadir` are the two names whose type this did change —
  see Types below
- **`pytest.mark.parametrize`'s names are a comma-separated string, not a
  tuple.** `("hexed", "encoded")` is `"hexed, encoded"` now, at 89 call
  sites over 37 files; `flake8-pytest-style`'s `parametrize-names-type`
  had never been set, so `tuple` was ruff's own default rather than a
  decision this file made, unlike everything around it. The comma is how
  pytest's own documentation writes a parametrize signature, and it is
  also what the bindings had already chosen, with that reason stated
- **`redundant-expr`, `possibly-undefined` and `warn_unreachable` are on**,
  closing the last three codes the mypy survey had left off as a block.
  Re-measured one at a time: `possibly-undefined`'s one finding was a
  `while True: break` retry loop mypy's flow analysis cannot follow,
  unrelated to the other two and gone now that
  `test_low_cardinality` counts the retry with a sentinel `while` instead.
  The other eight, in `network.py`, `bip21.py`, `script.py`,
  `bitcoin_core_rpc.py` (twice), `utils.py`, `block_context.py` and
  `fetch/fetcher.py`, are the deliberate idiom the old comment named:
  a runtime guard against a value whose static type promises more than
  json, a caller ignoring an annotation, or an operator's own dispatch
  protocol can guarantee. Each keeps the check on everywhere else with
  its own `# type: ignore[redundant-expr]` or `[unreachable]`, naming the
  code, rather than the three staying off for eight sites' sake
- **The same audit, over ruff's own ignore list.** Every code still in
  it was measured on its own rather than trusted on its comment: some
  found nothing at all and are gone -- `D406`, `D407`, `PLR0904`,
  `PLR0914` -- and others found a short, nameable list of sites, now
  each carrying a `# noqa` instead of the whole codebase going unchecked
  for them: `RUF003` (a mathematical minus sign and a stray no-break
  space -- the second one a typo, fixed rather than kept), `PLW1641`
  (the mutable dataclasses and one test double whose `__eq__` was never
  meant to survive hashing), `PLW2901` (not "throughout the code base"
  as the old comment said -- a handful of sites in a couple of files),
  and `PLR0911` with `PLR0912` (the same script-engine dispatch and
  classification functions the mccabe `# noqa: C901` already named, now
  carrying it too). `D301` and `D405`/`D413` found a few sites each that
  needed fixing outright, not ignoring: most were `r"""` withheld from a
  docstring on purpose, to keep a doubled backslash rendering as one --
  `bms.py`'s magic string, two code examples in tests -- and one,
  `utils.py`'s `b'\xde\xad\xbe\xef'` example, was rendering as decoded
  Latin-1 characters instead of the literal escapes, an actual bug the
  `r` prefix now fixes; the section-heading and blank-line findings were
  autofixed. `PLR2004`, `TRY003`, `PLR0913` and `PLR0917` stay: each was
  measured too, and each is spread widely enough across the tree to be
  this codebase's normal shape rather than a short exception list.
  `SIM300` was the fifth measured that way and does not stay: see below
- **`SIM300` is selected too, and every site it found was ruff's own
  autofix.** Yoda-condition, chosen for the reason the old comment gave --
  an uppercase math symbol such as `M`, `R` or `Q` reads to the rule as a
  constant, and every finding on this tree was one of those read
  backwards, `M >= (w2 // 2)` rewritten `(w2 // 2) <= M` -- rather than a
  real Yoda condition anywhere. Equivalent either way, since flipping the
  two sides of a comparison changes nothing it evaluates to
- **Five more rule sets never surveyed before, all clean today: `FA`,
  `FIX`, `FLY`, `SLOT`, `T10`.** `TD` was the other zero-finding set the
  same survey turned up, and is not selected: it and `FIX` both watch
  TODO-style comments, one disciplining the format and the other
  refusing them outright, and only one of the two belongs in a codebase
  that finishes what it starts. `SLOT` reads as a fresh ratchet rather
  than an unenforceable one — `psbt.musig2._SessionParts` is a real
  `NamedTuple` subclass, not a construct this codebase lacks the way
  `DTZ` or `ASYNC` are
- **A monthly workflow re-checks every vendored-vector pin against
  upstream**, and opens, updates or closes a tracking issue on what it
  finds. `tests/_data/README.md`'s own "Re-checking a pin" section was a
  manual procedure, last run by hand on the dates it records;
  `.github/scripts/check_vendored_vectors.py` automates exactly that
  procedure and nothing past it -- refreshing a stale vector stays a
  decision nobody but a maintainer makes. Scope is narrower than the
  README: only entries whose `behind` already reads 0, an entry already
  documented as behind being a gap someone already decided not to close,
  which re-reporting monthly would only turn into noise. Every heading
  the script does not check for that reason, or because its path is a
  placeholder standing in for several real ones, is named in its own
  report, so nothing reads as checked that was not. `issues: write` is
  new to this repository -- every other scheduled workflow stops at
  `contents: read`, on purpose, and this one does not, also on purpose
- **Four pins move from "behind, already reviewed" to the tip, into the
  monthly check above**: `bip32_test_vectors.json`,
  `bip32_invalid_keys.json`, `bip371_test_vectors.json` and
  `bip67_test_vectors.json` were each re-checked against the current tip
  of their path and re-pinned to it, a `behind` of anything but 0 being
  exactly what the check above skips. BIP32's two and BIP67's carried no
  change at all. BIP371's 17 cases didn't either, but two of their
  `description` labels did: "PSBT_KEY_PATH_SIG" is upstream's own older
  name for the field renamed `PSBT_IN_TAP_KEY_SIG` between the original
  pin and the tip, and both labels now read the field's current name --
  the `encoded psbt` of every case is unchanged throughout
- **BIP327's eight files and BIP324's two are pinned one real path at a
  time now, not one placeholder path standing in for a whole
  directory**, which is what brings all ten into the monthly check
  above: a placeholder is not a path GitHub's own "commits touching a
  path" call can be asked about. Splitting BIP324's pair changed
  nothing else, both genuinely tipped by one commit throughout. BIP327's
  eight were not: the placeholder cited one commit as the tip of all
  eight paths, but that commit touches only `sig_agg_vectors.json`; six
  of the other seven have been untouched since the commit that added
  all eight in 2023, and `sign_verify_vectors.json` was fixed once more
  in between. Each of the eight is now pinned to its own real tip, and
  every one is still the blob already vendored -- nothing to refresh,
  the fix is only in which commit each cites
- **BIP324's two files are "identical but for line endings", not
  byte-identical as the README had it.** A blob-SHA match against
  upstream's tip only proves upstream has not moved since the pin, not
  that upstream and the vendored copy agree, and fetching the actual
  bytes found both `ellswift_decode_test_vectors.csv` and
  `xswiftec_inv_test_vectors.csv` are CRLF upstream -- `mixed-line-ending`
  normalizes our copy to LF, the same exception `bip340_test_vectors.csv`
  already documented. Nothing in either file's vectors changed; the fix
  is the Verdict describing them, and the Summary list moving the pair
  from "identical byte for byte" to "identical but for CRLF against LF"
- **`check_vendored_vectors.py` and `rpc_smoke.py` now have test files,
  matching `mutation_counts.py`'s own** -- both are loaded by path and
  their `gh`/socket/file boundaries replaced with fakes, the same
  pattern `tests/mutation_counts_test.py` already uses and for the same
  reason. Writing `check_vendored_vectors.py`'s found a real bug on the
  way: an entry with no `commit` at all -- chain data, a file this
  project composed itself, a section heading with no pin of its own --
  was silently skipped, in contradiction of the script's own docstring,
  which already claimed every such heading would be named. It is now,
  and the README's seven chain-data and composed-locally headings appear
  in a `--dry-run` report for the first time. `check_vendored_vectors.py`
  reaches 100% this way. `rpc_smoke.py` cannot: most of it is a real
  `BitcoinCoreRpcClient` talking to a real bitcoind, which is the one
  thing the script exists to have rather than mock, so that half is
  `# pragma: no cover`, monitored instead by `rpc-smoke.yml` against
  Core itself -- what is covered is every function with no client behind
  it, `check_legacy_reply`, `check_v2_reply`, `check_cookie` and
  `print_log_tail` among them, plus `main`'s own argument parsing
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
- a `mutation` workflow asks what coverage cannot — not whether a line
  ran, but whether the suite would notice if it were wrong — weekly, on
  demand, and gating nothing (issue #219). Scoped to the consensus code,
  `btclib/script/engine/` and `btclib/script/sig_hash.py`, which is where
  all three of the defects that opened the issue lived, every one of them
  inside a tree measuring 100%. cosmic-ray and not mutmut, measured on
  this tree rather than chosen: mutmut 3.7 mutates a *copy* of an
  importable package, so a `source_paths` naming one file leaves that copy
  without the modules beside it — `ModuleNotFoundError: No module named
  'btclib.script.script'` — and the scope then has to move out of the
  configuration and into a name filter on the command line, with the whole
  package mutated to get there; a 25-minute trial of it also returned
  `check was interrupted by user` for 263 of the 603 verdicts it reached,
  which is not a verdict. cosmic-ray's `module-path` is the scope, and its
  `test-command` is run verbatim, which is what lets a session override
  the `-n auto` of `tool.pytest.ini_options` and add `-x`. Two
  configurations under `.github/mutation/` and not one, although
  `module-path = "btclib/script"` with the six non-consensus modules
  excluded was measured to enumerate exactly the same 3495 mutants: the
  test command belongs to the configuration, and the two halves of the
  scope cost 1.1 s and 7.2 s of cpu per mutant, so one shared command
  would make every sighash mutant pay the engine's price. The first pass
  is what the issue asked for and refused to guess at: 727 mutants in
  `sig_hash.py` against 2768 in the engine, a survival rate measured on
  the first of those, and a `timeout` of 300 s rather than 60 because at
  60 the *unmutated* baseline timed out on a machine under load — and
  cosmic-ray answers KILLED for a timeout, so a tight one turns a slow
  mutant into a kill nobody earned. It is not a gate and is not among
  master's required checks: a
  mutant survives because a test is missing, so a red merge would stop
  whoever next touched the file for a hole somebody else left
- the standalone Bitcoin Core RPC client has its own Cosmic Ray profile.
  Its request, reply, credential, cookie, transport and vendoring tests judge
  719 enumerated mutants; 187 replacements of `|` in deferred annotations are
  filtered as inert, and the remaining 532 finish in 2m13s, with 524 killed
  and eight equivalent survivors. The run found two unchecked status
  boundaries and a `break`-to-`continue` mutation that previously waited for
  the per-mutant timeout; the tests now distinguish all three, including EOF
  as the end of an incremental read. The weekly workflow runs and reports the
  profile in a 30-minute budget and applies each configuration's operator
  filter after initialization
- an `rpc-smoke` workflow asks live bitcoinds what the recorded replies
  under `tests/fetch/_data` claim, on demand and before a release (issue
  #377). The suite classifies every one of those replies without opening a
  socket, which is the right shape for it and leaves exactly one claim with
  nothing behind it: the recording is the thing being classified.
  `.github/scripts/rpc_smoke.py` is what the workflow runs — a node in a
  temporary datadir on Core's own regtest rpc port, the reply shapes read
  off the wire before btclib classifies them, and then the same result and
  the same error through `call`. Two pins, with the rule for moving them
  beside them: v27.2, end of life upstream and the final release of the
  last major that does not recognize the `"jsonrpc": "2.0"` marker at all,
  and v31.1, whatever is current. The first is the compatibility boundary —
  a client sending the marker to a node that has never heard of it reads
  back a 1.1 reply, an rpc error under an HTTP 500 included — and no
  supported release can demonstrate that, v28 and later all knowing the
  marker. The rest is what only a node can answer: the cookie file it
  wrote, one ascii line at the path Core's layout puts it; a wrong
  credential as a 401 with an empty body; the `/wallet/<name>` endpoint of
  a node with *two* wallets loaded, one named with a space and a plus in
  it, two being the case where the endpoint is load-bearing; an amount as
  an exact `Decimal`; and the three fetcher answers against a chain the
  script generates, so the expected height is arithmetic rather than a
  recording, with a coinbase paid outside both wallets that only
  `-txindex` can answer for. The download is verified rather than trusted:
  an immutable versioned url and never a `latest` one,
  the release SHA256SUMS digest written into the workflow instead of
  fetched beside the file it describes, checked before the archive is
  unpacked — and the same comparison against a rotated digest required to
  fail in the same step, a verification nothing tests being decorative. A
  workflow of its own and not a job in test.yml, whose matrix is
  interpreters where this one is node versions, and it gates no commit:
  RELEASING.md dispatches it, and CONTRIBUTING.md carries the command for
  a bitcoind of one's own
- mypy's scope grew by `.github/scripts`, where that script lives: no test
  collects it, so a workflow dispatch would otherwise be the first thing to
  read it — and in a script of checks, a bound method used as a truth value
  is a check that cannot fail
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
- **the license is an SPDX expression** (issue #363). `license = "MIT"` and
  `license-files = ["LICENSE", "AUTHORS.md"]` replace the TOML table
  `license = { text = "MIT License" }`, the `License :: OSI Approved :: MIT
  License` classifier is gone, and `[build-system] requires` is
  `setuptools>=77`, the version that added both halves of the PEP 639 form.
  The metadata field changes with it: the free-text `License: MIT License`
  of a wheel becomes `License-Expression: MIT`, one machine-readable
  statement where there were two spellings and a classifier. What prompted
  it is a build that was already loud about it — three
  `SetuptoolsDeprecationWarning`s per distribution, the table's naming
  2027-02-18 as the date the legacy call goes — and `uv build` is now
  silent on license metadata, with `twine check --strict`,
  `check-wheel-contents`, `check-manifest` and pyroma at 10/10 unchanged.
  `AUTHORS.md` is named beside `LICENSE` rather than dropped: setuptools'
  default globs matched both, so both were already in
  `dist-info/licenses/`, and the MIT notice names "Ferdinando M. Ametrano
  and btclib contributors" with that file being where the list is kept
- **btclib is developed against the released bindings** (issue #131).
  `tool.uv.sources` is gone, so uv resolves `btclib_libsecp256k1` from
  PyPI as pip does — from a wheel wherever 0.7.1 publishes one, which is
  every platform of the test matrix, and from the sdist, compiling,
  anywhere else — and the pin is `>=0.7.1`, the first release of the
  bindings that satisfies what this version needs. What that unlocks is
  the check the pin had been waiting for: the wheel smoke test, which
  asks for the built wheel and nothing else from an empty directory, so
  that the `Requires-Dist` the wheel carries is what pulls the bindings
  in, now runs in `dist-py` and gates every pull request. It had to stay
  out of that path while no published bindings could satisfy the pin,
  since a red check nobody can turn green from a branch is noise rather
  than a gate — and for the same reason `uv.lock` reaches it as
  constraints, which bind a version without requesting a package: a
  bindings release is exactly such a red, and a requirements file would
  have installed the bindings whether or not the wheel asked for them.
  What is asserted is the version (metadata can be missing, issue #150),
  an import of `btclib.ecc.dsa` (`import btclib` runs only
  `__init__.py`, which touches no binding) and a signature round trip (a
  bindings release can install and still answer wrongly). The release
  workflow keeps a smoke test of its own, unconstrained and on the wheel
  it uploads, which is not the one `dist-py` built: no pull request
  waits on that job, where the two publish jobs do, so it is where "does
  what a user installs today still work" belongs, and a release stopping
  on the answer is the outcome wanted. It runs after the upload, not
  before: installing a dependency executes its code, and the artifact
  the publish jobs download is frozen first. The scheduled
  `published` workflow goes: it existed to run the suite against the
  bindings a user installs, which is now what every job does, and
  `latest.yml` keeps the part it does not cover by upgrading every
  dependency, the bindings included, to the newest release that satisfies
  pyproject.toml. `pip install -e .` works here now, and readthedocs
  drives uv for the lock rather than for the resolution.
- **Each `PLW1641` site the audit above narrowed to states its own reason,
  not a bare `# noqa`.** `Tx` is mutable, which is the dataclass default
  that sets `__hash__` to `None`; `EqualTransport` and
  `TxInIgnoringWitness` are test doubles nothing hashes. `ScriptPubKey`
  was the odd one, its hand-written `__eq__` setting `__hash__` to `None`
  the same way Python does for any class defining one without the other:
  writing the reason down is what asked whether the class is meant to be
  unhashable at all, answered by issue #416 above, and it carries a
  `__hash__` rather than a `# noqa` now (issue #417)

### Documentation and the website

- **The tests are documented too, and the rendered pages show only what
  is documented.** The `tests/**` exemption from ruff's D rules is gone:
  every public test function, fixture and method states what it
  verifies — the property, the published vector, the failure mode —
  rather than leaving the name to speak, under the same pydocstyle gate
  as the library's public interface. With nothing left undocumented,
  the 92 `:undoc-members:` options are gone from the `automodule`
  blocks: a member without a docstring no longer renders as a bare
  signature, so `sphinx.ext.coverage` measures something again instead
  of reporting 100% by construction (issue #290). A private or nested
  helper is not what the gate reaches — `D102`/`D103` stop at pydocstyle's
  public-interface boundary, the one the library's own private helpers
  already sit outside of — so one is documented the same way a private
  library helper is: only where the name alone does not say what it
  does (issue #349)
- **One spelling per term, throughout the prose.** BIPnnn — no space, no
  hyphen — op code, segwit, merkle, sighash, x-only, and lowercase
  p2pkh/p2sh/p2wpkh/p2tr: each is the spelling already dominant in the
  tree, now the only one. Identifiers, quoted Core code and the vendored
  vectors keep their own spellings; the few runtime messages that spelled
  a term differently ("BIP 386", "sig hash type") follow the prose, and
  the tests asserting on them with it (issue #290)
- **Every public class, method and function has a docstring, and ruff
  now fails one that arrives without.** The members autodoc rendered as
  bare signatures state their contract: the script engine's op codes
  carry the stack effect, the refusals and the consensus rule each
  comes from; the trailing-underscore variants (`ssa.assert_as_valid_`,
  `dsa.crack_prv_key_`, ...) say what the suffix means — the input
  enters already prepared, unvalidated; the core types say what
  `to_dict`/`from_dict`, `serialize`/`parse` and `assert_valid` each
  validate, mutate and preserve; and the `is_p2*`/`assert_p2*` family
  says which raises and which answers a bool. `D101`, `D102` and `D103`
  moved out of `pyproject.toml`'s ruff `ignore`, so the finished state
  is a lint gate rather than a convention; `D107` stays ignored,
  `__init__` being documented by its class (issue #290)
- **One voice throughout the prose: neutral, factual, dry, and no
  history.** Docstrings, comments, the sphinx pages and the top-level
  markdown are reviewed to the same register — the reasoning with its
  negative results, the authority cited, no unchecked numbers, one fact
  in one place — and comments that told the story of what the code used
  to be now state the same reasoning in the present tense, history
  staying in this file and HISTORY.md. `amount.py` and `fee.py` drop
  their `Args:`/`Returns:` sections for the pep257 prose the rest of
  the tree uses (issue #290)
- **CONTRIBUTING.md states the documentation style, and CLAUDE.md
  points at it.** The tone of voice, the house style and the no-history
  rule were readable only by inference from the files a contributor
  happened to open; a new "Documentation and comments" section under
  "Make Changes" states them where a contributor reads, and it is the
  single statement — CLAUDE.md references it rather than repeating it
  (issue #290)
- **The documentation has a page that is not the API reference.** Issue
  #120 asked for worked examples for beginners — "sending transactions,
  deriving wallets, etc." — against fifteen pages of `automodule` stanzas
  that answer "what does this function take" and never "which function do
  I call". `docs/source/guide.rst` is arranged by task instead of by
  module: a mnemonic and the seed under it, an account xpub and the
  BIP44/49/84/86 addresses under that, reading a raw transaction,
  building one and computing the hash it commits to, signing it and
  checking the result against btclib's own script interpreter, ECDSA and
  BIP340 on their own, a message signed with an address, and the BIP174
  roles. It says the things a reference cannot: that a `str` is hex and
  not text wherever a signature says `Octets`, which is the first mistake
  everybody makes; that a WIF is a better private key to hand in than an
  integer, carrying the network and the compressed flag with it; and what
  btclib deliberately does not do — no network, no wallet, no persistence,
  no fee estimation, no coin selection. Every private key on it is a
  published vector of BIP39, BIP143 or BIP340, so each answer is
  checkable against the specification that published it, and a warning
  says as much where a reader would otherwise reuse one
- **The examples in the documentation are executed, not asserted.** An
  output pasted by hand is true on the afternoon it was pasted and
  silently false after the next rename, so every example on the guide
  page is a doctest and `tests/docs_examples_test.py` runs it: what
  follows a `>>>` is what the library answered, and drift is a red test
  rather than something a reader discovers by typing the page in. Which
  pages are examined is read off the pages — a doctest prompt is what
  makes one an example page — so the next one is covered without a line
  here to remember. Not `sphinx-build -b doctest`: that needs a job of
  its own, reports on one runner, and would have to be added to the
  branch rule to gate anything, where a test runs on every interpreter of
  the matrix, is gated by `tests-passed` already, and leaves `uv run
  pytest` the whole command. No doctest option flags either, elision
  included: an example checked in part is not the promise the page makes
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
  `.readthedocs.yaml` now drives uv, which installs the library the
  documentation imports, builds with
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
- **tests/README.md's "no `slow` marker" section states its findings and
  the command behind each, and no number.** Its figures had been taken when
  the suite was 7936 tests; the suite has since more than doubled, and every
  one of them had stopped being true a second time, the slowest test
  included. Restating them only resets a clock, which is the argument this
  file already makes about counting its own entries: a wall clock in prose
  is a line that every commit touching the suite has to edit, and nothing
  fails when it is not edited. The findings are unchanged, and each is now
  a run a reader can make — Bitcoin Core's vector files are the biggest
  thing in the suite and still not the slow part; the cost is
  `tests/script_engine/python_path_test.py`, so a `slow` marker would save
  something real, and none is registered still because a plain `uv run
  pytest` is the run that has looked at everything; `--dist worksteal`
  beats `load`, with `-p no:randomly` part of that comparison rather than
  decoration, two schedulers timed over two collection orders measuring the
  orders. pyproject.toml's comment on the flag points at those commands
  where it pointed at the figures, and states neither a share of the
  suite's work nor a wall clock per case: the imbalance that argues for
  worksteal is which tests are the slowest and by how many orders of
  magnitude, and that outlives any number of seconds
- **Neither pyproject.toml nor tests/README.md states a count a commit can
  falsify, and most of the counts they did state were already false.** The
  suite applies `usefixtures` and `skipif` beside `parametrize`, where the
  README said only `parametrize`; `--durations` names a test in
  `tests/ecc/dsa_test.py` as the slowest in the suite, where both files
  named the `tapscript-bigmulti` cases; `-ra`'s comment described a matrix
  of 42 jobs, which is what 6 platforms by 7 interpreters would build and
  not the 14 the 4 commented-out platforms leave; the requires-python
  comment split 35 of 132 locked packages at `">=3.9"` and counted 99 with
  4 splits at `">=3.10"`, where the lock holds 122 and splits 5;
  codespell's `ignore-regex` was worth 5 findings in this file and is worth
  7; E501's comment left 267 unbreakable lines, which are 469; W505's left
  20 over-long comments, which are 19. The counts that were still true went
  with them — the 9 mypy error codes the next line lists anyway, the one
  `simplefilter` call, and the 12 camelCase words, 6 typos and 592
  identifiers of measurements no run repeats — each being a line that the
  next bump has to edit, and none of them the reason the setting is what it
  is. What stands in their place is the mechanism, or the command that
  answers today: `--durations=0 --durations-min=0` for the whole
  distribution rather than the tail above 5 ms, a `-p` plugin for the
  collection-order question, `rm uv.lock && uv lock` at either floor for
  the resolver, and the hook with its rule taken out for what a spell
  checker would say. tests/README.md also states why it gives commands and
  not numbers: another checkout's `pre-commit` run on the same machine
  doubles the baseline, so a comparison of a second or two is worth reading
  only as best of three with nothing else running
- **The lint and type-check surveys keep their reasons and lose their
  counts.** The survey of unselected ruff rule sets was the largest tally
  in pyproject.toml and said in as many words what it was for — "with the
  count, so that nobody has to run it again" — and every one of its twelve
  numbers had moved: N 498 is 604, COM 417 is 783, EM 343 is 491, FBT 203
  is 285, EXE 153 is 203, TC 136 is 207, PTH 95 is 130, ARG 93 is 138, ANN
  20 is 37, SLF 7 is 38, PERF 3 is 4, and ERA, selected since it was
  surveyed at 89, now finds nothing at all. mypy's three deliberately
  absent codes read redundant-expr (2), warn_unreachable (1) and
  possibly-undefined (3) against the 2, 4 and 1 they find today. Each keeps
  the reason it was rejected — which is what decides it — and gains the
  command that re-derives the number: `ruff check --select N --no-cache`,
  `--enable-error-code` for the first and third code, `--warn-unreachable`
  for the second. The smaller ones went the same way, `[tool.ruff.mccabe]`'s
  2 functions over the default and the 2 prints of the dice interface
  included, both right today and neither the reason for the setting.
  `[tool.typos.default]`'s shape rule counted 34 findings without it, where
  what it now says is what the measurement costs: the hook fixes in place,
  so a run without the rule rewrites the vectors it reads, an extended key's
  `ThmBZ` becoming `ThemBZ`. That is the argument the count was standing in
  for. CLAUDE.md's "never state how many" convention now says that a wall
  clock and a findings count are counts as well, that no test fails on
  either, and which command re-derives each — with the survey that says
  "so that nobody has to run it again" named as the shape to distrust, and
  a vendored file's vector count as the one kind of number that pins
  rather than rots
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
