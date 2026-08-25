# Release notes

<!-- markdownlint-configure-file
  {
    // MD024/no-duplicate-heading - "Breaking changes" is the heading of a
    // subsection under every release that has one, which is what keeps
    // the page readable scrolling down it; only a duplicate under the
    // same release heading would be the accident this rule looks for.
    // CHANGELOG.md carries the same comment, for its group headings
    "MD024": { "siblings_only": true }
  }
-->

What a user has to *act* on, and nothing else: a breaking change, a
migration, a default that moved under them. Everything a reader would
merely notice is in [CHANGELOG.md](./CHANGELOG.md), which is the record
behind this file.

Release names follow *[calendar versioning](https://calver.org/)*:
full year, short month, short day (YYYY-M-D)

## v2026.9 (work in progress, not released yet)

### Breaking changes

- **A bool is no longer accepted as an integer** (issue #1206), which
  matters most where it was accepted as a *key*:

  ```python
  b58.wif_from_prv_key(True)   # was a WIF of the key 1
  ```

  Act on it if you pass `True` or `False` where an integer is expected —
  a key, a multiplier, a curve parameter, anything typed `Integer`. The
  class is always `BTClibTypeError`; the message depends on which check
  the value reaches first, so match on the class and not on the text.
  A key is the case to watch: `wif_from_prv_key(True)` says "not a
  private key" and `p2pkh(True)` "not a private or public key", where
  `mult(True)` and `dsa.sign(msg, True)` say "non-integer: True".

  A BIP340 x-only key is where that lands hardest, `ssa` having answered
  about a bool rather than refusing one — `True` as the key at x = 1,
  `False` as a complaint about the coordinate that the `verify`
  spellings swallow. All nine entry points raise a `BTClibTypeError`
  now: `point_from_bip340pub_key` where it returned that point, the four
  `verify` spellings where they returned False, and the four `assert_`
  spellings where they raised a `BTClibRuntimeError` for `True` and a
  `BTClibValueError` for `False`. An `except` written for either stops
  catching this.

  An `IntEnum` is unaffected and stays an integer. CHANGELOG.md has why
  a bool was reaching a key at all, and what the two arms did with it.
- **A `Point`'s coordinates are no longer accepted as bools** (issue
  #1249). `is_on_curve((x, False))` used to answer about the point at
  infinity for any x, `False == 0` in Python; `is_on_curve((True, y))`
  about the point at x = 1. Act on it if you build a `Point` tuple from
  a value that could be a bool — a JSON decoder's `true`/`false`
  included: `point_from_pub_key`, `point_from_bip340pub_key`,
  `PreparedPoint` and `bytes_from_point` all raise `BTClibTypeError`
  now, on every curve. CHANGELOG.md has which coordinate the message
  names.
- **`borromean.sign` refuses a private key or a nonce outside 1..n-1**
  (issue #1243). Neither sequence was read as a scalar, so a key of 0,
  of `n` or of `q + n` signed, where every other signer in `ecc`
  refuses all three. `q + n` is the one to look for in your own code:
  step 2's own `% ec.n` reduced it to `q`, so it produced a signature
  that verifies, and it now raises `BTClibValueError: private key not
  in 1..n-1`. A nonce of `k + n` was reduced by the same line and is
  refused by the same check.

  ```python
  borromean.sign(msg, ks, idx, [q + secp256k1.n], rings)  # signed
  borromean.sign(msg, ks, idx, [q % secp256k1.n], rings)  # reduce first
  ```

  Act on it if you build a key or a nonce by addition and rely on the
  reduction. An `int` key already in 1..n-1 signs exactly as it did.

  Widened in the same call: `ks` and `sign_keys` are
  `Sequence[Integer]` where they were `Sequence[int]`, so a scalar held
  as its `n_size` octets or as hex is taken here as `mult` and
  `dsa.sign` take it. Those spellings used to leave Python's own
  `OverflowError` and `TypeError`. `sign_key_idx` is still
  `Sequence[int]`: it indexes a ring.

- **`pedersen.commit` refuses a blinding factor of 0 mod n** (issue
  #1250). `commit(0, v)` and `commit(ec.n, v)` returned `v*H`, a
  commitment with no blinding in it that anyone can recompute by
  guessing `v`, and now raise `BTClibValueError: invalid (unblinded)
  commitment: r is 0 mod n`. `assert_as_valid` raises the same error,
  recomputing through `commit`; `verify` answers `False` instead of
  raising, as it already does for every other invalid `(r, v)`.

  Act on it if you construct a blinding factor that can land on 0 mod
  n — the sum of two blinding factors chosen to cancel each other is
  the case to watch; a blinding factor drawn at random and never
  summed to that value is unaffected. `v` is not checked: `commit(r,
  0)` is untouched.

- **`ecc` no longer takes a WIF or an extended key as a private key**
  (issue #1188). The entry points that took a private key however it was
  spelled — every one in `dsa`, `ssa`, `musig2`, `dleq`, `ecies`,
  `ellswift` and the three nonce modules, `gen_keys`, `Signer`,
  `anti_exfil_signer_commit` and `anti_exfil_sign` among them — took a
  WIF, an xprv, an
  `int` or octets. They now take an `int`, its `n_size` octets, or their
  hex. `borromean` is not among them and never was: it asked for a
  sequence of `int` outright, and issue #1243's bullet above is what
  gave it the same three spellings — never the WIF.

  ```python
  dsa.sign(msg, wif)                                  # was
  dsa.sign(msg, prv_keyinfo_from_prv_key(wif)[0])     # is
  ```

  `prv_keyinfo_from_prv_key` is the converter that decodes every
  spelling, and it answers the network and the compression flag beside
  the scalar; take the first of the three. The point is that the
  conversion is now a call you write, where it used to be a try-and-see
  inside the signer.

  Act on it if you hand one of those nine anything but a scalar.
  **`ecc.bms` is not among them**: message signing is bitcoin, so it
  still takes a WIF, an xprv and everything else it took, and everything
  below is about the nine and not about it.

  Refusals change with the input. `NotAPrvKeyError` is no longer raised
  by the nine — wrong-size octets, a non-hex string and a bad-checksum
  WIF are `bytes_from_octets`' own complaints now — and `bms` raises it
  exactly as before, so an `except NotAPrvKeyError` around `bms.sign`
  stays load-bearing while one around `dsa.sign` stops catching.

  One shape changes exception *family*: an extended **public** key
  spelled as a `BIP32KeyData` was an `InvalidPrvKeyError`, which is a
  `BTClibValueError`, and is now a `BTClibTypeError`. The private one
  does not appear here because it was accepted before and is withdrawn,
  not re-messaged.

  `except BTClibValueError` does not cover everything these nine raise —
  but it never did, a wrong type having always been a `BTClibTypeError`.
  If that is your catch, widen it to `BTClibException`; the advice is
  the same as it always was, and this change makes more inputs reach
  it.

- **`ecc.ssa` no longer accepts a BIP32 extended key as a BIP340 public
  key** (issue #1188). `BIP340PubKey` was

  ```python
  BIP340PubKey = Integer | Octets | BIP32Key | Point | PreparedPoint
  ```

  — with `BIP32Key` in it as far back as `v2023.7.12` — and is now

  ```python
  BIP340PubKey = int | Octets | Point | PreparedPoint
  ```

  Act on it if you pass a **public** extended key — an xpub as text, the
  same text as ASCII bytes, or a public `BIP32KeyData` — to
  `ssa.verify`, `ssa.verify_`, `ssa.assert_as_valid`,
  `ssa.assert_as_valid_`, `ssa.point_from_bip340pub_key` or the
  batch-verification entry points. That is the whole of the withdrawal:
  an xprv and a private `BIP32KeyData` were refused before this change
  too, the first as octets it could not parse and the second by name.

  Convert it first. From a `BIP32KeyData` the public key is `.key`, and
  from either text spelling it is `BIP32KeyData.b58decode(xpub).key`:
  33 compressed SEC octets, which these still take. One check does not
  survive the conversion: an xpub handed to a non-secp256k1 `ec` was
  refused, its version bytes matched against the curve — as text the
  complaint that surfaced was about octets, as a `BIP32KeyData` it was
  about the type. The 33 octets carry no version, so nothing compares
  them to the curve; what is left is the lift, which on a curve of the
  same size answers for about half of them and refuses the rest. On
  `secp256k1`, which is BIP340's curve, the answer is the same as
  before.

  Everything else is unchanged, and one thing is wider: an `int`, the
  p-size octets BIP340 defines, 33 or 65 SEC octets, their hex, a
  `Point` and a `PreparedPoint` all still work, and a `bytearray` or
  `memoryview` now works at the p-size too, where before it worked only
  at the SEC sizes.

  Refusals move as well, and the one to act on is a class change. What
  the old dispatch could not tell apart it reported as a type error,
  and each of those is a value error now: a `Point` off the curve, the
  point at infinity, a tuple that is malformed or out of range, a
  buffer of no key size, and a buffer of a key size that is no point.
  Code catching `BTClibTypeError` alone around any of them has to
  widen to `BTClibValueError` or to `BTClibException` — which is the
  rule rather than the list, the list being what was measured.
  CHANGELOG.md has the wording changes, which need no action.

- **`fingerprint` is `btclib.bip32`'s, and takes a BIP32 key** (issue
  #1188). It was

  ```python
  from btclib.to_pub_key import fingerprint
  fingerprint(key, network)
  ```

  — the spelling as far back as `v2023.7.12` — and is now

  ```python
  from btclib.bip32 import fingerprint
  fingerprint(xkey)
  ```

  Act on it if you import it from `to_pub_key`, if you pass anything
  that is not an extended key, or if you pass a network. Any extended
  key still works, SLIP132's `zprv` and `upub` among them, and so does
  every spelling of one — the text, that text as bytes, or a
  `BIP32KeyData`. The first is an import change and nothing more. For
  the second, the fingerprint of a plain public key was only ever
  `hash160` of its compressed SEC octets cut to four; take it
  directly, deriving the public key first if what you hold is a scalar
  or a WIF, which the old function accepted too.

  For the third, the argument refused a key whose version bytes named
  another network, and nothing inherits that. Reconstructing the check
  is a membership test rather than a name comparison: take the version
  — a `BIP32KeyData` has `.version`, and `BIP32KeyData.b58decode` gets
  one from the text — and ask whether it is in
  `xprvversions_from_network(net)` for a private key or
  `xpubversions_from_network(net)` for a public one, which is the pair
  the argument chose between by the kind of key it had. Not
  `network_from_xkeyversion(...) == net`: that reverse lookup answers
  "testnet" for the versions testnet, regtest, signet and testnet4
  share, so a name comparison rejects a signet key for being signet,
  which is the trap `to_prv_key` records as issue #207.

- **`psbt.psbt_utils.deserialize_tx` no longer accepts `None` for
  `include_witness`** (issue #1190). The annotation declared `bool |
  None` and a comment called `None` "either encoding"; the code took the
  same strict arm for `None` as for `False`, `not None` being `not
  False`. A third spelling of the second behaviour, and the only one
  whose documented meaning was never implemented. Passing `None` now
  raises `BTClibTypeError` as any other non-bool does.

  Act on it only if you call this function with `None`, which no caller
  in this package did: pass `False`, which is what `None` was doing.
  `True` is unchanged and is still the default, and is the value that
  accepts either encoding.

- **`NETWORKS["regtest"].genesis_block` was byte-reversed and is now
  Bitcoin Core's value** (issue #1203):

  ```text
  0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
  ```

  where it read the same octets in the opposite order,
  `06226e46…f188910f`. Nothing inside btclib reads the field, so
  addresses, WIF and the bip32 versions are unaffected, and no other
  network's value moves. A caller that read it — seeding a regtest
  chain, or comparing against `getblockhash 0` — got a silent wrong
  answer rather than an error, and one that had compensated by reversing
  the octets itself has to stop doing so. CHANGELOG.md has why.

- **The importable package moved from the repository root to
  `src/btclib/`** (issue #1322). `import btclib` resolves exactly as it
  did for anything installed from PyPI or from a built wheel; what moved
  is the checkout. A checkout is no longer importable straight from its
  own root, and a path inside this repository that named the package
  directly — `btclib/…` — now reads `src/btclib/…`.

  Act on it if your tooling imports from a checkout of this repository
  rather than from an installed distribution, or reads the package's
  path directly rather than through `import btclib`. CHANGELOG.md has
  every file the move touched.

### Worth knowing, though nothing raises

- **A `bytearray` and a `memoryview` are octets, and now the signatures
  say so** (issue #1238). `Octets` and `String` name all four spellings,
  and `Integer`, `PrvKey`, `PubKey`, `Key` and `Command` are built from
  them. Every one of those buffers was already accepted at run time —
  the type checks inside the library listed them — so no call that
  worked stops working, and nothing new is refused.

  Act on it only if you type-check your own code against btclib: a
  `# type: ignore[arg-type]` you wrote to pass a buffer is now unused,
  and mypy reports an unused ignore as an error under
  `warn_unused_ignores`. Delete those and the annotation says what the
  library does.

  Several places did not in fact take a buffer, and now do. The two worth
  reading are the ones that answered rather than raising: a legacy BMS
  signature held as a bytearray was checked as a BIP322 signature, which
  it is not, and came back False; and an address handed to `bms.sign` as
  `bytes` was not stripped of surrounding blanks where the same address
  as text was, so it signed under a different address than the caller
  named and said `mismatch between private key and address`.

  One exception class moves with that second fix: a non-ascii address as
  `bytes` raised Python's `UnicodeDecodeError` and now raises
  `BTClibValueError: non-ascii character in address`, so an `except
  UnicodeDecodeError` around `bms.sign` stops catching it.
  CHANGELOG.md lists them.

## v2026.8.21

### Breaking changes

- **`ansi_x9_63_kdf` is `btclib.kdf.ansi_x9_63_kdf`.** SEC 1's key
  derivation function moved out of `btclib.ecc.dh` into a module of its
  own, beside RFC 5869's `hkdf` which arrives with it, so neither `from
  btclib.ecc import ansi_x9_63_kdf` nor `from btclib.ecc.dh import
  ansi_x9_63_kdf` resolves any more: write `from btclib.kdf import
  ansi_x9_63_kdf`. The signature, the answer and the exceptions are
  unchanged, and `btclib.ecc.dh.diffie_hellman` is unaffected -- it calls
  the KDF where it now lives. CHANGELOG.md has why a KDF is not under
  `ecc`.

- **`psbt.musig2.session_context` returns `Session`, not a bare
  `SessionContext`.** `session_context(psbt, vin_i, aggregate_pub_key) ->
  musig2.SessionContext` is now `-> Session`, a `NamedTuple` of
  `.context` (the `SessionContext` it used to return alone) and
  `.key_agg_ctx` (the `KeyAggContext` it built the session on). A caller
  reading the result as a `SessionContext` -- passing it to
  `btclib.ecc.musig2.sign` or `partial_sig_verify_`, or reading
  `.pub_keys`, `.tweaks`, `.is_xonly`, `.msg` or `.agg_nonce` off it --
  takes `.context` first. CHANGELOG.md has why.

- **`musig2.SessionValues` carries three more fields.** The frozen
  dataclass gained `L`, `second` and `pub_keys_set` after `e`, so
  `SessionValues(Q, gacc, tacc, b, R, e)` is a `TypeError` now. Reading
  one is unaffected, and reading is what it is for: it is what
  `session_values(session_ctx)` hands back, and every field it already
  had answers the same thing. A caller that builds one itself passes the
  three, which are what a per-signer key-aggregation coefficient is
  computed from -- fixed for a session, so computed once here rather
  than by each of `_session_key_agg_coeff`'s callers. CHANGELOG.md has
  the measurement.

- **`pip install btclib` no longer installs `btclib_secp256k1`.** The
  bindings are the `secp256k1` extra now — `pip install
  "btclib[secp256k1]"` — and an install that does not ask for them gets a
  btclib that answers on its own Python arithmetic: tens of times slower,
  and not constant-time, both of which `SECURITY.md` publishes. Nothing
  raises and no import fails, so an upgrade that forgets the extra is a
  quiet change of implementation rather than an error; ask
  `btclib.curves.is_libsecp256k1_serving()` if the answer matters.
  Environments that resolve from a lock file are unaffected until the
  lock is regenerated.

- **`dsa.recover_pub_key_` reports a key_id outside 0..3 as a
  `BTClibValueError`.** It raised `BTClibRuntimeError` — "signature
  verification failed" — for a key_id whose `x_K = r + j*n` is no field
  element, that being the verification refusing it a double multiplication
  later; the screen that now refuses it says so as a value error, so an
  `except BTClibRuntimeError` written against key_id 4 catches nothing.
  `recover_pub_keys_` is unaffected, suppressing both classes as it always
  did, and so is every key_id a signature can name. `recover_pub_keys_`
  also stops reporting the point at infinity as a recovered key, which
  CHANGELOG.md has.

- **a transaction naming one outpoint twice is refused.**
  `Tx.assert_valid` implements Core's `bad-txns-inputs-duplicate` now, so
  building, parsing or serializing such a transaction raises
  `BTClibValueError` where it used to go through, and so does validating
  a psbt whose unsigned transaction is one. A caller that was holding a
  duplicate on purpose -- to measure it, or to feed it to the script
  engine -- passes `check_validity=False`, which is what that flag is
  for. CHANGELOG.md has why the rule is not gated on
  `unsigned_template`.

- **`Tx.parse` refuses a BIP144 marker over witnesses that are all
  empty.** It used to take such octets and answer the transaction without
  them, which re-serialized to the stripped encoding -- a different
  `hash`, so a caller relaying what it had parsed sent something other
  than what it received. It raises `BTClibValueError("superfluous witness
  record")` now, which is Bitcoin Core's own refusal of the same bytes,
  and `Block.parse` inherits it, a block's marker being per transaction.
  `check_validity=False` does not get past it: that flag gates
  `assert_valid`, and what is malformed here is the encoding rather than
  the transaction, which no field records. No transaction on any chain is
  affected -- Core has never accepted one -- so what changes is what a
  caller may be handed by a peer or read out of a file. CHANGELOG.md has
  the reasoning, and what it cost two of BIP174's vectors.

- **`TxOut.from_dict` refuses a `null` value.** It used to build an output
  of zero satoshi, `valid_sats_amount` reading `None` as zero for the
  caller it was written for; a stored dict carrying `{"value": null}` now
  raises `BTClibValueError` instead of loading as an output that pays
  nothing. `PsbtOut.amount` is unaffected: there `None` is the field being
  absent, which a psbt output may legitimately say.

- **the two descriptor parsers refuse three arguments they used to
  take.** `descriptors.parse(descriptor, <not a network name>)` and
  `miniscript.parse(expression, <not P2WSH or tapscript>)` are refused
  where they used to be carried into the object and refused later, or not
  at all; and `prv_keys` must be a mapping or `None` in both. A caller
  passing values of the declared types is unaffected, and the network
  name is now normalized as everywhere else in the library — `" MainNet
  "` and `"mainnet"` were already one network to the encoders, and the
  parsed object says so too. `taproot.parse`'s `exit_on_op_success` is
  the bool bullet below's, that being where every flag of the library was
  classified.
- **thirty-odd `bool` arguments that used to be accepted are refused.**
  A flag that decides what is computed is a kind and not a truth, so
  `dsa.sign(msg, q, lower_s="no")` — which returned a low-s signature,
  `"no"` being true — and `pub_keyinfo_from_prv_key(q, compressed="no")`
  — which returned the compressed key, and with it a different address —
  raise `BTClibTypeError` now. So do `compressed` in the nine other
  signatures that carry it, `grind`, the script engine's `segwit`,
  `const_scriptcode`, `skip_execution` and `exit_on_op_success`, `signed`,
  `include_witness` and `unsigned_template` at the psbt boundary,
  `shuffle_inp` and `shuffle_out`, BIP322's `legacy`, `sort`, `pad`,
  `shuffle`, `to_be_hashed`, `extendable`, `lexicographic_sorting`,
  `emulators`, `musig2`, `active` and `internal`. A caller passing a
  `bool` is unaffected, and mypy already refused every one of these calls;
  `0` and `1` are refused too, `bool` being a subclass of `int` and that
  being what made the type check no check at all. The flags that decide
  only whether a check runs — `check_validity`, `check_root_xkey`,
  `verify_checksum`, `strict`, `bip380_enforced` and the rest, listed in
  `tests/bool_parameter_test.py` — are still read for their truth, on the
  one condition issue #884 added: a truth's `True` has to be its
  conservative value. Every wrong value is true, so the misreading is
  always the flag's `True`, and three whose `True` was the permissive one
  are refused with the kinds above — the script engine's `verified`,
  which suppressed the NULLFAIL rule for a signature that failed to
  verify; `assert_signed`'s `allow_partial`, which accepted an input
  nobody signed; and `point_from_octets`'s `hybrid`, which parsed the
  0x06 and 0x07 prefixes it was written to keep out.

- **the serialization boundary refuses what it used to take, and reports
  through the exception contract.** A `from_dict` handed a mapping
  without a field raises `BTClibValueError` where it raised a bare
  `KeyError`, so an `except KeyError` around one catches nothing now;
  `Witness.from_dict({"stack": None})` was an empty witness and is
  refused; `tx.serialize(1)` and `block.serialize(0)` want the `bool`
  they declare; `PsbtIn.serialize(psbt_version=3)` and `PsbtOut`'s want
  one of the two versions there are; and `Bip21.parse(b"bitcoin:...")`
  raises `BTClibTypeError` rather than `BTClibValueError`, which an
  `except BTClibValueError` written against it no longer catches. A
  caller passing values of the declared types is unaffected.

- **four arguments that used to be accepted are refused.**
  `KeyGroup(1.5, keys)` built a group with a float quorum and
  `KeyGroup(keys, verify="no")` one with `verify=True`, `"no"` being
  truthy; `estimated_input_sizes(psbt_in, tx_in, sizer=<not callable>)`
  went through for every input the function answers for on its own, the
  sizer being consulted in one branch; and `satisfaction_sizer(one_key)`
  took the key for a list of them, `Iterable[Octets]` accepting a `str`
  and a `bytes`. All four raise a `BTClibTypeError` now. A caller handing
  any of them a value of the declared type is unaffected, and mypy already
  refused the first three.

- **the `_var` suffix finishes its sweep: `ellswift.encode_var`,
  `decode_var`, `create_var`, and `dsa.crack_prv_key_var`.** The map of
  BIP324's ElligatorSwift branches on its data — its inverse measures
  29.62x, 28 calls of 50 returning early — so the four public names built
  on it take the suffix, `crack_prv_key_` becoming `crack_prv_key_var_`
  where both conventions apply and the prepared-input underscore stays
  last. `ellswift.xdh` is unchanged at 1.01x, being dominated by a `mult`
  that is regular and blinded: the key agreement is not the map.
  CONTRIBUTING.md lists what measured at the floor and kept its plain
  name, with the figure for each.

- **nine more reads are properties, `master_fingerprint` and
  `capabilities` among them.** `PsbtSigner.master_fingerprint` and
  `PsbtSigner.capabilities` -- the two argument-less members of the signer
  contract -- are properties, and so are `HwiSigner`'s,
  `SoftwareSigner`'s and `SignerDecorator`'s implementations of them, plus
  `PsbtView.prevouts`. Drop the parentheses.

  For an adapter written against the contract this is a change to
  implement and not merely to call: a signer of your own declares
  `master_fingerprint` and `capabilities` with `@property` now, or as a
  plain attribute, which a Protocol property accepts as well.
  `psbt_signer_contract.assert_psbt_signer` reports the mismatch if you
  forget. Nothing costs a device round trip in any implementation that
  exists -- HWI's own `get_master_fingerprint` does, and if that is the
  signer being wrapped, the contract can be relaxed deliberately.

- **six `bool` methods are properties: `tx.is_segwit`, not
  `tx.is_segwit()`.** `Tx.is_segwit`, `Tx.is_coinbase`, `TxIn.is_segwit`,
  `TxIn.is_coinbase`, `OutPoint.is_coinbase` and `Block.is_segwit` took
  nothing but `self` and were the only argument-less bools in the library
  that were not properties -- thirty others were. Drop the parentheses;
  keeping them is `TypeError: 'bool' object is not callable`, which is a
  loud failure and not a silent one.

  It also makes a bug unsayable rather than merely caught: `if
  tx.is_segwit:` with the parentheses forgotten was a bound method, and
  every bound method is true. mypy's `truthy-function` reports it, so
  anyone type-checking was already safe; anyone not type-checking was not.

- **seven public `bool` names carry a prefix now.**
  `b32.has_segwit_prefix` is `b32.is_segwit_prefixed`,
  `BlockContext.bip34_active` is `is_bip34_active`,
  `Block.has_segwit_tx` is `Block.is_segwit`,
  `Miniscript.within_resource_limits` is `is_within_resource_limits`,
  `Miniscript.needs_signature` is `is_signature_required`,
  `CurveGroup.jac_equality` is `is_jac_equal`, and `hwi.available` is
  `hwi.is_available`. Old name, `AttributeError` or `ImportError`; new
  name, same answer, no change of signature or behaviour.

  Six other bools keep an English name — `Psbt.inputs_modifiable`,
  `Psbt.outputs_modifiable`, `Psbt.has_sig_hash_single`,
  `Miniscript.mixes_timelocks`, `Miniscript.has_duplicate_keys` and
  `miniscript.reads_back` — where the name is the standard's and a prefix
  would cost the reading. Those are unchanged.

- **`dsa.verify` answers False for a message that is not octets, where
  it raised.** It reduced the message with `hf` before the `try`, so a
  hex string that is not hex was a `BTClibValueError` where `verify_`,
  handed the hash, answered False about the same input. `ssa.verify` and
  `ssa.batch_verify` did the same and move with it. Code that relied on
  the refusal — a `try` around `verify` to catch a malformed message —
  has to read the bool instead; `assert_as_valid` is the spelling that
  still says why.

  The other way round, a `None` or a float in a verification is a
  `BTClibTypeError` now where it was a native `TypeError` or
  `AttributeError`: `ssa.batch_verify`'s three sequences,
  `merkle_proof.verify`'s branch, `bms.verify`'s and `bip322.verify`'s
  signature, and both engine signature adapters. Code catching
  `TypeError` keeps working, `BTClibTypeError` being one; code catching
  `AttributeError` around one of those two `verify` calls has to catch
  `TypeError` or `BTClibException`. `pedersen.verify` refuses a
  commitment of a type no point has, where it answered False.
- **the functions whose duration follows their operand gain a `_var`
  suffix, and `mod_inv` changes meaning.** The plain name beside the
  suffix is the one a secret may be handed. In `number_theory`,
  `mod_inv` is `mod_inv_var`, `xgcd` is `xgcd_var`, `legendre_symbol` is
  `legendre_symbol_var`, `mod_sqrt` is `mod_sqrt_var` and `tonelli` is
  `tonelli_var`; in `curves`, `double_mult` and `multi_mult` are
  `double_mult_var` and `multi_mult_var`, and `CurveGroup` renames
  `aff_from_jac`, `aff_from_jac_batch`, `x_aff_from_jac`,
  `y_aff_from_jac`, `add`, `add_aff`, `double_aff`, `y`, `y_even`,
  `y_low` and `y_quadratic_residue` the same way. `curves.mult` is
  unchanged, its two arms making the same additions for every scalar,
  and so is everything above the arithmetic: the suffix is measured on
  the value a function receives, not inherited from what it calls.

  An import or a call of one of the old spellings is an `AttributeError`
  or an `ImportError`, and each new name is a rename with no change of
  signature or behaviour.
  `mod_inv` is the exception and does not raise: the name survives and
  now returns the same inverse computed with a random blinding factor,
  so a caller inverting a secret is protected without changing a line,
  and one inverting public data should say `mod_inv_var` to keep the
  1.11x. CHANGELOG.md has the measurement behind each suffix and
  CONTRIBUTING.md the rule.

- **eleven `check_*` functions are renamed, and the prefix means one
  thing.** It meant four at once: nine refusals returning `None`, two
  bool verdicts, a converter returning bytes and a query returning a
  pair of bools. The nine are `assert_*` now --
  `assert_nullfail`, `assert_nulldummy`, `assert_pub_key_num`,
  `assert_signature_num`, `assert_not_disabled`, `assert_stack_size`,
  `assert_minimal_push`, `assert_balanced_if` and
  `assert_psbt_signer` -- `b32.check_witness` is
  `b32.bytes_from_witness_program`, and
  `psbt_signer_contract.check_optional_protocols` is
  `optional_protocols`. What keeps the prefix is the two that answer a
  bool *and* refuse what cannot be an answer:
  `script.engine.script.check_pub_key` and
  `script.taproot.check_output_pubkey`.

  An import of any of the eleven old names is an `ImportError`, and the
  new name is a rename with no change of signature or behaviour.
  `tests/name_contract_test.py` is the gate that keeps the four prefixes
  meaning what CONTRIBUTING.md says they mean.

- **a verification refuses a type it does not declare, where it used to
  answer `False`.** `dsa.verify` takes a `PubKey` -- bytes, a hex
  string, a `BIP32KeyData` or a `Point` -- and an int is none of those:
  in this library an int is a private key. `dsa.verify(msg, 12, sig)` is
  a `BTClibTypeError` now where it was `False`, and so is
  `ecc.dleq.verify_proof` with one. A key of a *declared* type that is
  not valid is still `False` -- `dsa.verify(msg, "not a key", sig)` is
  unchanged -- so a caller filtering signatures that arrived as bytes is
  unaffected; what changes is a call mypy already refused.

  The converters underneath moved with it, and that is the part to act
  on: `to_pub_key`'s `point_from_pub_key`, `pub_keyinfo_from_pub_key`,
  `point_from_key` and `pub_keyinfo_from_key` answer a `BTClibTypeError`
  for a type no spelling of a key has, where every refusal used to be a
  `BTClibValueError`. `to_prv_key`'s `int_from_prv_key` and
  `prv_keyinfo_from_prv_key` do the same, so a `Point` passed as a
  private key is a `BTClibTypeError` where it was a `NotAPrvKeyError`
  reporting three formats tried against a value none of them could hold.
  Code catching `TypeError` or `BTClibException` keeps working; code
  catching `BTClibValueError` — or `NotAPrvKeyError` — alone around one of
  those six has to widen.

- **a bad network name raises `BTClibValueError`, not `KeyError`.**
  Every function taking a `network: str` -- `b58.p2pkh`, `b32.p2wpkh`,
  `to_pub_key.fingerprint`, `bip39.mxprv_from_mnemonic` and the rest --
  refused an unknown name with a bare `KeyError`, which is a
  `LookupError` and so not caught by an `except BTClibValueError`. Code
  catching `KeyError` around one of these has to catch
  `BTClibValueError` instead; code already catching `BTClibValueError`
  starts working. A non-string name is a `BTClibTypeError` where it was
  an `AttributeError`. Nothing that worked stops working: the same call
  with a good name is unchanged, and a name in the wrong case or with
  spaces around it -- `"MAINNET"` to `b32.address_from_witness` -- is
  accepted now where it used to raise.

- **a malformed argument raises a btclib error, not a native one.** The
  rest of issue #744's census, and the same move the network name above
  made: an out-of-range derivation index was an `OverflowError`, an
  out-of-range `vin_i` an `IndexError`, a header timestamp that is no
  datetime an `AttributeError`, a hex string that is not one a bare
  `ValueError`. Each is a `BTClibValueError` or a `BTClibTypeError` now.
  Code catching `ValueError` or `TypeError` keeps working, the two
  deriving from those; code catching `OverflowError`, `IndexError` or
  `AttributeError` around one of these has to catch `BTClibException`,
  or one of the two builtins, instead.

  Two of them are not a narrowing, and are what to act on. What is
  neither `bytes` nor a hex `str` is a `BTClibTypeError` where
  `bytes_from_octets` used to return it untouched -- a tuple of 33 ints
  passed `taproot.assert_valid_control_block` as a control block size,
  and `bin_str_entropy_from_entropy(())` was reported as zero bits. And
  a dozen calls that answered a malformed argument with a *number*
  refuse it: `sig_hash.taproot` with an `input_index` past the end of
  the vin, `taproot.input_script_sig` with a negative leaf index,
  `bech32.encode` with a negative digit, `mod_inv` with a float,
  `int_from_json_number` with 1.5, `Psbt.weight_estimate` on an
  incoherent psbt. CHANGELOG.md lists all twelve.

- **the individual point multiplications are private.** `from
  btclib.curves.curve_group import mult_jac` is an `ImportError` now, and
  so is every other variant of `curve_group` and `curve_group_2`: the
  `mult_*`, the two `double_mult_*`, `multiples`, `cached_multiples`,
  `cached_multiples_fixwind`, `odd_multiples`, `signed_odd_multiples`,
  `jac_from_aff`, `mods`, `wNAF_of_m`, `convert_number_to_base` and
  `multiplier_decomposer` each carry a leading underscore. Use `mult`,
  `double_mult` and `multi_mult`, which are where they were and are the
  three that check a point is on the curve before multiplying it -- which
  is what the variants never did and what made them worth hiding. A variant
  that used to default to `w=4` takes the width from its caller.
- **verifying and recovering no longer take `lower_s`.**
  `dsa.assert_as_valid`, `dsa.verify`, `dsa.recover_pub_keys`,
  `dsa.recover_pub_key` and their four trailing-underscore twins used to
  take `lower_s: bool = True` in the slot before `hf`, and
  `bms.assert_as_valid` and `bms.verify` in the slot after the signature:
  `dsa.verify(msg, key, sig, True, sha256)` and `bms.verify(msg, addr,
  sig, False)` are a `TypeError` now, as is either spelled as a keyword.
  Drop the argument. Both forms of `s` are then accepted, which is what
  the `True` default refused and what Bitcoin Core's `verifymessage`
  always accepted -- whether `s` is the low one of the two was decided by
  whoever signed. A caller that does want the strict answer asks a private
  function for it: `dsa._assert_as_valid_(c, QJ, r, s, ec,
  lower_s=True)`. `dsa.sign` is unchanged, `lower_s=True` and all, the
  rule being the signer's: a high-s signature in a transaction is
  non-standard and does not relay.
- **an ECDSA signature is low-R now, and signing with your own nonce asks
  for `grind=False`.** `dsa.sign` and `dsa.sign_` grind by default, as
  Core has done since its 0.17, so the signature of a given key and
  message is a different one for about half of all messages -- and one DER
  byte shorter. `grind=False` is the plain RFC6979 signature, which is
  what a caller pinning btclib's bytes has to pass now.

  Two things to act on rather than one, because grinding is a search over
  nonces and its default pairs with `nonce=None`: `dsa.sign(msg, key,
  nonce)` and `dsa.sign_(msg_hash, key, nonce)` raise
  `BTClibValueError("grinding derives its own nonce")`, as does either
  with a sign-to-contract `commit`. Pass `grind=False` beside the nonce.
  The pair is refused rather than resolved in the caller's favour or the
  library's: which of the two won would not be readable back out of the
  signature.

  `dsa.sign_recoverable` and with it `bms.sign` are unaffected, a compact
  signature having no DER pad to save, and so is `bip322.sign`, which asks
  for the plain signature to keep reproducing the BIP's own vectors.
- **an ECDSA signature is low-R now.** `dsa.sign` and `dsa.sign_` grind
  for it wherever the nonce is theirs to derive, as Core has done since
  its 0.17, so the signature of a given key and message is a different one
  for about half of all messages -- and one DER byte shorter. `grind=False`
  is the plain RFC6979 signature, which is what a caller pinning btclib's
  bytes has to pass now. `dsa.sign_recoverable` and with it `bms.sign` are
  unaffected, a compact signature having no DER pad to save, and so is
  `bip322.sign`, which asks for the plain signature to keep reproducing
  the BIP's own vectors.
- **`NETWORKS` is read-only, and `Network.magic_bytes` is gone.**
  `NETWORKS["mynet"] = Network(...)` now raises `TypeError`. It was never
  honoured throughout: the extended-key version lists are built at import,
  so keys of a network registered afterwards were refused by `bip32` while
  `network_from_xkeyversion` named it. A `Network` is an encoding table and
  every field of one is the same for every deployment of that network, so
  the only thing a caller had to register a network *for* was a custom
  signet's p2p magic -- and that identifies a node, not an encoding.
  `bitcoin_core_rpc.magic_from_chain(chain)` and
  `magic_from_signet_challenge(challenge)` are where it is now;
  `NETWORKS[net].magic_bytes` has no replacement here, and note the byte
  order is Core's `pchMessageStart` where this field was its reverse.
  A custom signet is `BitcoinCoreFetcher(client, "signet",
  signet_challenge=...)`, which is the check that magic was read for.
- **`XPRV_VERSIONS_ALL` and `XPUB_VERSIONS_ALL` are frozensets.**
  `version in XPRV_VERSIONS_ALL` is unchanged and is what nearly every use
  was; indexing, slicing and `.index()` are not. The one use of the
  parallel positions -- the xpub version paired with an xprv version -- is
  `network.xpubversion_from_xprvversion(version)`.

- **a MOV-weak curve is refused with `BTClibValueError`, not
  `UserWarning`.** `Curve(p, a, b, G, n, cofactor)` with the default
  `weakness_check=True` used to raise `UserWarning("weak curve")` for a
  curve whose embedding degree is under 100, which no `except
  BTClibValueError` catches; every other refusal in that constructor
  already raised one. A caller that builds its own curves and catches
  `UserWarning` has to catch `BTClibValueError` instead. The catalogued
  curves are unaffected: they are built with `weakness_check=False`, the
  check having been paid once in `test_catalogued_curves`.
- **taproot takes no curve.** `output_pubkey`,
  `output_pubkey_from_merkle_root`, `output_prvkey`,
  `output_prvkey_from_merkle_root` and `check_output_pubkey` used to end
  in `ec: Curve = secp256k1`, and a caller passing one positionally --
  `output_pubkey(internal_key, script_tree, ec)`,
  `check_output_pubkey(q, script, control, ec)` -- now gets a
  `TypeError`. Dropping the argument is the whole of the change: BIP341
  is defined for secp256k1 alone, and the parameter was never honoured,
  the arithmetic behind it having always used secp256k1's generator
  whatever was passed.

- **`BIP32KeyData` is frozen.** `xkey.index = 0` on an already-built
  extended key, or on one `b58decode`/`parse` returned, now raises
  `dataclasses.FrozenInstanceError` instead of silently taking effect. A
  caller that needs a modified copy uses `dataclasses.replace(xkey,
  index=0)`, which re-validates by default -- the same function
  `BIP32KeyData(...)` still takes, and still defaulting to `True`.

- **the script number zero is the empty vector.** `encode_num(0)` was
  `b"\x00"` and is `b""`; `decode_num(b"")` was a `BTClibValueError` and
  is `0`; and `script.serialize([0])`, which pushes what `encode_num`
  writes, was `0100` and is `00` -- OP_0, with no "consider using OP_0"
  warning left to raise. A caller pinning any of those bytes has one
  substitution to make, and a caller reading a script number back has one
  refusal fewer to catch. `push_int(0)`, `op_int(0)` and the engine are
  unchanged, all three having answered OP_0 and the empty vector all
  along. The reason to act rather than to keep the old spelling: `0100`
  is not a minimally encoded script number, so the interpreter refuses
  it as one wherever MINIMALDATA is in force -- btclib's own engine
  included. One message moves with the pair: a negative zero read as a
  number under that flag is refused as `non-minimal encoding of 0: 80`,
  where it read `non-minimal encoding of zero`, the general check now
  answering for it too.

- **`borromean.sign` and `borromean.assert_as_valid` compute a
  different challenge hash.** The four-part preimage has been `m || R
  || ring || position` since `v2023.7.12`, the message hash before the
  point or the closing `e0`; it is `R || m || ring || position` now,
  matching secp256k1-zkp's `rangeproof` module. Every borromean
  signature this module ever produced was made with the old order and
  does not verify under the new one, and there is no version byte in
  the wire format to switch on -- CHANGELOG.md has why the break was
  worth paying.
- **`musig2.partial_sig_agg` refuses a session that carries an
  adaptor.** It briefly answered `ssa.Sig | PreSignature`, the type
  depending on `session_ctx.adaptor`; that shipped on `main` for under
  an hour before this release, so "before" is that commit rather than
  a numbered release. It is `-> ssa.Sig` again, exactly as every
  caller before adaptor signatures existed already relied on, and
  raises `BTClibValueError` for a session that carries an adaptor. The
  new `partial_sig_agg_adaptor` is the spelling for that session,
  answering the `PreSignature` the union used to. CHANGELOG.md has
  why: a return type keyed on a field of an argument taxes every
  caller that will never touch an adaptor, and it moved against where
  secp256k1-zkp#330 is taking the C API.

- **`borromean.sign` returns a `BorromeanSig`, and `verify` and
  `assert_as_valid` take one instead of the bare `e0`/`s` pair they
  have taken since `v2023.7.12`.** Before: `e0, s = borromean.sign(msg,
  ks, sign_key_idx, sign_keys, pubk_rings)` and `borromean.verify(msg,
  e0, s, pubk_rings)`. Now: `sig = borromean.sign(...)` and
  `borromean.verify(msg, sig, pubk_rings)` -- `sig` is a `BorromeanSig`
  with `.e0`, `.s` and `.ec`, `serialize()`/`BorromeanSig.parse()` for
  its wire format, and `verify`/`assert_as_valid` also accept the
  `serialize()`d octets directly in `sig`'s place. A caller unpacking
  the old tuple reads `sig.e0`/`sig.s` instead; a caller passing `e0`
  and `s` as two arguments passes `sig` as one. `sign`/`assert_as_valid`
  answering the point at infinity with a bare `BTClibValueError` also
  changes, to a `BorromeanRingError` (a `BTClibRuntimeError`): a caller
  catching `ValueError` around that one corner case catches nothing
  now. CHANGELOG.md has why, for both.

- **`borromean.verify` answers `False`, not a bare `IndexError`, for a
  `sig` whose ring shape disagrees with `pubk_rings`; `assert_as_valid`
  and `sign` refuse one with `BTClibValueError`, not the same
  `IndexError`.** Before: a `sig` with fewer rings than `pubk_rings`, or
  a ring with fewer s-values than it has keys, indexed past the end of a
  ring's tuple in `assert_as_valid`; a `sign_keys` shorter than
  `pubk_rings` indexed past its own end in `sign`'s step 2 the same way.
  Both reached a plain `IndexError`, neither caught by `verify`'s
  `except (ValueError, BTClibRuntimeError)` nor documented by any of the
  three functions. Now: `assert_as_valid` and `sign` both raise
  `BTClibValueError` naming the ring and the counts, and `verify`
  answers `False` for it, the same as any other invalid signature. A
  caller catching `IndexError` around any of the three calls to detect
  either case has to catch `BTClibValueError`, or nothing at all against
  `verify`, which no longer raises here. CHANGELOG.md has why the check
  is a `BTClibValueError` and not `BorromeanRingError`.

- **`BorromeanSig(e0, [[]], ...)` -- a ring with no keys -- is refused,
  where it used to build silently.** Before: `BorromeanSig.__init__` and
  `BorromeanSig.parse`, both with `check_validity`'s default of `True`,
  accepted it; `assert_as_valid` then reached a bare `IndexError`
  indexing `e[i][0]` on the empty list built for that ring, escaping
  `verify`'s `except (ValueError, BTClibRuntimeError)` the same way
  issue #1088's did. Now: `BorromeanSig.assert_valid` refuses it as
  `BTClibValueError`, so construction and `BorromeanSig.parse` raise it
  directly, `assert_as_valid` raises it in place of the `IndexError`,
  and `verify` answers `False` for it like any other invalid signature.
  A caller building a `BorromeanSig` with `check_validity=False` to hold
  one anyway still has it refused the moment `assert_as_valid`,
  `serialize` or `assert_valid` itself runs. CHANGELOG.md has why the
  check lives on `BorromeanSig` and not beside `_assert_matches_pubk_rings`.

- **`borromean.sign` refuses a `sign_key_idx[i]` that is not a position
  in its own ring.** Before: a value at or past the ring's size walked
  `s[i][j - 1]` and `pubk_rings[i][j - 1]` past the end of the ring's
  tuple in step 2, a bare `IndexError`; a negative value did not raise
  at all, Python's own negative indexing quietly signing a different
  position than the one named and returning a `BorromeanSig` that does
  not verify. Both are `BTClibValueError` now, naming the ring, its size
  and the index, raised once before step 1 -- which is also what refuses
  a ring with no keys on the signing side, no index being valid into an
  empty one. CHANGELOG.md has why this is a bound on `sign_key_idx` and
  not a copy of the empty-ring check above.

### Worth knowing, though nothing raises

- **Signing on the Python arm now checks the signature before answering
  with it**, where it did not check at all. Bitcoin Core's `CKey::Sign`
  does the same and the delegated arm always did, so this is the fallback
  ceasing to answer differently from the arm it stands in for — a
  signature that does not verify is a computation that went wrong, and
  the protection is not publishing one.

  Nothing raises that did not raise before and no signature changes: the
  same key and message give the same octets. What moves is the time, and
  it moves a long way. On an installation without the bindings a call
  that took 165.09 microseconds takes 907.87 — five and a half times what
  it was — the check adding 742.78, which is about four and a half
  signatures. One session, 5 rounds of 300 calls, minimum kept, noise
  0.24, an Apple M5, macOS 26.6, arm64, CPython 3.14.6.

  What to act on, and only if that shows: `dsa.sign(..., verify=False)`
  declines the check and gives the old time back, and
  `dsa.sign(..., pub_key=...)` hands in the key the check would otherwise
  derive, which brings the call to 754.17 — the check down to 589.08.

  Neither is needed on an installation with the bindings, where the call
  is 33.06 against 13.52 unchecked: the check adds 19.54 there, and
  handing the key in takes that to 13.75. Same process as the figures
  above and not the same run — a signature there being a twelfth of one
  here, those rows are 9 rounds of 3000 calls, noise 0.04.
  `btclib.curves.is_libsecp256k1_serving()` is what says which arm is
  answering.

- **The same is true of BIP340 signing**, and there the check is the
  specification's own step rather than a policy of this library:
  `ssa.sign`, `ssa.sign_` and `ssa.Signer` now check before answering,
  where the Python arm checked not at all. On an installation without the
  bindings a call that took 305.50 microseconds takes 962.81 — 3.15 times
  what it was — the check adding 657.31, which is about two signatures.
  One session, 9 rounds of 300 calls, minimum kept, noise 3.01, the same
  machine as above.

  `verify=False` declines it, on the free functions and on a `Signer`
  alike. There is no key to hand in as there is for ECDSA: BIP340 checks
  under a point the signer already holds, which is why that scheme pays
  two signatures where ECDSA pays four and a half, and why no `pub_key`
  argument exists here to bring it down.

### The bindings are now `btclib_secp256k1`

- **The secp256k1 bindings were renamed, and btclib requires the new
  name**: `btclib_secp256k1>=0.8.0.1`, where it required
  `btclib_libsecp256k1>=0.7.1.3`. `lib` named the C library, and a python
  distribution is not that library. Nothing in btclib's own API moves,
  and an install of btclib picks the new dependency up on its own.
  What to act on, and only if you name the bindings yourself: the old
  distribution stops at 0.7.1.3 and nothing on PyPI bridges the two, so a
  project that pins `btclib_libsecp256k1` beside btclib pins a package
  btclib no longer uses. The two can be installed at once — the import
  package was renamed with the distribution, so neither shadows the other
  — which is what makes moving one requirement at a time possible.

## v2026.8.9

### Breaking changes

- **the kind of a musig2 tweak is a `bool` and nothing else.**
  `apply_tweak`, `key_agg_and_tweak` and `SessionContext` used to read
  `is_xonly` for its truth, so `1` was an x-only tweak and `"false"` was
  one too; both raise `BTClibTypeError` now. A caller passing `True` or
  `False`, which the annotation always asked for, is unaffected.
- **a `BitcoinCoreFetcher` asks the node which chain it serves, before
  the first fetch.** One `getblockchaininfo` per fetcher, and a node on
  another chain than the label is a `BTClibValueError` instead of
  addresses for coins that are not there. `BitcoinCoreFetcher(client,
  network, verify_network=False)` is the previous behaviour, for a
  caller that has checked by other means or is talking to something that
  does not answer that call.
- **`btclib.keystore` is `btclib.wallet`, and its two classes are named
  after the family they now belong to.** The module is a package holding
  three kinds of wallet behind one vocabulary, so `from btclib.keystore
  import BIP32KeyStore, KeyStore, AddressInfo` becomes `from btclib.wallet
  import BIP32KeyWallet, KeyWallet, AddressInfo`. The methods a caller
  already used are unchanged in name and in answer -- `address`,
  `next_address`, `addresses`, `address_info`, `prv_key`, `sign`, `add`,
  `is_watch_only`, `in`, `len()` -- and what is added is the surface the
  other two wallets share: `script_pub_key`, `redeem_script`,
  `witness_script`, `position_of` and `branches`. `AddressInfo` carries
  two fields more, `branch` and `index`, so a caller comparing a whole
  record has to pass them; the three it had are in the same order.
  Two error messages read "wallet" where they read "keystore": an address
  the wallet never handed out, and the refusal to sign without a private
  key.
- **a `KeyManager` has one method more.** `psbt.sign` now offers a taproot
  input its script path as well as its key path, and asks for a leaf
  signature through `sign_schnorr_script_path(pub_key, origin, msg_hash,
  leaf_hash)`. A manager written against v2026.8.7 implements `sign_ecdsa`
  and `sign_schnorr` only: mypy stops accepting it where the protocol is
  asked for, and a taproot input carrying leaf scripts reaches it with an
  `AttributeError`. The method signs with the leaf key untweaked -- the
  tweak is what the control block proves -- and `None` from it is a
  manager saying it holds no key for that leaf, as `None` from the other
  two already is.
- **`btclib.descriptors` is a package, and its three checksum tables moved
  with the module into it.** `INPUT_CHARSET`, `CHECKSUM_CHARSET` and
  `GENERATOR` are `btclib.descriptors.descriptors.INPUT_CHARSET` and its
  two neighbours; they were never exported and are the tables BIP380's
  checksum is computed from, which `checksum`, `add_checksum` and
  `strip_checksum` answer with. Every exported name is unchanged: `from
  btclib.descriptors import parse` and its neighbours reach the same
  objects, and `btclib.descriptors.miniscript` is the new subgroup beside
  them.

### What it buys

- **A message can be signed for an address no key can be recovered from.**
  `ecc.bms` signs with a key and lets the verifier recover it, so it
  speaks only about the addresses that *are* a public key hash: a taproot
  address is a tweaked BIP340 key and a p2wsh address is the hash of a
  script, and no recovery flag names either. The new `btclib.bip322`
  makes the address the script_pub_key of a virtual output and the
  signature whatever spends it, so verification is `script.engine` rather
  than a key comparison, and every script the engine runs is a script
  that can sign -- multisig, taproot, time locks. Both directions and all
  four variants: `sign` writes the *simple* and *full* forms for the
  script types a single key satisfies, and `verify` reads those, the
  *proof of funds* psbt, and the *legacy* compact signature `ecc.bms`
  already made. It answers BIP322's three states rather than two,
  `InconclusiveError` being what today's rules cannot judge. The BIP's
  own vector files are vendored whole and every case runs, the error
  cases included and nothing marked `xfail`. SIGHASH_ALL is enforced
  through the interpreter, which reports what it consumed as a signature,
  rather than guessed at from the shape of a stack element -- and that is
  what makes a proof of funds a proof: ANYONECANPAY commits to no other
  input, so a signature lifted out of the transaction that really spent a
  utxo would otherwise satisfy that utxo's input inside a proof of
  control over it.
- **A witness script says what spends it.** `wsh()` no longer refuses a
  miniscript, and `btclib.descriptors.miniscript` is BIP379's language on
  its own: `parse` reads an expression, `Miniscript.script` compiles it,
  `from_script` reads a script back into the expression it is, and `str`
  writes that expression out again. The round trip is the property both
  directions are for -- a signer handed a witness script can say what
  spends it without being told, which is what miniscript exists for. The
  type system comes with it, `parse` naming the innermost fragment of an
  ill-typed expression rather than the whole, and so does the sanity a
  descriptor is held to: `wsh(<miniscript>)` is refused where the
  expression is malleable, needs no signature, mixes timelocks in blocks
  with timelocks in seconds, repeats a key, or has a spend that would
  pass a resource limit -- the same five Bitcoin Core refuses, in the same
  words. Both of BIP379's contexts are implemented, `P2WSH` and
  `TAPSCRIPT`; a miniscript is readable and spendable as a `tr()` leaf;
  `Miniscript.satisfy` picks a branch and satisfies it non-malleably; and
  `psbt.finalize` spends such an input. The oracle is Core's own
  `fixed_tests`, vendored whole: every expression it holds is checked in
  both contexts for validity, for the script it compiles to, for the type
  answers Core asserts, for every resource bound its calls pass, and for
  both round trips.
- **Three sources of addresses answer one set of questions.**
  `btclib.keystore` is `btclib.wallet`, a package holding three kinds of
  wallet whose words mean the same thing whichever one a caller holds:
  `script_pub_key(branch, index)`, `address`, `next_address`,
  `redeem_script`, `witness_script`, `position_of`, `address_info`,
  `addresses`, `len()`, `in` and `is_watch_only`. `BIP32KeyWallet` is the
  one that was there; `DescriptorWallet` is a descriptor per chain, built
  from BIP389's `<0;1>` multipath spelling or from an account xpub; and
  `ScriptWallet` is for the scripts no descriptor states -- the multisig
  wallets predating output descriptors that miss BIP380-390 by a detail,
  a `<n> OP_CSV OP_DROP` where miniscript writes `OP_CSV OP_VERIFY`, or a
  BIP67 sort applied to the *derived* keys of a quorum, which is an order
  no ranged descriptor can state. `position_of` is the one that is not a
  convenience: it is "is this output mine", the whole script computed at
  every position of every branch and compared -- never a key origin whose
  four-byte fingerprint matches, which is what would send change to
  somebody else -- and it takes the output as a `ScriptPubKey`, as bytes
  or hex, or as the address. The non-goals are unchanged and now stated
  once for all three: no utxos, no balances, no transaction building, no
  persistence, no encryption at rest.
- **A psbt taproot input is offered its script path as well as its key
  path.** `PSBT_IN_TAP_SCRIPT_SIG` was a field this library read,
  verified and finalized and never wrote, so the only script path
  signature a tree could produce was a BIP373 MuSig2 aggregation, one
  leaf shape of the several BIP371 describes. `sign` now offers each
  candidate the psbt names -- a key filed under a tapleaf hash by
  `PSBT_IN_TAP_BIP32_DERIVATION`, the leaf itself in
  `PSBT_IN_TAP_LEAF_SCRIPT`, both required as Bitcoin Core's signer
  requires them -- and asks a `KeyManager` for a leaf signature through
  `sign_schnorr_script_path`. That key signs as it is: a script path
  spend proves the leaf, the output key's tweak being what the control
  block carries, so there is no merkle root to tweak by. One input may
  come back signed for both paths, which of the two is spent being the
  Finalizer's choice.
- **What this library refuses to guess at, a caller can now supply.**
  `finalize` takes an `InputSolver` and `estimated_input_sizes` a
  `SolutionSizer`, for the inputs each was refusing not for want of data
  but for want of knowledge nobody but the caller has: a witness script
  of no standard kind, whose spend built from the signatures and the
  script is a guess that fails when the network runs it rather than when
  it is built, and a taproot script path, where which leaf will be spent
  is not in the psbt. Neither is asked in place of an answer btclib can
  work out, and neither takes over the bookkeeping BIP174 asks of a
  Finalizer. `Psbt` grows `weight_estimate` and `vsize_estimate` to pass
  a sizer, a property being unable to take one, and `satisfaction_sizer`
  is a sizer for a miniscript: the branch a spend will build, where
  `miniscript_sizer` answers the largest it could -- a timelocked
  recovery quorum behind the same address used to pay for whichever
  branch was larger even when it never opened it.
- **A signer written outside btclib can be held to the contract.** A
  protocol is a promise the type checker reads and nothing runs, so an
  adapter answering a five-byte fingerprint, an xpub derived from the
  wrong path, or a signature on an input whose key origin names another
  master type-checks and is wrong at the first spend. `check_psbt_signer`
  asks that question from outside and takes any `PsbtSigner` -- a command
  line adapter, an in-process driver, a signing service -- and it is a
  function belonging to no test framework. Beside it, `select_device` and
  `merge_devices` are the choice a caller makes before it holds a signer
  at all, by fingerprint and in an order that is the caller's;
  `SignerNotFoundError` tells a backend that is not installed from a
  device that refused; and `SoftwareSigner.from_accounts` builds a signer
  on the accounts a device exported, for the master fingerprint they came
  from, where the constructor takes one key and answers that key's own.
- **Three parsers answer for their own input.** `OutPoint` accepts half a
  coinbase marker, as Bitcoin Core does -- its rule is the conjunction
  where this library's was the exclusive or -- so a transaction naming a
  utxo through a synthetic funding transaction of that shape can be read
  at all, which is what BIP322's proof-of-funds vectors do and what
  `Psbt.parse` used to refuse before any signature could be looked at.
  `Psbt.b64decode` raises `BTClibValueError` for base64 it cannot read,
  where `binascii.Error` and a bare `ValueError` escaped from the codec.
  And a malformed `hwi enumerate` entry is a `SignerError`, carrying what
  the backend said, rather than an exception from inside the parsing of
  it. `tests/fuzz_test.py` reaches the entry points it was missing -- the
  base64 wrappers, `ecies.Envelope.parse`, and the two text languages
  `descriptors.parse` and `miniscript.parse` -- and adding the first of
  them is what found the `Psbt.b64decode` defect.
- **The flow the ordinary suite skips is run against a real node, on a
  schedule.** An `integration` workflow downloads a pinned Bitcoin Core
  release, checks it against the sha256 four guix builders attested, and
  runs the round trip end to end: btclib exports an account, Core imports
  it and pays it, btclib signs the spend and the node relays it. Two
  things it does not do: gate a merge -- a Core release or an unreachable
  download is not a branch's fault -- and trust a green exit, a step
  after the run failing the job if a regtest test skipped rather than
  ran, which is how a fixture that stopped finding the node would
  otherwise report success.

## v2026.8.7

The first release since 2023, and the largest; every entry of it is in
[CHANGELOG.md](./CHANGELOG.md). What follows is what a user has to act on
and what a user gains.

Every change is a *behaviour* change somewhere, so the honest summary is
this: btclib now refuses input it used to accept, reports errors it used
to swallow, and no longer lets one object's mutation reach another. If
something that worked stops working, the entry explaining why is in
CHANGELOG.md.

### Breaking changes

The changes below break code that worked on v2023.7.12. Each is described in
full in [CHANGELOG.md](./CHANGELOG.md). Every "before" spelling was checked
against the `v2023.7.12` tag.

- **A descriptor parsed from an xprv no longer derives a hardened step
  on its own.** `descriptors.parse` keeps no private key: it neuters the
  xprv and fills the `prv_keys` mapping handed to it, and
  `script_pub_keys`, `satisfy`, `update_psbt_input` and their neighbours
  take that mapping back as a last argument. `parse(d).script_pub_keys(0)`
  becomes `keys = {}; parse(d, prv_keys=keys).script_pub_keys(0, keys)`
  where the path has a hardened step; everything else is unchanged.
- **`str_from_index_int(i, "H")` raises.** A derivation path is written
  with `h` or `'`, the two hardened indicators BIP380 allows; the
  uppercase `H` that BIP32 writes its own vectors with is still read and
  is no longer written. Pass `"h"` or `"'"`, or take the default.
- **`btclib.bitcoin_core_rpc` is the `bitcoin-core-rpc` package.** The
  Bitcoin Core rpc client is no longer a module of btclib: it is
  [a distribution of its own](https://pypi.org/project/bitcoin-core-rpc/),
  which btclib now depends on, so `pip install btclib` still brings it and
  `import btclib.bitcoin_core_rpc` no longer resolves. `from
  bitcoin_core_rpc import ...` is the spelling, and
  `btclib.fetch.BitcoinCoreRpcClient` and
  `btclib.fetch.bitcoin_core.BitcoinCoreRpcClient` keep working unchanged.
  The one behaviour that moves with it: reaching the client through either
  of those names and catching `btclib.exceptions.RpcError` no longer
  catches, the package raising its own — `bitcoin_core_rpc.RpcError` is
  what a direct `client.call` raises now. A `Fetcher` is unaffected and
  still raises btclib's, `status` and `code` included.
- **`btclib.fetch.bitcoin_core.core_chain_from_network` is
  `chain_from_network`**, and its pair
  `bitcoin_core_rpc.network_from_core_chain` is `network_from_chain`. The
  rename is the `bitcoin-core-rpc` package's, in the v2026.8.7 release
  btclib now requires, and it leaves no alias behind: the `core_` prefix
  said inside a package named for Core what the package name already said.
  Both take and return what they always did.
- **`from btclib.ec import ...` is `from btclib.curves import ...`.** Every
  name the package exports is the name it exported before.
- **`Block.weight` is the weight of the block**, where it was the sum of
  its transactions' weights: Core's `GetBlockWeight`, so the 80-byte header
  and the var_int holding the transaction count are counted too — 332 more
  for a block with hundreds of transactions, 324 for one holding a single
  transaction — and `Block.vsize` moves with it. `Tx.weight` is unchanged.
  This is the number consensus reads, `MAX_BLOCK_WEIGHT` bounding it; the
  sum is still available as `sum(t.weight for t in block.transactions)`,
  and `Block.stripped_size` is the other quantity a block is bounded by.
- **a block is proved against a network's pow limit, mainnet's unless you
  say which.** `BlockHeader.assert_valid_pow()` and `Block.assert_valid()`
  compared the hash with the target and made none of `CheckProofOfWork`'s
  four range checks on that target, so a regtest or signet block passed as
  a mainnet one. Both now take a `pow_limit_bits`, and a block of another
  network is answered `proof-of-work target above the limit` until it is
  named: `assert_valid(REGTEST_POW_LIMIT_BITS)`. `Block.__init__`, `parse`
  and `serialize` have no such parameter, so build with
  `check_validity=False` and validate in a second step.
- **a psbt carrying a PSBT v2 field is refused**, where every one of the
  twelve was filed under `unknown` and round-tripped. BIP370 forbids them
  in version 0, which is the only version btclib reads, so
  `Psbt.b64decode` now answers `PSBT_IN_PREVIOUS_TXID is not allowed in a
  v0 psbt` and names whichever of the twelve it found. What this breaks is
  a psbt of your own using one of those type bytes — global `0x02` to
  `0x06`, input `0x0e` to `0x12`, output `0x03` and `0x04` — as a spare
  slot for data of your own: pick a byte no BIP has taken, or `0xfc`,
  which is reserved for exactly that.
- **`finalize_psbt` refuses a taproot input that carries no taproot
  signature**, where it used to build a script_sig out of the input's
  `PSBT_IN_PARTIAL_SIG` entries — a spend BIP341 gives no meaning to and
  btclib's own script engine rejects. A p2tr input is now finalized from
  `PSBT_IN_TAP_KEY_SIG` or `PSBT_IN_TAP_SCRIPT_SIG`, which is what
  `btclib.psbt.musig2` writes for a MuSig2 session and what any taproot
  signer writes; an input carrying neither answers "missing taproot
  signature".
- **a psbt whose global version or input sighash type is not four octets
  wide is refused.** BIP174 defines both as a little-endian uint32, and
  both were read at whatever length they arrived at and written back at
  four: `PSBT_GLOBAL_VERSION` of `02` in one octet was version 2, and
  `PSBT_IN_SIGHASH_TYPE` of `01` in one octet was SIGHASH_ALL. Both now
  answer `invalid global version length: 1 bytes instead of 4` and
  `invalid sig_hash type length: 1 bytes instead of 4`. What this breaks is
  a psbt written by something that padded neither field to its width; write
  the four octets. `psbt_utils.deserialize_int` is gone with the last of
  its call sites — `deserialize_sized_int` is the one to use, with the
  width of the field.
- **a psbt whose MuSig2 fields are malformed is refused**, where all four
  type bytes BIP373 defines were filed under `unknown` and round-tripped:
  input `0x1a`, `0x1b` and `0x1c`, output `0x08`. They are fields now, so
  a key or value of the wrong size is an error rather than opaque data —
  `invalid musig2 aggregate pub key length: 32 bytes instead of 33` and
  the like — and what this breaks is the same thing the entry above
  breaks, one of those bytes used as a spare slot for data of your own:
  `0xfc` is reserved for exactly that. `PsbtIn.to_dict` and
  `PsbtOut.to_dict` carry the new fields, and `from_dict` needs them, so a
  dict written by an older btclib does not load.
- **`Psbt.tx` is computed, not stored, and `Psbt(...)` takes the
  transaction's version where it took the transaction.**
  `Psbt(tx, inputs, outputs, version, hd_key_paths, unknown)` is
  `Psbt(tx.version, inputs, outputs, version, hd_key_paths, unknown,
  fallback_lock_time, tx_modifiable)`, and `Psbt.from_tx(tx)` — which
  now takes the input and output maps too — is the way to build one
  from a transaction. Reading `psbt.tx` still works and gives the same
  transaction; *writing* into it no longer reaches the psbt, because
  what comes back is built from the fields at every access:
  `psbt.tx.vin[0].prev_out = outpoint` is now
  `psbt.inputs[0].previous_tx_id, psbt.inputs[0].output_index`, and
  `psbt.tx.lock_time = n` is `psbt.fallback_lock_time = n`.
  `Psbt.to_dict()` carries the fields it holds — `tx_version`,
  `fallback_lock_time`, `tx_modifiable`, and the new per-input and
  per-output ones — with the transaction beside them for reading;
  `from_dict` needs the fields, so a dict written by an older btclib
  does not load. Why the format is held this way, and not as BIP174's
  transaction with the BIP370 fields shadowing it, is in the module
  docstring of `btclib.psbt.psbt`.
- **`sort_inputs`, `sort_outputs` and `join_psbts` can refuse a version
  2 psbt**, and `combine_psbts` refuses psbts of different versions. The
  first three are a Constructor's work, which BIP370 gates on
  `PSBT_GLOBAL_TX_MODIFIABLE`; nothing changes for a version 0 psbt,
  which has no such field. For the fourth, convert first with
  `to_v0()` or `to_v2()`.
- **`btclib.curves` no longer exports the individual multiplications**: the
  eleven `mult_*` variants, `multiples`, `cached_multiples` and
  `jac_from_aff` come from `btclib.curves.curve_group`, or from
  `curve_group_2` for `mult_sliding_window`, `mult_w_NAF` and
  `mult_endomorphism_secp256k1`. `mult`, `double_mult` and `multi_mult` are
  where they were.
- **`btclib.ec.libsecp256k1` and `btclib.ecc.libsecp256k1` are gone.**
  `mult`, `dsa.sign` and `ssa.sign` call the bindings themselves.
- **`btclib.bip32.bip32.ec` is gone.** BIP32 is defined for secp256k1 and
  for nothing else, so it was never configuration.
- **`borromean.ec` and `borromean.hf` are gone**, and are `ec` and `hf`
  parameters of `sign`, `verify` and `assert_as_valid`, with the same
  defaults.
- **`btclib.ecc.sign_to_contract` is gone**, and the commitment is a
  keyword-only parameter of `dsa.sign` and `ssa.sign`:
  `dsa_commit_sign(commit, msg, prv_key)` is
  `dsa.sign(msg, prv_key, commit=commit)`, returning the same
  `(sig, receipt)`, and `dsa_verify_commit(commit, receipt, msg, key, sig)`
  is `dsa.verify(msg, key, sig, commit=commit, receipt=receipt)`. ssa takes
  a commitment now too, which the module never offered. **The signature is
  not the one v2023.7.12 produced**, and an opening kept from it no longer
  opens: the scheme is libsecp256k1-zkp's `ecdsa_s2c` now, tagged hashes
  and all, because the old one let two commitments over one message leak
  the private key. Re-sign, and do not pass a nonce of your own beside a
  commitment — that is refused, the commitment having to reach the nonce
  derivation.
- **`check_validity` is keyword-only**, in all 91 signatures that take it:
  `f(..., check_validity=False)`, never positionally. `strict` of
  `dsa.Sig.parse` follows it behind the same star.
- **`ssa`'s `msg_hash` and `m_hashes` parameters are `msg` and `msgs`**, and
  take a BIP340 message of any size rather than a 32-byte array.
- **`BlockHeader`'s third parameter is `merkle_root`**, not `merkle_root_`.
- **`multiplier_decomposer` takes the scalar alone**:
  `multiplier_decomposer(m)`, where it was `(m, ec)`. The curve is what the
  bug was — it decomposed modulo `ec.p` where the congruence holds modulo
  the group order, so `mult_endomorphism_secp256k1` answered the wrong point
  for every scalar above ~2^127. The constants are secp256k1's and
  `CurveGroup` has no `n` to offer, so the parameter is gone rather than
  corrected.
- **`OutPoint`, `TxOut`, `Witness`, `Script` and `ScriptPubKey` are frozen
  dataclasses.** Assigning to a field raises `FrozenInstanceError`; build a
  new instance, or use `dataclasses.replace`.
- **`Witness.stack` is a `tuple[bytes, ...]`.** `Witness([*w.stack, element])`
  replaces `append`, and code comparing a stack against a list has to compare
  against a tuple. The constructor still takes any sequence, and `to_dict`
  still yields a list.
- **`borromean.assert_as_valid` returns `None`** and raises on failure, as its
  `dsa`, `ssa` and `bms` counterparts do. It used to return a `bool`, so
  `if borromean.assert_as_valid(...)` accepted forged ring signatures in
  silence; `borromean.verify` is the one that answers a bool.
- **`dsa.Sig.parse` rejects trailing bytes.** A script signature and a PSBT
  partial signature are a DER encoding *plus* a sighash type byte, and the
  parse used to ignore that byte instead of refusing it: `Sig.parse(sig[:-1])`
  is the spelling now, and `strict=False` keeps the old leniency for a caller
  that wants it.
- **`ScriptPubKey` equality compares the network type**, `"main"` or
  `"test"`, not the network name: a testnet `ScriptPubKey` is now equal to a
  signet, regtest or testnet4 one with the same script, those four networks
  sharing every address prefix, and mainnet is still equal to none of them.
  Code asserting that two test networks differ has to compare `.network`
  itself.
- **`sig_hash.legacy_script` and `sig_hash.witness_v0_script` are gone.**
  Both returned the list of script codes for zero, one, two ...
  OP_CODESEPARATORs executed, and both built each rung by re-serializing a
  parse, which is not the bytes a signature commits to. `sig_hash.legacy`
  now elides the separators itself, where Bitcoin Core elides them, so a
  legacy script code is the script as it stands; a segwit v0 one keeps
  them, as BIP143 says; and `from_tx(..., codesep_index=k)` is how a
  signer asks for the script code after the k-th of them.
- **`sig_hash.taproot_annex_and_ext` loses its `prevouts` parameter.**
  `taproot_annex_and_ext(tx, prevouts, vin_i)` is
  `taproot_annex_and_ext(tx, vin_i)`, the parameter having gone unused;
  dropping it moves `vin_i` to second position, so a positional caller
  breaks even where it passed `prevouts` as `None` or `[]`.
- **`sig_hash.SIG_HASH_TYPES` is a `frozenset`, not a `list`.** Every use
  of it is a membership test — `assert_valid_hash_type` and the script
  engine's own check — and a `list` was one shared mutable value nobody
  was meant to hold onto. Indexing it, appending to it, or comparing it
  against an equal-content list breaks; `sig_hash_type in
  SIG_HASH_TYPES` is unaffected.
- **`btclib.network.n_versions` is gone**, with the `_REPEATED_NETWORKS` list
  it counted for: the version-prefix lookups no longer index a parallel list
  of names, so the number of prefixes per network stopped being a fact about
  anything. `len(xprvversions_from_network(net))` is the spelling if it is
  wanted.
- **`script.engine.script.check_balanced_if(script)` is
  `script.engine.script_op_codes.check_balanced_if(condition_stack)`**, and
  it answers a different question: it was a pass over a parsed script
  counting OP_IF, OP_NOTIF and OP_ENDIF, and it is now the check Bitcoin
  Core makes once the interpreter loop is over, on the condition stack the
  loop leaves behind. The count could not see a conditional closed before
  it was opened, which is the script it let through.
- **`Psbt.parse`'s parameter is `data: BinaryData`**, not `psbt_bin:
  Octets`, so only a caller naming it by keyword has to change. Bytes and
  hex strings parse as before; a `BytesIO` now does too, and is left
  positioned right after the psbt.
- **`psbt_utils.deserialize_map` returns the map**, not the `(map, stream)`
  pair: `deserialize_map(data)[0]` is `deserialize_map(data)`, and a caller
  threading the stream through passes its own.
- **`PsbtIn.parse` and `PsbtOut.parse` take `BinaryData`**, not a decoded
  `Mapping[bytes, bytes]`: each reads one map from the stream, its
  terminator included, and leaves the stream on the next one.
- **`PsbtIn.serialize` and `PsbtOut.serialize` end with the `0x00`
  delimiter** that `Psbt.serialize` used to append for them, as Bitcoin
  Core's `PSBTInput::Serialize` does. A serialized psbt is unchanged;
  code appending that byte itself has to stop.
- **The three psbt constants are Bitcoin Core's.**
  `btclib.psbt.psbt.PSBT_MAGIC_BYTES` is the whole five-byte header,
  `b"psbt\xff"`; `PSBT_SEPARATOR` is the `0x00` that ends a map and is
  imported from `btclib.psbt.psbt_utils`, where it was the `0xff` and came
  from `btclib.psbt.psbt`; `PSBT_DELIMITER`, which was that `0x00`, is
  gone. `malformed psbt: missing separator` goes with it: one header is
  one check, and a fifth byte that is not `0xff` is `malformed psbt:
  missing magic bytes`.
- **`Psbt.parse` and `Psbt.b64decode` reject trailing bytes**, as
  `dsa.Sig.parse` does: octets are a whole psbt, and `malformed psbt: N
  bytes after the psbt` is the answer to anything after one. Handing a
  `BytesIO` over is how a caller says the rest of the buffer is theirs.
- **`to_dict` renders a script as `{"asm": ..., "hex": ...}`**, where it
  rendered the bare hex string: `TxIn`'s `scriptSig`, `TxOut`'s
  `scriptPubKey`, `PsbtIn`'s `redeem_script`, `witness_script` and
  `final_script_sig`, and `PsbtOut`'s `redeem_script` and `witness_script`.
  `d["scriptSig"]` is `d["scriptSig"]["hex"]`, and so on for the seven.
  `from_dict` still reads the old spelling, a stored dict staying readable,
  and reads the `hex` in both — but an `asm` that the `hex` does not produce
  is refused rather than ignored. `TxOut.to_dict` no longer emits `reqSigs`,
  which was always `None`; Bitcoin Core dropped it in v22 for being an answer
  only a bare multisig had.
- **`electrum.mnemonic_from_entropy` returns the mnemonic Electrum
  returns**, which is not the one btclib returned: the words run
  least-significant first and the search starts at `entropy + 1`, so the
  same entropy now gives a different sentence, and
  `electrum.entropy_from_mnemonic` reads the same sentence as a different
  integer. Anyone who stored an entropy value expecting btclib to
  reproduce a mnemonic from it has to store the mnemonic instead — which
  is the safe direction anyway, the seed deriving from the words alone.
  `version_from_mnemonic` also answers `"old"` now for a pre-2.0 Electrum
  seed, where it raised — or, for an old seed whose hash happened to
  start with one of the four prefixes, named a new version and handed
  back the wrong derivation; and it accepts what Electrum accepts, so an
  upper-cased or accented mnemonic is read rather than refused.
- **`bip39.seed_from_mnemonic` normalizes NFKD, so a non-ASCII mnemonic or
  passphrase derives another wallet than it used to.** BIP39 stretches the
  sentence and the passphrase in UTF-8 NFKD and btclib normalized neither,
  which made all twenty-four of BIP39's Japanese vectors wrong seeds.
  ASCII is NFKD already, so an English mnemonic with an ASCII passphrase
  is untouched; anyone whose passphrase or mnemonic holds a character
  outside ASCII was deriving a wallet no other implementation agrees with,
  and has to re-derive from the same words to reach the right one.
- **`Script(script_bytes)` no longer raises for a script that cannot be
  executed.** A push over 520 bytes and a push declaring more bytes than
  follow it used to be `Invalid pushdata length` and `Not enough data for
  pushdata` out of `Script`, `ScriptPubKey`, `.asm` and `script.parse`;
  they are now decoded, the second as everything up to the place the
  bytes stop being a script plus the marker `"[error]"` Bitcoin Core
  writes there. Code that caught `BTClibValueError` around a `Script` to
  sort scripts it could handle from scripts it could not has to ask the
  question it meant: `"[error]" in Script(s).asm` for one that cannot be
  read to the end, `script.engine.verify_input` for one that cannot be
  spent. There are twelve such scripts in blocks 251718 to 299571.
- **`script.parse(stream, accept_unknown)` is `script.parse(stream)`.**
  The parameter's answer is fixed at what every caller passed, so a byte
  no op-code table names is always `UNKNOWN_OP_CODE_n` and never
  `Unknown op code`: Core reads it too, and it is the interpreter that
  refuses it. A caller passing it positionally or by keyword gets a
  TypeError.
- **`script.engine.validate_redeem_script` is
  `script.engine.validate_push_only`, and takes the script_sig bytes**:
  `validate_push_only(tx.vin[i].script_sig)`, where it was
  `validate_redeem_script(parse(tx.vin[i].script_sig))`. It is Core's
  `CScript::IsPushOnly`, which compares each op code against OP_16 — and
  the name says which script it is asked about, the script_sig, at both
  call sites as in Core.
- **`script.engine.script.calculate_script_code` and `.op_checksig` name
  their code-separator parameter `codesep_offset`**, where it was
  `separator_index` and `codesep_index`. `script.engine.tapscript.
  op_checksig` gains a required `flags: ScriptFlag` parameter besides,
  which is what lets it refuse a tapscript public key that is neither
  empty nor 32 bytes under DISCOURAGE_UPGRADABLE_PUBKEYTYPE. All three
  are the script engine's own internals — `verify_input` and
  `verify_transaction` take no new parameter — and break only a caller
  driving the interpreter's op codes directly.
- **`join_psbts` and `join_txs` no longer take `merge_out`.** It was the
  fourth positional parameter of both, and `merge_out=True` raised
  `output merge not implemented yet`: delete the argument at each call
  site, `merge_out=False` having been the only value that did anything.
  Merging two outputs that pay one script changes the output set, so
  every signature already made over it stops verifying, and both
  functions shuffle or sort the outputs first — summing two payments
  into one output is the caller's, before signing.
- **`psbt_utils.assert_valid_taproot_tree` is gone**, with the leaf-script
  validation it performed: a PSBT tap tree is stored as it arrives, as
  Core's PSBT stores it. Nothing replaces the call — `PsbtOut.assert_valid`
  simply no longer parses the leaves — and a caller that wants to know
  whether a leaf can be executed runs it.
- **`psbt_utils.assert_valid_taproot_signatures`'s second parameter is
  `what`, not `err_msg`.** It used to be raised as the whole message; now
  it names what is being validated, and the function builds one of three
  messages around it depending on the failure — a wrong length, an
  explicit SIGHASH_DEFAULT byte, an unsupported hash type — so a caller
  passing a full sentence gets it wrapped inside a new one rather than
  raised verbatim.
- **`BIP32DerPath` is `DerPath`, and the three `*_from_bip32_path`
  converters are `*_from_der_path`.** `indexes_from_bip32_path`,
  `str_from_bip32_path` and `bytes_from_bip32_path` answer as they did
  under `indexes_from_der_path`, `str_from_der_path` and
  `bytes_from_der_path`, so a search and replace for `bip32_path` and
  `BIP32DerPath` is the whole cost. No alias is kept, as the `btclib.ec`
  rename kept none.
- **`CurveSubGroup` is gone**, and nothing replaces `from btclib.ec.curve
  import CurveSubGroup`: the class held a generator and no order, which is
  a cyclic group that cannot say how many elements it has. `CurveGroup`
  and `Curve` are the hierarchy — every point of the curve, and the cyclic
  subgroup of prime order generated by G — and `Curve(p, a, b, G, n,
  cofactor)` is what a caller of the removed class wanted.
- **`from btclib.ecc import bip340_nonce_` is
  `from btclib.ecc.bip340_nonce import bip340_nonce_`.** The package now
  names the three nonce modules — `bip340_nonce`, `rfc6979_nonce`,
  `commit_nonce` — where it used to export one function out of one of
  them, and no name ending in an underscore is in its `__all__` any more.

- **a truncated or over-long serialization is refused where it used to
  parse.** A fixed-width field has to hold its bytes now, and an octet
  string handed to `parse` has to hold exactly one object:
  `Tx.parse(raw[:-1])` and `Tx.parse(raw + b"junk")` both raise
  `BTClibValueError`, where the first answered a transaction with a
  shorter lock time and the second answered the transaction of `raw`. The
  same holds for `TxIn`, `TxOut`, `OutPoint`, `Block`, `BlockHeader`,
  `BIP32KeyData`, `Witness`, `PsbtIn` and `PsbtOut`, and whatever
  `check_validity` says — the length is what
  makes the fields mean anything, not an opinion about what they hold. A
  stream is unaffected, what follows the object in it being the caller's:
  reading a transaction out of a block reads on as before. Parsing one
  object out of a longer buffer is `parse(BytesIO(buffer))` rather than
  `parse(buffer)`. `BIP32KeyOrigin.parse` goes with them for the width of
  its master fingerprint, which `check_validity=False` used to defer: four
  octets, or it is not a key origin.
- **a boolean is refused wherever a field is an integer quantity.**
  `bool` being a subclass of `int`, `valid_sats_amount(True)` was 1,
  `FeeRate(sats_per_kvbyte=True)` was a one-sat/kvB rate, and
  `OutPoint(tx_id, True)` was output number one; all of them raise
  `BTClibTypeError` now. This matters at a json boundary, where `true`
  decodes to `True`: what used to be one satoshi is an error next to the
  field that carried it. Only an actual boolean is affected — an `IntEnum`
  or any other deliberate integer subclass is still an integer.

- **`ssa.verify` answers False for a 65-byte taproot witness signature**,
  where it answered True: the 65th octet is BIP341's sighash type, not
  part of the BIP340 signature, and `Sig.parse` read the first sixty-four
  octets and dropped the rest. `ssa.Sig.parse` and `ssa.assert_as_valid`
  raise `BTClibValueError` on it, as they do on a truncation. Strip the
  byte at the call site — `ssa.verify(msg, pub_key, witness_sig[:64])`,
  which is what btclib's own script engine does after reading the sighash
  type off it.
- **`btclib.psbt` no longer exports the nine `psbt_utils` names**:
  `serialize_bytes`, `deserialize_int`, `deserialize_map`,
  `deserialize_tx`, `encode_dict_bytes_bytes`, `decode_dict_bytes_bytes`,
  `serialize_dict_bytes_bytes`, `serialize_hd_key_paths` and
  `assert_valid_unknown` come from `btclib.psbt.psbt_utils`, which is
  where they are defined. They are how one field of one psbt map is
  written and read; `Psbt`, `PsbtIn` and `PsbtOut` are where a caller
  reads and writes a psbt.
- **`from btclib.base58 import b58encode, b58decode` is `encode,
  decode`.** The two call sites that need both codecs in scope —
  `btclib/b58.py` and `btclib/to_prv_key.py` — alias them back at the
  import, `from btclib.base58 import decode as b58decode, encode as
  b58encode`, so a caller doing the same keeps its own names.
  `BIP32KeyData.b58encode`/`.b58decode`, `bms.Sig.b64encode`/`.b64decode`
  and `Psbt.b64encode`/`.b64decode` are methods and are unaffected.
- **`descriptors.descriptor_checksum` and `.descriptor_from_address` are
  `checksum` and `from_address`.** Both spellings were already there at
  `v2023.7.12` — checked against the tag. `add_checksum` and
  `strip_checksum` keep their names.
- **`tx.join_txs` is `tx.join`; `psbt.combine_psbts`, `psbt.join_psbts`
  and `psbt.finalize_psbt` are `combine`, `join` and `finalize`.** All
  four spellings were already there at `v2023.7.12` — checked against
  the tag. `psbt.extract_tx` is unchanged.
- **`btclib.bip32.slip132` is `btclib.slip132`.** `from btclib.bip32
  import slip132` was the spelling at `v2023.7.12` — checked against the
  tag — and is `from btclib import slip132` now. `bip44`, which needs
  the same top-level placement for the same reason, was already there.
- **`from btclib.<module> import *` hands out that module's own names.**
  Every module of the library declares `__all__` now, where none did at
  `v2023.7.12` — checked against the tag — so a star import stops binding
  what the module imported: `Octets`, `String` and `sha256` came out of
  `btclib.b58` and come out of `btclib.alias` and `btclib.hashes`, which
  define them. Every named import of a name a module defines is unchanged,
  `from btclib.b58 import p2pkh` included. What does go is the residue of
  three load loops and one type variable: `net`, `filename` and `f` in
  `btclib.network`, `filename`, `file_` and `ec_name` in
  `btclib.curves.curve`, and `TypeA` in `btclib.psbt.psbt`, all
  underscored now, so `from btclib.network import net` — which the
  underscore rule already said was nobody's to write — raises
  `ImportError`.
- **`from btclib import *` binds the library's modules**, where it bound
  `name` and the two names the version lookup imports. `btclib.__all__` is
  the packages and top-level modules now, imported on demand by a module
  `__getattr__`, so `import btclib` still costs the metadata lookup alone
  and `btclib.b58` answers without an import of its own. `btclib.name` is
  where it was, and is no longer star-imported.
- **`network.datadir` and `curves.curve.datadir` are `Path`, not `str`.**
  `str(btclib.network.datadir)` recovers the `v2023.7.12` value; code
  that concatenated it, sliced it, or called a string method on it does
  not.

Two changes are deliberately *not* on that list, because what they change
stays compatible. The new `BTClibTypeError`, `NotAPrvKeyError` and
`InvalidPrvKeyError` all derive from what was raised before, so `except
BTClibValueError` and `except TypeError` keep catching them. And the `is_p2*`
and `verify` families now let a `TypeError` out where they used to answer
`False`: that is a caller error surfacing, not an interface moving.

### What it buys

- **Forged signatures and mutated blocks are refused.** `borromean.assert_
  as_valid` used to *return* a bool, so calling it as a statement — which
  is what its `dsa` and `ssa` counterparts ask for — accepted forgeries in
  silence. `Block.assert_valid` now rejects the CVE-2012-2459 merkle
  mutation and checks the BIP141 witness commitment, without which every
  signature in a block could be replaced wholesale with the header
  untouched; it also bounds the block's size, weight and signature
  operations, and a caller holding a height and a clock can ask the two
  rules that need them — the coinbase's BIP34 commitment and the timestamp
  — through `Block.assert_valid_contextual`. The low-s rule is decided by
  exact integer division, where
  `ec.n / 2` had put the threshold 2^127 above the true midpoint, and
  `dsa.verify` no longer accepts a *private* key where a public one goes.
- **Secrets stay out of logs.** A routine network mismatch used to put a
  full xprv into the exception text; the messages now carry the version
  bytes or the size, and a private `BIP32KeyData` repr masks its key and
  chain code.
- **Hostile input costs what it should.** Five bytes of a PSBT used to cost
  gigabytes, and 160k characters in an address field 3.3 seconds. Parsers
  bound their allocation by the data they were handed, `var_int` enforces
  Core's shortest encoding and 32 MiB cap, and `tests/fuzz_test.py` holds
  every parse entry point to the exception contract of
  `btclib/exceptions.py`.
- **Every script that is on chain can be read.** Twelve `scriptPubKey`s in
  blocks 251718 to 299571 raised out of `Script`, `ScriptPubKey` and
  `.asm`, two of them for pushing more than the stack can hold and ten for
  declaring a push longer than the bytes that follow it. Whether a script
  can be *executed* is now the interpreter's answer, given by executing
  it, which is where Bitcoin Core keeps it — and the five transactions
  reported are vendored as vectors.
- **Signing a transaction is linear in its inputs**, where it was Θ(N²):
  the new `sig_hash.PrecomputedTxData` takes 400 taproot inputs from 164 ms
  to 0.4 ms. `bms.sign` is twice as fast, recovering one candidate public key
  at a time where it recovered all four and then searched them. A public key
  from a private key is 13% faster, its compressed serialization now sliced
  out of the bindings' own answer instead of routed through a Python point.
  Importing btclib is 140 ms faster, and `Script.asm` is cached.
- **Importing btclib changes nothing outside btclib.** It no longer dies
  where hashlib has no RIPEMD-160, no longer re-enables OpenSSL's
  deprecated algorithms process-wide, and no longer traps decimal
  `FloatOperation` in the process context.
- **One object's mutation no longer reaches another.** `OutPoint`, `TxOut`,
  `Witness`, `Script` and `ScriptPubKey` are frozen, `Witness.stack` is a
  tuple, default arguments are built per call, and `assert_valid` no longer
  rewrites what it validates — `verify_transaction` used to rewrite the
  very transaction it was validating.
- **A failure says what failed.** 76 empty `BTClibValueError()` raises in
  the script engine carry a message and the command index; a private key in
  a recognised-but-wrong format reports its own fault instead of being
  retried as another format; the script verification flags are an
  `enum.Flag`, where a misspelled name used to be a silently disabled
  consensus rule.
- **A descriptor is now an address, not just a checksum.**
  `descriptors.parse` reads BIP380 to BIP386 and BIP389 — everything
  but miniscript — and hands back the scripts and addresses a descriptor
  pays to at any index, so one line of text is enough to watch a wallet.
  Checked against Bitcoin Core's own vectors; miniscript and the four
  functions left out say so by name rather than being read wrong.
- **A mnemonic in any of the twelve languages**, where two word-lists
  shipped and English was the only one a seed could be derived in:
  `seed_from_mnemonic` verified every checksum against English, and
  normalized neither the sentence nor the passphrase, which BIP39
  requires and which is the difference between two seeds rather than
  between an accepted input and a rejected one. All 288 vectors of the
  reference implementation pass, and so do the japanese ones the BIP
  cites beside them. The language need not be given — the words say which
  it is — and electrum's five word-lists are here too, its 1626-word
  Portuguese included.
- **BIP340 messages of any size**, as the BIP has allowed since 2023-04:
  the four vectors btclib used to `xfail` all verify.
- **MuSig2 is implemented**, `btclib.ecc.musig2` against all 56 cases of
  BIP327's eight vector files: many signers, one BIP340 signature that
  `ssa.verify_` accepts. One primitive per round rather than a function
  that signs, the protocol being interactive.
- **A psbt carries a taproot signature with its sig_hash type**, the
  65-byte form of BIP341 that BIP371 spells out and btclib refused, while
  its own script engine read it.
- **btclib can go and ask the chain**, which it never could: `btclib.fetch`
  is a transaction by id, the output an outpoint names and the chain tip,
  behind one interface with two backends — a full node's JSON-RPC and a
  block explorer's HTTP api — answering in `Tx` and `TxOut`. Nothing to
  install for it: the client is `urllib.request`. It is
  `btclib.bitcoin_core_rpc`, one standard-library-only file a project can
  copy whole instead of depending on btclib, and `btclib.exceptions`
  re-exports the three exceptions it defines so that one `except` catches
  them by either name — which is why an import that reaches
  `btclib.exceptions` loads `urllib.request` too, `import btclib` itself
  still costing the metadata lookup alone. Nothing connects until a call is
  made.
- **btclib can hand a psbt to an external signer.** `btclib.psbt_signer`
  defines the `PsbtSigner` protocol — `master_fingerprint`, `xpub`,
  `sign_psbt`, `capabilities`, `close` — and the checks a caller runs
  over an untrusted answer: `request_signatures` holds the returned psbt
  to the one that was sent, `export_account` refuses an xpub that is not
  the account the path names, `display_address` compares a device's own
  address against btclib's. `btclib.hwi.HwiSigner` is the one shipped
  implementation, over Bitcoin Core HWI's five JSON commands — HWI
  reaching Trezor, Ledger, KeepKey, Digital Bitbox, Coldcard, BitBox02
  and Jade — selecting a device by fingerprint rather than by
  enumeration order, with nothing imported from `hwilib` and nothing to
  install: an executable named at the call site is the whole runtime
  requirement. `exceptions.SignerError` carries HWI's own error code, so
  a declined signature and a disconnected cable answer as different
  numbers rather than as one unread message (issue #381).
- **Borromean ring signatures work on a curve other than secp256k1**, which
  is what the `ec` parameter has been offering since it stopped being a module
  global: the arithmetic ignored it and computed on secp256k1, so the first
  point encoded against `ec` raised and no other curve could sign at all.
- **SLIP-0039 shares can be read and written.** `btclib.mnemonic.slip39`
  is the third scheme beside BIP39 and Electrum, and until now btclib
  could not read a single share of the Shamir backup every Trezor since
  2019 offers.
- **The documentation has a guide and not only a reference.** A new page
  arranged by task — a mnemonic and its seed, an account xpub and the
  BIP44/49/84/86 addresses under it, reading a raw transaction, building
  one and computing the hash it commits to, ECDSA and BIP340, a signed
  message, a PSBT — where there had been fifteen pages of `automodule`
  and nothing to start from (issue #120). Every example on it is a
  doctest the test suite runs, so what follows a `>>>` is what the
  library answered rather than what somebody expected it to.
- **Python 3.10 through 3.14**, free-threaded 3.14t included; 3.7, 3.8 and
  3.9 are gone. 3.9 went end-of-life in 2025-10, and it had become the only
  interpreter pulling a second toolchain into the lock: 35 of 132 packages
  resolved twice, mypy 1.19 beside 2.3 and pytest 8.4 beside 9.1, so the 3.9
  jobs were testing against releases nobody else ran. The project is
  managed with uv, the lint gate is
  `.pre-commit-config.yaml` and CI runs exactly it, and
  btclib.readthedocs.io has an API in it again — it had been fifteen module
  titles with nothing under them.

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

- add support for PSBT's taproot fields (BIP370)
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

- dropped Python 3.6 support
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

This is the latest release to support Python 3.6

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
- made btclib compatible with Python 3.6
- ssa.det_nonce now returns an int
- moved tagged_hash from ssa into hashes module
- added CurveGroup._y_aff_from_jac and removed unused methods
- discontinued y_odd in favor of y_even as y-symmetry tiebreaker criterium
- removed nonce input from dsa.sign and ssa.sign (only available from _sign functions)
- cleaned up Exception handling, avoided bare/broad except
- introduced btclib Exceptions that can be discriminated from regular Exceptions

## v2020.11.10

Major changes includes:

- removed TypedDict in favor of dataclass;
  this also restored the ability of using btclib with Python 3.7
- introduced dataclasses_json as requirement, used to
  serialize to file the json representation of dataclasses
- Network is now a dataclass
- bip32: BIP32KeyData is now a dataclass instead of dict, its data member
  have to be accessed accordingly. Consequently, where previously it was
  bip32.deserialize(xkey), now it is bip32.BIP32KeyData.deserialize(xkey)
- bip32: added str_from_bip32_path and bytes_from_bip32_path
- bip32: made the index an int (not bytes) to avoid byteorder ambiguity.
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
- added PsbtIn, PsbtOut, and Psbt data classes for
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
- removed ambiguous functions going from prv_key to address
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
initiated with v2020.3.20; it requires Python>=3.8 as we use TypedDict.

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
