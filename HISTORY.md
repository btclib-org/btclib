# Release notes

Notable changes to the codebase are documented here.

Release names follow *[calendar versioning](https://calver.org/)*:
full year, short month, short day (YYYY-M-D)

## v2026.8 (work in progress, not released yet)

The first release since 2023, and the largest: a hundred and fifty-three
entries, in [CHANGELOG.md](./CHANGELOG.md). What follows is what a user has
to act on and what a user gains.

Every change is a *behaviour* change somewhere, so the honest summary is
this: btclib now refuses input it used to accept, reports errors it used
to swallow, and no longer lets one object's mutation reach another. If
something that worked stops working, the entry explaining why is in
CHANGELOG.md.

### Breaking changes

Seventeen changes break code that worked on v2023.7.12. Each is described in
full in [CHANGELOG.md](./CHANGELOG.md). Every "before" spelling was checked
against the `v2023.7.12` tag.

- **`from btclib.ec import ...` is `from btclib.curves import ...`.** Every
  name the package exports is the name it exported before.
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
  them, as BIP-143 says; and `from_tx(..., codesep_index=k)` is how a
  signer asks for the script code after the k-th of them.
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
  untouched. The low-s rule is decided by exact integer division, where
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
- **Signing a transaction is linear in its inputs**, where it was Θ(N²):
  the new `sig_hash.PrecomputedTxData` takes 400 taproot inputs from 164 ms
  to 0.4 ms. `bms.sign` is twice as fast, recovering one candidate public key
  at a time where it recovered all four and then searched them. A public key
  from a private key is 13% faster, its compressed serialization now sliced
  out of the bindings' own answer instead of routed through a python point.
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
- **BIP340 messages of any size**, as the BIP has allowed since 2023-04:
  the four vectors btclib used to `xfail` all verify.
- **A psbt carries a taproot signature with its sig_hash type**, the
  65-byte form of BIP341 that BIP371 spells out and btclib refused, while
  its own script engine read it.
- **Borromean ring signatures work on a curve other than secp256k1**, which
  is what the `ec` parameter has been offering since it stopped being a module
  global: the arithmetic ignored it and computed on secp256k1, so the first
  point encoded against `ec` raised and no other curve could sign at all.
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
- discontinued y_odd in favor of y_even as y-symmetry tiebreaker criterium
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
