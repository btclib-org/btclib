# Release notes

Notable changes to the codebase are documented here.

Release names follow [*calendar versioning*](https://calver.org/):
full year, short month, short day (YYYY-M-D)

## v2020.12 (current master, in development, not released yet)

Major changes includes:

- fixed ssa batch verification functions' logic
- enforced snake_case convention for 'script_pubkey' and 'script_sig'
  variable names

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
  Consequently, where previously it was xkey_dict["index"][0] < 0x80,
  now it is xkey_dict.index < 0x80000000
- bip32: local "./" derivation, opposed to absolute "m/" derivation,
  is not available anymore
- bip32: indexes_from_bip32_path now returns List[int] instead of
  Tuple[List[bytes], bool] losing the "absolute derivation" bool
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
- renamed prvkey_info_* as prvkeyinfo_*
- renamed pubkey_info_* as pubkeyinfo_*
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
- removed ambigous functions going from prvkey to address
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
