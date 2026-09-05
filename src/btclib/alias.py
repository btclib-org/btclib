# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The type aliases of the public API, and the input conventions they name.

Octets and String below are the same union, so mypy cannot tell one
from the other: passing a text string where a hex-string is expected
is a type error this file names but no checker can catch. The distinction
is enforced at run time instead, by the converter each function calls on
its way in -- bytes_from_octets for Octets, str_from_string for String --
and it is documented here because that is the only place it can be read
as one piece.

Making them NewTypes would let mypy separate them, at the cost of every
caller having to wrap its literals: Octets("deadbeef") instead of
"deadbeef", throughout a public API whose whole style is to accept
whatever is convertible. That is a different library, not a fix to this
one.
"""

from __future__ import annotations

from collections.abc import Callable
from io import BytesIO
from typing import Any, Literal, Protocol, Union

__all__ = [
    "INF",
    "INFJ",
    "BIP44ScriptType",
    "BinaryData",
    "BlockCipherF",
    "CipherF",
    "Command",
    "EmbeddedScriptType",
    "H160_Net",
    "HashDigestF",
    "HashF",
    "HashObject",
    "Integer",
    "JacPoint",
    "KeyOrder",
    "MnemonicLang",
    "NetworkField",
    "NetworkName",
    "NetworkType",
    "Octets",
    "Point",
    "ScriptList",
    "ScriptType",
    "String",
    "TaprootLeaf",
    "TaprootLeafPaths",
    "TaprootScriptTree",
    "ValidSigHashType",
]

# hex-strings are strings that can be converted to bytes using bytes.fromhex,
# e.g.:
# "deadbeef"
# "dead beef"
# "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf
#     f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
# "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
# "02cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
#
# use btclib.utils.bytes_from_octets to convert Octets to bytes
#
# Octets are used for serialized script, h160 (20 bytes), h256 (32 bytes),
# BIP32 version (4 bytes), sig_hash_type (1 byte),
# dsa.Sig (DER serialization of ECDSA signature),
# ssa.Sig (BIP340 serialization of Schnorr signature)
# etc.
#
# Every buffer, and not `bytes` alone: each is accepted at run time by
# every consumer of an `Octets`, `utils.bytes_from_octets` being the one
# coercion they share and `curves.sec_point._PUB_KEY_TYPES` naming the same
# list from the other side. Narrower here than in the code, this cost a
# caller who wrote a buffer down a `type: ignore` -- and cost more than
# that, mypy not being able to see the buffer paths, so a place that
# breaks on one was found a caller at a time (issue #1238)
#: Bytes, or the hex-string that decodes to them, wherever raw bytes are
#: asked for.
Octets = bytes | str | bytearray | memoryview

# bytes or text string (not hex-string)
#
# this is for a string that can be converted to bytes with encode(),
# e.g. a message to be signed
#
# or 'ascii' strings like addresses (base58 or bech32),
# WIFs, or BIP32 keys:
# "37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"
# "KyLk7s6Z1FtgYEVp3bPckPVnXvLUWNCcVL6wNt3gaT96EmzTKZwP"
# "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVv
#     vNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
# "bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck"
#
# also bms.Sig (Bitcoin message compact signature serialization),
#
# In almost all cases (but messages to be signed)
# leading and trailing blanks should always be stripped
#
# In those cases often there is no need to encode() to bytes
# as b58decode/b32decode/etc. will take care of that
#
# The buffers for the reason `Octets` has them: `utils.str_from_string`
# reads every one of them, and `base58.decode` did before either
# annotation said so
String = bytes | str | bytearray | memoryview

# binary data, usually to be consumed as byte stream,
# but possibly provided as Octets too
BinaryData = BytesIO | Octets

# hex-string or bytes representation of an int
#
# a str is read as a hex-string, always: int_from_integer("1234") is 4660,
# not 1234, and "9" raises rather than being nine. There is no ambiguity to
# resolve by convention here -- a decimal representation is what int itself
# is for, and int("1234") costs the caller nothing -- so the ambiguity is
# resolved the way every other str in this file resolves it
Integer = Octets | int

# What kind of chain a network is: the real one, or one of the test ones.
#
# This is the distinction the version bytes were designed to draw --
# Satoshi's 0x6f, BIP32's tpub, SLIP132, and SLIP44 giving every test
# chain one coin type -- and every network in the catalogue can still be
# placed by it: no prefix of any test network equals any prefix of
# mainnet, on any field, so "main or test" always has an answer where
# "which chain" does not. testnet, regtest, signet and
# testnet4 share one set of prefixes on purpose, Core copying testnet's
# into the newer two, so a prefix cannot tell them apart. See issue #207
# and btclib.network's three network_type_from_* functions.
#
# "main" is Core's own name for the chain (`chain=main` in getblockchain
# info); "test" is SLIP44's testnet *family*, and deliberately not
# Core's `chain=test`, which names testnet3 alone.
#
# A Literal and not an Enum: network names are plain str throughout this
# library, so a lone enum here would be an island, and mypy strict
# already rejects the typo an Enum would guard against. That is the same
# choice the four vocabularies below make, for the reasons written over
# them
NetworkType = Literal["main", "test"]

# The closed vocabularies this library passes as plain str, one Literal
# each: issue #216. Strict mypy refuses a typo at every call site that
# spells the value out, which is most of them, and refuses nothing where
# the string is computed at run time -- that is the whole of what a
# Literal buys and the whole of what it does not.
#
# Literal and not Enum, and the issue measures why: `class Net(str,
# Enum)` formats a member as `mainnet` on 3.10 and as `Net.MAINNET` on
# 3.11 and later, so a mixin enum would make the six error messages
# that interpolate a network name -- text some tests match verbatim --
# read differently on different interpreters, while enum.StrEnum, which
# formats as the value everywhere, is 3.11+ against a 3.10 floor. A
# Literal has no runtime existence at all: nothing to format, nothing
# new for to_dict to serialize, and no signature that stops accepting a
# str.
#
# Which of them a *parameter* may take is the other half of the answer,
# and it is not the same for all four: an argument annotated with a
# Literal is a promise that the vocabulary is closed, so only the two
# whose data is closed are spelled on parameters. The other two name
# what btclib ships, for a caller who uses only that.

# What a script_pub_key pays to, as script.script_pub_key.type_and_payload
# names it. Closed, and checked to be: these nine are exactly what that
# function returns, mypy comparing each return against this alias. Note
# that "unknown" is one of them -- the answer for bytes this library does
# not classify, not the absence of an answer -- so there is no None here
# to widen the type of every caller. Parameters take it: b58's two
# address functions dispatch on it
ScriptType = Literal[
    "nulldata",
    "p2ms",
    "p2pk",
    "p2pkh",
    "p2sh",
    "p2tr",
    "p2wpkh",
    "p2wsh",
    "unknown",
    "witness_unknown",
]

# A field name of network.Network, which the three *_from_key_value
# lookups take as a str and resolve with getattr. The most fragile of
# these vocabularies, and so a parameter type: mypy holds a caller to
# these seventeen, and `network._NETWORK_FIELDS` is the same vocabulary
# at run time, for the callers mypy never sees -- a name outside it is a
# BTClibValueError there rather than the AttributeError getattr would
# raise, and rather than the empty list that would read as a fact about
# the prefix. network_test.py checks the members against
# dataclasses.fields(Network), the one thing mypy cannot check about a
# name resolved with getattr.
#
# Not "NetworkKey": in this library a key is a private or a public one
NetworkField = Literal[
    "curve",
    "network_type",
    "consensus",
    "genesis_block",
    "wif",
    "p2pkh",
    "p2sh",
    "hrp",
    "bip32_prv",
    "bip32_pub",
    "slip132_p2wpkh_p2sh_prv",
    "slip132_p2wpkh_p2sh_pub",
    "slip132_p2wsh_p2sh_prv",
    "slip132_p2wsh_p2sh_pub",
    "slip132_p2wpkh_prv",
    "slip132_p2wpkh_pub",
    "slip132_p2wsh_prv",
    "slip132_p2wsh_pub",
]

# The networks btclib ships, which is every network there is here:
# network.NETWORKS is fixed at import and read-only, so this list is the
# whole of the vocabulary and not a sample of it.
#
# Still not a parameter type, and issue #216 is where that is decided: the
# `network: str` parameters accept a name with spaces around it and in any
# case -- `network.network_from_name` is what they run it through -- so the
# set they take is wider than the spellings named here, and narrowing the
# annotation without dropping that tolerance would reject calls that work.
# One converter and not a `strip().lower()` per call site, which is what
# left b32 and the mnemonic modules indexing NETWORKS raw and refusing the
# tolerance this paragraph promised (issue #744).
# It names the spellings for a caller who wants mypy to hold them to it;
# network.py annotates with it the tuple of names it loads, which is what
# keeps this list equal to the data
NetworkName = Literal["mainnet", "testnet", "regtest", "signet", "testnet4"]

# The word-lists btclib ships: BIP39's twelve languages, and SLIP-0039's
# single list under a key that is a scheme and not a language code -- the
# SLIP defines no localization, so "slip39" is the whole of it. Every key
# of the WORDLISTS registry is named here, which is what keeps this list
# equal to the data; that the thirteen are not interchangeable is the
# schemes' business, and bip39 enforces its own half by refusing any list
# that is not 2048 words long.
#
# Open, as NetworkName is, and more plainly so:
# WordLists.load_lang(lang, filename) adds a language, which is how a
# word-list btclib does not ship is read -- electrum's 1626-word
# Portuguese is one, on a registry of its own -- so the ten `lang: str`
# parameters of mnemonic, bip39 and electrum stay str: a Literal there
# would type check the library's own languages and reject the file a
# caller has just loaded
MnemonicLang = Literal[
    "cs",
    "en",
    "es",
    "fr",
    "it",
    "ja",
    "ko",
    "pt",
    "ru",
    "tr",
    "zh",
    "zh_tw",
    "slip39",
]

# The seven hash types script.sig_hash.SIG_HASH_TYPES allows: the low
# five bits' four values -- DEFAULT, ALL, NONE, SINGLE -- alone and each
# ORed with ANYONECANPAY. Not an IntFlag over the whole byte: SINGLE ==
# ALL | NONE, both being 3, so a flag decomposition would make SINGLE an
# alias of ALL | NONE, a bit structure the protocol does not have (issue
# #273). Not an IntEnum either: the wire is wider than these seven --
# `legacy` and `segwit_v0` mask rather than validate, and a byte such as
# 0x05 must still hash, being a value a mined signature can carry -- so
# assert_valid_hash_type keeps `hash_type: int` and checks a plain int
# against all 256 possible bytes (sig_hash_taproot_test.py's
# test_valid_sighash_type), which a Literal-typed parameter could not be
# called with. Narrowed only where the wire is already closed:
# PsbtIn.sig_hash_type, checked against this same set once truthy.
# psbt_in_test.py checks the two stay equal
ValidSigHashType = Literal[0, 1, 2, 3, 129, 130, 131]


# The four address encodings a purpose level can name: 44 is p2pkh, 49
# p2wpkh-p2sh, 84 p2wpkh and 86 p2tr. It types both sides of btclib.bip44
# -- the mapping read out of _data/bip44_purposes.json and the script_type
# argument that overrides it -- so the two cannot drift apart in silence.
#
# Qualified BIP44, and not named ScriptType, because it is not the
# library's notion of one: script.type_and_payload answers p2pk, p2ms,
# nulldata, p2sh and p2wsh besides these, b58.address_from_h160 takes
# p2pkh or p2sh, and p2wpkh-p2sh belongs to neither list -- it is a
# nesting of one script in another, not an output script type. The field
# is called script_type because that is what electrum's
# bip39_wallet_formats.json, the source of the mapping, calls it; the name
# is kept and qualified rather than corrected, so that the data and the
# code read the same.
#
# A Literal for the reasons NetworkType is one, and with the same limit:
# it is a mypy fact and not a runtime one, so the json is still checked
# where it is used
BIP44ScriptType = Literal["p2pkh", "p2wpkh-p2sh", "p2wpkh", "p2tr"]

# The three ways a script becomes an output, which is what a
# wallet.ScriptWallet takes: the script is hashed into a p2sh, into a
# p2wsh, or into a p2wsh that a p2sh wraps. Not ScriptType either, and
# for BIP44ScriptType's reason -- `p2sh-p2wsh` is a nesting of one script
# in another and not something type_and_payload answers -- while the
# overlap with those four is only apparent: these three say what happens
# to a *script*, where those four say what happens to a key.
#
# A parameter type: the vocabulary is closed by what a hash of a script
# can be paid to, so a fourth entry would need a new output type rather
# than a new line here
EmbeddedScriptType = Literal["p2sh", "p2wsh", "p2sh-p2wsh"]

# When a wallet.ScriptWallet orders the keys of a quorum, which is the
# one thing about a pre-descriptor multisig wallet that cannot be read off
# its script: "derived" sorts them at every index, which is BIP67 on the
# derived keys and what sortedmulti() follows; "account" sorts the account
# keys once and derives afterwards, which multi() states; "none" keeps
# them as declared. The three are a strategy and not a constant because
# deployed wallets disagree, and the sort_key beside them is what a wallet
# ordering by something that is not a byte order needs
KeyOrder = Literal["none", "account", "derived"]


# What a HashF returns: as much of the hashlib object as this library uses,
# and no more. A Protocol rather than Any: under Any, hf().digest() and
# hf().digest_size go unchecked, and with them every expression downstream
# of a hash function -- in a mypy-strict code base a typo in either would
# be a runtime AttributeError.
#
# Not hashlib._Hash, which is what typeshed calls the class: a private
# name, and structural typing is the right tool for "whatever hashlib.new
# returns". typeshed writes this same Protocol beside it, under this very
# class's name, and marks it type_check_only, so importing that one is no
# option either.
#
# An extendable-output function is not one of these, and here is where it
# is refused: hashlib.shake_128 fails this Protocol statically, its
# digest() requiring the output length that digest() -> bytes does not
# declare, and its digest_size reading 0. Not a btclib restriction --
# typeshed derives HASHXOF from HASH through a type: ignore[override], and
# hmac.new rejects an XOF as a digestmod for the same reason, which is
# dsa.sign's answer too: rfc6979 hands hf to hmac.new, and HMAC over an
# XOF is not defined (NIST specifies KMAC instead). An XOF is a function
# of data *and* length, and the length has nowhere to live here, so what
# reads SHAKE vectors is an adapter pinning one, not a wider Protocol
class HashObject(Protocol):
    """The slice of a hashlib object this library reads, as a Protocol.

    Structural: anything hashlib.new returns satisfies it, and the
    members carry hashlib's own meanings.
    """

    @property
    def digest_size(self) -> int:
        """Return the digest length in bytes."""
        ...

    @property
    def block_size(self) -> int:
        """Return the internal block length in bytes."""
        ...

    @property
    def name(self) -> str:
        """Return the name hashlib.new would accept."""
        ...

    # Any, alone in this Protocol, and not for want of trying: hmac.new
    # takes a digestmod whose update() accepts typeshed's ReadableBuffer,
    # a union this library cannot spell before 3.12, collections.abc.Buffer
    # being 3.12 and the floor 3.10, and a narrower parameter here makes
    # the whole Protocol unassignable to hmac's -- rfc6979 hands hf to
    # hmac.new. The two members that are actually read, digest() and
    # digest_size, stay exact, which is the point of the Protocol
    def update(self, data: Any, /) -> None:
        """Absorb more data, as hashlib's update does."""
        ...

    def digest(self) -> bytes:
        """Return the digest of everything absorbed so far."""
        ...

    def hexdigest(self) -> str:
        """Return the digest as a hex string."""
        ...

    def copy(self) -> HashObject:
        """Return a clone that can absorb independently."""
        ...


# Hash digest constructor: it may be any name suitable to hashlib.new().
# Called with no argument and then fed through update(), which is how every
# hf parameter in the package is used -- digest() and digest_size are the
# whole of what it reads off the result, so no argument is the whole of the
# capability it needs. Typing a callback at the capability actually used is
# what leaves the widest set of callables able to be one: a lambda and a
# functools.partial are a HashF here, and typeshed types the same object
# the same way, hmac's digestmod being Callable[[], _HashObject].
#
# The price is that hf(data) does not type check, though hashlib.sha256
# accepts it and that is what makes the distinction below invisible at run
# time. A Protocol declaring __call__ with an optional positional parameter
# would take both spellings, and would take with the other hand: a
# zero-argument constructor would no longer be a HashF, which is
# contravariance and not an oversight. btclib.hashes.reduce_to_hlen is the
# one-shot digest, for whoever wants one
HashF = Callable[[], HashObject]

# A one-shot digest: hf(data) returns the digest, where a HashF returns an
# object to update. The merkle functions of btclib.hashes take this one --
# hash256, not hashlib.sha256.
#
# Naming it makes a swap a type error rather than a runtime one, and the
# type is load-bearing in both directions: hashlib.sha256 satisfies HashF's
# arity but returns a HASH and not bytes, so it is rejected here, and
# hash256 takes an argument, so it is rejected as a HashF
HashDigestF = Callable[[Octets], bytes]

# A block cipher under a key and an initialization vector: (key, iv, data)
# to the transformed data. btclib.ecc.ecies takes one of these in each
# direction because it ships no cipher of its own; that module's docstring
# has the contract the two callables must honour, which this name cannot
# carry -- padding and block size are not in the signature.
#
# The three parameters are positional here and passed positionally, so a
# caller's own names for them do not have to match
CipherF = Callable[[bytes, bytes, bytes], bytes]

# A single block under a key, with no mode and no padding: (key, block) to
# the transformed block, both fixed-size. btclib.bip38 takes one of these
# in each direction for the same reason CipherF exists -- it ships no
# cipher of its own -- but BIP38 calls AES-256 directly on one or two
# 16-byte blocks rather than chaining them, so there is no iv and nothing
# for a mode parameter to name
BlockCipherF = Callable[[bytes, bytes], bytes]

H160_Net = tuple[bytes, str]

# Elliptic curve point in affine coordinates.
# Warning: to make Point a NamedTuple would slow down the code
Point = tuple[int, int]

# the infinity point in affine coordinates is INF = (int, 0)
# (no affine point has y=0 coordinate in a group of prime order).
# It can be checked with 'INF[1] == 0'
# The x-coordinate is arbitrary: 5 is preferred
# because it is not a valid x-coordinate in secp256k1
# (and even 5 + secp256k1.n is not a valid x-coordinate)
INF = 5, 0

# Elliptic curve point in Jacobian coordinates.
JacPoint = tuple[int, int, int]

# Infinity point in Jacobian coordinates is INF = (int, int, 0).
# It can be checked with 'INF[2] == 0'
# The default x and y coordinates are arbitrary:
# 7, 0 are used because those are what one would obtain
# from the generic affine to Jacobian transformation
# of the INF Point
# which sends Q to its two coordinates followed by 1, or by 0 at infinity
INFJ = 7, 0, 0

# spelled out rather than written `int | Octets`, though the spellings
# are the same list: a `str` here is an opcode name or hex data and an
# `Octets` str is hex and nothing else, so the two aliases would be one
# name for two roles. The buffers are here because a push of a
# bytearray is a push of what it holds: `script.serialize` wrote one
# already, and `taproot.serialize` had to be taught to -- its
# OP_SUCCESS arm asked `isinstance(script[0], bytes)` and refused the
# other two
Command = int | str | bytes | bytearray | memoryview
ScriptList = list[Command]

# A BIP341 taproot script tree, recursive: a branch nests two more of
# the same alias.
#
# list, and not the Sequence mypy's variance note suggests when a caller's
# list[tuple[int, list[str]]] does not fit: str is itself a Sequence[str],
# so under Sequence the recursion accepts any str as an entire tree --
# output_pubkey(None, "hello") type checks -- and a (leaf_version, script)
# tuple with a str version passes as a branch of two subtrees. Measured
# over five malformed trees, list rejects five and Sequence three.
# Invariance is the cost and the point: it is what makes a str not a tree.
# It is paid wherever a tree is built into a variable instead of passed as
# a literal, by annotating that variable with this alias
TaprootLeaf = tuple[int, ScriptList]
#: A leaf, a one-element list holding a `TaprootLeaf`, or a branch, a
#: two-element list of subtrees.
TaprootScriptTree = list[Union[TaprootLeaf, "TaprootScriptTree"]]

# what tree_helper returns beside the merkle root: every leaf of the tree
# paired with the concatenated sibling hashes that prove it, i.e. the tail
# of the control block input_script_sig builds
TaprootLeafPaths = list[tuple[TaprootLeaf, bytes]]
