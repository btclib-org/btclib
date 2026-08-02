#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Aliases.

mypy aliases, documenting also coding input conventions.

Octets and String below are both `bytes | str`, so mypy cannot tell
one from the other: passing a text string where a hex-string is expected
is a type error this file names but no checker can catch. The distinction
is enforced at run time instead, by the converter each function calls on
its way in -- bytes_from_octets for Octets, encode() for String -- and it
is documented here because that is the only place it can be read as one
piece.

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

# Octets are a sequence of eight-bit bytes or a hex-string (not text string)
#
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
Octets = bytes | str

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
String = bytes | str

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
Integer = bytes | str | int

# What kind of chain a network is: the real one, or one of the test ones.
#
# This is the distinction the version bytes were designed to draw --
# Satoshi's 0x6f, BIP32's tpub, SLIP132, and SLIP44 giving every test
# chain one coin type -- and it is the one they can still draw now that
# five networks are known: no prefix of any test network equals any
# prefix of mainnet, on any field, so "main or test" always has an
# answer where "which chain" does not. testnet, regtest, signet and
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
# already rejects the typo an Enum would guard against. Whether btclib
# should move to enums wholesale -- script types and network names
# first -- is a real question, and a separate one
NetworkType = Literal["main", "test"]


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


# What a HashF returns: as much of the hashlib object as this library uses,
# and no more. A Protocol rather than Any: under Any, hf().digest() and
# hf().digest_size go unchecked, and with them every expression downstream
# of a hash function. Eleven sites read digest_size and nine build a digest
# through update(); with Any, a typo in either is a runtime AttributeError
# in a mypy-strict code base.
#
# Not hashlib._Hash, which is what typeshed calls it: a private name, and
# structural typing is the right tool for "whatever hashlib.new returns"
class HashObject(Protocol):
    @property
    def digest_size(self) -> int: ...

    @property
    def block_size(self) -> int: ...

    @property
    def name(self) -> str: ...

    # Any, alone in this Protocol, and not for want of trying: hmac.new
    # takes a digestmod whose update() accepts typeshed's ReadableBuffer,
    # a union this library cannot spell before 3.12, collections.abc.Buffer
    # being 3.12 and the floor 3.10, and a narrower parameter here makes
    # the whole Protocol unassignable to hmac's -- rfc6979 passes hf to
    # hmac.new eight times. The two members that are actually read,
    # digest() and digest_size, stay exact, which is the point of the
    # Protocol
    def update(self, data: Any, /) -> None: ...

    def digest(self) -> bytes: ...

    def hexdigest(self) -> str: ...

    def copy(self) -> HashObject: ...


# Hash digest constructor: it may be any name suitable to hashlib.new().
# Called with no argument and then fed through update(), which is how every
# hf parameter in the package is used: hf(data) does not type check here,
# and hashlib.sha256 accepting it anyway is what makes the distinction
# below invisible at run time
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

H160_Net = tuple[bytes, str]

# Elliptic curve point in affine coordinates.
# Warning: to make Point a NamedTuple would slow down the code
Point = tuple[int, int]

# Note that the infinity point in affine coordinates is INF = (int, 0)
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

Command = int | str | bytes
ScriptList = list[Command]

# A BIP341 taproot script tree: a leaf is a one-element list holding a
# (leaf_version, script) pair, a branch a two-element list of subtrees;
# the nesting is what makes the alias recursive.
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
TaprootScriptTree = list[Union[TaprootLeaf, "TaprootScriptTree"]]

# what tree_helper returns beside the merkle root: every leaf of the tree
# paired with the concatenated sibling hashes that prove it, i.e. the tail
# of the control block input_script_sig builds
TaprootLeafPaths = list[tuple[TaprootLeaf, bytes]]
