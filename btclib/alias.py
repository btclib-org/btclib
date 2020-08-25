#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Aliases

mypy aliases, documenting also coding imput conventions.
"""


from typing import (
    Any,
    BinaryIO,
    Callable,
    Iterable,
    List,
    Tuple,
    TypedDict,
    Union,
)

# binary octets are eight-bit bytes or hex-string (not text string)
#
# use bytes_from_octets to properly convert to bytes
#
# used for serialized script, h160 (20 bytes), h256 (32 bytes),
# bip32version (4 bytes), sighash (1 byte),
# dersig (DER serialization of ECDSA signature),
# msgsig (Bitcoin message compact signature serialization, 65 bytes),
# etc.
Octets = Union[bytes, str]

# binary data, usually to be cosumed as byte stream,
# but possibily provided as Octets too
BinaryData = Union[BinaryIO, Octets]

# hex-string or bytes representation of an int
# Integer = Union[Octets, int]
Integer = Union[bytes, str, int]

# bytes or text string (not hex-string)
#
# to convert to bytes, just encode()
# e.g. in order to sign a message
#    if isinstance(msg, str):
#        msg = msg.encode()
#
# in many cases (e.g. b58addr, b32addr, wif, bip32key)
# leading/trailing blanks can be stripped
# if isinstance(b58addr, str):
#     b58addr = b58addr.strip()
#
# in those cases often there is no need to encode() to bytes
# as b58decode/b32decode/etc. will take care of that
# also those string are 'ascii', a subset of 'utf-8'
String = Union[bytes, str]


# Hash digest constructor: it may be any name suitable to hashlib.new()
HashF = Callable[[], Any]
# HashF = Callable[[Any], Any]


# Elliptic curve point in affine coordinates.
# Warning: to make Point a NamedTuple would slow down the code
Point = Tuple[int, int]

# Note that the infinity point in affine coordinates is INF = (int, 0)
# (no affine point has y=0 coordinate in a group of prime order n).
# It can be checked with 'INF[1] == 0'
# The x-coordinate is arbitrary: 7 is preferred
# because it is not a field element in secp256k1
INF = 7, 0


# Elliptic curve point in Jacobian coordinates.
JacPoint = Tuple[int, int, int]

# Infinity point in Jacobian coordinates is INF = (int, int, 0).
# It can be checked with 'INF[2] == 0'
# The default x and y coordinates are arbitrary:
# 7, 0 are used because those are what one would obtain
# from the generic affine to Jacobian transformation
# of the INF Point
# QJ = Q[0], Q[1], 1 if Q[1] else 0
INFJ = 7, 0, 0


# the main internal representation of entropy is binary 0/1 string
BinStr = str
# but int or bytes are fine too
Entropy = Union[BinStr, int, bytes]


# BIP 32 derivation path
# absolute path as "m/44h/0'/1H/0/10" string
# relative path as "./0/10" string
# relative path as sequence of integer indexes
# relative one level child derivation with single 4-bytes index
# relative one level child derivation with single integer index
# TODO: allow also Iterable[bytes], while making mypy happy
Path = Union[str, Iterable[int], int, bytes]


# BIP 32 extended key as a TypedDict
class BIP32KeyDict(TypedDict):
    version: bytes
    depth: int
    parent_fingerprint: bytes
    index: bytes
    chain_code: bytes
    key: bytes


BIP32Key = Union[BIP32KeyDict, String]

# private key inputs:
# integer as Union[int, Octets]
# BIP32key as BIP32Key
# WIF as String
#
# BIP32key and WIF also provide extra info about
# network and (un)compressed-pubkey-derivation
PrvKey = Union[int, bytes, str, BIP32KeyDict]

# public key inputs:
# elliptic curve point as Union[Octets, BIP32Key, Point]
PubKey = Union[bytes, str, BIP32KeyDict, Point]

# public or private key input,
# usable wherever a PubKey is logically expected
Key = Union[int, bytes, str, BIP32KeyDict, Point]

# ECDSA signature
# (r, s)
# both r and s are scalar: 0 < r < ec.n, 0 < s < ec.n
DSASigTuple = Tuple[int, int]
# DSASigTuple or DER serialization (bytes or hex-string, no sighash)
DSASig = Union[DSASigTuple, Octets]


# Bitcoin message signature
# (rf, r, s), where r and s are the components of a DSASigTuple
BMSigTuple = Tuple[int, int, int]
# BMSigTuple or base64 65-bytes serialization (bytes or hex-string)
BMSig = Union[BMSigTuple, Octets]


# BIP340-Schnorr signature
# (r, s)
# r is a _field_element_, 0 <= r < ec.p
# s is a scalar, 0 <= s < ec.n (yes, for BIP340-Schnorr it can be zero)
# (p is the field prime, n is the curve order)
SSASigTuple = Tuple[int, int]
# SSASigTuple or BIP340-Schnorr 64-bytes serialization (bytes or hex-string)
SSASig = Union[SSASigTuple, Octets]

# the integers [0-16] are shorcuts for 'OP_0'-'OP_16'
# the integer -1 is a shorcut for 'OP_1NEGATE'
# other integers are bytes encoded (require push operation)
# ascii str are for opcodes (e.g. 'OP_HASH160')
# Octets are for data to be pushed
Token = Union[int, str, bytes]

# Bitcoin script expressed as List[Token]
# e.g. [OP_HASH160, script_h160, OP_EQUAL]
# or Octets of its byte-encoded representation
Script = Union[Octets, List[Token]]
