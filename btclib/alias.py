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


from typing import (Any, Callable, Iterable, List, Optional, Tuple, TypedDict,
                    Union)

# binary octets are eight-bit bytes or hex-string (not text string)
#
# use bytes_from_octets to properly convert to bytes
#
# used for script, h160 (20 bytes), h256 (32 bytes),
# bip32version (4 bytes), sighash (1 byte),
# dersig (DER serialization of ECDSA signature),
# msgsig (Bitcoin message compact signature serialization, 65 bytes),
# etc.
Octets = Union[bytes, str]

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
# The x and y coordinates are arbitrary: 7, 0
# are used as because those are what one would obtain
# from the generic affine to jacobian transformation:
# QJ = Q[0], Q[1], 1 if Q[1] else 0
INFJ = 7, 0, 0


# BIP 32 derivation path
# absolute path as "m/44h/0'/1H/0/10" string
# relative path as "./0/10" string
# relative path as sequence of integer indexes
# relative one level child derivation with single 4-bytes index
# relative one level child derivation with single integer index
# TODO: allow also Iterable[bytes], while making mypy happy
Path = Union[str, Iterable[int], int, bytes]


# BIP 32 extended key as a TypedDict
class XkeyDict(TypedDict):
    version            : bytes
    depth              : int
    parent_fingerprint : bytes
    index              : bytes
    chain_code         : bytes
    key                : bytes
    # extensions used to cache intemediate results
    # in multi-level derivation: do not rely on them elsewhere
    q                  : int  # non-zero for private key only
    Q                  : Point  # non-Infinity for public key only
    # TODO remove network, as it is not used in derivation
    network            : str  # mainnet, testnet, regtest, etc.


# private key inputs:
# integer -> q: int
# integer, possibly in bytes representation -> prvkey: Union[int, Octets]
# BIP32key -> xkey: Union[XkeyDict, String]
# WIF -> wif: String
#
# BIP32key and WIF also provide extra network
# and compressed-pubkey-derivation info
PrvKey = Union[int, Octets, String, XkeyDict]

# public key inputs:
# ...
PubKey = Union[Point, XkeyDict, bytes, str]


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
