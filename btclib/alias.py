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


from typing import Any, Callable, Iterable, List, Tuple, TypedDict, Union


# binary octets are eight-bit bytes or hex-string (not text string)
#
# use bytes_from_hexstring to properly convert to bytes
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
String = Union[bytes, str]


# Hash digest constructor: it may be any name suitable to hashlib.new()
HashF = Callable[[], Any]
# HashF = Callable[[Any], Any]


# Elliptic curve point in affine coordinates
# Note that the Infinity point in affine coordinates is Inf = (int, 0)
# (no affine point has y=0 coordinate in a group of prime order n).
# It can be checked with 'Inf[1] == 0'
# Warning: to make Point a NamedTuple would slow down the code
Point = Tuple[int, int]


# Elliptic curve point in JAcobian coordinates
# infinity point in Jacobian coordinates is Inf = (int, int, 0)
# it can be checked with 'Inf[2] == 0'
_JacPoint = Tuple[int, int, int]


# BIP 32 derivation path
# absolute path as "m/44h/0'/1H/0/10" string
# relative path as "./0/10" string
# relative path as sequence of integer indexes
# relative one level child derivation with single 4-bytes index
# relative one level child derivation with single integer index
# TODO allow also Iterable[bytes], while making mypy happy
Path = Union[str, Iterable[int], int, bytes]


# BIP 32 extended key as a TypedDict
class XkeyDict(TypedDict):
    version            : bytes
    depth              : int
    parent_fingerprint : bytes
    index              : bytes
    chain_code         : bytes
    key                : bytes
    # btclib convenience extensions
    q                  : int  # non-zero for private key only
    Q                  : Point  # non-Infinity for public key only
    network            : str  # mainnet, testnet, regtest, etc.


# ECDSA signature
# (r, s) or DER serialization (bytes or hex-string)
# both r and s are scalar: 0 < r < ec.n, 0 < s < ec.n 
DSASig = Union[Tuple[int, int], Octets]


# Bitcoin message signature
# (rf, r, s) or base64 compact serialization (bytes or hex-string)
# (r, s) are a DSASig
BMSig = Union[Tuple[int, int, int], Octets]


# Schnorr signature
# (r, s), no serialization available yet
# Tuple[field element, scalar]
# r is a field element, s is a scalar: 0 < r < ec.p, 0 < s < ec.n 
SSASig = Tuple[int, int]


# commitment receipt
Receipt = Tuple[int, Point]
