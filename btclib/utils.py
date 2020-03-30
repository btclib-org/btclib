#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Assorted conversion utilities.

Most conversions from SEC 1 v.2 2.3 are included.

https://www.secg.org/sec1-v2.pdf
"""

import hashlib
from typing import Any, Callable, Optional, Union

from .curve import Curve, Point
from .curves import secp256k1

# the digest constructor: it may be any name suitable to hashlib.new()
HashF = Callable[[], Any]
# HashF = Callable[[Any], Any]

# binary octets are eight-bit bytes or hex-string (not text string)
#
# use bytes_from_hexstring to properly convert to bytes
#
# e.g. script, h160 (20 bytes), h256 (32 bytes),
# bip32version (4 bytes), sighash (1 byte),
# dersig (DER serialization of ECDSA signature),
# msgsig (Bitcoin message compact signature serialization, 65 bytes),
# etc.
Octets = Union[bytes, str]

# bytes or ASCII string (not hex-string)
#
# to convert to bytes, just encode()
# e.g. in order to sign a message
#    if isinstance(msg, str):
#        msg = msg.encode('ascii')
#
# in many cases (e.g. b58addr, b32addr, wif, bip32key )
# leading/trailing blanks can be stripped
# if isinstance(b58addr, str):
#     b58addr = b58addr.strip()
#
# in those cases often there is no need to encode() to bytes
# as b58decode/b32decode/etc. will take care of that
String = Union[bytes, str]


def point_from_octets(o: Octets, ec: Curve = secp256k1) -> Point:
    """Return a tuple (Px, Py) that belongs to the curve.

    Return a tuple (Px, Py) that belongs to the curve according to
    SEC 1 v.2, section 2.3.4.
    """

    o = bytes_from_hexstring(o)

    bsize = len(o)  # bytes
    if bsize == 1 and o[0] == 0x00:      # infinity point
        return 1, 0

    if bsize == ec.psize+1:              # compressed point
        if o[0] not in (0x02, 0x03):
            msg = f"{ec.psize+1} bytes, but not a compressed point"
            raise ValueError(msg)
        Px = int.from_bytes(o[1:], byteorder='big')
        try:
            Py = ec.y_odd(Px, o[0] % 2)  # also check Px validity
            return Px, Py
        except:
            msg = f"{ec.psize+1} bytes, but not a valid x coordinate {Px}"
            raise ValueError(msg)
    else:                                # uncompressed point
        if bsize != 2*ec.psize+1:
            msg = f"wrong byte-size ({bsize}) for a point: it "
            msg += f"should have be {ec.psize+1} or {2*ec.psize+1}"
            raise ValueError(msg)
        if o[0] != 0x04:
            raise ValueError("not an uncompressed point")
        Px = int.from_bytes(o[1:ec.psize+1], byteorder='big')
        P = Px, int.from_bytes(o[ec.psize+1:], byteorder='big')
        if ec.is_on_curve(P):
            return P
        else:
            raise ValueError(f"point {P} not on curve")


def octets_from_point(Q: Point, compressed: bool, ec: Curve = secp256k1) -> bytes:
    """Return a point as compressed/uncompressed octet sequence.

    Return a point as compressed (0x02, 0x03) or uncompressed (0x04)
    octet sequence, according to SEC 1 v.2, section 2.3.3.
    """

    # check that Q is a point and that is on curve
    ec.require_on_curve(Q)

    if Q[1] == 0:  # infinity point in affine coordinates
        return b'\x00'

    bPx = Q[0].to_bytes(ec.psize, byteorder='big')
    if compressed:
        return (b'\x03' if (Q[1] & 1) else b'\x02') + bPx

    return b'\x04' + bPx + Q[1].to_bytes(ec.psize, byteorder='big')


def int_from_octets(o: Octets) -> int:
    """Return an integer from an octet sequence (bytes or hex string).

    Return an integer from an octet sequence (bytes or hex string)
    according to SEC 1 v.2, section 2.3.8.
    """

    o = bytes_from_hexstring(o)
    return int.from_bytes(o, byteorder='big')


def octets_from_int(i: int, bytesize: int) -> bytes:
    """Return an octet sequence from an integer.

    Return an octet sequence from an integer
    according to SEC 1 v.2, section 2.3.7.
    """

    return i.to_bytes(bytesize, byteorder='big')


def int_from_bits(o: Octets, ec: Curve = secp256k1) -> int:
    """Return the leftmost nlen bits reduced modulo n.

    Take as input a sequence of blen bits and calculate a
    non-negative integer i that is less than 2^nlen according to
    SEC 1 v.2 section 4.1.3 (5). Further,
    reduce i module n to ensure that 0 < i < n.

    int_from_bits is used during signature generation and verification
    in ECDSA and ECSSA to transform a hash value (computed over the
    input message) into an integer modulo n.

    Note that int_from_bits is not the reverse of octets_from_int, even
    for input sequences of length nlen: octets_from_int will add some
    bits on the left, while int_from_bits will discard some bits on the
    right. octets_from_int is the reverse of int_from_bits only when
    nlen is a multiple of 8 and bit sequences already have length nlen.
    See https://tools.ietf.org/html/rfc6979#section-2.3.5.
    """
    i = _int_from_bits(o, ec)
    return i % ec.n  # might be implemented as difference


def _int_from_bits(o: Octets, ec: Curve = secp256k1) -> int:
    """Return the leftmost nlen bits.

    Take as input a sequence of blen bits and calculate a
    non-negative integer i that is less than 2^nlen according to
    SEC 1 v.2 section 4.1.3 (5).  Note that an additional
    reduction modulo n would be required to ensure that 0 < i < n.
    """
    i = int_from_octets(o)

    blen = len(o) * 8  # bits
    n = (blen - ec.nlen) if blen >= ec.nlen else 0
    return i >> n


def sha256(o: Octets) -> bytes:
    """Return SHA256(*) of the input octet sequence."""

    o = bytes_from_hexstring(o)
    return hashlib.sha256(o).digest()


def hash160(o: Octets) -> bytes:
    """Return RIPEMD160(SHA256(*)) of the input octet sequence."""

    t = sha256(o)
    return hashlib.new('ripemd160', t).digest()


def hash256(o: Octets) -> bytes:
    """Return SHA256(SHA256(*)) of the input octet sequence."""

    t = sha256(o)
    return hashlib.sha256(t).digest()


def bytes_from_hexstring(o: Union[Any, str], out_size: Optional[int] = None) -> Union[Any, bytes]:
    """Return bytes from a hex-string, stripping leading/trailing spaces.

    If the input is not a string, then it goes untouched.
    Optionally, it also ensures required output size.
    """

    if isinstance(o, str):  # hex string
        o = bytes.fromhex(o)

    if (out_size is None) or (len(o) == out_size):
       return o

    m = f"Invalid size: {len(o)} bytes instead of {out_size}"
    raise ValueError(m)


def h160_from_pubkey(pubkey: Octets,
                     compressed_only: bool = True, ec: Curve = secp256k1) -> bytes:

    pubkey = bytes_from_hexstring(pubkey)
    plength = len(pubkey)

    compressed = pubkey[0] in (2, 3) and plength == ec.psize+1
    uncompressed = pubkey[0] == 4 and plength == 2*ec.psize+1
    if not (compressed or uncompressed):
        raise ValueError(f"Invalid SEC public key: {pubkey.hex()}")

    if uncompressed and compressed_only:
        raise ValueError(f"Compressed SEC public key: {pubkey.hex()}")
    return hash160(pubkey)


def ensure_is_power_of_two(n: int, var_name: str = None) -> None:
    # http://www.graphics.stanford.edu/~seander/bithacks.html
    if n & (n - 1) != 0:
        raise ValueError(f"{var_name} ({n}) must be a power of two")
