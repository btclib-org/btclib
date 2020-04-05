#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Union

from . import bip32
from .alias import Octets, Point, PubKey
from .curve import Curve
from .curves import secp256k1
from .utils import bytes_from_octets

# TODO: do not rely on BIP32 extensions


def bytes_from_point(Q: Point, compressed: bool, ec: Curve = secp256k1) -> bytes:
    """Return a point as compressed/uncompressed octet sequence.

    Return a point as compressed (0x02, 0x03) or uncompressed (0x04)
    octet sequence, according to SEC 1 v.2, section 2.3.3.
    """

    # check that Q is a point and that is on curve
    ec.require_on_curve(Q)

    if Q[1] == 0:  # infinity point in affine coordinates
        raise ValueError("No bytes representation for the infinity point")

    bPx = Q[0].to_bytes(ec.psize, byteorder='big')
    if compressed:
        return (b'\x03' if (Q[1] & 1) else b'\x02') + bPx

    return b'\x04' + bPx + Q[1].to_bytes(ec.psize, byteorder='big')


def point_from_octets(pubkey: Octets, ec: Curve = secp256k1) -> Point:
    """Return a tuple (Px, Py) that belongs to the curve.

    Return a tuple (Px, Py) that belongs to the curve according to
    SEC 1 v.2, section 2.3.4.
    """

    pubkey = bytes_from_octets(pubkey)

    bsize = len(pubkey)  # bytes
    if bsize == ec.psize + 1:                 # compressed point
        if pubkey[0] not in (0x02, 0x03):
            msg = f"{ec.psize+1} bytes, but not a compressed point"
            raise ValueError(msg)
        Px = int.from_bytes(pubkey[1:], byteorder='big')
        try:
            Py = ec.y_odd(Px, pubkey[0] % 2)  # also check Px validity
            return Px, Py
        except:
            msg = f"{ec.psize+1} bytes, but not a valid x coordinate {Px}"
            raise ValueError(msg)
    else:                                     # uncompressed point
        if bsize != 2*ec.psize + 1:
            msg = f"wrong byte-size ({bsize}) for a point: it "
            msg += f"should have be {ec.psize+1} or {2*ec.psize+1}"
            raise ValueError(msg)
        if pubkey[0] != 0x04:
            raise ValueError("not an uncompressed point")
        Px = int.from_bytes(pubkey[1:ec.psize+1], byteorder='big')
        P = Px, int.from_bytes(pubkey[ec.psize+1:], byteorder='big')
        if P[1] == 0:  # infinity point in affine coordinates
            raise ValueError("No bytes representation for the infinity point")
        if ec.is_on_curve(P):
            return P
        else:
            raise ValueError(f"point {P} not on curve")


def to_pub_tuple(P: Union[Point, bip32.XkeyDict, bytes, str], ec: Curve) -> Point:
    """Return a public key tuple from any possible representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - Octets (bytes or hex-string)
    - native tuple
    """

    if isinstance(P, tuple):
        if ec.is_on_curve(P) and P[1] != 0:
            return P
        raise ValueError(f"Not a public key: {P}")
    elif isinstance(P, dict):
        if P['q'] != 0 or P['Q'][1]==0:
            raise ValueError(f"Not a public key: {P['key'].hex()}")
        return P['Q']
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            if xkey['q'] != 0 or xkey['Q'][1]==0:
                raise ValueError(f"Not a public key: {xkey['key'].hex()}")
            return xkey['Q']

    return point_from_octets(P, ec)


def to_pub_bytes(P: Union[Point, bip32.XkeyDict, bytes, str], compressed: bool, ec: Curve) -> bytes:
    """Return a public key tuple from any possible representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - Octets (bytes or hex-string)
    - native tuple
    """

    if isinstance(P, tuple):
        return bytes_from_point(P, compressed, ec)
    elif isinstance(P, dict):
        if not compressed:
            m = "Uncompressed BIP32 / compressed SEC key mismatch"
            raise ValueError(m)
        if P['q'] != 0:
            raise ValueError(f"Not a public key: {P['key'].hex()}")
        return P['key']
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            if not compressed:
                m = "Uncompressed BIP32 / compressed SEC key mismatch"
                raise ValueError(m)
            if xkey['q'] != 0:
                raise ValueError(f"Not a public key: {xkey['key'].hex()}")
            return xkey['key']


        pubkey = bytes_from_octets(P)
        if not compressed and len(pubkey) != 2*ec.psize + 1:
            m = f"Wrong size ({len(pubkey)}-bytes) for uncompressed SEC key"
            raise ValueError(m)
        if compressed and len(pubkey) != ec.psize + 1:
            m = f"Wrong size ({len(pubkey)}-bytes) for compressed SEC key"
            raise ValueError(m)
        Q = point_from_octets(pubkey, ec)  # verify it is a valid point
        return bytes_from_point(Q, compressed, ec)
