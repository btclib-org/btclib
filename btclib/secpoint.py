#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""SEC compressed/uncompressed point representation."""

from .alias import Octets, Point
from .curve import Curve
from .curves import secp256k1
from .utils import bytes_from_octets


def bytes_from_point(Q: Point, ec: Curve = secp256k1, compressed: bool = True) -> bytes:
    """Return a point as compressed/uncompressed octet sequence.

    Return a point as compressed (0x02, 0x03) or uncompressed (0x04)
    octet sequence, according to SEC 1 v.2, section 2.3.3.
    """

    # check that Q is a point and that is on curve
    ec.require_on_curve(Q)

    if Q[1] == 0:  # infinity point in affine coordinates
        raise ValueError("No bytes representation for the infinity point")

    bPx = Q[0].to_bytes(ec.psize, byteorder="big")
    if compressed:
        return (b"\x03" if (Q[1] & 1) else b"\x02") + bPx

    return b"\x04" + bPx + Q[1].to_bytes(ec.psize, byteorder="big")


def point_from_octets(pubkey: Octets, ec: Curve = secp256k1) -> Point:
    """Return a tuple (Px, Py) that belongs to the curve.

    Return a tuple (Px, Py) that belongs to the curve according to
    SEC 1 v.2, section 2.3.4.
    """

    pubkey = bytes_from_octets(pubkey, (ec.psize + 1, 2 * ec.psize + 1))

    bsize = len(pubkey)  # bytes
    if bsize == ec.psize + 1:  # compressed point
        if pubkey[0] not in (0x02, 0x03):
            msg = f"{ec.psize+1} bytes, "
            msg += f"but not a compressed point prefix ({pubkey[0]})"
            raise ValueError(msg)
        Px = int.from_bytes(pubkey[1:], byteorder="big")
        try:
            Py = ec.y_odd(Px, pubkey[0] % 2)  # also check Px validity
            return Px, Py
        except Exception:
            msg = f"{ec.psize+1} bytes, but not a valid x coordinate {Px}"
            raise ValueError(msg)
    else:  # uncompressed point
        if pubkey[0] != 0x04:
            raise ValueError("not an uncompressed point")
        Px = int.from_bytes(pubkey[1 : ec.psize + 1], byteorder="big")
        P = Px, int.from_bytes(pubkey[ec.psize + 1 :], byteorder="big")
        if P[1] == 0:  # infinity point in affine coordinates
            raise ValueError("No bytes representation for the infinity point")
        if ec.is_on_curve(P):
            return P
        else:
            raise ValueError(f"point {P} not on curve")
