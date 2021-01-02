#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""SEC compressed/uncompressed point representation."""

from btclib.alias import Octets, Point
from btclib.ecc.curve import Curve, secp256k1
from btclib.exceptions import BTClibValueError
from btclib.utils import bytes_from_octets, hex_string


def bytes_from_point(Q: Point, ec: Curve = secp256k1, compressed: bool = True) -> bytes:
    """Return a point as compressed/uncompressed octet sequence.

    Return a point as compressed (0x02, 0x03) or uncompressed (0x04)
    octet sequence, according to SEC 1 v.2, section 2.3.3.
    """

    # check that Q is a point and that is on curve
    ec.require_on_curve(Q)

    if Q[1] == 0:  # infinity point in affine coordinates
        raise BTClibValueError("no bytes representation for infinity point")

    bytes_ = Q[0].to_bytes(ec.p_size, byteorder="big", signed=False)
    if compressed:
        return (b"\x03" if (Q[1] & 1) else b"\x02") + bytes_

    return b"\x04" + bytes_ + Q[1].to_bytes(ec.p_size, byteorder="big", signed=False)


def point_from_octets(pub_key: Octets, ec: Curve = secp256k1) -> Point:
    """Return a tuple (x_Q, y_Q) that belongs to the curve.

    Return a tuple (x_Q, y_Q) that belongs to the curve according to
    SEC 1 v.2, section 2.3.4.
    """

    pub_key = bytes_from_octets(pub_key, (ec.p_size + 1, 2 * ec.p_size + 1))

    bsize = len(pub_key)  # bytes
    if pub_key[0] in (0x02, 0x03):  # compressed point
        if bsize != ec.p_size + 1:
            err_msg = "invalid size for compressed point: "
            err_msg += f"{bsize} instead of {ec.p_size + 1}"
            raise BTClibValueError(err_msg)
        x_Q = int.from_bytes(pub_key[1:], byteorder="big")
        try:
            y_Q = ec.y_even(x_Q)  # also check x_Q validity
            return x_Q, y_Q if pub_key[0] == 0x02 else ec.p - y_Q
        except BTClibValueError as e:
            msg = f"invalid x-coordinate: '{hex_string(x_Q)}'"
            raise BTClibValueError(msg) from e
    elif pub_key[0] == 0x04:  # uncompressed point
        if bsize != 2 * ec.p_size + 1:
            err_msg = "invalid size for uncompressed point: "
            err_msg += f"{bsize} instead of {2 * ec.p_size + 1}"
            raise BTClibValueError(err_msg)
        x_Q = int.from_bytes(pub_key[1 : ec.p_size + 1], byteorder="big", signed=False)
        Q = x_Q, int.from_bytes(pub_key[ec.p_size + 1 :], byteorder="big", signed=False)
        if Q[1] == 0:  # infinity point in affine coordinates
            raise BTClibValueError("no bytes representation for infinity point")
        if ec.is_on_curve(Q):
            return Q
        raise BTClibValueError(f"point not on curve: {Q}")
    else:
        raise BTClibValueError(f"not a point: {pub_key!r}")
