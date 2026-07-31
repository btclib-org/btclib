#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""SEC compressed/uncompressed point representation."""

from btclib.alias import Octets, Point
from btclib.curves.curve import Curve, secp256k1
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


def point_from_octets(
    pub_key: Octets, ec: Curve = secp256k1, *, hybrid: bool = False
) -> Point:
    """Return a tuple (x_Q, y_Q) that belongs to the curve.

    Return a tuple (x_Q, y_Q) that belongs to the curve according to SEC
    1 v.2, section 2.3.4.

    hybrid admits the 0x06 and 0x07 prefixes of that same section, which
    carry both coordinates like 0x04 does and repeat the parity of y in
    the prefix. It is off by default, and not out of squeamishness: the
    point is a point, and libsecp256k1's ec_pubkey_parse takes all three
    65-byte prefixes (eckey_impl.h). What decides is where the parsed key
    goes next -- addresses, WIF and the descriptor language have no
    hybrid form to render, and nothing in bitcoin produces one. Consensus
    has to accept what was mined instead: Core rejects hybrid keys only
    under STRICTENC, so the script engine is the one caller that asks for
    them (issue #129).
    """
    pub_key = bytes_from_octets(pub_key, (ec.p_size + 1, 2 * ec.p_size + 1))

    bsize = len(pub_key)  # bytes
    prefix = pub_key[0]
    if prefix in (0x02, 0x03):  # compressed point
        if bsize != ec.p_size + 1:
            err_msg = "invalid size for compressed point: "
            err_msg += f"{bsize} instead of {ec.p_size + 1}"
            raise BTClibValueError(err_msg)
        x_Q = int.from_bytes(pub_key[1:], byteorder="big")
        try:
            y_Q = ec.y_even(x_Q)  # also check x_Q validity
            return x_Q, y_Q if prefix == 0x02 else ec.p - y_Q
        except BTClibValueError as e:
            msg = f"invalid x-coordinate: '{hex_string(x_Q)}'"
            raise BTClibValueError(msg) from e
    elif prefix == 0x04 or (hybrid and prefix in (0x06, 0x07)):  # both coordinates
        if bsize != 2 * ec.p_size + 1:
            err_msg = "invalid size for uncompressed point: "
            err_msg += f"{bsize} instead of {2 * ec.p_size + 1}"
            raise BTClibValueError(err_msg)
        x_Q = int.from_bytes(pub_key[1 : ec.p_size + 1], byteorder="big", signed=False)
        Q = x_Q, int.from_bytes(pub_key[ec.p_size + 1 :], byteorder="big", signed=False)
        if Q[1] == 0:  # infinity point in affine coordinates
            raise BTClibValueError("no bytes representation for infinity point")
        # 0x06 says y is even and 0x07 says it is odd, so a hybrid prefix
        # is redundant with the coordinate that follows it -- and a prefix
        # disagreeing with its own coordinate is not a point. libsecp256k1
        # makes this very check, before asking whether the point is on the
        # curve; without it btclib would take a key that the bindings, and
        # therefore consensus, refuse
        if prefix != 0x04 and Q[1] % 2 != prefix - 0x06:
            err_msg = f"y is {'odd' if Q[1] % 2 else 'even'}"
            err_msg += f", against the hybrid prefix 0x{prefix:02x}"
            raise BTClibValueError(err_msg)
        if ec.is_on_curve(Q):
            return Q
        raise BTClibValueError(f"point not on curve: {Q}")
    else:
        # never echo the octets: a 33-byte 0x00-prefixed input
        # is the key field of an xprv, i.e. a private key
        raise BTClibValueError(f"not a point: prefix 0x{pub_key[:1].hex()}")
