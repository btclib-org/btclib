#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""SEC compressed/uncompressed point representation."""

from btclib_libsecp256k1.mult import mult_ as libsecp256k1_mult_

from btclib.alias import Integer, Octets, Point
from btclib.curves.curve import Curve, _libsecp256k1_applicable, mult, secp256k1
from btclib.exceptions import BTClibValueError
from btclib.utils import bytes_from_octets, hex_string, int_from_integer


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


def bytes_from_prv_key_int(
    prv_key_int: Integer, ec: Curve = secp256k1, compressed: bool = True
) -> bytes:
    """Return the public key of a scalar, as SEC octets.

    This is bytes_from_point(mult(prv_key_int, ec.G, ec), ec, compressed)
    and answers what that answers, the edges included: the scalar is
    reduced mod n, and zero -- the infinity point -- has no
    representation and raises.

    That composition is what BIP32 derivation and every private-to-public
    conversion do once per key (issue #127), and for secp256k1 this
    never materializes the point. The bindings serialize the point they
    create with SECP256K1_EC_UNCOMPRESSED, i.e. 0x04 || x || y (SEC 1
    v.2, section 2.3.3), so the compressed form is the first 33 bytes of
    it with the prefix rewritten to the parity of the y being dropped --
    the rule bytes_from_point applies above, and the whole of what those
    32 discarded bytes are needed for. Asking for the uncompressed form
    is then free.

    Measured per call over 2000 random keys, best of nine: 7.75 us here
    against 8.90 for bytes_from_point(mult(...)), which turns 64 bytes
    into two ints, re-proves on curve a point libsecp256k1 has just
    created, and serializes it again; and 8.13 for
    keys.serialize(keys.parse(mult_(...))), which pays a
    secp256k1_ec_pubkey_parse to undo a serialization the same library had
    just done. The floor is mult_ alone, 7.60.

    That floor is the reason the decision here was btclib's to take and
    not the bindings'. A pubkey_from_prvkey of their own -- one
    secp256k1_ec_pubkey_create plus one compressed serialize, proposed in
    btclib_libsecp256k1#41 -- measures 7.67 dropped into this same
    function, i.e. 0.06 us or 0.8% below the slice, since the 32 bytes it
    does not serialize cost about what the slice costs. It remains worth
    having for the bindings' own API, whose stated convention is that
    public keys come out compressed unless otherwise required; when it
    lands it replaces the three lines below and nothing else.
    """
    q = int_from_integer(prv_key_int) % ec.n

    # q == 0 is the infinity point, which the bindings reject as a scalar
    if q and _libsecp256k1_applicable(ec):
        sec = libsecp256k1_mult_(q)
        if not compressed:
            return sec
        # sec[64], not sec[-1]: were mult_ ever to answer 33 bytes, this
        # raises IndexError instead of taking a byte of x for a parity
        return (b"\x03" if sec[64] & 1 else b"\x02") + sec[1:33]

    return bytes_from_point(mult(q, ec=ec), ec, compressed)


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
