# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""SEC compressed/uncompressed point representation."""

import contextlib

from btclib._libsecp256k1 import (
    pubkey_from_prvkey as libsecp256k1_pubkey_from_prvkey,
)
from btclib._libsecp256k1 import pubkey_tweak_mul as libsecp256k1_pubkey_tweak_mul
from btclib._libsecp256k1 import pubkey_verify as libsecp256k1_pubkey_verify
from btclib.alias import Integer, Octets, Point
from btclib.curves.curve import (
    Curve,
    _assert_valid_ec,
    _libsecp256k1_serves,
    _point_from_sec,
    _y_even_var,
    mult,
    secp256k1,
)
from btclib.exceptions import BTClibValueError
from btclib.utils import assert_type, bytes_from_octets, hex_string, int_from_integer

__all__ = [
    "bytes_from_point",
    "bytes_from_prv_key_int",
    "point_from_octets",
]


def bytes_from_point(Q: Point, ec: Curve = secp256k1, compressed: bool = True) -> bytes:
    """Return a point as compressed/uncompressed octet sequence.

    Return a point as compressed (0x02, 0x03) or uncompressed (0x04)
    octet sequence, according to SEC 1 v.2, section 2.3.3.
    """
    _assert_valid_ec(ec)
    assert_type(compressed, bool, "compressed")
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
    conversion do once per key (issue #127). For secp256k1 this never
    materializes the point: keys.pubkey_from_prvkey is one
    secp256k1_ec_pubkey_create plus one serialize, with the compressed
    flag passed straight through, so the bindings are the ones writing
    the compressed encoding rather than btclib slicing it out of the
    uncompressed one (issue #459).
    """
    _assert_valid_ec(ec)
    # before the bindings, which take it as the C bool they serialize with
    assert_type(compressed, bool, "compressed")
    q = int_from_integer(prv_key_int) % ec.n

    # q == 0 is the infinity point, which the bindings reject as a scalar
    if q and _libsecp256k1_serves(ec, None):
        return libsecp256k1_pubkey_from_prvkey(q, compressed)

    return bytes_from_point(mult(q, ec=ec), ec, compressed)


def point_from_octets(
    pub_key: Octets, ec: Curve = secp256k1, *, hybrid: bool = False
) -> Point:
    """Return a tuple (x_Q, y_Q) that belongs to the curve.

    Return a tuple (x_Q, y_Q) that belongs to the curve according to SEC
    1 v.2, section 2.3.4.

    The compressed prefixes are the only branch libsecp256k1 serves, and
    the whole cost of the function is there: lifting x to a point is a
    modular square root, 75 us of the 76 in Python against 2.9 of the 3.2
    delegated, while the 65-byte forms carry the y and take 1.2 either
    way (issue 284).

    hybrid admits the 0x06 and 0x07 prefixes of that same section, which
    carry both coordinates like 0x04 does and repeat the parity of y in
    the prefix. It is off by default, and not out of squeamishness: the
    point is a point, and libsecp256k1's ec_pubkey_parse takes all three
    65-byte prefixes (eckey_impl.h). What decides is where the parsed key
    goes next -- addresses, WIF and the descriptor language have no
    hybrid form to render, and nothing in bitcoin produces one. Consensus
    has to accept what was mined instead: Core rejects hybrid keys only
    under STRICTENC, so the script engine is the one caller that asks for
    them (issue #129). It is refused rather than read for its truth: its
    `True` is the permissive value, and a non-bool is true, so
    `hybrid="no"` would parse the very prefixes it was written down to
    keep out.
    """
    assert_type(hybrid, bool, "hybrid")
    _assert_valid_ec(ec)
    pub_key = bytes_from_octets(pub_key, (ec.p_size + 1, 2 * ec.p_size + 1))

    bsize = len(pub_key)  # bytes
    prefix = pub_key[0]
    if prefix in {0x02, 0x03}:  # compressed point
        if bsize != ec.p_size + 1:
            err_msg = "invalid size for compressed point: "
            err_msg += f"{bsize} instead of {ec.p_size + 1}"
            raise BTClibValueError(err_msg)
        x_Q = int.from_bytes(pub_key[1:], byteorder="big")
        try:
            y_Q = _y_even_var(x_Q, ec)  # also check x_Q validity
            return x_Q, y_Q if prefix == 0x02 else ec.p - y_Q
        except BTClibValueError as e:
            msg = f"invalid x-coordinate: '{hex_string(x_Q)}'"
            raise BTClibValueError(msg) from e
    elif prefix == 0x04 or (hybrid and prefix in {0x06, 0x07}):  # both coordinates
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


def _mult_sec_var(sec: bytes, m: int, ec: Curve) -> Point:
    """Return m*P, for a point given as the SEC octets that prove it one.

    `mult(m, point_from_octets(sec, ec), ec)` is the same answer, and pays
    a round trip this does not: the octets are lifted to a point on the
    way in, and `mult` writes that point back out as octets for
    secp256k1_ec_pubkey_tweak_mul, which is the call libsecp256k1 would
    have made on the bytes it was handed.

    The caller has proved these octets a point already -- they are what
    `pub_keyinfo_from_pub_key` answers -- so nothing here re-proves it:
    what the bindings decline falls through to the lift, which raises
    where the octets are no point.
    """
    if m and _libsecp256k1_serves(ec, None):
        with contextlib.suppress(ValueError):
            return _point_from_sec(libsecp256k1_pubkey_tweak_mul(sec, m, False))

    return mult(m, point_from_octets(sec, ec), ec)


def _sec_from_octets(pub_key: bytes, ec: Curve) -> bytes:
    """Return SEC octets of a p-size or 2*p-size length, verified.

    Verified and not converted: bytes_from_point(point_from_octets(sec))
    asked for the form sec already has is the identity on it, so what
    that round trip does for a caller that wants octets back is prove
    them a point of the curve -- which is the whole of what
    to_pub_key.pub_keyinfo_from_pub_key wants of it.

    For a compressed key on secp256k1 that proof is `keys.pubkey_verify`,
    which is ec_pubkey_parse and a verdict: 2.4 us against the 4.4 of a
    round trip that lifts x, re-proves the point it lifted on the curve
    and serializes it again -- and against the 2.7 of `keys.reserialize`,
    which answers the octets this already has. The parse is also the very
    call libsecp256k1 will make on these bytes if they are on their way to
    its dsa.verify -- which is why a caller that is about to make it does
    not come through here at all, but through
    `to_pub_key._sec_from_pub_key`, and lets that call be the proof
    (issue 887).

    Anything the bindings refuse falls through to the round trip, and so
    does every 65-byte form: the message that names what is wrong with
    the octets is point_from_octets's, and the hybrid prefixes are the
    reason the fallthrough cannot be skipped for a length ec_pubkey_parse
    accepts -- it takes 0x06 and 0x07, point_from_octets only when asked,
    and there is nothing to ask here.
    """
    compressed = len(pub_key) == ec.p_size + 1
    if (
        compressed
        and _libsecp256k1_serves(ec, None)
        and libsecp256k1_pubkey_verify(pub_key)
    ):
        return pub_key

    return bytes_from_point(point_from_octets(pub_key, ec), ec, compressed)
