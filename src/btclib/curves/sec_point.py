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
    PreparedPoint,
    _assert_valid_ec,
    _libsecp256k1_serves,
    _point_from_sec,
    _y_even_var,
    mult,
    secp256k1,
)
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import assert_type, bytes_from_octets, hex_string, int_from_integer

__all__ = [
    "PubKey",
    "bytes_from_point",
    "bytes_from_prv_key_int",
    "point_from_octets",
    "point_from_pub_key",
    "scalar_from_prv_key",
]

# public key inputs: the curve point, as a tuple, as a PreparedPoint, or
# as the SEC octets of one.
#
# Named where `scalar_from_prv_key`'s union is not, and the difference is
# whether mypy has anything to check: a scalar's spellings are `Integer`
# exactly, so a second name for that union would say nothing, where these
# three types are a union no alias holds
PubKey = Octets | Point | PreparedPoint

# the union at run time, with the buffers bytes_from_octets accepts beside
# bytes. `to_pub_key._KEY_TYPES` is this list plus the int that names a
# private key, and is built from this one rather than repeating it
_PUB_KEY_TYPES = (bytes, bytearray, memoryview, str, tuple, PreparedPoint)


def scalar_from_prv_key(prv_key: Integer, ec: Curve = secp256k1) -> int:
    """Return a verified-as-valid private key integer.

    Here rather than in a converter, and beside `bytes_from_prv_key_int`
    for its reason: a scalar in 1..n-1 is a fact about the curve and
    nothing above it knows more about it than this file does.

    `Integer` and not a `PrvKey` of this module's own, which would be
    that same union of types under a second name and so nothing mypy
    could check; the parameter carries the role the way `mult`'s `m_int`
    does. The spellings this takes are narrower than the ones `Integer`
    names -- `int_from_integer` reads "0xc0ffee" and a short hex string,
    where a key is `n_size` octets or nothing. What rules those out is
    reading them with `bytes_from_octets` and the size handed to it,
    rather than with `int_from_integer`; the annotation could not, the
    two unions being one. A WIF and an extended key are not among the
    spellings -- they are `b58`'s and `bip32`'s objects, and turning one
    into a scalar is a call a caller makes rather than a spelling this
    layer guesses at (issue #1188).

    The range is checked in Python for every curve. `keys.prvkey_verify`
    is libsecp256k1's answer to the same question and is not called for
    want of anything to gain: a comparison on a value that is already a
    Python int, with no constant-time argument to pay for the call with,
    since whether a key is in range is precisely what the caller is being
    told. The comparison also serves every curve, where the binding is
    secp256k1 alone.
    """
    _assert_valid_ec(ec)

    if isinstance(prv_key, int):
        # through `int_from_integer` for an int this already has: it is
        # where the bool rule lives, so a `True` is refused here in the
        # words every other `Integer` parameter refuses it in, and a real
        # int comes back untouched. The hex spellings it also takes never
        # reach it -- the isinstance above is what keeps "0xc0ffee" out
        q = int_from_integer(prv_key)
    else:
        # `n_size` and not a guess: 32 for secp256k1, where a point is 33
        # or 65, so the size alone separates a scalar from one. That is
        # not true of every curve in the catalogue -- secp160k1,
        # secp160r1, secp160r2 and secp224k1 have an `n_size` equal to
        # their compressed point size -- and there a point is refused by
        # the range check below instead, its 02 or 03 prefix putting the
        # integer past n. The refusal is the same; only which line makes
        # it differs
        q = int.from_bytes(bytes_from_octets(prv_key, ec.n_size), "big")

    if not 0 < q < ec.n:
        raise BTClibValueError("private key not in 1..n-1")

    return q


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
    modular square root, nearly all of that cost on either arm, and
    delegated it costs a small fraction of what the Python one does,
    while the 65-byte forms carry the y and cost the same either way
    (issue 284).

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


def _assert_pub_key_type(pub_key: PubKey) -> None:
    """Refuse a type no spelling of a public key has.

    Asked at the top of the parse, not inferred from whichever spelling
    failed last: a value of no key type at all is a BTClibTypeError here,
    kept apart from the BTClibValueError a spelling raises once its type
    is right and its content is not, so "this key is not on the curve"
    and "this is not a key at all" answer as two different classes rather
    than one.

    The difference is what a boolean verification reads, and issue #814
    is where it is stated: `dsa.verify` answers False about a value of a
    declared type and refuses a type it does not declare, exactly as
    `script_pub_key.is_p2sh` does. The union is closed, so the question
    has an answer here; `ssa.point_from_bip340pub_key` ends in this same
    refusal for the same reason.

    Never echo the input: it may be private material passed by mistake,
    which is the very confusion issue #143 is about -- an int is a
    private key here, so it is refused as a type rather than reported as
    a public key that does not verify.
    """
    if not isinstance(pub_key, _PUB_KEY_TYPES):
        raise BTClibTypeError("not a public key")


def point_from_pub_key(pub_key: PubKey, ec: Curve = secp256k1) -> Point:
    """Return an elliptic curve point tuple from a public key.

    `point_from_octets` is the parse of the one spelling that has to be
    parsed; this is that parse with the two spellings that are already a
    point in front of it, and it lives here for the reason
    `scalar_from_prv_key` does -- what a public key is, at this layer, is
    a point of the curve, and nothing above knows more about one than
    this file (issue #1188). A spelling that carries a network or a
    compression flag is not among them: an extended key is `bip32`'s
    object, read by `bip32.point_from_xpub`.

    **A prepared point is read as the point it holds.**
    `curves.PreparedPoint` is a `Point` plus a caller's word that it will
    be multiplied again, and the word is the whole of the difference: a
    point is the point's. What is *not* is the memoized tables, which
    whatever reads them reads off the object and not through here.

    Nothing compares a curve on the way through: a prepared point of
    another curve fails the `is_on_curve` its tuple then faces, exactly
    as a bare `Point` of that curve does and with the same message.
    """
    _assert_valid_ec(ec)
    _assert_pub_key_type(pub_key)
    if isinstance(pub_key, PreparedPoint):
        return point_from_pub_key(pub_key.point, ec)

    if isinstance(pub_key, tuple):
        if ec.is_on_curve(pub_key) and pub_key[1] != 0:
            return pub_key[0], pub_key[1]
        raise BTClibValueError(f"not a valid public key: {pub_key}")
    # it must be octets
    try:
        return point_from_octets(pub_key, ec)
    except (TypeError, ValueError) as e:
        # never echo the input: it may be private material passed by
        # mistake; the chained exception carries the parsing reason
        raise BTClibValueError("not a public key") from e


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
    which is ec_pubkey_parse and a verdict, cheaper than a round trip
    that lifts x, re-proves the point it lifted on the curve and
    serializes it again, and cheaper than `keys.reserialize`, which
    answers the octets this already has. The parse is also the very
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
