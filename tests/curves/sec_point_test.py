# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.sec_point` module."""

import pytest

from btclib.alias import INF
from btclib.b58 import wif_from_prv_key
from btclib.bip32 import BIP32KeyData, rootxprv_from_seed
from btclib.curves import (
    Curve,
    PreparedPoint,
    bytes_from_point,
    bytes_from_prv_key_int,
    # the module, not only the names in it: `_libsecp256k1_available` is
    # an attribute of it, and switching it off is how the tests below
    # reach the Python arithmetic underneath
    curve,
    mult,
    point_from_octets,
    point_from_pub_key,
    scalar_from_prv_key,
    secp256k1,
)
from btclib.curves.curve import CURVES
from btclib.curves.sec_point import _mult_sec_var, _sec_from_octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from tests import needs_bindings

# test curves: very low cardinality
# 13 % 4 = 1; 13 % 8 = 5
low_card_curves = {"ec13_11": Curve(13, 7, 6, (1, 1), 11, 1, False)}
low_card_curves["ec13_19"] = Curve(13, 0, 2, (1, 9), 19, 1, False)
# 17 % 4 = 1; 17 % 8 = 1
low_card_curves["ec17_13"] = Curve(17, 6, 8, (0, 12), 13, 2, False)
low_card_curves["ec17_23"] = Curve(17, 3, 5, (1, 14), 23, 1, False)
# 19 % 4 = 3; 19 % 8 = 3
low_card_curves["ec19_13"] = Curve(19, 0, 2, (4, 16), 13, 2, False)
low_card_curves["ec19_23"] = Curve(19, 2, 9, (0, 16), 23, 1, False)
# 23 % 4 = 3; 23 % 8 = 7
low_card_curves["ec23_19"] = Curve(23, 9, 7, (5, 4), 19, 1, False)
low_card_curves["ec23_31"] = Curve(23, 5, 1, (0, 1), 31, 1, False)

# the union operator, as in curves.curve and tests/curves/curve_test.py
all_curves = low_card_curves | CURVES


def test_octets2point() -> None:
    """Round-trip SEC encodings on every curve, and check the refusals."""
    for ec in all_curves.values():
        G_bytes = bytes_from_point(ec.G, ec)
        G_point = point_from_octets(G_bytes, ec)
        assert G_point == ec.G

        G_bytes = bytes_from_point(ec.G, ec, False)
        G_point = point_from_octets(G_bytes, ec)
        assert G_point == ec.G

        # just a point, not INF
        Q = ec.G

        Q_bytes = b"\x03" if Q[1] & 1 else b"\x02"
        Q_bytes += Q[0].to_bytes(ec.p_size, byteorder="big", signed=False)
        Q_point = point_from_octets(Q_bytes, ec)
        assert Q_point[0] == Q[0]
        assert Q_point[1] == Q[1]
        assert bytes_from_point(Q_point, ec) == Q_bytes

        Q_hex_str = Q_bytes.hex()
        Q_point = point_from_octets(Q_hex_str, ec)
        assert Q_point == Q

        Q_bytes = b"\x04" + Q[0].to_bytes(ec.p_size, byteorder="big", signed=False)
        Q_bytes += Q[1].to_bytes(ec.p_size, byteorder="big", signed=False)
        Q_point = point_from_octets(Q_bytes, ec)
        assert Q_point == Q
        assert bytes_from_point(Q_point, ec, False) == Q_bytes

        Q_hex_str = Q_bytes.hex()
        Q_point = point_from_octets(Q_hex_str, ec)
        assert Q_point == Q

        Q_bytes = b"\x01" + b"\x01" * ec.p_size
        with pytest.raises(BTClibValueError, match="not a point: "):
            point_from_octets(Q_bytes, ec)

        Q_bytes = b"\x01" + b"\x01" * 2 * ec.p_size
        with pytest.raises(BTClibValueError, match="not a point: "):
            point_from_octets(Q_bytes, ec)

        Q_bytes = b"\x04" + b"\x01" * ec.p_size
        with pytest.raises(
            BTClibValueError, match="invalid size for uncompressed point: "
        ):
            point_from_octets(Q_bytes, ec)

        Q_bytes = b"\x02" + b"\x01" * 2 * ec.p_size
        with pytest.raises(
            BTClibValueError, match="invalid size for compressed point: "
        ):
            point_from_octets(Q_bytes, ec)

        Q_bytes = b"\x03" + b"\x01" * 2 * ec.p_size
        with pytest.raises(
            BTClibValueError, match="invalid size for compressed point: "
        ):
            point_from_octets(Q_bytes, ec)

    # invalid x_Q coordinate
    ec = CURVES["secp256k1"]
    x_Q = 0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
    xstr = format(x_Q, "32X")
    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        point_from_octets(f"03{xstr}", ec)
    with pytest.raises(BTClibValueError, match="point not on curve: "):
        point_from_octets("04" + 2 * xstr, ec)
    with pytest.raises(BTClibValueError, match="point not on curve"):
        bytes_from_point((x_Q, x_Q), ec)
    with pytest.raises(BTClibValueError, match="point not on curve"):
        bytes_from_point((x_Q, x_Q), ec, False)


def test_hybrid_prefixes_are_admitted_only_when_asked() -> None:
    """0x06 and 0x07 are SEC 1 too, and consensus takes them.

    The bindings' ec_pubkey_parse takes all three 65-byte prefixes
    (eckey_impl.h), and Core refuses the hybrid pair only under
    STRICTENC, so a script spending to one must verify -- the
    script_tests.json vector "P2PK NOT with hybrid pubkey but no
    STRICTENC" is the generator with a 0x06 in front, and the Python path
    could not parse it at all (issue #129). Off by default because an
    address, a WIF and a descriptor have no hybrid form to render.
    """
    ec = CURVES["secp256k1"]
    Q = ec.G
    body = Q[0].to_bytes(ec.p_size, byteorder="big", signed=False)
    body += Q[1].to_bytes(ec.p_size, byteorder="big", signed=False)
    prefix = b"\x07" if Q[1] & 1 else b"\x06"
    mismatched = b"\x06" if Q[1] & 1 else b"\x07"

    assert point_from_octets(prefix + body, ec, hybrid=True) == Q
    assert point_from_octets((prefix + body).hex(), ec, hybrid=True) == Q

    with pytest.raises(BTClibValueError, match="not a point: prefix "):
        point_from_octets(prefix + body, ec)

    # the prefix repeats the parity of the y that follows it, so the two
    # can contradict each other, and then it is not a point
    with pytest.raises(BTClibValueError, match="against the hybrid prefix "):
        point_from_octets(mismatched + body, ec, hybrid=True)

    # and 0x04 does not acquire a parity rule it never had
    assert point_from_octets(b"\x04" + body, ec, hybrid=True) == Q
    assert point_from_octets(b"\x04" + body, ec) == Q


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_sec_from_octets(bindings: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """Octets in, the same octets out, and the refusals unmoved.

    `_sec_from_octets` skips the round trip through a point that
    to_pub_key.pub_keyinfo_from_pub_key used to make of it (issue 284), so
    what has to be asserted is the identity it claims -- for both forms,
    both parities, and the low-cardinality curves the bindings never see
    -- and that everything the round trip refuses is still refused, with
    the message point_from_octets phrases. The hybrid prefixes are the
    trap: ec_pubkey_parse takes 0x06 and 0x07, and nothing here asks for
    them.
    """
    if not bindings:
        monkeypatch.setattr(curve, "_libsecp256k1_available", False)

    for ec in all_curves.values():
        for Q in (ec.G, mult(2, ec.G, ec), mult(3, ec.G, ec)):
            for compressed in (True, False):
                sec = bytes_from_point(Q, ec, compressed)
                assert _sec_from_octets(sec, ec) == sec

    ec = CURVES["secp256k1"]
    # both prefixes, i.e. both answers of the parity rule: 6G is the first
    # of the small multiples to have an odd y
    assert {
        _sec_from_octets(bytes_from_point(mult(q, ec.G, ec), ec), ec)[0]
        for q in range(1, 13)
    } == {0x02, 0x03}

    # an x that is not a coordinate, which is where the two implementations
    # could disagree and where the message has to be btclib's
    x_Q = 0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
    for prefix in (b"\x02", b"\x03"):
        with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
            _sec_from_octets(prefix + x_Q.to_bytes(ec.p_size, "big"), ec)

    body = ec.G[0].to_bytes(ec.p_size, "big") + ec.G[1].to_bytes(ec.p_size, "big")
    # the hybrid prefixes ec_pubkey_parse accepts and this must not
    for prefix in (b"\x06", b"\x07"):
        with pytest.raises(BTClibValueError, match="not a point: prefix "):
            _sec_from_octets(prefix + body, ec)
    # nor an uncompressed point that is not on the curve, nor infinity
    with pytest.raises(BTClibValueError, match="point not on curve: "):
        _sec_from_octets(b"\x04" + 2 * x_Q.to_bytes(ec.p_size, "big"), ec)
    with pytest.raises(
        BTClibValueError, match="no bytes representation for infinity point"
    ):
        _sec_from_octets(b"\x04" + bytes(2 * ec.p_size), ec)


def test_bytes_from_prv_key_int() -> None:
    """It composes mult and bytes_from_point, so it must answer as they do.

    For secp256k1 it does not: it calls the bindings'
    pubkey_from_prvkey directly, without ever building a point of this
    module's own (issue #459), which is why the equality is asserted
    here scalar by scalar rather than taken as read.
    """
    ec = CURVES["secp256k1"]
    prefixes = set()
    for q in range(1, 13):
        Q = mult(q, ec.G, ec)
        assert bytes_from_prv_key_int(q) == bytes_from_point(Q, ec)
        assert bytes_from_prv_key_int(q, ec, False) == bytes_from_point(Q, ec, False)
        prefixes.add(bytes_from_prv_key_int(q)[0])
    # 6G is the first odd y of the twelve, so both prefixes are covered,
    # i.e. both answers of the parity rule and not one of them twice
    assert prefixes == {0x02, 0x03}

    # the edges of the scalar range, and the reduction mod n that mult
    # applies and this has to keep applying
    for q in (1, ec.n - 1):
        assert bytes_from_prv_key_int(q) == bytes_from_point(mult(q, ec.G, ec), ec)
        assert bytes_from_prv_key_int(q + ec.n) == bytes_from_prv_key_int(q)

    # an Integer, not an int: the octets of a scalar are that scalar
    q_bytes = (ec.n - 1).to_bytes(32, byteorder="big", signed=False)
    assert bytes_from_prv_key_int(q_bytes) == bytes_from_prv_key_int(ec.n - 1)
    assert bytes_from_prv_key_int(q_bytes.hex()) == bytes_from_prv_key_int(ec.n - 1)

    # every other curve is the Python path, which is the composition
    for ec in (CURVES["secp256r1"], low_card_curves["ec13_11"]):
        for q in range(1, min(ec.n, 13)):
            Q = mult(q, ec.G, ec)
            assert bytes_from_prv_key_int(q, ec) == bytes_from_point(Q, ec)
            assert bytes_from_prv_key_int(q, ec, False) == bytes_from_point(
                Q, ec, False
            )

    # a zero scalar is the infinity point, on either path, and the
    # bindings reject it rather than answering a serialization of it
    for ec in (CURVES["secp256k1"], low_card_curves["ec13_11"]):
        for q in (0, ec.n):
            with pytest.raises(
                BTClibValueError, match="no bytes representation for infinity point"
            ):
                bytes_from_prv_key_int(q, ec)


def test_infinity_point_bytes() -> None:
    """Refuse to serialize the point at infinity."""
    with pytest.raises(
        BTClibValueError, match="no bytes representation for infinity point"
    ):
        bytes_from_point(INF)


def test_infinity_point_from_octets() -> None:
    """Refuse an uncompressed encoding spelling the point at infinity."""
    curve_size = CURVES["secp256k1"].p_size
    inf_bytes = b"\x04"
    inf_bytes += INF[0].to_bytes(curve_size, byteorder="big", signed=False)
    inf_bytes += INF[1].to_bytes(curve_size, byteorder="big", signed=False)
    with pytest.raises(
        BTClibValueError, match="no bytes representation for infinity point"
    ):
        point_from_octets(inf_bytes)


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_mult_sec_var(bindings: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """m*P from the octets is m*P from the point, on every curve.

    `_mult_sec_var` skips the round trip `mult(m, point_from_octets(sec))`
    makes -- the lift on the way in and the serialization back out, of a
    point neither side reads a coordinate of -- so what has to be asserted
    is that identity, for both forms of the octets and for the scalars the
    bindings decline: zero, which is infinity and no libsecp256k1 answer,
    and the ones landing on the point itself.

    The low-cardinality curves reach the same lines with no bindings under
    them at all, which is what the `python` case then repeats for
    secp256k1.
    """
    if not bindings:
        monkeypatch.setattr(curve, "_libsecp256k1_available", False)

    for ec in all_curves.values():
        for Q in (ec.G, mult(2, ec.G, ec), mult(3, ec.G, ec)):
            for compressed in (True, False):
                sec = bytes_from_point(Q, ec, compressed)
                for m in (0, 1, 2, ec.n - 1):
                    assert _mult_sec_var(sec, m, ec) == mult(m, Q, ec)

    # and octets that are no point at all are the lift's refusal, which is
    # what the fallthrough exists to keep saying
    ec = CURVES["secp256k1"]
    x_Q = 0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        _mult_sec_var(b"\x02" + x_Q.to_bytes(ec.p_size, "big"), 2, ec)


def test_a_scalar_is_an_int_or_its_octets_and_nothing_else() -> None:
    """What a private key may be spelled as at this layer (issue #1188).

    The integer, its `n_size` octets, their hex, and the buffers
    `bytes_from_octets` takes beside them. A WIF and an extended key are
    not among them: they are `b58`'s and `bip32`'s objects, and this file
    knows about a curve and not about bitcoin, so it could not decode one
    without importing a layer above itself.

    On secp256k1 the size alone separates a scalar from a point --
    `n_size` is 32 where a point is 33 or 65. That is a coincidence and
    not a rule: `sec_point` names the catalogued curves whose `n_size`
    is their compressed size, and there a point is refused by the range
    check instead.
    """
    q = 0xC0FFEE
    octets = q.to_bytes(32, "big")
    for spelling in (q, octets, octets.hex(), bytearray(octets), memoryview(octets)):
        assert scalar_from_prv_key(spelling) == q

    # a WIF and an xprv reach here as text, and text is hex or nothing
    for text in (wif_from_prv_key(q), rootxprv_from_seed("5e" * 32)):
        with pytest.raises(BTClibValueError, match="invalid hex string"):
            scalar_from_prv_key(text)
    with pytest.raises(BTClibTypeError, match="invalid octets type: BIP32KeyData"):
        scalar_from_prv_key(BIP32KeyData.b58decode(rootxprv_from_seed("5e" * 32)))  # type: ignore[arg-type]

    for out_of_range in (0, secp256k1.n):
        with pytest.raises(BTClibValueError, match="private key not in 1..n-1"):
            scalar_from_prv_key(out_of_range)


def test_a_public_key_is_a_point_or_its_octets_and_nothing_else() -> None:
    """What a public key may be spelled as at this layer (issue #1188).

    `scalar_from_prv_key`'s twin above, asked of the other half: the
    point as a tuple, as a `PreparedPoint`, or as the SEC octets
    `point_from_octets` parses. A WIF and an extended key are not among
    them for that test's reason, and neither is a scalar -- in this
    library an int is a private key and never a public one, so it is
    refused as a type rather than reported as a key that does not verify.

    Which spellings the two conversions of `to_pub_key` build on this one
    then accept, crossed with network and compression, is
    `tests/to_pub_key_test.py`; what is here is the parse itself.
    """
    q = 0xC0FFEE
    point = mult(q)
    for spelling in (
        point,
        PreparedPoint(point),
        bytes_from_point(point),
        bytes_from_point(point, compressed=False),
        bytes_from_point(point).hex(),
        bytearray(bytes_from_point(point)),
    ):
        assert point_from_pub_key(spelling) == point

    # a type no spelling has, the scalar among them: refused as a type,
    # and never echoed -- it may be the private material issue #143 is
    # about
    for wrong_type in (q, 1.5, None):
        with pytest.raises(BTClibTypeError, match="not a public key"):
            point_from_pub_key(wrong_type)  # type: ignore[arg-type]

    # a tuple of the right shape that is no point of the curve, and the
    # infinity point, which has no public key
    for not_a_point in ((1, 2), INF):
        with pytest.raises(BTClibValueError, match="not a valid public key"):
            point_from_pub_key(not_a_point)

    # octets of a declared type whose content is no point: a value error,
    # and the parse's own reason is chained under it
    with pytest.raises(BTClibValueError, match="not a public key"):
        point_from_pub_key(wif_from_prv_key(q))
