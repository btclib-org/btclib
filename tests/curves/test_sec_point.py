#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.sec_point` module."""

import pytest

from btclib.alias import INF
from btclib.curves import Curve, bytes_from_point, point_from_octets
from btclib.curves.curve import CURVES
from btclib.exceptions import BTClibValueError

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

# the union operator, as in curves.curve and tests/curves/test_curve.py
all_curves = low_card_curves | CURVES


def test_octets2point() -> None:
    for ec in all_curves.values():
        G_bytes = bytes_from_point(ec.G, ec)
        G_point = point_from_octets(G_bytes, ec)
        assert ec.G == G_point

        G_bytes = bytes_from_point(ec.G, ec, False)
        G_point = point_from_octets(G_bytes, ec)
        assert ec.G == G_point

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
    STRICTENC" is the generator with a 0x06 in front, and the python path
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


def test_infinity_point_bytes() -> None:
    with pytest.raises(
        BTClibValueError, match="no bytes representation for infinity point"
    ):
        bytes_from_point(INF)


def test_infinity_point_from_octets() -> None:
    curve_size = CURVES["secp256k1"].p_size
    inf_bytes = b"\x04"
    inf_bytes += INF[0].to_bytes(curve_size, byteorder="big", signed=False)
    inf_bytes += INF[1].to_bytes(curve_size, byteorder="big", signed=False)
    with pytest.raises(
        BTClibValueError, match="no bytes representation for infinity point"
    ):
        point_from_octets(inf_bytes)
