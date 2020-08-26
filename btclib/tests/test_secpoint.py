#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.secpoint` module."

import secrets
from typing import Dict

import pytest

from btclib.curve import Curve, _mult_aff
from btclib.curves import CURVES
from btclib.secpoint import bytes_from_point, point_from_octets

# test curves: very low cardinality
low_card_curves: Dict[str, Curve] = {}
# 13 % 4 = 1; 13 % 8 = 5
low_card_curves["ec13_11"] = Curve(13, 7, 6, (1, 1), 11, 1, False)
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

all_curves: Dict[str, Curve] = {}
all_curves.update(low_card_curves)
all_curves.update(CURVES)


@pytest.mark.third
def test_octets2point() -> None:
    for ec in all_curves.values():

        Gbytes = bytes_from_point(ec.G, ec)
        G2 = point_from_octets(Gbytes, ec)
        assert ec.G == G2

        Gbytes = bytes_from_point(ec.G, ec, False)
        G2 = point_from_octets(Gbytes, ec)
        assert ec.G == G2

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = _mult_aff(q, ec.G, ec)

        Q_bytes = b"\x03" if Q[1] & 1 else b"\x02"
        Q_bytes += Q[0].to_bytes(ec.psize, byteorder="big")
        R = point_from_octets(Q_bytes, ec)
        assert R == Q
        assert bytes_from_point(R, ec) == Q_bytes

        Q_hex_str = Q_bytes.hex()
        R = point_from_octets(Q_hex_str, ec)
        assert R == Q

        Q_bytes = b"\x04" + Q[0].to_bytes(ec.psize, byteorder="big")
        Q_bytes += Q[1].to_bytes(ec.psize, byteorder="big")
        R = point_from_octets(Q_bytes, ec)
        assert R == Q
        assert bytes_from_point(R, ec, False) == Q_bytes

        Q_hex_str = Q_bytes.hex()
        R = point_from_octets(Q_hex_str, ec)
        assert R == Q

        err_msg = "'<' not supported between instances of 'tuple' and 'int'"
        with pytest.raises(TypeError, match=err_msg):
            _mult_aff(tuple(), ec.G, ec)  # type: ignore

        Q_bytes = b"\x01" + b"\x01" * ec.psize
        with pytest.raises(ValueError, match="not a point: "):
            point_from_octets(Q_bytes, ec)

        Q_bytes = b"\x01" + b"\x01" * 2 * ec.psize
        with pytest.raises(ValueError, match="not a point: "):
            point_from_octets(Q_bytes, ec)

        Q_bytes = b"\x04" + b"\x01" * ec.psize
        with pytest.raises(ValueError, match="invalid size for uncompressed point: "):
            point_from_octets(Q_bytes, ec)

        Q_bytes = b"\x02" + b"\x01" * 2 * ec.psize
        with pytest.raises(ValueError, match="invalid size for compressed point: "):
            point_from_octets(Q_bytes, ec)

        Q_bytes = b"\x03" + b"\x01" * 2 * ec.psize
        with pytest.raises(ValueError, match="invalid size for compressed point: "):
            point_from_octets(Q_bytes, ec)

    # invalid x_Q coordinate
    ec = CURVES["secp256k1"]
    x_Q = 0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
    xstr = format(x_Q, "32X")
    with pytest.raises(ValueError, match="invalid x-coordinate: "):
        point_from_octets("03" + xstr, ec)
    with pytest.raises(ValueError, match="point not on curve: "):
        point_from_octets("04" + 2 * xstr, ec)
    with pytest.raises(ValueError, match="point not on curve"):
        bytes_from_point((x_Q, x_Q), ec)
    with pytest.raises(ValueError, match="point not on curve"):
        bytes_from_point((x_Q, x_Q), ec, False)
