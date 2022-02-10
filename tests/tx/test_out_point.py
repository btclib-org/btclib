#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.tx_in` module."

import json
from os import path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx


def test_out_point() -> None:
    out_point = OutPoint()
    assert out_point.tx_id == b"\x00" * 32
    assert out_point.vout == 0xFFFFFFFF
    assert out_point.hash == int.from_bytes(out_point.tx_id, "big", signed=False)
    assert out_point.n == out_point.vout
    assert out_point.is_coinbase()
    assert out_point == OutPoint.parse(out_point.serialize())
    assert out_point == OutPoint.from_dict(out_point.to_dict())

    tx_id = "d5b5982254eebca64e4b42a3092a10bfb76ab430455b2bf0cf7c4f7f32db1c2e"
    vout = 0
    out_point = OutPoint(tx_id, vout)
    assert out_point.tx_id.hex() == tx_id
    assert out_point.vout == vout
    assert out_point.hash == int.from_bytes(out_point.tx_id, "big", signed=False)
    assert out_point.n == out_point.vout
    assert not out_point.is_coinbase()
    assert out_point == OutPoint.parse(out_point.serialize())
    assert out_point == OutPoint.from_dict(out_point.to_dict())


def test_dataclasses_json_dict_out_point() -> None:
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as binary_file_:
        temp = Tx.parse(binary_file_.read())

    out_point_data = temp.vin[0].prev_out

    # dataclass
    assert isinstance(out_point_data, OutPoint)

    # Tx to/from dict
    out_point_dict = out_point_data.to_dict()
    assert isinstance(out_point_dict, dict)
    assert out_point_data == OutPoint.from_dict(out_point_dict)

    datadir = path.join(path.dirname(__file__), "_generated_files")

    # Tx dict to/from dict file
    filename = path.join(datadir, "out_point.json")
    with open(filename, "w", encoding="ascii") as file_:
        json.dump(out_point_dict, file_, indent=4)
    with open(filename, "r", encoding="ascii") as file_:
        out_point_dict2 = json.load(file_)
    assert isinstance(out_point_dict2, dict)
    assert out_point_dict == out_point_dict2


def test_invalid_outpoint() -> None:

    out_point = OutPoint(b"\x01" * 31, 18, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid OutPoint tx_id: "):
        out_point.assert_valid()

    out_point = OutPoint(b"\x01" * 32, -1, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid vout: "):
        out_point.assert_valid()

    out_point = OutPoint(b"\x01" * 32, 0xFFFFFFFF + 1, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid vout: "):
        out_point.assert_valid()

    out_point = OutPoint(b"\x00" * 31 + b"\x01", 0xFFFFFFFF, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid OutPoint"):
        out_point.assert_valid()

    out_point = OutPoint(b"\x00" * 32, 0, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid OutPoint"):
        out_point.assert_valid()
