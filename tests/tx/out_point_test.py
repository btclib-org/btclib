# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.tx_in` module."""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.tx import OutPoint, Tx
from tests.conftest import JsonGolden


def test_out_point() -> None:
    """Check defaults, coinbase detection, and both round-trips."""
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


def test_frozen() -> None:
    """Refuse assignment to either field: a frozen OutPoint is hashable."""
    out_point = OutPoint(
        "d5b5982254eebca64e4b42a3092a10bfb76ab430455b2bf0cf7c4f7f32db1c2e", 0
    )

    with pytest.raises(FrozenInstanceError):
        out_point.tx_id = b"\x00" * 32  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        out_point.vout = 1  # type: ignore[misc]

    # both fields being immutable too, a frozen OutPoint is hashable: the
    # dict key or set member an utxo set wants
    assert hash(out_point) == hash(
        OutPoint("d5b5982254eebca64e4b42a3092a10bfb76ab430455b2bf0cf7c4f7f32db1c2e", 0)
    )
    assert len({out_point, OutPoint(out_point.tx_id, out_point.vout)}) == 1


def test_dataclasses_json_dict_out_point(json_golden: JsonGolden) -> None:
    """Round-trip an OutPoint through dict, against the golden json."""
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as binary_file_:
        temp = Tx.parse(binary_file_.read())

    out_point_data = temp.vin[0].prev_out

    # dataclass
    assert isinstance(out_point_data, OutPoint)

    # Tx to/from dict
    out_point_dict = out_point_data.to_dict()
    assert isinstance(out_point_dict, dict)
    assert out_point_data == OutPoint.from_dict(out_point_dict)

    # against the json committed beside this module, not written to it
    json_golden("out_point.json", out_point_dict)


def test_invalid_outpoint() -> None:
    """Refuse a bad tx_id length, vout range, or half-coinbase outpoint."""
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


def test_a_tx_id_is_exactly_32_bytes() -> None:
    """Too long is refused as well as too short, the field being fixed.

    A length checked from below only is the shape issue 322 reported
    elsewhere: 33 bytes serialize back to 37, so the octets an OutPoint
    was built from and the octets it writes would differ, and the two
    would name different outputs.
    """
    for size in (0, 31, 33, 64):
        out_point = OutPoint(b"\x01" * size, 18, check_validity=False)
        with pytest.raises(BTClibValueError, match="invalid OutPoint tx_id: "):
            out_point.assert_valid()


def test_a_coinbase_marker_is_both_fields_or_neither() -> None:
    """is_coinbase answers for the pair, and half of it is not a coinbase.

    assert_valid refuses the mix, so a valid OutPoint cannot tell the
    conjunction from either half of it: the objects built with the check
    off are the only place the question can be put, and the answer decides
    whether a transaction with such an input is read as a coinbase.
    """
    assert OutPoint().is_coinbase()

    for tx_id, vout in (
        (b"\x00" * 32, 0),  # the null tx_id, a real vout
        (b"\x01" * 32, 0xFFFFFFFF),  # a real tx_id, the null vout
        (b"", 0xFFFFFFFF),  # no tx_id at all
        (b"\x00" * 32, 0xFFFFFFFF + 1),  # a vout no four bytes hold
        (b"\x01" * 32, 0),
    ):
        assert not OutPoint(tx_id, vout, check_validity=False).is_coinbase()
