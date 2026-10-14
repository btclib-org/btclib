# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the int fields `serialize(check_validity=False)` writes.

`check_validity=False` skips `assert_valid`, and not the check of each
int field the serializers write: a non-int is a `BTClibTypeError`, an int
outside the range of its octets a `BTClibValueError`, and a bool is
written as zero or one. Without that check `int.to_bytes` and `bytes`
raise their own errors, and a field written through `int` writes `1.5`
and `"1"` as one.

Each row names one field by a function that builds an object holding the
value under test, `check_validity=False` or not as the caller says.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p import (
    CFCheckpt,
    CFHeaders,
    CFilter,
    GetBlocks,
    GetCFCheckpt,
    GetCFHeaders,
    GetCFilters,
    GetHeaders,
    Inventory,
    NetworkAddress,
    NetworkAddressV2,
    Reject,
    SendTxRcncl,
    TimestampedNetworkAddress,
    Version,
)

_MAX_U8 = 2**8 - 1
_MAX_U16 = 2**16 - 1
_MAX_U32 = 2**32 - 1
_MAX_U64 = 2**64 - 1
_MIN_I32 = -(2**31)
_MAX_I32 = 2**31 - 1
_MIN_I64 = -(2**63)
_MAX_I64 = 2**63 - 1

_Make = Callable[..., Any]

# name: (builds an object from a value and `check_validity`, what the
# error calls the field, lowest value, highest value)
_FIELDS: dict[str, tuple[_Make, str, int, int]] = {
    "SendTxRcncl.version": (
        lambda v, **kw: SendTxRcncl(v, 0, **kw),
        "version",
        0,
        _MAX_U32,
    ),
    "SendTxRcncl.salt": (
        lambda v, **kw: SendTxRcncl(0, v, **kw),
        "salt",
        0,
        _MAX_U64,
    ),
    "Version.version": (
        lambda v, **kw: Version(version=v, **kw),
        "version",
        _MIN_I32,
        _MAX_I32,
    ),
    "Version.services": (
        lambda v, **kw: Version(services=v, **kw),
        "services",
        0,
        _MAX_U64,
    ),
    "Version.timestamp": (
        lambda v, **kw: Version(timestamp=v, **kw),
        "timestamp",
        _MIN_I64,
        _MAX_I64,
    ),
    "Version.nonce": (lambda v, **kw: Version(nonce=v, **kw), "nonce", 0, _MAX_U64),
    "Version.start_height": (
        lambda v, **kw: Version(start_height=v, **kw),
        "start height",
        _MIN_I32,
        _MAX_I32,
    ),
    "GetBlocks.version": (
        GetBlocks,
        "version",
        _MIN_I32,
        _MAX_I32,
    ),
    "GetHeaders.version": (
        GetHeaders,
        "version",
        _MIN_I32,
        _MAX_I32,
    ),
    "Inventory.type_code": (
        Inventory,
        "type_code",
        0,
        _MAX_U32,
    ),
    "GetCFilters.filter_type": (
        GetCFilters,
        "filter_type",
        0,
        _MAX_U8,
    ),
    "GetCFilters.start_height": (
        lambda v, **kw: GetCFilters(0, v, **kw),
        "start_height",
        0,
        _MAX_U32,
    ),
    "GetCFHeaders.start_height": (
        lambda v, **kw: GetCFHeaders(0, v, **kw),
        "start_height",
        0,
        _MAX_U32,
    ),
    "CFilter.filter_type": (
        CFilter,
        "filter_type",
        0,
        _MAX_U8,
    ),
    "CFHeaders.filter_type": (
        CFHeaders,
        "filter_type",
        0,
        _MAX_U8,
    ),
    "GetCFCheckpt.filter_type": (
        GetCFCheckpt,
        "filter_type",
        0,
        _MAX_U8,
    ),
    "CFCheckpt.filter_type": (
        CFCheckpt,
        "filter_type",
        0,
        _MAX_U8,
    ),
    "NetworkAddress.services": (
        NetworkAddress,
        "services",
        0,
        _MAX_U64,
    ),
    "NetworkAddress.port": (
        lambda v, **kw: NetworkAddress(port=v, **kw),
        "port",
        0,
        _MAX_U16,
    ),
    "TimestampedNetworkAddress.timestamp": (
        TimestampedNetworkAddress,
        "timestamp",
        0,
        _MAX_U32,
    ),
    "NetworkAddressV2.timestamp": (
        NetworkAddressV2,
        "timestamp",
        0,
        _MAX_U32,
    ),
    "NetworkAddressV2.services": (
        lambda v, **kw: NetworkAddressV2(services=v, **kw),
        "services",
        0,
        _MAX_U64,
    ),
    "NetworkAddressV2.network_id": (
        lambda v, **kw: NetworkAddressV2(network_id=v, **kw),
        "network_id",
        0,
        _MAX_U8,
    ),
    "NetworkAddressV2.port": (
        lambda v, **kw: NetworkAddressV2(port=v, **kw),
        "port",
        0,
        _MAX_U16,
    ),
    "Reject.code": (lambda v, **kw: Reject("", v, **kw), "code", 0, _MAX_U8),
}

_IDS = list(_FIELDS)


def _field(name: str) -> tuple[_Make, str, int, int]:
    return _FIELDS[name]


@pytest.mark.parametrize("name", _IDS)
@pytest.mark.parametrize("value", [1.5, None, "1", b"\x01"], ids=repr)
def test_an_unchecked_field_that_is_no_int_is_refused_where_it_is_written(
    name: str, value: object
) -> None:
    """Neither `AttributeError` nor `TypeError` leaves `serialize`."""
    make, what, _, _ = _field(name)
    unchecked = make(value, check_validity=False)
    with pytest.raises(BTClibTypeError, match=f"invalid {what} type"):
        unchecked.serialize(check_validity=False)


@pytest.mark.parametrize("name", _IDS)
@pytest.mark.parametrize("side", ["below", "above", "huge"])
def test_an_unchecked_field_out_of_range_is_refused_where_it_is_written(
    name: str, side: str
) -> None:
    """`OverflowError` does not leave `serialize`, whatever the value's size."""
    make, what, low, high = _field(name)
    value = {"below": low - 1, "above": high + 1, "huge": 2**4300}[side]
    unchecked = make(value, check_validity=False)
    with pytest.raises(BTClibValueError, match=f"invalid {what}"):
        unchecked.serialize(check_validity=False)


@pytest.mark.parametrize("name", _IDS)
def test_an_unchecked_field_the_octets_hold_is_written(name: str) -> None:
    """The edges of the range write what a checked object writes."""
    make, _, low, high = _field(name)
    for value in (low, high):
        written = make(value, check_validity=False).serialize(check_validity=False)
        assert written == make(value).serialize()


@pytest.mark.parametrize("name", _IDS)
def test_an_unchecked_bool_is_written_as_zero_or_one(name: str) -> None:
    """Only `check_validity` refuses a bool, which is an int."""
    make, _, _, _ = _field(name)
    for flag in (False, True):
        unchecked = make(flag, check_validity=False)
        assert unchecked.serialize(check_validity=False) == make(int(flag)).serialize()


@pytest.mark.parametrize("relay", [1.5, "1", b"\x01"], ids=repr)
def test_an_unchecked_relay_that_is_no_int_is_refused_where_it_is_written(
    relay: Any,
) -> None:
    """The relay octet is written through `int`, which reads `1.5` as one."""
    unchecked = Version(relay=relay, check_validity=False)
    with pytest.raises(BTClibTypeError, match="invalid relay type"):
        unchecked.serialize(check_validity=False)


@pytest.mark.parametrize("relay", [-1, 256, 2**4300])
def test_an_unchecked_relay_out_of_range_is_refused_where_it_is_written(
    relay: int,
) -> None:
    """One octet holds 0 to 255, and `bytes([...])` would raise `ValueError`."""
    unchecked = Version(relay=relay, check_validity=False)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="invalid relay"):
        unchecked.serialize(check_validity=False)


def test_an_unchecked_relay_the_octet_holds_is_written() -> None:
    """A bool, and an int that only `check_validity` refuses."""
    for relay in (False, True, 0, 255):
        unchecked = Version(relay=relay, check_validity=False)  # type: ignore[arg-type]
        assert unchecked.serialize(check_validity=False)[-1:] == bytes([int(relay)])
    assert len(Version(relay=None).serialize()) + 1 == len(
        Version(relay=True).serialize()
    )
