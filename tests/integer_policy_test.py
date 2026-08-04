#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the one policy on integer fields: a bool is not a number.

One file rather than a case per module, because the decision is one and
`btclib.utils.is_integer` states it. What makes it worth a refusal is the
json boundary: `true` decodes to `True`, and a schema mistake used to
become one satoshi, one virtual byte, one index or a one-sat/kvB fee rate
instead of failing beside the input that caused it.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

import pytest

from btclib.amount import valid_sats_amount
from btclib.bip32 import BIP32KeyData
from btclib.block import BlockHeader
from btclib.block.block_context import BlockContext
from btclib.exceptions import BTClibTypeError
from btclib.fee import FeeRate, fee_from_vsize
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utils import is_integer

_TX_ID = "01" * 32
_RATE = FeeRate(sats_per_kvbyte=1000)
_NOW = datetime(2026, 8, 4, tzinfo=timezone.utc)


def _tx(version: Any = 1, lock_time: Any = 0) -> Tx:
    return Tx(
        version,
        lock_time,
        [TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF)],
        [TxOut(1, b"")],
    )


def _header(version: Any = 1, nonce: Any = 1) -> BlockHeader:
    return BlockHeader(
        version,
        "00" * 32,
        "11" * 32,
        datetime(2009, 1, 9, tzinfo=timezone.utc),
        "1d00ffff",
        nonce,
    )


# every field whose contract is an integer quantity, with the shortest
# call that reaches its validator
_CASES: list[tuple[str, Callable[[Any], object]]] = [
    ("satoshi amount", valid_sats_amount),
    ("fee rate", lambda v: FeeRate(sats_per_kvbyte=v)),
    ("virtual size", lambda v: fee_from_vsize(v, _RATE)),
    ("output value", lambda v: TxOut(v, b"")),
    ("outpoint vout", lambda v: OutPoint(_TX_ID, v)),
    (
        "outpoint vout from a dict",
        lambda v: OutPoint.from_dict({"txid": _TX_ID, "vout": v}),
    ),
    ("input sequence", lambda v: TxIn(OutPoint(_TX_ID, 0), b"", v)),
    ("transaction version", _tx),
    ("transaction lock time", lambda v: _tx(lock_time=v)),
    ("header version", _header),
    ("header nonce", lambda v: _header(nonce=v)),
    ("block height", lambda v: BlockContext(v, _NOW)),
    ("bip34 height", lambda v: BlockContext(1, _NOW, v)),
    (
        "bip32 depth",
        lambda v: BIP32KeyData(
            b"\x04\x88\xad\xe4", v, b"\x00" * 4, 0, b"\x00" * 32, b"\x00" * 33
        ),
    ),
    (
        "bip32 index",
        lambda v: BIP32KeyData(
            b"\x04\x88\xad\xe4", 0, b"\x00" * 4, v, b"\x00" * 32, b"\x00" * 33
        ),
    ),
]

_IDS = [case[0] for case in _CASES]
_CALLS = [case[1] for case in _CASES]


@pytest.mark.parametrize("call", _CALLS, ids=_IDS)
@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_a_bool_is_not_an_integer_field(
    call: Callable[[Any], object], *, value: bool
) -> None:
    """Every integer field refuses a boolean, and refuses it as a type.

    `isinstance(True, int)` is what let each of these through as one or
    zero, and `int(True) == True` is what let the satoshi amount through a
    conversion-and-equality check on top of that.
    """
    with pytest.raises(BTClibTypeError):
        call(value)


def test_the_integers_a_bool_refusal_must_not_take_with_it() -> None:
    """The same calls with a number, which is what the refusal is around.

    A test that only checks refusals passes just as well when the field
    refuses everything.
    """
    assert valid_sats_amount(1) == 1
    assert FeeRate(sats_per_kvbyte=1).sats_per_kvbyte == 1
    assert fee_from_vsize(1, _RATE) == 1
    assert TxOut(1, b"").value == 1
    assert OutPoint(_TX_ID, 1).vout == 1
    assert OutPoint.from_dict({"txid": _TX_ID, "vout": 1}).vout == 1
    assert TxIn(OutPoint(_TX_ID, 0), b"", 1).sequence == 1
    assert _tx(version=1, lock_time=1).lock_time == 1
    assert _header(nonce=1).nonce == 1
    assert BlockContext(1, _NOW).height == 1


def test_an_int_subclass_that_is_not_a_bool_is_still_an_integer() -> None:
    """`IntEnum` stays a number, which is why the predicate names bool.

    Issue #273 asks whether the sighash types should become an `IntEnum`;
    `type(value) is int` would have answered it in advance, and with a no.
    """

    class Sighash(IntEnum):
        ALL = 1

    assert is_integer(Sighash.ALL)
    assert valid_sats_amount(Sighash.ALL) == 1
    assert FeeRate(sats_per_kvbyte=Sighash.ALL).sats_per_kvbyte == 1

    assert is_integer(0)
    assert is_integer(-1)
    assert not is_integer(True)
    assert not is_integer(False)
    assert not is_integer(1.0)
    assert not is_integer("1")
    assert not is_integer(None)
