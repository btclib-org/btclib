# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the one policy on integer fields: a bool is not a number.

One file rather than a case per module, because the decision is one and
`btclib.utils.is_integer` states it. What makes it worth a refusal is the
json boundary: `true` decodes to `True`, and a schema mistake used to
become one satoshi, one virtual byte, one index or a one-sat/kvB fee rate
instead of failing beside the input that caused it.

The predicate does have a second spelling, `btclib.bitcoin_core_rpc` being
vendorable as one file and therefore importing nothing of btclib's. The last
test here is what keeps that copy from drifting.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from decimal import Decimal
from enum import IntEnum
from typing import Any

import pytest

from btclib import base58, var_int
from btclib.amount import valid_sats_amount
from btclib.bip32 import BIP32KeyData
from btclib.bip32.der_path import (
    bytes_from_der_path,
    indexes_from_der_path,
    str_from_der_path,
    str_from_index_int,
)
from btclib.bitcoin_core_rpc import _is_integer
from btclib.block import BlockHeader
from btclib.block.block_context import BlockContext
from btclib.exceptions import BTClibTypeError
from btclib.fee import FeeRate, fee_from_vsize
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utils import bytes_from_octets, is_integer

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
    ("dust threshold", lambda v: valid_sats_amount(1, dust=v)),
    ("derivation index", indexes_from_der_path),
    ("derivation index in a sequence", lambda v: indexes_from_der_path([v])),
    ("derivation path as bytes", bytes_from_der_path),
    ("derivation path as text", str_from_der_path),
    ("derivation index as a step", str_from_index_int),
    ("output size", lambda v: bytes_from_octets(b"x", v)),
    ("output size in an iterable", lambda v: bytes_from_octets(b"x", [v])),
    ("base58 output size", lambda v: base58.decode(base58.encode(b"x"), v)),
    ("var_int", var_int.serialize),
    ("var_int max_size", lambda v: var_int.parse(b"\x01", max_size=v)),
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
    assert valid_sats_amount(1, dust=1) == 1
    assert indexes_from_der_path(1) == [1]
    assert indexes_from_der_path([1, 2]) == [1, 2]
    assert bytes_from_der_path(1).hex() == "01000000"
    assert str_from_der_path([1]) == "m/1"
    assert str_from_index_int(1) == "1"
    assert bytes_from_octets(b"x", 1) == b"x"
    assert bytes_from_octets(b"xx", [1, 2]) == b"xx"
    assert base58.decode(base58.encode(b"x"), 1) == b"x"
    assert var_int.serialize(1) == b"\x01"
    assert var_int.parse(b"\x01", max_size=1) == 1

    # the str and bytes spellings of a path are untouched by any of it
    assert indexes_from_der_path("m/44h/0h") == [2147483692, 2147483648]


def test_what_is_no_integer_at_all_is_refused_the_same_way() -> None:
    """The policy is about integers, and a bool is only its sharpest case.

    These boundaries used to convert what they were handed -- a derivation
    path through `int()`, a dust threshold through a comparison -- or to
    complain about the wrong thing: an output size that is neither a number
    nor an iterable of them met `tuple()` and answered "not iterable", from
    underneath the library rather than through its exception contract.
    """
    with pytest.raises(BTClibTypeError, match="non-integer satoshi dust"):
        valid_sats_amount(1, dust=1.0)  # type: ignore[arg-type]

    with pytest.raises(BTClibTypeError, match="invalid derivation index type"):
        indexes_from_der_path([2.0])  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid derivation index type"):
        str_from_index_int(1.0)  # type: ignore[arg-type]

    for out_size in (1.5, object(), "1"):
        with pytest.raises(BTClibTypeError, match="invalid output size type"):
            bytes_from_octets(b"x", out_size)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid output size type"):
        bytes_from_octets(b"x", [1.5])  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid output size type"):
        base58.decode(base58.encode(b"x"), 1.0)  # type: ignore[arg-type]

    for not_a_count in (1.5, "1", object()):
        with pytest.raises(BTClibTypeError, match="non-integer var_int"):
            var_int.serialize(not_a_count)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="non-integer max_size"):
            var_int.parse(b"\x01", max_size=not_a_count)  # type: ignore[arg-type]


def test_an_int_subclass_that_is_not_a_bool_is_still_an_integer() -> None:
    """`IntEnum` stays a number, which is why the predicate names bool.

    Issue #273 asks whether the sighash types should become an `IntEnum`;
    `type(value) is int` would have answered it in advance, and with a no.

    The path step is the case that has to be *answered* with a number and
    not merely accepted as one: `str()` of an `IntEnum` is its name up to
    Python 3.10, so a derivation path of one would have read
    "Sighash.ALL" there and "1" on every later interpreter -- which the
    3.10 cells of the matrix caught and this assertion now pins.
    """

    class Sighash(IntEnum):
        ALL = 1

    assert is_integer(Sighash.ALL)
    assert valid_sats_amount(Sighash.ALL) == 1
    assert FeeRate(sats_per_kvbyte=Sighash.ALL).sats_per_kvbyte == 1
    assert indexes_from_der_path(Sighash.ALL) == [1]
    assert indexes_from_der_path([Sighash.ALL]) == [1]
    assert str_from_index_int(Sighash.ALL) == "1"
    assert bytes_from_octets(b"x", Sighash.ALL) == b"x"
    assert base58.decode(base58.encode(b"x"), Sighash.ALL) == b"x"
    assert var_int.serialize(Sighash.ALL) == b"\x01"
    assert var_int.parse(b"\x01", max_size=Sighash.ALL) == 1

    assert is_integer(0)
    assert is_integer(-1)
    assert not is_integer(True)
    assert not is_integer(False)
    assert not is_integer(1.0)
    assert not is_integer("1")
    assert not is_integer(None)


def test_the_vendorable_rpc_client_carries_the_same_predicate() -> None:
    """The copy in `btclib.bitcoin_core_rpc` answers what this one answers.

    That file is the one btclib source meant to be copied out of the
    package, so it imports nothing of btclib's and spells the predicate
    again -- which is a second statement of a decision this file exists to
    say there is only one of. Nothing else would notice the two parting
    company: the copy guards a json-rpc parameter and an HTTP body size, and
    a `True` accepted there is a limit of one octet or a parameter the node
    reads as the number one.
    """

    class Sighash(IntEnum):
        ALL = 1

    # an `IntEnum` among them, and it is the value that makes this a test:
    # `type(value) is int` agrees with `is_integer` on everything else here,
    # and is exactly the spelling the test above rules out. A Decimal too,
    # that being what the client decodes a json number into, so it is what
    # most easily reaches the copy
    values: list[Any] = [
        0,
        -1,
        1,
        Sighash.ALL,
        True,
        False,
        1.0,
        "1",
        None,
        Decimal(1),
    ]
    assert [_is_integer(value) for value in values] == [
        is_integer(value) for value in values
    ]
