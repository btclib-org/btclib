#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.amount` module."""

from __future__ import annotations

from decimal import Decimal, FloatOperation, getcontext, localcontext
from threading import Thread

import pytest

from btclib.amount import (
    btc_from_sats,
    sats_from_btc,
    valid_btc_amount,
    valid_sats_amount,
)
from btclib.exceptions import BTClibTypeError, BTClibValueError


def test_conversions() -> None:
    for trap_float_operation in (True, False):
        with localcontext() as ctx:
            ctx.traps[FloatOperation] = trap_float_operation

            assert 1.1 + 2.2 != 3.3
            assert Decimal("1.1") + Decimal("2.2") == Decimal("3.3")

            assert btc_from_sats(10000) == Decimal("0.00010000")
            assert str(btc_from_sats(10000)) != str(Decimal("0.00010000"))
            assert str(btc_from_sats(10000)) == str(Decimal("0.00010000").normalize())

            assert btc_from_sats(10000) == Decimal("0.0001")
            assert str(btc_from_sats(10000)) == str(Decimal("0.0001"))

            assert valid_btc_amount(None) == 0
            assert valid_sats_amount(None) == 0


def test_caller_decimal_context() -> None:
    # importing btclib must not trap FloatOperation process-wide:
    # it would change the Decimal semantics of the unrelated code
    # of the hosting application
    assert not getcontext().traps[FloatOperation]
    # what the trap forbids: building a Decimal from a float,
    # and comparing a Decimal with one
    assert Decimal(1 / 2) == Decimal("0.5")
    assert Decimal("1.1") != 1.1

    for trap_float_operation in (True, False):
        with localcontext() as ctx:
            ctx.traps[FloatOperation] = trap_float_operation
            # the functions trap FloatOperation in a local context,
            # leaving the caller one exactly as it was
            btc_from_sats(sats_from_btc(valid_btc_amount("0.0001")))
            assert getcontext().traps[FloatOperation] == trap_float_operation


def test_other_thread() -> None:
    # getcontext() is thread-local: a thread created elsewhere does not
    # inherit any trap, so the amount functions must not rely on one
    results: list[str] = []

    def worker() -> None:
        assert not getcontext().traps[FloatOperation]
        sats = sats_from_btc(0.0001)  # type: ignore[arg-type]
        results.append(str(btc_from_sats(sats)))
        with pytest.raises(BTClibValueError, match="too many decimals"):
            valid_btc_amount(0.123456789)

    thread = Thread(target=worker)
    thread.start()
    thread.join()
    assert results == ["0.0001"]


def test_exceptions() -> None:
    for trap_float_operation in (True, False):
        with localcontext() as ctx:
            ctx.traps[FloatOperation] = trap_float_operation

            err_msg = "invalid satoshi amount: "
            with pytest.raises(BTClibValueError, match=err_msg):
                btc_from_sats(2_100_000_000_000_001)

            err_msg = "invalid BTC amount: "
            with pytest.raises(BTClibValueError, match=err_msg):
                sats_from_btc(Decimal("21_000_000.00000001"))

            err_msg = "too many decimals for a BTC amount: "
            with pytest.raises(BTClibValueError, match=err_msg):
                sats_from_btc(Decimal("0.123456789"))
            # too many decimals, now with a float
            with pytest.raises(BTClibValueError, match=err_msg):
                valid_btc_amount(0.123456789)

            with pytest.raises(TypeError):
                btc_from_sats(2.5)  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                btc_from_sats(5 / 2)  # type: ignore[arg-type]
            with pytest.raises(ValueError):
                btc_from_sats("2.5")  # type: ignore[arg-type]
            err_msg = "non-integer satoshi amount: "
            with pytest.raises(BTClibTypeError, match=err_msg):
                btc_from_sats(Decimal("2.5"))  # type: ignore[arg-type]


def test_max_money_is_the_consensus_bound() -> None:
    """The bound is MAX_MONEY, inclusive, and not the issued supply.

    Guards against the bound being 2_099_999_997_690_000, what the
    halving schedule actually pays out: 2_310_000 satoshi below
    MoneyRange's bound, and enough to make `Tx.parse` refuse the two
    `MAX_MONEY output` vectors of Bitcoin Core's tx_valid.json
    (issue 167).
    """
    max_money = 2_100_000_000_000_000
    assert valid_sats_amount(max_money) == max_money
    assert valid_btc_amount(Decimal(21_000_000)) == 21_000_000
    assert btc_from_sats(max_money) == 21_000_000
    assert sats_from_btc(Decimal(21_000_000)) == max_money

    # the supply that will be issued is inside the range, not its end
    issued = 2_099_999_997_690_000
    assert valid_sats_amount(issued) == issued
    assert issued < max_money

    with pytest.raises(BTClibValueError, match="invalid satoshi amount: "):
        valid_sats_amount(max_money + 1)
    with pytest.raises(BTClibValueError, match="invalid BTC amount: "):
        valid_btc_amount(Decimal("21_000_000.00000001"))


def test_self_consistency() -> None:
    for trap_float_operation in (True, False):
        with localcontext() as ctx:
            ctx.traps[FloatOperation] = trap_float_operation

            # 8.50390625 = 2177 / pow(2, 8)
            # 8.50390625 * 100_000_000 is 850390625.0
            # 8.50492428 * 100_000_000 is 850492427.9999999
            btc_amounts = [0, 1, 8.50390625, 8.50492428]
            cases: list[int | float | str | Decimal] = []
            for num in btc_amounts:
                cases += [num, float(num), str(num), f"{num:.7E}", Decimal(str(num))]

            for btc_amount in cases:
                exp_btc = Decimal(str(btc_amount)).normalize()
                btc = btc_from_sats(sats_from_btc(btc_amount))  # type: ignore[arg-type]
                assert btc == exp_btc
                assert str(btc) == str(exp_btc)
