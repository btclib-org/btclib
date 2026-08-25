# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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
    """Round-trip sats to BTC under both FloatOperation trap settings."""
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
    """Check the caller's Decimal context survives the amount functions."""
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
    """Verify the conversions need no trap set in the calling thread."""
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
    """Verify the errors for overflow, excess decimals and wrong types."""
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
    """Round-trip BTC amounts through sats for every accepted input type."""
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


@pytest.mark.parametrize(
    "amount",
    ["abc", "1,2", "", "0x10", object(), "nan", "sNaN", "-nan", "inf", "-Infinity"],
)
def test_what_is_no_decimal_number_is_refused_as_btclib_refuses_things(
    amount: object,
) -> None:
    """The exception is this library's, not the decimal module's.

    `str()` renders every object there is and `Decimal` refuses most of
    what it renders with an `InvalidOperation` -- an `ArithmeticError`,
    which `except BTClibValueError` does not catch and nobody writes
    `except ArithmeticError` around an amount. The argument is `Any` on
    purpose, so this is reachable from ordinary input rather than from
    something exotic.
    """
    with pytest.raises(BTClibValueError, match="invalid BTC amount"):
        valid_btc_amount(amount)


def test_a_nan_does_not_leave_through_the_range_check() -> None:
    """The NaNs are why `is_finite` is there and a `try` is not enough.

    `Decimal("nan")` is valid syntax and constructs without a word: the
    *comparison* in the range check is what raises `InvalidOperation`,
    so catching the constructor alone would leave every spelling of a
    NaN leaking an ArithmeticError out of a validator.
    """
    for nan in (float("nan"), "nan", "sNaN", Decimal("NaN")):
        with pytest.raises(BTClibValueError, match="invalid BTC amount"):
            valid_btc_amount(nan)

    # an infinity does compare, so the range check is what refuses it,
    # and that is the line the NaNs never reach
    for infinity in (float("inf"), "-inf", Decimal("Infinity")):
        with pytest.raises(BTClibValueError, match="invalid BTC amount"):
            valid_btc_amount(infinity)


def test_a_satoshi_amount_that_int_refuses_is_refused_in_kind() -> None:
    """int()'s bare ValueError and TypeError become this library's own.

    Each maps to btclib's counterpart of the very builtin it was --
    BTClibValueError derives from ValueError, BTClibTypeError from
    TypeError -- so a caller catching either of the builtins catches
    exactly what it caught before, and one catching btclib's now sees
    these too.
    """
    for amount in ("abc", "", b"\x01", "1,2"):
        with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
            valid_sats_amount(amount)

    for other in ([], {}, object()):
        with pytest.raises(BTClibTypeError, match="non-integer satoshi amount"):
            valid_sats_amount(other)


@pytest.mark.parametrize("amount", [1.5, -1.5, Decimal("2.5"), Decimal("-2.5")])
def test_a_fraction_of_a_satoshi_is_refused_at_either_sign(amount: object) -> None:
    """A negative fraction is refused as a non-integer, not as a range.

    `int()` truncates towards zero, so the truncation is *below* a
    positive amount and *above* a negative one. A check that the
    truncation changed the value therefore has to be an inequality and
    not a comparison: at -1.5 the truncation is -1, which is greater, and
    an ordering test lets it through to the range check below -- where it
    is still refused, but as an invalid amount rather than as a
    non-integer one. Which exception a caller catches is the distinction
    this function's own comment is about.
    """
    with pytest.raises(BTClibTypeError, match="non-integer satoshi amount"):
        valid_sats_amount(amount)


@pytest.mark.parametrize(
    "amount",
    [float("inf"), float("-inf"), Decimal("Infinity"), Decimal("-Infinity")],
)
def test_a_non_finite_satoshi_amount_is_refused_in_kind(amount: object) -> None:
    """An infinity leaves int() as an OverflowError, which is no ValueError.

    It is an ArithmeticError, like the InvalidOperation of the BTC
    validator: a caller catching ValueError around a satoshi amount never
    caught it. A NaN is a ValueError out of the same call, which is int()'s
    asymmetry rather than this function's, and both answer the same way
    now.
    """
    with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
        valid_sats_amount(amount)

    for nan in (float("nan"), Decimal("NaN")):
        with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
            valid_sats_amount(nan)
