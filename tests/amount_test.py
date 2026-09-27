# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.amount` module."""

from __future__ import annotations

import string
from decimal import (
    Decimal,
    FloatOperation,
    Inexact,
    InvalidOperation,
    getcontext,
    localcontext,
)
from fractions import Fraction
from threading import Thread

import pytest
from typing_extensions import override

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


def test_a_numeric_string_is_accepted_as_the_comment_admits() -> None:
    """A str is a type the function's own comment calls legitimate.

    The equality check used to refuse every one of them regardless of
    value -- `int("10") != "10"` -- where a float of the same value
    passes.
    """
    assert valid_sats_amount("10") == 10
    assert valid_sats_amount("0") == 0
    assert valid_sats_amount("10", dust=10) == 10
    with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
        # exempting str from the equality check does not widen what
        # int() itself parses: a fractional string is still refused,
        # now by the constructor rather than by the equality check
        valid_sats_amount("10.5")


def test_a_sats_amount_string_refuses_digit_grouping_underscores() -> None:
    """`int(str)` accepts Python's own digit-grouping underscore too.

    Exempting `str` from the equality check (above) removed the
    incidental protection that check gave against `"1_0"`, which `int()`
    itself parses as ten -- not a value anybody actually wrote.
    """
    with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
        valid_sats_amount("1_0")
    with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
        valid_sats_amount("1_000_000")


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


def test_a_float_btc_dust_threshold_is_refused_in_kind() -> None:
    """A float dust used to leak `decimal.FloatOperation` past this contract.

    It is compared against the parsed amount inside the trap this
    function itself sets. `valid_sats_amount` already type-checks its own
    dust threshold; this is the same check.
    """
    with pytest.raises(BTClibTypeError, match="non-Decimal BTC dust threshold"):
        valid_btc_amount("1", dust=0.5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="non-Decimal BTC dust threshold"):
        valid_btc_amount("1", dust=1)  # type: ignore[arg-type]
    assert valid_btc_amount("1", dust=Decimal("0.5")) == 1


def test_a_btc_amount_string_refuses_digit_grouping_underscores() -> None:
    """`Decimal(str)` accepts Python's own digit-grouping underscore.

    `"1_0"` would silently read as ten BTC rather than being refused the
    way `"1,2"` already is.
    """
    with pytest.raises(BTClibValueError, match="invalid BTC amount"):
        valid_btc_amount("1_0")
    with pytest.raises(BTClibValueError, match="invalid BTC amount"):
        valid_btc_amount("1_000_000")


@pytest.mark.parametrize("amount", ["-0", "-0.00000000", "-0.0"])
def test_a_negative_zero_btc_amount_normalizes_the_sign(amount: str) -> None:
    """`Decimal("-0")` compares equal to zero and passes every check unchanged.

    It carries its sign straight through to the return value unless the
    sign is cleared on the way out.
    """
    btc = valid_btc_amount(amount)
    assert btc == 0
    assert not btc.is_signed()


# what str.strip() with no argument also takes and Bitcoin Core's IsSpace
# does not: NO-BREAK SPACE, IDEOGRAPHIC SPACE, LINE SEPARATOR, and two of
# the control characters str.isspace counts
_NON_CORE_SPACES = [chr(c) for c in (0xA0, 0x3000, 0x2028, 0x1C, 0x85)]
# ten in ARABIC-INDIC and in FULLWIDTH digits, both of which int and
# Decimal read as ten
_NON_ASCII_TENS = [chr(0x661) + chr(0x660), chr(0xFF11) + chr(0xFF10)]


@pytest.mark.parametrize("pad", _NON_CORE_SPACES)
def test_only_ascii_whitespace_is_stripped_from_an_amount(pad: str) -> None:
    """ASCII whitespace around an amount is trimmed, and nothing else is."""
    ws = string.whitespace
    assert valid_btc_amount(f"{ws}10{ws}") == 10
    assert valid_sats_amount(f"{ws}10{ws}") == 10

    with pytest.raises(BTClibValueError, match="invalid BTC amount"):
        valid_btc_amount(f"{pad}10{pad}")
    with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
        valid_sats_amount(f"{pad}10{pad}")


@pytest.mark.parametrize("ten", _NON_ASCII_TENS)
def test_an_amount_is_read_in_ascii_digits_alone(ten: str) -> None:
    """Digits outside ASCII are refused, as both of Core's amount parsers do."""
    with pytest.raises(BTClibValueError, match="invalid BTC amount"):
        valid_btc_amount(ten)
    with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
        valid_sats_amount(ten)


def test_the_exponent_form_is_a_btc_amount() -> None:
    """Core's `ParseFixedPoint` reads "1e1", and so does this."""
    assert valid_btc_amount("1e1") == 10
    assert valid_btc_amount("1E-8") == Decimal("0.00000001")
    assert sats_from_btc("1e-8") == 1  # type: ignore[arg-type]


@pytest.mark.parametrize("amount", ["+1", "+0", " +1", "+1e1", "+-1"])
def test_an_amount_refuses_a_leading_plus(amount: str) -> None:
    """Neither `ParseMoney` nor `ParseFixedPoint` reads a leading "+"."""
    with pytest.raises(BTClibValueError, match="invalid BTC amount"):
        valid_btc_amount(amount)
    with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
        valid_sats_amount(amount)


def test_the_exponent_keeps_its_plus() -> None:
    """`ParseFixedPoint` reads "1e+1", and `str(Decimal)` writes "1E+1"."""
    assert valid_btc_amount("1e+1") == 10
    assert valid_btc_amount(Decimal("1E+1")) == 10
    assert str(Decimal("1E+1")) == "1E+1"


# what Decimal, and for "01" and "00" int too, reads and Bitcoin Core's
# ParseFixedPoint refuses: a leading zero before another digit, and a
# point without a digit on both sides of it
_NOT_FIXED_POINT = ["01", "00", ".5", "1.", ".5e1", "01e1", "-01", "-.5"]
# a huge exponent ParseFixedPoint's grammar spells and Decimal cannot hold
_PAST_DECIMAL = "1e" + "9" * 30


@pytest.mark.parametrize("amount", _NOT_FIXED_POINT)
def test_an_amount_is_spelled_as_parse_fixed_point_spells_it(amount: str) -> None:
    """`ParseFixedPoint` is the parser Core reads an RPC amount through."""
    with pytest.raises(BTClibValueError, match="invalid BTC amount"):
        valid_btc_amount(amount)
    with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
        valid_sats_amount(amount)


@pytest.mark.parametrize(
    "amount, btc",
    [
        ("0", 0),
        ("-0", 0),
        ("0.5", Decimal("0.5")),
        ("0e1", 0),
        ("1e1", 10),
        ("1e+1", 10),
        ("1E-8", Decimal("0.00000001")),
    ],
)
def test_what_parse_fixed_point_reads_is_a_btc_amount(
    amount: str, btc: Decimal
) -> None:
    """A lone 0 before a point or an exponent, and a signed zero, are read."""
    assert valid_btc_amount(amount) == btc


def test_a_lone_zero_is_a_sats_amount() -> None:
    """`ParseFixedPoint` reads "0" and "-0", and `int` reads both as 0."""
    assert valid_sats_amount("0") == 0
    assert valid_sats_amount("-0") == 0


@pytest.mark.parametrize("trap", [True, False])
def test_an_exponent_decimal_cannot_hold_is_refused_in_kind(trap: bool) -> None:
    """The grammar spells it and `Decimal` signals InvalidOperation on it.

    Untrapped by the caller's context, the signal is a NaN rather than a
    raise, and the refusal is the same either way.
    """
    with localcontext() as ctx:
        ctx.traps[InvalidOperation] = trap
        with pytest.raises(BTClibValueError, match="invalid BTC amount"):
            valid_btc_amount(_PAST_DECIMAL)


# the reproductions of issue #2387: a caller's context decides nothing
@pytest.mark.parametrize("trap", [True, False])
def test_a_low_precision_changes_no_amount(trap: bool) -> None:
    """At ten digits an amount near the cap is past the quantize's reach.

    Trapped, the quantize raised a bare InvalidOperation; untrapped, it
    gave a NaN and an amount of one decimal was refused as having too
    many; and the product in `btc_from_sats` rounded to ten digits.
    """
    with localcontext() as ctx:
        ctx.prec = 10
        ctx.traps[InvalidOperation] = trap
        assert valid_btc_amount("20999999.5") == Decimal("20999999.5")
        assert sats_from_btc(Decimal("20999999.12345678")) == 2_099_999_912_345_678
        assert btc_from_sats(2_099_999_912_345_678) == Decimal("20999999.12345678")
        assert btc_from_sats(2_100_000_000_000_000) == 21_000_000
        with pytest.raises(BTClibValueError, match="too many decimals"):
            valid_btc_amount("20999999.123456789")


def test_a_trapped_inexact_changes_no_amount() -> None:
    """No amount in range is rounded, so `Inexact` is never signalled."""
    with localcontext() as ctx:
        ctx.traps[Inexact] = True
        assert sats_from_btc(Decimal("20999999.12345678")) == 2_099_999_912_345_678
        assert btc_from_sats(1) == Decimal("0.00000001")


def test_a_long_spelling_is_returned_as_parsed() -> None:
    """The sign of a zero is cleared without rounding to any precision."""
    spelled = "1." + "0" * 40
    assert str(valid_btc_amount(spelled)) == spelled
    assert str(valid_btc_amount("-0.00000000")) == "0E-8"


# the review's cases for issue #2387: a dust threshold is an amount, and
# a negative one admitted amounts _CONTEXT's precision cannot quantize
@pytest.mark.parametrize(
    "amount, dust",
    [
        ("-100000000", Decimal("-1e9")),
        ("-1000000000000", Decimal("-1e20")),
        ("-50000000", Decimal("-1e9")),
        ("1", Decimal("NaN")),
        ("1", Decimal("sNaN")),
        ("1", Decimal("Infinity")),
        ("1", Decimal("-0.00000001")),
        ("1", Decimal("21000000.00000001")),
    ],
)
def test_a_btc_dust_threshold_is_an_amount(amount: str, dust: Decimal) -> None:
    """Not finite, negative or above the cap, it is refused in kind."""
    with pytest.raises(BTClibValueError, match="invalid BTC dust threshold"):
        valid_btc_amount(amount, dust=dust)


@pytest.mark.parametrize(
    "dust",
    [
        -1,
        -(10**9),
        2_100_000_000_000_001,
        pytest.param(10**5000, id="10**5000"),
    ],
)
def test_a_sats_dust_threshold_is_an_amount(dust: int) -> None:
    """Negative or above the cap, it is refused, and the message quotes none."""
    with pytest.raises(BTClibValueError, match="invalid satoshi dust threshold$"):
        valid_sats_amount(-5, dust=dust)


def test_a_dust_threshold_at_either_end_is_an_amount() -> None:
    """Zero and the cap are thresholds, the cap admitting the cap alone."""
    assert valid_btc_amount("0", dust=Decimal(0)) == 0
    assert valid_btc_amount("-0", dust=Decimal("-0")) == 0
    assert valid_btc_amount("21000000", dust=Decimal(21_000_000)) == 21_000_000
    assert valid_sats_amount(0, dust=0) == 0
    assert valid_sats_amount(2_100_000_000_000_000, dust=2_100_000_000_000_000) > 0


# an int str() refuses to write, past 4300 digits (issue #2389)
_TOO_LONG_TO_WRITE = 10**5000


@pytest.mark.parametrize(
    "sign", [pytest.param(1, id="positive"), pytest.param(-1, id="negative")]
)
def test_an_int_too_long_to_write_is_refused_in_kind(sign: int) -> None:
    """Refused as an amount, described by its bit length and not its digits."""
    value = sign * _TOO_LONG_TO_WRITE
    with pytest.raises(BTClibValueError, match=r"invalid BTC amount: .*16610 bits$"):
        valid_btc_amount(value)
    with pytest.raises(BTClibValueError, match=r"invalid BTC amount: .*16610 bits$"):
        sats_from_btc(value)  # type: ignore[arg-type]
    match = r"invalid satoshi amount: .*16610 bits$"
    with pytest.raises(BTClibValueError, match=match):
        valid_sats_amount(value)
    with pytest.raises(BTClibValueError, match=match):
        btc_from_sats(value)


def test_an_int_amount_in_range_still_reads() -> None:
    """The int bound runs ahead of `str()` and admits every int in range."""
    assert valid_btc_amount(21_000_000) == 21_000_000
    assert valid_btc_amount(0) == 0
    with pytest.raises(BTClibValueError, match="invalid BTC amount: 21000001$"):
        valid_btc_amount(21_000_001)
    with pytest.raises(BTClibValueError, match="invalid BTC amount: -1$"):
        valid_btc_amount(-1)


# a Fraction str() refuses to write, whether the numerator or the
# denominator is past 4300 digits (issue #2389)
_UNWRITABLE_FRACTIONS = [
    pytest.param(Fraction(_TOO_LONG_TO_WRITE), id="+big"),
    pytest.param(Fraction(-_TOO_LONG_TO_WRITE), id="-big"),
    pytest.param(Fraction(1, _TOO_LONG_TO_WRITE), id="+1/big"),
    pytest.param(Fraction(-1, _TOO_LONG_TO_WRITE), id="-1/big"),
]


@pytest.mark.parametrize("value", _UNWRITABLE_FRACTIONS)
def test_a_value_str_cannot_write_is_refused_in_kind(value: Fraction) -> None:
    """Every amount refusal names its type where `str()` raises on it."""
    unwritable = r"a Fraction str\(\) cannot write$"
    with pytest.raises(BTClibValueError, match=f"invalid BTC amount: {unwritable}"):
        valid_btc_amount(value)
    with pytest.raises(BTClibValueError, match=f"invalid BTC amount: {unwritable}"):
        sats_from_btc(value)  # type: ignore[arg-type]
    match = f"non-Decimal BTC dust threshold: {unwritable}"
    with pytest.raises(BTClibTypeError, match=match):
        valid_btc_amount("1", dust=value)  # type: ignore[arg-type]
    match = f"non-integer satoshi dust threshold: {unwritable}"
    with pytest.raises(BTClibTypeError, match=match):
        valid_sats_amount(1, dust=value)  # type: ignore[arg-type]
    # a whole Fraction is an amount out of range, and a fraction of one
    # a non-integer amount
    match = f"(invalid|non-integer) satoshi amount: {unwritable}"
    with pytest.raises((BTClibValueError, BTClibTypeError), match=match):
        valid_sats_amount(value)
    with pytest.raises((BTClibValueError, BTClibTypeError), match=match):
        btc_from_sats(value)  # type: ignore[arg-type]


class _Unwritable:
    @override
    def __str__(self) -> str:
        raise RuntimeError


def test_a_value_whose_str_raises_is_refused_in_kind() -> None:
    """A caller's own `__str__` raising anything is this library's refusal."""
    unwritable = r"a _Unwritable str\(\) cannot write$"
    with pytest.raises(BTClibValueError, match=f"invalid BTC amount: {unwritable}"):
        valid_btc_amount(_Unwritable())
    with pytest.raises(BTClibValueError, match=f"invalid BTC amount: {unwritable}"):
        sats_from_btc(_Unwritable())  # type: ignore[arg-type]
    match = f"non-integer satoshi amount: {unwritable}"
    with pytest.raises(BTClibTypeError, match=match):
        valid_sats_amount(_Unwritable())


class _UncomparableInt(int):
    @override
    def __le__(self, other: object) -> bool:
        raise RuntimeError

    @override
    def __ge__(self, other: object) -> bool:
        raise RuntimeError


def test_an_int_is_bounded_through_int_s_own_comparison() -> None:
    """A subclass overriding the comparison is refused as an amount.

    The bound runs ahead of `str()`, and a comparison of the subclass's
    own raising would leave as that error instead (issue #2394).
    """
    # the overrides do raise, so a bound reaching them would too
    with pytest.raises(RuntimeError):
        _ = _UncomparableInt(1) <= 2
    with pytest.raises(RuntimeError):
        _ = _UncomparableInt(1) >= 0
    for value in (_TOO_LONG_TO_WRITE, -_TOO_LONG_TO_WRITE, 21_000_001):
        with pytest.raises(BTClibValueError, match="invalid BTC amount: "):
            valid_btc_amount(_UncomparableInt(value))
