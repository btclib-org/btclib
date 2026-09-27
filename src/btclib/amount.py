# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Monetary amounts: satoshi ints and BTC Decimals, never floats.

A BTC amount is an int number of satoshi (1 BTC is 100_000_000) or a
Decimal with up to 8 decimals, e.g. Decimal("0.12345678"). Not a
float: binary floating point cannot hold most decimal fractions
exactly (1.1 + 2.2 != 3.3), so a float between a rate and the satoshi
it owes is a rounding error waiting for money to measure it. The
functions here convert between the two spellings and refuse what no
output can carry.

Amounts are never negative, here as in the protocol.
"""

from __future__ import annotations

import re
import string
from decimal import (
    MAX_EMAX,
    MIN_EMIN,
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    FloatOperation,
    InvalidOperation,
    localcontext,
)
from typing import Any

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import _message_text, is_integer

__all__ = [
    "btc_from_sats",
    "sats_from_btc",
    "valid_btc_amount",
    "valid_sats_amount",
]

# do not import _SATOSHI_PER_BITCOIN and _BITCOIN_PER_SATOSHI
# instead, better use sats_from_btc and btc_from_sats
_SATOSHI_PER_BITCOIN = 100_000_000
_BITCOIN_PER_SATOSHI = Decimal("0.00000001")

# same suggestion for the following variables:
# to check for max amount might be not enough;
# instead, better use sats_from_btc and btc_from_sats
# to ensure a valid amount.
# This is MAX_MONEY, the bound of Bitcoin Core's MoneyRange(), and it is
# inclusive: a transaction with an output of exactly MAX_MONEY passes
# CheckTransaction, and tx_valid.json carries two of them.
# Not 2_099_999_997_690_000, the supply the halving schedule actually
# issues -- 2_310_000 satoshi less, what the subsidy loses to integer
# division on its way down: that is a fact about issuance and not a
# validity rule, an amount above it being unfundable rather than
# invalid, and bounding by it would make btclib refuse to so much as
# parse two transactions the network considers valid (issue 167)
# twenty-one million is written once and converted the way every other
# amount in this module is, `sats_from_btc` below being that same
# expression: two spellings of one bound can be edited apart, and the
# paragraph above belongs to both of them
_MAX_BITCOIN = Decimal(21_000_000)
_MAX_SATOSHI = int(_MAX_BITCOIN * _SATOSHI_PER_BITCOIN)

# The context this module's Decimal arithmetic runs in, and
# FeeRate.from_btc_per_kvbyte's rounding with it: built here rather than
# copied from the caller's, whose precision and traps are the
# application's and would otherwise decide what an amount is: a lower
# precision makes quantize signal InvalidOperation on an amount in range
# and rounds a product silently, and a trapped Inexact makes the
# rounding round_up exists for raise. Set on a local context, never on
# the process-wide one, which would change the Decimal semantics of any
# application merely importing btclib, and which is thread-local anyway.
#
# The precision is what an amount in range needs to be exact. The range
# runs from a dust threshold to MAX_MONEY, and the threshold is itself
# refused outside zero to MAX_MONEY, so an amount in range is at most
# _MAX_SATOSHI satoshi in magnitude: a quantize to one satoshi, a
# product by _SATOSHI_PER_BITCOIN and a product of a satoshi count by
# _BITCOIN_PER_SATOSHI all have a value of at most as many significant
# digits as _MAX_SATOSHI. What needs more is out of range:
# valid_btc_amount, sats_from_btc and btc_from_sats refuse it before
# the operation, and from_btc_per_kvbyte's rounding, which runs ahead of
# any range check, turns the InvalidOperation its quantize signals into
# a refusal of its own. The exponent limits are the widest there are, and
# every field is spelled out, since one left unset is copied from the
# process-wide DefaultContext. FloatOperation is trapped so that no
# float reaches the arithmetic unnoticed, InvalidOperation so that the
# signal is a raise and not a NaN; Inexact is not, a rounding being
# round_up's whole purpose
_CONTEXT = Context(
    prec=len(str(_MAX_SATOSHI)),
    rounding=ROUND_HALF_EVEN,
    Emin=MIN_EMIN,
    Emax=MAX_EMAX,
    capitals=1,
    clamp=0,
    flags=[],
    traps=[FloatOperation, InvalidOperation],
)


# Bitcoin Core's `ParseFixedPoint` grammar: an optional "-", then a lone
# 0 or a digit string not starting with 0, then optionally "." and at
# least one digit, then optionally an exponent of at least one digit.
# `[0-9]` is ASCII in `re` whatever the flags
_FIXED_POINT = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


def _number_text(text: str, err_msg: str) -> str:
    """Return the text of a number stripped of ASCII whitespace, or refuse it.

    `int` and `Decimal` read every Unicode decimal digit, so U+0661
    U+0660 (ARABIC-INDIC ONE, ZERO) and U+FF11 U+FF10 (FULLWIDTH ONE,
    ZERO) are ten to both. Both strip what `str.isspace` counts, `int`
    all of it but U+001C to U+001F and `Decimal` all of it. Both read the
    digit-grouping underscore of Python's number literals, so "1_0" is
    ten too, and both read a leading "+" and "01". `Decimal` also reads
    ".5" and "1.". None of that is how anybody writes an amount, and each
    is a second spelling of one.

    What is left once `string.whitespace` is stripped has to be spelled
    as Bitcoin Core's `ParseFixedPoint` spells a number. That is the
    parser `AmountFromValue` reads an RPC amount through, and it is why
    the exponent form, "1e1" and "1e+1", stays an amount. The six
    characters stripped are the ones Core's `ParseMoney` strips. The
    grammar of `ParseFixedPoint` is taken and its bounds on the mantissa
    and the exponent are not.
    """
    text = text.strip(string.whitespace)
    if not _FIXED_POINT.fullmatch(text):
        raise BTClibValueError(err_msg)
    return text


def _decimal_from_value(value: object, err_msg: str) -> Decimal:
    """Return the finite Decimal the text of a value spells, or refuse it.

    The text is `str(value)`, which raises ValueError for an int past
    `sys.get_int_max_str_digits()` digits and for what is written with
    one, a Fraction for one, and which a `__str__` of the caller's own
    can make raise anything: refused as what it is, a value that is no
    amount, rather than let out as that error. Every Exception, for the
    reason `utils._message_text` catches every one.

    The grammar `_number_text` holds the text to spells no NaN and no
    infinity, but it does spell an exponent past what `Decimal` can hold
    ("1e" and thirty nines). `Decimal` signals InvalidOperation on that,
    which `_CONTEXT` traps, so the refusal is this library's whatever the
    caller's context does with the signal.
    """
    try:
        text = str(value)
    except Exception as e:
        raise BTClibValueError(err_msg) from e
    text = _number_text(text, err_msg)
    with localcontext(_CONTEXT):
        try:
            return Decimal(text)
        except InvalidOperation as e:
            raise BTClibValueError(err_msg) from e


def valid_btc_amount(amount: Any, dust: Decimal = Decimal(0)) -> Decimal:
    """Return the BTC amount as a Decimal, refusing what no output holds.

    None reads as zero, and anything str() renders as a decimal number
    in ASCII is accepted. Refused: an amount below `dust` or above the 21
    million cap, and one with more than 8 decimals, no output being
    able to carry a fraction of a satoshi. `dust` is an amount too, so
    one that is not finite, is negative or is above the cap is refused.
    """
    # dust is compared against the parsed amount inside the FloatOperation
    # trap _CONTEXT sets, so a float dust trips that trap and leaks a bare
    # decimal.FloatOperation instead of this library's own exception
    # contract. It is type-checked here, by name and not by attempting a
    # conversion, the same way valid_sats_amount type-checks its own dust
    # threshold
    if not isinstance(dust, Decimal):
        err_msg = f"non-Decimal BTC dust threshold: {_message_text(dust)}"  # type: ignore[unreachable]
        raise BTClibTypeError(err_msg)
    # a threshold is an amount, and bounding it is what bounds the range
    # below to amounts _CONTEXT holds exactly: a negative one would admit
    # a negative amount of any magnitude. is_finite goes first, a NaN
    # signalling InvalidOperation on the comparisons after it
    if not (dust.is_finite() and 0 <= dust <= _MAX_BITCOIN):
        raise BTClibValueError("invalid BTC dust threshold")
    # an int is bounded as an int, before str() reads it: str() of one
    # past 4300 digits raises ValueError, and every int it would refuse
    # for that is out of range
    if isinstance(amount, int) and not 0 <= amount <= int(_MAX_BITCOIN):
        raise BTClibValueError(f"invalid BTC amount: {_message_text(amount)}")
    with localcontext(_CONTEXT):
        # any input str() writes is read through its text
        amount = "0" if amount is None else amount
        err_msg = f"invalid BTC amount: {_message_text(amount)}"
        # reading the Decimal through str avoids the FloatOperation
        # exception _CONTEXT traps; what comes back is finite, so the
        # range check below compares finite values
        btc = _decimal_from_value(amount, err_msg)
        if not dust <= btc <= _MAX_BITCOIN:
            raise BTClibValueError(err_msg)
        # in range, so the quantize is exact at _CONTEXT's precision
        if btc == btc.quantize(_BITCOIN_PER_SATOSHI):
            # a signed zero ("-0", "-0.00000000") compares equal to zero
            # and passes every check above unchanged; copy_abs clears its
            # sign, reading no context, and every other value is returned
            # exactly as parsed, exponent included
            return btc.copy_abs() if btc.is_zero() else btc
        err_msg = f"too many decimals for a BTC amount: {_message_text(amount)}"
        raise BTClibValueError(err_msg)


def sats_from_btc(amount: Decimal) -> int:
    """Return the satoshi equivalent of the provided BTC amount."""
    btc = valid_btc_amount(amount)
    with localcontext(_CONTEXT):
        return int(btc * _SATOSHI_PER_BITCOIN)


def valid_sats_amount(amount: Any, dust: int = 0) -> int:
    """Return the satoshi amount as int, if valid and not less than dust.

    `dust` is an amount too, so one that is negative or is above the cap
    is refused.
    """
    # a bool is an int in Python, so True reached the conversion below as
    # the number one and `int(True) == True` let it through the equality
    # check as well: refused by name, for the reason is_integer gives --
    # and by name because this argument is Any, so a str and a Decimal are
    # legitimate here and the predicate cannot be the gate
    if isinstance(amount, bool):
        raise BTClibTypeError(f"non-integer satoshi amount: {amount}")
    # and the threshold it is compared against: a bool passes the
    # comparison below as zero or one, so `dust=True` is a dust level of
    # one satoshi rather than a caller error
    if not is_integer(dust):
        err_msg = f"non-integer satoshi dust threshold: {_message_text(dust)}"
        raise BTClibTypeError(err_msg)
    # bounded as valid_btc_amount bounds its own, so that the two keep one
    # contract; the message quotes no value, an int past 4300 digits
    # being one str() refuses
    if not 0 <= dust <= _MAX_SATOSHI:
        raise BTClibValueError("invalid satoshi dust threshold")
    text = amount
    if isinstance(amount, str):
        text = _number_text(amount, f"invalid satoshi amount: {amount}")
    # any input that can be converted to int is fine -- and int() refuses
    # what it cannot convert with a bare ValueError ("abc", b"\x01"), a
    # bare TypeError (a list), or a bare OverflowError (an infinity, where
    # a NaN is a ValueError: the asymmetry is int()'s, not this
    # function's). None of the three says that btclib refused anything,
    # and OverflowError is not even a ValueError -- it is an
    # ArithmeticError, so a caller catching ValueError never caught it.
    # Each is answered with this library's counterpart of the builtin it
    # was, so what a caller catches does not shrink
    try:
        sats = 0 if amount is None else int(text)
    except (ValueError, OverflowError) as e:
        err_msg = f"invalid satoshi amount: {_message_text(amount)}"
        raise BTClibValueError(err_msg) from e
    except TypeError as e:
        err_msg = f"non-integer satoshi amount: {_message_text(amount)}"
        raise BTClibTypeError(err_msg) from e
    # sats != amount is what catches the truncation int() performs
    # silently on a float or a Decimal fraction (int(2.5) == 2, so
    # 2 != 2.5 fires); it cannot fire that way on a str, since int()
    # only ever parses a string that already spells a bare integer, no
    # fraction surviving to be truncated -- and an int compares unequal
    # to every str regardless of value, which is what refused every
    # numeric string despite the comment above admitting one. A str is
    # exempted from the check rather than compared under it
    if amount is not None and not isinstance(amount, str) and sats != amount:
        err_msg = f"non-integer satoshi amount: {_message_text(amount)}"
        raise BTClibTypeError(err_msg)
    if not dust <= sats <= _MAX_SATOSHI:
        raise BTClibValueError(f"invalid satoshi amount: {_message_text(amount)}")
    return sats


def btc_from_sats(amount: int) -> Decimal:
    """Return the BTC Decimal equivalent of the provided satoshi amount."""
    sats = valid_sats_amount(amount)
    with localcontext(_CONTEXT):
        # normalize() strips the rightmost trailing zeros
        # and produces canonical values for attributes of an equivalence class
        return (sats * _BITCOIN_PER_SATOSHI).normalize()
