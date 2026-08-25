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

from decimal import Decimal, FloatOperation, InvalidOperation, localcontext
from typing import Any

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import is_integer

__all__ = [
    "btc_from_sats",
    "sats_from_btc",
    "valid_btc_amount",
    "valid_sats_amount",
]

# The two functions below doing Decimal algebra trap FloatOperation in a
# local context, not in the process-wide one at import time:
# getcontext().traps[FloatOperation] = True would change the Decimal
# semantics of the unrelated code of any application merely importing
# btclib; moreover, the current context is thread-local, so the trap the
# functions rely on would be absent in any thread created elsewhere.

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


def valid_btc_amount(amount: Any, dust: Decimal = Decimal(0)) -> Decimal:
    """Return the BTC amount as a Decimal, refusing what no output holds.

    None reads as zero, and anything str() renders as a decimal number
    is accepted. Refused: an amount below `dust` or above the 21
    million cap, and one with more than 8 decimals, no output being
    able to carry a fraction of a satoshi.
    """
    with localcontext() as ctx:
        ctx.traps[FloatOperation] = True
        # any input that can be converted to str is fine
        amount = "0" if amount is None else str(amount)
        err_msg = f"invalid BTC amount: {amount}"
        # using str in the Decimal constructor avoids the
        # FloatOperation exception trapped just above.
        #
        # str() renders every object there is and Decimal refuses most of
        # what it renders with an InvalidOperation -- an ArithmeticError,
        # which nobody catches around an amount and which `except
        # BTClibValueError` does not catch either. Accepting Any is what
        # makes it reachable from ordinary input, "1,2" being how half the
        # world writes a decimal, so the width of the argument has to be
        # matched by one exception of this library's:
        # FeeRate.from_sats_per_vbyte answers the same way
        try:
            btc = Decimal(amount)
        except InvalidOperation as e:
            raise BTClibValueError(err_msg) from e
        # a NaN parses and is no amount, and the range check below is not
        # what refuses it: an ordering comparison against a NaN raises
        # InvalidOperation of its own, so "nan" would leave through the
        # very line meant to bound it. An infinity does compare, and the
        # range refuses it there
        if not btc.is_finite():
            raise BTClibValueError(err_msg)
        if not dust <= btc <= _MAX_BITCOIN:
            raise BTClibValueError(err_msg)
        if btc == btc.quantize(_BITCOIN_PER_SATOSHI):
            return btc
        raise BTClibValueError(f"too many decimals for a BTC amount: {amount}")


def sats_from_btc(amount: Decimal) -> int:
    """Return the satoshi equivalent of the provided BTC amount."""
    btc = valid_btc_amount(amount)
    return int(btc * _SATOSHI_PER_BITCOIN)


def valid_sats_amount(amount: Any, dust: int = 0) -> int:
    """Return the satoshi amount as int, if valid and not less than dust."""
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
        raise BTClibTypeError(f"non-integer satoshi dust threshold: {dust}")
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
        sats = 0 if amount is None else int(amount)
    except (ValueError, OverflowError) as e:
        raise BTClibValueError(f"invalid satoshi amount: {amount}") from e
    except TypeError as e:
        raise BTClibTypeError(f"non-integer satoshi amount: {amount}") from e
    if amount is not None and sats != amount:
        raise BTClibTypeError(f"non-integer satoshi amount: {amount}")
    if not dust <= sats <= _MAX_SATOSHI:
        raise BTClibValueError(f"invalid satoshi amount: {amount}")
    return sats


def btc_from_sats(amount: int) -> Decimal:
    """Return the BTC Decimal equivalent of the provided satoshi amount."""
    sats = valid_sats_amount(amount)
    with localcontext() as ctx:
        ctx.traps[FloatOperation] = True
        # normalize() strips the rightmost trailing zeros
        # and produces canonical values for attributes of an equivalence class
        return (sats * _BITCOIN_PER_SATOSHI).normalize()
