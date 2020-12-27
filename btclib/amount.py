#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Proper handling of monetary amounts.

A BTC monetary amount can be expressed
as number of satoshis (1 BTC is 100_000_000) or
as Python Decimal with up to 8 digits, e.g. Decimal("0.12345678").

Because of floating-point conversion issues
(e.g. with floats 1.1 + 2.2 != 3.3)
algebra with bitcoin amounts should never involve floats.

The provided functions handle conversion between
satoshi amounts (sats) and Decimal/float values.
"""

import decimal
from typing import Any

from btclib.exceptions import BTClibValueError

BITCOIN_PER_SATOSHI = decimal.Decimal("0.00000001")
SATOSHI_PER_BITCOIN = 100_000_000

MAX_BITCOIN = decimal.Decimal("20_999_999.9769")
MAX_SATOSHI = 2_099_999_997_690_000

decimal.getcontext().traps[decimal.FloatOperation] = True


def sats_from_btc(amount: Any) -> int:
    "Return the satoshi equivalent of the provided BTC amount."
    # any input that can be converted to str is fine
    amount = str(amount)
    # using str avoids the decimal.FloatOperation exception
    btc = decimal.Decimal(amount)
    if abs(btc) > MAX_BITCOIN:
        raise BTClibValueError(f"invalid btc amount: {amount}")
    sats = btc * SATOSHI_PER_BITCOIN
    if int(sats) == round(sats):
        return int(sats)
    raise BTClibValueError(f"too many decimals for a BTC amount: {amount}")


def btc_from_sats(sats: int) -> decimal.Decimal:
    "Return the BTC Decimal equivalent of the provided satoshi amount."
    if abs(sats) > MAX_SATOSHI:
        raise BTClibValueError(f"invalid number of satoshis: {sats}")
    # normalize() strips the rightmost trailing zeros
    # and produces canonical values for attributes of an equivalence class
    return (sats * BITCOIN_PER_SATOSHI).normalize()
