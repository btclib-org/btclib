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

from decimal import Decimal, FloatOperation, getcontext
from typing import Union

from btclib.exceptions import BTClibValueError

BITCOIN_PER_SATOSHI = Decimal("0.00000001")
SATOSHI_PER_BITCOIN = 100_000_000

MAX_BITCOIN = Decimal("20_999_999.97690000")
MAX_SATOSHI = 2_099_999_997_690_000

getcontext().traps[FloatOperation] = True


def sats_from_btc(amount: Union[float, Decimal]) -> int:
    "Return the satoshi equivalent of the provided BTC amount."
    btc = Decimal(str(amount))
    if btc > MAX_BITCOIN:
        raise BTClibValueError(f"btc amount is too big: {amount}")
    sats = btc * SATOSHI_PER_BITCOIN
    if int(sats) == round(sats):
        return int(sats)
    raise BTClibValueError(f"too many decimals for a BTC amount: {amount}")


def btc_from_sats(sats: int) -> Decimal:
    "Return the BTC Decimal equivalent of the provided satoshi amount."
    if sats > MAX_SATOSHI:
        raise BTClibValueError(f"too many satoshis: {sats}")
    return sats * BITCOIN_PER_SATOSHI
