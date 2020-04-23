#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Proper handling of monetary amounts.

Monetary amounts are expressed as number of satoshis in the Bitcoin Core
client and this python library (e.g. 1 BTC is 100,000,000). Instead,
monetary values are express as double-precision floats in the JSON API
(e.g. 1 BTC is 1.00000000).

One needs to be aware of possible floating-point conversion issues:
as example, with floats 1.1 + 2.2 != 3.3;
algebra with bitcoin amounts should always be performed using satoshis.

The provided functions properly handle conversion between satoshi amounts
and float monetary values.
"""


def sat_from_float(value: float) -> int:
    """Return the satoshi amount equivalent of a float monetary value."""
    return int(round(value * 1e8))


def float_from_sat(amount: int) -> float:
    """Return the float monetary value equivalent of a satoshi amount."""
    return float(amount / 1e8)
