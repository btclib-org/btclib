#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.amount` module."

from decimal import Decimal, FloatOperation, localcontext
from typing import List, Union

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

            float_1 = 1.1
            float_2 = 2.2
            float_tot = float_1 + float_2
            # _NOT_ equal !!
            assert float_tot != 3.3

            btc_1 = Decimal("1.1")
            btc_2 = Decimal("2.2")
            btc_tot = btc_1 + btc_2
            # equal !!
            assert btc_tot == Decimal("3.3")

            assert btc_from_sats(10000) == Decimal("0.00010000")
            assert str(btc_from_sats(10000)) != str(Decimal("0.00010000"))
            assert str(btc_from_sats(10000)) == str(Decimal("0.00010000").normalize())

            assert btc_from_sats(10000) == Decimal("0.0001")
            assert str(btc_from_sats(10000)) == str(Decimal("0.0001"))

            assert valid_btc_amount(None) == 0
            assert valid_sats_amount(None) == 0


def test_exceptions() -> None:

    for trap_float_operation in (True, False):
        with localcontext() as ctx:
            ctx.traps[FloatOperation] = trap_float_operation

            err_msg = "invalid satoshi amount: "
            with pytest.raises(BTClibValueError, match=err_msg):
                btc_from_sats(2_099_999_997_690_001)

            err_msg = "invalid BTC amount: "
            with pytest.raises(BTClibValueError, match=err_msg):
                sats_from_btc(Decimal("20_999_999.97690001"))

            err_msg = "too many decimals for a BTC amount: "
            with pytest.raises(BTClibValueError, match=err_msg):
                sats_from_btc(Decimal("0.123456789"))
            # too many decimales, now with a float
            with pytest.raises(BTClibValueError, match=err_msg):
                valid_btc_amount(0.123456789)

            with pytest.raises(TypeError):
                btc_from_sats(2.5)  # type: ignore
            with pytest.raises(TypeError):
                btc_from_sats(5 / 2)  # type: ignore
            with pytest.raises(ValueError):
                btc_from_sats("2.5")  # type: ignore
            err_msg = "non-integer satoshi amount: "
            with pytest.raises(BTClibTypeError, match=err_msg):
                btc_from_sats(Decimal("2.5"))  # type: ignore


def test_self_consistency() -> None:

    for trap_float_operation in (True, False):
        with localcontext() as ctx:
            ctx.traps[FloatOperation] = trap_float_operation

            # 8.50390625 = 2177 / pow(2, 8)
            # 8.50390625 * 100_000_000 is 850390625.0
            # 8.50492428 * 100_000_000 is 850492427.9999999
            btc_amounts = [0, 1, 8.50390625, 8.50492428]
            cases: List[Union[int, float, str, Decimal]] = []
            for num in btc_amounts:
                cases += [num, float(num), str(num), f"{num:.7E}", Decimal(str(num))]

            for btc_amount in cases:
                exp_btc = Decimal(str(btc_amount)).normalize()
                btc = btc_from_sats(sats_from_btc(btc_amount))  # type: ignore
                assert btc == exp_btc
                assert str(btc) == str(exp_btc)
