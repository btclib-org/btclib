#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.amount` module."

from decimal import Decimal

import pytest

from btclib.amount import MAX_BITCOIN, MAX_SATOSHI, btc_from_sats, sats_from_btc
from btclib.exceptions import BTClibValueError


def test_conversions() -> None:
    float_1 = 1.1
    float_2 = 2.2
    float_tot = float_1 + float_2
    # _NOT_ equal !!
    assert float_tot != 3.3

    sats_1 = sats_from_btc(float_1)
    sats_2 = sats_from_btc(float_2)
    sats_tot = sats_1 + sats_2
    # equal !!
    assert btc_from_sats(sats_tot) == Decimal("3.3")

    btc_1 = Decimal("1.1")
    btc_2 = Decimal("2.2")
    btc_tot = btc_1 + btc_2
    # _NOT_ equal !!
    assert btc_tot == Decimal("3.3")


def test_exceptions() -> None:

    with pytest.raises(BTClibValueError, match="invalid number of satoshis: "):
        btc_from_sats(MAX_SATOSHI + 1)
    with pytest.raises(BTClibValueError, match="invalid number of satoshis: "):
        btc_from_sats(-MAX_SATOSHI - 1)

    with pytest.raises(BTClibValueError, match="invalid btc amount: "):
        sats_from_btc(MAX_BITCOIN + Decimal("0.00000001"))
    with pytest.raises(BTClibValueError, match="invalid btc amount: "):
        sats_from_btc(-MAX_BITCOIN - Decimal("0.00000001"))

    err_msg = "too many decimals for a BTC amount: "
    with pytest.raises(BTClibValueError, match=err_msg):
        sats_from_btc(Decimal("0.123456789"))
    with pytest.raises(BTClibValueError, match=err_msg):
        sats_from_btc(0.123456789)


def test_self_consistency() -> None:

    # "8.50492428" must not raise Exception, even if the float representation
    # of the corresponding satoshi amount is 850492427.9999999
    cases = ("0", "0e0", "32.100", "0.321000e+2", "0.12345678", "8.50492428", "-0.1234")
    for string_amount in cases:
        btc = Decimal(string_amount).normalize()
        assert btc_from_sats(sats_from_btc(string_amount)) == btc
        assert btc_from_sats(sats_from_btc(Decimal(string_amount))) == btc


def test_normalization() -> None:

    assert btc_from_sats(10000) == Decimal("0.00010000")
    assert str(btc_from_sats(10000)) != str(Decimal("0.00010000"))
    assert str(btc_from_sats(10000)) == str(Decimal("0.00010000").normalize())

    assert btc_from_sats(10000) == Decimal("0.0001")
    assert str(btc_from_sats(10000)) == str(Decimal("0.0001"))

    assert btc_from_sats(-10000) == Decimal("-0.00010000")
    assert str(btc_from_sats(-10000)) != str(Decimal("-0.00010000"))
    assert str(btc_from_sats(-10000)) == str(Decimal("-0.00010000").normalize())

    assert btc_from_sats(-10000) == Decimal("-0.0001")
    assert str(btc_from_sats(-10000)) == str(Decimal("-0.0001"))
