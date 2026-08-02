#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.fee` module.

The dust tests are the interesting half. `dust_threshold` computes what
other wallets tabulate, so the check that matters is computed against
tabulated: electrum's `electrum/bitcoin.py` carries five constants --
DUST_LIMIT_P2PKH 546, DUST_LIMIT_P2SH 540, DUST_LIMIT_P2WSH 330,
DUST_LIMIT_P2WPKH 294, DUST_LIMIT_UNKNOWN_SEGWIT 354 -- and Bitcoin
Core's own comment above `GetDustThreshold` works two of them out by
hand, 182 and 98 virtual bytes at 3000 sat/kvB. Nothing in btclib names
any of those numbers, so agreeing with them is evidence rather than
tautology.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import (
    DUST_RELAY_FEE_RATE,
    FeeRate,
    dust_threshold,
    fee_from_vsize,
)
from btclib.script import ScriptPubKey, serialize
from btclib.script.limits import MAX_SCRIPT_SIZE

_PUB_KEY = "02cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"


def test_the_unit_is_in_the_name() -> None:
    """A bare number never reaches the constructor without its unit."""
    with pytest.raises(TypeError):
        FeeRate(3000)  # type: ignore[call-arg]

    rate = FeeRate(sats_per_kvbyte=3000)
    assert rate.sats_per_kvbyte == 3000
    assert rate.sats_per_vbyte == 3
    assert rate == FeeRate.from_sats_per_vbyte(3)


@pytest.mark.parametrize(
    ("sats_per_vbyte", "sats_per_kvbyte"),
    [
        (0, 0),
        (1, 1000),
        ("1.5", 1500),
        ("0.001", 1),
        (Decimal("2.345"), 2345),
        # a float is read through its repr, so what was written is what
        # is meant: 1.1 is 1100 sat/kvB and not the 1099 or 1101 that
        # the nearest binary fraction could argue for
        (1.1, 1100),
        ("1e3", 1_000_000),
    ],
)
def test_sats_per_vbyte_round_trip(sats_per_vbyte: Any, sats_per_kvbyte: int) -> None:
    rate = FeeRate.from_sats_per_vbyte(sats_per_vbyte)
    assert rate.sats_per_kvbyte == sats_per_kvbyte
    assert rate.sats_per_vbyte == Decimal(str(sats_per_vbyte))
    # and back again, from the accessor into the constructor
    assert FeeRate.from_sats_per_vbyte(rate.sats_per_vbyte) == rate


def test_sats_per_vbyte_is_exact_or_it_is_an_error() -> None:
    """Truncation is refused, not performed."""
    err_msg = "sat/vB fee rate finer than a millisatoshi per virtual byte"
    with pytest.raises(BTClibValueError, match=err_msg):
        FeeRate.from_sats_per_vbyte("0.0005")
    with pytest.raises(BTClibValueError, match=err_msg):
        FeeRate.from_sats_per_vbyte(Decimal(1) / 3)
    # the boundary: three decimals are held, a fourth is not
    assert FeeRate.from_sats_per_vbyte("0.001").sats_per_kvbyte == 1
    with pytest.raises(BTClibValueError, match=err_msg):
        FeeRate.from_sats_per_vbyte("0.0001")


@pytest.mark.parametrize("rate", ["NaN", "Infinity", "-Infinity"])
def test_a_rate_that_is_not_a_number(rate: str) -> None:
    err_msg = "invalid sat/vB fee rate: "
    with pytest.raises(BTClibValueError, match=err_msg):
        FeeRate.from_sats_per_vbyte(rate)


def test_a_rate_is_a_non_negative_integer_number_of_sats_per_kvbyte() -> None:
    err_msg = "non-integer sat/kvB fee rate: "
    with pytest.raises(BTClibTypeError, match=err_msg):
        FeeRate(sats_per_kvbyte=1.5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match=err_msg):
        FeeRate(sats_per_kvbyte="3000")  # type: ignore[arg-type]

    err_msg = "negative fee rate: "
    with pytest.raises(BTClibValueError, match=err_msg):
        FeeRate(sats_per_kvbyte=-1)
    # Core would take this one and floor the fee it computes at -1
    # satoshi; here it is refused before there is a fee to floor
    with pytest.raises(BTClibValueError, match=err_msg):
        FeeRate.from_sats_per_vbyte("-1.5")


def test_rates_compare_and_hash() -> None:
    slow = FeeRate(sats_per_kvbyte=1000)
    fast = FeeRate.from_sats_per_vbyte("1.001")
    assert slow < fast
    assert max(slow, fast) is fast
    assert sorted([fast, slow]) == [slow, fast]
    assert len({slow, fast, FeeRate(sats_per_kvbyte=1000)}) == 2


@pytest.mark.parametrize(
    ("sats_per_kvbyte", "vsize", "fee"),
    [
        # the rate is per thousand virtual bytes, so a thousand of them
        # owe exactly the rate: no rounding to hide a factor of 1000 in
        (3000, 1000, 3000),
        (1000, 141, 141),
        # rounded up, and by the smallest amount there is: 140.999 sat
        # is not 140 sat, because 140 sat does not pay the rate
        (999, 141, 141),
        (1, 141, 1),
        # the smallest fee a nonzero rate can owe for a nonzero size is
        # one satoshi, and exact ceiling division gives it without a
        # special case
        (1, 1, 1),
        # a zero rate owes zero at any size, and a zero size owes zero at
        # any rate: neither is a division by zero, here or in Core
        (0, 1000, 0),
        (0, 0, 0),
        (3000, 0, 0),
        # Core's own worked examples, from the comment above
        # GetDustThreshold
        (3000, 182, 546),
        (3000, 98, 294),
    ],
)
def test_fee_from_vsize(sats_per_kvbyte: int, vsize: int, fee: int) -> None:
    assert fee_from_vsize(vsize, FeeRate(sats_per_kvbyte=sats_per_kvbyte)) == fee


def test_the_fee_rounds_up_at_every_remainder() -> None:
    """One satoshi per kvB, over every size a kilo-virtual-byte holds.

    The rate that makes the rounding visible everywhere: the fee is 1 for
    every size from 1 to 1000 and 2 for 1001, so a floor anywhere in the
    arithmetic is a wrong answer 999 times over.
    """
    rate = FeeRate(sats_per_kvbyte=1)
    assert fee_from_vsize(0, rate) == 0
    assert all(fee_from_vsize(vsize, rate) == 1 for vsize in range(1, 1001))
    assert fee_from_vsize(1001, rate) == 2


def test_a_negative_virtual_size_is_not_a_size() -> None:
    with pytest.raises(BTClibValueError, match="negative virtual size: "):
        fee_from_vsize(-1, DUST_RELAY_FEE_RATE)


def _script_pub_keys() -> dict[str, bytes]:
    """The output types, built by btclib rather than written out.

    The sizes the threshold is computed from are then the sizes btclib's
    own constructors produce, which a script literal copied into this
    file would not be evidence of.
    """
    redeem_script = ScriptPubKey.p2pkh(_PUB_KEY).script
    return {
        "p2pkh": ScriptPubKey.p2pkh(_PUB_KEY).script,
        "p2sh": ScriptPubKey.p2sh(redeem_script).script,
        "p2wpkh": ScriptPubKey.p2wpkh(_PUB_KEY).script,
        "p2wsh": ScriptPubKey.p2wsh(redeem_script).script,
        "p2tr": ScriptPubKey.p2tr(_PUB_KEY).script,
        # the largest witness program there is, at a version no proposal
        # has claimed: the "unknown segwit" electrum tabulates
        "unknown_segwit": serialize(["OP_16", bytes(40)]),
        "p2pk": ScriptPubKey.p2pk(_PUB_KEY).script,
    }


@pytest.mark.parametrize(
    ("script_type", "threshold"),
    [
        # electrum/bitcoin.py's DUST_LIMIT_* table, every entry of it
        ("p2pkh", 546),
        ("p2sh", 540),
        ("p2wsh", 330),
        ("p2wpkh", 294),
        ("unknown_segwit", 354),
        # not in that table, and computed all the same: a taproot output
        # is a 34-byte witness program like a p2wsh one, so it costs the
        # same to spend. Nothing in btclib.fee mentions taproot
        ("p2tr", 330),
        # a bare public key, 33 of them compressed plus the push and the
        # OP_CHECKSIG: 8 + 1 + 35 + 148 = 192 vB at 3000 sat/kvB
        ("p2pk", 576),
    ],
)
def test_dust_threshold_against_the_tabulated_limits(
    script_type: str, threshold: int
) -> None:
    assert dust_threshold(_script_pub_keys()[script_type]) == threshold


def test_dust_threshold_takes_a_hex_string_too() -> None:
    script_pub_key = _script_pub_keys()["p2wpkh"]
    assert dust_threshold(script_pub_key.hex()) == dust_threshold(script_pub_key)


def test_the_dust_relay_rate_is_a_parameter() -> None:
    """-dustrelayfee is Core's option, and this is the same knob."""
    script_pub_key = _script_pub_keys()["p2pkh"]
    assert DUST_RELAY_FEE_RATE == FeeRate(sats_per_kvbyte=3000)
    assert dust_threshold(script_pub_key, DUST_RELAY_FEE_RATE) == 546
    # the 182 virtual bytes Core's comment names, at three other rates
    assert dust_threshold(script_pub_key, FeeRate(sats_per_kvbyte=1000)) == 182
    assert dust_threshold(script_pub_key, FeeRate.from_sats_per_vbyte(1)) == 182
    assert dust_threshold(script_pub_key, FeeRate(sats_per_kvbyte=0)) == 0
    # rounded up like any other fee: 182 * 1.5 is 273 exactly, 182 * 1.501
    # is 273.182 and costs the extra satoshi
    assert dust_threshold(script_pub_key, FeeRate.from_sats_per_vbyte("1.5")) == 273
    assert dust_threshold(script_pub_key, FeeRate.from_sats_per_vbyte("1.501")) == 274


@pytest.mark.parametrize(
    "script_pub_key",
    [
        # every shape Core's IsUnspendable answers True for: a standard
        # nulldata output, a bare OP_RETURN and an OP_RETURN that btclib's
        # own is_nulldata refuses (issue #211), plus a script one byte
        # over MAX_SCRIPT_SIZE
        pytest.param(serialize(["OP_RETURN", b"\xde\xad\xbe\xef"]), id="nulldata"),
        pytest.param(b"\x6a", id="bare OP_RETURN"),
        pytest.param(b"\x6a\x51", id="OP_RETURN OP_1"),
        pytest.param(b"\x6a" + bytes(MAX_SCRIPT_SIZE), id="huge OP_RETURN"),
        pytest.param(b"\x51" * (MAX_SCRIPT_SIZE + 1), id="over MAX_SCRIPT_SIZE"),
    ],
)
def test_an_unspendable_output_has_no_dust_threshold(script_pub_key: bytes) -> None:
    assert dust_threshold(script_pub_key) == 0


def test_the_unspendable_test_is_cores_and_not_the_nulldata_classifier() -> None:
    """`is_nulldata` is narrower than Core's `IsUnspendable`, on purpose.

    Reading the answer off the classifier would give a bare OP_RETURN and
    an OP_RETURN followed by several pushes a threshold apiece, which a
    node that will never let either be spent does not agree with.
    """
    from btclib.script import is_nulldata  # noqa: PLC0415

    assert not is_nulldata(b"\x6a")
    assert not is_nulldata(b"\x6a\x51")
    assert dust_threshold(b"\x6a") == 0
    assert dust_threshold(b"\x6a\x51") == 0


def test_a_script_that_is_no_type_at_all_still_has_a_threshold() -> None:
    """Unknown is not unspendable, and the arithmetic needs no type.

    A script btclib cannot classify is spent by an input of some size all
    the same, so it gets the non-witness figure: 8 for the value, the
    var_int length prefix, the script, and 148 for the input.
    """
    # the empty script: 8 + 1 + 0 + 148 = 157 vB, 471 satoshi
    assert dust_threshold(b"") == 471
    # a witness program at the shortest length segwit admits
    assert dust_threshold(serialize(["OP_1", bytes(2)])) == 240
    # one byte longer than any witness program, so not one: it takes the
    # 148-byte input rather than the 67-byte one, and 8 + 1 + 43 + 148 is
    # 200 vB against the 118 the 40-byte program above pays for
    assert dust_threshold(serialize(["OP_1", bytes(41)])) == 600


def test_the_var_int_prefix_is_counted() -> None:
    """A script over 252 bytes takes a three-byte length prefix.

    The one place the output's own serialized size stops being
    len(script) + 9, and the boundary nothing else in the suite crosses.
    """
    at_the_limit = b"\x51" * 252
    over_it = b"\x51" * 253
    # 8 + 1 + 252 + 148 = 409 vB, and then 8 + 3 + 253 + 148 = 412
    assert dust_threshold(at_the_limit) == 1227
    assert dust_threshold(over_it) == 1236
