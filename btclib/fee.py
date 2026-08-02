#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Fee rates, the fee a virtual size owes, and the dust threshold.

Three answers, each a function of its arguments alone: what a fee rate
is, what fee a transaction of a given virtual size owes at that rate, and
how small an output has to be before the network refuses to relay it.

A fee rate is a price, and the unit is where the mistakes are. Bitcoin
Core states it in satoshi per kilo-virtual-byte, wallets and their users
state it in satoshi per virtual byte, and the two differ by a factor of a
thousand that a bare int does not record. `FeeRate` names the unit in the
one constructor and in both accessors, so the factor is never the
caller's to remember, and it refuses a sat/vB rate it could not hold
exactly rather than truncating one.

Explicitly not here, and the boundary is the point: everything downstream
of a network. Mempool histograms, a fee estimate for a confirmation
target, an ETA, a "how many blocks" slider -- those are policy fed by
live data. They need a node, they answer differently every minute, and
they belong to an application rather than to a library. What this module
computes it computes from its arguments and from Bitcoin Core's
constants, and the same arguments give the same answer forever.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from btclib import var_int
from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script.limits import MAX_SCRIPT_SIZE
from btclib.script.script import BYTE_FROM_OP_CODE_NAME
from btclib.script.script_pub_key import is_segwit
from btclib.utils import bytes_from_octets

# the kilo in sat/kvB, i.e. how many virtual bytes a rate is quoted over
_VBYTES_PER_KVBYTE = 1000


@dataclass(frozen=True, order=True, kw_only=True)
class FeeRate:
    """A fee rate, held as an integer number of satoshi per kvB.

    sat/kvB as an int is the exact representation, and the only one that
    is. It is what Core stores, so no conversion stands between this
    number and the fee a node computes; it is integral, so the arithmetic
    is Python's unbounded int rather than a float that stops counting in
    ones somewhere below MAX_MONEY; and it is fine enough to hold every
    rate a user can state, sat/vB being quoted to three decimals at most
    -- 1.5 sat/vB is exactly 1500 sat/kvB. Storing sat/vB instead would
    make the common unit the lossy one: 1.5 is not representable as an
    int, and as a float it is one of the few decimals that happen to be
    exact, which is worse than none of them being.

    Keyword-only, so that no bare number is ever passed to the
    constructor without its unit beside it: `FeeRate(3000)` is the
    off-by-a-thousand this class exists to prevent, and it is a
    TypeError. There is no `from_sats_per_kvbyte` classmethod either --
    the field is that constructor, already spelled with its unit, and a
    second spelling of one thing is a menu rather than an API.

    Ordered, because comparing two prices is the question a caller
    actually asks of them, and the comparison is exact for the same
    reason the storage is.
    """

    sats_per_kvbyte: int

    def __post_init__(self) -> None:
        if not isinstance(self.sats_per_kvbyte, int):
            raise BTClibTypeError(
                f"non-integer sat/kvB fee rate: {self.sats_per_kvbyte}"
            )
        # Core's CFeeRate admits a negative rate, and its GetFee floors
        # the result at -1 satoshi when it sees one. That is not leniency
        # to copy: the fraction CFeeRate stores is also the slope of a
        # feerate diagram, where the difference between two chunks can
        # run downhill, and the floor is there for that use. A FeeRate
        # here is only ever a price, never a difference, so a negative
        # one is a caller's mistake and the floor has nothing to protect
        if self.sats_per_kvbyte < 0:
            raise BTClibValueError(f"negative fee rate: {self.sats_per_kvbyte} sat/kvB")

    @classmethod
    def from_sats_per_vbyte(cls, sats_per_vbyte: Any) -> FeeRate:
        """Return the fee rate quoted in satoshi per virtual byte.

        Args:
            sats_per_vbyte (Any): The rate in sat/vB: a Decimal, an int,
                a string, or anything else str() renders as a decimal
                number. A float is read through its repr, so 1.1 is the
                1.1 that was written rather than the binary fraction
                nearest to it.

        Raises:
            BTClibValueError: If the rate is not finite, or if it is not
                a whole number of millisatoshi per virtual byte -- i.e.
                if sat/kvB could not hold it exactly.

        Returns:
            FeeRate: The same rate, in sat/kvB.
        """
        rate = Decimal(str(sats_per_vbyte))
        # as_integer_ratio raises OverflowError on an infinity and
        # ValueError on a NaN, and the first of those is outside this
        # library's exception contract: both are refused here instead
        if not rate.is_finite():
            raise BTClibValueError(f"invalid sat/vB fee rate: {sats_per_vbyte}")
        # the ratio is exact and reads no decimal context, where
        # multiplying the Decimal by a thousand would round to whatever
        # precision the caller's context happens to carry. A conversion
        # whose reason for existing is that truncation must be impossible
        # cannot be the place that truncates
        numerator, denominator = rate.as_integer_ratio()
        sats_per_kvbyte, remainder = divmod(numerator * _VBYTES_PER_KVBYTE, denominator)
        if remainder:
            raise BTClibValueError(
                "sat/vB fee rate finer than a millisatoshi per virtual byte: "
                f"{sats_per_vbyte}"
            )
        return cls(sats_per_kvbyte=sats_per_kvbyte)

    @property
    def sats_per_vbyte(self) -> Decimal:
        """Return the rate in satoshi per virtual byte, exactly.

        A Decimal and not a float, for the reason the class docstring
        gives: the unit users speak is the unit a binary fraction cannot
        hold, and handing back 1.1000000000000001 would undo the
        conversion that refused to truncate on the way in.
        """
        whole, milli_sats = divmod(self.sats_per_kvbyte, _VBYTES_PER_KVBYTE)
        # built from its digits rather than by dividing two Decimals,
        # which rounds to the ambient context precision: what a caller
        # has set that to is no business of a fee rate.
        # normalize() strips the trailing zeros, as btc_from_sats does,
        # so that equal rates print the same way
        return Decimal(f"{whole}.{milli_sats:03d}").normalize()


def fee_from_vsize(vsize: int, fee_rate: FeeRate) -> int:
    """Return the fee in satoshi owed by a transaction of that virtual size.

    Rounded up, which is what Core's `CFeeRate::GetFee` does and the
    reason it does it: a fee one satoshi short of the rate is a fee below
    the rate, and a transaction paying it does not relay.

    Args:
        vsize (int): The virtual size, in virtual bytes.
        fee_rate (FeeRate): The rate the fee is owed at.

    Raises:
        BTClibValueError: If the virtual size is negative.

    Returns:
        int: The fee, in satoshi.
    """
    if vsize < 0:
        raise BTClibValueError(f"negative virtual size: {vsize}")
    # integer division and a bump, not math.ceil of a quotient: the
    # quotient would be a float, and Core's own comment on this
    # computation is that "we've previously had bugs creep in from silent
    # double->int conversion".
    #
    # No floor at one satoshi either, though GetFee carries a branch that
    # looks like one. Exact ceiling division already returns at least 1
    # for any nonzero rate over a nonzero size -- one satoshi per kvB
    # over a single virtual byte is a fee of one satoshi, not of none --
    # so what is left of that branch upstream catches negative rates
    # alone, which this module has none of. A zero rate owes zero at
    # every size, and that is the answer rather than an edge case: it is
    # also how Core answers for a rate it holds as no rate at all
    sats, remainder = divmod(fee_rate.sats_per_kvbyte * vsize, _VBYTES_PER_KVBYTE)
    return sats + 1 if remainder else sats


# Core's DUST_RELAY_TX_FEE, the default of its -dustrelayfee option. A
# FeeRate and not the bare 3000 of policy.h, so that the default and the
# parameter it defaults are the same type: handing a number to something
# that wants a rate is the mistake this module exists to make impossible
DUST_RELAY_FEE_RATE = FeeRate(sats_per_kvbyte=3000)

# what spending an output costs, in the two shapes Core measures: 32
# bytes of previous-output hash, 4 of previous-output index, 1 for the
# length of the script_sig, 107 of script_sig -- a DER signature and a
# compressed public key, the minimum satisfaction of a p2pkh output --
# and 4 of sequence
_SPEND_SIZE = 32 + 4 + 1 + 107 + 4
# the same input spending a witness program, where those 107 bytes sit in
# the witness and weigh a quarter. The division is integer and Core's,
# WITNESS_SCALE_FACTOR being 4, so the discount is 26 and not 26.75.
# The 107 is a p2wpkh satisfaction and is used for every witness version,
# taproot included, whose real minimum is a single 64-byte BIP340
# signature: Core measured taproot with the p2wpkh figure rather than
# lower the dust level further, and matching Core is the whole point here
_SEGWIT_SPEND_SIZE = 32 + 4 + 1 + 107 // 4 + 4

# 8 bytes of value, and then the script behind its var_int length prefix:
# the output as it sits in the transaction that creates it
_TXOUT_VALUE_SIZE = 8


def dust_threshold(
    script_pub_key: Octets, fee_rate: FeeRate = DUST_RELAY_FEE_RATE
) -> int:
    """Return the smallest relayable value, in satoshi, for such an output.

    Core's `GetDustThreshold`, computed and not tabulated: the fee, at
    the dust relay rate, of the output itself plus the input that will
    one day spend it. An output worth less than that costs more to spend
    than it holds.

    Computing it is what makes it follow the script type on its own. p2tr
    answers 330 without p2tr being named anywhere below, and so will
    whatever output type comes next; a table of one limit per type is
    accurate the day it is written and needs an edit every time the
    network grows a type.

    An unspendable output has no input to pay for, so its threshold is
    zero and no value is dust.

    Args:
        script_pub_key (Octets): The output script.
        fee_rate (FeeRate, optional): The dust relay fee rate. Defaults
            to DUST_RELAY_FEE_RATE, Core's 3000 sat/kvB.

    Returns:
        int: The threshold, in satoshi. An output is dust when its value
        is below this; an output worth exactly this is not.
    """
    script_pub_key = bytes_from_octets(script_pub_key)

    # Core's CScript::IsUnspendable, spelled out rather than read off
    # btclib's is_nulldata, which is narrower on purpose (issue #211): a
    # bare OP_RETURN, and an OP_RETURN followed by several pushes, are
    # unknown to that classifier and unspendable to a node, and asking it
    # would hand each of them a threshold it does not have.
    # Sliced and not indexed, so that an empty script is a script with no
    # leading OP_RETURN rather than an IndexError
    if (
        script_pub_key[:1] == BYTE_FROM_OP_CODE_NAME["OP_RETURN"]
        or len(script_pub_key) > MAX_SCRIPT_SIZE
    ):
        return 0

    size = (
        _TXOUT_VALUE_SIZE
        + len(var_int.serialize(len(script_pub_key)))
        + len(script_pub_key)
    )
    size += _SEGWIT_SPEND_SIZE if is_segwit(script_pub_key) else _SPEND_SIZE
    return fee_from_vsize(size, fee_rate)
