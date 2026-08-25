# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Fee rates, the fee a virtual size owes, package fees, and dust.

Each answer is a function of its arguments alone: what a fee rate is,
what fee a transaction of a given virtual size owes at that rate, what a
child owes when the outputs it spends are unconfirmed, and how small an
output has to be before the network refuses to relay it.

A fee rate is a price, and the unit is where the mistakes are. Bitcoin
Core stores it in satoshi per kilo-virtual-byte, quotes it in BTC per
kilo-virtual-byte wherever its RPC replies mention one, and wallets and
their users state it in satoshi per virtual byte: three units and two
factors that a bare int does not record. `FeeRate` names the unit in
every constructor and accessor, so no factor is the caller's to
remember, and it refuses a rate it could not hold exactly rather than
truncating one.

Explicitly not here, and the boundary is the point: everything downstream
of a network. Mempool histograms, a fee estimate for a confirmation
target, an ETA, a "how many blocks" slider -- those are policy fed by
live data. They need a node, they answer differently every minute, and
they belong to an application rather than to a library. `package_fee` is
on this side of that line and its inputs are on the other: which
ancestors are unconfirmed and what each of them paid is what a node
answers, the arithmetic over those totals is not. What this module
computes it computes from its arguments and from Bitcoin Core's
constants, and the same arguments give the same answer forever.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from btclib import var_int
from btclib.alias import Octets
from btclib.amount import sats_from_btc, valid_sats_amount
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script.limits import MAX_SCRIPT_SIZE
from btclib.script.script import BYTE_FROM_OP_CODE_NAME
from btclib.script.script_pub_key import is_segwit
from btclib.utils import bytes_from_octets, is_integer

__all__ = [
    "DUST_RELAY_FEE_RATE",
    "FeeRate",
    "dust_threshold",
    "fee_from_vsize",
    "package_fee",
]

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
        if not is_integer(self.sats_per_kvbyte):
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
        """Return the same rate in sat/kvB from a sat/vB quote.

        The quote is a Decimal, an int, a string, or anything else
        str() renders as a decimal number; a float is read through
        its repr, so 1.1 is the 1.1 that was written rather than the
        binary fraction nearest to it. Refused: what does not read as
        a decimal number, is not finite, or is not a whole number of
        millisatoshi per virtual byte -- what sat/kvB cannot hold
        exactly.
        """
        err_msg = f"invalid sat/vB fee rate: {sats_per_vbyte}"
        # str() renders every object there is, and Decimal refuses most
        # of what it renders with an InvalidOperation -- an
        # ArithmeticError, which nobody catches around a fee rate.
        # Accepting Any is what makes that reachable from ordinary
        # input, "1,2" being how half the world writes a decimal, so the
        # width of the argument has to be matched by one exception of
        # this library's rather than one of decimal's
        try:
            rate = Decimal(str(sats_per_vbyte))
        except InvalidOperation as e:
            raise BTClibValueError(err_msg) from e
        # as_integer_ratio raises OverflowError on an infinity and
        # ValueError on a NaN, and the first of those is outside this
        # library's exception contract: both are refused here instead.
        # The same message as above, because it is the same complaint:
        # "NaN" parses and is not a rate, "abc" does not parse and is
        # not a rate either
        if not rate.is_finite():
            raise BTClibValueError(err_msg)
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

    @classmethod
    def from_btc_per_kvbyte(cls, btc_per_kvbyte: Any) -> FeeRate:
        """Return the same rate in sat/kvB from a BTC/kvB quote.

        BTC/kvB is the unit Bitcoin Core quotes a rate in wherever an
        RPC reply carries one -- `estimatesmartfee`'s `feerate`,
        `getmempoolinfo`'s `mempoolminfee` and `minrelaytxfee`,
        `getnetworkinfo`'s `relayfee` -- and it is a unit of the
        interface rather than of the node: what those numbers are
        compared against internally is the sat/kvB this class holds.
        `getblockstats` is the exception worth knowing, quoting its
        `minfeerate` and `avgfeerate` in sat/vB, which is the
        constructor above.

        A rate per kvB scales from BTC to satoshi by the factor an
        amount does, so `sats_from_btc` is the conversion and its
        refusals are the ones that apply: what does not read as a
        decimal number, what is not finite, a negative quote, and one
        naming a fraction of a satoshi -- what sat/kvB cannot hold
        exactly. Its complaints name a BTC amount, which is what is
        being converted.
        """
        # `valid_btc_amount` reads None as zero, which is right for an
        # amount -- no amount is no money -- and wrong for a price:
        # `estimatesmartfee` answers an `errors` array and no `feerate`
        # key at all when it cannot estimate one, so the missing quote a
        # caller reads out of that reply would become a free
        # transaction, and paying nothing is not what "no estimate"
        # says. Only the absent quote is refused: a zero a caller means
        # is a zero rate through this constructor like any other
        if btc_per_kvbyte is None:
            raise BTClibValueError(f"invalid BTC/kvB fee rate: {btc_per_kvbyte}")
        return cls(sats_per_kvbyte=sats_from_btc(btc_per_kvbyte))

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
    the rate, and a transaction paying it does not relay. A virtual
    size that is not an int, or is negative, is refused.
    """
    # checked for the reason FeeRate checks its own field: a float does
    # not fail this arithmetic, it passes through it, and
    # fee_from_vsize(141.5, ...) would answer 425.0 -- a float fee out of
    # the one function whose contract is that no float ever stands
    # between a rate and the satoshi it owes. A str fails instead, but on
    # the comparison below and with a bare TypeError naming '<'
    if not is_integer(vsize):
        raise BTClibTypeError(f"non-integer virtual size: {vsize}")
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


def package_fee(
    vsize: int,
    fee_rate: FeeRate,
    *,
    ancestor_vsize: int = 0,
    ancestor_fee: int = 0,
) -> int:
    """Return the fee in satoshi owed by a transaction and its ancestors.

    Child pays for parent. A transaction spending an unconfirmed output
    is mined with what it depends on or not at all, so the rate a miner
    reads is the package's -- Core's mempool scores a transaction by
    `fees.ancestor` over `ancestorsize`, both of `getmempoolentry` --
    and buying a rate for the child means buying it for everything
    unconfirmed behind it, less what that already paid.

    The answer is the larger of two fees: what the child owes for its
    own virtual size, and what the package owes for the sum of the
    sizes, less `ancestor_fee`. The second is what lifts a package its
    ancestors underpay. The first is what stands when they pay the rate
    or more, where the difference would be a *discount* on the child --
    a child cheaper than the rate because its parent overpaid, which is
    a transaction that may not relay on its own and a fee no caller
    asked for.

    `ancestor_vsize` and `ancestor_fee` are totals over the unconfirmed
    ancestors, the child itself excluded; zero for both, the default, is
    a child with nothing unconfirmed behind it and the answer is
    `fee_from_vsize`. Which transactions those are, whether the set
    stops at the parents or walks the whole graph, and what each of them
    paid is a mempool question, and it stays with the caller: an
    ancestor's own descendants are not in it, and neither are Core's
    `-limitancestorcount` and `-limitancestorsize`, which bound what it
    will accept but not what a fee is.

    Keyword-only, the two of them, because they are same-typed
    non-negative ints beside each other: a swapped pair is a wrong fee
    that nothing else in the arithmetic can notice.
    """
    if not is_integer(ancestor_vsize):
        raise BTClibTypeError(f"non-integer ancestor virtual size: {ancestor_vsize}")
    # bounded here rather than left to the sum below, where a negative
    # total would cancel against `vsize` and price the package as
    # something smaller than the child it holds
    if ancestor_vsize < 0:
        raise BTClibValueError(f"negative ancestor virtual size: {ancestor_vsize}")
    # the ancestors' fee is money, so the amount validator is the gate:
    # non-integer, negative and above MAX_MONEY are its answers to give,
    # and that bound is one this module has no business restating
    ancestor_fee = valid_sats_amount(ancestor_fee)

    # `vsize` itself is checked where it is used, `fee_from_vsize` being
    # the whole of the arithmetic here -- and not two optional arguments
    # on that function, which is exact ceiling division and nothing else:
    # the maximum below is the rule that a child is never priced under
    # the rate it was asked for, and a rule reads better under a name of
    # its own than as a branch inside the primitive every fee goes
    # through
    own_fee = fee_from_vsize(vsize, fee_rate)
    package = fee_from_vsize(vsize + ancestor_vsize, fee_rate)
    return max(own_fee, package - ancestor_fee)


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

    `fee_rate` is the dust relay rate, defaulting to Core's 3000
    sat/kvB. An output is dust when its value is below the returned
    satoshi; one worth exactly it is not.
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
