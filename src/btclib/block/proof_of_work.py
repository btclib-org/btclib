# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Proof-of-work arithmetic: compact targets, retargeting, work, hash rate.

Pure functions over the four `bits` bytes a header carries and the times
two headers carry, deliberately: which chain is best, what the next
target is and how fast the network hashes are three questions asked of
several competing chains at once, and a function taking a chain object
could answer them for one. `BlockHeader` supplies the inputs and this
module does the arithmetic; nothing here reads or builds a header.

Bitcoin Core's `pow.cpp` and `arith_uint256.cpp` are the reference for
every value returned. The functions are named after what they answer
rather than after Core's spelling -- `bits_from_target` is `GetCompact`,
`target_from_bits` is `SetCompact`, `next_bits` is
`CalculateNextWorkRequired`, `block_work` is `GetBlockProof` -- and each
docstring names its counterpart.

`SetCompact` answers three things at once, the number and two
out-parameters, so it is two functions here: `target_from_bits` is the
number and raises where `fOverflow` is set, `is_negative_bits` is
`fNegative`. Refusing a header on either takes both, which is what
`BlockHeader.assert_valid_pow` asks.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from btclib.alias import Octets
from btclib.consensus import CONSENSUS_PARAMS
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import assert_type, bytes_from_octets, is_integer, is_octets

__all__ = [
    "DIFFICULTY_ADJUSTMENT_INTERVAL",
    "MAINNET_POW_LIMIT_BITS",
    "POW_TARGET_SPACING",
    "POW_TARGET_TIMESPAN",
    "REGTEST_POW_LIMIT_BITS",
    "TARGET_SIZE",
    "bits_from_target",
    "block_work",
    "chain_work",
    "hash_rate",
    "is_negative_bits",
    "next_bits",
    "retarget_first_height",
    "target_from_bits",
]

# a target is a 256-bit number, i.e. the hash it is compared against
TARGET_SIZE = 32

# the high bit of the three-byte significand is a sign and not a
# magnitude: Core's SetCompact reads the number out of
# `nCompact & 0x007fffff` and reports the bit through fNegative. Not
# exported, the two functions below being what a caller asks instead
_SIGNIFICAND_MASK = 0x007FFFFF
_SIGNIFICAND_SIGN_BIT = 0x00800000

# two weeks, the timespan a difficulty period aims at
POW_TARGET_TIMESPAN = 14 * 24 * 60 * 60
# ten minutes, the block interval it aims at
POW_TARGET_SPACING = 10 * 60
# 2016 blocks
DIFFICULTY_ADJUSTMENT_INTERVAL = POW_TARGET_TIMESPAN // POW_TARGET_SPACING

# the easiest target a network allows, as bits rather than as the 32
# bytes Core's params.powLimit holds, so that a caller reads the same
# four bytes a header carries. The compact form rounds down -- mainnet's
# limit and regtest's are both wider than three significand bytes, and
# only signet's survives the encoding unchanged -- and the rounding
# reaches no comparison anybody makes: the next target the compact form
# can express above the rounded value is already above Core's own limit,
# so a header's bits fall on the same side of either. Mainnet's is the
# genesis block target, which is why the genesis difficulty is 1, and
# testnet3 and testnet4 share it.
#
# The numbers are `btclib.consensus`'s, where every network has a row and
# where each is transcribed from Core with the line it was read at. These
# two names are the defaults of the signatures below, and they stay names
# because that is what a default is written as
MAINNET_POW_LIMIT_BITS = CONSENSUS_PARAMS["mainnet"].pow_limit_bits
# regtest's, the one loose enough to mine against in a test. Not
# something to hand to next_bits as a starting target: regtest sets
# fPowNoRetargeting, so Core never retargets from it, and 2^255 is a
# target the retarget's own multiplication overflows -- see the note
# there. As the pow_limit_bits of a network that does retarget it is
# fine, being compared and never multiplied
REGTEST_POW_LIMIT_BITS = CONSENSUS_PARAMS["regtest"].pow_limit_bits


def _value_from_bits(bits: bytes) -> int:
    """Return the magnitude the compact `bits` denote, unbounded.

    The body of Core's `SetCompact` and neither of its flags: nothing
    here objects to what 32 bytes cannot hold, which is the caller's
    business, and the sign is masked off rather than reported.
    """
    # significand (also known as mantissa or coefficient), the sign bit
    # masked off as Core's `nCompact & 0x007fffff` does
    significand = (
        int.from_bytes(bits[1:], byteorder="big", signed=False) & _SIGNIFICAND_MASK
    )
    # power term, also called characteristics. Core's SetCompact shifts
    # rather than multiplying by a power of 256, and so does this:
    # pow(256, -1) is a float in Python, so an exponent below 3 would send
    # a 256-bit number through float arithmetic
    exponent = bits[0]
    if exponent < 3:
        return significand >> (8 * (3 - exponent))
    return significand << (8 * (exponent - 3))


def target_from_bits(bits: Octets) -> bytes:
    """Return the 32-byte target the compact `bits` denote.

    The target yyzzww * 256^(xx-3) is represented by the 4 bytes
    'bits' xxyyzzww. Bitcoin Core spells this `SetCompact`.

    The high bit of yy is the sign of that number and not part of it, so
    it is masked off here and answered by `is_negative_bits`: a target
    is what a hash is compared against, and 0x1d80ffff denotes the
    genesis target with a sign, not one 2^7 easier.
    """
    bits = bytes_from_octets(bits, 4)
    value = _value_from_bits(bits)

    # the compact form can denote what 32 bytes cannot hold, which
    # to_bytes would answer with an OverflowError. Core raises the same
    # objection through the fOverflow flag of SetCompact, on which
    # CheckProofOfWork rejects the header
    if value >= 256**TARGET_SIZE:
        err_msg = f"invalid proof-of-work target: 0x{bits.hex()}"
        err_msg += f" overflows {TARGET_SIZE} bytes"
        raise BTClibValueError(err_msg)

    return value.to_bytes(TARGET_SIZE, "big", signed=False)


def is_negative_bits(bits: Octets) -> bool:
    """Return whether the compact `bits` denote a negative number.

    Bitcoin Core's `fNegative`, the flag `SetCompact` reports beside the
    value: 0x00800000 of the significand is a sign and not magnitude, so
    `bits` carrying it denote a number below zero, which no target is and
    no header may claim. `CheckProofOfWork` refuses such a header, and
    `BlockHeader.assert_valid_pow` is where btclib does. `target_from_bits`
    masks the bit off and answers the magnitude alone, which is what makes
    the flag a question of its own.

    A significand of zero has no sign, which is Core's `nWord != 0 &&`:
    0x03800000 denotes zero rather than negative zero, the sign bit being
    all there is of it. The magnitude asked about is the one the exponent
    has already been applied to, as it is in Core, so 0x018000ff is zero
    as well -- the only byte its masked significand holds is shifted out
    by an exponent of 1. And it is the sign of the number the four bytes
    denote, not the sign of the target, which is unsigned and cannot
    carry the answer -- hence a predicate, where Core has an
    out-parameter.
    """
    bits = bytes_from_octets(bits, 4)
    significand = int.from_bytes(bits[1:], byteorder="big", signed=False)
    return bool(significand & _SIGNIFICAND_SIGN_BIT) and _value_from_bits(bits) != 0


def bits_from_target(target: Octets) -> bytes:
    """Return the compact `bits` denoting a target, rounded down.

    The inverse of target_from_bits, i.e. Bitcoin Core's `GetCompact`,
    and lossy in the direction that keeps the target harder: the
    significand holds three bytes, so everything below them is dropped.
    A target that came from bits is recovered exactly.

    The sign bit of the significand is what makes this more than a
    change of base. The compact form reads 0x00800000 as "negative", so
    a significand whose high bit is set is divided by 256 and the
    exponent raised -- 0x800000 is written 0x04008000, four bytes rather
    than three, and never 0x03800000, where that bit is the sign and
    `SetCompact` masks it off, leaving four bytes that denote zero.
    is_negative_bits is the flag itself, for the other direction.
    """
    target = bytes_from_octets(target)
    if len(target) > TARGET_SIZE:
        err_msg = f"invalid target: {len(target)} bytes"
        err_msg += f" instead of at most {TARGET_SIZE}"
        raise BTClibValueError(err_msg)

    value = int.from_bytes(target, byteorder="big", signed=False)
    # ceil(bit_length / 8), the number of bytes the value occupies, which
    # is Core's CeilDiv(bits(), 8): zero occupies none, so bits 0x00000000
    # is what a zero target is written as
    exponent = (value.bit_length() + 7) // 8
    if exponent <= 3:
        significand = value << (8 * (3 - exponent))
    else:
        significand = value >> (8 * (exponent - 3))

    if significand & _SIGNIFICAND_SIGN_BIT:
        significand >>= 8
        exponent += 1

    return bytes([exponent]) + significand.to_bytes(3, "big", signed=False)


def retarget_first_height(last_height: int) -> int:
    """Return the height the retarget window is measured from.

    The window ends at `last_height`, the last block of a difficulty
    period, and this is the first block of that same period: 2015 blocks
    back, not 2016.

    That is the off-by-one Bitcoin Core keeps for compatibility. The
    period holds 2016 blocks but only 2015 intervals between their
    timestamps, and the retarget divides the measured timespan by two
    weeks all the same, so the difficulty is set as if 2016 intervals had
    been observed and blocks come out roughly 0.05% faster than the ten
    minutes aimed at. Fixing it would be a hard fork over a rounding
    error, so `GetNextWorkRequired` still reads
    `nHeight - (DifficultyAdjustmentInterval() - 1)`.
    """
    # a height, before the arithmetic: `"2015" + 1` is a bare TypeError
    # about concatenating a str, and `True + 1` is the height two
    if not is_integer(last_height):
        raise BTClibTypeError(f"invalid height type: {type(last_height).__name__}")

    # Core only retargets when the *next* height is a multiple of 2016,
    # so the last block of a period is the one 2015 blocks after its
    # first. Refused rather than answered for any other height: the
    # answer would be a window Core never measures, and the caller
    # asking has mistaken which block ends the period
    if (last_height + 1) % DIFFICULTY_ADJUSTMENT_INTERVAL:
        err_msg = f"invalid retarget height: {last_height}"
        err_msg += f" is not a multiple of {DIFFICULTY_ADJUSTMENT_INTERVAL}"
        err_msg += " minus one"
        raise BTClibValueError(err_msg)

    return last_height - (DIFFICULTY_ADJUSTMENT_INTERVAL - 1)


def next_bits(
    bits: Octets,
    first_block_time: datetime,
    last_block_time: datetime,
    *,
    pow_limit_bits: Octets = MAINNET_POW_LIMIT_BITS,
) -> bytes:
    """Return the compact target of the difficulty period that follows.

    `bits` is what the last block of the ending period carries,
    `last_block_time` its timestamp and `first_block_time` the timestamp
    of the block `retarget_first_height` names -- 2015 blocks earlier,
    which is the off-by-one documented there.

    The new target is the old one scaled by the measured timespan over
    the two weeks aimed at, so a period mined too fast tightens it. The
    timespan itself is clamped to a quarter and to four times two weeks
    *before* the scaling, which is what bounds a single retarget to a
    factor of four either way; the result is then clamped to the
    network's easiest target and re-encoded, and the rounding of that
    re-encoding is part of the answer.

    Bitcoin Core spells this `CalculateNextWorkRequired`.
    """
    # both are datetimes, checked before the subtraction: two ints
    # subtract to an int and answer `AttributeError: 'int' object has no
    # attribute 'total_seconds'`, which is neither half of this library's
    # exception contract, and a str answers a TypeError about the operands
    for name, value in (
        ("first block time", first_block_time),
        ("last block time", last_block_time),
    ):
        assert_type(value, datetime, name)

    # the difference of two datetimes, not two timestamp() calls: aware
    # or naive, the subtraction is the same number of seconds, so the
    # answer does not depend on the machine's time zone for the naive
    # datetime that BlockHeader.assert_valid rejects but arithmetic here
    # has no reason to
    actual_timespan = int((last_block_time - first_block_time).total_seconds())
    actual_timespan = max(actual_timespan, POW_TARGET_TIMESPAN // 4)
    actual_timespan = min(actual_timespan, POW_TARGET_TIMESPAN * 4)

    target = int.from_bytes(target_from_bits(bits), "big", signed=False)
    # Core multiplies in arith_uint256, which wraps: the mask is that
    # wrap, and it is the difference between matching Core and being
    # right in a way no node agrees with. Written as arithmetic rather
    # than as a comment, because an answer that differs from Core's is
    # not a target.
    # The product overflows above 2^256 / 4838400, i.e. above roughly
    # 2^233.8, which is well over mainnet's pow limit of 2^224 and over
    # testnet3's and testnet4's, they being the same one. Regtest's is
    # 2^255 and would overflow on any timespan at all -- which is
    # consistent rather than a hole, Core setting fPowNoRetargeting there
    # and never reaching this line
    target = (target * actual_timespan) % 2**256
    target //= POW_TARGET_TIMESPAN

    pow_limit = int.from_bytes(target_from_bits(pow_limit_bits), "big", signed=False)
    target = min(target, pow_limit)

    return bits_from_target(target.to_bytes(TARGET_SIZE, "big", signed=False))


def block_work(bits: Octets) -> int:
    """Return the expected number of hashes a block of this target costs.

    A hash satisfies the target with probability (target + 1) / 2^256,
    so 2^256 / (target + 1) evaluations are expected before one does.
    This is the block's contribution to the chain work, and Bitcoin Core
    spells it `GetBlockProof`.

    Core answers 0 for a zero target, and for the two `SetCompact` flags
    besides, because `GetBlockProof` doubles as the gate that keeps an
    invalid header from being credited with work. Here both are
    exceptions instead: target_from_bits raises on the overflow, and a
    zero target -- which no hash can ever satisfy, so no block can ever
    carry it -- raises here rather than being reported as free.
    """
    target = int.from_bytes(target_from_bits(bits), "big", signed=False)
    if not target:
        raise BTClibValueError(
            f"zero proof-of-work target: 0x{bytes_from_octets(bits).hex()}"
        )

    return 2**256 // (target + 1)


def chain_work(bits_sequence: Sequence[Octets]) -> int:
    """Return the cumulative work of the blocks carrying these bits.

    Which of two chains is best is this number's comparison, not a
    height comparison: a longer chain of easier blocks is not the one
    with the most work behind it, and only the second is expensive to
    replace. Bitcoin Core accumulates the same sum as `nChainWork`.
    """
    # every Octets is a Sequence too: passing one instead of a list of
    # them would zip through its bytes and sum the work of each as if it
    # were its own `bits` (issue #1405)
    if is_octets(bits_sequence) or not isinstance(bits_sequence, Sequence):
        raise BTClibTypeError(
            f"invalid bits sequence type: {type(bits_sequence).__name__}"
        )
    return sum(block_work(bits) for bits in bits_sequence)


def hash_rate(difficulty: float, timespan: float, block_count: int = 1) -> float:
    """Return the hashes per second a window of blocks implies.

    A block of difficulty d costs d * 2^32 hash evaluations on average,
    so `block_count` of them found over `timespan` seconds put the
    network at that many hashes per second. `BlockHeader.difficulty`
    supplies the first argument, and the timestamps of the window's ends
    the second.

    This is an estimate of a quantity nobody can measure, and a noisy
    one: hashing is a Poisson process, so the timespan of n blocks is a
    sum of n exponential intervals and its relative standard deviation
    is 1/sqrt(n) -- 100% over a single block, 8% over a day's 144, and
    still 2% over a whole 2016-block window. A number that has moved by
    less than that has not moved.

    Two things also make the inputs less solid than they look. The
    timestamps are the miners' own, constrained only by the median of
    the last eleven blocks below and two hours ahead of the node's clock
    above, so a short window's timespan can be negative in the middle of
    it; Core's `getnetworkhashps` takes the minimum and the maximum time
    over the window rather than its ends for exactly that reason. And a
    window spanning a retarget has no single difficulty to be given
    here: sum the `block_work` of the blocks in it and divide by the
    timespan instead, which is what Core does, and which this agrees
    with to within the 1/65536 by which the genesis target falls short
    of 2^224.
    """
    # the types before the three comparisons, each of which is a bare
    # TypeError about the operands for anything that is not a number. A
    # difficulty and a timespan are `float` here and an integer is one of
    # those, `1.0` and `1` being the same rate; a block count is a count,
    # so it is the narrower question -- and a bool is neither, `True`
    # being one block, one second and difficulty one
    for name, value in (("timespan", timespan), ("difficulty", difficulty)):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BTClibTypeError(f"invalid {name} type: {type(value).__name__}")
    if not is_integer(block_count):
        raise BTClibTypeError(f"invalid block count type: {type(block_count).__name__}")

    if timespan <= 0:
        raise BTClibValueError(f"invalid timespan: {timespan}")
    if block_count < 1:
        raise BTClibValueError(f"invalid block count: {block_count}")
    if difficulty <= 0:
        raise BTClibValueError(f"invalid difficulty: {difficulty}")

    return difficulty * 2**32 * block_count / timespan
