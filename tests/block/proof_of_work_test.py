#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.block.proof_of_work` module.

Every retarget vector below is mainnet history, and every number in it
comes from one of two places, named per test:

- `bitcoin/src/test/pow_tests.cpp`, whose own comments give the height
  each timestamp belongs to. One value there is flagged by Core itself as
  "NOT an actual block time", and this file repeats the flag;
- the `_data/block_*.bin` files this directory already vendors, which
  verify themselves: `Block.parse` recomputes each hash from the bytes,
  so the `bits` taken from them are bits that satisfied real work.
"""

from datetime import datetime, timedelta, timezone
from os import path

import pytest

from btclib.block import Block
from btclib.block.proof_of_work import (
    DIFFICULTY_ADJUSTMENT_INTERVAL,
    MAINNET_POW_LIMIT_BITS,
    POW_TARGET_SPACING,
    POW_TARGET_TIMESPAN,
    REGTEST_POW_LIMIT_BITS,
    bits_from_target,
    block_work,
    chain_work,
    hash_rate,
    is_negative_bits,
    next_bits,
    retarget_first_height,
    target_from_bits,
)
from btclib.exceptions import BTClibValueError


def _time(timestamp: int) -> datetime:
    """Return the UTC datetime of a unix timestamp."""
    return datetime.fromtimestamp(timestamp, timezone.utc)


def _bits_of(fname: str) -> bytes:
    """Return the bits of a vendored block, which verifies itself."""
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()
    return Block.parse(block_bytes).header.bits


def test_consensus_parameters() -> None:
    """Verify the retarget constants and mainnet's genesis-block limit."""
    assert POW_TARGET_TIMESPAN == 14 * 24 * 60 * 60
    assert POW_TARGET_SPACING == 10 * 60
    assert DIFFICULTY_ADJUSTMENT_INTERVAL == 2016

    # mainnet's limit is the genesis block target, which is what makes
    # the genesis difficulty 1
    assert (
        target_from_bits(MAINNET_POW_LIMIT_BITS).hex()
        == f"{'00' * 4}{'ff' * 2}{'00' * 26}"
    )
    assert _bits_of("block_1.bin") == MAINNET_POW_LIMIT_BITS


def test_target_from_bits() -> None:
    """The compact form, exponent by exponent."""
    # exponent below 3: the significand shifted *down*, discarding the
    # low bytes rather than multiplying by a fractional power of 256
    assert int.from_bytes(target_from_bits("0200ffff"), "big") == 0xFFFF >> 8
    assert int.from_bytes(target_from_bits("0100ffff"), "big") == 0xFFFF >> 16
    assert int.from_bytes(target_from_bits("0000ffff"), "big") == 0

    # exponent 3 exactly: neither shift
    assert int.from_bytes(target_from_bits("0300ffff"), "big") == 0xFFFF

    # and above it
    assert int.from_bytes(target_from_bits("0400ffff"), "big") == 0xFFFF << 8

    # what 32 bytes cannot hold, which Core flags as fOverflow
    for bits in ("22ffffff", "ff000001", "fdffffff"):
        with pytest.raises(BTClibValueError, match="invalid proof-of-work target: "):
            target_from_bits(bits)

    # bits are four bytes, whatever else is handed over
    with pytest.raises(BTClibValueError, match="invalid size: 3 bytes instead of 4"):
        target_from_bits("00ffff")


def test_bits_from_target_round_trip() -> None:
    """Bits taken from real headers survive the round trip."""
    # every vendored block, i.e. every bits value this directory already
    # knows to have satisfied real work
    vendored = {
        "block_1.bin": "1d00ffff",
        "block_170.bin": "1d00ffff",
        "block_200000.bin": "1a05db8b",
        "block_481824.bin": "18013ce9",
    }
    for fname, bits_hex in vendored.items():
        bits = _bits_of(fname)
        assert bits.hex() == bits_hex
        assert bits_from_target(target_from_bits(bits)) == bits

    # the two pow limits, and the four old/new bits of the retarget
    # vectors below
    for bits_hex in (
        "1d00ffff",
        "207fffff",
        "1d00d86a",
        "1c05a3f4",
        "1c0168fd",
        "1c387f6f",
        "1d00e1fd",
    ):
        bits = bytes.fromhex(bits_hex)
        assert bits_from_target(target_from_bits(bits)) == bits


def test_bits_from_target_edges() -> None:
    """Check the compact encoding at its edges: truncation, sign bit, zero."""
    # the significand holds three bytes, so everything below them is
    # dropped and the round trip is lossy the other way: what comes back
    # is the same target or a harder one, never an easier one
    all_ones = b"\xff" * 32
    assert bits_from_target(all_ones).hex() == "2100ffff"
    assert target_from_bits("2100ffff") < all_ones

    # the sign bit: 0x800000 needs a fourth byte, because 0x03800000
    # denotes a negative number no header may carry
    assert bits_from_target((0x800000).to_bytes(32, "big")).hex() == "04008000"
    assert bits_from_target((0x7FFFFF).to_bytes(32, "big")).hex() == "037fffff"
    assert bits_from_target((0x80).to_bytes(32, "big")).hex() == "02008000"

    # a value occupying fewer than three bytes is shifted *up* into the
    # significand, which is the exponent <= 3 branch of Core's GetCompact
    assert bits_from_target("01").hex() == "01010000"
    assert bits_from_target("0102").hex() == "02010200"

    # zero occupies no bytes at all
    assert bits_from_target(b"").hex() == "00000000"
    assert bits_from_target(b"\x00" * 32).hex() == "00000000"

    # a target is 256 bits
    with pytest.raises(BTClibValueError, match="invalid target: 33 bytes"):
        bits_from_target(b"\xff" * 33)


def test_is_negative_bits() -> None:
    """Core's fNegative, the flag SetCompact reports beside the value.

    `nWord = nCompact & 0x007fffff` and `*pfNegative = nWord != 0 &&
    (nCompact & 0x00800000) != 0`, so the answers below are read off
    `arith_uint256.cpp` and not off btclib: 0x03800000 is the row that
    tells the two apart, its significand masking to zero, which is a
    number with no sign rather than a negative zero.

    The flag is asked of the four bytes and not of the target, which is
    unsigned and cannot carry it. `assert_valid_pow` is what refuses a
    header for it, as `CheckProofOfWork` does.
    """
    # every bits value this file and the vendored blocks already use
    for bits_hex in ("1d00ffff", "207fffff", "1a05db8b", "18013ce9", "2000ffff"):
        assert not is_negative_bits(bits_hex)

    # the sign bit set, over a significand that is not zero
    assert is_negative_bits("03ffffff")
    assert is_negative_bits("1d80ffff")
    assert is_negative_bits("03800001")

    # and set over one that is: no sign on zero
    assert not is_negative_bits("03800000")
    assert not is_negative_bits("1d800000")

    # bits are four bytes, whatever else is handed over
    with pytest.raises(BTClibValueError, match="invalid size: 3 bytes instead of 4"):
        is_negative_bits("00ffff")


def test_retarget_first_height() -> None:
    """The window measures 2015 intervals, not 2016.

    The pairings are Core's own: `pow_tests.cpp` puts `pindexLast` at
    height 32255 and comments its `nLastRetargetTime` with "Block
    #30240", at 68543 with "Block #66528", and at 2015 with "Block #0".
    """
    assert retarget_first_height(2015) == 0
    assert retarget_first_height(32255) == 30240
    assert retarget_first_height(68543) == 66528
    assert retarget_first_height(46367) == 44352

    # the interval is what separates the two, one short of the 2016
    # blocks the period holds
    for last in (2015, 32255, 68543):
        assert last - retarget_first_height(last) == DIFFICULTY_ADJUSTMENT_INTERVAL - 1

    # any other height ends no period, so it names no window
    for last in (0, 1, 2014, 2016, 32256):
        with pytest.raises(BTClibValueError, match="invalid retarget height: "):
            retarget_first_height(last)


def test_next_bits_mainnet_history() -> None:
    """The four retarget vectors of Core's `pow_tests.cpp`.

    Heights and timestamps are that file's, which names each height in a
    comment beside the value. The genesis timestamp is also the lower
    bound `BlockHeader.assert_valid` already enforces, and the old bits
    of the first two are those of `block_1.bin`, vendored here.
    """
    # get_next_work: the first difficulty change mainnet ever made, at
    # height 32256. Blocks #30240 and #32255, 11.8 days apart, so the
    # target tightens and difficulty goes from 1 to 1.18
    assert next_bits(
        _bits_of("block_1.bin"), _time(1261130161), _time(1262152739)
    ) == bytes.fromhex("1d00d86a")

    # get_next_work_pow_limit: blocks #0 and #2015, 23.8 days apart. The
    # target wants to grow and cannot, mainnet's limit being the genesis
    # target -- which is why the first sixteen periods all sat at
    # difficulty 1 and the change above is the first one
    assert next_bits(
        _bits_of("block_1.bin"), _time(1231006505), _time(1233061996)
    ) == bytes.fromhex("1d00ffff")

    # get_next_work_lower_limit_actual: blocks #66528 and #68543, 3.35
    # days apart, i.e. less than the quarter of two weeks the timespan is
    # clamped at. Without the clamp the target would tighten by 4.2 and
    # not by 4
    assert next_bits("1c05a3f4", _time(1279008237), _time(1279297671)) == bytes.fromhex(
        "1c0168fd"
    )

    # get_next_work_upper_limit_actual: block #46367 and a first time
    # Core's own comment flags as "NOT an actual block time" -- 70 days
    # before it, chosen to reach the other clamp. The target loosens by 4
    assert next_bits("1c387f6f", _time(1263163443), _time(1269211443)) == bytes.fromhex(
        "1d00e1fd"
    )


def test_next_bits_clamps() -> None:
    """The factor of four holds either way, whatever the timespan.

    The significand of these bits is a multiple of four and stays inside
    three bytes when quadrupled, so both clamped answers are exactly
    representable and the compact rounding is out of the way.
    """
    bits = bytes.fromhex("1b0404cc")
    first = _time(1262152739)

    quarter = timedelta(seconds=POW_TARGET_TIMESPAN // 4)
    fourfold = timedelta(seconds=POW_TARGET_TIMESPAN * 4)

    # a period mined instantly is a period mined in 3.5 days
    assert next_bits(bits, first, first) == next_bits(bits, first, first + quarter)
    # and one that took a year is one that took eight weeks
    year = timedelta(days=365)
    assert next_bits(bits, first, first + year) == next_bits(
        bits, first, first + fourfold
    )

    # the clamped answers are the old target divided and multiplied by
    # four, up to the rounding of the compact re-encoding
    target = int.from_bytes(target_from_bits(bits), "big")
    hardest = next_bits(bits, first, first)
    easiest = next_bits(bits, first, first + fourfold)
    assert int.from_bytes(target_from_bits(hardest), "big") == target // 4
    assert int.from_bytes(target_from_bits(easiest), "big") == target * 4

    # two weeks exactly changes nothing
    unchanged = next_bits(bits, first, first + timedelta(seconds=POW_TARGET_TIMESPAN))
    assert unchanged == bits


def test_next_bits_pow_limit_is_per_network() -> None:
    """The clamp is the network's, and it is what stops the loosening."""
    first = _time(1262152739)
    slow = first + timedelta(seconds=POW_TARGET_TIMESPAN * 4)

    # mainnet is already at its limit, so a period four times too slow
    # loosens it by nothing at all
    assert next_bits(MAINNET_POW_LIMIT_BITS, first, slow) == MAINNET_POW_LIMIT_BITS

    # the same target and the same period under regtest's far looser
    # limit: the factor of four is the only thing left holding it, and
    # the answer is the mainnet limit times four
    loose = next_bits(
        MAINNET_POW_LIMIT_BITS, first, slow, pow_limit_bits=REGTEST_POW_LIMIT_BITS
    )
    assert loose == bytes.fromhex("1d03fffc")
    assert int.from_bytes(target_from_bits(loose), "big") == 4 * int.from_bytes(
        target_from_bits(MAINNET_POW_LIMIT_BITS), "big"
    )


def test_next_bits_wraps_as_core_does() -> None:
    """Core multiplies in arith_uint256, and arith_uint256 wraps.

    Multiplying by the timespan and dividing by it is the identity over
    the integers and not over the 256-bit ring, which is where Core does
    it. The bits below denote 0xff * 2^248, the largest kind of target
    `SetCompact` accepts without flagging an overflow, and two weeks
    exactly is the timespan that leaves both clamps alone: the product is
    a multiple of 2^256, so the answer is a zero target rather than the
    unchanged one integer arithmetic would give.

    No chain reaches this. Every network refuses a target above its pow
    limit, and mainnet's is 2^224, so the case exists only to pin the
    ring the arithmetic happens in.
    """
    two_weeks = timedelta(seconds=POW_TARGET_TIMESPAN)
    first = _time(1262152739)

    # not an overflow: Core's SetCompact accepts it, and so does btclib
    assert target_from_bits("220000ff")[0] == 0xFF

    assert next_bits("220000ff", first, first + two_weeks) == bytes(4)


def test_block_work() -> None:
    """Work is 2^256 / (target + 1), the hashes a block is worth."""
    # the genesis block, whose difficulty is 1: 2^32 hash evaluations,
    # give or take the 1/65535 by which 0xffff falls short of 2^16
    assert block_work(MAINNET_POW_LIMIT_BITS) == 2**48 // 0xFFFF
    assert block_work(MAINNET_POW_LIMIT_BITS) == 4_295_032_833
    assert 1 < block_work(MAINNET_POW_LIMIT_BITS) / 2**32 < 1.0000153

    # a harder target is more work, and 2^32 times the difficulty is the
    # same number to within that ratio
    bits = _bits_of("block_481824.bin")
    difficulty = 888_171_856_257
    assert 1 < block_work(bits) / (difficulty * 2**32) < 1.0000153

    # no hash can satisfy a zero target, so no block can carry one.
    # Core answers 0 there, GetBlockProof doubling as the validity gate
    for bits_hex in ("00000000", "03000000", "1d000000"):
        with pytest.raises(BTClibValueError, match="zero proof-of-work target: "):
            block_work(bits_hex)


def test_chain_work() -> None:
    """Best is most work, not most blocks."""
    easy = MAINNET_POW_LIMIT_BITS
    hard = _bits_of("block_200000.bin")

    assert chain_work([]) == 0
    assert chain_work([easy, easy]) == 2 * block_work(easy)

    # ten easy blocks are a longer chain than one hard block and a
    # cheaper one to replace, which is the whole reason this is the
    # comparison and height is not
    long_and_cheap = [easy] * 10
    short_and_dear = [hard]
    assert len(long_and_cheap) > len(short_and_dear)
    assert chain_work(long_and_cheap) < chain_work(short_and_dear)


def test_hash_rate() -> None:
    """Difficulty times 2^32, over the seconds a block took."""
    # the genesis difficulty over the ten minutes aimed at: 2^32 hashes
    # in 600 seconds
    assert hash_rate(1.0, POW_TARGET_SPACING) == 2**32 / 600

    # block 481,824's difficulty, at the spacing the retarget aims at:
    # 6.36 EH/s, which is the order mainnet was hashing at in August 2017
    august_2017 = hash_rate(888_171_856_257, POW_TARGET_SPACING)
    assert 6.35e18 < august_2017 < 6.36e18

    # a window of blocks: n of them over a timespan is n times one of
    # them over the same timespan
    assert hash_rate(1.0, 2 * POW_TARGET_TIMESPAN, DIFFICULTY_ADJUSTMENT_INTERVAL) == (
        hash_rate(1.0, 2 * POW_TARGET_TIMESPAN) * DIFFICULTY_ADJUSTMENT_INTERVAL
    )
    # a window mined in half the time it aimed at doubles the estimate
    full = hash_rate(1.0, POW_TARGET_TIMESPAN, DIFFICULTY_ADJUSTMENT_INTERVAL)
    half = hash_rate(1.0, POW_TARGET_TIMESPAN // 2, DIFFICULTY_ADJUSTMENT_INTERVAL)
    assert half == 2 * full

    # the same window measured through the work of its blocks, which is
    # what Core's getnetworkhashps sums: the two agree to the 1/65536 the
    # genesis target falls short of 2^224 by
    through_work = chain_work([MAINNET_POW_LIMIT_BITS] * 4) / POW_TARGET_TIMESPAN
    through_difficulty = hash_rate(1.0, POW_TARGET_TIMESPAN, 4)
    assert 1 < through_work / through_difficulty < 1.0000153


def test_hash_rate_exceptions() -> None:
    """Refuse a non-positive timespan, a zero count, a zero difficulty."""
    # no timespan, no rate: Core's getnetworkhashps returns 0 when the
    # window's ends carry the same time, and a negative one is what
    # miner-supplied timestamps can produce
    for timespan in (0, -1.0):
        with pytest.raises(BTClibValueError, match="invalid timespan: "):
            hash_rate(1.0, timespan)

    with pytest.raises(BTClibValueError, match="invalid block count: "):
        hash_rate(1.0, 600.0, 0)

    with pytest.raises(BTClibValueError, match="invalid difficulty: "):
        hash_rate(0.0, 600.0)
