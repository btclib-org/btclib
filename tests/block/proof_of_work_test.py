# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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
from pathlib import Path

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
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()
    return Block.parse(block_bytes).header.bits


def test_consensus_parameters() -> None:
    """Verify the retarget constants and mainnet's genesis-block limit."""
    assert POW_TARGET_TIMESPAN == 14 * 24 * 60 * 60
    assert POW_TARGET_SPACING == 10 * 60
    assert DIFFICULTY_ADJUSTMENT_INTERVAL == 2016
    # a `//` weakened to `/` still equals 2016, floating point being exact
    # at this size, but is no longer the int retarget_first_height's own
    # subtraction wants
    assert isinstance(DIFFICULTY_ADJUSTMENT_INTERVAL, int)

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


@pytest.mark.parametrize(
    "bits_hex, target_hex, negative",
    [
        # the genesis bits, where the sign bit is not set and nothing
        # about them changes
        ("1d00ffff", f"{'00' * 4}{'ff' * 2}{'00' * 26}", False),
        # the sign bit alone, in the significand's own byte: masked off,
        # so the number is 0x7fffff and not 0xffffff
        ("03ffffff", f"{'00' * 29}7fffff", True),
        # a significand that is nothing but the sign bit is zero, which
        # is why Core's fNegative asks nWord != 0 as well
        ("03800000", "00" * 32, False),
        # the genesis bits signed: the same target, not one 2^7 easier
        ("1d80ffff", f"{'00' * 4}{'ff' * 2}{'00' * 26}", True),
        # the magnitude is read after the exponent, as Core reads it: the
        # one byte left of the masked significand is shifted out
        ("018000ff", "00" * 32, False),
        # regtest's limit signed, and the target above it unchanged
        ("20ffffff", f"7fffff{'00' * 29}", True),
    ],
)
def test_target_from_bits_sign_bit(
    bits_hex: str, target_hex: str, negative: bool
) -> None:
    """The sign bit of nBits is a sign, and not the target's high bit.

    Core's `SetCompact` masks the significand with 0x007fffff and reports
    0x00800000 through its `fNegative` out-parameter; the rows are its
    values for the same input, `target_from_bits` answering the number
    and `is_negative_bits` the flag (issue #402).
    """
    assert target_from_bits(bits_hex).hex() == target_hex
    assert is_negative_bits(bits_hex) is negative

    # the sign does not survive the round trip, and cannot: bits_from_target
    # never emits a negative encoding, which is what its docstring is about
    assert not is_negative_bits(bits_from_target(target_from_bits(bits_hex)))


def _set_compact(n_compact: int) -> tuple[int, bool, bool]:
    """Return what Core's `arith_uint256::SetCompact` computes.

    A transcription of the reference, value and both out-parameters,
    kept here rather than folded into vectors: the claim being checked is
    that btclib agrees with it over the whole four-byte space, and a
    handful of hard-coded numbers cannot say that. The value wraps, as
    the arith_uint256 it is assigned to does.
    """
    n_size = n_compact >> 24
    n_word = n_compact & 0x007FFFFF
    if n_size <= 3:
        n_word >>= 8 * (3 - n_size)
        value = n_word
    else:
        value = n_word << (8 * (n_size - 3))
    negative = n_word != 0 and (n_compact & 0x00800000) != 0
    overflow = n_word != 0 and (
        n_size > 34
        or (n_word > 0xFF and n_size > 33)
        or (n_word > 0xFFFF and n_size > 32)
    )
    return value % 2**256, negative, overflow


def test_target_from_bits_agrees_with_set_compact() -> None:
    """Every exponent against Core's SetCompact, sign bit included.

    The significands are the edges: zero, the smallest, the byte and
    two-byte boundaries the overflow rule reads, and each of them with
    the sign bit set. Where Core flags an overflow btclib raises instead,
    which is the same refusal and is asserted as such -- and where it
    does not, the two numbers and the two flags must agree.
    """
    significands = (
        0x000000,
        0x000001,
        0x0000FF,
        0x000100,
        0x00FFFF,
        0x010000,
        0x123456,
        0x7FFFFF,
    )
    for exponent in range(0x100):
        for significand in significands:
            for sign in (0, 0x800000):
                n_compact = (exponent << 24) | sign | significand
                bits = n_compact.to_bytes(4, "big")
                value, negative, overflow = _set_compact(n_compact)

                assert is_negative_bits(bits) is negative, bits.hex()
                if overflow:
                    err_msg = "invalid proof-of-work target: "
                    with pytest.raises(BTClibValueError, match=err_msg):
                        target_from_bits(bits)
                else:
                    assert int.from_bytes(target_from_bits(bits), "big") == value, (
                        bits.hex()
                    )


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

    # exponent 4 exactly, the first value of the *other* branch: `<= 3`
    # weakened to `<= 4` sends it through the left shift above instead,
    # by a negative amount, which is not a quiet wrong answer but a
    # `ValueError` of its own
    assert bits_from_target((0x01000000).to_bytes(32, "big")).hex() == "04010000"

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


def test_next_bits_reads_the_pow_limit_unsigned() -> None:
    """A pow_limit past 2^255 is read as itself, not as its negative twin.

    `min(target, pow_limit)` has nothing downstream to wrap a misread
    back into range the way the multiplication two lines above does for
    `target` itself (see `test_next_bits_wraps_as_core_does`): a signed
    read of `pow_limit_bits` here raises trying to re-encode a negative
    result instead of leaving the small, unclamped target alone.
    """
    first = _time(1262152739)
    two_weeks = timedelta(seconds=POW_TARGET_TIMESPAN)
    assert (
        next_bits(
            MAINNET_POW_LIMIT_BITS,
            first,
            first + two_weeks,
            pow_limit_bits="2100ffff",
        )
        == MAINNET_POW_LIMIT_BITS
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

    # the ring is 2^256 and not 2^255: this target's bit 255 is the one
    # the product's wrap carries into the quotient, which a `% 2**256`
    # weakened to `% 2**255` drops before the floor division ever sees
    # it, changing an unchanged two-week period into a wrong one instead
    assert next_bits(
        "1e080000", first, first + two_weeks, pow_limit_bits=REGTEST_POW_LIMIT_BITS
    ) == bytes.fromhex("1e080000")


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

    # every target above is within a whisker of 2^224, where `target + 1`
    # and `target - 1` floor-divide 2^256 to the same integer -- a target
    # this small is what tells the `+ 1` the formula is written on from
    # the `- 1` that would only fail loudly at target 1, never silently
    small_target_bits = bits_from_target((2).to_bytes(32, "big"))
    assert block_work(small_target_bits) == 2**256 // 3

    # target 1, odd rather than even: `+ 1` weakened to `| 1` or `^ 1`
    # agrees with it on every even target, 2 above included, and only an
    # odd one tells the three apart (2 vs 1 vs 0 for a target of 1)
    odd_target_bits = bits_from_target((1).to_bytes(32, "big"))
    assert block_work(odd_target_bits) == 2**256 // 2

    # a target past 2^255, the sign bit of a 32-byte signed read: nothing
    # downstream masks or wraps this one back, unlike `next_bits`'s own
    # `int.from_bytes` of a target, see there
    assert block_work("2100ffff") == 1


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
    # zero and negative are refused by two different comparisons, and
    # zero alone does not tell `<= 0` from `== 0`
    with pytest.raises(BTClibValueError, match="invalid difficulty: "):
        hash_rate(-1.0, 600.0)

    # 1 is the smallest timespan `<= 0` accepts; `<= 1` would refuse it
    assert hash_rate(1.0, 1.0) > 0
