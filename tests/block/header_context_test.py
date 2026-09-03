# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.block.header_context` module.

The four `next_bits_required` mainnet vectors are Bitcoin Core's own
`src/test/pow_tests.cpp`, at bitcoin/bitcoin@9be056a8a7 (v31.1): each
puts a real height, timestamp and `bits` beside the retarget it computed
from them, and the comment names the block each timestamp belongs to.
Every chain built to carry one is a placeholder except at the two
heights the vector names -- `next_bits_required` reads only the parent
and the period's first header, so what sits between them cannot change
the answer, only the cost of the walk to it.

Every other test is synthetic, over headers built with
`check_validity=False`: the proof-of-work these rules read from a header
is the timestamp and the `bits`, and Core's own algorithm is checked
against a target no chain would ever hand out just as readily as
against a real one.
"""

import dataclasses
import secrets
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

import pytest

from btclib.block.block_header import BlockHeader
from btclib.block.header_context import (
    MEDIAN_TIME_SPAN,
    ParentOf,
    header_at_height,
    median_time_past,
    next_bits_required,
)
from btclib.block.limits import MAX_TIMEWARP
from btclib.block.proof_of_work import next_bits
from btclib.consensus import CONSENSUS_PARAMS, ConsensusParams
from btclib.exceptions import BTClibTypeError, BTClibValueError

MAIN = CONSENSUS_PARAMS["mainnet"]
TESTNET = CONSENSUS_PARAMS["testnet"]
TESTNET4 = CONSENSUS_PARAMS["testnet4"]
REGTEST = CONSENSUS_PARAMS["regtest"]

POW_LIMIT = MAIN.pow_limit_bits
REGTEST_POW_LIMIT = REGTEST.pow_limit_bits
# 2^216, three bytes into the compact form and a quarter and four times of
# it as well, so any retarget answer is read straight off the exponent
HARD = b"\x1c\x01\x00\x00"

EPOCH = datetime.fromtimestamp(1231006505, timezone.utc)  # the mainnet genesis time


def _time(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp, timezone.utc)


def _small_interval(
    *,
    enforce_bip94: bool,
    pow_no_retargeting: bool,
    pow_allow_min_difficulty_blocks: bool = True,
) -> ConsensusParams:
    """Return a row with a four-block difficulty period.

    A row of `CONSENSUS_PARAMS` with `pow_target_spacing` and
    `pow_target_timespan` replaced so `difficulty_adjustment_interval` is
    4 rather than 2016 or 144 -- short enough that a test builds a whole
    period without a two-thousand-header chain -- and with the three
    boolean rules a caller of this function is asking about, which
    `TESTNET4` does not carry the combination of. `pow_limit_bits` stays
    testnet4's.
    """
    return dataclasses.replace(
        TESTNET4,
        pow_target_spacing=600,
        pow_target_timespan=600 * 4,
        enforce_bip94=enforce_bip94,
        pow_no_retargeting=pow_no_retargeting,
        pow_allow_min_difficulty_blocks=pow_allow_min_difficulty_blocks,
    )


def _header(previous_block_hash: bytes, time: datetime, bits: bytes) -> BlockHeader:
    """Build a header, skipping the proof-of-work check.

    `check_validity=False` is what lets a test hand it a target no chain
    hands out.
    """
    return BlockHeader(
        version=1,
        previous_block_hash=previous_block_hash,
        merkle_root=secrets.token_bytes(32),
        time=time,
        bits=bits,
        nonce=1,
        check_validity=False,
    )


def a_chain(
    times: Sequence[datetime], bits: Sequence[bytes]
) -> tuple[list[BlockHeader], ParentOf]:
    """Return headers at heights 0, 1, ... and the walk back over them."""
    headers: list[BlockHeader] = []
    previous_block_hash = b"\x00" * 32
    for time, header_bits in zip(times, bits, strict=True):
        header = _header(previous_block_hash, time, header_bits)
        headers.append(header)
        previous_block_hash = header.hash
    by_hash = {header.hash: header for header in headers}

    def parent_of(header: BlockHeader) -> BlockHeader:
        return by_hash[header.previous_block_hash]

    return headers, parent_of


# ---------------------------------------------------------------------------
# median_time_past


def test_the_median_of_a_chain_shorter_than_the_window() -> None:
    """Below height ten the window is the whole chain, not a fixed eleven.

    Core's `GetMedianTimePast` stops at `pindex` becoming null, which is
    the same as this stopping once `parent_of` has nothing further back.
    """
    times = [EPOCH + timedelta(seconds=s) for s in (0, 10, 20, 30)]
    headers, parent_of = a_chain(times, [POW_LIMIT] * 4)
    assert median_time_past(headers[0], 0, parent_of) == int(times[0].timestamp())
    assert median_time_past(headers[1], 1, parent_of) == int(times[1].timestamp())
    assert median_time_past(headers[3], 3, parent_of) == int(times[2].timestamp())


def test_the_median_of_eleven_is_not_the_last_of_them() -> None:
    """The window sorts the eleven rather than trusting a miner's clock.

    A miner's own timestamp need not be increasing, so the median of a
    full eleven-block window is not simply the newest header's time.
    """
    seconds = [0, 1000, 2000, 300, 400, 500, 600, 700, 800, 900, 100, 950]
    times = [EPOCH + timedelta(seconds=s) for s in seconds]
    headers, parent_of = a_chain(times, [POW_LIMIT] * len(times))
    window = sorted(seconds[1:])
    expected = int(
        (EPOCH + timedelta(seconds=window[MEDIAN_TIME_SPAN // 2])).timestamp()
    )
    assert median_time_past(headers[-1], len(times) - 1, parent_of) == expected


def test_a_header_is_weighed_by_the_second_it_serializes_as() -> None:
    """A fraction of a second is truncated, as `BlockHeader.serialize` does.

    The four wire bytes hold a whole second, so a header carrying a
    fraction of one past that is compared as it goes on the wire.
    """
    header = _header(b"\x00" * 32, EPOCH, POW_LIMIT)
    header.time += timedelta(microseconds=999_999)
    headers, parent_of = a_chain([header.time], [POW_LIMIT])
    assert median_time_past(headers[0], 0, parent_of) == int(EPOCH.timestamp())


def test_median_time_past_refuses_a_height_that_is_not_one() -> None:
    """A non-integer or negative height is refused before the walk."""
    headers, _ = a_chain([EPOCH], [POW_LIMIT])
    header = headers[0]
    for not_a_height in ("0", None, 1.5):
        with pytest.raises(BTClibTypeError, match="invalid height type: "):
            median_time_past(header, not_a_height, lambda h: h)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="invalid height: -1"):
        median_time_past(header, -1, lambda h: h)


# ---------------------------------------------------------------------------
# header_at_height


def test_header_at_height_walks_back_to_the_target_height() -> None:
    """A target height of zero, the height itself, and one in between."""
    times = [EPOCH + timedelta(seconds=600 * h) for h in range(5)]
    headers, parent_of = a_chain(times, [POW_LIMIT] * 5)
    assert header_at_height(headers[4], 4, 0, parent_of) is headers[0]
    assert header_at_height(headers[4], 4, 4, parent_of) is headers[4]
    assert header_at_height(headers[4], 4, 2, parent_of) is headers[2]


def test_header_at_height_refuses_a_target_height_outside_the_range() -> None:
    """A target height above the header's own, or a negative one, or type."""
    headers, parent_of = a_chain([EPOCH, EPOCH], [POW_LIMIT] * 2)
    with pytest.raises(BTClibValueError, match="invalid target height: 5"):
        header_at_height(headers[1], 1, 5, parent_of)
    with pytest.raises(BTClibValueError, match="invalid target height: -1"):
        header_at_height(headers[1], 1, -1, parent_of)
    with pytest.raises(BTClibValueError, match="invalid height: -1"):
        header_at_height(headers[1], -1, 0, parent_of)
    for not_a_height in ("1", None, 1.5):
        with pytest.raises(BTClibTypeError, match="invalid height type: "):
            header_at_height(headers[1], not_a_height, 0, parent_of)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="invalid target height type: "):
            header_at_height(headers[1], 1, not_a_height, parent_of)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# next_bits_required -- Bitcoin Core's own mainnet vectors


def _period(
    first_time: datetime,
    parent_time: datetime,
    parent_bits: bytes,
) -> tuple[BlockHeader, BlockHeader, ParentOf]:
    """Build a whole mainnet difficulty period ending at `parent`.

    Only the first header returned and `parent` carry the vector's own
    time; every block between them is a placeholder a minute apart, which
    `next_bits_required` never reads -- it asks `header_at_height` for
    the first header and nothing else.
    """
    interval = MAIN.difficulty_adjustment_interval
    times = [first_time + timedelta(minutes=i) for i in range(interval - 1)] + [
        parent_time
    ]
    bits = ([POW_LIMIT] * (interval - 1)) + [parent_bits]
    headers, parent_of = a_chain(times, bits)
    return headers[0], headers[-1], parent_of


@pytest.mark.parametrize(
    "parent_height, first_time, parent_time, parent_bits, expected",
    [
        # get_next_work: Block #30240 to Block #32255
        (32255, 1261130161, 1262152739, "1d00ffff", "1d00d86a"),
        # get_next_work_pow_limit: Block #0 to Block #2015, already at limit
        (2015, 1231006505, 1233061996, "1d00ffff", "1d00ffff"),
        # get_next_work_lower_limit_actual: Block #66528 to Block #68543
        (68543, 1279008237, 1279297671, "1c05a3f4", "1c0168fd"),
        # get_next_work_upper_limit_actual: Block #44352 (flagged by Core
        # itself as "NOT an actual block time") to Block #46367
        (46367, 1263163443, 1269211443, "1c387f6f", "1d00e1fd"),
    ],
)
def test_next_bits_required_matches_cores_own_mainnet_vectors(
    parent_height: int,
    first_time: int,
    parent_time: int,
    parent_bits: str,
    expected: str,
) -> None:
    """Reproduce one of Core's own `pow_tests.cpp` retarget vectors."""
    _first, parent, parent_of = _period(
        _time(first_time), _time(parent_time), bytes.fromhex(parent_bits)
    )
    # next_bits_required does not read the candidate's own bits, only its
    # time; check_validity=False is what lets it carry an arbitrary one
    candidate = _header(parent.hash, parent.time, bytes.fromhex(parent_bits))
    assert next_bits_required(
        candidate, parent, parent_height, parent_of, MAIN
    ) == bytes.fromhex(expected)


# ---------------------------------------------------------------------------
# next_bits_required -- off a retarget boundary


def test_between_two_retargets_the_target_is_the_parents() -> None:
    """Off a boundary, with no min-difficulty rule, the target holds."""
    headers, parent_of = a_chain([EPOCH, EPOCH + timedelta(seconds=600)], [HARD, HARD])
    candidate = _header(headers[1].hash, EPOCH + timedelta(seconds=1200), HARD)
    assert next_bits_required(candidate, headers[1], 1, parent_of, MAIN) == HARD


def test_a_chain_that_does_not_retarget_keeps_the_target_it_has() -> None:
    """`pow_no_retargeting` is checked at the boundary, answers the parent's."""
    consensus = _small_interval(
        enforce_bip94=False,
        pow_no_retargeting=True,
        pow_allow_min_difficulty_blocks=False,
    )
    interval = consensus.difficulty_adjustment_interval
    headers, parent_of = a_chain(
        [EPOCH + timedelta(seconds=600 * h) for h in range(interval)],
        [HARD] * interval,
    )
    parent = headers[-1]
    candidate = _header(parent.hash, parent.time + timedelta(seconds=600), HARD)
    assert (
        next_bits_required(candidate, parent, interval - 1, parent_of, consensus)
        == HARD
    )


# ---------------------------------------------------------------------------
# next_bits_required -- the minimum-difficulty rule


def test_a_slow_block_may_be_mined_at_the_limit() -> None:
    """More than two target spacings after the parent, the limit is allowed."""
    headers, parent_of = a_chain([EPOCH, EPOCH + timedelta(seconds=600)], [HARD, HARD])
    parent = headers[1]
    late = parent.time + timedelta(seconds=2 * TESTNET.pow_target_spacing + 1)
    on_time = parent.time + timedelta(seconds=2 * TESTNET.pow_target_spacing)
    assert (
        next_bits_required(
            _header(parent.hash, late, HARD), parent, 1, parent_of, TESTNET
        )
        == TESTNET.pow_limit_bits
    )
    # one second sooner is not enough
    assert (
        next_bits_required(
            _header(parent.hash, on_time, HARD), parent, 1, parent_of, TESTNET
        )
        == HARD
    )


def test_the_block_after_a_min_difficulty_one_goes_back_to_the_real_target() -> None:
    """A min-difficulty block does not make the rest of the period easy."""
    times = [EPOCH + timedelta(seconds=600 * h) for h in range(4)]
    headers, parent_of = a_chain(
        times, [HARD, HARD, TESTNET.pow_limit_bits, TESTNET.pow_limit_bits]
    )
    parent = headers[-1]
    candidate = _header(parent.hash, parent.time + timedelta(seconds=600), HARD)
    assert next_bits_required(candidate, parent, 3, parent_of, TESTNET) == HARD


def test_the_walk_back_stops_at_the_genesis() -> None:
    """A chain mined at the limit from block zero has no easier target."""
    headers, parent_of = a_chain(
        [EPOCH, EPOCH + timedelta(seconds=600)], [TESTNET.pow_limit_bits] * 2
    )
    parent = headers[1]
    candidate = _header(parent.hash, parent.time + timedelta(seconds=600), HARD)
    assert (
        next_bits_required(candidate, parent, 1, parent_of, TESTNET)
        == TESTNET.pow_limit_bits
    )


def test_regtest_min_difficulty_rule_applies_despite_no_retargeting() -> None:
    """The min-difficulty rule fires on regtest even though it never retargets.

    Core's `GetNextWorkRequired` reads `fPowAllowMinDifficultyBlocks`
    before it ever looks at `fPowNoRetargeting`, which only gates
    `CalculateNextWorkRequired` at a period boundary: a slow block off a
    boundary is answered by the min-difficulty branch regardless. A
    caller returning the parent's own bits whenever
    `pow_no_retargeting` is set, without checking the height first, would
    answer `HARD` here instead of the network's limit.
    """
    headers, parent_of = a_chain([EPOCH, EPOCH + timedelta(seconds=600)], [HARD, HARD])
    parent = headers[1]
    late = parent.time + timedelta(seconds=2 * REGTEST.pow_target_spacing + 1)
    candidate = _header(parent.hash, late, HARD)
    assert (
        next_bits_required(candidate, parent, 1, parent_of, REGTEST)
        == REGTEST_POW_LIMIT
    )


def test_regtest_min_difficulty_walk_stops_at_its_own_144_block_boundary() -> None:
    """The walk-back's stop condition reads regtest's own 144-block interval.

    Heights 0 to 143 carry a non-limit target and 144 to 150 the network
    limit; asked at height 151 (off any boundary), the walk from the
    parent back through the limit-carrying blocks has to stop at height
    144 -- a boundary under regtest's own `pow_target_timespan` of one
    day, 144 blocks, but not under the 2016-block interval every other
    network uses. A walk using the wrong interval would not stop there
    and would answer `HARD`, the target the blocks below 144 carry,
    instead of the limit height 144 itself carries.
    """
    assert REGTEST.difficulty_adjustment_interval == 144
    times = [EPOCH + timedelta(seconds=600 * h) for h in range(151)]
    bits = [HARD] * 144 + [REGTEST_POW_LIMIT] * 7
    headers, parent_of = a_chain(times, bits)
    parent = headers[150]
    on_time = parent.time + timedelta(seconds=2 * REGTEST.pow_target_spacing)
    candidate = _header(parent.hash, on_time, REGTEST_POW_LIMIT)
    assert (
        next_bits_required(candidate, parent, 150, parent_of, REGTEST)
        == REGTEST_POW_LIMIT
    )


# ---------------------------------------------------------------------------
# next_bits_required -- BIP94


def test_bip94_rebases_the_retarget_on_the_periods_first_target() -> None:
    """Under BIP94 the retarget scales the period's own first bits.

    Core's `CalculateNextWorkRequired`: `bnNew.SetCompact(pindexFirst->nBits)`
    rather than `pindexLast->nBits`, so a min-difficulty block mined at
    the very end of the period does not make the whole period's
    difficulty look easier than it was.
    """
    consensus = _small_interval(enforce_bip94=True, pow_no_retargeting=False)
    interval = consensus.difficulty_adjustment_interval
    times = [EPOCH + timedelta(seconds=600 * h) for h in range(interval)]
    bits = [HARD] * (interval - 1) + [consensus.pow_limit_bits]
    headers, parent_of = a_chain(times, bits)
    parent = headers[-1]
    candidate_time = parent.time + timedelta(seconds=600)
    candidate = _header(parent.hash, candidate_time, HARD)

    expected = next_bits(
        HARD, headers[0].time, parent.time, pow_limit_bits=consensus.pow_limit_bits
    )
    assert (
        next_bits_required(candidate, parent, interval - 1, parent_of, consensus)
        == expected
    )
    # and it is not simply the parent's own bits scaled instead
    not_bip94 = next_bits(
        parent.bits,
        headers[0].time,
        parent.time,
        pow_limit_bits=consensus.pow_limit_bits,
    )
    assert expected != not_bip94


def test_bip94_refuses_a_period_opening_too_far_behind_its_parent() -> None:
    """time-timewarp-attack: a new period must not open too early.

    Core's `ContextualCheckBlockHeader`, `enforce_BIP94` branch: the
    first block of a new difficulty period must not be timestamped more
    than `MAX_TIMEWARP` seconds behind `pindexPrev->GetBlockTime()`.
    """
    consensus = _small_interval(enforce_bip94=True, pow_no_retargeting=False)
    interval = consensus.difficulty_adjustment_interval
    times = [EPOCH + timedelta(seconds=600 * h) for h in range(interval)]
    headers, parent_of = a_chain(times, [HARD] * interval)
    parent = headers[-1]

    too_early = parent.time - timedelta(seconds=MAX_TIMEWARP + 1)
    candidate = _header(parent.hash, too_early, HARD)
    with pytest.raises(BTClibValueError, match="timewarp attack"):
        next_bits_required(candidate, parent, interval - 1, parent_of, consensus)

    # exactly at the bound is not refused
    at_bound = parent.time - timedelta(seconds=MAX_TIMEWARP)
    candidate = _header(parent.hash, at_bound, HARD)
    next_bits_required(candidate, parent, interval - 1, parent_of, consensus)


def test_bip94_timewarp_check_is_independent_of_no_retargeting() -> None:
    """`-test=bip94` on regtest sets both flags at once, Core's own combination.

    `enforce_BIP94` and `fPowNoRetargeting` are read by two different
    functions in Core (`ContextualCheckBlockHeader` and
    `CalculateNextWorkRequired`), so a chain with both set still refuses
    the timewarped header even though its retarget is always a no-op.
    """
    consensus = _small_interval(enforce_bip94=True, pow_no_retargeting=True)
    interval = consensus.difficulty_adjustment_interval
    times = [EPOCH + timedelta(seconds=600 * h) for h in range(interval)]
    headers, parent_of = a_chain(times, [HARD] * interval)
    parent = headers[-1]

    too_early = parent.time - timedelta(seconds=MAX_TIMEWARP + 1)
    candidate = _header(parent.hash, too_early, HARD)
    with pytest.raises(BTClibValueError, match="timewarp attack"):
        next_bits_required(candidate, parent, interval - 1, parent_of, consensus)


def test_bip94_off_the_boundary_is_not_checked() -> None:
    """The timewarp bound only applies to a period's first block."""
    consensus = _small_interval(enforce_bip94=True, pow_no_retargeting=False)
    headers, parent_of = a_chain([EPOCH, EPOCH + timedelta(seconds=600)], [HARD, HARD])
    parent = headers[1]
    way_early = parent.time - timedelta(seconds=MAX_TIMEWARP * 10)
    candidate = _header(parent.hash, way_early, HARD)
    # height 2 is not a multiple of the four-block interval, so this is
    # answered instead of refused
    assert next_bits_required(candidate, parent, 1, parent_of, consensus) == HARD


# ---------------------------------------------------------------------------
# next_bits_required -- input validation


def test_next_bits_required_refuses_a_parent_height_that_is_not_one() -> None:
    """A non-integer or negative parent height is refused up front."""
    headers, parent_of = a_chain([EPOCH], [POW_LIMIT])
    candidate = _header(headers[0].hash, EPOCH, POW_LIMIT)
    for not_a_height in ("0", None, 1.5):
        with pytest.raises(BTClibTypeError, match="invalid parent height type: "):
            next_bits_required(
                candidate,
                headers[0],
                not_a_height,  # type: ignore[arg-type]
                parent_of,
                MAIN,
            )
    with pytest.raises(BTClibValueError, match="invalid parent height: -1"):
        next_bits_required(candidate, headers[0], -1, parent_of, MAIN)
