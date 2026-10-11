# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Properties of the retarget, median time past and the BIP94 timewarp bound.

Each holds for every input the strategies draw; `proof_of_work_test.py` and
`header_context_test.py` check chosen cases. The rules are those of Bitcoin
Core v31.1 (bitcoin/bitcoin@9be056a8a7):

- `pow_transition` in `src/test/fuzz/pow.cpp`: the target
  `CalculateNextWorkRequired` gives is one `PermittedDifficultyTransition`
  permits;
- `CalculateNextWorkRequired` in `src/pow.cpp`: at most four times the old
  target and at most the proof-of-work limit;
- `CBlockIndex::GetMedianTimePast` in `src/chain.h`;
- `ContextualCheckBlockHeader`'s `time-timewarp-attack` in
  `src/validation.cpp`.
"""

import statistics
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib.block.block_header import BlockHeader
from btclib.block.header_context import (
    assert_not_timewarp,
    median_time_past,
)
from btclib.block.limits import MAX_TIMEWARP
from btclib.block.proof_of_work import (
    next_bits,
    permitted_difficulty_transition,
    target_from_bits,
)
from btclib.consensus import CONSENSUS_PARAMS, ConsensusParams
from btclib.exceptions import BTClibValueError

EPOCH = datetime.fromtimestamp(0, UTC)

# the networks that retarget by the rule `permitted_difficulty_transition`
# bounds: the others allow a block at the easiest target or never retarget
RETARGETING = [CONSENSUS_PARAMS["mainnet"], CONSENSUS_PARAMS["signet"]]
RETARGETING_IDS = ["mainnet", "signet"]

_UINT32 = st.integers(min_value=0, max_value=0xFFFFFFFF)

# Core's CBlockIndex::nMedianTimeSpan
MEDIAN_TIME_SPAN = 11

# a timestamp is four bytes on the wire
TIMES = _UINT32.map(lambda t: EPOCH + timedelta(seconds=t))


def _target(bits: bytes) -> int:
    return int.from_bytes(target_from_bits(bits), "big")


def _bits_up_to(pow_limit_bits: bytes) -> st.SearchStrategy[bytes]:
    """Draw four bytes, the limit's bits standing in for a larger target.

    Core's `pow_transition` fuzz target does the same.

    The exponent byte is drawn up to the limit's, so that the targets
    spread over the range and the odd encodings (sign bit, zero, small
    exponents) stay. No such value overflows 256 bits.
    """

    def clamp(bits: bytes) -> bytes:
        return bits if _target(bits) <= _target(pow_limit_bits) else pow_limit_bits

    return st.builds(
        lambda exponent, significand: bytes([exponent]) + significand,
        st.integers(min_value=0, max_value=pow_limit_bits[0]),
        st.binary(min_size=3, max_size=3),
    ).map(clamp)


@pytest.mark.parametrize("consensus", RETARGETING, ids=RETARGETING_IDS)
@given(data=st.data())
def test_a_retarget_is_a_permitted_transition(
    consensus: ConsensusParams, data: st.DataObject
) -> None:
    """`next_bits` gives what `permitted_difficulty_transition` permits."""
    bits = data.draw(_bits_up_to(consensus.pow_limit_bits))
    first, last = data.draw(TIMES), data.draw(TIMES)
    periods = data.draw(st.integers(min_value=1, max_value=10**6))
    height = periods * consensus.difficulty_adjustment_interval

    new_bits = next_bits(bits, first, last, pow_limit_bits=consensus.pow_limit_bits)

    assert permitted_difficulty_transition(consensus, height, bits, new_bits)


@pytest.mark.parametrize("consensus", RETARGETING, ids=RETARGETING_IDS)
@given(data=st.data())
def test_a_retarget_is_at_most_four_times_the_target_and_the_limit(
    consensus: ConsensusParams, data: st.DataObject
) -> None:
    """The new target is at most four times the old one and the limit."""
    bits = data.draw(_bits_up_to(consensus.pow_limit_bits))
    first, last = data.draw(TIMES), data.draw(TIMES)

    new_bits = next_bits(bits, first, last, pow_limit_bits=consensus.pow_limit_bits)

    assert _target(new_bits) <= 4 * _target(bits)
    assert _target(new_bits) <= _target(consensus.pow_limit_bits)


@pytest.mark.parametrize("consensus", RETARGETING, ids=RETARGETING_IDS)
@given(data=st.data())
def test_a_longer_period_never_gives_a_smaller_target(
    consensus: ConsensusParams, data: st.DataObject
) -> None:
    """The new target does not decrease as the timespan grows."""
    bits = data.draw(_bits_up_to(consensus.pow_limit_bits))
    first = data.draw(TIMES)
    short, long = sorted(
        data.draw(st.integers(min_value=-(2**32), max_value=2**32)) for _ in range(2)
    )

    shorter = next_bits(
        bits,
        first,
        first + timedelta(seconds=short),
        pow_limit_bits=consensus.pow_limit_bits,
    )
    longer = next_bits(
        bits,
        first,
        first + timedelta(seconds=long),
        pow_limit_bits=consensus.pow_limit_bits,
    )

    assert _target(shorter) <= _target(longer)


def _chain(times: list[int]) -> tuple[BlockHeader, dict[bytes, BlockHeader]]:
    """Return the tip of a chain of these timestamps, and its headers."""
    headers: list[BlockHeader] = []
    previous_block_hash = bytes(32)
    for height, time in enumerate(times):
        header = BlockHeader(
            version=1,
            previous_block_hash=previous_block_hash,
            merkle_root=height.to_bytes(32, "big"),
            time=EPOCH + timedelta(seconds=time),
            check_validity=False,
        )
        headers.append(header)
        previous_block_hash = header.hash
    return headers[-1], {header.hash: header for header in headers}


@given(times=st.lists(_UINT32, min_size=1, max_size=3 * MEDIAN_TIME_SPAN))
def test_the_median_time_past_is_the_upper_middle_of_the_last_eleven(
    times: list[int],
) -> None:
    """The median is taken over the last eleven timestamps, or all of them."""
    tip, by_hash = _chain(times)

    mtp = median_time_past(
        tip, len(times) - 1, lambda header: by_hash[header.previous_block_hash]
    )

    assert mtp == statistics.median_high(times[-MEDIAN_TIME_SPAN:])


@pytest.mark.parametrize("consensus", CONSENSUS_PARAMS.values(), ids=CONSENSUS_PARAMS)
@given(data=st.data())
def test_a_timewarp_is_refused_where_bip94_is_enforced(
    consensus: ConsensusParams, data: st.DataObject
) -> None:
    """A period's first header over `MAX_TIMEWARP` behind its parent fails."""
    interval = consensus.difficulty_adjustment_interval
    parent_height = data.draw(
        st.one_of(
            st.integers(min_value=0, max_value=10**7),
            st.tuples(
                st.integers(min_value=1, max_value=10**5),
                st.sampled_from([0, 0, 0, -1, 1]),
            ).map(lambda k_offset: k_offset[0] * interval - 1 + k_offset[1]),
        )
    )
    parent_time = data.draw(_UINT32)
    # on the bound, either side of it, and anywhere
    behind = data.draw(
        st.one_of(
            st.sampled_from([MAX_TIMEWARP - 1, MAX_TIMEWARP, MAX_TIMEWARP + 1]),
            st.integers(min_value=-2000, max_value=2000),
            st.integers(min_value=-(2**32), max_value=2**32),
        )
    )
    time = min(max(parent_time - behind, 0), 0xFFFFFFFF)
    behind = parent_time - time

    parent = BlockHeader(
        time=EPOCH + timedelta(seconds=parent_time), check_validity=False
    )
    header = BlockHeader(time=EPOCH + timedelta(seconds=time), check_validity=False)

    refused = (
        consensus.enforce_bip94
        and (parent_height + 1) % interval == 0
        and behind > MAX_TIMEWARP
    )
    if refused:
        with pytest.raises(BTClibValueError, match="timewarp attack"):
            assert_not_timewarp(header, parent, parent_height, consensus)
    else:
        assert_not_timewarp(header, parent, parent_height, consensus)
