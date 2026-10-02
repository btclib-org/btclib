# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a header owes the chain before it: median time, target, ancestor.

Bitcoin Core's `CBlockIndex::GetMedianTimePast`, `GetNextWorkRequired` /
`CalculateNextWorkRequired`, and `CBlockIndex::GetAncestor`, over a header,
its height, and a callable that steps back one header at a time rather
than over an index: a batch of headers off the wire is checked before any
of it is indexed, so its own members are what the header after them is
checked against, and btclib does not learn what a block index is.

`ConsensusParams` is what tells `next_bits_required` and
`assert_not_timewarp` which network they answer for -- `pow_limit_bits`,
`pow_allow_min_difficulty_blocks`, `pow_no_retargeting`, `enforce_bip94`, and
the retarget window `pow_target_spacing`/`pow_target_timespan` -- and
`btclib.block.proof_of_work` is where the arithmetic of a single retarget
lives; this module is the walk that feeds it a period's first header and the
two chain-wide readings that do not need the whole retarget.

Bitcoin Core v31.1 (bitcoin/bitcoin@9be056a8a7) is the reference for
every rule, `src/chain.h`, `src/pow.cpp` and `src/validation.cpp`'s
`ContextualCheckBlockHeader`, cited beside the code that transcribes it.
"""

from __future__ import annotations

from collections.abc import Callable

from btclib.block.block_header import BlockHeader
from btclib.block.limits import MAX_TIMEWARP
from btclib.block.proof_of_work import next_bits
from btclib.consensus import ConsensusParams
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import _message_text, is_integer

__all__ = [
    "MEDIAN_TIME_SPAN",
    "ParentOf",
    "assert_not_timewarp",
    "header_at_height",
    "median_time_past",
    "next_bits_required",
]

# Core's CBlockIndex::nMedianTimeSpan
MEDIAN_TIME_SPAN = 11

# a header, and the one before it: whatever the callable raises for a
# header it cannot answer for is the caller's exception, since every walk
# below stops at a height it computed rather than at the callable's own
# end
ParentOf = Callable[[BlockHeader], BlockHeader]


def _block_time(header: BlockHeader) -> int:
    """Return the second the header's four timestamp bytes hold.

    Core's `CBlockHeader::GetBlockTime`. `BlockHeader.serialize` writes
    `int(time.timestamp())`, so that is the value the rules here compare:
    a header is weighed as it goes on the wire, not as it was built.
    """
    return int(header.time.timestamp())


def median_time_past(header: BlockHeader, height: int, parent_of: ParentOf) -> int:
    """Return the median timestamp of a header and its ten ancestors.

    Core's `CBlockIndex::GetMedianTimePast`, whose window is however many
    of the eleven exist: nearer the genesis than that it is the whole
    chain, and the median of an even number of times is the later of the
    two middle ones -- `sort` and take the middle index, as Core's own
    pointer arithmetic does.
    """
    if not is_integer(height):
        raise BTClibTypeError(f"invalid height type: {type(height).__name__}")
    if height < 0:
        raise BTClibValueError(f"invalid height: {_message_text(height)}")

    times = [_block_time(header)]
    for _ in range(min(MEDIAN_TIME_SPAN, height + 1) - 1):
        header = parent_of(header)
        times.append(_block_time(header))
    times.sort()
    return times[len(times) // 2]


def header_at_height(
    header: BlockHeader,
    height: int,
    target_height: int,
    parent_of: ParentOf,
) -> BlockHeader:
    """Walk back from `header`, at `height`, to its ancestor at `target_height`.

    Core's `CBlockIndex::GetAncestor`, over a skip list there; this walks
    `parent_of` one header at a time, which is the same cost
    `median_time_past` already pays to reach its own eleventh ancestor --
    unbounded here rather than capped at ten, since a caller asking for a
    BIP68 time-locked input's own coin height can name any past height,
    not only one within the last eleven blocks.
    """
    for name, value in (("height", height), ("target height", target_height)):
        if not is_integer(value):
            raise BTClibTypeError(f"invalid {name} type: {type(value).__name__}")
    if height < 0:
        raise BTClibValueError(f"invalid height: {_message_text(height)}")
    if not 0 <= target_height <= height:
        err_msg = f"invalid target height: {_message_text(target_height)}"
        err_msg += f" is not between 0 and {_message_text(height)}"
        raise BTClibValueError(err_msg)

    for _ in range(height - target_height):
        header = parent_of(header)
    return header


def _min_difficulty_bits(
    header: BlockHeader,
    parent: BlockHeader,
    parent_height: int,
    parent_of: ParentOf,
    consensus: ConsensusParams,
) -> bytes:
    """Return the target of a block on a min-difficulty-allowing chain.

    Core's own two branches of `GetNextWorkRequired`'s
    `fPowAllowMinDifficultyBlocks` case: a block more than two target
    spacings after its parent may be mined at the network's easiest
    target, and every block after it goes back to the last target that
    was not that easiest one, so that a single slow block does not make
    the rest of the period easy.
    """
    if _block_time(header) > _block_time(parent) + 2 * consensus.pow_target_spacing:
        return consensus.pow_limit_bits

    interval = consensus.difficulty_adjustment_interval
    candidate, candidate_height = parent, parent_height
    while candidate_height % interval and candidate.bits == consensus.pow_limit_bits:
        candidate = parent_of(candidate)
        candidate_height -= 1
    return candidate.bits


def _assert_valid_parent_height(parent_height: int) -> None:
    if not is_integer(parent_height):
        err_msg = f"invalid parent height type: {type(parent_height).__name__}"
        raise BTClibTypeError(err_msg)
    if parent_height < 0:
        raise BTClibValueError(f"invalid parent height: {_message_text(parent_height)}")


def assert_not_timewarp(
    header: BlockHeader,
    parent: BlockHeader,
    parent_height: int,
    consensus: ConsensusParams,
) -> None:
    """Refuse a period's first header timestamped too far behind its parent.

    Core's `time-timewarp-attack`, in `ContextualCheckBlockHeader`: where
    the network enforces BIP94 (`consensus.enforce_bip94`) and `header`
    opens a difficulty period, it must not be timestamped more than
    `MAX_TIMEWARP` seconds before `parent`. Any other header passes.

    Core asks this after bad-diffbits and time-too-old, so a caller
    checking in Core's order calls `next_bits_required`, compares, tests
    the median time past, and only then calls this.
    """
    _assert_valid_parent_height(parent_height)

    if (
        consensus.enforce_bip94
        and (parent_height + 1) % consensus.difficulty_adjustment_interval == 0
        and _block_time(header) < _block_time(parent) - MAX_TIMEWARP
    ):
        err_msg = "invalid timestamp (timewarp attack): "
        err_msg += f"{_block_time(header)} < {_block_time(parent)} - {MAX_TIMEWARP}"
        raise BTClibValueError(err_msg)


def next_bits_required(
    header: BlockHeader,
    parent: BlockHeader,
    parent_height: int,
    parent_of: ParentOf,
    consensus: ConsensusParams,
) -> bytes:
    """Return the compact target `header`, on this `parent`, has to carry.

    Core's `GetNextWorkRequired` and `CalculateNextWorkRequired` combined,
    the min-difficulty walk included: the target moves once every
    `consensus.difficulty_adjustment_interval` blocks and is the parent's
    the rest of the time, unless the network allows min-difficulty blocks,
    in which case `_min_difficulty_bits` answers instead.

    It does not check the BIP94 timewarp bound: Core asks it after
    time-too-old, so `assert_not_timewarp` is a call of its own, and the
    caller puts it where Core does (`ContextualCheckBlockHeader`,
    `src/validation.cpp` at bitcoin/bitcoin@9be056a8a7: bad-diffbits,
    time-too-old, time-timewarp-attack).

    At a period boundary and `consensus.enforce_bip94`, the retarget
    scales the period's own first target rather than the parent's,
    which is what keeps a period's real difficulty from being
    overwritten by a min-difficulty block mined at its very end.
    """
    _assert_valid_parent_height(parent_height)

    interval = consensus.difficulty_adjustment_interval
    height = parent_height + 1

    if height % interval:
        if consensus.pow_allow_min_difficulty_blocks:
            return _min_difficulty_bits(
                header, parent, parent_height, parent_of, consensus
            )
        return parent.bits

    if consensus.pow_no_retargeting:
        return parent.bits

    first_height = parent_height - (interval - 1)
    first = header_at_height(parent, parent_height, first_height, parent_of)
    base_bits = first.bits if consensus.enforce_bip94 else parent.bits
    return next_bits(
        base_bits, first.time, parent.time, pow_limit_bits=consensus.pow_limit_bits
    )
