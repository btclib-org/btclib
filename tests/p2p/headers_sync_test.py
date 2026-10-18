# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib.p2p.headers_sync`, Core's `HeadersSyncState`.

Core's own `headers_sync_chainwork_tests`
(`src/test/headers_sync_chainwork_tests.cpp`, at
bitcoin/bitcoin@310071f8d0, the v32.0rc4 tag) are ported first, constant
for constant, then btclib-node's tests of its copy of this class
(`tests/unit/p2p/headers_sync_test.py`, at
btclib-org/btclib-node@eb2a8851), where they test the state machine and
not the node.

`HeadersSyncState` checks no header's own proof of work -- its caller
does -- so the chains here are built unsolved, which is what lets them
be as long as Core's own test chains. The offset and the salt are drawn
from `secrets` when a sync is built and read only once headers arrive,
so a test sets them right after building it.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from btclib.block.block_header import BlockHeader
from btclib.block.genesis import genesis_block
from btclib.block.limits import MAX_FUTURE_BLOCK_TIME
from btclib.block.proof_of_work import block_work
from btclib.consensus import CONSENSUS_PARAMS, ConsensusParams, HeadersSyncParams
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256, siphash
from btclib.p2p.headers_sync import (
    ChainStart,
    HeadersSyncState,
    ProcessingResult,
    State,
    _BitQueue,
    anti_dos_work_threshold,
)
from btclib.p2p.limits import MAX_HEADERS_RESULTS

_REGTEST = CONSENSUS_PARAMS["regtest"]
_GENESIS = genesis_block("regtest").header
_WORK = block_work(_GENESIS.bits)  # every regtest header's own work
_START = ChainStart(_GENESIS, 0, _WORK, 0, (_GENESIS.hash,))
_SALT = (0x0706050403020100, 0x0F0E0D0C0B0A0908)
_NOW = datetime.fromtimestamp(10**9, UTC)


def at(seconds: float) -> datetime:
    """Return the instant `seconds` after the epoch, as an aware datetime."""
    return datetime.fromtimestamp(seconds, UTC)


def unsolved_chain(
    count: int,
    start: BlockHeader = _GENESIS,
    *,
    merkle_root: bytes = b"\x00" * 32,
    bits: bytes | None = None,
) -> list[BlockHeader]:
    """Return `count` headers off `start`, a second apart, none of them mined.

    `merkle_root` tells two chains off the same start apart, as Core's own
    test does.
    """
    chain: list[BlockHeader] = []
    previous = start
    for _ in range(count):
        header = BlockHeader(
            version=start.version,
            previous_block_hash=previous.hash,
            merkle_root=merkle_root,
            time=previous.time + timedelta(seconds=1),
            bits=start.bits if bits is None else bits,
            nonce=0,
            check_validity=False,
        )
        chain.append(header)
        previous = header
    return chain


def state_of(sync: HeadersSyncState) -> State:
    """Read `sync.state` again, which mypy would otherwise take as unchanged.

    An `assert` on the state narrows it, and a later method call moving it
    does not widen it back.
    """
    return sync.state


def fixed(
    sync: HeadersSyncState, offset: int = 0, salt: tuple[int, int] = _SALT
) -> HeadersSyncState:
    """Set the offset and the salt a sync drew, before it takes a header."""
    sync._commit_offset = offset
    sync._salt = salt
    return sync


def a_sync(
    required_blocks: int,
    *,
    period: int = 600,
    buffer: int = 100,
    offset: int = 0,
    consensus: ConsensusParams = _REGTEST,
    start: ChainStart = _START,
    now: datetime = _NOW,
    salt: tuple[int, int] = _SALT,
) -> HeadersSyncState:
    """Build a sync from regtest's genesis, towards `required_blocks` of work.

    `required_blocks` counts the genesis, whose work the chain start
    carries.
    """
    sync = HeadersSyncState(
        consensus,
        HeadersSyncParams(commitment_period=period, redownload_buffer_size=buffer),
        start,
        required_blocks * _WORK,
        now=now,
    )
    return fixed(sync, offset, salt)


def check(
    result: ProcessingResult,
    sync: HeadersSyncState,
    state: State,
    *,
    success: bool,
    request_more: bool,
    released: int,
    first_released_prev: bytes | None,
    locator_head: bytes | None,
) -> None:
    """Core's `CHECK_RESULT`, argument for argument."""
    assert sync.state is state
    assert result.success is success
    assert result.request_more is request_more
    assert len(result.pow_validated_headers) == released
    if first_released_prev is None:
        assert released == 0
    else:
        assert result.pow_validated_headers[0].previous_block_hash == (
            first_released_prev
        )
    if locator_head is None:
        assert state is State.FINAL
    else:
        assert sync.next_headers_request_locator[0] == locator_head


# Core's own constants, which its comments explain: the redownload buffer
# well below the blocks the work needs, and a period close to mainnet's
_TARGET_BLOCKS = 15_000
_REDOWNLOAD_BUFFER_SIZE = _TARGET_BLOCKS - (MAX_HEADERS_RESULTS + 123)
_COMMITMENT_PERIOD = 600


@pytest.fixture(scope="module")
def first_chain() -> list[BlockHeader]:
    """Core's `FirstChain`: the work Core's test asks for, genesis in."""
    return unsolved_chain(_TARGET_BLOCKS - 1)


@pytest.fixture(scope="module")
def second_chain() -> list[BlockHeader]:
    """Core's `SecondChain`: another root, one header short of the work."""
    return unsolved_chain(_TARGET_BLOCKS - 2, merkle_root=b"\x01" + b"\x00" * 31)


def core_s_state() -> HeadersSyncState:
    """Core's `CreateState`, the offset and the salt fixed."""
    return a_sync(
        _TARGET_BLOCKS, period=_COMMITMENT_PERIOD, buffer=_REDOWNLOAD_BUFFER_SIZE
    )


def test_sneaky_redownload(
    first_chain: list[BlockHeader], second_chain: list[BlockHeader]
) -> None:
    """Core's `sneaky_redownload`: another chain in REDOWNLOAD is caught.

    The salt is fixed here, so the one chance in 2^25 that every
    commitment matches by accident, which Core's test runs, is not run.
    """
    sync = core_s_state()
    check(
        sync.process_next_headers(first_chain[:1], full_headers_message=True),
        sync,
        State.PRESYNC,
        success=True,
        request_more=True,
        released=0,
        first_released_prev=None,
        locator_head=first_chain[0].hash,
    )
    check(
        sync.process_next_headers(first_chain[1:], full_headers_message=True),
        sync,
        State.REDOWNLOAD,
        success=True,
        request_more=True,
        released=0,
        first_released_prev=None,
        locator_head=_GENESIS.hash,
    )
    check(
        sync.process_next_headers(second_chain, full_headers_message=True),
        sync,
        State.FINAL,
        success=False,
        request_more=False,
        released=0,
        first_released_prev=None,
        locator_head=None,
    )


@pytest.mark.parametrize("full_headers_message", [False, True])
def test_happy_path(
    first_chain: list[BlockHeader],
    full_headers_message: bool,
) -> None:
    """Core's `happy_path`: the chain redownloaded is released, all of it."""
    sync = core_s_state()
    check(
        sync.process_next_headers(
            first_chain, full_headers_message=full_headers_message
        ),
        sync,
        State.REDOWNLOAD,
        success=True,
        request_more=True,
        released=0,
        first_released_prev=None,
        locator_head=_GENESIS.hash,
    )
    check(
        sync.process_next_headers(
            first_chain[:_REDOWNLOAD_BUFFER_SIZE], full_headers_message=True
        ),
        sync,
        State.REDOWNLOAD,
        success=True,
        request_more=True,
        released=0,
        first_released_prev=None,
        locator_head=first_chain[_REDOWNLOAD_BUFFER_SIZE - 1].hash,
    )
    check(
        sync.process_next_headers(
            first_chain[_REDOWNLOAD_BUFFER_SIZE : _REDOWNLOAD_BUFFER_SIZE + 1],
            full_headers_message=True,
        ),
        sync,
        State.REDOWNLOAD,
        success=True,
        request_more=True,
        released=1,
        first_released_prev=_GENESIS.hash,
        locator_head=first_chain[_REDOWNLOAD_BUFFER_SIZE].hash,
    )
    result = sync.process_next_headers(
        first_chain[_REDOWNLOAD_BUFFER_SIZE + 1 :],
        full_headers_message=full_headers_message,
    )
    check(
        result,
        sync,
        State.FINAL,
        success=True,
        request_more=False,
        released=len(first_chain) - 1,
        first_released_prev=first_chain[0].hash,
        locator_head=None,
    )
    # and the headers released are the chain's own, byte for byte
    assert [
        h.serialize(check_validity=False) for h in result.pow_validated_headers
    ] == [h.serialize(check_validity=False) for h in first_chain[1:]]


def test_too_little_work(second_chain: list[BlockHeader]) -> None:
    """Core's `too_little_work`: a chain ending short of the work, no error."""
    sync = core_s_state()
    assert sync.state is State.PRESYNC
    check(
        sync.process_next_headers(second_chain[:1], full_headers_message=True),
        sync,
        State.PRESYNC,
        success=True,
        request_more=True,
        released=0,
        first_released_prev=None,
        locator_head=second_chain[0].hash,
    )
    check(
        sync.process_next_headers(second_chain[1:], full_headers_message=False),
        sync,
        State.FINAL,
        success=True,
        request_more=False,
        released=0,
        first_released_prev=None,
        locator_head=None,
    )


def test_system_clock_lagging_behind_chain_start() -> None:
    """Core's `system_clock_lagging_behind_chain_start`, to the second.

    Core truncates the time since the chain start toward zero, so half a
    second more behind is not a second behind.
    """
    mtp = 1_296_688_602
    start = replace(_START, median_time_past=mtp)
    a_sync(1, start=start, now=at(mtp - MAX_FUTURE_BLOCK_TIME))
    a_sync(1, start=start, now=at(mtp - MAX_FUTURE_BLOCK_TIME - 0.5))
    with pytest.raises(BTClibValueError, match="120 minutes behind"):
        a_sync(1, start=start, now=at(mtp - MAX_FUTURE_BLOCK_TIME - 1))


def test_the_commitment_is_core_s_siphash_of_the_uint256() -> None:
    """The bit is SipHash's over the hash in Core's own byte order.

    Core's `PresaltedSipHasher` vector (`src/test/hash_tests.cpp`, at
    bitcoin/bitcoin@9be056a8a7, the v31.1 tag): its `uint256` is written
    the way `BlockHeader.hash` displays a hash. Over a chain's hashes the
    bit is the one of that order, and not of the displayed one, which
    gives a different bit for some of them.
    """
    displayed = bytes.fromhex(
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
    )
    assert siphash(*_SALT, displayed[::-1]) == 0x7127512F72F27CCE
    sync = a_sync(1)
    hashes = [header.hash for header in unsolved_chain(32)]
    assert [sync._commitment(h[::-1]) for h in hashes] == [
        siphash(*_SALT, h[::-1]) & 1 for h in hashes
    ]
    assert any(siphash(*_SALT, h[::-1]) & 1 != siphash(*_SALT, h) & 1 for h in hashes)


def test_presync_keeps_the_bit_core_keeps() -> None:
    """What PRESYNC keeps is the bit of each committed header's own hash."""
    chain = unsolved_chain(40)
    sync = a_sync(100, period=1)
    assert sync.process_next_headers(chain, full_headers_message=True).success
    queue = sync._commitments
    assert [queue.popleft() for _ in chain] == [
        siphash(*_SALT, h.hash[::-1]) & 1 for h in chain
    ]


def bounded(now: float, median_time_past: int = 0) -> HeadersSyncState:
    """Return a sync committing every sixth header, at `now`.

    At a period of six, Core's bound of six blocks a second since the
    start, plus `MAX_FUTURE_BLOCK_TIME`, is one commitment a second.
    """
    start = replace(_START, median_time_past=median_time_past)
    return a_sync(1000, period=6, buffer=10, start=start, now=at(now))


@pytest.mark.parametrize("now, taken", [(-7189, True), (-7190, False)])
def test_the_bound_on_commitments_is_six_blocks_a_second_since_the_start(
    now: int,
    taken: bool,
) -> None:
    """Core's `m_max_commitments`, the future-time allowance included.

    Sixty-six headers commit eleven times at a period of six: eleven
    seconds' worth of chain is enough, ten is one commitment past the
    bound, and the sync ends there.
    """
    sync = bounded(now)
    result = sync.process_next_headers(unsolved_chain(66), full_headers_message=True)
    assert result.success is taken
    assert (sync.state is State.FINAL) is not taken


@pytest.mark.parametrize("now, taken", [(-7189, True), (-7190, False)])
def test_the_bound_counts_from_the_chain_start_s_median_time_past(
    now: int,
    taken: bool,
) -> None:
    """The start's median time past, not the clock alone, bounds the chain."""
    late = 10**9
    sync = bounded(late + now, median_time_past=late)
    result = sync.process_next_headers(unsolved_chain(66), full_headers_message=True)
    assert result.success is taken


def test_a_clock_at_the_allowance_s_edge_allows_no_commitment() -> None:
    """A clock exactly `MAX_FUTURE_BLOCK_TIME` behind bounds the chain at none.

    It is not refused, Core's refusal being of a negative bound: the first
    commitment is one too many, and the header before it is taken.
    """
    sync = bounded(-MAX_FUTURE_BLOCK_TIME)
    chain = unsolved_chain(6)
    assert sync.process_next_headers(chain[:5], full_headers_message=True).success
    assert not sync.process_next_headers(chain[5:], full_headers_message=True).success


def test_the_bound_truncates_a_clock_finer_than_a_second_toward_zero() -> None:
    """Core's `Ticks<std::chrono::seconds>`: a fraction behind is no second.

    Eleven seconds' worth of chain from a clock 7189.999 seconds behind,
    where a floor would make it 7190 and ten.
    """
    sync = bounded(-7189.999)
    result = sync.process_next_headers(unsolved_chain(66), full_headers_message=True)
    assert result.success is True


def test_the_offset_and_the_salt_are_drawn_from_secrets() -> None:
    """The offset falls in the period and the salt is two 64-bit keys.

    Across 64 syncs, every key is below 2^64 and some reaches 2^63. A
    narrower key fails the second check, a wider one fails the first but
    for a chance of 2^-64, and a 64-bit key fails the second with a chance
    of 2^-64. And some offset is not zero, which fails with a chance of
    7^-64.
    """
    keys = []
    offsets = []
    for _ in range(64):
        sync = HeadersSyncState(_REGTEST, HeadersSyncParams(7, 10), _START, 0, now=_NOW)
        assert 0 <= sync._commit_offset < 7
        offsets.append(sync._commit_offset)
        keys.append(sync._salt)
    assert any(offsets)
    for column in zip(*keys, strict=True):
        assert all(0 <= key < 2**64 for key in column)
        assert any(key >= 2**63 for key in column)


def test_the_clock_and_the_batch_size_are_keywords_alone() -> None:
    """What decides the answer cannot be passed by position by mistake."""
    with pytest.raises(TypeError):
        HeadersSyncState(  # type: ignore[call-arg]
            _REGTEST, HeadersSyncParams(7, 10), _START, 0, _NOW
        )
    with pytest.raises(TypeError):
        a_sync(1).process_next_headers(unsolved_chain(1), True)  # type: ignore[call-arg]


def test_a_full_presync_batch_asks_on_from_its_last_header() -> None:
    """PRESYNC asks from the last header taken, then the start's own locator."""
    start_locator = (b"\x0a" * 32, _GENESIS.hash)
    sync = a_sync(100, start=replace(_START, locator=start_locator))
    chain = unsolved_chain(3)
    check(
        sync.process_next_headers(chain, full_headers_message=True),
        sync,
        State.PRESYNC,
        success=True,
        request_more=True,
        released=0,
        first_released_prev=None,
        locator_head=chain[-1].hash,
    )
    assert sync.next_headers_request_locator == [chain[-1].hash, *start_locator]
    assert sync.presync_height == 3
    assert sync.presync_work == 4 * _WORK
    assert sync.presync_time == chain[-1].time


def test_a_short_presync_batch_ends_the_sync_without_an_error() -> None:
    """A short batch below the work ends it: taken, nothing released."""
    sync = a_sync(100)
    check(
        sync.process_next_headers(unsolved_chain(3), full_headers_message=False),
        sync,
        State.FINAL,
        success=True,
        request_more=False,
        released=0,
        first_released_prev=None,
        locator_head=None,
    )


def off(parent: bytes) -> BlockHeader:
    """Return a header on `parent`, a hash the sync need not know."""
    return BlockHeader(
        version=1,
        previous_block_hash=parent,
        merkle_root=b"\x00" * 32,
        time=_GENESIS.time + timedelta(seconds=1),
        bits=_GENESIS.bits,
        nonce=0,
        check_validity=False,
    )


def _with(header: BlockHeader, **fields: Any) -> BlockHeader:
    """Return a copy of `header` with `fields` rebound, unchecked."""
    copy = BlockHeader(
        header.version,
        header.previous_block_hash,
        header.merkle_root,
        header.time,
        header.bits,
        header.nonce,
        check_validity=False,
    )
    for key, value in fields.items():
        setattr(copy, key, value)
    return copy


_BELOW, _ABOVE = b"\x00" * 32, b"\xff" * 32


@pytest.mark.parametrize("parent", [_BELOW, _ABOVE], ids=["below", "above"])
def test_a_presync_batch_not_building_on_the_last_header_ends_the_sync(
    parent: bytes,
) -> None:
    """PRESYNC's own continuity, against the last header it took."""
    sync = a_sync(100)
    assert sync.process_next_headers(
        unsolved_chain(2), full_headers_message=True
    ).success
    result = sync.process_next_headers([off(parent)], full_headers_message=True)
    assert result == ProcessingResult([], success=False, request_more=False)
    assert sync.state is State.FINAL
    # Core's `Finalize` zeroes the height, as its getter then reports
    assert sync.presync_height == 0


def test_a_presync_batch_broken_inside_ends_the_sync() -> None:
    """Every header of a PRESYNC batch builds on the one before it.

    Core asks the first header alone and leaves the rest to its caller;
    here a batch whose third header builds on the first ends the sync,
    and the two taken before it are counted.
    """
    chain = unsolved_chain(2)
    (fork,) = unsolved_chain(1, chain[0], merkle_root=b"\x02" * 32)
    sync = a_sync(100)
    result = sync.process_next_headers([*chain, fork], full_headers_message=True)
    assert result == ProcessingResult([], success=False, request_more=False)
    assert sync.state is State.FINAL
    assert sync.presync_work == 3 * _WORK


def _no_min_difficulty() -> ConsensusParams:
    """Regtest's consensus, told to check difficulty transitions."""
    return replace(_REGTEST, pow_allow_min_difficulty_blocks=False)


# A start at mainnet's own starting target, since four times regtest's
# overflows the 256 bits Core's retarget arithmetic wraps at, and a
# target one step harder, which a retarget may move to and nothing else
_HARD = BlockHeader(
    version=1,
    previous_block_hash=b"\x00" * 32,
    merkle_root=b"\x00" * 32,
    time=_GENESIS.time,
    bits=bytes.fromhex("1d00ffff"),
    nonce=0,
    check_validity=False,
)
_HARDER = bytes.fromhex("1d00fffe")
_HARDEST = bytes.fromhex("1d00fffd")


def at_143() -> HeadersSyncState:
    """Return a sync checking transitions, from `_HARD` at regtest's 143."""
    work = block_work(_HARD.bits)
    sync = HeadersSyncState(
        _no_min_difficulty(),
        HeadersSyncParams(600, 100),
        ChainStart(_HARD, 143, work, 0, (_HARD.hash,)),
        3 * work,
        now=_NOW,
    )
    return fixed(sync)


def test_a_presync_header_changing_its_bits_off_a_retarget_ends_the_sync() -> None:
    """PRESYNC asks `permitted_difficulty_transition` of every header."""
    chain = unsolved_chain(2)
    chain += unsolved_chain(1, chain[-1], bits=bytes.fromhex("207ffffe"))
    assert a_sync(100).process_next_headers(chain, full_headers_message=True).success
    strict = a_sync(100, consensus=_no_min_difficulty())
    result = strict.process_next_headers(chain, full_headers_message=True)
    assert result.success is False
    assert strict.state is State.FINAL
    # the transition is asked of the header's own height: regtest retargets
    # every 144, so a sync starting at 143 takes the change at 144
    changed = unsolved_chain(1, _HARD, bits=_HARDER)
    assert at_143().process_next_headers(changed, full_headers_message=True).success


def test_the_work_reaching_the_threshold_exactly_moves_to_redownload() -> None:
    """At the threshold, not above it, and even from a short batch.

    A short batch reaching the work still asks for more: the chain is
    wanted again from its start.
    """
    below = a_sync(5)
    result = below.process_next_headers(unsolved_chain(3), full_headers_message=True)
    assert below.state is State.PRESYNC
    assert result.request_more
    exact = a_sync(5)
    result = exact.process_next_headers(unsolved_chain(4), full_headers_message=False)
    assert exact.state is State.REDOWNLOAD
    assert result == ProcessingResult([], success=True, request_more=True)
    assert exact.next_headers_request_locator == [_GENESIS.hash, _GENESIS.hash]


def redownloading(
    required_blocks: int, chain: list[BlockHeader], **kwargs: Any
) -> HeadersSyncState:
    """Return a sync that took `chain` in PRESYNC and now redownloads it."""
    sync = a_sync(required_blocks, **kwargs)
    assert sync.process_next_headers(chain, full_headers_message=True).success
    assert sync.state is State.REDOWNLOAD
    return sync


def test_redownload_holds_the_buffer_and_releases_past_it() -> None:
    """Held while the buffer is not over its size, released one past it.

    The first released header is rebuilt on the chain start, and each
    later one on the one before it.
    """
    chain = unsolved_chain(20)
    sync = redownloading(21, chain, buffer=5)
    check(
        sync.process_next_headers(chain[:5], full_headers_message=True),
        sync,
        State.REDOWNLOAD,
        success=True,
        request_more=True,
        released=0,
        first_released_prev=None,
        locator_head=chain[4].hash,
    )
    result = sync.process_next_headers(chain[5:7], full_headers_message=True)
    check(
        result,
        sync,
        State.REDOWNLOAD,
        success=True,
        request_more=True,
        released=2,
        first_released_prev=_GENESIS.hash,
        locator_head=chain[6].hash,
    )
    assert [h.hash for h in result.pow_validated_headers] == [
        chain[0].hash,
        chain[1].hash,
    ]
    assert sync.next_headers_request_locator == [chain[6].hash, _GENESIS.hash]
    # the height PRESYNC reached is what is reported while redownloading
    assert sync.presync_height == 20


def test_reaching_the_target_releases_every_header_held() -> None:
    """The header reaching the work releases the whole buffer and ends it."""
    chain = unsolved_chain(20)
    sync = redownloading(21, chain, buffer=100)
    assert not sync.process_next_headers(
        chain[:19], full_headers_message=True
    ).pow_validated_headers
    result = sync.process_next_headers(chain[19:], full_headers_message=True)
    check(
        result,
        sync,
        State.FINAL,
        success=True,
        request_more=False,
        released=20,
        first_released_prev=_GENESIS.hash,
        locator_head=None,
    )


def test_a_header_past_the_target_is_released_with_it() -> None:
    """A chain grown since PRESYNC runs out of commitments past the target.

    The target is reached at the tenth header; the commitments cover what
    PRESYNC saw and no more, and none is asked from the target on.
    """
    chain = unsolved_chain(30)
    sync = redownloading(11, chain[:10], period=2, offset=1)
    result = sync.process_next_headers(chain, full_headers_message=False)
    check(
        result,
        sync,
        State.FINAL,
        success=True,
        request_more=False,
        released=30,
        first_released_prev=_GENESIS.hash,
        locator_head=None,
    )


def differing_salt(first: BlockHeader, second: BlockHeader) -> tuple[int, int]:
    """Return a salt under which the two headers' commitment bits differ."""
    return next(
        (k, k)
        for k in range(100)
        if siphash(k, k, first.hash[::-1]) & 1 != siphash(k, k, second.hash[::-1]) & 1
    )


def test_the_target_header_itself_is_not_checked_against_a_commitment() -> None:
    """Core sets the flag before the commitment is asked, at the same header.

    PRESYNC reaches the work at the tenth header, which is also its one
    commitment at a period of ten. The redownload serves another tenth
    header, whose bit differs: it reaches the target, so its commitment is
    never asked, and the sync ends with it released.
    """
    chain = unsolved_chain(10)
    (other,) = unsolved_chain(1, chain[8], merkle_root=b"\x01" * 32)
    salt = differing_salt(chain[9], other)
    sync = redownloading(11, chain, period=10, offset=0, salt=salt)
    result = sync.process_next_headers([*chain[:9], other], full_headers_message=True)
    assert result.success
    assert [h.hash for h in result.pow_validated_headers] == [
        *(h.hash for h in chain[:9]),
        other.hash,
    ]


def a_bit_apart(first: BlockHeader, second: BlockHeader, bit: int) -> tuple[int, int]:
    """Return a salt committing `first` to `bit` and `second` to the other."""
    return next(
        (k, k)
        for k in range(200)
        if siphash(k, k, first.hash[::-1]) & 1 == bit
        and siphash(k, k, second.hash[::-1]) & 1 != bit
    )


@pytest.mark.parametrize("kept", [0, 1])
def test_another_chain_in_redownload_is_a_commitment_mismatch(kept: int) -> None:
    """A redownloaded header whose bit is not the one kept ends the sync.

    Every header commits at a period of one; the fifth header of another
    chain, the last of its batch, carries the other bit, whichever of the
    two PRESYNC kept, after four that match.
    """
    chain = unsolved_chain(10)
    (other,) = unsolved_chain(1, chain[3], merkle_root=b"\x01" * 32)
    salt = a_bit_apart(chain[4], other, kept)
    sync = redownloading(11, chain, period=1, offset=0, salt=salt)
    result = sync.process_next_headers([*chain[:4], other], full_headers_message=True)
    assert result == ProcessingResult([], success=False, request_more=False)
    assert sync.state is State.FINAL


def test_a_commitment_asked_with_none_left_is_an_overrun() -> None:
    """More committed heights in REDOWNLOAD than PRESYNC kept ends the sync.

    PRESYNC reaches the work in a chain whose commitments this test then
    empties; the first committed height of the redownload, the last of
    its batch, finds none.
    """
    chain = unsolved_chain(10)
    sync = redownloading(11, chain, period=1, offset=0)
    sync._commitments = _BitQueue()
    result = sync.process_next_headers(chain[:1], full_headers_message=True)
    assert result.success is False
    assert sync.state is State.FINAL


@pytest.mark.parametrize("parent", [_BELOW, _ABOVE], ids=["below", "above"])
def test_a_redownloaded_header_not_building_on_the_buffer_ends_the_sync(
    parent: bytes,
) -> None:
    """REDOWNLOAD's own continuity, against the last header buffered."""
    chain = unsolved_chain(10)
    sync = redownloading(11, chain)
    assert sync.process_next_headers(chain[:3], full_headers_message=True).success
    result = sync.process_next_headers([off(parent)], full_headers_message=True)
    assert result.success is False
    assert sync.state is State.FINAL


def test_a_redownload_crossing_the_threshold_without_meeting_it_releases_all() -> None:
    """The target is reached at or past the work, whichever lands first.

    An odd threshold, which regtest's work of two a block never lands on.
    """
    chain = unsolved_chain(5)
    sync = fixed(
        HeadersSyncState(
            _REGTEST, HeadersSyncParams(600, 100), _START, 5 * _WORK + 1, now=_NOW
        )
    )
    assert sync.process_next_headers(chain, full_headers_message=True).success
    assert sync.state is State.REDOWNLOAD
    result = sync.process_next_headers(chain, full_headers_message=True)
    assert len(result.pow_validated_headers) == 5
    assert state_of(sync) is State.FINAL


def test_an_empty_buffer_before_the_target_still_asks_for_more() -> None:
    """Core ends the sync on an empty buffer only once the target is reached.

    A buffer of none releases every header as it is checked, the target
    still ahead.
    """
    chain = unsolved_chain(10)
    sync = redownloading(11, chain, buffer=0)
    result = sync.process_next_headers(chain[:3], full_headers_message=True)
    assert len(result.pow_validated_headers) == 3
    assert result.request_more
    assert sync.state is State.REDOWNLOAD


def test_a_redownloaded_header_changing_its_bits_ends_the_sync() -> None:
    """REDOWNLOAD asks the transition of every header, as PRESYNC does."""
    chain = unsolved_chain(10)
    sync = redownloading(11, chain, consensus=_no_min_difficulty())
    assert sync.process_next_headers(chain[:2], full_headers_message=True).success
    changed = unsolved_chain(1, chain[1], bits=bytes.fromhex("207ffffe"))
    assert not sync.process_next_headers(changed, full_headers_message=True).success
    assert sync.state is State.FINAL


def test_the_first_redownloaded_header_is_weighed_against_the_chain_start() -> None:
    """An empty buffer takes the chain start's own bits as the previous ones."""
    chain = unsolved_chain(10)
    sync = redownloading(11, chain, consensus=_no_min_difficulty())
    changed = unsolved_chain(1, bits=bytes.fromhex("207ffffe"))
    assert not sync.process_next_headers(changed, full_headers_message=True).success


def test_a_later_redownloaded_header_is_weighed_against_the_buffer() -> None:
    """Past the first, the previous bits are the buffer's last header's.

    Regtest retargets every 144 blocks. From a start at 143, the header
    at 144 changes its bits, as a retarget may, and so does the one at
    288; the one at 289 keeps them. Weighed against the start's own bits,
    or against the buffer's first header, it would be refused.
    """
    chain = unsolved_chain(1, _HARD, bits=_HARDER)
    chain += unsolved_chain(144, chain[-1], bits=_HARDER)[:143]
    chain += unsolved_chain(2, chain[-1], bits=_HARDEST)
    sync = at_143()
    sync._minimum_required_work = sum(block_work(h.bits) for h in [_HARD, *chain])
    assert sync.process_next_headers(chain, full_headers_message=True).success
    assert sync.state is State.REDOWNLOAD
    assert sync.process_next_headers(chain, full_headers_message=True).success


def test_a_short_redownload_batch_before_the_target_ends_the_sync() -> None:
    """A peer declining to serve again what it served once is given up on.

    Taken, and what the buffer released is still released.
    """
    chain = unsolved_chain(20)
    sync = redownloading(21, chain, buffer=2)
    result = sync.process_next_headers(chain[:5], full_headers_message=False)
    check(
        result,
        sync,
        State.FINAL,
        success=True,
        request_more=False,
        released=3,
        first_released_prev=_GENESIS.hash,
        locator_head=None,
    )


def test_an_ended_sync_takes_nothing_and_asks_nothing() -> None:
    """Core's `Assume` guards, answered without ending anything further."""
    sync = a_sync(100)
    assert sync.process_next_headers([], full_headers_message=True) == (
        ProcessingResult([], success=False, request_more=False)
    )
    assert sync.state is State.PRESYNC
    sync.process_next_headers(unsolved_chain(1), full_headers_message=False)
    assert state_of(sync) is State.FINAL
    assert sync.next_headers_request_locator == []
    assert sync.process_next_headers(unsolved_chain(1), full_headers_message=True) == (
        ProcessingResult([], success=False, request_more=False)
    )


def test_a_sync_ended_in_redownload_takes_nothing_more() -> None:
    """Not even the next header of the chain it was redownloading.

    A short batch ends the redownload; the header after it builds on the
    last one buffered, and is refused with nothing released.
    """
    chain = unsolved_chain(20)
    sync = redownloading(21, chain, buffer=2)
    sync.process_next_headers(chain[:5], full_headers_message=False)
    assert sync.state is State.FINAL
    assert sync.process_next_headers(chain[5:6], full_headers_message=True) == (
        ProcessingResult([], success=False, request_more=False)
    )


def test_a_header_btclib_would_refuse_survives_the_buffer() -> None:
    """Taken and rebuilt unchecked, as Core copies the fields it holds.

    A time before genesis is btclib's own refusal, which Core leaves to
    `ContextualCheckBlockHeader`'s `time-too-old` when the header is
    indexed, so the sync does not ask btclib either way.
    """
    early = _GENESIS.time.replace(year=2000)
    header = BlockHeader(
        version=4,
        previous_block_hash=_GENESIS.hash,
        merkle_root=b"\x00" * 32,
        time=early,
        bits=_GENESIS.bits,
        nonce=0,
        check_validity=False,
    )
    with pytest.raises(BTClibValueError, match="before genesis"):
        header.assert_valid()
    sync = redownloading(2, [header])
    result = sync.process_next_headers([header], full_headers_message=True)
    (rebuilt,) = result.pow_validated_headers
    assert rebuilt.time == early
    assert rebuilt.hash == header.hash


def test_the_bit_queue_gives_back_what_it_took_in_order() -> None:
    """Packed eight to an octet, across octet boundaries, first in first out."""
    bits = [1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1]
    queue = _BitQueue()
    for bit in bits:
        queue.append(bit)
    assert len(queue) == len(bits)
    assert len(queue._octets) == 2
    assert [queue.popleft() for _ in range(4)] == bits[:4]
    assert len(queue) == len(bits) - 4
    assert [queue.popleft() for _ in bits[4:]] == bits[4:]
    assert not queue


def test_the_redownload_buffer_holds_headers_compressed() -> None:
    """The buffer holds Core's 48-byte `CompressedHeader`, not a `BlockHeader`.

    The serialized header less its parent's hash, read off the buffer
    after a redownload held short of both the buffer's size and the
    target.
    """
    buffered = 2_000
    chain = unsolved_chain(buffered + 10)
    sync = redownloading(buffered + 11, chain, buffer=buffered)
    result = sync.process_next_headers(chain[:buffered], full_headers_message=True)
    assert not result.pow_validated_headers
    entries = sync._redownloaded_headers
    assert len(entries) == buffered
    assert all(type(entry) is bytes for entry in entries)
    raw = chain[0].serialize(check_validity=False)
    assert entries[0] == raw[:4] + raw[36:]


def test_a_commitment_offset_past_256_is_kept_and_checked() -> None:
    """The height is compared by value: a small-int identity stops at 256.

    Kept at height 300 in PRESYNC, and checked there in REDOWNLOAD: a
    header of another chain at 300, its bit differing, is refused.
    """
    chain = unsolved_chain(310)
    (other,) = unsolved_chain(1, chain[298], merkle_root=b"\x01" * 32)
    salt = differing_salt(chain[299], other)
    sync = redownloading(311, chain, period=400, offset=300, salt=salt)
    assert len(sync._commitments) == 1
    result = sync.process_next_headers([*chain[:299], other], full_headers_message=True)
    assert result.success is False


@pytest.mark.parametrize("offset", [0, 3])
def test_the_commitment_offset_is_where_presync_and_redownload_both_look(
    offset: int,
) -> None:
    """A header off the offset is never checked; one on it is.

    Period four: the other chain's header at the height the offset names
    is refused, and one at any other height with its bit differing goes
    through to the target.
    """
    chain = unsolved_chain(8)
    for height in range(1, 8):
        parent = chain[height - 2] if height > 1 else _GENESIS
        (other,) = unsolved_chain(1, parent, merkle_root=b"\x01" * 32)
        salt = differing_salt(chain[height - 1], other)
        sync = redownloading(9, chain, period=4, offset=offset, salt=salt)
        assert len(sync._commitments) == len(
            [h for h in range(1, 9) if h % 4 == offset]
        )
        result = sync.process_next_headers(
            [*chain[: height - 1], other], full_headers_message=True
        )
        assert result.success is (height % 4 != offset)


def test_the_commitments_cost_one_bit_each() -> None:
    """A commitment per header of a long chain costs an eighth of an octet."""
    count = 8_000
    chain = unsolved_chain(count)
    sync = a_sync(count + 2, period=1, offset=0)
    assert sync.process_next_headers(chain, full_headers_message=True).success
    assert len(sync._commitments) == count
    assert len(sync._commitments._octets) == count // 8


@pytest.mark.parametrize(
    "heights, minimum, expected_blocks",
    [
        (199, 0, 200 - 144),
        (144, 0, 1),
        (143, 0, 0),
        (10, 0, 0),
        (199, 100, 100),
        (10, 7, 7),
    ],
)
def test_the_threshold_is_the_tip_less_144_blocks_or_the_minimum(
    heights: int, minimum: int, expected_blocks: int
) -> None:
    """Core's `GetAntiDoSWorkThreshold`, in blocks of regtest's own work."""
    threshold = anti_dos_work_threshold(
        (heights + 1) * _WORK, _GENESIS.bits, minimum * _WORK
    )
    assert threshold == expected_blocks * _WORK


def test_the_threshold_weighs_144_blocks_at_the_tip_s_own_work() -> None:
    """The 144 blocks are the tip's own proof, not the chain's average."""
    hard = block_work(_HARD.bits)
    assert anti_dos_work_threshold(10**20, _HARD.bits, 0) == 10**20 - 144 * hard
    assert anti_dos_work_threshold(10**6, _GENESIS.bits, 0) == 10**6 - 144 * _WORK


def test_the_threshold_with_no_tip_is_the_minimum() -> None:
    """Core's threshold with no tip: no work, and the minimum alone."""
    assert anti_dos_work_threshold(0, _GENESIS.bits, 5) == 5


@pytest.mark.parametrize(
    "args, error, match",
    [
        ((1.5, _GENESIS.bits, 0), BTClibTypeError, "invalid tip_chain_work type"),
        ((True, _GENESIS.bits, 0), BTClibTypeError, "invalid tip_chain_work type"),
        ((-1, _GENESIS.bits, 0), BTClibValueError, "invalid tip_chain_work: -1"),
        ((0, _GENESIS.bits, None), BTClibTypeError, "invalid minimum_chain_work type"),
        ((0, _GENESIS.bits, -1), BTClibValueError, "invalid minimum_chain_work: -1"),
        ((0, b"\x00" * 4, 0), BTClibValueError, "zero proof-of-work target"),
        ((0, None, 0), BTClibTypeError, "invalid octets type"),
    ],
)
def test_the_threshold_refuses_what_is_no_work_or_no_bits(
    args: tuple[Any, ...], error: type[Exception], match: str
) -> None:
    """Every argument is asked before any arithmetic."""
    with pytest.raises(error, match=match):
        anti_dos_work_threshold(*args)


def test_a_chain_start_copies_its_header_and_is_frozen() -> None:
    """Core holds `m_chain_start` as a `const CBlockIndex&`."""
    header = unsolved_chain(1)[0]
    start = ChainStart(header, 1, 2 * _WORK, 0, [header.hash.hex()])
    assert start.locator == (header.hash,)
    assert start.header is not header
    assert start.header.hash == header.hash
    header.nonce = 1
    assert start.header.nonce == 0
    with pytest.raises(FrozenInstanceError):
        start.height = 0  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs, error, match",
    [
        ({"header": "no header"}, BTClibTypeError, "invalid header type"),
        ({"height": -1}, BTClibValueError, "invalid height: -1"),
        ({"height": 1.0}, BTClibTypeError, "invalid height type"),
        ({"chain_work": -1}, BTClibValueError, "invalid chain_work: -1"),
        ({"median_time_past": -1}, BTClibValueError, "invalid median_time_past: -1"),
        (
            {"median_time_past": 2**32},
            BTClibValueError,
            "invalid median_time_past: 4294967296",
        ),
        ({"header": _with(_GENESIS, bits=b"\x00" * 4)}, BTClibValueError, "zero"),
        ({"locator": b"\x00" * 32}, BTClibTypeError, "invalid locator type"),
        ({"locator": None}, BTClibTypeError, "invalid locator type"),
        ({"locator": [b"\x00" * 31]}, BTClibValueError, "invalid size: 31"),
    ],
)
def test_a_chain_start_refuses_what_is_no_chain_start(
    kwargs: dict[str, Any], error: type[Exception], match: str
) -> None:
    """Every field is asked at construction."""
    fields: dict[str, Any] = {
        "header": _GENESIS,
        "height": 0,
        "chain_work": _WORK,
        "median_time_past": 0,
        "locator": (_GENESIS.hash,),
    } | kwargs
    with pytest.raises(error, match=match):
        ChainStart(**fields)


def test_a_median_time_past_is_up_to_the_last_four_byte_instant() -> None:
    """A median time past is a header's time, so 2^32 - 1 is the last one."""
    start = ChainStart(_GENESIS, 0, _WORK, 2**32 - 1, ())
    assert start.median_time_past == 2**32 - 1


def test_a_chain_start_built_unchecked_is_asked_by_the_sync() -> None:
    """`check_validity=False` defers the check to the sync it starts."""
    start = ChainStart(_GENESIS, -1, _WORK, 0, (), check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid height: -1"):
        a_sync(1, start=start)


@pytest.mark.parametrize(
    "fields, error, match",
    [
        ({"previous_block_hash": b"\x00" * 33}, BTClibValueError, "invalid previous"),
        ({"merkle_root": "00" * 32}, BTClibTypeError, "invalid merkle_root type"),
        ({"bits": b"\x00" * 5}, BTClibValueError, "invalid bits length: 5"),
        ({"bits": b"\x00" * 4}, BTClibValueError, "zero proof-of-work target"),
        ({"nonce": 2**32}, BTClibValueError, "nonce"),
    ],
)
def test_a_header_without_its_eighty_bytes_is_refused_before_any_is_taken(
    fields: dict[str, Any], error: type[Exception], match: str
) -> None:
    """The batch is asked whole first: a refusal leaves the sync as it was."""
    chain = unsolved_chain(3)
    sync = a_sync(100)
    with pytest.raises(error, match=match):
        sync.process_next_headers(
            [*chain[:2], _with(chain[2], **fields)], full_headers_message=True
        )
    assert sync.state is State.PRESYNC
    assert sync.presync_height == 0
    assert sync.process_next_headers(chain, full_headers_message=True).success


@pytest.mark.parametrize("headers", [None, b"\x00" * 80, "headers", 3])
def test_a_batch_that_is_no_sequence_of_headers_is_refused(headers: Any) -> None:
    """Octets are a sequence too, of what no batch holds."""
    with pytest.raises(BTClibTypeError, match="invalid headers type"):
        a_sync(1).process_next_headers(headers, full_headers_message=True)


def test_a_batch_holding_what_is_no_header_is_refused() -> None:
    """Each element is a `BlockHeader`."""
    with pytest.raises(BTClibTypeError, match="invalid header type"):
        a_sync(1).process_next_headers(
            [_GENESIS.serialize()],  # type: ignore[list-item]
            full_headers_message=True,
        )


@pytest.mark.parametrize("value", ["no", 0, 1, None])
def test_the_batch_size_is_a_bool(value: Any) -> None:
    """`full_headers_message` decides what is asked next, so it is a kind."""
    with pytest.raises(BTClibTypeError, match="invalid full_headers_message type"):
        a_sync(1).process_next_headers(unsolved_chain(1), full_headers_message=value)


@pytest.mark.parametrize(
    "args, kwargs, error, match",
    [
        (("regtest",), {}, BTClibTypeError, "invalid consensus type"),
        ((_REGTEST, (600, 100)), {}, BTClibTypeError, "invalid params type"),
        (
            (_REGTEST, HeadersSyncParams(0, 100)),
            {},
            BTClibValueError,
            "invalid commitment_period: 0",
        ),
        (
            (_REGTEST, HeadersSyncParams(-1, 100)),
            {},
            BTClibValueError,
            "invalid commitment_period: -1",
        ),
        (
            (_REGTEST, HeadersSyncParams(1.5, 100)),  # type: ignore[arg-type]
            {},
            BTClibTypeError,
            "invalid commitment_period type",
        ),
        (
            (_REGTEST, HeadersSyncParams(600, -1)),
            {},
            BTClibValueError,
            "invalid redownload_buffer_size: -1",
        ),
        (
            (_REGTEST, HeadersSyncParams(600, None)),  # type: ignore[arg-type]
            {},
            BTClibTypeError,
            "invalid redownload_buffer_size type",
        ),
        (
            (_REGTEST, HeadersSyncParams(600, 100), "genesis"),
            {},
            BTClibTypeError,
            "invalid chain_start type",
        ),
        (
            (_REGTEST, HeadersSyncParams(600, 100), _START, -1),
            {},
            BTClibValueError,
            "invalid minimum_required_work: -1",
        ),
        (
            (_REGTEST, HeadersSyncParams(600, 100), _START, 1.0),
            {},
            BTClibTypeError,
            "invalid minimum_required_work type",
        ),
        (
            (_REGTEST, HeadersSyncParams(600, 100), _START, 1),
            {"now": 10**9},
            BTClibTypeError,
            "invalid now type",
        ),
        (
            (_REGTEST, HeadersSyncParams(600, 100), _START, 1),
            {"now": datetime(2026, 10, 17)},
            BTClibValueError,
            "naive now",
        ),
    ],
)
def test_a_sync_refuses_what_it_cannot_start_from(
    args: tuple[Any, ...], kwargs: dict[str, Any], error: type[Exception], match: str
) -> None:
    """Every argument is asked before anything is drawn."""
    full = (*args, *(_REGTEST, HeadersSyncParams(600, 100), _START, 1)[len(args) :])
    with pytest.raises(error, match=match):
        HeadersSyncState(*full, now=kwargs.get("now", _NOW))


def test_a_clock_in_another_time_zone_is_the_same_instant() -> None:
    """The bound is read off the instant, not off the time zone it is in.

    West of UTC, a wall time read as UTC would be five hours earlier, and
    the clock would be refused as behind the chain start.
    """
    west = timezone(timedelta(hours=-5))
    sync = bounded(-7189)
    elsewhere = a_sync(
        1000,
        period=6,
        buffer=10,
        start=replace(_START, median_time_past=0),
        now=at(-7189).astimezone(west),
    )
    chain = unsolved_chain(66)
    assert sync.process_next_headers(chain, full_headers_message=True).success
    assert elsewhere.process_next_headers(chain, full_headers_message=True).success


def test_the_hash_kept_is_the_header_s_own() -> None:
    """The locator's head is the hash the header displays, and Core asks for."""
    chain = unsolved_chain(2)
    sync = a_sync(100)
    sync.process_next_headers(chain, full_headers_message=True)
    assert sync.next_headers_request_locator[0] == chain[-1].hash
    assert hash256(chain[-1].serialize(check_validity=False))[::-1] == chain[-1].hash
