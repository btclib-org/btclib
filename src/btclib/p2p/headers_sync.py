# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The low-work headers sync: a peer's chain downloaded twice before it is kept.

`HeadersSyncState` is Bitcoin Core's class of the same name
(`src/headerssync.h` and `src/headerssync.cpp`, at
bitcoin/bitcoin@9be056a8a7, the v31.1 tag), and
`anti_dos_work_threshold` is its `GetAntiDoSWorkThreshold`
(`src/net_processing.cpp`, same tag). In `PRESYNC` the peer's headers
are counted and, every `commitment_period` headers from a secret offset,
one salted bit of a header's hash is kept. Once the work reaches the
threshold, `REDOWNLOAD` asks for the same chain again from its start,
checks each kept bit against it, and releases a header only once
`redownload_buffer_size` more have been checked behind it, or once the
redownloaded chain reaches the threshold itself. So a chain that never
reaches the threshold costs the bits and the buffer, and nothing else.

The sync is handed headers and the time, and hands back headers and a
locator: sending `getheaders` and reading `headers` is the caller's.
Core's `ProcessHeadersMessage` is the order a caller follows:

1. an empty `headers` message drops the peer's sync, if it has one, and
   answers the last `getheaders`; nothing else is done;
2. otherwise, check each header's proof of work and that the batch is
   continuous (Core's `CheckHeadersPoW`), before the steps below and
   before skipping a batch already held;
3. where the peer has a sync, hand it the batch with
   `process_next_headers`, send a `getheaders` with
   `next_headers_request_locator` where it asks for more, and drop the
   sync once it is `FINAL`. On a success, the headers it releases take
   the batch's place, their work taken as checked; on a failure, the
   batch goes on as if no sync ran;
4. otherwise, where the batch's last header is not already on the
   caller's best chain, and the chain work of the batch's parent plus
   the work the batch claims is below `anti_dos_work_threshold`, keep
   none of the batch: a full batch starts a sync from that parent and
   is handed to it, and a short one is dropped.

What differs from Core is said beside the code it shapes.
"""

from __future__ import annotations

import enum
import secrets
from collections import deque
from collections.abc import Sequence
from copy import copy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.block.limits import MAX_FUTURE_BLOCK_TIME
from btclib.block.proof_of_work import block_work, permitted_difficulty_transition
from btclib.consensus import ConsensusParams, HeadersSyncParams
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256, siphash
from btclib.utils import (
    _message_text,
    assert_type,
    bytes_from_octets,
    is_integer,
    is_octets,
)

__all__ = [
    "ChainStart",
    "HeadersSyncState",
    "ProcessingResult",
    "State",
    "anti_dos_work_threshold",
]

# Core's buffer below the tip, in blocks, in `GetAntiDoSWorkThreshold`:
# a chain forking this near the tip is weighed against the tip's work
# less this many of the tip's own blocks
_NEAR_TIP_BLOCKS = 144

# the most headers a second the median-time-past rule lets a chain
# carry, which bounds how long a chain can be at any moment: Core's
# literal 6 in the `HeadersSyncState` constructor
_MAX_BLOCKS_PER_SECOND = 6

# the serialized header's fields, as offsets into its eighty bytes.
# Core's `CompressedHeader` is the header less its parent's hash, 48
# bytes: the buffer holds the parent's hash once, for its first header,
# and derives it for every later one
_HASH_SIZE = 32
_VERSION_END = 4
_PREVIOUS_HASH_END = _VERSION_END + _HASH_SIZE
_COMPRESSED_BITS = slice(40, 44)

# the three fields of a header that are bytes, and their sizes:
# `BlockHeader.serialize(check_validity=False)` checks the others
_BYTES_FIELDS = (
    ("previous_block_hash", _HASH_SIZE),
    ("merkle_root", _HASH_SIZE),
    ("bits", 4),
)

# the last instant a header's four bytes of time can carry, which is
# as far as a median time past can be
_MAX_TIME = 0xFFFFFFFF

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ONE_SECOND = timedelta(seconds=1)


def _assert_non_negative_int(value: int, what: str) -> None:
    """Refuse `value` unless it is an int at or above zero."""
    if not is_integer(value):
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}")
    if value < 0:
        raise BTClibValueError(f"invalid {what}: {_message_text(value)}")


def _sequence_of(values: Sequence[object], what: str) -> None:
    """Refuse what is not a sequence, or is octets or text.

    An `Octets` is a sequence too, of characters or integers, which is
    what neither a batch of headers nor a locator holds.
    """
    if is_octets(values) or not isinstance(values, Sequence):
        raise BTClibTypeError(f"invalid {what} type: {type(values).__name__}")


def anti_dos_work_threshold(
    tip_chain_work: int, tip_bits: Octets, minimum_chain_work: int
) -> int:
    """Return the work below which a peer's chain is synced before it is kept.

    Core's `GetAntiDoSWorkThreshold` (`src/net_processing.cpp`, at
    bitcoin/bitcoin@9be056a8a7): the active tip's chain work less 144
    blocks of the tip's own work, and never less than
    `minimum_chain_work`, which is Core's `-minimumchainwork` and
    defaults to the network's `ConsensusParams.minimum_chain_work`.
    `tip_bits` is the tip's own `bits`. Core also allows for no tip at
    all; a caller holding none passes zero work and the genesis bits.
    """
    _assert_non_negative_int(tip_chain_work, "tip_chain_work")
    _assert_non_negative_int(minimum_chain_work, "minimum_chain_work")
    tip_proof = block_work(tip_bits)
    near_tip_work = tip_chain_work - min(_NEAR_TIP_BLOCKS * tip_proof, tip_chain_work)
    return max(near_tip_work, minimum_chain_work)


class State(enum.Enum):
    """Core's `HeadersSyncState::State`.

    `PRESYNC` counts the peer's chain and keeps commitments to it,
    `REDOWNLOAD` downloads it again and checks them, and `FINAL` is an
    ended sync, which the caller drops.
    """

    PRESYNC = enum.auto()
    REDOWNLOAD = enum.auto()
    FINAL = enum.auto()


@dataclass(frozen=True)
class ChainStart:
    """The held block a peer's chain builds on: Core's `m_chain_start`.

    Core keeps a reference to the `CBlockIndex` and reads what it needs
    off it. This carries those values: the header, its height, its chain
    work and median time past, and its own locator, which Core rebuilds
    from it on every request and which is the same list each time. The
    header is copied, so that the caller changing it changes no sync.
    """

    header: BlockHeader
    height: int
    chain_work: int
    median_time_past: int
    locator: tuple[bytes, ...]

    def __init__(
        self,
        header: BlockHeader,
        height: int,
        chain_work: int,
        median_time_past: int,
        locator: Sequence[Octets],
        *,
        check_validity: bool = True,
    ) -> None:
        assert_type(header, BlockHeader, "header")
        object.__setattr__(self, "header", copy(header))
        object.__setattr__(self, "height", height)
        object.__setattr__(self, "chain_work", chain_work)
        object.__setattr__(self, "median_time_past", median_time_past)
        _sequence_of(locator, "locator")
        object.__setattr__(
            self, "locator", tuple(bytes_from_octets(h, _HASH_SIZE) for h in locator)
        )

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a header with no eighty bytes, or a number out of range.

        The header's work is asked too, which refuses `bits` no target
        can be read from. Nothing else of the header is: it is a header
        the caller holds, checked when it was taken. The median time past
        is a header's time, so four bytes hold it.
        """
        _serialized(self.header)
        block_work(self.header.bits)
        for key in ("height", "chain_work", "median_time_past"):
            _assert_non_negative_int(getattr(self, key), key)
        if self.median_time_past > _MAX_TIME:
            err_msg = f"invalid median_time_past: {self.median_time_past}"
            raise BTClibValueError(err_msg)


@dataclass(frozen=True)
class ProcessingResult:
    """Core's `HeadersSyncState::ProcessingResult`.

    `pow_validated_headers` are the headers ready to be indexed, in
    chain order. `success` is false where the batch was not taken.
    `request_more` is whether to send a `getheaders` with
    `next_headers_request_locator`.
    """

    pow_validated_headers: list[BlockHeader]
    success: bool
    request_more: bool


class _BitQueue:
    """Core's `bitdeque`, as far as `HeadersSyncState` uses it.

    One bit per commitment, packed eight to a byte: a list of `bool`
    takes a pointer per bit, and mainnet's bound on the commitments of
    one peer runs to millions. Bits are appended in `PRESYNC` and taken
    from the front in `REDOWNLOAD`, never both, so what has been taken
    is not reclaimed until the queue is dropped.
    """

    def __init__(self) -> None:
        self._octets = bytearray()
        self._head = 0
        self._tail = 0

    def __len__(self) -> int:
        return self._tail - self._head

    def append(self, bit: int) -> None:
        """Add `bit` at the back."""
        index, offset = divmod(self._tail, 8)
        if not offset:
            self._octets.append(0)
        self._octets[index] |= bit << offset
        self._tail += 1

    def popleft(self) -> int:
        """Take the bit at the front."""
        index, offset = divmod(self._head, 8)
        self._head += 1
        return (self._octets[index] >> offset) & 1


def _serialized(header: BlockHeader) -> bytes:
    """Return the eighty bytes of `header`, refusing a header without them.

    `serialize(check_validity=False)` refuses a version, a time or a
    nonce its four bytes cannot hold, and the fields that are bytes are
    asked their size here. Nothing else is asked: the rest of
    `BlockHeader.assert_valid` refuses headers Core takes here. A time
    before the genesis block's is one, which Core's `time-too-old`
    answers in `ContextualCheckBlockHeader`, when the header is indexed.
    """
    assert_type(header, BlockHeader, "header")
    for key, size in _BYTES_FIELDS:
        value = getattr(header, key)
        assert_type(value, bytes, key)
        if len(value) != size:
            err_msg = f"invalid {key} length: {len(value)} bytes instead of {size}"
            raise BTClibValueError(err_msg)
    return header.serialize(check_validity=False)


class HeadersSyncState:
    """One peer's low-work headers sync: Core's `HeadersSyncState`.

    `consensus` is the network's row, which the difficulty transitions
    are checked against, and `params` its `HEADERS_SYNC_PARAMS` row.
    `minimum_required_work` is the threshold the peer's chain has to
    reach, fixed when the sync starts: `anti_dos_work_threshold` at that
    moment. `now` is the caller's clock, as an aware `datetime`.

    The commitment offset and the salt are drawn from `secrets`, once per
    sync: they are what a peer must not learn.
    """

    def __init__(
        self,
        consensus: ConsensusParams,
        params: HeadersSyncParams,
        chain_start: ChainStart,
        minimum_required_work: int,
        *,
        now: datetime,
    ) -> None:
        """Start a sync from `chain_start`, towards `minimum_required_work`.

        A clock more than `MAX_FUTURE_BLOCK_TIME` behind the chain
        start's median time past is refused, as Core at
        bitcoin/bitcoin@310071f8d0, the v32.0rc4 tag, refuses it with
        `SystemClockError`.
        """
        assert_type(consensus, ConsensusParams, "consensus")
        assert_type(params, HeadersSyncParams, "params")
        period = params.commitment_period
        _assert_non_negative_int(period, "commitment_period")
        if not period:
            raise BTClibValueError("invalid commitment_period: 0")
        buffer_size = params.redownload_buffer_size
        _assert_non_negative_int(buffer_size, "redownload_buffer_size")
        assert_type(chain_start, ChainStart, "chain_start")
        chain_start.assert_valid()
        _assert_non_negative_int(minimum_required_work, "minimum_required_work")
        assert_type(now, datetime, "now")
        if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
            raise BTClibValueError(f"naive now (no time zone): {now}")

        # Core's `Ticks<std::chrono::seconds>` of the time since the
        # chain start, which truncates toward zero, then the allowance
        # for a header from the future
        elapsed = now - (_EPOCH + chain_start.median_time_past * _ONE_SECOND)
        seconds = abs(elapsed) // _ONE_SECOND
        if elapsed < timedelta(0):
            seconds = -seconds
        max_seconds_since_start = seconds + MAX_FUTURE_BLOCK_TIME
        if max_seconds_since_start < 0:
            err_msg = "the clock is more than"
            err_msg += f" {MAX_FUTURE_BLOCK_TIME // 60} minutes behind"
            err_msg += f" the chain start's median time past: {now}"
            raise BTClibValueError(err_msg)

        self._consensus = consensus
        self._period = period
        self._buffer_size = buffer_size
        self._chain_start = chain_start
        self._chain_start_hash = chain_start.header.hash
        self._minimum_required_work = minimum_required_work
        self._commit_offset = secrets.randbelow(period)
        # the two 64-bit keys of Core's `SaltedUint256Hasher`
        self._salt = (secrets.randbits(64), secrets.randbits(64))
        # the longest chain the median-time-past rule allows between the
        # chain start and now, at six blocks a second, in commitments: a
        # peer offering more is offering what cannot be a valid chain
        self._max_commitments = (
            _MAX_BLOCKS_PER_SECOND * max_seconds_since_start // period
        )
        self._state = State.PRESYNC
        self._commitments = _BitQueue()
        # PRESYNC: the work, the last header and its height so far
        self._current_chain_work = chain_start.chain_work
        self._last_header_received_hash = self._chain_start_hash
        self._last_header_received_bits = chain_start.header.bits
        self._last_header_received_time = chain_start.header.time
        self._current_height = chain_start.height
        # REDOWNLOAD, set as it begins. Each entry is a 48-byte `bytes`,
        # Core's `CompressedHeader`, with the object's own overhead and its
        # deque slot on top: `sys.getsizeof(bytes(48))` plus a pointer
        self._redownloaded_headers: deque[bytes] = deque()
        self._redownload_buffer_last_height = 0
        self._redownload_buffer_last_hash = b""
        self._redownload_buffer_first_prev_hash = b""
        self._redownload_chain_work = 0
        self._process_all_remaining_headers = False

    @property
    def state(self) -> State:
        """Return where the sync is, as Core's `GetState` does."""
        return self._state

    @property
    def presync_height(self) -> int:
        """Return the height `PRESYNC` has reached, Core's `GetPresyncHeight`.

        Zero once the sync is `FINAL`, as Core's `Finalize` leaves it.
        """
        return self._current_height

    @property
    def presync_time(self) -> datetime:
        """Return the last `PRESYNC` header's time, Core's `GetPresyncTime`."""
        return self._last_header_received_time

    @property
    def presync_work(self) -> int:
        """Return the work `PRESYNC` has counted, Core's `GetPresyncWork`."""
        return self._current_chain_work

    @property
    def next_headers_request_locator(self) -> list[bytes]:
        """Return the locator of the next `getheaders`, as Core builds it.

        The last header `PRESYNC` took, or the last one `REDOWNLOAD`
        buffered, then the chain start's locator. Empty once the sync is
        `FINAL`, as Core's is.
        """
        if self._state is State.FINAL:
            return []
        if self._state is State.PRESYNC:
            head = self._last_header_received_hash
        else:
            head = self._redownload_buffer_last_hash
        return [head, *self._chain_start.locator]

    def _commitment(self, raw_hash: bytes) -> int:
        """Return the bit a header commits to, its hash in Core's byte order.

        Core's `SaltedUint256Hasher` hashes the `uint256`, whose bytes are
        `hash256`'s, the reverse of the order `BlockHeader.hash` displays.
        """
        k0, k1 = self._salt
        return siphash(k0, k1, raw_hash) & 1

    def _finalize(self) -> None:
        """Free what the sync holds, and end it: Core's `Finalize`.

        Core also nulls its hashes so that the object cannot be reused
        with the same salt. Here every method answers a `FINAL` sync
        without reading them.
        """
        self._commitments = _BitQueue()
        self._redownloaded_headers = deque()
        self._process_all_remaining_headers = False
        self._current_height = 0
        self._state = State.FINAL

    def process_next_headers(
        self, headers: Sequence[BlockHeader], *, full_headers_message: bool
    ) -> ProcessingResult:
        """Take the peer's next batch: Core's `ProcessNextHeaders`.

        The caller has checked each header's proof of work and that the
        batch is continuous. `full_headers_message` is whether the batch
        held `MAX_HEADERS_RESULTS` headers, the peer then perhaps having
        more. The sync ends, `FINAL`, wherever the result is not both a
        success and a request for more.

        An empty batch, or one handed to a `FINAL` sync, is no success and
        ends nothing, as Core's `Assume` guards answer it.

        A header with no eighty bytes, or whose `bits` no target can be
        read from, is refused before any header is taken.
        """
        assert_type(full_headers_message, bool, "full_headers_message")
        _sequence_of(headers, "headers")
        # every header's bytes, hash and work before any of them is taken,
        # so that a refusal leaves the sync as it was
        batch = []
        for header in headers:
            raw = _serialized(header)
            batch.append((header, raw, hash256(raw), block_work(header.bits)))

        # read once: the PRESYNC branch below moves `self._state` itself
        state = self._state
        if not batch or state is State.FINAL:
            return ProcessingResult([], success=False, request_more=False)
        validated: list[BlockHeader] = []
        if state is State.PRESYNC:
            success = self._validate_and_store_headers_commitments(batch)
            # a full batch may have more behind it, and a sync that has
            # just moved to REDOWNLOAD asks again from the start whatever
            # the size; a short batch still in PRESYNC is a chain that
            # ended short of the work, and the sync ends without an error
            request_more = success and (
                full_headers_message or self._state is State.REDOWNLOAD
            )
        else:
            success = all(
                self._validate_and_store_redownloaded_header(*entry) for entry in batch
            )
            request_more = False
            if success:
                validated = self._pop_headers_ready_for_acceptance()
                # a sync whose every header is released at the target is
                # over; before it, a short batch is a peer declining to
                # serve again the chain it served once, and ends it too
                request_more = full_headers_message and not (
                    self._process_all_remaining_headers
                    and not self._redownloaded_headers
                )
        if not (success and request_more):
            self._finalize()
        return ProcessingResult(validated, success=success, request_more=request_more)

    def _validate_and_store_headers_commitments(
        self, batch: list[tuple[BlockHeader, bytes, bytes, int]]
    ) -> bool:
        """Take a `PRESYNC` batch.

        Core's `ValidateAndStoreHeadersCommitments`.
        """
        if not all(
            self._validate_and_process_single_header(header, raw_hash, work)
            for header, _, raw_hash, work in batch
        ):
            return False
        if self._current_chain_work >= self._minimum_required_work:
            start = self._chain_start
            self._redownloaded_headers = deque()
            self._redownload_buffer_last_height = start.height
            self._redownload_buffer_first_prev_hash = self._chain_start_hash
            self._redownload_buffer_last_hash = self._chain_start_hash
            self._redownload_chain_work = start.chain_work
            self._state = State.REDOWNLOAD
        return True

    def _validate_and_process_single_header(
        self, header: BlockHeader, raw_hash: bytes, work: int
    ) -> bool:
        """Take one `PRESYNC` header: Core's `ValidateAndProcessSingleHeader`.

        Every header is asked whether it builds on the last one taken,
        where Core asks only the first of a batch and leaves the rest to
        its caller's `CheckHeadersAreContinuous`: the hash is at hand,
        and a caller that skipped the check then ends the sync rather
        than counting a chain that is not one.
        """
        if header.previous_block_hash != self._last_header_received_hash:
            return False
        next_height = self._current_height + 1
        if not permitted_difficulty_transition(
            self._consensus, next_height, self._last_header_received_bits, header.bits
        ):
            return False
        if next_height % self._period == self._commit_offset:
            self._commitments.append(self._commitment(raw_hash))
            if len(self._commitments) > self._max_commitments:
                return False
        self._current_chain_work += work
        self._last_header_received_hash = raw_hash[::-1]
        self._last_header_received_bits = header.bits
        self._last_header_received_time = header.time
        self._current_height = next_height
        return True

    def _validate_and_store_redownloaded_header(
        self, header: BlockHeader, raw: bytes, raw_hash: bytes, work: int
    ) -> bool:
        """Take one `REDOWNLOAD` header.

        Core's `ValidateAndStoreRedownloadedHeader`.
        """
        next_height = self._redownload_buffer_last_height + 1
        if header.previous_block_hash != self._redownload_buffer_last_hash:
            return False
        if self._redownloaded_headers:
            previous_bits = self._redownloaded_headers[-1][_COMPRESSED_BITS][::-1]
        else:
            previous_bits = self._chain_start.header.bits
        if not permitted_difficulty_transition(
            self._consensus, next_height, previous_bits, header.bits
        ):
            return False
        self._redownload_chain_work += work
        # set before the commitment is asked, so that the header reaching
        # the target is not checked: a peer whose chain grew since PRESYNC
        # runs out of commitments past that point, and is not refused
        if self._redownload_chain_work >= self._minimum_required_work:
            self._process_all_remaining_headers = True
        if (
            not self._process_all_remaining_headers
            and next_height % self._period == self._commit_offset
        ):
            if not self._commitments:
                return False
            if self._commitment(raw_hash) != self._commitments.popleft():
                return False
        self._redownloaded_headers.append(raw[:_VERSION_END] + raw[_PREVIOUS_HASH_END:])
        self._redownload_buffer_last_height = next_height
        self._redownload_buffer_last_hash = raw_hash[::-1]
        return True

    def _pop_headers_ready_for_acceptance(self) -> list[BlockHeader]:
        """Release the headers checked enough.

        Core's `PopHeadersReadyForAcceptance`.
        """
        ready: list[BlockHeader] = []
        buffer = self._redownloaded_headers
        while len(buffer) > self._buffer_size or (
            buffer and self._process_all_remaining_headers
        ):
            compressed = buffer.popleft()
            raw = compressed[:_VERSION_END]
            raw += self._redownload_buffer_first_prev_hash[::-1]
            raw += compressed[_VERSION_END:]
            ready.append(BlockHeader.parse(raw, check_validity=False))
            self._redownload_buffer_first_prev_hash = hash256(raw)[::-1]
        return ready
