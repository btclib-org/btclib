# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for btclib.fetch.decorators: CachingFetcher and FallbackFetcher.

`CountingFetcher` below, and not the `Recorded` transport seam
`tests/fetch/bitcoin_core_test.py` and `tests/fetch/esplora_test.py`
build their fetchers over: what these tests check is how many times a
decorator reaches the `Fetcher` it wraps, never how a backend turns a
wire response into one, so a fetcher with no wire underneath it at all
is the simpler tool -- the transport seam would add a layer of
serialization these tests have no use for.
"""

from __future__ import annotations

import pytest
from typing_extensions import override

from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibValueError, FetchError
from btclib.fetch.decorators import CachingFetcher, FallbackFetcher
from btclib.fetch.fetcher import Fetcher
from btclib.tx import OutPoint, Tx
from tests.fetch import TIP_HEADER_RAW, TIP_HEIGHT, TIP_ID, TX_ID, recorded_body

RAW = recorded_body("esplora_tx_hex.txt").decode().strip()


class CountingFetcher(Fetcher):
    """A Fetcher answering one fixed transaction and header, call-counted.

    `fail_with`, settable at any time, is raised exactly once and then
    cleared -- which is what lets a test script a single failure between
    two otherwise identical calls without a second class.
    """

    def __init__(
        self,
        tx: Tx | None = None,
        header: BlockHeader | None = None,
        network: str = "mainnet",
    ) -> None:
        super().__init__(network)
        self.tx = tx
        self.header = header
        self.fail_with: Exception | None = None
        self.calls = {
            "get_tx": 0,
            "get_block_count": 0,
            "get_best_block_id": 0,
            "get_block_header": 0,
        }

    def _maybe_fail(self) -> None:
        if self.fail_with is not None:
            error, self.fail_with = self.fail_with, None
            raise error

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        self.calls["get_tx"] += 1
        self._maybe_fail()
        assert self.tx is not None
        return self.tx

    @override
    def get_block_count(self) -> int:
        self.calls["get_block_count"] += 1
        self._maybe_fail()
        return TIP_HEIGHT

    @override
    def get_best_block_id(self) -> bytes:
        self.calls["get_best_block_id"] += 1
        self._maybe_fail()
        return bytes.fromhex(TIP_ID)

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        self.calls["get_block_header"] += 1
        self._maybe_fail()
        assert self.header is not None
        return self.header


# --- CachingFetcher -----------------------------------------------------


def test_get_tx_out_amortizes_across_many_outpoints() -> None:
    """The issue this module answers: twenty calls, one backend fetch."""
    tx = Tx.parse(RAW)
    backend = CountingFetcher(tx=tx)
    caching = CachingFetcher(backend)
    for i in range(20):
        out = caching.get_tx_out(OutPoint(TX_ID, i % 2))
        assert out == tx.vout[i % 2]
    assert backend.calls["get_tx"] == 1


def test_get_tx_key_normalizes_octets_spellings() -> None:
    """Every spelling of one id shares one cache entry.

    Keying on the raw argument would cache the same transaction under
    several keys -- this is the amortization the issue is about, lost to
    the argument's spelling rather than its value.
    """
    backend = CountingFetcher(tx=Tx.parse(RAW))
    caching = CachingFetcher(backend)
    caching.get_tx(TX_ID)
    caching.get_tx(bytes.fromhex(TX_ID))
    caching.get_tx(bytearray.fromhex(TX_ID))
    caching.get_tx(memoryview(bytes.fromhex(TX_ID)))
    caching.get_tx(f"  {TX_ID}  ")
    assert backend.calls["get_tx"] == 1


def test_the_tip_passes_through_uncached() -> None:
    """Two calls to either tip method are two calls to the backend."""
    backend = CountingFetcher(tx=Tx.parse(RAW))
    caching = CachingFetcher(backend)
    assert caching.get_block_count() == TIP_HEIGHT
    assert caching.get_block_count() == TIP_HEIGHT
    assert caching.get_best_block_id().hex() == TIP_ID
    assert caching.get_best_block_id().hex() == TIP_ID
    assert backend.calls["get_block_count"] == 2
    assert backend.calls["get_best_block_id"] == 2


def test_get_block_header_is_cached() -> None:
    """A second call for the same height answers from the cache."""
    header = BlockHeader.parse(TIP_HEADER_RAW)
    backend = CountingFetcher(tx=Tx.parse(RAW), header=header)
    caching = CachingFetcher(backend)
    assert caching.get_block_header(TIP_HEIGHT).hash.hex() == TIP_ID
    assert caching.get_block_header(TIP_HEIGHT).hash.hex() == TIP_ID
    assert backend.calls["get_block_header"] == 1


def test_a_raising_call_does_not_poison_the_cache() -> None:
    """A FetchError is never cached: the next call reaches the backend."""
    backend = CountingFetcher(tx=Tx.parse(RAW))
    caching = CachingFetcher(backend)
    backend.fail_with = FetchError("the node is down")
    with pytest.raises(FetchError, match="the node is down"):
        caching.get_tx(TX_ID)
    assert backend.calls["get_tx"] == 1

    # the failed call left nothing behind, so this one reaches the backend
    tx = caching.get_tx(TX_ID)
    assert tx.id.hex() == TX_ID
    assert backend.calls["get_tx"] == 2

    # and this one is now served from the cache the successful call filled
    caching.get_tx(TX_ID)
    assert backend.calls["get_tx"] == 2


def test_lru_eviction_at_max_size() -> None:
    """The least recently used entry is the one an overflow evicts.

    Three ids over a cache of two: `id_a` is read again before `id_c` is
    inserted, so the eviction that makes room for `id_c` falls on `id_b`
    instead -- the one thing a plain "oldest inserted first" eviction
    would get wrong.
    """
    id_a, id_b, id_c = "a1" * 32, "b2" * 32, "c3" * 32
    backend = CountingFetcher(tx=Tx.parse(RAW))
    caching = CachingFetcher(backend, max_size=2)

    caching.get_tx(id_a)
    caching.get_tx(id_b)
    assert backend.calls["get_tx"] == 2  # cache: id_a, id_b

    caching.get_tx(id_a)  # a hit, and moves id_a to the most-recent end
    assert backend.calls["get_tx"] == 2

    caching.get_tx(id_c)  # a miss: evicts id_b, the least recently used
    assert backend.calls["get_tx"] == 3  # cache: id_a, id_c

    caching.get_tx(id_a)  # still cached, thanks to the read above
    assert backend.calls["get_tx"] == 3

    caching.get_tx(id_b)  # id_b was evicted: a miss
    assert backend.calls["get_tx"] == 4


def test_clear_forgets_every_cached_answer() -> None:
    """Both caches are emptied, and the next call reaches the backend."""
    header = BlockHeader.parse(TIP_HEADER_RAW)
    backend = CountingFetcher(tx=Tx.parse(RAW), header=header)
    caching = CachingFetcher(backend)
    caching.get_tx(TX_ID)
    caching.get_block_header(TIP_HEIGHT)

    caching.clear()

    caching.get_tx(TX_ID)
    caching.get_block_header(TIP_HEIGHT)
    assert backend.calls["get_tx"] == 2
    assert backend.calls["get_block_header"] == 2


# --- FallbackFetcher -----------------------------------------------------


def test_fallback_answers_all_four_from_the_first_backend() -> None:
    """A working primary answers every question; the secondary is unused."""
    tx = Tx.parse(RAW)
    header = BlockHeader.parse(TIP_HEADER_RAW)
    primary = CountingFetcher(tx=tx, header=header)
    secondary = CountingFetcher(tx=tx, header=header)
    fallback = FallbackFetcher([primary, secondary])

    assert fallback.get_tx(TX_ID).id.hex() == TX_ID
    assert fallback.get_block_count() == TIP_HEIGHT
    assert fallback.get_best_block_id().hex() == TIP_ID
    assert fallback.get_block_header(TIP_HEIGHT).hash.hex() == TIP_ID
    assert secondary.calls == {
        "get_tx": 0,
        "get_block_count": 0,
        "get_best_block_id": 0,
        "get_block_header": 0,
    }


def test_fallback_moves_on_past_a_fetch_error() -> None:
    """A dead primary is skipped in favour of the one that answers."""
    tx = Tx.parse(RAW)
    primary = CountingFetcher(tx=tx)
    secondary = CountingFetcher(tx=tx)
    primary.fail_with = FetchError("connection refused")
    fallback = FallbackFetcher([primary, secondary])

    result = fallback.get_tx(TX_ID)

    assert result.id.hex() == TX_ID
    assert primary.calls["get_tx"] == 1
    assert secondary.calls["get_tx"] == 1


def test_fallback_does_not_move_on_past_a_value_error() -> None:
    """A misconfigured backend is a caller error, not papered over."""
    tx = Tx.parse(RAW)
    primary = CountingFetcher(tx=tx)
    secondary = CountingFetcher(tx=tx)
    primary.fail_with = BTClibValueError("node serves another chain")
    fallback = FallbackFetcher([primary, secondary])

    with pytest.raises(BTClibValueError, match="node serves another chain"):
        fallback.get_tx(TX_ID)
    assert secondary.calls["get_tx"] == 0


def test_fallback_names_every_backend_when_all_fail() -> None:
    """The message and the chain both name every backend that was tried."""
    tx = Tx.parse(RAW)
    first, second, third = (
        CountingFetcher(tx=tx),
        CountingFetcher(tx=tx),
        CountingFetcher(tx=tx),
    )
    errors = (
        FetchError("first is down"),
        FetchError("second is down"),
        FetchError("third is down"),
    )
    first.fail_with, second.fail_with, third.fail_with = errors
    fallback = FallbackFetcher([first, second, third])

    with pytest.raises(FetchError) as exc_info:
        fallback.get_tx(TX_ID)

    message = str(exc_info.value)
    assert "first is down" in message
    assert "second is down" in message
    assert "third is down" in message
    assert exc_info.value.__cause__ is errors[-1]


def test_fallback_refuses_a_network_mismatch() -> None:
    """A mainnet backend and a testnet one are refused before any call."""
    mainnet = CountingFetcher(tx=Tx.parse(RAW), network="mainnet")
    testnet = CountingFetcher(tx=Tx.parse(RAW), network="testnet")
    with pytest.raises(BTClibValueError, match="mismatched networks"):
        FallbackFetcher([mainnet, testnet])


def test_fallback_refuses_an_empty_sequence() -> None:
    """A FallbackFetcher with nothing to fall back to answers nothing."""
    with pytest.raises(BTClibValueError, match="no backends given"):
        FallbackFetcher([])
