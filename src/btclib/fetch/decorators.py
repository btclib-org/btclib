# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Two `Fetcher`s that answer from another `Fetcher`, not from a network.

`CachingFetcher` composes one backend and remembers what it answered;
`FallbackFetcher` composes several and tries them in order. Both are
`Fetcher` subclasses in their own right -- calling code takes a `Fetcher`
and does not learn that either is standing in front of something else.

**Nesting order is not free to choose either way.**
`CachingFetcher(FallbackFetcher([a, b]))` is the recommended shape: one
cache shared across the failover, so a backend going down and the next
one taking over does not re-fetch what is already held.
`FallbackFetcher([CachingFetcher(a), CachingFetcher(b)])` builds two
caches that each learn the same transactions separately -- twice the
memory for the overlap, and a fetch that fails over to `b` still pays
for what `a`'s cache already knew.
"""

from __future__ import annotations

# imported at runtime and not under TYPE_CHECKING, which the annotations
# below would not need and the documentation build does:
# `sphinx.ext.autodoc`'s resolution of the deferred annotation falls back
# to the annotation's own text when a name it uses is missing from the
# module, and that text is a cross-reference with two targets for a name
# btclib re-exports at its package root -- `Tx` and `BlockHeader` both
# are -- which is one warning per occurrence for `-W` to fail the build
# on. `core_import.py`'s own comment documents the same failure for
# `Descriptor`
from collections import OrderedDict
from collections.abc import Callable, Sequence
from typing import TypeVar

from typing_extensions import override

from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibValueError, FetchError
from btclib.fetch.fetcher import Fetcher, tx_id_hex
from btclib.tx import Tx

__all__ = ["CachingFetcher", "FallbackFetcher"]

_T = TypeVar("_T")
_K = TypeVar("_K")
_V = TypeVar("_V")


class CachingFetcher(Fetcher):
    """A `Fetcher` that remembers `get_tx` and `get_block_header` answers.

    Composes a `Fetcher` rather than subclassing one: the wrapped fetcher
    is an attribute, `fetcher`, and any backend satisfies the interface
    without knowing it is being cached. `get_tx_out` is **not**
    overridden here, and that is what makes the caching pay off rather
    than being one more place to keep in step -- `Fetcher.get_tx_out` is
    concrete and calls `self.get_tx`, so caching `get_tx` amortizes it
    for free: twenty outpoints spending one transaction cost one fetch of
    it. The consequence is that a wrapped backend which overrides
    `get_tx_out` with an answer of its own has that override bypassed --
    this class's `get_tx_out` is the ABC's, inherited, and never reaches
    the wrapped fetcher's. No backend here overrides it, so this only
    matters for a third-party backend.

    **What is cached, and for how long, differs per method:**

    - `get_tx` is cached with no expiry. The id is a hash of the bytes,
      so the answer cannot change without the question changing.
    - `get_block_header` is cached with no expiry too, and that has a
      consequence worth stating rather than leaving implicit: a height is
      not an identity, and a reorg can replace the block at one. This
      class holds no chain tip and has no way to notice. Caching it
      anyway is still the right default -- the caller that repeatedly
      asks for headers by height is building a chain of them, verified
      by each header's `previous_block_hash` link to the one before it,
      so a stale entry fails that check loudly rather than being trusted
      silently.
    - `get_block_count` and `get_best_block_id` are **never** cached --
      both are the chain tip, and it moves. Every call reaches the
      wrapped fetcher.

    No expiry was rejected as the general policy for the same two: a
    lifetime is a second parameter with a clock behind it, untestable
    without freezing time and wrong for somebody at whatever value it
    defaulted to. Nothing here hammers the tip -- `get_tx_out` never
    touches it -- so a caller who wants it held briefly holds it in a
    local variable, which costs one line and needs no policy here.

    **A raised `FetchError` is never cached.** `get_tx` and
    `get_block_header` write their cache only after the wrapped fetcher
    answers successfully, so a transaction that does not exist yet, or a
    backend that is briefly down, is asked again next time rather than
    having its failure remembered forever -- negative caching is a policy
    nobody asked for.

    `max_size` bounds each of the two caches separately rather than
    pooling them under one shared count: they hold answers of different
    shape and different traffic -- a header is a fixed eighty bytes, a
    transaction is not -- and a caller who floods one by asking for many
    headers should not evict transactions it never touched. `None`, the
    default, leaves both unbounded, which is a real leak in a
    long-running process; a caller that holds a fetcher for a long time
    is the one to set it. Eviction is least-recently-used, a hit moving
    an entry to the end of its `OrderedDict` and an overflow popping from
    the front.
    """

    fetcher: Fetcher
    max_size: int | None

    def __init__(self, fetcher: Fetcher, max_size: int | None = None) -> None:
        super().__init__(fetcher.network)
        self.fetcher = fetcher
        self.max_size = max_size
        self._tx_cache: OrderedDict[str, Tx] = OrderedDict()
        self._header_cache: OrderedDict[int, BlockHeader] = OrderedDict()

    def _remember(self, cache: OrderedDict[_K, _V], key: _K, value: _V) -> None:
        """Store an answer and evict the oldest entry past `max_size`."""
        cache[key] = value
        if self.max_size is not None and len(cache) > self.max_size:
            cache.popitem(last=False)

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the cached transaction, or fetch and cache it.

        Keyed on `tx_id_hex(tx_id)` and not on `tx_id` itself: `Octets`
        is bytes, a bytearray, a memoryview or a hex string, so the same
        transaction asked for two different ways would otherwise be
        cached under two different keys and fetched twice -- the very
        amortization this class exists for, lost to the argument's
        spelling rather than its value. `tx_id_hex` is the normalizer
        `Fetcher` already validates ids with, so this reuses it rather
        than writing a second one.
        """
        key = tx_id_hex(tx_id)
        if key in self._tx_cache:
            self._tx_cache.move_to_end(key)
            return self._tx_cache[key]
        tx = self.fetcher.get_tx(tx_id)
        self._remember(self._tx_cache, key, tx)
        return tx

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Return the cached header, or fetch and cache it."""
        if height in self._header_cache:
            self._header_cache.move_to_end(height)
            return self._header_cache[height]
        header = self.fetcher.get_block_header(height)
        self._remember(self._header_cache, height, header)
        return header

    @override
    def get_block_count(self) -> int:
        """Pass the call through, uncached: this is the chain tip."""
        return self.fetcher.get_block_count()

    @override
    def get_best_block_id(self) -> bytes:
        """Pass the call through, uncached: this is the chain tip."""
        return self.fetcher.get_best_block_id()

    def clear(self) -> None:
        """Forget every cached transaction and header."""
        self._tx_cache.clear()
        self._header_cache.clear()


class FallbackFetcher(Fetcher):
    """A `Fetcher` that tries a sequence of backends, in order.

    Composes the backends rather than subclassing one, `fetchers`
    holding the sequence as given. The first one that does not raise
    answers; a later one is tried only when an earlier one raises
    `FetchError` -- which `HttpError` and `RpcError` both subclass, so a
    dead socket, an HTTP 500 and "no such transaction" all fall through
    the same way. `BTClibValueError`, which `Fetcher.__init__` raises for
    an unknown network and which `client_errors` raises for a node
    serving the wrong chain, propagates instead: a misconfigured backend
    is a caller error to fix, not a failure to paper over by asking the
    next one.

    When every backend raises, this raises a `FetchError` naming each of
    them and its failure, chained (`raise ... from`) off the last one --
    not the last one's message alone, which would report a second-string
    backend's 404 for what began as the primary's dead socket.

    **This never compares two answers.** It stops at the first backend
    that does not raise, so on the disagreement two backends could have
    about the tip, nothing is thrown away: there is only ever one answer
    in hand. An object that asked every backend and compared their
    answers would be a quorum fetcher, a different policy with a
    different cost -- worth its own issue if anyone wants it, and not
    this class.

    Refuses an empty sequence at construction: a `FallbackFetcher` with
    nothing to fall back to answers no question at all. Refuses a
    `network` mismatch too, comparing every backend's `network` rather
    than trusting the first: a mainnet node and a testnet explorer behind
    one `FallbackFetcher` is a configuration error that would otherwise
    surface as a transaction whose outputs are labelled for the wrong
    chain, wherever the failover happened to land.
    """

    fetchers: tuple[Fetcher, ...]

    def __init__(self, fetchers: Sequence[Fetcher]) -> None:
        if len(fetchers) == 0:
            raise BTClibValueError("no backends given")
        networks = {fetcher.network for fetcher in fetchers}
        if len(networks) > 1:
            err_msg = f"mismatched networks: {sorted(networks)}"
            raise BTClibValueError(err_msg)
        super().__init__(fetchers[0].network)
        self.fetchers = tuple(fetchers)

    def _first_answer(self, description: str, call: Callable[[Fetcher], _T]) -> _T:
        """Try each backend in order, falling through `FetchError` alone."""
        failures: list[str] = []
        exceptions: list[FetchError] = []
        for fetcher in self.fetchers:
            try:
                return call(fetcher)
            except FetchError as e:
                failures.append(f"{type(fetcher).__name__}: {e}")
                exceptions.append(e)
        err_msg = f"{description}: every backend failed -- " + "; ".join(failures)
        # `self.fetchers` is non-empty by construction, so the loop above
        # ran at least once and `exceptions` holds the last backend's error
        raise FetchError(err_msg) from exceptions[-1]

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Answer from the first backend that does not raise `FetchError`."""
        return self._first_answer("get_tx", lambda fetcher: fetcher.get_tx(tx_id))

    @override
    def get_block_count(self) -> int:
        """Answer from the first backend that does not raise `FetchError`."""
        return self._first_answer(
            "get_block_count", lambda fetcher: fetcher.get_block_count()
        )

    @override
    def get_best_block_id(self) -> bytes:
        """Answer from the first backend that does not raise `FetchError`."""
        return self._first_answer(
            "get_best_block_id", lambda fetcher: fetcher.get_best_block_id()
        )

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Answer from the first backend that does not raise `FetchError`."""
        return self._first_answer(
            "get_block_header", lambda fetcher: fetcher.get_block_header(height)
        )
