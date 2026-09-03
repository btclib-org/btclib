# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The interface a chain backend answers, whichever backend it is.

Four questions btclib cannot answer from bytes it was handed: what
transaction has this id, what output does this outpoint name, where is
the chain tip, and what header does a given height carry. `Fetcher` is
those questions and nothing else, so that calling code takes a `Fetcher`
and never learns whether a full node or an explorer is behind it.

What comes back is btclib types -- `Tx`, `TxOut`, `BlockHeader` -- and
not the dicts the backends send. A wrapper handing over
`response["vout"][0]["value"]` leaves the caller to know which backend it
is talking to, in the one place the whole point was not to.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager

import bitcoin_core_rpc as rpc

from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
    FetchError,
    HttpError,
    RpcError,
)
from btclib.network import NETWORKS, _validated_network_name, network_from_name
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxOut
from btclib.utils import bytes_from_octets, is_integer, is_octets

__all__ = [
    "Fetcher",
    "block_header_from_raw",
    "block_header_height",
    "client_errors",
    "fetch_errors",
    "tx_for_network",
    "tx_from_raw",
    "tx_id_hex",
]


@contextmanager
def client_errors() -> Iterator[None]:
    """Re-raise what the rpc client raises as btclib's own exception.

    `bitcoin_core_rpc` declares a `FetchError`, an `HttpError` and an
    `RpcError` of its own -- it declares zero dependencies and imports
    nothing of btclib's -- so those three are not the classes
    `btclib.exceptions` declares, and an `except FetchError` written
    against btclib does not catch them. This is the one place the
    two meet, and every call that crosses into the package goes through
    it: `EsploraFetcher.text` and `BitcoinCoreFetcher._call` are the two
    lines that do.

    The fields are what make this a translation rather than a blanket
    wrap: `status` and `code` are the whole reason those two classes
    exist, and losing them would leave a caller matching on the text of a
    message again.

    `args[0]` and not `str(e)`: both sides compose their message in
    `__str__`, so handing the composed one back in would report
    "not found (rpc error code -5) (rpc error code -5)" -- once more per
    translation.
    """
    try:
        yield
    except rpc.RpcError as e:
        raise RpcError(e.args[0], e.code, e.data) from e
    except rpc.HttpError as e:
        raise HttpError(e.args[0], e.status) from e
    except rpc.FetchError as e:
        raise FetchError(str(e)) from e
    except rpc.BtcRpcValueError as e:
        # what `assert_chain` raises for a node serving another chain: a
        # refusal on valid inputs, so `BTClibValueError` and not a
        # `FetchError`. Its message names the node's chain and the client's,
        # which is the whole of what a caller has to act on
        raise BTClibValueError(str(e)) from e


@contextmanager
def fetch_errors(source: str) -> Iterator[None]:
    """Report what a conversion refuses as a failure of `source`.

    Every answer a backend gives is a string it chose, so every parse of
    one is a place the backend can be wrong: a hex field that is not hex,
    a height that is not a number, a transaction truncated in transit.
    Those arrive as ValueError and TypeError from `int` and
    `bytes_from_octets`, and as BTClibRuntimeError from the stream
    readers under `Tx.parse` -- "not enough binary data" is what a
    transaction truncated in transit looks like from inside `var_bytes`.
    All three name the converter and not the host, and the host is what
    has to be fixed.
    """
    try:
        yield
    except FetchError:
        # already the answer this would produce, and a BTClibRuntimeError
        # too, so it has to be let through before the clause below wraps
        # its message inside a second copy of itself
        raise
    except (TypeError, ValueError, BTClibRuntimeError) as e:
        raise FetchError(f"{source}: {e}") from e


def tx_for_network(tx: Tx, network: str) -> Tx:
    """Return the transaction with its outputs labelled for `network`.

    `Tx.parse` labels every `script_pub_key` mainnet, and is right to:
    the serialization carries a script and no network, so a parser handed
    bytes alone has nothing else to say. A fetcher does -- it was told
    which chain it is talking to -- and the label is what
    `ScriptPubKey.address` renders from, so an unlabelled testnet output
    reports a mainnet address for coins that are not there.

    Mainnet in, mainnet out: for the default network this returns a
    transaction equal to its argument, the label being the only thing it
    touches. The bytes are untouched in every case, `ScriptPubKey`
    serializing the script alone.

    The name is resolved and not compared as text. Resolving refuses a
    network no table has, which every `check_validity=False` below would
    otherwise write into the transaction handed back, to surface far
    from here as whatever went on to render an address; and it answers
    the same for " MainNet " as for "mainnet", where a comparison would
    relabel every output instead of returning the transaction as it is.
    """
    if network_from_name(network) == NETWORKS["mainnet"]:
        return tx
    vout = [
        TxOut(
            out.value,
            ScriptPubKey(out.script_pub_key.script, network, check_validity=False),
            check_validity=False,
        )
        for out in tx.vout
    ]
    return Tx(tx.version, tx.lock_time, tx.vin, vout, check_validity=False)


class Fetcher(ABC):
    """What a backend must answer, and what btclib does with the answers.

    Four abstract methods, one per question, each with a return type of
    its own. That is the shape on purpose rather than one `get(kind, id)`
    returning whatever: a backend able to *prove* what it says -- the
    Electrum protocol serves a merkle branch, which a client checks
    against a header it already holds (issues #188, #204 and #1132) --
    returns evidence beside the data, and evidence is a different type.
    Adding a method for it is additive; widening the return type of
    `get_tx` would be a break for everyone already calling it.

    `get_tx_out` is concrete, and is the one operation every backend can
    derive from another: an output is a field of the transaction that
    created it. A backend with a cheaper answer overrides it.
    """

    network: str

    def __init__(self, network: str = "mainnet") -> None:
        """Bind the fetcher to a network, by the name btclib resolves.

        `_validated_network_name` is the converter `descriptors.parse`
        and `p2p.magic.magic_from_network` reach for across modules, so
        the `strip().lower()` tolerance issue #216 decided to keep
        reaches a backend too. `self.network` is a key of `NETWORKS`, and
        it is what `tx_from_raw` labels a transaction with.
        """
        self.network = _validated_network_name(network)

    @abstractmethod
    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction with this id."""

    @abstractmethod
    def get_block_count(self) -> int:
        """Return the height of the chain tip."""

    @abstractmethod
    def get_best_block_id(self) -> bytes:
        """Return the id of the block at the chain tip."""

    @abstractmethod
    def get_block_header(self, height: int) -> BlockHeader:
        """Return the header of the block at this height.

        Height, and not hash: Bitcoin Core and Esplora both answer for a
        hash and map a height to one with a second call --
        `getblockhash`, `/block-height/<height>` -- but the Electrum
        protocol's `blockchain.block.header` takes a height and publishes
        no call that takes a hash at all. A hash-only signature would be
        one this interface's third backend could never answer, which is
        the `NotImplementedError`-in-an-ABC outcome the three questions
        above already avoid.

        Checked on arrival: `assert_valid` and `assert_valid_pow`, so a
        well-formed header answers for eighty bytes that took a real hash
        to produce. `assert_valid_time` is not one of the two -- it
        compares against the local clock, and a header that is genuinely
        on the chain should not start failing this because the machine
        running it has drifted.

        That is the whole of what the check establishes. Not that the
        header is on the chain the caller means, not that it is truly at
        the height asked for, and not that it is the tip: a backend
        serving a real header from the wrong chain, or from the wrong
        height, passes it just the same. Only a chain of headers answers
        that, which is issue #1127's territory and not this method's.
        """

    def get_tx_out(self, out_point: OutPoint) -> TxOut:
        """Return the output an outpoint names, spent or not.

        Spent or not, which is what makes this the useful question and
        not `gettxout`'s. bitcoind's `gettxout` reads the utxo set, so it
        answers null for an output that has been spent -- and every input
        of a confirmed transaction names an output that has been spent,
        by that very transaction. A fee is the inputs less the outputs,
        so an unspent-only answer cannot compute one.

        The cost is that the whole previous transaction is fetched to
        read one output of it, and against bitcoind that means a node
        with `-txindex`.
        """
        tx = self.get_tx(out_point.tx_id)
        if out_point.vout >= len(tx.vout):
            err_msg = f"out of range vout: {out_point.vout}"
            err_msg += f" for a transaction with {len(tx.vout)} outputs"
            raise FetchError(err_msg)
        return tx.vout[out_point.vout]


def tx_id_hex(tx_id: Octets) -> str:
    """Return the display hex of a transaction id, checking it is one.

    Both backends put the id in a request as hex, and both accept
    whatever `Octets` accepts, so both need the same 32-byte check --
    performed here rather than left to the backend, which would otherwise
    report a mistyped id as the remote host's 404.
    """
    return bytes_from_octets(tx_id, 32).hex()


def tx_from_raw(raw: Octets, tx_id: str, network: str) -> Tx:
    """Return the transaction a serialization holds, if it is the one asked for.

    Both backends answer `get_tx` with the serialization rather than with
    a rendering of it, and this is why: the id is a hash of those bytes,
    so recomputing it says whether what arrived is what was asked for. No
    other answer here can be checked at all -- a height and a tip hash
    are taken on the backend's word -- and this one costs a hash of a few
    hundred bytes.

    It is not only the untrusted backend it guards. A node behind a
    caching proxy, a truncated response and a request that raced another
    all show up here, as the wrong id rather than as a wrong amount
    somewhere later.
    """
    if not is_octets(raw):
        # `Tx.parse` reads a stream and lets anything that is not Octets
        # through untouched, so a json number where the hex belongs
        # surfaces as AttributeError on `.read` -- a traceback into the
        # parser for what is the backend answering the wrong shape
        err_msg = f"transaction {tx_id}: not a serialization,"  # type: ignore[unreachable]
        err_msg += f" but a {type(raw).__name__}"
        raise FetchError(err_msg)
    with fetch_errors(f"transaction {tx_id}"):
        tx = tx_for_network(Tx.parse(raw), network)
    if tx.id.hex() != tx_id:
        raise FetchError(f"transaction {tx_id}: the answer is {tx.id.hex()}")
    return tx


def block_header_height(height: int) -> int:
    """Return the height, refusing what no chain has a block at.

    Both backends map a height to a block before they can answer
    `get_block_header` at all -- `getblockhash`,
    `/block-height/<height>` -- so both need the same guard in front of
    that first request, rather than each discovering its own backend's
    answer to a negative or fractional height: RPC code -8 for Core, a
    404 or a 400 for an Esplora deployment, neither naming the height as
    what is wrong with the request.
    """
    if not is_integer(height):
        raise BTClibTypeError(f"invalid height type: {type(height).__name__}")
    if height < 0:
        raise BTClibValueError(f"invalid height: {height}")
    return height


def block_header_from_raw(raw: Octets, height: int) -> BlockHeader:
    """Return the header a serialization holds, checked on arrival.

    Both backends answer with the raw serialization rather than a
    rendering of it, the way `get_tx` does -- but a header names no
    height and no chain of its own, so there is nothing here to recompute
    it against the way `tx_from_raw` recomputes a txid. What is checked
    instead is `Fetcher.get_block_header`'s two: `BlockHeader.assert_valid`,
    for eighty well-formed bytes, and `assert_valid_pow`, for a hash that
    took real work to find. Its docstring is where what neither check
    establishes is written down.
    """
    with fetch_errors(f"block header {height}"):
        header = BlockHeader.parse(raw, check_validity=False)
        header.assert_valid()
        header.assert_valid_pow()
    return header
