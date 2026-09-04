# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The btclib fetcher backed by a `BitcoinCoreRpcClient`.

The client itself is the `bitcoin-core-rpc` package: zero dependencies of
its own, nothing but the standard library behind it, and no part of
btclib. What this module adds is the integration -- the answers turned
into btclib transactions, and the chain the node serves compared with the
network those transactions are labelled for.

The names it re-exports are the package's own, unchanged, so that
`from btclib.fetch.bitcoin_core import BitcoinCoreRpcClient` keeps
resolving. Their behaviour is the package's too, exceptions included: a
`client.call` reached that way raises `bitcoin_core_rpc.RpcError`, not
`btclib.exceptions.RpcError`. The `Fetcher` interface is where btclib's
own exceptions are promised, and `_call` below is the line that makes it
true.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from bitcoin_core_rpc import (
    COOKIE_USER,
    DEFAULT_DATADIR,
    BitcoinCoreRpcClient,
    chain_from_network,
    cookie_auth,
    magic_from_signet_challenge,
)
from typing_extensions import override

from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibValueError, FetchError
from btclib.fetch.fetcher import (
    NetworkVerifyingFetcher,
    block_header_from_raw,
    block_header_height,
    client_errors,
    fetch_errors,
    tx_from_raw,
    tx_id_hex,
)
from btclib.tx import Tx
from btclib.utils import bytes_from_octets

__all__ = [
    "COOKIE_USER",
    "DEFAULT_DATADIR",
    "BitcoinCoreFetcher",
    "BitcoinCoreRpcClient",
    "chain_from_network",
    "cookie_auth",
]

# What a reply that is a number or a hash may weigh: the JSON envelope and a
# value of a few dozen octets. `getrawtransaction` is the one answer here that
# is not small, and it keeps the client's default.
_MAX_SMALL_REPLY = 1024


class BitcoinCoreFetcher(NetworkVerifyingFetcher):
    """The four fetcher questions, answered by a node over its RPC.

    Also a `Broadcaster`: `broadcast` sends `sendrawtransaction`, which
    `-rest` -- and so `BitcoinCoreRestFetcher` -- has no equivalent of.
    Holding a fetcher is not broadcasting; a caller has to call the
    method, and `broadcast`'s own docstring is where its non-idempotence
    is stated, at the point a caller meets it.

    The client is a constructor argument rather than a set of connection
    arguments repeated here: one class owns the endpoint and credentials,
    this one owns the mapping onto btclib types, and a caller who already has
    a client does not build a second.

    `network` is btclib's chain label and belongs here, not to the connection:
    it is what the outputs of a fetched transaction are labelled with. The
    client knows a URL and no chain, so the label is a claim until the node
    is asked, and `assert_network` is the question.

    `signet_challenge` is which signet, for the one label that names more
    than one chain: Core answers `signet` for the default signet and for
    every custom one alike, so a fetcher on a signet of its own passes the
    challenge and `assert_network` holds the node to it. Hex or the bytes
    it spells, as `-signetchallenge` takes it. It is what a custom signet
    needs from this class and the whole of it -- the addresses of one are
    signet's, `NETWORKS` describing the encoding and not the chain -- so it
    is refused with a network that is no signet, and refused with
    `verify_network` off, either being a check that would not be made.
    """

    def __init__(
        self,
        client: BitcoinCoreRpcClient,
        network: str = "mainnet",
        *,
        verify_network: bool = True,
        signet_challenge: str | bytes | None = None,
    ) -> None:
        super().__init__(network, verify_network=verify_network)
        if signet_challenge is not None:
            if chain_from_network(self.network) != "signet":
                err_msg = f"a signet_challenge for {self.network},"
                err_msg += " which is no signet"
                raise BTClibValueError(err_msg)
            if not verify_network:
                err_msg = "a signet_challenge is what verify_network"
                err_msg += " compares, and checks nothing with it off"
                raise BTClibValueError(err_msg)
            # derived here and thrown away, so that a challenge that is no
            # script fails at the line that wrote it rather than at the
            # first fetch: what the check itself uses is the challenge, the
            # comparison being of the node's derived magic against this one
            with client_errors():
                magic_from_signet_challenge(signet_challenge)
        self.client = client
        self.signet_challenge = signet_challenge

    def _call(
        self,
        method: str,
        params: Sequence[Any] | Mapping[str, Any] | None,
        *,
        max_body_size: int | None,
    ) -> Any:
        """Invoke one rpc method, raising btclib's exceptions for it.

        The one line of this class that crosses into `bitcoin_core_rpc`,
        which is why every method below goes through it: the package
        declares a `FetchError` of its own, and what a `Fetcher` promises
        its caller is `btclib.exceptions`'. `client_errors` carries the
        `status` and the `code` across.

        `max_body_size` is omitted rather than passed as None when a
        caller does not narrow it, so the client's own default -- the
        widest ordinary answer -- is what applies.
        """
        bound = {} if max_body_size is None else {"max_body_size": max_body_size}
        with client_errors():
            return self.client.call(method, params, **bound)

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction with this id.

        `getrawtransaction` with no verbosity returns the serialization. Those
        bytes are what `Tx.parse` recomputes the id from, so a transaction
        arriving wrong announces itself. A node answers for a transaction in
        its mempool, one of its wallet's, and -- only with `-txindex` -- any
        other. Without the index the error is RPC code -5.
        """
        self._verify_once()
        hex_ = tx_id_hex(tx_id)
        raw = self._call("getrawtransaction", [hex_], max_body_size=None)
        return tx_from_raw(raw, hex_, self.network)

    @override
    def get_block_count(self) -> int:
        """Return the height of the node's best chain tip."""
        self._verify_once()
        with fetch_errors("getblockcount"):
            reply = self._call("getblockcount", None, max_body_size=_MAX_SMALL_REPLY)
            return int(reply)

    @override
    def get_best_block_id(self) -> bytes:
        """Return the hash of the node's best chain tip, display order."""
        self._verify_once()
        with fetch_errors("getbestblockhash"):
            reply = self._call("getbestblockhash", None, max_body_size=_MAX_SMALL_REPLY)
            return bytes_from_octets(reply, 32)

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Return the header of the block at this height, checked on arrival.

        Two calls, Core answering `getblockheader` by hash and not by
        height: `getblockhash` maps the height first, and `getblockheader`
        with verbosity `false` returns the serialization rather than a
        rendering of it -- the same shape `getrawtransaction` answers
        `get_tx` with.
        """
        self._verify_once()
        height = block_header_height(height)
        with fetch_errors("getblockhash"):
            reply = self._call("getblockhash", [height], max_body_size=_MAX_SMALL_REPLY)
            block_hash = bytes_from_octets(reply, 32).hex()
        raw = self._call(
            "getblockheader", [block_hash, False], max_body_size=_MAX_SMALL_REPLY
        )
        return block_header_from_raw(raw, height)

    @override
    def assert_network(self) -> None:
        """Raise unless the node serves the chain this fetcher labels with.

        Worth the call, because the failure it catches is silent.
        A client built for a testnet node -- an explicit url, no port
        default in the way -- under a fetcher labelled `mainnet` renders a
        mainnet address for every output it fetches, for coins that are
        not there. `getblockchaininfo` answers that in one round trip;
        what it needs is a vocabulary to be compared through, which is
        `chain_from_network`, Core naming the chain `main` where
        btclib names it `mainnet`.

        Signet is the case a name cannot settle: Core reports `signet` for
        the default one and for every custom one alike, so two nodes
        sharing nothing but the shape of a challenge answer the same
        string. The challenge is what tells them apart, and this fetcher's
        is the constructor's `signet_challenge`, or the default signet with
        none given.

        Both comparisons are the client's `assert_chain`, this method being
        the translation into btclib's vocabulary and btclib's exceptions:
        `chain_from_network` on the way in, `client_errors` on the way out.
        The check itself belongs beside the protocol it reads, and lived
        here only while `bitcoin_core_rpc` did not have it.
        """
        # every network of NETWORKS is a chain of Core's -- the catalogue is
        # fixed at import and `tests/fetch/bitcoin_core_test.py` holds the
        # two vocabularies to covering each other -- so the translation
        # cannot fail for a name this fetcher was allowed to carry
        with client_errors():
            self.client.assert_chain(
                chain_from_network(self.network),
                signet_challenge=self.signet_challenge,
            )

    def broadcast(self, tx: Tx, *, maxfeerate: float | None = None) -> bytes:
        """Announce `tx` to the node, and return the txid it confirmed.

        `_verify_once` is called first, as every other method here calls
        it -- but a broadcast to a node on the wrong chain is the worst
        version of the silent failure `verify_network` exists to catch: a
        fetch answering with the wrong data is corrected on the next
        read, where a signed transaction fanned out to the wrong network's
        peers cannot be called back.

        `sendrawtransaction` with the wire serialization, witness
        included -- what a peer relays and eventually mines, not the
        stripped form `Tx.id` hashes. `maxfeerate` is forwarded exactly as
        given, an absent one leaving the parameter out of the call rather
        than substituting a value of this method's choosing: Core's own
        default (`DEFAULT_MAX_RAW_TX_FEE_RATE`) refuses a fee a caller may
        have deliberately chosen, so a default written here would refuse
        it on the caller's behalf.

        The id is computed from `tx` before the request, the way
        `tx_from_raw` recomputes one from a fetched serialization: a
        success naming a different txid is a `FetchError`, the node
        having confirmed some other transaction. One request and no
        retry -- after a timeout this method cannot tell a transaction
        that never reached the mempool from one that did and whose
        acknowledgement was merely lost on the way back, so trying again
        could announce the same signed spend twice for no information
        gained. That decision is the caller's, made with whatever else it
        can ask the node.
        """
        self._verify_once()
        txid = tx.id
        hex_ = tx.serialize(include_witness=True).hex()
        params: list[Any] = [hex_] if maxfeerate is None else [hex_, maxfeerate]
        reply = self._call("sendrawtransaction", params, max_body_size=_MAX_SMALL_REPLY)
        with fetch_errors("sendrawtransaction"):
            answered = bytes_from_octets(reply, 32)
        if answered != txid:
            err_msg = f"broadcast {txid.hex()}: the node confirmed {answered.hex()}"
            raise FetchError(err_msg)
        return answered
