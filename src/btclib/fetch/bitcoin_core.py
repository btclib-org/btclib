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
from btclib.exceptions import BTClibValueError
from btclib.fetch.fetcher import (
    Fetcher,
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


class BitcoinCoreFetcher(Fetcher):
    """The four fetcher questions, answered by a node over its RPC.

    The client is a constructor argument rather than a set of connection
    arguments repeated here: one class owns the endpoint and credentials,
    this one owns the mapping onto btclib types, and a caller who already has
    a client does not build a second.

    `network` is btclib's chain label and belongs here, not to the connection:
    it is what the outputs of a fetched transaction are labelled with. The
    client knows a URL and no chain, so the label is a claim until the node
    is asked, and `assert_network` is the question.

    `verify_network` is who asks it. On by default and before the first
    fetch rather than in this constructor: the answer costs a round trip
    that is worth paying where it is checked and wasted where a fetcher is
    built and never used, and a node that is merely down should not be a
    failure to *construct* anything. The answer is then kept -- a node
    does not change chain under a client that goes on pointing at it --
    and a caller that would rather not ask says `verify_network=False`.

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
        super().__init__(network)
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
        self.verify_network = verify_network
        self.signet_challenge = signet_challenge
        self._agreed = False
        self._disagreement = ""

    def _verify_once(self) -> None:
        """Compare the node's chain with this fetcher's label, once.

        Called by the four fetches and not by `_call`, which is what
        `assert_network` itself goes through: a check in there would ask
        the node about the node, from inside the question.

        A disagreement is remembered and raised again for every later
        fetch, because it is a settled fact about a configuration rather
        than a request that failed -- and a fetcher that asked once,
        refused once and then served an address would be the silent
        failure this exists to stop. A `FetchError` is not an answer and
        is remembered as nothing: the node was unreachable or spoke
        nonsense, which the next fetch may well find otherwise.
        """
        if not self.verify_network or self._agreed:
            return
        if self._disagreement:
            raise BTClibValueError(self._disagreement)
        try:
            self.assert_network()
        except BTClibValueError as e:
            self._disagreement = str(e)
            raise
        self._agreed = True

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

    def assert_network(self) -> None:
        """Raise unless the node serves the chain this fetcher labels with.

        One round trip, asked once and not per fetch: the answer cannot
        change under a client that goes on pointing at the same node.
        `verify_network` is what asks it before the first fetch, and this
        stays public for a caller that wants the question answered at a
        moment of its own -- at startup, or after a client was repointed.

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

        A malformed reply is a `FetchError`. A disagreement is a
        `BTClibValueError`: the node is the authority on which chain it
        serves, so the fetcher's label is the thing to fix.
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
