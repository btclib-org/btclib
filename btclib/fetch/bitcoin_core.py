# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The btclib fetcher backed by a `BitcoinCoreRpcClient`.

The client itself is the `bitcoin-core-rpc` package: one file with nothing
but the standard library behind it, installable or vendorable, and no part
of btclib. What this module adds is the integration -- the answers turned
into btclib transactions, and the chain the node serves compared with the
network those transactions are labelled for.

The five names it re-exports are the package's own, unchanged, so that
`from btclib.fetch.bitcoin_core import BitcoinCoreRpcClient` keeps
resolving. Their behaviour is the package's too, exceptions included: a
`client.call` reached that way raises `bitcoin_core_rpc.RpcError`, not
`btclib.exceptions.RpcError`. The `Fetcher` interface is where btclib's
own exceptions are promised, and `_call` below is the line that makes it
true.
"""

from collections.abc import Mapping, Sequence
from typing import Any

import bitcoin_core_rpc as rpc
from bitcoin_core_rpc import (
    COOKIE_USER,
    DEFAULT_DATADIR,
    BitcoinCoreRpcClient,
    chain_from_network,
    cookie_auth,
)

from btclib import var_bytes
from btclib.alias import Octets
from btclib.exceptions import BTClibValueError
from btclib.fetch.fetcher import (
    Fetcher,
    client_errors,
    fetch_errors,
    tx_from_raw,
    tx_id_hex,
)
from btclib.hashes import hash256
from btclib.network import NETWORKS
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


def _signet_magic(challenge: str) -> bytes:
    """Return the p2p magic a signet's block challenge determines.

    Core: the message start is the first four bytes of the sha256d of the
    block script, serialized with its CompactSize length, taken in the
    order the digest produces them -- which is the reverse of how this
    library writes `magic_bytes`, hence the slice reversed here.
    `tests/network_test.py` checks the default signet's own magic against
    this same computation, from the challenge in Core's chainparams.
    """
    return hash256(var_bytes.serialize(challenge))[:4][::-1]


class BitcoinCoreFetcher(Fetcher):
    """The three fetcher questions, answered by a node over its RPC.

    The client is a constructor argument rather than a set of connection
    arguments repeated here: one class owns the endpoint and credentials,
    this one owns the mapping onto btclib types, and a caller who already has
    a client does not build a second.

    `network` is btclib's chain label and belongs here, not to the connection:
    it is what the outputs of a fetched transaction are labelled with. The
    client knows a URL and no chain, and no fetch asks the node which one it
    serves; `assert_network` is that question, asked when a caller asks it.
    """

    def __init__(self, client: BitcoinCoreRpcClient, network: str = "mainnet") -> None:
        super().__init__(network)
        self.client = client

    def _call(
        self,
        method: str,
        params: Sequence[Any] | Mapping[str, Any] | None = None,
        *,
        max_body_size: int | None = None,
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

    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction with this id.

        `getrawtransaction` with no verbosity returns the serialization. Those
        bytes are what `Tx.parse` recomputes the id from, so a transaction
        arriving wrong announces itself. A node answers for a transaction in
        its mempool, one of its wallet's, and -- only with `-txindex` -- any
        other. Without the index the error is RPC code -5.
        """
        hex_ = tx_id_hex(tx_id)
        raw = self._call("getrawtransaction", [hex_])
        return tx_from_raw(raw, hex_, self.network)

    def get_block_count(self) -> int:
        """Return the height of the node's best chain tip."""
        with fetch_errors("getblockcount"):
            reply = self._call("getblockcount", max_body_size=_MAX_SMALL_REPLY)
            return int(reply)

    def get_best_block_id(self) -> bytes:
        """Return the hash of the node's best chain tip, display order."""
        with fetch_errors("getbestblockhash"):
            reply = self._call("getbestblockhash", max_body_size=_MAX_SMALL_REPLY)
            return bytes_from_octets(reply, 32)

    def assert_network(self) -> None:
        """Raise unless the node serves the chain this fetcher labels with.

        Explicit, and asked by a caller rather than by every fetch: it
        costs an rpc round trip that a caller with one node and one chain
        has no use for, and the answer cannot change under a client that
        goes on pointing at the same node.

        Worth one call, though, because the failure it catches is silent.
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
        string. `signet_challenge` is what tells them apart, and the p2p
        magic derived from it is compared with the network's own -- which
        also checks a caller-registered custom signet, `NETWORKS` being a
        dict a caller adds to, and issue #207 the reason they do.

        A malformed reply is a `FetchError` naming the method. A
        disagreement is a `BTClibValueError`: the node is the authority on
        which chain it serves, so the fetcher's label is the thing to fix.
        """
        with fetch_errors("getblockchaininfo"):
            info: Any = self._call("getblockchaininfo")
            if not isinstance(info, Mapping):
                err_msg = f"not a JSON object: {type(info).__name__}"
                raise BTClibValueError(err_msg)
            chain = info.get("chain")
            if not isinstance(chain, str):
                err_msg = f"no chain name in the reply: {chain!r}"
                raise BTClibValueError(err_msg)
            # None off signet, and the reason the comparison below is
            # written against it rather than against the name a second
            # time: what the node answered is read here, in one place,
            # and what it is worth is decided there
            node_magic: bytes | None = None
            if chain == "signet":
                challenge = info.get("signet_challenge")
                if not isinstance(challenge, str):
                    err_msg = f"no signet_challenge in the reply: {challenge!r}"
                    raise BTClibValueError(err_msg)
                node_magic = _signet_magic(challenge)

        # outside the block above, so that a node that answered a
        # well-formed disagreement is not reported as a failure to fetch
        if node_magic is not None:
            expected_magic = NETWORKS[self.network].magic_bytes
            if node_magic != expected_magic:
                # worded for both mismatches it catches: another signet,
                # and a fetcher that is on no signet at all
                err_msg = "the node is on a signet this fetcher is not:"
                err_msg += f" its challenge derives magic {node_magic.hex()},"
                err_msg += f" where {self.network} has {expected_magic.hex()}"
                raise BTClibValueError(err_msg)
            return
        try:
            expected_chain = chain_from_network(self.network)
        except rpc.BtcRpcValueError as e:
            # `BtcRpcValueError` and not btclib's `BTClibValueError`:
            # `chain_from_network` is the package's function and raises
            # the package's class, so catching btclib's here would let a
            # name it does not know escape as something no caller of
            # `assert_network` is told to expect. The two were spelled
            # alike until the package renamed its own, and this line is
            # why -- it read correct and was wrong.
            #
            # A Network the caller registered: its name is btclib's alone,
            # so there is nothing to compare a chain name with, and only a
            # signet carries an identity a node can be asked for
            err_msg = f"the node is on {chain}, and {self.network} is no"
            err_msg += " chain of Core's to compare that with: a custom"
            err_msg += " network is identified by its challenge, so only a"
            err_msg += " signet node can answer for one"
            raise BTClibValueError(err_msg) from e
        if chain != expected_chain:
            err_msg = f"the node is on {chain}, this fetcher on"
            err_msg += f" {self.network}, which is Core's {expected_chain}"
            raise BTClibValueError(err_msg)
