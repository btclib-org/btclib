#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""The btclib fetcher backed by a `BitcoinCoreRpcClient`.

The client itself lives in `btclib.bitcoin_core_rpc`: that file has no btclib
or third-party import and can be vendored as one source file. The imports below
keep the original `btclib.fetch.bitcoin_core` client path working while this
module provides only the integration with btclib transactions and networks.
"""

from btclib.alias import Octets
from btclib.bitcoin_core_rpc import (
    COOKIE_USER,
    DEFAULT_DATADIR,
    BitcoinCoreRpcClient,
    cookie_auth,
)
from btclib.fetch.fetcher import Fetcher, fetch_errors, tx_from_raw, tx_id_hex
from btclib.tx import Tx
from btclib.utils import bytes_from_octets

__all__ = [
    "COOKIE_USER",
    "DEFAULT_DATADIR",
    "BitcoinCoreFetcher",
    "BitcoinCoreRpcClient",
    "cookie_auth",
]

# What a reply that is a number or a hash may weigh: the JSON envelope and a
# value of a few dozen octets. `getrawtransaction` is the one answer here that
# is not small, and it keeps the client's default.
_MAX_SMALL_REPLY = 1024


class BitcoinCoreFetcher(Fetcher):
    """The three fetcher questions, answered by a node over its RPC.

    The client is a constructor argument rather than a set of connection
    arguments repeated here: one class owns the endpoint and credentials,
    this one owns the mapping onto btclib types, and a caller who already has
    a client does not build a second.

    `network` is btclib's chain label and belongs here, not to the connection:
    it is what the outputs of a fetched transaction are labelled with. The
    client knows a URL and no chain, and nothing here asks the node which one
    it serves; `getblockchaininfo` through `call` is how a caller checks.
    """

    def __init__(self, client: BitcoinCoreRpcClient, network: str = "mainnet") -> None:
        super().__init__(network)
        self.client = client

    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction with this id.

        `getrawtransaction` with no verbosity returns the serialization. Those
        bytes are what `Tx.parse` recomputes the id from, so a transaction
        arriving wrong announces itself. A node answers for a transaction in
        its mempool, one of its wallet's, and -- only with `-txindex` -- any
        other. Without the index the error is RPC code -5.
        """
        hex_ = tx_id_hex(tx_id)
        raw = self.client.call("getrawtransaction", [hex_])
        return tx_from_raw(raw, hex_, self.network)

    def get_block_count(self) -> int:
        """Return the height of the node's best chain tip."""
        with fetch_errors("getblockcount"):
            reply = self.client.call("getblockcount", max_body_size=_MAX_SMALL_REPLY)
            return int(reply)

    def get_best_block_id(self) -> bytes:
        """Return the hash of the node's best chain tip, display order."""
        with fetch_errors("getbestblockhash"):
            reply = self.client.call("getbestblockhash", max_body_size=_MAX_SMALL_REPLY)
            return bytes_from_octets(reply, 32)
