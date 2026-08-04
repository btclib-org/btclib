#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Module btclib.fetch.

**Where the chain is.** Everything else in btclib works on bytes it was
handed. This package is the one place that goes and asks: what
transaction has this id, what output does this outpoint name, where is
the chain tip. `Fetcher` is the interface, and it is implemented twice --
`BitcoindFetcher` over a full node's JSON-RPC, `EsploraFetcher` over a
block explorer's HTTP api -- so that calling code takes a `Fetcher` and
never branches on which one it got.

**It adds no dependency.** `urllib.request`, `json` and `base64` from the
standard library are the whole of the client; nothing here is imported by
anything below it, so a user who never fetches never pays for it. The
argument against `requests` is in `btclib.fetch.transport`, along with
the seam that lets the test suite exercise all of this while opening no
socket.

Importing the package does not connect to anything, and constructing a
fetcher does not either: the first call is what opens a connection, and
what raises if there is nothing to connect to.

**What is exported, and what is not.** The two fetchers, the interface
they implement, the rpc client a bitcoind one is reached through, and the
transport seam: the timeout, the protocol a substitute has to satisfy and
the one implementation of it that opens a socket. That last group is here
because the seam is the supported way to test calling code without a node,
which is not a detail of the two implementations.

`bitcoind.cookie_auth` is deliberately not here: `BitcoindRpcClient` takes
a `cookie_path` and reads that file at every call -- the node rewrites the
cookie whenever it restarts -- so a caller who wants cookie authentication
passes the path and never the credential, and a name for reading it is one
way to hold a credential longer than the node does. `fetcher.fetch_errors`,
`tx_from_raw`, `tx_id_hex` and `tx_for_network` are not here either: they
are what an implementation of the interface is built out of, and they are
the answer to a third implementation rather than to a caller of the two --
`from btclib.fetch.fetcher import fetch_errors` is that answer, and it says
which layer it is reaching into.

`FetchError`, `HttpError` and `RpcError` are not here because no exception
is: `btclib.exceptions` holds every one of them together, which is what
lets a caller see at a glance what the library raises.
"""

from btclib.fetch.bitcoind import BitcoindFetcher, BitcoindRpcClient
from btclib.fetch.esplora import BLOCKSTREAM_INFO, EsploraFetcher
from btclib.fetch.fetcher import Fetcher
from btclib.fetch.transport import DEFAULT_TIMEOUT, HttpTransport, urlopen_transport

__all__ = [
    "BLOCKSTREAM_INFO",
    "DEFAULT_TIMEOUT",
    "BitcoindFetcher",
    "BitcoindRpcClient",
    "EsploraFetcher",
    "Fetcher",
    "HttpTransport",
    "urlopen_transport",
]
