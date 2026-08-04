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
`BitcoinCoreFetcher` over a full node's JSON-RPC, `EsploraFetcher` over a
block explorer's HTTP api -- so that calling code takes a `Fetcher` and
never branches on which one it got.

**It adds no dependency.** `urllib.request`, `json` and `base64` from the
standard library are the whole of the client. Its canonical implementation is
the independently vendorable `btclib.bitcoin_core_rpc`; the transport exports
here are aliases to that same source, not another implementation. The seam
lets the test suite exercise all of this while opening no socket.

It is no longer free for a user who never fetches, and that is what one
exception identity costs. `FetchError` and the two below it are defined in
the standalone file and re-exported by `btclib.exceptions`, so that the
class is one whichever import path a caller reached it by -- the alternative
being two of them that no single `except` catches. Most of the library
imports `btclib.exceptions`, so most of it now loads `urllib.request`, with
`ssl` and `socket` under it; `import btclib` and `btclib.alias` are the kind
that still do not. What no arrangement buys is a copy of that file raising
btclib's class: a copy is another module, and its exceptions are its own.

Importing the package does not connect to anything, and constructing a
fetcher does not either: the first call is what opens a connection, and
what raises if there is nothing to connect to.

**What is exported, and what is not.** The two fetchers, the interface
they implement, the rpc client a Bitcoin Core one is reached through, and
the transport seam: the timeout, the protocol a substitute has to satisfy
and the one implementation of it that opens a socket. That last group is
here because the seam is the supported way to test calling code without a
node, which is not a detail of the two implementations.

`bitcoin_core.cookie_auth` is deliberately not here:
`BitcoinCoreRpcClient` takes a `cookie_path` and reads that file at every
call -- the node rewrites the cookie whenever it restarts -- so a caller
who wants cookie authentication passes the path and never the credential,
and a name for reading it is one way to hold a credential longer than the
node does. `fetcher.fetch_errors`,
`tx_from_raw`, `tx_id_hex` and `tx_for_network` are not here either: they
are what an implementation of the interface is built out of, and they are
the answer to a third implementation rather than to a caller of the two --
`from btclib.fetch.fetcher import fetch_errors` is that answer, and it says
which layer it is reaching into.

`FetchError`, `HttpError` and `RpcError` are not here because no exception
is: `btclib.exceptions` holds every one of them together, which is what
lets a caller see at a glance what the library raises.
"""

from btclib.bitcoin_core_rpc import BitcoinCoreRpcClient
from btclib.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib.fetch.esplora import BLOCKSTREAM_INFO, EsploraFetcher
from btclib.fetch.fetcher import Fetcher
from btclib.fetch.transport import DEFAULT_TIMEOUT, HttpTransport, urlopen_transport

__all__ = [
    "BLOCKSTREAM_INFO",
    "DEFAULT_TIMEOUT",
    "BitcoinCoreFetcher",
    "BitcoinCoreRpcClient",
    "EsploraFetcher",
    "Fetcher",
    "HttpTransport",
    "urlopen_transport",
]
