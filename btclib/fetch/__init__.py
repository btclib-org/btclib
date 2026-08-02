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
"""

from btclib.fetch.bitcoind import AuthProxy, BitcoindFetcher
from btclib.fetch.esplora import BLOCKSTREAM_INFO, EsploraFetcher
from btclib.fetch.fetcher import Fetcher
from btclib.fetch.transport import DEFAULT_TIMEOUT, HttpTransport, urlopen_transport

__all__ = [
    "BLOCKSTREAM_INFO",
    "DEFAULT_TIMEOUT",
    "AuthProxy",
    "BitcoindFetcher",
    "EsploraFetcher",
    "Fetcher",
    "HttpTransport",
    "urlopen_transport",
]
