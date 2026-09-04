# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.fetch.

**Where the chain is.** Everything else in btclib works on bytes it was
handed. This package is the one place that goes and asks: what
transaction has this id, what output does this outpoint name, where is
the chain tip. `Fetcher` is the interface, and it is implemented three
times -- `BitcoinCoreFetcher` over a full node's JSON-RPC,
`BitcoinCoreRestFetcher` over the same node's unauthenticated `-rest`
interface, `EsploraFetcher` over a block explorer's HTTP api -- so that
calling code takes a `Fetcher` and never branches on which one it got.

**`Broadcaster` is the one place that announces a transaction rather than
asking about one**, and is a `typing.Protocol` rather than a fourth
`Fetcher` method: `BitcoinCoreFetcher` and `EsploraFetcher` satisfy it,
`BitcoinCoreRestFetcher` does not -- Core's `-rest` interface is
read-only, and a protocol lets that asymmetry be a fact of the type
rather than a `NotImplementedError` written into a class that never
promised the capability.

**It adds no dependency.** `urllib.request`, `json` and `base64` from the
standard library are the whole of the client. Its canonical implementation is
the `bitcoin-core-rpc` package, which btclib depends on and does not
contain; the transport exports here are aliases to that same source, not
another implementation. The seam lets the test suite exercise all of this
while opening no socket.

**The exceptions a `Fetcher` raises are btclib's**, and that costs one
translation. The package declares a `FetchError`, an `HttpError` and an
`RpcError` of its own -- it declares zero dependencies and imports
nothing of btclib's -- so those are not the classes
`btclib.exceptions` declares, and `fetcher.client_errors` re-raises them
as the ones a caller catches, `status` and `code` carried across. What
that buys back is the import cost: `btclib.exceptions` no longer reaches
a protocol client, so `urllib.request`, `ssl` and `socket` are loaded by
the code that fetches and not by every module that catches.

The re-exported client is the exception: `btclib.fetch.BitcoinCoreRpcClient`
is the package's class unchanged, so calling it directly raises the
package's exceptions and not btclib's. It is the client's API, reached
through btclib's name for it.

Importing the package does not connect to anything, and constructing a
fetcher does not either: the first call is what opens a connection, and
what raises if there is nothing to connect to.

**What is exported, and what is not.** The fetchers, the interface
they implement, `Broadcaster` beside it, the two clients a Bitcoin Core
node is reached through -- `BitcoinCoreRpcClient` for the JSON-RPC
server, `BitcoinCoreRestClient` for `-rest` -- and the transport seam:
the timeout, the protocol a substitute has to satisfy and the two
implementations of it that open a socket -- one connection per call, and
one kept open across calls. That last group is here because the seam is
the supported way to test calling code without a node, which is not a
detail of the fetcher implementations.

`bitcoin_core.cookie_auth` is deliberately not here:
`BitcoinCoreRpcClient` takes a `cookie_path` and reads that file at every
call -- the node rewrites the cookie whenever it restarts -- so a caller
who wants cookie authentication passes the path and never the credential,
and a name for reading it is one way to hold a credential longer than the
node does. `-rest` takes no credential to hold, `BitcoinCoreRestClient`
declaring no equivalent at all. `fetcher.fetch_errors`,
`tx_from_raw`, `tx_id_hex` and `tx_for_network` are not here either: they
are what an implementation of the interface is built out of, and they are
the answer to a caller writing their own rather than to a caller of the
ones shipped here -- `from btclib.fetch.fetcher import fetch_errors` is
that answer, and it says which layer it is reaching into.

`FetchError`, `HttpError` and `RpcError` are not here because no exception
is: `btclib.exceptions` holds every one of them together, which is what
lets a caller see at a glance what the library raises.

**`CachingFetcher` and `FallbackFetcher` answer the same interface from
another `Fetcher`, not from a network.** Neither is a backend: both
compose one or more `Fetcher`s and are exported beside the ones that
open a connection because a caller reaches for them the same way,
`btclib.fetch.decorators` naming the module they actually live in the
way `btclib.fetch.fetcher` does for the interface itself.
"""

from bitcoin_core_rpc import BitcoinCoreRestClient, BitcoinCoreRpcClient

from btclib.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib.fetch.bitcoin_core_rest import BitcoinCoreRestFetcher
from btclib.fetch.broadcaster import Broadcaster
from btclib.fetch.decorators import CachingFetcher, FallbackFetcher
from btclib.fetch.esplora import BLOCKSTREAM_INFO, EsploraFetcher
from btclib.fetch.fetcher import Fetcher
from btclib.fetch.transport import (
    DEFAULT_TIMEOUT,
    HttpTransport,
    SessionTransport,
    urlopen_transport,
)

__all__ = [
    "BLOCKSTREAM_INFO",
    "DEFAULT_TIMEOUT",
    "BitcoinCoreFetcher",
    "BitcoinCoreRestClient",
    "BitcoinCoreRestFetcher",
    "BitcoinCoreRpcClient",
    "Broadcaster",
    "CachingFetcher",
    "EsploraFetcher",
    "FallbackFetcher",
    "Fetcher",
    "HttpTransport",
    "SessionTransport",
    "urlopen_transport",
]
