# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The standard-library HTTP transport, re-exported under btclib's name.

`LineTransport` is declared here too, beside it, and not yet implemented
-- the paragraphs below the exceptions one say why and what that costs.

The HTTP half's implementation is `bitcoin_core_rpc`'s: a bounded read, no
redirect followed and no proxy taken from the environment, in a package
that depends on nothing beyond the standard library. btclib depends on it
for the rpc client and reaches the same transport through it, rather than
keeping a second copy of that bounded-read and redirect policy in step
with the first.

Aliases and not wrappers: `EsploraFetcher` passes `transport=` straight
through to `http_request`, and a caller substituting one for a test needs
the object those two agree on. `HttpTransport` is that seam, and this is
btclib's name for it.

Two implementations satisfy it. `urlopen_transport` is the default: one
connection per call, opened and handed to the node to close.
`SessionTransport` keeps one connection per `(scheme, host, port)` open
across calls instead, which is worth choosing over many calls against one
node -- a walker fetching many transactions, a client polling one --
where the reused connection, and on `https` the reused TLS handshake, is
what the default pays for on every call. It has a `close()` and works as
a context manager; nothing here calls either on a caller's behalf.

What does *not* come through unchanged is the exceptions. `http_request`
raises the package's `FetchError` and `HttpError`, which are not the
classes `btclib.exceptions` declares;
`btclib.fetch.fetcher.client_errors` is what translates them, and every
call into this module from inside btclib is wrapped in it.

**`LineTransport` is not an alias of anything.** `bitcoin_core_rpc`'s own
transport is HTTP, and the Electrum protocol `btclib.electrum` speaks is
newline-delimited JSON-RPC over a raw TCP or TLS socket, which that
package does not carry. `ElectrumFetcher` (`btclib.fetch.electrum`) takes
one request line, already terminated by `btclib.electrum.encode_request`'s
own newline, and a timeout in seconds, and returns the answering line
with its delimiter consumed rather than included -- bytes on both sides,
the shape `btclib.electrum`'s own framing already produces and reads, so
the boundary needs no encoding step of its own, the same reason
`HttpTransport` is bytes in and bytes out. A transport that cannot
answer raises `bitcoin_core_rpc`'s own `FetchError` or a subclass of it,
the vocabulary `HttpTransport` already raises through this same package;
`btclib.fetch.fetcher.client_errors` is what translates it, at every
`ElectrumFetcher` call the way it is at every other backend's.

**No implementation ships in this half.** issue #1127's second half is
what adds a strict-verifying one and gives `ElectrumFetcher` a default
transport; until then this is a declared seam and every caller -- and
every test in this tree -- supplies a transport of its own, opening no
socket.
"""

from collections.abc import Callable

from bitcoin_core_rpc import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    MAX_ERROR_BODY_SIZE,
    HttpTransport,
    SessionTransport,
    http_request,
    urlopen_transport,
)

LineTransport = Callable[[bytes, float], bytes]

__all__ = [
    "DEFAULT_MAX_BODY_SIZE",
    "DEFAULT_TIMEOUT",
    "MAX_ERROR_BODY_SIZE",
    "HttpTransport",
    "LineTransport",
    "SessionTransport",
    "http_request",
    "urlopen_transport",
]
