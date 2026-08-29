# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The standard-library HTTP transport, re-exported under btclib's name.

The implementation is `bitcoin_core_rpc`'s: a bounded read, no redirect
followed and no proxy taken from the environment, in a package that
depends on nothing beyond the standard library. btclib depends on it
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
"""

from bitcoin_core_rpc import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    MAX_ERROR_BODY_SIZE,
    HttpTransport,
    SessionTransport,
    http_request,
    urlopen_transport,
)

__all__ = [
    "DEFAULT_MAX_BODY_SIZE",
    "DEFAULT_TIMEOUT",
    "MAX_ERROR_BODY_SIZE",
    "HttpTransport",
    "SessionTransport",
    "http_request",
    "urlopen_transport",
]
