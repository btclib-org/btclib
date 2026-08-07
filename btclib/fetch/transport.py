# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The standard-library HTTP transport, re-exported under btclib's name.

The implementation is `bitcoin_core_rpc`'s: a bounded read, no redirect
followed and no proxy taken from the environment, in a package that is one
file with nothing but the standard library behind it. btclib depends on it
for the rpc client and reaches the same transport through it, rather than
keeping a second copy of that bounded-read and redirect policy in step
with the first.

Aliases and not wrappers: `EsploraFetcher` passes `transport=` straight
through to `http_request`, and a caller substituting one for a test needs
the object those two agree on. `HttpTransport` is that seam, and this is
btclib's name for it.

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
    http_request,
    urlopen_transport,
)

__all__ = [
    "DEFAULT_MAX_BODY_SIZE",
    "DEFAULT_TIMEOUT",
    "MAX_ERROR_BODY_SIZE",
    "HttpTransport",
    "http_request",
    "urlopen_transport",
]
