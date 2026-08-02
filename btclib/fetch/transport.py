#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""HTTP over the standard library, and the seam the tests replace.

`urllib.request` is the whole of the client. Not `requests`, and not
`httpx`: btclib's install closure is hashlib and the
`btclib_libsecp256k1` bindings, and a cryptography library that pulls a
transitive tree of `certifi`, `urllib3`, `charset-normalizer` and `idna`
in order to offer an *optional* convenience has made every user of the
other ninety percent of the library pay for it. What those clients buy over
`urlopen` -- connection pooling, retries, sessions -- is what a caller
fetching a handful of transactions does not need, and a caller who does
need it passes a transport of their own: that is what the `HttpTransport`
alias below is for.

The seam is deliberate, and it is what keeps the test suite off the
network. `http_request` never calls `urlopen` itself; it calls whatever
callable it was handed, `urlopen_transport` by default. A test hands it a
function answering from a recorded response, so the suite exercises the
request building, the status handling and the error mapping while opening
no socket at all.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from btclib.exceptions import BTClibValueError, FetchError

# What a fetcher does its I/O with: a callable taking the request and a
# timeout in seconds, answering with the HTTP status and the response
# body. A status rather than an exception, because a JSON-RPC error can
# arrive with a 500 and its body is the error object -- see
# btclib.fetch.bitcoind
HttpTransport = Callable[[Request, float], tuple[int, bytes]]

# 30 seconds. Long enough for `getrawtransaction` against a node reading
# from a cold transaction index, short enough that a caller notices a host
# that is not answering: urllib's own default is no timeout at all, i.e.
# whatever the socket does, which on a silently dropped connection is
# minutes. A caller who needs longer says so; a default nobody can reach
# is not a timeout
DEFAULT_TIMEOUT = 30.0

# http and https, and nothing else. `urlopen` also speaks `file:` and
# `data:`, so a base url taken from configuration could make a fetcher
# read the local disk and report the bytes as a transaction. Refusing the
# scheme here is what makes the `noqa` in `urlopen_transport` true rather
# than hopeful
_SCHEMES = ("http", "https")


def urlopen_transport(request: Request, timeout: float) -> tuple[int, bytes]:
    """Perform the request with urllib, reading the whole response.

    The default `HttpTransport`, and the only function in btclib that
    opens a socket. It maps nothing and interprets nothing: the status
    and the bytes go back as they arrived, and `http_request` is where
    the failures become btclib errors.
    """
    # what reaches urlopen is http or https: `http_request` is the only
    # thing that builds a Request, and it checks the scheme first
    with urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.status, response.read()


def http_request(
    url: str,
    *,
    data: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    transport: HttpTransport = urlopen_transport,
) -> tuple[int, bytes]:
    """Return the status and body of a GET, or of a POST when data is given.

    Everything below the HTTP status is a FetchError: a refused
    connection, an unresolvable host and an expired timeout are one
    answer to the caller -- the backend did not answer -- and none of
    them is a bitcoin error worth a type of its own.

    A non-2xx status is *not* a failure here. It comes back like any
    other, because the body of a 500 is where bitcoind's JSON-RPC 1.0
    reply puts its error object, and the body of a 404 is where an
    explorer says what it could not find. Deciding what a status means is
    the backend's job, that being the layer that knows.
    """
    scheme = urlsplit(url).scheme
    if scheme not in _SCHEMES:
        raise BTClibValueError(f"invalid url scheme: '{scheme}' instead of http(s)")

    # S310 asks what scheme this url can carry, and the answer is the
    # three lines above: nothing but http and https reaches a Request
    request = Request(  # noqa: S310
        url, data=data, headers=dict(headers or {}), method="POST" if data else "GET"
    )
    try:
        return transport(request, timeout)
    except HTTPError as e:
        # a subclass of URLError, so it has to be caught before the OSError
        # below. It is also a response: `read` gives the body the server
        # sent with the status, and discarding it would turn whatever
        # diagnosis the backend offered into a bare number
        return e.code, e.read()
    except OSError as e:
        # URLError and TimeoutError both derive from it, which is every
        # way urllib reports that the exchange did not happen
        raise FetchError(f"no answer from {url}: {e}") from e
