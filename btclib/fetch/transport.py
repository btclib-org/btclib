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
network. `http_request` opens no socket itself; it calls whatever
callable it was handed, `urlopen_transport` by default. A test hands it a
function answering from a recorded response, so the suite exercises the
request building, the status handling and the error mapping while opening
no socket at all.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import suppress
from http.client import HTTPMessage
from typing import IO, Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from btclib.exceptions import BTClibTypeError, BTClibValueError, FetchError
from btclib.utils import is_integer

# What a fetcher does its I/O with: a callable taking the request and a
# timeout in seconds, answering with the HTTP status and the response
# body. A status rather than an exception, because a JSON-RPC error can
# arrive with a 500 and its body is the error object -- see
# btclib.fetch.bitcoin_core
#
# Two arguments and no more, which is what a caller's own transport is
# owed and what it owes. What it is owed: a `Request` with its url, its
# method, its body and its headers already built, and a timeout in
# seconds. What it owes, none of which this module can check for it:
#
# - *its own* bound on what it holds in memory while reading. It is handed
#   no `max_body_size` -- there is nowhere in two arguments to pass one --
#   and btclib's limit is a per-call number applied to the bytes it hands
#   back, which is a refusal after the allocation and not instead of it.
#   The two are different bounds, and a transport that reads a body of any
#   size has already spent the memory btclib then declines to use;
# - no redirect followed. The request already carries the `Authorization`
#   for the host it names -- `_OPENER` below is what does this for the
#   default -- and a client library that follows a 30x sends that
#   credential to whatever the `Location` says;
# - its own thread-safety. `BitcoinCoreRpcClient` promises that concurrent
#   calls are safe while its configuration is not mutated, and the
#   transport is part of that configuration: a session object that is not
#   thread-safe makes the client not thread-safe, and only its author
#   knows which it is.
HttpTransport = Callable[[Request, float], tuple[int, bytes]]

# 30 seconds. Long enough for `getrawtransaction` against a node reading
# from a cold transaction index, short enough that a caller notices a host
# that is not answering: urllib's own default is no timeout at all, i.e.
# whatever the socket does, which on a silently dropped connection is
# minutes. A caller who needs longer says so; a default nobody can reach
# is not a timeout
DEFAULT_TIMEOUT = 30.0

# How much of a response body btclib will hold in memory, and why there
# is a number at all: `EsploraFetcher`'s endpoint is allowed to be a
# public explorer -- a host on the internet that says it validated the
# chain -- and `response.read()` with nothing in front of it lets that
# host hand over as much as it likes before any parser of btclib's gets to
# refuse it. The socket timeout is no substitute: a peer delivering data
# slowly but steadily resets it with every packet.
#
# Eight megabytes and a little. The largest of the three answers a fetcher
# asks for is a raw transaction, a transaction fits in a block, and Esplora
# sends it as hex, so the bound is twice Core's 4,000,000-byte buffer bound
# on a serialized block, plus room for the newline a proxy may add.
# btclib/block/limits.py leaves that constant out on purpose, consensus
# capping the weight rather than the size -- here a buffer bound is
# precisely what is wanted, so it is spelled out rather than imported.
# A caller fetching something larger through `http_request` says so with
# max_body_size
_MAX_BLOCK_SERIALIZED_SIZE = 4_000_000
DEFAULT_MAX_BODY_SIZE = 2 * _MAX_BLOCK_SERIALIZED_SIZE + 1024

# where a status stops being an answer and becomes a diagnosis: urlopen
# raises HTTPError from 400 up, so this is the same line drawn for a
# transport of a caller's own that catches its own errors and returns them
_CLIENT_ERROR = 400

# what is kept of the body of a failure: enough to carry whatever the
# backend said with its status, and not the megabytes an error page from
# something in the way can be. Truncated rather than refused, a diagnostic
# being worth more incomplete than absent
MAX_ERROR_BODY_SIZE = 64 * 1024

# http and https, and nothing else. `urlopen` also speaks `file:` and
# `data:`, so a base url taken from configuration could make a fetcher
# read the local disk and report the bytes as a transaction. Refusing the
# scheme here is what makes the `noqa` in `urlopen_transport` true rather
# than hopeful
_SCHEMES = ("http", "https")


class _NoRedirect(HTTPRedirectHandler):
    """The handler that does not follow a 30x, and answers None to say so.

    `redirect_request` returning None means "not handled" to
    `OpenerDirector.error`, which then reaches `HTTPDefaultErrorHandler`
    and raises the `HTTPError` -- so a redirect arrives at `http_request`
    as the status and the bounded body of any other non-2xx.
    """

    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        """Answer None: no redirect is followed, whatever it points at."""
        return None


# The one opener btclib does its I/O with, and what it is missing is the
# point: urllib's default `HTTPRedirectHandler`, which follows a 30x
# before any of this module sees a response. Three things it does that no
# caller asked for, read off CPython's urllib/request.py:
#
# - `redirect_request` copies every request header except `content-length`
#   and `content-type`, so an `Authorization` built for a node reaches
#   whatever host the redirect names -- a JSON-RPC POST also arriving there
#   as a GET;
# - `http_error_302` admits `http`, `https`, `ftp` and the empty scheme, so
#   an https request can be answered with an http target and the scheme
#   check of `http_request` covers only the first url;
# - it calls `fp.read()` with no argument before following, so the whole
#   intermediate body is read whatever `max_body_size` says.
#
# Refused rather than policed, and that is a decision (issue #358): a
# redirect policy is stripping credentials across origins, refusing a
# downgrade, bounding every intermediate body and counting hops, which is
# a redirect implementation inside a module whose subject is one bounded
# request. What following a same-origin redirect would buy a caller -- an
# endpoint that moved path -- is a base url they fix once, and both
# fetchers turn the 30x into a FetchError naming the status and the url,
# which is what tells them to. A caller passing a transport of their own
# does its own I/O, so what `requests` or `httpx` does with a 30x is
# theirs.
#
# `ProxyHandler({})` is the second thing missing, and for the same reason
# as the first. `build_opener` otherwise installs a `ProxyHandler` built
# from `getproxies()`, i.e. from `HTTP_PROXY`, `HTTPS_PROXY` and the
# system's proxy configuration -- so an rpc call to a node would be sent
# to whatever host an environment variable named, carrying the `Basic`
# credential btclib puts on every request before being asked for it.
# Ambient configuration is exactly the wrong source for that decision: the
# variable is set for a browser or a package manager and inherited by
# everything in the shell, while the endpoint here is a node the caller
# named. A caller who does want a proxy has `HttpTransport` and a client
# that reads the environment if that is what they mean.
#
# An empty map does not install an inert handler, it installs none:
# `ProxyHandler.__init__` sets one `<scheme>_open` method per entry,
# `add_handler` keeps a handler only when it registered something, and
# `build_opener` drops the default of a class it was handed an instance
# of. So this argument is how the handler is *removed*, and the chain has
# nothing in it that could proxy.
#
# `build_opener` and not `install_opener`: the default opener is process
# wide, and a library that replaced it would decide this for every other
# user of `urlopen` in the program
_OPENER = build_opener(_NoRedirect, ProxyHandler({}))


def _assert_valid_max_body_size(max_body_size: int) -> None:
    """Refuse a limit that is no size, before it is read as one.

    A float reaches `read` and leaves through a bare `TypeError` about the
    argument of a read, from underneath the library rather than through its
    exception contract; a negative limit makes the bounded read ask for
    nothing and then report every body as too large. Zero is a size and is
    left alone: it says that only an empty body is an answer.

    `is_integer` and not a second spelling of it, so a bool is refused here
    for the reason it is refused everywhere else: `max_body_size=True`
    would be a limit of one octet, and `true` is what a json configuration
    decodes to.
    """
    if not is_integer(max_body_size):
        err_msg = f"non-integer max_body_size: {max_body_size}"
        raise BTClibTypeError(err_msg)
    if max_body_size < 0:
        raise BTClibValueError(f"negative max_body_size: {max_body_size}")


def _read_bounded(response: Any, max_body_size: int, where: str) -> bytes:
    """Return the body, having never held more than the limit of it.

    `Content-Length` first, when the response carries one: a server
    announcing more than the limit is refused before a byte of it is
    read. It is not believed, though -- it is the sender's claim about
    the sender -- so the read is bounded as well, and by one octet more
    than the limit, which is what tells a body *at* the limit from one
    over it.

    The reads are incremental because the point is not to hold the body:
    `read(limit + 1)` may answer with less than was asked for on a
    chunked response, so this loops until the limit is filled or the peer
    is done.
    """
    _assert_valid_max_body_size(max_body_size)

    announced = response.headers.get("Content-Length")
    if announced is not None:
        # a header, so it can be anything: a value that is not a number
        # says nothing about the size and is left to the bounded read
        with suppress(ValueError):
            if int(announced) > max_body_size:
                err_msg = f"{where}: announced {int(announced)} bytes,"
                err_msg += f" more than the {max_body_size} allowed"
                raise FetchError(err_msg)

    chunks = []
    remaining = max_body_size + 1
    while remaining > 0:
        chunk = response.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    body = b"".join(chunks)

    if len(body) > max_body_size:
        raise FetchError(f"{where}: response larger than {max_body_size} bytes")
    return body


def urlopen_transport(
    request: Request,
    timeout: float,
    *,
    max_body_size: int = DEFAULT_MAX_BODY_SIZE,
) -> tuple[int, bytes]:
    """Perform the request with urllib, reading a bounded response.

    The default `HttpTransport`, and the only function in btclib that
    opens a socket. It maps nothing and interprets nothing: the status
    and the bytes go back as they arrived, and `http_request` is where
    the failures become btclib errors.

    Bounded, and this is the only place a bound can be incremental: the
    limit is a keyword with a default, so this function still *is* an
    `HttpTransport` and a caller's own transport still satisfies that
    type. What a transport of someone else's returns is bytes it has
    already read, so all `http_request` can do for those is refuse to pass
    an oversized body on -- see its `max_body_size`.

    No redirect is followed: `_OPENER` above says why, and what a 30x
    arrives as is the `HTTPError` any other non-2xx status does.
    """
    # what reaches the opener is http or https: `http_request` is the only
    # thing that builds a Request, it checks the scheme first, and a
    # redirect cannot introduce a second url
    with _OPENER.open(request, timeout=timeout) as response:
        body = _read_bounded(response, max_body_size, request.full_url)
        return response.status, body


def http_request(
    url: str,
    *,
    data: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_body_size: int = DEFAULT_MAX_BODY_SIZE,
    transport: HttpTransport = urlopen_transport,
) -> tuple[int, bytes]:
    """Return the status and body of a GET, or of a POST when data is given.

    Everything below the HTTP status is a FetchError: a refused
    connection, an unresolvable host and an expired timeout are one
    answer to the caller -- the backend did not answer -- and none of
    them is a bitcoin error worth a type of its own.

    A non-2xx status is *not* a failure here. It comes back like any
    other, because the body of a 500 is where bitcoind's legacy JSON-RPC
    1.1 reply puts its error object, and the body of a 404 is where an
    explorer says what it could not find. Deciding what a status means is
    the backend's job, that being the layer that knows. A 30x is one of
    those statuses now rather than a second request: `urlopen_transport`
    follows no redirect, and `_OPENER` says why.

    `max_body_size` is what an *answer* may weigh, and the caller sets it
    from what it asked for: a tip height is a few octets and a raw
    transaction is megabytes, so one number for both would be the larger.
    The body of a failure is bounded separately, by `MAX_ERROR_BODY_SIZE`
    and by truncation rather than refusal -- an error page arriving one
    octet over a caller's limit for a *height* is still the diagnosis of
    why there is no height.
    """
    _assert_valid_max_body_size(max_body_size)

    scheme = urlsplit(url).scheme
    if scheme not in _SCHEMES:
        raise BTClibValueError(f"invalid url scheme: '{scheme}' instead of http(s)")

    # S310 asks what scheme this url can carry, and the answer is the
    # three lines above: nothing but http and https reaches a Request
    request = Request(  # noqa: S310
        url, data=data, headers=dict(headers or {}), method="POST" if data else "GET"
    )
    try:
        # the limit reaches the read itself for the transport of this
        # module, which is the only one it can: `HttpTransport` is two
        # positional arguments, so a caller's transport has nowhere to be
        # told a limit and nothing to do with one it does not know about.
        # Identity and not a subclass check because there is one such
        # function, and the fetchers pass it explicitly
        if transport is urlopen_transport:
            status, body = urlopen_transport(
                request, timeout, max_body_size=max_body_size
            )
        else:
            status, body = transport(request, timeout)
    except HTTPError as e:
        # a subclass of URLError, so it has to be caught before the OSError
        # below. It is also a response: `read` gives the body the server
        # sent with the status, and discarding it would turn whatever
        # diagnosis the backend offered into a bare number -- bounded,
        # because an error page is written by whatever is in the way and
        # is not a size this library agreed to
        try:
            return e.code, e.read(MAX_ERROR_BODY_SIZE)
        finally:
            # an HTTPError is a response, and a bounded read leaves it with
            # octets still in it: releasing the connection is nobody
            # else's, and an unclosed one is a ResourceWarning out of a
            # deallocator at whatever later moment the collector picks --
            # which under `filterwarnings = ["error"]` fails an unrelated
            # test. The `with` in `urlopen_transport` does this for the
            # responses that are not errors
            e.close()
    except OSError as e:
        # URLError and TimeoutError both derive from it, which is every
        # way urllib reports that the exchange did not happen
        raise FetchError(f"no answer from {url}: {e}") from e

    # a failure, whether it arrived as an exception above or as a status
    # from a transport that catches its own: the body is a diagnostic and
    # not the answer, so it is bounded by truncation rather than held to
    # the caller's limit for the answer. An explorer explaining a 404 in a
    # paragraph of html is worth reading even when what was asked for was
    # a tip height, sixty-four octets wide
    if status >= _CLIENT_ERROR:
        return status, body[:MAX_ERROR_BODY_SIZE]

    # the transport of this module has already stopped reading at the
    # limit; a caller's own has not, and cannot be made to, so this is
    # what is left to promise for one: an oversized answer goes no further
    if len(body) > max_body_size:
        err_msg = f"{url}: response of {len(body)} bytes,"
        err_msg += f" more than the {max_body_size} allowed"
        raise FetchError(err_msg)
    return status, body
