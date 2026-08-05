# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

# Those terms are the ones below, embedded rather than referenced: this file
# is meant to be copied out of the distribution, and a copy has no LICENSE
# beside it. No year in it, MIT asking for none: a copy nobody has touched
# would otherwise look out of date every January, and updating one is a diff
# against the tag it was taken from rather than a year to bump.
# SPDX-License-Identifier: MIT
# Copyright (c) The btclib developers
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""A standalone JSON-RPC client against Bitcoin Core.

One source file with nothing but the standard library behind it, so that a
project can copy it whole -- **Vendoring and updates** below is how. Its
first consumer is btclib's own `BitcoinCoreFetcher`, which asks a node the
three questions btclib has of a chain and turns the answers into btclib
types: that class is named a few times here, as the example of a caller, and
nothing in this file needs it.

`BitcoinCoreRpcClient` invokes any one rpc method a node has, with
positional or named parameters: one HTTP POST per call, basic
authentication, the result or an exception. Any method, and not only the
three `BitcoinCoreFetcher` asks for -- a caller with a node has every reason
to ask it something else, and refusing that would only mean they write
this class again. One method per call, though: a batch answers several at
once and needs an api for correlating the answers and for partly failing,
which is a question of its own and not this one.

**Not python-bitcoinrpc's `AuthServiceProxy`, and not a port of it.**
That class, and the copy of it Core's test framework maintains, carry the
LGPL-2.1 of their python-jsonrpc ancestry, where btclib is MIT: this is
an implementation of the protocol rather than a translation of theirs,
and shares no line with either. It is not API-compatible with them
either, and does not try to be -- `call("getblockcount")` against an
attribute lookup that builds a method name is a different interface, and
the explicit one is what makes an unknown method a value rather than a
typo that becomes a request.

**Migrating from `AuthServiceProxy`.** A migration and not a drop-in
replacement: four things change, and each of them is the difference
deliberately.

.. code-block:: python

    # a method is an argument, not an attribute: an unknown one is a
    # value that arrives at the node, not an AttributeError here
    rpc.getblock(block_id, 2)
    client.call("getblock", [block_id, 2])

    # and the named form is the other structure Core takes, which no
    # attribute lookup can express
    client.call("getblock", {"blockhash": block_id, "verbosity": 2})

    # credentials leave the url, which is what gets written into a
    # config file and printed in a traceback
    AuthServiceProxy(f"http://{user}:{password}@127.0.0.1:8332")
    BitcoinCoreRpcClient("http://127.0.0.1:8332", user=user, password=password)
    BitcoinCoreRpcClient.from_chain("main")  # or the node's cookie file

    # one wallet of a multi-wallet node, percent-encoded
    client.for_wallet("hot").call("getbalance")

`JSONRPCException` becomes three exceptions, because it covered three
things a caller acts on differently: `RpcError` when the node computed an
error, with its `code`; `HttpError` when the exchange failed, with its
`status`; `FetchError` when there was no answer to read at all. All three
are `FetchError`, so one `except FetchError` is the equivalent of the one
`except JSONRPCException`. What catching them apart buys is a policy on
the status -- a 503 from a full work queue is the case where the same
request works later, and a 401 is the case where it never will. It is not
a rule about which failures are transient: a refused connection and an
expired timeout arrive as a plain `FetchError` and can both clear on
their own.
Whether *this* call may be sent again is the caller's question and the
method's, and this module's docstring says why -- a timeout is not a
deadline.

``batch_`` is what a consumer loses: several calls in one request, which
is a named non-goal here because a batch needs an api for correlating the
answers and for partly failing. Core's maintained fork spells it `batch`.
A loop over `call` is the replacement, at one HTTP request each.

Notifications -- a request sent with no `id`, which a node does not answer
-- are a non-goal too, and no `AuthServiceProxy` consumer is giving one
up: both implementations count an `id` into every request they build, so
sending one at all means reaching past the public interface into
`_request`.

**One call, one HTTP request, and no retry.** A 503 from bitcoind means
its rpc work queue is full and the same request works once the queue
drains, so a retry is the obvious convenience -- and it is the caller's
to write, for two reasons. `call` carries any method, so this class
cannot know whether re-sending one is safe. And a timeout is not a
deadline: a node that stopped answering may still be executing the call,
so a client re-sending a wallet command of its own accord can execute it
twice. `HttpError.status` is what makes the caller's policy three lines
rather than a match on the text of a message.

**JSON-RPC 2.0, and 1.1 read back.** Core answers 1.1 by default and 2.0
to a request carrying the `"jsonrpc": "2.0"` marker, and the difference
is which layer reports a bitcoin error: under 1.1 an unknown transaction
comes back as HTTP 500 with the error object in the body, so a genuine
server fault and a routine "no such transaction" are the same status.
Under 2.0 an rpc error is HTTP 200 with an `error` member, and a non-2xx
means the HTTP exchange itself failed. Both are read here -- a node older
than v28 does not know the marker and replies 1.1 to it -- but only one
of them can be told apart from a proxy in the way.

**No credentials in the url.** A url with the userinfo part filled in --
the `<user>:<password>@` before the host -- puts a password in a string
that ends up in configuration files, tracebacks and logs. Such a url is
refused here; the password arrives as an argument, or, better, is never
seen at all -- `.cookie` is what bitcoind writes for exactly this,
rotated at every restart, readable by the user running the node and by
nobody else.

**Vendoring and updates.** This file is the canonical, standard-library-only
source. Copy `btclib/bitcoin_core_rpc.py` whole from a btclib release tag,
keep the license notice above, and record the tag beside the copy. The
upstream source is
`https://github.com/btclib-org/btclib/blob/master/btclib/bitcoin_core_rpc.py`,
and the raw source of a release is
`https://raw.githubusercontent.com/btclib-org/btclib/<tag>/btclib/bitcoin_core_rpc.py`
-- the whole path, so that it can be fetched as it stands. An update is a
replacement of the whole file; this shows every behavioral change first:

.. code-block:: console

    git diff OLD..NEW -- btclib/bitcoin_core_rpc.py

A vendored copy receives no security or compatibility fix automatically, so
its recorded tag is what tells a maintainer whether it needs replacing. There
is deliberately no embedded version constant: the release tag is the version,
and a number inside a copied source is a second one that can drift from it.
"""

from __future__ import annotations

import json
from base64 import b64encode
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from decimal import Decimal, DecimalException
from http.client import HTTPException, HTTPMessage
from math import isfinite
from pathlib import Path
from secrets import token_hex
from typing import IO, Any
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

__all__ = [
    "COOKIE_USER",
    "DEFAULT_DATADIR",
    "DEFAULT_MAX_BODY_SIZE",
    "DEFAULT_TIMEOUT",
    "MAX_ERROR_BODY_SIZE",
    "BTClibRuntimeError",
    "BTClibTypeError",
    "BTClibValueError",
    "BitcoinCoreRpcClient",
    "FetchError",
    "HttpError",
    "HttpTransport",
    "RpcError",
    "cookie_auth",
    "core_chain_from_network",
    "http_request",
    "network_from_core_chain",
    "urlopen_transport",
]

# These are defined here, rather than as parallel classes beside the rest of
# btclib's exceptions, because an exception has one identity: inside an
# installed btclib the `FetchError` of this module, of `btclib.exceptions` and
# of `btclib.fetch.bitcoin_core` is one class, so one `except` catches
# whichever of the three import paths raised it. Declaring a parallel class
# beside the other exceptions is what would make two.
#
# Not across a copy of this file, which no arrangement here could manage: a
# copy is another module, these definitions execute again in it, and its
# `FetchError` is its own class -- so a project vendoring this catches the
# exception the copy exports, and an `except btclib.exceptions.FetchError`
# beside it catches nothing the copy raises.
#
# The three BTClib bases come with them so the established TypeError,
# ValueError, and RuntimeError hierarchies remain exact.


class BTClibValueError(ValueError):
    """A value no valid input could carry; the library's usual refusal."""


class BTClibTypeError(TypeError):
    """An input of a type no conversion accepts: a caller error."""


class BTClibRuntimeError(RuntimeError):
    """A check that failed on valid inputs, e.g. a failed verification."""


class FetchError(BTClibRuntimeError):
    """A backend did not answer, or did not answer this.

    A RuntimeError and not a ValueError, which is the distinction worth
    keeping: nothing the caller passed is wrong. The node is down, the
    credentials are stale, the explorer sent html, the transaction is not
    in the index -- retrying later can work, and correcting the argument
    cannot.

    It covers the conversion of an answer too. A backend that replies
    with something which is not a transaction has failed, and reporting
    that as the BTClibValueError the parser of the reply raised -- btclib's
    `Tx.parse`, for the fetchers built on this -- would name the parser
    rather than the host that has to be fixed.
    """


class HttpError(FetchError):
    """A backend failed at the HTTP layer, and `status` is what it said.

    A field because acting on a status is the caller's job and btclib's
    retries nothing: a 401 says the credentials are wrong and will stay
    wrong until they are changed, while a 503 from bitcoind says its rpc
    work queue is full and the same request works when the queue drains.
    A caller writing that policy needs to recognise the status, and
    matching on the text of a message is what a field spares them.

    Not every FetchError carries one, and that is the distinction: a
    refused connection and an expired timeout are failures of an exchange
    that never produced a status, and stay a plain FetchError. So does a
    body that is no answer -- not json, not utf-8, not a reply object --
    when it arrived with an HTTP 200: there the status says nothing and
    the shape of the body is the whole diagnosis. The same body under a
    non-200 is this exception instead, carrying that status: it cannot be
    an answer the backend computed, so what is left to report is the
    status it came with. The message states the status too -- an exception
    is a diagnostic before it is a value.

    A FetchError still, so code catching that keeps catching this.
    """

    def __init__(self, message: str, status: int) -> None:
        self.status = status
        super().__init__(message)


class RpcError(FetchError):
    """bitcoind answered with a JSON-RPC error object, and this is it.

    `code` is the node's, from `src/rpc/protocol.h`: -5 is
    RPC_INVALID_ADDRESS_OR_KEY, which is what `getrawtransaction` returns
    for a transaction it cannot find -- including every non-wallet
    transaction on a node running without `-txindex`. A caller that means
    to tell "no such transaction" from "the node is unreachable" needs
    the number, and parsing it back out of the message is what having a
    field avoids.

    `data` is JSON-RPC's optional third member of an error object, kept
    as it arrived. Core leaves it out today, so it is None for every
    error a node sends; a method that starts sending one -- or a proxy
    between the two adding its own -- would otherwise have it dropped
    here, which is the one place it cannot be recovered from.

    A FetchError still, so code catching that keeps catching this.
    """

    def __init__(self, message: str, code: int, data: Any = None) -> None:
        self.code = code
        self.data = data
        super().__init__(f"{message} (rpc error code {code})")


# Inside btclib these have always been public from `btclib.exceptions`, and a
# class's module is part of its traceback and pickle contract. A copied file is
# different: its exceptions truthfully name the module it was copied as.
if __name__ == "btclib.bitcoin_core_rpc":
    BTClibValueError.__module__ = "btclib.exceptions"
    BTClibTypeError.__module__ = "btclib.exceptions"
    BTClibRuntimeError.__module__ = "btclib.exceptions"
    FetchError.__module__ = "btclib.exceptions"
    HttpError.__module__ = "btclib.exceptions"
    RpcError.__module__ = "btclib.exceptions"


def _is_integer(value: Any) -> bool:
    """Return whether value is an integer, with a bool not being one.

    `btclib.utils.is_integer` is the same predicate and states the policy:
    `bool` being a subclass of `int`, every field whose contract is an
    integer quantity accepted `True` as the number one, and the json
    boundary is what makes that worth a refusal rather than a shrug.
    Copied rather than imported, this file importing nothing of btclib's,
    and `tests/integer_policy_test.py` is what keeps the two in step.
    """
    return isinstance(value, int) and not isinstance(value, bool)


# What this module does its I/O with: a callable taking the request and a
# timeout in seconds, answering with the HTTP status and the response
# body. A status rather than an exception, because a JSON-RPC error can
# arrive with a 500 and its body is the error object -- see
# `BitcoinCoreRpcClient` below
#
# Two arguments and no more, which is what a caller's own transport is
# owed and what it owes. What it is owed: a `Request` with its url, its
# method, its body and its headers already built, and a timeout in
# seconds. What it owes, none of which this module can check for it:
#
# - *its own* bound on what it holds in memory while reading. It is handed
#   no `max_body_size` -- there is nowhere in two arguments to pass one --
#   and the limit here is a per-call number applied to the bytes it hands
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

# How much of a response body this module will hold in memory, and why
# there is a number at all: an endpoint is allowed to be a host on the
# internet -- a public explorer that says it validated the chain, which is
# what btclib's `EsploraFetcher` reaches through this same transport -- and
# `response.read()` with nothing in front of it lets that host hand over as
# much as it likes before any parser gets to refuse it. The socket timeout
# is no substitute: a peer delivering data slowly but steadily resets it
# with every packet.
#
# Eight megabytes and a little. The widest answer asked for here is a raw
# transaction, a transaction fits in a block, and an explorer sends it as
# hex, so the bound is twice Core's 4,000,000-byte buffer bound on a
# serialized block, plus room for the newline a proxy may add. A buffer
# bound and not a consensus rule, consensus capping the weight of a block
# rather than its size: btclib's own block/limits.py leaves the constant
# out for that very reason, so it is spelled out here rather than imported
# from anywhere. A caller fetching something larger through `http_request`
# says so with max_body_size
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
# endpoint that moved path -- is a base url they fix once, and a 30x
# arrives as a FetchError naming the status and the url, which is what
# tells them to. A caller passing a transport of their own does its own
# I/O, so what `requests` or `httpx` does with a 30x is theirs.
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

    `_is_integer` and not a second spelling of it, so a bool is refused here
    for the reason it is refused everywhere else: `max_body_size=True`
    would be a limit of one octet, and `true` is what a json configuration
    decodes to.
    """
    if not _is_integer(max_body_size):
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

    The default `HttpTransport`, and the only function that opens a
    socket, here or anywhere in btclib. It maps nothing and interprets
    nothing: the status and the bytes go back as they arrived, and
    `http_request` is where the failures become the exceptions above.

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
    # `data is not None` and not the truth of it: `data=b""` is a body a
    # caller passed, so the request is the POST they asked for. urllib draws
    # the same line -- an absent body is what makes a request a GET there --
    # and Core answers a GET with "JSON-RPC: method not allowed", which is
    # not the diagnosis an empty body deserves
    request = Request(  # noqa: S310
        url,
        data=data,
        headers=dict(headers or {}),
        method="POST" if data is not None else "GET",
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
            try:
                return e.code, e.read(MAX_ERROR_BODY_SIZE)
            except (OSError, HTTPException):
                # the body of the failure failed too -- a connection dropped
                # mid-error-page is `IncompleteRead` here. The status is the
                # part worth keeping and it is already in hand, so it goes
                # back with no body rather than replacing a 503 a caller has
                # a policy for with a report about reading it
                return e.code, b""
        finally:
            # an HTTPError is a response, and a bounded read leaves it with
            # octets still in it: releasing the connection is nobody
            # else's, and an unclosed one is a ResourceWarning out of a
            # deallocator at whatever later moment the collector picks --
            # which under `filterwarnings = ["error"]` fails an unrelated
            # test. The `with` in `urlopen_transport` does this for the
            # responses that are not errors
            e.close()
    except (OSError, HTTPException) as e:
        # URLError and TimeoutError derive from OSError, which is every way
        # urllib reports that the exchange did not happen. `HTTPException` is
        # the other family and no relation of it: `IncompleteRead` from a
        # chunked body that stopped early, `BadStatusLine` and `LineTooLong`
        # from a peer that is not speaking HTTP. Those arrive from inside the
        # read rather than from the connect, so nothing above catches them,
        # and this function promises that everything below the status is a
        # FetchError
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


# the rpc port and the datadir subdirectory of each chain, from Core's
# `CreateBaseChainParams` in src/chainparamsbase.cpp. Main's cookie is in
# the datadir itself, which is the empty subdirectory below. Keyed by
# Core's chain names -- `ChainTypeToString` in src/util/chaintype.cpp,
# which is what `-chain=` reads and what `getblockchaininfo` reports --
# because what they index here is a port and a directory: a chain btclib
# knows and Core has no default port for is an explicit url, which is the
# constructor.
#
# `test` indexes `testnet3`, which is the third vocabulary for that one
# chain and the reason both columns are Core's: a directory name is no
# more btclib's to choose than a port number is
_RPC_PORT = {
    "main": 8332,
    "test": 18332,
    "testnet4": 48332,
    "signet": 38332,
    "regtest": 18443,
}
_DATADIR_SUBDIR = {
    "main": "",
    "test": "testnet3",
    "testnet4": "testnet4",
    "signet": "signet",
    "regtest": "regtest",
}

# btclib's network names against Core's chain names: `mainnet`/`main` and
# `testnet`/`test` differ, the rest agree. btclib spells what BIP32 and
# BIP173 spell, Core what `-chain=` takes, and neither vocabulary is going
# to adopt the other -- btclib's `network` names the encoding table to
# encode *with*, and answers `testnet` for a signet address, where Core's
# `chain` is an identity. So the pair is written down once, here, this
# being the file that speaks Core's protocol and therefore the boundary
# between the two.
#
# A translation of vocabulary and not a promise of availability: v31.1
# warns that support for testnet3 is deprecated and will be removed, so
# `test` is a name Core still reads rather than a chain every node still
# serves.
_CORE_CHAIN_FROM_NETWORK = {
    "mainnet": "main",
    "testnet": "test",
    "testnet4": "testnet4",
    "signet": "signet",
    "regtest": "regtest",
}
_NETWORK_FROM_CORE_CHAIN = {
    chain: network for network, chain in _CORE_CHAIN_FROM_NETWORK.items()
}


def core_chain_from_network(network: str) -> str:
    """Return Core's chain name for one of btclib's network names.

    Raises rather than passing an unrecognized name through, in both
    directions: a chain Core adds later is then a failure here, naming
    what it knows, instead of a string that reaches a node as a port
    lookup or a directory name.
    """
    if network not in _CORE_CHAIN_FROM_NETWORK:
        known = ", ".join(_CORE_CHAIN_FROM_NETWORK)
        raise BTClibValueError(f"unknown network: {network} not in ({known})")
    return _CORE_CHAIN_FROM_NETWORK[network]


def network_from_core_chain(chain: str) -> str:
    """Return btclib's network name for one of Core's chain names.

    The inverse of `core_chain_from_network`, and raising for the same
    reason.
    """
    if chain not in _NETWORK_FROM_CORE_CHAIN:
        known = ", ".join(_NETWORK_FROM_CORE_CHAIN)
        raise BTClibValueError(f"unknown Core chain: {chain} not in ({known})")
    return _NETWORK_FROM_CORE_CHAIN[chain]


# the username bitcoind writes into the cookie file, COOKIEAUTH_USER in
# src/rpc/request.cpp. The node ignores it -- cookie authentication
# compares the whole `user:password` line -- so it is documentation, and
# a cookie file whose first field is something else is still a valid one
COOKIE_USER = "__cookie__"


def _default_datadir() -> Path | None:
    """Return `~/.bitcoin`, or None where no absolute home is knowable.

    Two ways there is no home to name, and neither may raise: this is
    module level, and the module holds the exceptions the rest of the
    library imports, so an exception here fails an import of most of it on
    a host that was never going to fetch anything.

    `Path.home()` raises RuntimeError when nothing resolves `~` -- no
    `HOME` in the environment and no passwd entry for the uid, which is a
    container run under an arbitrary one. It also answers with whatever
    `HOME` holds, so a relative `HOME` gives a relative home and raises
    nothing.

    None for both, rather than a path that is no datadir. A relative one
    would be resolved against the working directory at the moment of the
    read, so `~/.bitcoin/.cookie` would make a file a caller's cwd happens
    to contain the credential this client presents -- a wrong guess about
    the datadir is one thing, reading a credential from wherever the
    process was started is another. `from_chain` refuses instead, naming
    `cookie_path` as what to pass; a caller on macOS or Windows already
    passes one.

    Called by `from_chain` when it derives a cookie path, and not once at
    import: `Path.home()` reads `HOME`, so a value computed at import is
    the environment as it stood whenever the first import reached this
    module -- which, this module holding the library's exceptions, is
    whenever anything imported btclib at all. An unrelated early import is
    no way to decide which credentials a later call sends.
    """
    try:
        home = Path.home()
    except RuntimeError:
        return None
    return home / ".bitcoin" if home.is_absolute() else None


# `~/.bitcoin`, which is the datadir on Linux and on nothing else: macOS
# puts it under ~/Library/Application Support/Bitcoin and Windows under
# %APPDATA%\Bitcoin. Guessing per platform would put two branches here
# that no test on a third platform can reach, and a wrong absolute guess
# fails exactly as an absent file does; `cookie_path` is how a caller says
# where it really is, and the unreadable-cookie error names the file it
# looked for, which is what tells a caller on either platform to pass one
#
# This is the answer as it stood at import, kept for a caller who wants to
# name the location or build a path under it. `from_chain` does not read
# it -- it asks `_default_datadir` at the call, so that a `HOME` set after
# btclib was imported is the one that counts.
#
# `Path | None`, and that is a deliberate declaration rather than an
# oversight: None is what a host with no absolute home directory has, and
# the alternatives are a `Path` that lies -- an invented absolute path -- or
# the relative `~/.bitcoin` that made a cwd file a credential. A caller
# whose strict type checking now asks for the None case is being asked the
# question the value always had
DEFAULT_DATADIR: Path | None = _default_datadir()

# what a cookie file may weigh. bitcoind writes one line of some seventy
# octets, so a bound three orders of magnitude above that refuses nothing
# a node wrote; what it refuses is holding a log, a core dump or a disk
# image in memory whole because `cookie_path` pointed at one, only to
# report a missing colon afterwards
_MAX_COOKIE_SIZE = 4096

# how many random bytes make the `id` of a request this call's. Random
# per call rather than fixed or counted: the echo check exists to catch a
# reply that answers another request -- a caching proxy in the way -- and
# a value reused across calls cannot tell that reply from the right one.
# Random rather than a counter because a counter is shared mutable state,
# which is the one thing that would make a client unsafe to call from two
# threads. Prefixed on the way out, so a node's debug log says whose call
# it was
_RPC_ID_BYTES = 8

# how deep a parameter structure may nest. Both the encoder and the walk
# that checks a structure before it recurse, so a bound is what turns
# something too deep for either into a refusal that names the parameters
# rather than a RecursionError out of the standard library. Core's own
# methods nest a few levels -- the inputs of a psbt, the tree of a
# descriptor -- so this is not a limit a call arrives at
_MAX_PARAMS_DEPTH = 100


def _rpc_id() -> str:
    """Return the `id` of one request, distinct from every other."""
    return f"btclib-{token_hex(_RPC_ID_BYTES)}"


def _assert_valid_timeout(timeout: float, what: str) -> None:
    """Refuse a timeout that is not a number of seconds to wait.

    A bool is not a duration and `timeout=True` would be one second; a
    zero or a negative one makes the socket give up before it connects;
    an infinity or a nan is what `Infinity` in a json configuration
    decodes to. All four reach the socket layer and fail there, out of
    the standard library rather than through btclib's exception contract.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise BTClibTypeError(f"non-numeric {what}: {timeout!r}")
    if not isfinite(timeout) or timeout <= 0:
        raise BTClibValueError(f"{what} is not a positive number of seconds: {timeout}")


def _checked_url(url: str) -> str:
    """Return the endpoint url, having refused what is not one.

    Checked when the client is built and not at the first call, which is
    where `urlopen` would refuse most of it: a url is configuration, and
    configuration that cannot work is worth refusing while the caller who
    supplied it is still looking at the line.
    """
    split = urlsplit(url)
    if split.scheme not in _SCHEMES:
        err_msg = f"invalid rpc url scheme: '{split.scheme}' instead of http(s)"
        raise BTClibValueError(err_msg)
    if split.username is not None or split.password is not None:
        err_msg = "credentials in the rpc url:"
        err_msg += " pass user and password, or use the cookie file"
        raise BTClibValueError(err_msg)
    if not split.hostname:
        raise BTClibValueError(f"no host in the rpc url: {url}")
    if split.query or split.fragment:
        err_msg = f"query or fragment in the rpc url: {url}"
        err_msg += " -- an rpc endpoint is a path, and the call is the body"
        raise BTClibValueError(err_msg)
    try:
        # the port is parsed on access and not before, so this is what
        # refuses `http://node:https` here rather than at the first call
        _ = split.port
    except ValueError as e:
        raise BTClibValueError(f"invalid port in the rpc url: {url}") from e
    return url


def cookie_auth(cookie_path: Path) -> str:
    """Return the `user:password` bitcoind wrote in its cookie file.

    One line, `__cookie__:` and 32 random bytes in hex, rewritten at
    every start of the node. Read at each call rather than once at
    construction: a client built when the node was up and used an hour
    later would otherwise answer 401 for the rest of the process, the
    node having been restarted in between, and the cost of not doing so
    is one small local read against an HTTP round trip.

    One line, ascii, and a bounded read. A path that is not a cookie file
    is the ordinary mistake here, and a credential is the one value that
    must not appear in the error reporting it: what the three checks buy
    is that everything a wrong path produces -- a binary file, a log,
    something enormous -- arrives as a FetchError naming the file, rather
    than as a UnicodeDecodeError or as memory nobody agreed to.
    """
    try:
        with cookie_path.open("rb") as file:
            raw = file.read(_MAX_COOKIE_SIZE + 1)
    except OSError as e:
        raise FetchError(f"unreadable rpc cookie file {cookie_path}: {e}") from e
    if len(raw) > _MAX_COOKIE_SIZE:
        err_msg = f"oversized rpc cookie file {cookie_path}:"
        err_msg += f" more than the {_MAX_COOKIE_SIZE} bytes one can be"
        raise FetchError(err_msg)
    try:
        line = raw.decode("ascii").strip()
    except UnicodeDecodeError as e:
        raise FetchError(f"non-ascii rpc cookie file {cookie_path}: {e}") from e
    if "\n" in line or "\r" in line:
        raise FetchError(f"malformed rpc cookie file {cookie_path}: several lines")
    if ":" not in line:
        raise FetchError(f"malformed rpc cookie file {cookie_path}: no ':' in it")
    return line


def _params_member(params: Sequence[Any] | Mapping[str, Any] | None) -> Any:
    """Return what goes in the request as `params`, refusing what cannot.

    JSON-RPC has two parameter structures and Core takes both: an array,
    read positionally, and an object, read by name. Which of them a
    method wants is the method's business, so both go through unchanged
    -- Core's `args` convenience included, a named call carrying an array
    of leading positional values, which is one key of a caller's mapping
    and needs nothing here.

    A str, bytes or bytearray is a Sequence and is never a list of
    parameters: `call("getblock", block_id)` means one parameter, where
    json would have sent sixty-four of them. Refused rather than wrapped,
    since a caller who meant a sequence of one has `[block_id]` to say so
    and nothing tells the two intentions apart from here.
    """
    if params is None:
        return []
    if isinstance(params, Mapping):
        return dict(params)
    if isinstance(params, (str, bytes, bytearray)):
        err_msg = f"rpc params is a {type(params).__name__} and not a sequence"
        err_msg += " of parameters: pass [params] for a single positional one"
        raise BTClibTypeError(err_msg)
    if isinstance(params, Sequence):
        return list(params)
    err_msg = "rpc params is neither a sequence nor a mapping, but a"  # type: ignore[unreachable]
    err_msg += f" {type(params).__name__}"
    raise BTClibTypeError(err_msg)


def _assert_json_params(
    value: Any, depth: int = 0, enclosing: tuple[int, ...] = ()
) -> None:
    """Refuse a parameter structure json cannot carry, before it is encoded.

    Walked rather than left to the encoder, because most of what goes
    wrong here is silent or unhelpful in it. A mapping keyed by anything
    but a string is *rewritten*: `{1: "a"}` encodes as `{"1": "a"}`, so a
    caller's value reaches the node changed rather than refused, and only
    the outermost mapping is a name a caller wrote by hand. A structure
    containing itself raises ValueError("Circular reference detected"),
    which is the same type a non-finite number raises and means something
    else entirely. One nested past the interpreter's stack raises
    RecursionError from inside the encoder. And a Decimal or a `bytes`
    reaches `default`, which cannot say where in the structure it was.

    `enclosing` carries the ids of the containers this value sits inside,
    which is what a cycle is: a container reached from within itself. No
    depth bound tells that from a structure that is merely deep, and no
    bound on a *reply* helps -- these are the caller's own objects.
    """
    if depth > _MAX_PARAMS_DEPTH:
        err_msg = f"rpc params nested deeper than the {_MAX_PARAMS_DEPTH} allowed"
        raise BTClibValueError(err_msg)
    if _json_scalar(value):
        return
    if isinstance(value, Mapping):
        _assert_no_cycle(value, enclosing)
        for name, item in value.items():
            if not isinstance(name, str):
                raise BTClibTypeError(f"non-string rpc parameter name: {name!r}")
            _assert_json_params(item, depth + 1, (*enclosing, id(value)))
        return
    if isinstance(value, Sequence):
        _assert_no_cycle(value, enclosing)
        for item in value:
            _assert_json_params(item, depth + 1, (*enclosing, id(value)))
        return
    raise BTClibTypeError(f"rpc parameter that is not a json value: {value!r}")


def _json_scalar(value: Any) -> bool:
    """Say whether a value is a json scalar, refusing three that look like one.

    A Decimal, a non-finite float and a `bytes` are each a value a caller
    has a reason to pass and json has no rendering for, so each is refused
    where what to pass instead can be named -- rather than reported as
    "not a json value" from the end of the walk, or, for the `bytes`,
    walked as the list of the ints of its octets.
    """
    if isinstance(value, Decimal):
        err_msg = "Decimal rpc parameter: json carries no exact decimal, so"
        err_msg += " pass what the method documents -- an int of satoshis,"
        err_msg += " or the string it accepts -- rather than a rounded float"
        raise BTClibTypeError(err_msg)
    if isinstance(value, float) and not isfinite(value):
        raise BTClibValueError(f"not a json number in the rpc params: {value}")
    if isinstance(value, (bytes, bytearray)):
        raise BTClibTypeError(f"rpc parameter that is not a json value: {value!r}")
    return value is None or isinstance(value, (bool, int, float, str))


def _assert_no_cycle(value: Any, enclosing: tuple[int, ...]) -> None:
    """Refuse a container reached from inside itself, by the ids it is in."""
    if id(value) in enclosing:
        raise BTClibValueError("rpc params contains itself, so it has no json")


def _refuse_param(value: Any) -> Any:
    """Refuse a parameter the walk before the encoder did not anticipate.

    The backstop, and every type it can be reached with today is one
    `_assert_json_params` refuses first. What keeps it here is that
    `json.dumps` calling this is the alternative to a TypeError from
    inside the encoder: an object that is a `Sequence` of json values and
    still has no json -- `range(3)` is one -- passes the walk and arrives
    here.
    """
    raise BTClibTypeError(f"rpc parameter that is not a json value: {value!r}")


def _json_number(token: str) -> Decimal:
    """Return the Decimal a json number is, having refused a non-finite one.

    `Decimal(token)` is built in whatever decimal context the *caller* is
    running under, and that context decides whether an exponent the
    implementation cannot represent raises or is answered quietly: with
    `InvalidOperation` untrapped -- `localcontext()` and
    `ctx.traps[InvalidOperation] = False`, which is a reasonable thing for a
    program doing its own arithmetic to want -- `1e999999999999999999999999999`
    comes back as `Decimal("NaN")` instead. That is an amount that compares
    false against itself for the rest of its life, arriving past the refusal
    of NaN this module states, and no exception is raised anywhere for the
    `DecimalException` normalization to catch.

    So the value is checked rather than the exception waited for. Size is not
    the question and is deliberately not asked: a finite number is an answer
    however large, which is what lets pypy's decimal build exponents
    libmpdec declines to.
    """
    number = Decimal(token)
    if not number.is_finite():
        raise FetchError(f"not a json number in the reply: {token}")
    return number


def _refuse_constant(name: str) -> Any:
    """Refuse the three non-numbers Python's json decodes by default.

    `NaN`, `Infinity` and `-Infinity` are what Python writes and reads
    for floats json has no numbers for. A node does not send them; a
    proxy or a stub in the way can, and a nan arriving as an amount
    compares false against itself for the rest of its life.
    """
    raise FetchError(f"not a json number in the reply: {name}")


def _http_error(where: str, status: int) -> HttpError:
    """Turn a status that is itself the failure into the exception for it."""
    if status == 401:
        message = f"{where}: HTTP 401, the node refused the credentials"
        return HttpError(message, status)
    return HttpError(f"{where}: HTTP {status}", status)


def _id_error(where: str, request_id: str, reply: Mapping[str, Any]) -> FetchError:
    """Say that a reply answers some request other than this one."""
    err_msg = f"{where}: reply id {reply.get('id')!r}"
    err_msg += f" is not the {request_id!r} asked for"
    return FetchError(err_msg)


def _rpc_error(where: str, error: Any) -> FetchError:
    """Turn what the node put in `error` into the exception for it.

    An error object is a code that is an integer and a message that is a
    string; a caller acts on the first and reads the second, so neither is
    something to render whatever arrived. A missing message would become
    an empty one and a list would be formatted into the exception, both of
    which report the node as having said something it did not.
    """
    if not isinstance(error, Mapping):
        return FetchError(f"{where}: unreadable rpc error {error!r}")
    # Any, both of them: every value of a reply is whatever the backend
    # put there, which is what the two checks below are for
    code: Any = error.get("code")
    message: Any = error.get("message")
    if not _is_integer(code) or not isinstance(message, str):
        return FetchError(f"{where}: unreadable rpc error {error!r}")
    return RpcError(f"{where}: {message}", code, error.get("data"))


def _unreadable(where: str, cause: Exception) -> FetchError:
    """Say what shape a body was, for the 200 where the status says nothing.

    Each shape gets its own sentence, being a different thing to go and
    look at: not utf-8, nested past the interpreter's stack, not json.
    Anything else -- a json integer longer than
    `sys.get_int_max_str_digits` allows, a number whose exponent the
    decimal module refuses to build, and whatever a later Python adds --
    is the parser refusing the reply, which is what happened.

    Only for a 200. Under any other status the shape is not the answer:
    see `_reply_object`, which reaches this only after ruling that out.
    """
    if isinstance(cause, UnicodeDecodeError):
        return FetchError(f"{where}: a reply that is not utf-8 ({cause})")
    if isinstance(cause, RecursionError):
        return FetchError(f"{where}: a reply nested too deeply to parse")
    if isinstance(cause, json.JSONDecodeError):
        return FetchError(f"{where}: not json ({cause})")
    return FetchError(f"{where}: a reply the json parser refused ({cause})")


def _reply_object(where: str, status: int, payload: bytes) -> Mapping[str, Any]:
    """Return the json object a reply is, or say what arrived instead.

    One rule for every body that is not a json-rpc reply, whichever way it
    is not one: none of them can be a *correlated* answer, so none can be
    this call's rpc error, and on a non-200 what is left to report is the
    status -- the 401 with the empty body Core sends, or a 503 whose body
    is whatever stands in front of the node. Reporting the encoding of an
    error page would name the symptom and hide the cause.

    The status cannot be consulted before this, which is why the rule
    lives here and not at the top of `_result`: a 1.1 error object
    arriving with an HTTP 500 *is* a reply, and giving up on the status
    first would report every "no such transaction" from an old node as a
    server fault.
    """
    try:
        reply = json.loads(
            payload, parse_float=_json_number, parse_constant=_refuse_constant
        )
    except FetchError as e:
        # one of this module's own two refusals of a number: the three
        # non-numbers Python decodes by default, through `_refuse_constant`,
        # or a `Decimal` that came back non-finite because the caller's
        # context does not trap that, through `_json_number`. Each names
        # what it saw, so under a 200 it is re-raised as it stands -- `raise
        # _unreadable(...) from e` would hand back this very object and make
        # the exception its own `__cause__`, which anything walking that
        # chain follows in a loop
        if status == 200:
            raise
        raise _http_error(where, status) from e
    except (ValueError, RecursionError, DecimalException) as e:
        # the rest of the ways a parse fails: JSONDecodeError and
        # UnicodeDecodeError are both ValueError, the bare ValueError of
        # the integer digit limit is a third, and json recurses.
        # `DecimalException` is none of those and is the price of
        # `parse_float=Decimal`: `1e999999999999999999999999999` is a json
        # number this parser will not build, an `InvalidOperation` out of
        # the decimal module, and an ArithmeticError rather than a
        # ValueError -- so it escaped a promise this module makes about
        # every unreadable reply
        if status != 200:
            raise _http_error(where, status) from e
        raise _unreadable(where, e) from e
    if not isinstance(reply, dict):
        # read, and still not a reply: an array, a string or a number is
        # no more a json-rpc answer than a page of html is, so a 503 whose
        # body is `[1, 2, 3]` is a 503
        if status != 200:
            raise _http_error(where, status)
        raise FetchError(f"{where}: not a json-rpc reply, but a {type(reply).__name__}")
    return reply


def _legacy_result(
    where: str, request_id: str, status: int, reply: Mapping[str, Any]
) -> Any:
    """Return the `result` of a reply carrying no version marker.

    Core's legacy JSON-RPC 1.1: what a node answers to a request without
    the 2.0 marker, and what v27 and older answer to every request.
    `result` and `error` are both present, one of them null, and an rpc
    error arrives with an HTTP 500 -- so the error is read before the
    status, or every "no such transaction" from an old node would be
    reported as a server fault.

    Before the status, but not before the id. A 500 from something in the
    way, carrying an error object of its own or another call's, is a
    failure of the HTTP exchange and not this call's rpc error.

    And not before the status either when the `error` member is no error
    object: `{"id": ours, "error": "bad"}` under a 503 is a correlated
    something, but nothing the node computed -- so what is left to report is
    the status, which is the thing a caller has a policy for. Only a
    readable error object outranks it.
    """
    ours = reply.get("id") == request_id
    error = reply.get("error")
    if ours and error is not None:
        rpc_error = _rpc_error(where, error)
        if isinstance(rpc_error, RpcError) or status == 200:
            raise rpc_error
        raise _http_error(where, status) from rpc_error
    if status != 200:
        raise _http_error(where, status)
    if not ours:
        raise _id_error(where, request_id, reply)
    if "result" not in reply:
        raise FetchError(f"{where}: a reply with neither result nor error")
    return reply["result"]


def _v2_result(
    where: str, request_id: str, status: int, reply: Mapping[str, Any]
) -> Any:
    """Return the `result` of a JSON-RPC 2.0 reply.

    The status is read first, and that is the whole gain of asking for
    2.0: a non-200 is a failure of the HTTP exchange and never an rpc
    error, Core answering 200 with an `error` member for those. So a 401
    from the node, a 403 from something in front of it and a 503 from a
    full work queue cannot be reported as anything the node computed,
    however json-shaped the body beside them is.

    Then exactly one of `result` and `error`, which is 2.0's own rule and
    what tells a 2.0 reply from a 1.1 one wearing the marker. Which member
    is *present*, and not which is non-null: `"error": null` beside a
    result is the 1.1 shape, and a reply that is 1.1 under a 2.0 marker is
    one whose errors this function would look for in the wrong place.
    """
    if status != 200:
        raise _http_error(where, status)
    if reply.get("id") != request_id:
        raise _id_error(where, request_id, reply)
    has_result = "result" in reply
    has_error = "error" in reply
    if has_result == has_error:
        both = "both result and error" if has_result else "neither result nor error"
        raise FetchError(f"{where}: a 2.0 reply with {both}")
    if has_error:
        raise _rpc_error(where, reply["error"])
    return reply["result"]


class BitcoinCoreRpcClient:
    """One Bitcoin Core JSON-RPC endpoint, and the credentials to reach it.

    Not a dataclass, and that is about the password: a generated
    `__repr__` prints every field, so the credential would appear in any
    traceback that renders the client, and in any log line that prints
    it.

    Credentials or a cookie path, and not both: each of the two says who
    is calling, so a client given both would have to rank them, and a
    caller who passed both has a mistaken idea of which one is in use.
    `from_chain` is the constructor that fills in a cookie path, along
    with the port, from Core's own defaults.

    **Concurrent calls are supported while the configuration is not
    mutated.** `call` writes nothing on the client, opens its own
    connection and takes its request id from no shared counter, so one
    client serves any number of threads. What is not promised is a client
    whose url, credentials or transport are reassigned while a call is in
    flight, or a caller's transport that is not itself thread-safe --
    that one is the transport's own contract.

    **Basic authentication is cleartext over plain HTTP**, that being
    what Core's rpc speaks. On loopback, which is what `from_chain`
    builds, the cleartext is between one process and the node beside it.
    For a node anywhere else it is on the wire, and rpc credentials
    authorise every wallet command that node has: an `https` url, or a
    tunnel, is what keeps them off it.

    Nothing here asks the node which chain it is on. The url and the
    cookie path say where to ask; `BitcoinCoreFetcher`'s `network` says what
    the answers are labelled with, and holding the two together is the
    caller's -- `BitcoinCoreFetcher.assert_network` is what asks, and
    `core_chain_from_network` is the vocabulary it compares through.
    """

    def __init__(
        self,
        url: str,
        *,
        user: str | None = None,
        password: str | None = None,
        cookie_path: Path | str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: HttpTransport = urlopen_transport,
    ) -> None:
        self.url = _checked_url(url)
        if (user is None) != (password is None):
            raise BTClibValueError("rpc user and password go together, or neither")
        if user is not None and cookie_path is not None:
            err_msg = "both rpc credentials and a cookie path:"
            err_msg += " either of them says who is calling, so pass one"
            raise BTClibValueError(err_msg)
        if user is None and cookie_path is None:
            err_msg = "no rpc credentials: pass user and password, or the"
            err_msg += " path of the cookie file the node writes"
            raise BTClibValueError(err_msg)
        for name, value in (("user", user), ("password", password)):
            if value is not None and not isinstance(value, str):
                # the annotation is not a check, and neither half of the
                # credential survives being something else: a `bytes` or an
                # `int` user made the colon test below raise a bare TypeError
                # from underneath the library, and a list passed it and was
                # formatted into the credential -- `['alice']:secret` reaching
                # the node as a username nobody wrote.
                #
                # The type and not the value, which is the same reason this
                # class has no generated `__repr__`: a rejected `password` is
                # a credential, and putting it in an exception writes it into
                # every traceback and log that renders one. The type is what a
                # caller needs to see, and `bytes` is the mistake this catches
                # most often
                err_msg = f"non-string rpc {name}: {type(value).__name__}"  # type: ignore[unreachable]
                raise BTClibTypeError(err_msg)
        if user is not None and ":" in user:
            # the Basic credential is `user:password`, and Core splits it at
            # the *first* colon -- `RPCAuthorized` in src/httprpc.cpp. So a
            # user of `alice:admin` reaches the node as the user `alice`,
            # whose credential begins `admin:`: a different rpc user, a
            # different `-rpcwhitelist` and no error anywhere, the two
            # spellings encoding to the same header so that nothing
            # downstream can tell them apart. A colon on the other side is
            # unambiguous and stays valid, everything after the first one
            # belonging to the second field by definition
            # and the user is not quoted back either, for the reason above
            # applied to this refusal in particular: the string being refused
            # is one with a colon in it, so the likeliest thing it holds is
            # `user:password` written into the first argument -- which is a
            # credential, and would go into the traceback with it.
            # `_checked_url` refuses a url with userinfo in it without echoing
            # the url, and this is the same rule
            err_msg = "colon in the rpc user. The credential is user:password"
            err_msg += " and the node splits it at the first colon, so a user"
            err_msg += " containing one names a different user than intended"
            raise BTClibValueError(err_msg)
        _assert_valid_timeout(timeout, "rpc timeout")
        self.user = user
        self._password = password
        self.cookie_path = None if cookie_path is None else Path(cookie_path)
        self.timeout = timeout
        self.transport = transport

    @classmethod
    def from_chain(
        cls,
        chain: str = "main",
        *,
        user: str | None = None,
        password: str | None = None,
        cookie_path: Path | str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: HttpTransport = urlopen_transport,
    ) -> BitcoinCoreRpcClient:
        """Return a client for the local node of one of Core's chains.

        The convenience of not writing out a loopback url, a port and a
        datadir: all three come from Core's own tables, and everything
        else is the constructor's. `chain` is spelled as Core spells it --
        the string `-chain=` takes and `getblockchaininfo` reports, so
        `main` where btclib says `mainnet` -- because what it indexes here
        is a port and a directory, neither of which btclib names.
        `core_chain_from_network` translates for a caller holding a btclib
        name; a chain btclib knows and Core has no default port for is an
        explicit url with a `cookie_path`, which is the constructor.

        Nor is this the chain the answers get labelled with. That is
        `BitcoinCoreFetcher`'s `network`, and `assert_network` there is
        what asks the node whether it agrees.

        The datadir is asked for here rather than read off
        `DEFAULT_DATADIR`, so that the `HOME` of this call is the one that
        counts and not the one that stood when btclib was first imported.
        Where there is no absolute home directory to name -- see
        `_default_datadir` -- deriving a cookie path is what this refuses,
        rather than reading a relative one against whatever the working
        directory is. `cookie_path` is the answer, and the error says so.

        Nothing is derived when the caller said who is calling: a `user` or
        a `password`, either of them, is an answer to that question, and
        the constructor is where the two are held to going together. A
        cookie derived before that check would report a missing home
        directory to a caller who passed a password and forgot the user.
        """
        if chain not in _RPC_PORT:
            known = ", ".join(_RPC_PORT)
            err_msg = f"unknown chain: {chain} not in ({known})."
            err_msg += " These are Core's names, not btclib's"
            raise BTClibValueError(err_msg)
        if user is None and password is None and cookie_path is None:
            datadir = _default_datadir()
            if datadir is None:
                err_msg = "no home directory, so no default datadir to find"
                err_msg += " the cookie file in: pass cookie_path, or user"
                err_msg += " and password"
                raise BTClibValueError(err_msg)
            cookie_path = datadir / _DATADIR_SUBDIR[chain] / ".cookie"
        return cls(
            f"http://127.0.0.1:{_RPC_PORT[chain]}",
            user=user,
            password=password,
            cookie_path=cookie_path,
            timeout=timeout,
            transport=transport,
        )

    def for_wallet(self, wallet_name: str) -> BitcoinCoreRpcClient:
        """Return a client for this node's `/wallet/<name>` endpoint.

        Which is how a node with several wallets loaded is told which one
        a wallet command is about. The name is percent-encoded, a wallet
        being a directory and free to be called anything a filesystem
        accepts: a space, a `#` or a `/` written into the path unencoded
        addresses a different endpoint, or none.

        The credentials, the timeout and the transport are this client's,
        the endpoint being the only difference -- so a caller working on
        several wallets builds one client and derives the rest.
        """
        url = f"{self.url.rstrip('/')}/wallet/{quote(wallet_name, safe='')}"
        return BitcoinCoreRpcClient(
            url,
            user=self.user,
            password=self._password,
            cookie_path=self.cookie_path,
            timeout=self.timeout,
            transport=self.transport,
        )

    def auth_header(self) -> str:
        """Return the Basic credential, from the arguments or the cookie.

        RFC 7617 leaves the charset of the credential unspecified and
        Core compares the decoded bytes, so utf-8 is a choice that only
        matters for a password with a non-ascii character in it -- where
        it is the choice that matches what a shell and a config file
        would have written.
        """
        if self.cookie_path is not None:
            credential = cookie_auth(self.cookie_path)
        else:
            credential = f"{self.user}:{self._password}"
        return "Basic " + b64encode(credential.encode()).decode("ascii")

    def call(
        self,
        method: str,
        params: Sequence[Any] | Mapping[str, Any] | None = None,
        *,
        request_timeout: float | None = None,
        max_body_size: int = DEFAULT_MAX_BODY_SIZE,
    ) -> Any:
        """Invoke one rpc method, returning its `result`.

        `params` is one value, shaped as json-rpc shapes it: a sequence
        for the positional form, a mapping for the named one. The
        client's own controls are keyword-only for that reason --
        `timeout` is a parameter of several Core methods, and a signature
        mixing the two would have to decide which of them owns the name.

        Amounts do not travel as binary floating point in either
        direction: a number in the reply decodes as a Decimal, and a
        Decimal parameter is refused rather than rounded through `float`.
        `NaN` and `Infinity` are refused both ways, being what Python
        writes for floats json has no numbers for.

        `request_timeout` is this call's, defaulting to the client's.
        What it is for is the handful of methods that legitimately run
        long -- `rescanblockchain`, `scantxoutset`, `dumptxoutset` -- for
        which the alternative is a second client whose wider timeout
        applies to everything.

        `max_body_size` is what the reply may weigh, and it defaults to
        the widest answer a fetcher asks for -- a raw transaction, as hex
        inside a json envelope. A caller invoking something whose reply is
        a number tightens it; one invoking `getblock` on a large block
        widens it, this being their node and their memory.

        There is no retry: one call is one HTTP request, whatever comes
        back. `HttpError.status` is what a caller's own policy reads --
        503 from a full work queue is worth another attempt, 401 never is
        -- and the reason the policy is theirs is in this module's
        docstring: any method may be carried here, and a timeout does not
        say the node stopped executing one.
        """
        request_id = _rpc_id()
        if not isinstance(method, str):
            # json-rpc's `method` is a string, and the annotation is not a
            # check: `call(7)` otherwise built `"method": 7` and sent it,
            # which is this client constructing an invalid request while it
            # walks the caller's params for exactly that reason. An unknown
            # method is a value the node answers for -- that is the point of
            # taking it as an argument -- and a number is not one
            raise BTClibTypeError(f"rpc method that is not a string: {method!r}")
        timeout = self.timeout if request_timeout is None else request_timeout
        _assert_valid_timeout(timeout, "rpc request_timeout")
        params_member = _params_member(params)
        _assert_json_params(params_member)
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params_member,
        }
        try:
            body = json.dumps(request, allow_nan=False, default=_refuse_param).encode()
        except ValueError as e:
            # an int of more digits than `sys.get_int_max_str_digits`
            # allows, which is the mirror of the limit a *reply* holding
            # one runs into: json has the number and this interpreter will
            # not write it. The walk above refuses the types json has no
            # rendering for, and this is a value of a type it does, so the
            # encoder is where it surfaces
            raise BTClibValueError(f"rpc params json cannot carry: {e}") from e
        status, payload = http_request(
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": self.auth_header(),
            },
            timeout=timeout,
            max_body_size=max_body_size,
            transport=self.transport,
        )
        return self._result(method, request_id, status, payload)

    def _result(self, method: str, request_id: str, status: int, payload: bytes) -> Any:
        where = f"{method} at {self.url}"
        reply = _reply_object(where, status, payload)
        if "jsonrpc" not in reply:
            # the member and not its value: `"jsonrpc": null` is a reply
            # that names no protocol, which is not the same thing as a
            # 1.1 reply, and it is the member's absence that means 1.1
            return _legacy_result(where, request_id, status, reply)
        marker = reply["jsonrpc"]
        if marker != "2.0":
            # a version this module does not read, so the object is no
            # answer -- and under a non-200 the status is what is left to
            # report, as it is for a body that would not parse at all. A
            # `"jsonrpc": "1.0"` beside a 503 is a 503, and losing that
            # would cost the caller the policy `HttpError.status` is for
            if status != 200:
                raise _http_error(where, status)
            err_msg = f"{where}: json-rpc version {marker!r}, neither 2.0"
            err_msg += " nor the legacy reply that carries no version at all"
            raise FetchError(err_msg)
        return _v2_result(where, request_id, status, reply)
