#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for btclib.fetch.transport."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from types import TracebackType
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from btclib.exceptions import BTClibValueError, FetchError
from btclib.fetch import transport as transport_module
from btclib.fetch.transport import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    MAX_ERROR_BODY_SIZE,
    http_request,
    urlopen_transport,
)
from tests.fetch import Recorded

URL = "http://127.0.0.1:8332"


class FakeResponse:
    """What the real urlopen answers with, reduced to what is read of it.

    `content_length` is what the response *claims*, which is a header and
    so is the sender's claim about the sender: a test sets it apart from
    the body on purpose. `chunk_size` caps every read, which is what a
    chunked response does and what the bounded read has to loop over.
    """

    def __init__(
        self,
        status: int,
        body: bytes,
        *,
        content_length: str | None = None,
        chunk_size: int | None = None,
    ) -> None:
        self.status = status
        self._body = body
        self.closed = False
        self._offset = 0
        self._chunk_size = chunk_size
        self.reads: list[int | None] = []
        self.headers: dict[str, str] = (
            {} if content_length is None else {"Content-Length": content_length}
        )

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.closed = True

    def read(self, amt: int | None = None) -> bytes:
        """Return up to amt octets of the recorded body, as a socket would.

        Every read is remembered, which is how a test checks that a
        caller's limit reached the read rather than the check after it.
        """
        self.reads.append(amt)
        size = len(self._body) - self._offset if amt is None else amt
        if self._chunk_size is not None:
            size = min(size, self._chunk_size)
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


def test_urlopen_transport_reads_status_and_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one function in btclib that opens a socket, with none opened.

    urlopen is replaced rather than called: what is under test is that
    the status and the body come back untouched and that the timeout is
    handed on, none of which needs a server -- and a test that needed one
    would be a test this suite cannot have.
    """
    seen: dict[str, object] = {}
    response = FakeResponse(200, b"body")

    def fake_urlopen(request: Request, timeout: float) -> FakeResponse:
        seen["request"] = request
        seen["timeout"] = timeout
        return response

    monkeypatch.setattr(transport_module, "urlopen", fake_urlopen)

    request = Request(URL, method="GET")
    assert urlopen_transport(request, 12.5) == (200, b"body")
    assert seen["request"] is request
    assert seen["timeout"] == 12.5
    # the `with` closed it, which is what keeps the connection from
    # being held until the garbage collector notices
    assert response.closed


@contextmanager
def http_error(status: int, body: bytes = b"") -> Iterator[HTTPError]:
    """Yield an HTTPError carrying a body, closed when the test is done.

    Built with no file object, urllib gives it a temporary file of its
    own; nobody closing it is a ResourceWarning raised from a deallocator
    at some later collection, which `filterwarnings = ["error"]` then
    fails an unrelated test with.
    """
    error = HTTPError(URL, status, "Internal Server Error", {}, None)  # type: ignore[arg-type]

    # HTTPError is a response as well as an exception, and this is what
    # the server sent with the status
    def read(n: int = -1) -> bytes:
        # as the real one does: -1 is the whole of it, a size is a size
        return body if n < 0 else body[:n]

    error.read = read  # type: ignore[method-assign]
    try:
        yield error
    finally:
        error.close()


def test_urlopen_transport_does_not_swallow_an_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-2xx is urlopen's exception, and it goes up to http_request."""
    with http_error(500) as error:

        def fake_urlopen(request: Request, timeout: float) -> FakeResponse:
            raise error

        monkeypatch.setattr(transport_module, "urlopen", fake_urlopen)

        with pytest.raises(HTTPError):
            urlopen_transport(Request(URL, method="GET"), DEFAULT_TIMEOUT)


def test_the_body_of_a_response_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bound is the point of the transport, not a courtesy of the peer.

    An explorer is a host on the internet, and an unbounded `read()` lets
    it decide how much memory this process spends before any parser gets
    to refuse the answer. One octet over the limit is what tells a body at
    the limit from one past it.
    """
    limit = 32

    def serve(body: bytes) -> FakeResponse:
        response = FakeResponse(200, body)

        def fake_urlopen(request: Request, timeout: float) -> FakeResponse:
            return response

        monkeypatch.setattr(transport_module, "urlopen", fake_urlopen)
        return response

    serve(b"a" * limit)
    request = Request(URL, method="GET")
    assert urlopen_transport(request, DEFAULT_TIMEOUT, max_body_size=limit) == (
        200,
        b"a" * limit,
    )

    serve(b"a" * (limit + 1))
    with pytest.raises(FetchError, match=f"response larger than {limit} bytes"):
        urlopen_transport(request, DEFAULT_TIMEOUT, max_body_size=limit)


def test_a_chunked_body_is_read_to_the_limit_and_no_further(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """read(n) may answer with less than n, so the bounded read loops.

    A single `read(limit + 1)` would take a chunked response for a short
    one and hand back a truncated body as if the peer were done with it.
    """
    limit = 100
    body = b"z" * limit
    response = FakeResponse(200, body, chunk_size=7)

    def fake_urlopen(request: Request, timeout: float) -> FakeResponse:
        return response

    monkeypatch.setattr(transport_module, "urlopen", fake_urlopen)

    request = Request(URL, method="GET")
    assert urlopen_transport(request, DEFAULT_TIMEOUT, max_body_size=limit) == (
        200,
        body,
    )


def test_an_announced_size_over_the_limit_is_refused_before_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Content-Length fails the request early, and is never believed.

    Early because a server that says it is about to send a gigabyte can be
    refused without reading one, and never believed because the header is
    the sender's claim about the sender: the third case below announces a
    single octet and sends more, and the bounded read is what catches it.
    """
    limit = 16
    request = Request(URL, method="GET")

    def serve(response: FakeResponse) -> None:
        def fake_urlopen(req: Request, timeout: float) -> FakeResponse:
            return response

        monkeypatch.setattr(transport_module, "urlopen", fake_urlopen)

    serve(FakeResponse(200, b"a" * 4, content_length=str(limit + 1)))
    with pytest.raises(FetchError, match=f"announced {limit + 1} bytes"):
        urlopen_transport(request, DEFAULT_TIMEOUT, max_body_size=limit)

    # not a number: no claim about the size, so the read decides
    serve(FakeResponse(200, b"a" * 4, content_length="banana"))
    assert urlopen_transport(request, DEFAULT_TIMEOUT, max_body_size=limit) == (
        200,
        b"a" * 4,
    )

    serve(FakeResponse(200, b"a" * (limit + 1), content_length="1"))
    with pytest.raises(FetchError, match=f"response larger than {limit} bytes"):
        urlopen_transport(request, DEFAULT_TIMEOUT, max_body_size=limit)


def test_an_oversized_body_from_a_caller_transport_goes_no_further() -> None:
    """What is left to promise for a transport this module did not write.

    A caller's transport hands over bytes it has already read, so nothing
    here can keep it from having read them; refusing to pass the body on
    is the whole of what remains, and it is what keeps a fetcher's own
    limit meaningful whichever transport is underneath it.
    """
    transport = Recorded((200, b"a" * 40))
    assert http_request(URL, max_body_size=40, transport=transport) == (200, b"a" * 40)

    with pytest.raises(FetchError, match="response of 40 bytes, more than the 39"):
        http_request(URL, max_body_size=39, transport=Recorded((200, b"a" * 40)))


def test_the_limit_reaches_the_read_of_the_default_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller's limit is incremental where it can be, i.e. here.

    `HttpTransport` is two positional arguments, so a limit cannot be
    handed to a transport this module did not write; the one it did write
    takes it as a keyword, and `http_request` passes it -- otherwise a
    request for a tip height would buffer megabytes before refusing them.
    """
    response = FakeResponse(200, b"a" * 100)

    def fake_urlopen(request: Request, timeout: float) -> FakeResponse:
        return response

    monkeypatch.setattr(transport_module, "urlopen", fake_urlopen)

    with pytest.raises(FetchError, match="response larger than 64 bytes"):
        http_request(URL, max_body_size=64)

    # what the read asked for, and the whole of what it asked for: the
    # limit and the one octet that tells a body at it from one over it
    assert response.reads == [65]


def test_the_body_of_a_failure_is_truncated_not_refused() -> None:
    """An error page is bounded separately, and by truncation.

    A backend's explanation of why there is no answer is worth having
    even when it arrives longer than the answer would have been allowed to
    be: a 404 page is not a 404-byte page. What it may not be is
    unbounded, an error page being written by whatever is in the way.
    """
    with http_error(404, b"x" * (MAX_ERROR_BODY_SIZE + 10)) as error:
        status, body = http_request(URL, max_body_size=64, transport=Recorded(error))
    assert status == 404
    assert len(body) == MAX_ERROR_BODY_SIZE


def test_the_default_limit_is_a_transaction_in_hex() -> None:
    """Twice Core's buffer bound on a block, plus room for a newline."""
    assert DEFAULT_MAX_BODY_SIZE == 2 * 4_000_000 + 1024
    defaults = http_request.__kwdefaults__
    assert defaults is not None
    assert defaults["max_body_size"] == DEFAULT_MAX_BODY_SIZE


def test_the_default_transport_is_the_urllib_one() -> None:
    """Nothing else can be, and no test in this directory relies on it.

    Read off the signature rather than by calling `http_request` without
    a transport, which is the one thing the suite must never do.
    """
    defaults = http_request.__kwdefaults__
    assert defaults is not None
    assert defaults["transport"] is urlopen_transport
    assert defaults["timeout"] == DEFAULT_TIMEOUT


def test_a_get_carries_no_body() -> None:
    """Verify a GET sends no body and uses the default timeout."""
    transport = Recorded((200, b"7"))
    assert http_request(f"{URL}/x", transport=transport) == (200, b"7")
    assert transport.request.get_method() == "GET"
    assert transport.request.data is None
    assert transport.request.full_url == f"{URL}/x"
    assert transport.timeouts == [DEFAULT_TIMEOUT]


def test_data_makes_it_a_post_with_the_headers_given() -> None:
    """Verify data makes the request a POST carrying the headers given."""
    transport = Recorded((200, b"{}"))
    http_request(
        URL,
        data=b'{"method":"getblockcount"}',
        headers={"Content-Type": "application/json"},
        timeout=1.5,
        transport=transport,
    )
    assert transport.request.get_method() == "POST"
    assert transport.body == b'{"method":"getblockcount"}'
    # urllib capitalizes what it is given, so this is the header as sent
    assert transport.request.get_header("Content-type") == "application/json"
    assert transport.timeouts == [1.5]


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "data:text/plain,0100000001",
        "ftp://example.com/tx",
        "127.0.0.1:8332",
        "",
    ],
)
def test_only_http_and_https_are_opened(url: str) -> None:
    """The scheme check, which is what makes the S310 waiver true.

    `file:` and `data:` are the two urlopen would otherwise accept, and
    both turn a base url read from configuration into a way of reading
    the local disk. The last two have no scheme at all.
    """
    transport = Recorded((200, b"never reached"))
    with pytest.raises(BTClibValueError, match="invalid url scheme"):
        http_request(url, transport=transport)
    assert transport.requests == []


def test_an_http_error_is_a_status_and_a_body_not_an_exception() -> None:
    """Where bitcoind's 1.0 error object and Esplora's 404 text come from."""
    with http_error(500, b'{"result":null,"error":{"code":-5}}') as error:
        assert http_request(URL, transport=Recorded(error)) == (
            500,
            b'{"result":null,"error":{"code":-5}}',
        )


@pytest.mark.parametrize(
    "error",
    [
        URLError("Connection refused"),
        TimeoutError("timed out"),
        ConnectionResetError("peer went away"),
        OSError("no route to host"),
    ],
)
def test_an_exchange_that_did_not_happen_is_a_fetch_error(error: Exception) -> None:
    """One answer for four ways of not getting one.

    A timeout is the one worth naming: `socket.timeout` has been
    `TimeoutError` since 3.10, so it arrives here as an OSError like the
    rest, and there is nothing left for a caller to tell apart.
    """
    with pytest.raises(FetchError, match="no answer from"):
        http_request(URL, transport=Recorded(error))
