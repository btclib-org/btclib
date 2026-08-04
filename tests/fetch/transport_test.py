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
    DEFAULT_TIMEOUT,
    http_request,
    urlopen_transport,
)
from tests.fetch import Recorded

URL = "http://127.0.0.1:8332"


class FakeResponse:
    """What the real urlopen answers with, reduced to what is read of it."""

    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body
        self.closed = False

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.closed = True

    def read(self) -> bytes:
        """Return the recorded body."""
        return self._body


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
        return body

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
