# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for btclib.fetch.transport."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.client import (
    BadStatusLine,
    HTTPException,
    HTTPMessage,
    IncompleteRead,
    LineTooLong,
)
from io import BytesIO
from types import SimpleNamespace, TracebackType
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPHandler,
    HTTPRedirectHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
    getproxies_environment,
)
from urllib.response import addinfourl

import pytest

from btclib import bitcoin_core_rpc as transport_module
from btclib.exceptions import BTClibTypeError, BTClibValueError, FetchError
from btclib.fetch.transport import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    MAX_ERROR_BODY_SIZE,
    http_request,
    urlopen_transport,
)
from tests.fetch import Recorded

URL = "http://127.0.0.1:8332"
# where a 30x would send the request, and the host that must receive
# nothing: `.invalid` is reserved by RFC 2606, so a test that started
# following redirects would fail on a resolution error rather than reach
# somebody
REDIRECT_URL = "http://elsewhere.invalid/"
# the credential of the reproduction in issue #358, which is what the
# redirected request carried verbatim: `alice:secret`
CREDENTIAL = "Basic YWxpY2U6c2VjcmV0"


def _opener(open_: Callable[..., Any]) -> SimpleNamespace:
    """Return something with an `open`, which is all the transport uses.

    `urlopen_transport` does its I/O through the module's own opener --
    urllib's default one without the redirect handler -- so that is what a
    test replaces, and `.open(request, timeout=...)` is the whole of the
    interface it needs to offer.
    """
    return SimpleNamespace(open=open_)


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
        self._returned_eof = False
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
        if self._returned_eof:
            raise AssertionError("the response was read again after EOF")
        self.reads.append(amt)
        size = len(self._body) - self._offset if amt is None else amt
        if self._chunk_size is not None:
            size = min(size, self._chunk_size)
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        self._returned_eof = not chunk
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

    def fake_open(request: Request, timeout: float) -> FakeResponse:
        seen["request"] = request
        seen["timeout"] = timeout
        return response

    monkeypatch.setattr(transport_module, "_OPENER", _opener(fake_open))

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

        def fake_open(request: Request, timeout: float) -> FakeResponse:
            raise error

        monkeypatch.setattr(transport_module, "_OPENER", _opener(fake_open))

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

        def fake_open(request: Request, timeout: float) -> FakeResponse:
            return response

        monkeypatch.setattr(transport_module, "_OPENER", _opener(fake_open))
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

    def fake_open(request: Request, timeout: float) -> FakeResponse:
        return response

    monkeypatch.setattr(transport_module, "_OPENER", _opener(fake_open))

    request = Request(URL, method="GET")
    assert urlopen_transport(request, DEFAULT_TIMEOUT, max_body_size=limit) == (
        200,
        body,
    )


def test_eof_ends_the_incremental_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty chunk is EOF, so the transport does not read it again."""
    response = FakeResponse(200, b"")

    def fake_open(request: Request, timeout: float) -> FakeResponse:
        return response

    monkeypatch.setattr(transport_module, "_OPENER", _opener(fake_open))

    request = Request(URL, method="GET")
    assert urlopen_transport(request, DEFAULT_TIMEOUT, max_body_size=64) == (
        200,
        b"",
    )
    assert response.reads == [65]
    with pytest.raises(AssertionError, match="read again after EOF"):
        response.read(1)


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
        def fake_open(req: Request, timeout: float) -> FakeResponse:
            return response

        monkeypatch.setattr(transport_module, "_OPENER", _opener(fake_open))

    serve(FakeResponse(200, b"a" * 4, content_length=str(limit + 1)))
    with pytest.raises(FetchError, match=f"announced {limit + 1} bytes"):
        urlopen_transport(request, DEFAULT_TIMEOUT, max_body_size=limit)

    # equal is still within the limit: changing `>` to `>=` must not turn
    # the largest permitted response into an early refusal
    serve(FakeResponse(200, b"a" * limit, content_length=str(limit)))
    assert urlopen_transport(request, DEFAULT_TIMEOUT, max_body_size=limit) == (
        200,
        b"a" * limit,
    )

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

    def fake_open(request: Request, timeout: float) -> FakeResponse:
        return response

    monkeypatch.setattr(transport_module, "_OPENER", _opener(fake_open))

    with pytest.raises(FetchError, match="response larger than 64 bytes"):
        http_request(URL, max_body_size=64)

    # what the read asked for, and the whole of what it asked for: the
    # limit and the one octet that tells a body at it from one over it
    assert response.reads == [65]


def test_an_odd_limit_still_reads_the_octet_that_proves_it_was_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sentinel octet is read after a chunk exactly fills the limit.

    An odd limit distinguishes `limit + 1` from the bitwise expressions a
    mutation can replace it with. The first chunk leaves that one octet to
    read; stopping with one remaining would silently accept a truncated body.
    """
    response = FakeResponse(200, b"a" * 64, chunk_size=63)

    def fake_open(request: Request, timeout: float) -> FakeResponse:
        return response

    monkeypatch.setattr(transport_module, "_OPENER", _opener(fake_open))

    with pytest.raises(FetchError, match="response larger than 63 bytes"):
        http_request(URL, max_body_size=63)
    assert response.reads == [64, 1]


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


def test_the_failure_body_limit_is_64_kib() -> None:
    """The public diagnostic bound has a stable value, not only a name."""
    assert MAX_ERROR_BODY_SIZE == 64 * 1024


def test_the_response_of_a_failure_is_closed() -> None:
    """A bounded read leaves octets in it, and nobody else will close it.

    An HTTPError is a response as well as an exception, so releasing the
    connection is this function's now that it stops reading early. Left
    open, it is a ResourceWarning out of a deallocator at whatever later
    moment the collector picks -- which under `filterwarnings = ["error"]`
    fails whichever unrelated test is running then.
    """
    with http_error(500, b"x" * (MAX_ERROR_BODY_SIZE + 1)) as error:
        closed: list[bool] = []
        already = error.close

        def close() -> None:
            closed.append(True)
            already()

        error.close = close  # type: ignore[method-assign]
        status, body = http_request(URL, transport=Recorded(error))

        assert status == 500
        assert len(body) == MAX_ERROR_BODY_SIZE
        assert closed == [True]


@pytest.mark.parametrize("max_body_size", [1.5, "64", None, 64.0, True, False])
def test_a_limit_that_is_no_size_is_refused_as_such(max_body_size: object) -> None:
    """And refused before it is read as one.

    A float reaches `read` and leaves through a bare `TypeError` about the
    argument of a read: outside this library's exception contract, and out
    of a function whose whole subject is what it refuses to read. A bool
    goes with it, through the `is_integer` of issue #326: `True` would be a
    limit of one octet, and `true` is what a json configuration decodes to.
    """
    transport = Recorded((200, b"7"))
    with pytest.raises(BTClibTypeError, match="non-integer max_body_size"):
        http_request(URL, max_body_size=max_body_size, transport=transport)  # type: ignore[arg-type]
    assert transport.requests == []


def test_a_negative_limit_is_no_limit_at_all() -> None:
    """Where zero is a limit: only an empty body answers it."""
    with pytest.raises(BTClibValueError, match="negative max_body_size: -1"):
        http_request(URL, max_body_size=-1, transport=Recorded((200, b"")))

    assert http_request(URL, max_body_size=0, transport=Recorded((200, b""))) == (
        200,
        b"",
    )
    with pytest.raises(FetchError, match="more than the 0 allowed"):
        http_request(URL, max_body_size=0, transport=Recorded((200, b"7")))


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
    assert DEFAULT_TIMEOUT == 30.0


def test_the_incremental_limit_is_keyword_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two-argument transport protocol stays valid for custom transports."""
    monkeypatch.setattr(
        transport_module,
        "_OPENER",
        _opener(lambda _request, **_kwargs: FakeResponse(200, b"body")),
    )
    untyped_transport: Any = urlopen_transport
    with pytest.raises(TypeError):
        untyped_transport(Request(URL), DEFAULT_TIMEOUT, 64)


def test_a_transport_equal_to_the_default_is_still_the_callers_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The special incremental path is selected by identity, not equality."""
    monkeypatch.setattr(
        transport_module,
        "_OPENER",
        _opener(
            lambda _request, **_kwargs: FakeResponse(200, b"the module's transport")
        ),
    )

    class EqualTransport:
        def __init__(self) -> None:
            self.requests: list[Request] = []

        def __eq__(self, other: object) -> bool:
            return other is urlopen_transport

        def __call__(self, request: Request, timeout: float) -> tuple[int, bytes]:
            self.requests.append(request)
            return 200, b"the caller's transport"

    transport = EqualTransport()
    assert transport == urlopen_transport
    assert http_request(URL, transport=transport) == (200, b"the caller's transport")
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "status, is_error",
    [(int("399"), False), (int("400"), True), (int("401"), True)],
)
def test_a_caller_transport_uses_400_as_the_error_boundary(
    status: int, is_error: bool
) -> None:
    """A 400 starts diagnostics; a 399 remains a size-limited answer."""
    transport = Recorded((status, b"too long"))
    if not is_error:
        with pytest.raises(FetchError, match="more than the 1 allowed"):
            http_request(URL, max_body_size=1, transport=transport)
        return

    assert http_request(URL, max_body_size=1, transport=transport) == (
        status,
        b"too long",
    )


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
    """Where bitcoind's 1.1 error object and Esplora's 404 text come from."""
    with http_error(500, b'{"result":null,"error":{"code":-5}}') as error:
        assert http_request(URL, transport=Recorded(error)) == (
            500,
            b'{"result":null,"error":{"code":-5}}',
        )


def test_the_opener_does_not_follow_a_redirect() -> None:
    """One redirect handler is installed, and it is the one that refuses.

    The direct claim behind the exchange the next test measures, and worth
    a test of its own for what it says when it fails: an opener carrying
    urllib's own handler follows a 30x before this module sees a response,
    and that is a fact about which object is in the chain.
    """
    # getattr with a default because typeshed does not declare `handlers`
    # on OpenerDirector: the attribute is what add_handler appends to, and
    # a plain access would be an attr-defined error rather than a test
    handlers = getattr(transport_module._OPENER, "handlers", [])
    redirect_handlers = [
        handler for handler in handlers if isinstance(handler, HTTPRedirectHandler)
    ]
    assert len(redirect_handlers) == 1
    assert isinstance(redirect_handlers[0], transport_module._NoRedirect)


@pytest.mark.parametrize("variable", ["http_proxy", "HTTPS_PROXY"])
def test_no_proxy_is_taken_from_the_environment(
    variable: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A variable set for a browser does not get btclib's rpc credential.

    `build_opener` installs a `ProxyHandler` built from `getproxies()` by
    default, so without the empty one this module passes it, a call to a
    node on loopback would be sent to whatever host `HTTP_PROXY` names --
    with the `Basic` header btclib puts on every request before being
    asked for one. The environment is inherited by everything in a shell
    and is nobody's statement about which host holds the node.

    There is no proxy handler in the chain at all, which is what passing
    an empty map achieves: `ProxyHandler.__init__` sets one `<scheme>_open`
    method per entry, `add_handler` appends a handler only when it
    registered something, and `build_opener` skips the default of a class
    it was handed an instance of. So the empty one takes the place of
    urllib's and then declines to be in the chain.

    Measured against what the default opener does with the same
    environment, which is the other half of the claim: a handler that
    would have proxied is there, and in btclib's opener it is not.

    These two variables and not `ALL_PROXY`, which is the case that looks
    like a wildcard and is not one: `getproxies_environment` maps it to
    the key `all`, `ProxyHandler` registers `all_open` from that, and
    `OpenerDirector` dispatches an http request through the `http` chain
    alone. So an `ALL_PROXY` handler is installed and never proxies
    either scheme, which would make this a test that a handler exists
    rather than one about where a credential goes.
    """
    monkeypatch.setenv(variable, "http://proxy.invalid:3128")
    assert getproxies_environment()  # the environment does name one

    default = getattr(build_opener(), "handlers", [])
    assert [h for h in default if isinstance(h, ProxyHandler)]

    handlers = getattr(transport_module._OPENER, "handlers", [])
    assert [h for h in handlers if isinstance(h, ProxyHandler)] == []


@pytest.mark.parametrize(
    "target",
    [
        REDIRECT_URL,  # another origin, which is where the credential leaked
        f"{URL}/moved",  # the same one, i.e. an endpoint that changed path
        "https://elsewhere.invalid/",  # an upgrade
        "ftp://elsewhere.invalid/tx",  # not http at all, and urllib admits it
    ],
)
def test_no_redirect_target_is_followed(target: str) -> None:
    """Cross-origin, same-origin, an upgrade and an ftp target alike.

    urllib's own handler follows all four -- `http_error_302` admits http,
    https, ftp and the empty scheme -- and a redirect policy would have had
    to tell them apart: strip the credential across origins, refuse a
    downgrade, bound the intermediate body, keep the rest. Answering None
    before the target is read is what makes the four one case, and it is
    why a downgrade needs no rule of its own: the scheme of the request is
    not consulted either.
    """
    handlers = getattr(transport_module._OPENER, "handlers", [])
    redirect = next(h for h in handlers if isinstance(h, HTTPRedirectHandler))
    headers = HTTPMessage()
    headers["Location"] = target

    request = Request(URL, data=b"{}", headers={"Authorization": CREDENTIAL})
    assert (
        redirect.redirect_request(
            request, BytesIO(b"moved"), 302, "Found", headers, target
        )
        is None
    )


class RecordedBody(BytesIO):
    """A response body that remembers what was read of it.

    Which is the half of the fix a status cannot show: urllib's redirect
    handler calls `fp.read()` with no argument before following, so the
    whole intermediate body was held whatever the caller's limit said. A
    read of -1 in `reads` is that call.
    """

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.reads: list[int] = []

    def read(self, size: int | None = -1, /) -> bytes:
        """Record the size asked for, and answer as a BytesIO does."""
        self.reads.append(-1 if size is None else size)
        return super().read(size)


class RecordedHTTP(HTTPHandler):
    """The opener's socket, replaced by a scripted response in memory.

    A handler and not a whole opener: what the redirect exchange runs
    through is urllib's own chain -- the redirect handler, the error
    processor, the default error handler -- and the only part of it that
    would reach the network is this one. `Location` is set on every
    response, so a handler that follows redirects has somewhere to go and
    the test can tell that it went.
    """

    def __init__(self, code: int, body: bytes) -> None:
        super().__init__()
        self.code = code
        self.body = RecordedBody(body)
        self.requests: list[Request] = []

    # typeshed types `http_open` by what urllib's own answers with, an
    # `HTTPResponse` read off a socket; the chain downstream only takes a
    # status, headers and bytes off it, which is what an `addinfourl` is --
    # and what `FileHandler.file_open` beside it answers with
    def http_open(self, req: Request) -> addinfourl:  # type: ignore[override]
        """Record the request and answer the scripted response."""
        self.requests.append(req)
        headers = HTTPMessage()
        headers["Location"] = REDIRECT_URL
        response = addinfourl(self.body, headers, req.full_url, self.code)
        # what `do_open` sets from the reason line and `HTTPErrorProcessor`
        # reads off a response beside the status; addinfourl has no such
        # attribute of its own, and typeshed says so
        response.msg = "Found"  # type: ignore[attr-defined]
        return response


def _opener_over(handler: HTTPHandler) -> OpenerDirector:
    """Return the module's own opener with `handler` in place of the socket.

    The redirect handler is taken from `_OPENER` rather than named here,
    and that is what makes a test built on this fail if urllib's own comes
    back: the exchange would then be two requests instead of one, which is
    the property under test rather than a spelling of it.
    """
    handlers = getattr(transport_module._OPENER, "handlers", [])
    redirect = next(h for h in handlers if isinstance(h, HTTPRedirectHandler))
    return build_opener(type(redirect), handler)


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_redirect_is_a_status_and_not_a_second_request(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """The credential goes nowhere, and the 30x body is bounded.

    urllib's default handler copies every header but the content ones onto
    the redirected request, so an `Authorization` built for a node reached
    whatever host the `Location` named -- and it read the whole 30x body
    before following, whatever `max_body_size` said.

    The whole chain runs here, socket excepted: `http_request` builds the
    request, `urlopen_transport` hands it to the module's opener, and the
    30x travels `OpenerDirector.error` -> the redirect handler ->
    `HTTPDefaultErrorHandler` -> the `HTTPError` that `http_request`
    answers with a status. What a caller gets is one request and one
    response, which for both fetchers is a `FetchError` naming the status.
    """
    handler = RecordedHTTP(code, b"x" * (MAX_ERROR_BODY_SIZE + 10))
    monkeypatch.setattr(transport_module, "_OPENER", _opener_over(handler))

    status, body = http_request(
        URL,
        data=b'{"method":"getblockcount"}',
        headers={"Authorization": CREDENTIAL},
        max_body_size=64,
    )

    assert status == code
    # bounded as any failure body is, by truncation rather than refusal
    assert len(body) == MAX_ERROR_BODY_SIZE
    # one request, to the url the caller asked for, carrying the credential
    # exactly once and nowhere else
    assert len(handler.requests) == 1
    assert handler.requests[0].full_url == URL
    assert handler.requests[0].get_header("Authorization") == CREDENTIAL
    # and the body of the 30x was read to the bound and no further, which
    # the `fp.read()` of a following handler would have done first
    assert handler.body.reads == [MAX_ERROR_BODY_SIZE]
    assert handler.body.closed


@pytest.mark.parametrize(
    "error",
    [
        URLError("Connection refused"),
        TimeoutError("timed out"),
        ConnectionResetError("peer went away"),
        OSError("no route to host"),
        IncompleteRead(b"ab", 10),
        BadStatusLine("not a status line"),
        LineTooLong("header line"),
    ],
)
def test_an_exchange_that_did_not_happen_is_a_fetch_error(error: Exception) -> None:
    """One answer for every way of not getting one.

    A timeout is the one worth naming among the first four: `socket.timeout`
    has been `TimeoutError` since 3.10, so it arrives here as an OSError like
    the rest, and there is nothing left for a caller to tell apart.

    The last three are the other family, and no relation of `OSError`:
    `HTTPException` is a plain Exception, so an `except OSError` never saw
    them. They come from inside the read rather than from the connect -- a
    chunked body that stopped early, a peer answering something that is not
    a status line -- which is exactly where this function's promise that
    everything below the status is a FetchError used to end.
    """
    assert not issubclass(HTTPException, OSError)
    with pytest.raises(FetchError, match="no answer from"):
        http_request(URL, transport=Recorded(error))


def test_a_failure_body_that_cannot_be_read_keeps_its_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The status outlives the error page, which is the part with a policy.

    An `HTTPError` is a response and its body is the backend's diagnosis, so
    it is read -- and that read is over the same connection that just
    failed, so it can fail the same way. What a caller does about a 503 does
    not depend on the page, so the status goes back with an empty body
    rather than being replaced by a report about reading one.
    """

    class UnreadableError(HTTPError):
        def read(self, amt: int | None = None) -> bytes:
            raise IncompleteRead(b"", 42)

    error = UnreadableError(URL, 503, "busy", HTTPMessage(), None)

    def fake_open(request: Request, timeout: float) -> FakeResponse:
        raise error

    monkeypatch.setattr(transport_module, "_OPENER", _opener(fake_open))

    assert http_request(URL) == (503, b"")


def test_an_explicitly_empty_body_is_still_a_post() -> None:
    """`data=b""` is a body a caller passed, and a POST is what they asked.

    The public contract is a POST "when data is given", and the truth of the
    bytes is not what gives them: an empty body used to build a GET, which
    Core answers with "JSON-RPC: method not allowed" -- a diagnosis about
    the method for a request whose body was the problem. `urllib.request`
    draws the line at `data is None` too.
    """
    methods = []

    def spy(request: Request, timeout: float) -> tuple[int, bytes]:
        methods.append(request.get_method())
        return 200, b"{}"

    http_request(URL, data=b"", transport=spy)
    http_request(URL, data=b"{}", transport=spy)
    http_request(URL, transport=spy)
    assert methods == ["POST", "POST", "GET"]
