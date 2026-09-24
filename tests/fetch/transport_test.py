# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `TlsLineTransport`, over a fake connection.

No socket is opened: `create_connection` is replaced in the module under
test, and the context handed to the transport is an `ssl.SSLContext`
whose `wrap_socket` returns a scripted connection rather than performing
a handshake. What that leaves untested is the handshake itself, which is
`ssl`'s; what it tests is everything this module decides around it --
the deadline, the bounded read, and what a failure becomes.
"""

from __future__ import annotations

import json
import ssl
from typing import Any, Self

import pytest
from bitcoin_core_rpc import FetchError as RpcFetchError
from typing_extensions import override

from btclib.exceptions import BTClibTypeError, BTClibValueError, FetchError
from btclib.fetch import transport as transport_module
from btclib.fetch.electrum import ElectrumFetcher
from btclib.fetch.transport import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    TlsLineTransport,
)
from tests.fetch import TIP_HEADER_RAW, TIP_HEIGHT

HOST = "electrum.example"
PORT = 50002
REQUEST = b'{"id": 1, "method": "server.ping", "params": []}\n'


class FakeConnection:
    """A socket answering `recv` from a script, recording everything else.

    Stands in for both the TCP socket `create_connection` returns and the
    TLS one `wrap_socket` returns: each chunk is consumed in order, an
    `Exception` among them is raised in its place, and an exhausted
    script reads as the peer closing the connection.
    """

    def __init__(self, *chunks: bytes | Exception) -> None:
        self.chunks = list(chunks)
        self.sent = b""
        self.timeouts: list[float] = []
        self.asked: list[int] = []
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        """Record the timeout each operation was given."""
        self.timeouts.append(timeout)

    def sendall(self, data: bytes) -> None:
        """Record what was sent."""
        self.sent += data

    def recv(self, size: int) -> bytes:
        """Answer the next scripted chunk, or b'' once there are none."""
        self.asked.append(size)
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, Exception):
            raise chunk
        assert len(chunk) <= size
        return chunk

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.closed = True


class FakeContext(ssl.SSLContext):
    """An `ssl.SSLContext` whose handshake is a scripted connection."""

    tls: FakeConnection
    failure: Exception | None
    server_hostname: str | None

    @override
    def wrap_socket(  # type: ignore[override]
        self, sock: Any, server_hostname: str | None = None, **_: Any
    ) -> FakeConnection:
        """Return the scripted TLS connection, or raise the scripted failure."""
        self.wrapped = sock
        self.server_hostname = server_hostname
        if self.failure is not None:
            raise self.failure
        return self.tls


def fake_context(
    *chunks: bytes | Exception, failure: Exception | None = None
) -> FakeContext:
    """Return a context whose TLS connection answers with these chunks."""
    context = FakeContext(ssl.PROTOCOL_TLS_CLIENT)
    context.tls = FakeConnection(*chunks)
    context.failure = failure
    return context


@pytest.fixture
def tcp(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Replace `create_connection`, recording each call and its socket.

    Every test that reaches `__call__` takes this, so a test that forgot
    it would be the one test here that opens a real socket.
    """
    calls: list[Any] = []

    def create_connection(address: tuple[str, int], timeout: float) -> FakeConnection:
        sock = FakeConnection()
        calls.append((address, timeout, sock))
        return sock

    monkeypatch.setattr(transport_module, "create_connection", create_connection)
    return calls


def test_the_default_context_verifies_the_certificate_and_the_host() -> None:
    """The strict posture: a chain to the trust store, and the host checked."""
    context = TlsLineTransport(HOST, PORT).context
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_construction_keeps_what_it_was_given() -> None:
    """The context passed is the one used, not a copy or a default."""
    context = fake_context()
    transport = TlsLineTransport(HOST, PORT, context=context, max_line_size=10)
    assert transport.host == HOST
    assert transport.port == PORT
    assert transport.context is context
    assert transport.max_line_size == 10
    assert TlsLineTransport(HOST, PORT).max_line_size == DEFAULT_MAX_BODY_SIZE


def test_one_line_is_sent_and_one_line_read(tcp: list[Any]) -> None:
    """The answer without its newline; what follows it is not returned."""
    answer = b'{"id": 1, "result": null}'
    notification = b'{"method": "blockchain.headers.subscribe"}\n'
    context = fake_context(answer + b"\n" + notification)
    line = TlsLineTransport(HOST, PORT, context=context)(REQUEST, 7.0)
    assert line == answer
    [(address, timeout, sock)] = tcp
    assert address == (HOST, PORT)
    assert timeout == 7.0
    assert context.wrapped is sock
    assert context.server_hostname == HOST
    assert context.tls.sent == REQUEST
    assert context.tls.closed
    assert sock.closed


def test_every_operation_gets_what_is_left_of_one_deadline(
    tcp: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """No operation is given more than what is left of the one deadline."""
    clock = iter([100.0, 100.5, 101.0, 101.5, 102.0, 102.5])
    monkeypatch.setattr(transport_module, "monotonic", lambda: next(clock))
    context = fake_context(b'{"id"', b": 1}", b"\n")
    TlsLineTransport(HOST, PORT, context=context)(REQUEST, 3.0)
    [(_, _, sock)] = tcp
    timeouts = sock.timeouts + context.tls.timeouts
    assert len(timeouts) == 1 + 1 + 3
    assert timeouts == [2.5, 2.0, 1.5, 1.0, 0.5]


def test_a_line_arriving_in_pieces_is_joined(tcp: list[Any]) -> None:
    """A line is what ends at the newline, not what one read returns."""
    context = fake_context(b'{"id": 1, ', b'"result": ', b"true}\n")
    line = TlsLineTransport(HOST, PORT, context=context)(REQUEST, 1.0)
    assert line == b'{"id": 1, "result": true}'


def test_the_deadline_is_over_the_whole_exchange(
    tcp: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server dripping a line cannot hold the call past its timeout."""
    clock = iter([100.0, 100.5, 101.0, 101.5, 102.5])
    monkeypatch.setattr(transport_module, "monotonic", lambda: next(clock))
    context = fake_context(b"{", b"}")
    with pytest.raises(RpcFetchError, match="timeout expired"):
        TlsLineTransport(HOST, PORT, context=context)(REQUEST, 2.0)


def test_a_line_at_the_limit_is_an_answer(tcp: list[Any]) -> None:
    """`max_line_size` counts the line, the newline not included."""
    context = fake_context(b"12345", b"\n")
    assert (
        TlsLineTransport(HOST, PORT, context=context, max_line_size=5)(REQUEST, 1.0)
        == b"12345"
    )


def test_a_line_over_the_limit_is_refused(tcp: list[Any]) -> None:
    """Refused rather than truncated, and never read far past the limit."""
    context = fake_context(b"123", b"456", b"\n")
    transport = TlsLineTransport(HOST, PORT, context=context, max_line_size=5)
    with pytest.raises(RpcFetchError, match="max_line_size of 5"):
        transport(REQUEST, 1.0)
    assert context.tls.asked == [6, 3]


def test_a_read_asks_for_no_more_than_a_chunk(tcp: list[Any]) -> None:
    """A large limit is not what one read allocates."""
    context = fake_context(b"{}\n")
    TlsLineTransport(HOST, PORT, context=context)(REQUEST, 1.0)
    assert context.tls.asked == [transport_module._READ_CHUNK]


def test_a_connection_closed_before_the_newline_is_a_fetch_error(
    tcp: list[Any],
) -> None:
    """A partial line is not an answer, however much of one arrived."""
    context = fake_context(b'{"id": 1, "result"')
    with pytest.raises(RpcFetchError, match="closed before a whole line"):
        TlsLineTransport(HOST, PORT, context=context)(REQUEST, 1.0)


@pytest.mark.parametrize(
    "failure",
    [
        ConnectionRefusedError("connection refused"),
        TimeoutError("timed out"),
        ssl.SSLCertVerificationError("certificate verify failed"),
    ],
)
def test_what_goes_wrong_below_the_answer_is_a_fetch_error(
    tcp: list[Any], failure: Exception
) -> None:
    """The contract `LineTransport` states, the cause kept."""
    context = fake_context(failure=failure)
    with pytest.raises(RpcFetchError, match=f"no answer from {HOST}:{PORT}") as e:
        TlsLineTransport(HOST, PORT, context=context)(REQUEST, 1.0)
    assert e.value.__cause__ is failure


def test_a_failed_read_is_a_fetch_error(tcp: list[Any]) -> None:
    """A reset after the handshake is the same answer as a refused connect."""
    reset = ConnectionResetError("reset")
    context = fake_context(b"{", reset)
    with pytest.raises(RpcFetchError, match="reset") as e:
        TlsLineTransport(HOST, PORT, context=context)(REQUEST, 1.0)
    assert e.value.__cause__ is reset
    assert context.tls.closed


def test_electrum_fetcher_translates_what_the_transport_raises(tcp: list[Any]) -> None:
    """Through the fetcher, the transport's failure is btclib's `FetchError`."""
    context = fake_context(b"")
    transport = TlsLineTransport(HOST, PORT, context=context)
    endpoint = ElectrumFetcher(transport=transport, verify_network=False)
    with pytest.raises(FetchError, match="closed before a whole line"):
        endpoint.get_block_count()


def test_electrum_fetcher_answers_over_it(tcp: list[Any]) -> None:
    """The fetcher and this transport agree on the line at the boundary."""
    reply = {"id": 1, "result": {"height": TIP_HEIGHT, "hex": TIP_HEADER_RAW}}
    context = fake_context(json.dumps(reply).encode() + b"\n")
    transport = TlsLineTransport(HOST, PORT, context=context)
    endpoint = ElectrumFetcher(transport=transport, verify_network=False)
    assert endpoint.get_block_count() == TIP_HEIGHT
    assert json.loads(context.tls.sent)["method"] == "blockchain.headers.subscribe"
    [(_, timeout, _)] = tcp
    assert timeout == DEFAULT_TIMEOUT


@pytest.mark.parametrize(
    "args, kwargs, error, match",
    [
        ((b"host", PORT), {}, BTClibTypeError, "non-string host"),
        (("", PORT), {}, BTClibValueError, "empty host"),
        (("a..b", PORT), {}, BTClibValueError, "invalid host"),
        ((HOST, True), {}, BTClibTypeError, "non-integer port"),
        ((HOST, "50002"), {}, BTClibTypeError, "non-integer port"),
        ((HOST, 0), {}, BTClibValueError, "invalid port"),
        ((HOST, 65536), {}, BTClibValueError, "invalid port"),
        ((HOST, PORT), {"context": object()}, BTClibTypeError, "SSLContext"),
        ((HOST, PORT), {"max_line_size": 1.5}, BTClibTypeError, "max_line_size"),
        ((HOST, PORT), {"max_line_size": 0}, BTClibValueError, "max_line_size"),
    ],
)
def test_construction_validates_its_arguments(
    args: tuple[Any, ...], kwargs: dict[str, Any], error: type[Exception], match: str
) -> None:
    """A malformed argument is refused where it is given, not at the call."""
    with pytest.raises(error, match=match):
        TlsLineTransport(*args, **kwargs)


@pytest.mark.parametrize(
    "request_, timeout, error, match",
    [
        ("{}\n", 1.0, BTClibTypeError, "non-bytes request"),
        (b"", 1.0, BTClibValueError, "one newline-terminated line"),
        (b"{}", 1.0, BTClibValueError, "one newline-terminated line"),
        (b"{}\n{}\n", 1.0, BTClibValueError, "one newline-terminated line"),
        (b"{}\n{}", 1.0, BTClibValueError, "one newline-terminated line"),
        (REQUEST, True, BTClibTypeError, "non-numeric timeout"),
        (REQUEST, "1", BTClibTypeError, "non-numeric timeout"),
        (REQUEST, 0, BTClibValueError, "not a positive number"),
        (REQUEST, float("nan"), BTClibValueError, "not a positive number"),
        (REQUEST, float("inf"), BTClibValueError, "not a positive number"),
    ],
)
def test_a_call_validates_its_arguments_before_connecting(
    tcp: list[Any], request_: Any, timeout: Any, error: type[Exception], match: str
) -> None:
    """Refused before anything is opened, so no connection is attempted."""
    transport = TlsLineTransport(HOST, PORT, context=fake_context(b"{}\n"))
    with pytest.raises(error, match=match):
        transport(request_, timeout)
    assert not tcp
