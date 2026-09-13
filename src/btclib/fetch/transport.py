# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The transports a fetcher does its I/O with, and the network policy of each.

Two seams, one per wire shape. `HttpTransport` is re-exported under
btclib's name with its implementations; `LineTransport` is declared here
and `TlsLineTransport` implements it here.

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

The HTTP implementations differ in how they hold the connection.
`urlopen_transport` is the default: one connection per call, opened and
handed to the node to close. `SessionTransport` keeps one connection per
`(scheme, host, port)` open
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

**`LineTransport` carries no host, so its implementation is an object
that does.** `TlsLineTransport(host, port)` is the callable
`ElectrumFetcher` takes, and that fetcher has no default for it: a
default transport would have to be a default server, which
`ElectrumFetcher`'s own docstring refuses.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable
from math import isfinite
from socket import create_connection
from time import monotonic

from bitcoin_core_rpc import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    MAX_ERROR_BODY_SIZE,
    FetchError,
    HttpTransport,
    SessionTransport,
    http_request,
    urlopen_transport,
)

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import is_integer

LineTransport = Callable[[bytes, float], bytes]

__all__ = [
    "DEFAULT_MAX_BODY_SIZE",
    "DEFAULT_TIMEOUT",
    "MAX_ERROR_BODY_SIZE",
    "HttpTransport",
    "LineTransport",
    "SessionTransport",
    "TlsLineTransport",
    "http_request",
    "urlopen_transport",
]

# how much one read asks for: a recv allocates what it is asked for, so a
# limit widened for one large answer is not paid on every small one
_READ_CHUNK = 64 * 1024

_MAX_PORT = 65535


def _time_left(deadline: float, where: str) -> float:
    """Return the seconds left before `deadline`, refusing none or fewer.

    What each socket operation is given as its own timeout, so that the
    operations together cannot outlast the one deadline the call took.
    """
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise FetchError(f"{where}: timeout expired before an answer arrived")
    return remaining


def _read_line(
    connection: ssl.SSLSocket, max_line_size: int, where: str, deadline: float
) -> bytes:
    """Return the first line the connection delivers, without its newline.

    Never holds more than one octet past `max_line_size`: each read asks
    for at most what would take the line there, which is what tells a line
    at the limit from one over it. What
    follows the newline -- a notification the server pushed after the
    answer -- is read or not and discarded either way, the connection
    closing behind this call.
    """
    buffer = bytearray()
    while True:
        connection.settimeout(_time_left(deadline, where))
        chunk = connection.recv(min(_READ_CHUNK, max_line_size + 1 - len(buffer)))
        if not chunk:
            raise FetchError(f"{where}: connection closed before a whole line")
        end = chunk.find(b"\n")
        if end != -1:
            buffer.extend(chunk[:end])
            return bytes(buffer)
        buffer.extend(chunk)
        if len(buffer) > max_line_size:
            err_msg = f"{where}: line longer than the max_line_size of {max_line_size}"
            raise FetchError(err_msg)


class TlsLineTransport:
    """A `LineTransport` over TLS to one server, verifying its certificate.

    Constructed with the host and port it connects to, so the instance is
    the server: `ElectrumFetcher(transport=TlsLineTransport(host, port))`
    is the whole of naming one. Construction opens nothing.

    **One connection per call.** Each call connects, performs the TLS
    handshake, sends the one request line, reads the one line answering
    it, and closes. A connection kept across calls is what
    `blockchain.headers.subscribe` rules out: the server then pushes a
    notification line down that same connection at every new block, and a
    later call reading the next line would read the notification in place
    of its own answer. What a kept connection would save -- the connect
    and the handshake -- is paid on every call instead. Nothing is kept
    between calls, so concurrent calls share the `ssl.SSLContext` and
    nothing else.

    **The network policy**, the one `urlopen_transport` keeps for HTTP:

    - a bounded read: the line is refused, not truncated, once it passes
      `max_line_size` octets without a newline. The default is
      `DEFAULT_MAX_BODY_SIZE`, sized for a whole block as hex, so
      `blockchain.transaction.get` fits for any transaction a block holds;
    - a timeout over the whole exchange -- connect, handshake, send and
      read -- rather than per socket operation: each operation is given
      what is left of one deadline, so a server dripping a line one octet
      at a time cannot hold the call open past it;
    - no proxy from the environment: `socket.create_connection` reads no
      proxy variable, so the connection goes to the host named here;
    - TLS verified by default: `context` defaults to
      `ssl.create_default_context()`, which requires a certificate chaining
      to the default CA certificates it loads and matching `host`.

    A server whose certificate those do not trust -- a server of
    one's own with a self-signed certificate, say -- is reached by passing
    a `context` that trusts that certificate,
    `ssl.create_default_context(cafile=...)`, which keeps both checks on.
    No flag here turns verification off; what a context a caller supplies
    accepts is that caller's decision, as a transport of their own would
    be. Plain TCP is not offered: a caller who wants it writes that
    `LineTransport`.

    Everything that goes wrong below the answer -- an unresolvable host, a
    refused connection, a handshake the certificate fails, a timeout, a
    connection closed before a whole line, a line over the limit -- is
    `bitcoin_core_rpc`'s `FetchError`, the contract `LineTransport` states,
    which `ElectrumFetcher` translates into btclib's own.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        context: ssl.SSLContext | None = None,
        max_line_size: int = DEFAULT_MAX_BODY_SIZE,
    ) -> None:
        if not isinstance(host, str):
            raise BTClibTypeError(f"non-string host: {host!r}")
        if not host:
            raise BTClibValueError("empty host")
        try:
            # what `create_connection` and the handshake both encode the
            # host with, and a `UnicodeError` rather than an `OSError` there
            host.encode("idna")
        except UnicodeError as e:
            raise BTClibValueError(f"invalid host: {host!r}") from e
        if not is_integer(port):
            raise BTClibTypeError(f"non-integer port: {port!r}")
        if not 0 < port <= _MAX_PORT:
            raise BTClibValueError(f"invalid port: {port}")
        if context is not None and not isinstance(context, ssl.SSLContext):
            raise BTClibTypeError(f"not an ssl.SSLContext: {context!r}")
        if not is_integer(max_line_size):
            raise BTClibTypeError(f"non-integer max_line_size: {max_line_size!r}")
        if max_line_size < 1:
            raise BTClibValueError(f"invalid max_line_size: {max_line_size}")
        self._host = host
        self._port = port
        self._context = ssl.create_default_context() if context is None else context
        self._max_line_size = max_line_size

    @property
    def host(self) -> str:
        """Return the host this transport connects to."""
        return self._host

    @property
    def port(self) -> int:
        """Return the port this transport connects to."""
        return self._port

    @property
    def context(self) -> ssl.SSLContext:
        """Return the context the TLS handshake is verified against."""
        return self._context

    @property
    def max_line_size(self) -> int:
        """Return the octets an answering line may hold before it is refused."""
        return self._max_line_size

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Send one request line and return the line answering it.

        `request` is one line, its newline the last octet and the only
        one: a second would be a second request, whose answer this call
        would never read.
        """
        if not isinstance(request, bytes):
            raise BTClibTypeError(f"non-bytes request: {request!r}")
        if request.count(b"\n") != 1 or not request.endswith(b"\n"):
            raise BTClibValueError(f"not one newline-terminated line: {request!r}")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise BTClibTypeError(f"non-numeric timeout: {timeout!r}")
        if not isfinite(timeout) or timeout <= 0:
            raise BTClibValueError(f"timeout is not a positive number: {timeout}")

        where = f"{self._host}:{self._port}"
        deadline = monotonic() + timeout
        try:
            with create_connection((self._host, self._port), timeout=timeout) as sock:
                sock.settimeout(_time_left(deadline, where))
                with self._context.wrap_socket(
                    sock, server_hostname=self._host
                ) as connection:
                    connection.settimeout(_time_left(deadline, where))
                    connection.sendall(request)
                    return _read_line(connection, self._max_line_size, where, deadline)
        except OSError as e:
            # `ssl.SSLError`, `socket.gaierror` and `TimeoutError` all derive
            # from it, which makes it every way the exchange did not happen
            raise FetchError(f"no answer from {where}: {e}") from e
