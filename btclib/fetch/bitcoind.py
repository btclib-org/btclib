#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""A JSON-RPC client against bitcoind, and the fetcher built on it.

`AuthProxy` is python-bitcoinrpc's name for this, kept because it is the
name the request that asked for it used, and it does what that one does:
one HTTP POST per call, basic authentication, the result or an exception.
What it does differently is the version and the credentials.

**JSON-RPC 2.0, not 1.0.** Core answers 1.0 by default and 2.0 to a
request carrying the `"jsonrpc": "2.0"` marker, and the difference is
which layer reports a bitcoin error: under 1.0 an unknown transaction
comes back as HTTP 500 with the error object in the body, so a genuine
server fault and a routine "no such transaction" are the same status.
Under 2.0 an rpc error is HTTP 200 with an `error` member, and a non-2xx
means the HTTP exchange itself failed. Both are read here -- a node older
than v28 does not know the marker and replies 1.0 to it -- but only one
of them can be told apart from a proxy in the way.

**No credentials in the url.** python-bitcoinrpc takes a url with the
userinfo part filled in -- the `<user>:<password>@` before the host --
which puts a password in a string that ends up in configuration files,
tracebacks and logs. Such a url is refused here; the password arrives
as an argument, or, better,
is never seen at all -- `.cookie` is what bitcoind writes for exactly
this, rotated at every restart, readable by the user running the node and
by nobody else.
"""

from __future__ import annotations

import json
from base64 import b64encode
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from btclib.alias import Octets
from btclib.exceptions import BTClibValueError, FetchError, RpcError
from btclib.fetch.fetcher import Fetcher, fetch_errors, tx_from_raw, tx_id_hex
from btclib.fetch.transport import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    HttpTransport,
    http_request,
    urlopen_transport,
)
from btclib.tx import Tx
from btclib.utils import bytes_from_octets

# the rpc port and the datadir subdirectory of each network, from Core's
# `CreateBaseChainParams` in src/chainparamsbase.cpp. Mainnet's cookie is
# in the datadir itself, which is the empty subdirectory below
_RPC_PORT = {
    "mainnet": 8332,
    "testnet": 18332,
    "testnet4": 48332,
    "signet": 38332,
    "regtest": 18443,
}
_DATADIR_SUBDIR = {
    "mainnet": "",
    "testnet": "testnet3",
    "testnet4": "testnet4",
    "signet": "signet",
    "regtest": "regtest",
}

# the username bitcoind writes into the cookie file, COOKIEAUTH_USER in
# src/rpc/request.cpp. The node ignores it -- cookie authentication
# compares the whole `user:password` line -- so it is documentation, and
# a cookie file whose first field is something else is still a valid one
COOKIE_USER = "__cookie__"

# `~/.bitcoin`, which is the datadir on Linux and on nothing else: macOS
# puts it under ~/Library/Application Support/Bitcoin and Windows under
# %APPDATA%\Bitcoin. Guessing per platform would put two branches here
# that no test on a third platform can reach, and a wrong guess fails
# exactly as an absent file does; `cookie_path` is how a caller says
# where it really is
DEFAULT_DATADIR = Path.home() / ".bitcoin"

# What goes in the request as `id`, and what the reply has to echo. Not a
# counter: each call here is its own HTTP request and its own response,
# so there is nothing to match up that the socket has not already
# matched. Checking it back is worth the line anyway -- it is what
# catches a caching proxy answering one call with another's reply
_RPC_ID = "btclib"

# what a reply that is a number or a hash may weigh: the json envelope
# around `result`, `error` and `id`, and a value of a few dozen octets.
# `getrawtransaction` is the one answer here that is not small, and it
# keeps the default of `call`
_MAX_SMALL_REPLY = 1024


def cookie_auth(cookie_path: Path) -> str:
    """Return the `user:password` bitcoind wrote in its cookie file.

    One line, `__cookie__:` and 32 random bytes in hex, rewritten at
    every start of the node. Read at each call rather than once at
    construction: a proxy built when the node was up and used an hour
    later would otherwise answer 401 for the rest of the process, the
    node having been restarted in between, and the cost of not doing so
    is one small local read against an HTTP round trip.
    """
    try:
        line = cookie_path.read_text(encoding="ascii").strip()
    except OSError as e:
        raise FetchError(f"unreadable rpc cookie file {cookie_path}: {e}") from e
    if ":" not in line:
        raise FetchError(f"malformed rpc cookie file {cookie_path}: no ':' in it")
    return line


class AuthProxy:
    """One bitcoind JSON-RPC endpoint, and the credentials to reach it.

    Not a dataclass, and that is about the password: a generated
    `__repr__` prints every field, so the credential would appear in any
    traceback that renders the proxy, and in any log line that prints it.
    """

    def __init__(
        self,
        url: str = "",
        *,
        network: str = "mainnet",
        user: str | None = None,
        password: str | None = None,
        cookie_path: Path | str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: HttpTransport = urlopen_transport,
    ) -> None:
        if network not in _RPC_PORT:
            raise BTClibValueError(f"unknown network: {network}")
        self.network = network
        self.url = url or f"http://127.0.0.1:{_RPC_PORT[network]}"
        split = urlsplit(self.url)
        if split.username is not None or split.password is not None:
            err_msg = "credentials in the rpc url:"
            err_msg += " pass user and password, or use the cookie file"
            raise BTClibValueError(err_msg)
        if (user is None) != (password is None):
            raise BTClibValueError("rpc user and password go together, or neither")
        self.user = user
        self._password = password
        self.cookie_path = (
            Path(cookie_path)
            if cookie_path is not None
            else DEFAULT_DATADIR / _DATADIR_SUBDIR[network] / ".cookie"
        )
        self.timeout = timeout
        self.transport = transport

    def auth_header(self) -> str:
        """Return the Basic credential, from the arguments or the cookie.

        RFC 7617 leaves the charset of the credential unspecified and
        Core compares the decoded bytes, so utf-8 is a choice that only
        matters for a password with a non-ascii character in it -- where
        it is the choice that matches what a shell and a config file
        would have written.
        """
        if self.user is None:
            credential = cookie_auth(self.cookie_path)
        else:
            credential = f"{self.user}:{self._password}"
        return "Basic " + b64encode(credential.encode()).decode("ascii")

    def call(
        self, method: str, *params: Any, max_body_size: int = DEFAULT_MAX_BODY_SIZE
    ) -> Any:
        """Invoke one rpc method, returning its `result`.

        Any method, not only the three the fetcher needs: a caller with a
        node has every reason to ask it something else, and refusing that
        would only mean they write this class again.

        `max_body_size` is what the reply may weigh, and it defaults to the
        widest answer a fetcher asks for -- a raw transaction, as hex
        inside a json envelope. A caller invoking something whose reply is
        a number tightens it; one invoking `getblock` on a large block
        widens it, this being their node and their memory.
        """
        body = json.dumps(
            {"jsonrpc": "2.0", "id": _RPC_ID, "method": method, "params": list(params)}
        ).encode()
        status, payload = http_request(
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": self.auth_header(),
            },
            timeout=self.timeout,
            max_body_size=max_body_size,
            transport=self.transport,
        )
        return self._result(method, status, payload)

    def _result(self, method: str, status: int, payload: bytes) -> Any:
        where = f"{method} at {self.url}"
        try:
            reply = json.loads(payload)
        except json.JSONDecodeError as e:
            # a 401 is the common way to get here: Core answers an
            # unauthorized request with the status and an empty body, so
            # reporting "not json" would name the symptom and hide the
            # cause
            if status != 200:
                raise FetchError(f"{where}: {_http_reason(status)}") from e
            raise FetchError(f"{where}: not json ({e})") from e

        if not isinstance(reply, dict):
            raise FetchError(f"{where}: not a json-rpc reply, but a {type(reply)}")

        # before the status, because this is where a 1.0 reply keeps the
        # error object it sends with its 500
        error = reply.get("error")
        if error is not None:
            raise _rpc_error(where, error)

        if status != 200:
            raise FetchError(f"{where}: {_http_reason(status)}")
        if reply.get("id") != _RPC_ID:
            raise FetchError(f"{where}: reply id {reply.get('id')!r} is not ours")
        if "result" not in reply:
            raise FetchError(f"{where}: a reply with neither result nor error")
        return reply["result"]


def _http_reason(status: int) -> str:
    """Say what a status means for a caller who has to act on it."""
    if status == 401:
        return "HTTP 401, the node refused the credentials"
    return f"HTTP {status}"


def _rpc_error(where: str, error: Any) -> FetchError:
    """Turn what the node put in `error` into the exception for it."""
    if not isinstance(error, dict) or not isinstance(error.get("code"), int):
        return FetchError(f"{where}: unreadable rpc error {error!r}")
    return RpcError(f"{where}: {error.get('message', '')}", error["code"])


class BitcoindFetcher(Fetcher):
    """The three questions, answered by a node over `AuthProxy`.

    The proxy is a constructor argument rather than a set of connection
    arguments repeated here: one class owns the endpoint and the
    credentials, this one owns the mapping onto btclib types, and a
    caller who already has a proxy does not build a second.
    """

    def __init__(self, proxy: AuthProxy) -> None:
        super().__init__(proxy.network)
        self.proxy = proxy

    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction with this id.

        `getrawtransaction` with no verbosity, i.e. the serialization
        rather than the node's json rendering of it: the bytes are what
        `Tx.parse` recomputes the id from, so a transaction that arrived
        wrong announces itself, and a rendering that btclib and Core
        disagree about cannot come between them.

        A node answers for a transaction in its mempool, one of its
        wallet's, and -- only with `-txindex` -- any other. Without the
        index the error is rpc code -5, and its message says so.
        """
        hex_ = tx_id_hex(tx_id)
        raw = self.proxy.call("getrawtransaction", hex_)
        return tx_from_raw(raw, hex_, self.network)

    def get_block_count(self) -> int:
        """Return the height of the node's best chain tip."""
        with fetch_errors("getblockcount"):
            return int(self.proxy.call("getblockcount", max_body_size=_MAX_SMALL_REPLY))

    def get_best_block_id(self) -> bytes:
        """Return the hash of the node's best chain tip, display order."""
        with fetch_errors("getbestblockhash"):
            reply = self.proxy.call("getbestblockhash", max_body_size=_MAX_SMALL_REPLY)
            return bytes_from_octets(reply, 32)
