#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for btclib.bitcoin_core_rpc, against recorded replies.

Under `tests/fetch/` although its subject moved out of `btclib.fetch`, and
that is `tests/fetch/__init__.py`: the recorded replies and the transports
that serve them are there, shared with the Esplora tests and with the
fetcher's. `tests/bitcoin_core_rpc_standalone_test.py` needs none of that
and sits beside the module instead.

Every client here is built with a transport, so no test reaches a node.
The recorded bodies under `_data` are Core's, shape and newline included;
the failure bodies a node cannot be asked to produce on demand -- a 401,
a proxy's html -- are written inline, where what they are is visible
beside the assertion.

The recorded bodies carry the id of the call they answered, and `call`
sends a fresh one per request: `Echoing` puts the request's id in the
reply the way a node does, so that a test about the *reply* is not also a
test about the id. A test about the id builds its own body and uses
`Recorded` directly, through `verbatim`.
"""

from __future__ import annotations

import json
import re
from base64 import b64decode
from decimal import Decimal
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.request import Request

import pytest

from btclib.bitcoin_core_rpc import (
    COOKIE_USER,
    DEFAULT_DATADIR,
    BitcoinCoreRpcClient,
    _default_datadir,
    cookie_auth,
)
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    FetchError,
    HttpError,
    RpcError,
)
from btclib.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib.fetch.transport import DEFAULT_MAX_BODY_SIZE, DEFAULT_TIMEOUT
from btclib.tx import OutPoint
from tests.fetch import TIP_HEIGHT, TIP_ID, TX_ID, Recorded, recorded_body

# the shape bitcoind writes: the fixed user, a colon, and 32 random bytes
# in hex. This one is not random and is the credential of nothing -- the
# point is the parsing, and a real cookie would be a secret in a
# repository
COOKIE_LINE = f"{COOKIE_USER}:" + "ab" * 32

# the rpc credentials every test here passes. Named once rather than
# written at each call, which is what keeps the string out of a
# `password=` argument: the two secret scanners read a literal there as a
# credential, and they are right to -- a real one belongs in neither
RPC_USER = "rpcuser"
RPC_PASSWORD = "rpcpassword"  # noqa: S105  # pragma: allowlist secret

# the endpoint the tests build against, written once. A url is required,
# there being no network here to derive one from -- `from_network` is what
# derives one, and has its own tests
URL = "http://127.0.0.1:8332"


def asked_id(request: Request) -> str:
    """Return the json-rpc id a recorded request was sent with."""
    data = request.data
    assert isinstance(data, bytes)
    request_id = json.loads(data)["id"]
    assert isinstance(request_id, str)
    return request_id


def echoed(body: bytes, request_id: str) -> bytes:
    """Return a recorded reply carrying the id of the request it answers."""
    try:
        reply = json.loads(body)
    except (ValueError, RecursionError):
        # not json, or not json anything can parse: both are what several
        # tests are about, and a node would not have answered them either
        return body
    if not isinstance(reply, dict):
        return body
    reply["id"] = request_id
    return json.dumps(reply).encode()


class Echoing(Recorded):
    """A Recorded answering with the request's own id, as a node does."""

    def __call__(self, request: Request, timeout: float) -> tuple[int, bytes]:
        """Answer the next scripted reply, with this request's id in it."""
        status, body = super().__call__(request, timeout)
        return status, echoed(body, asked_id(request))


def client(
    *answers: tuple[int, bytes] | Exception, **kwargs: object
) -> BitcoinCoreRpcClient:
    """Return a client over an id-echoing recording, credentials of no node."""
    return BitcoinCoreRpcClient(
        URL,
        user=RPC_USER,
        password=RPC_PASSWORD,
        transport=Echoing(*answers),
        **kwargs,  # type: ignore[arg-type]
    )


def verbatim(*answers: tuple[int, bytes] | Exception) -> BitcoinCoreRpcClient:
    """Return a client answering exactly these bodies, their id included."""
    return BitcoinCoreRpcClient(
        URL, user=RPC_USER, password=RPC_PASSWORD, transport=Recorded(*answers)
    )


def fetcher(
    *answers: tuple[int, bytes] | Exception, **kwargs: object
) -> BitcoinCoreFetcher:
    """Return a BitcoinCoreFetcher over a recorded client."""
    network = kwargs.pop("network", "mainnet")
    assert isinstance(network, str)
    return BitcoinCoreFetcher(client(*answers, **kwargs), network)


def recording(endpoint: BitcoinCoreRpcClient) -> Recorded:
    """Return the recording a client was built with, as one."""
    transport = endpoint.transport
    assert isinstance(transport, Recorded)
    return transport


def sent(endpoint: BitcoinCoreRpcClient) -> dict[str, object]:
    """Return the json request body a client's only call was sent with."""
    body = json.loads(recording(endpoint).body)
    assert isinstance(body, dict)
    return body


def test_from_network_is_the_local_node_of_that_network() -> None:
    """The rpc port and the datadir subdirectory of Core's chainparamsbase."""
    # what `from_network` asks at the call. None where no absolute home is
    # knowable, which is not a machine the suite runs on -- and asserting it
    # is what makes the paths below a Path
    datadir = _default_datadir()
    assert datadir is not None
    # the constant is the same answer, taken at import: a snapshot for a
    # caller to read, and not what the derivation goes through
    assert DEFAULT_DATADIR == datadir

    from_network = BitcoinCoreRpcClient.from_network
    assert from_network().url == "http://127.0.0.1:8332"
    assert from_network("testnet").url == "http://127.0.0.1:18332"
    assert from_network("testnet4").url == "http://127.0.0.1:48332"
    assert from_network("signet").url == "http://127.0.0.1:38332"
    assert from_network("regtest").url == "http://127.0.0.1:18443"

    assert from_network().cookie_path == datadir / ".cookie"
    assert from_network("testnet").cookie_path == datadir / "testnet3" / ".cookie"
    assert from_network("regtest").cookie_path == datadir / "regtest" / ".cookie"


def test_from_network_reads_the_home_of_the_call_and_not_of_the_import(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A home set after btclib was imported is the one a cookie comes from.

    `btclib.exceptions` imports this module, so anything importing btclib at
    all imports it: a datadir resolved once, at that moment, is the
    environment as it stood whenever some unrelated early import happened.
    Reproduced before this was fixed -- `HOME=/tmp/home-before`, `import
    btclib.exceptions`, `HOME=/tmp/home-after`, and `from_network()` still
    answered with `/tmp/home-before/.bitcoin/.cookie`.

    Which is what a test can only see by *not* patching `DEFAULT_DATADIR`:
    that constant is the frozen answer, and patching it would pass against
    either implementation. The home is what moves here, and the derivation
    has to follow it.
    """
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home-after")

    expected = tmp_path / "home-after" / ".bitcoin" / "regtest" / ".cookie"
    assert BitcoinCoreRpcClient.from_network("regtest").cookie_path == expected
    assert DEFAULT_DATADIR != _default_datadir()


def test_from_network_derives_no_cookie_when_told_who_is_calling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A user or a password is the answer to that, so nothing is derived.

    Either of the two on its own is a caller's mistake, and the constructor
    is where the pair is held together. What this pins is that the datadir is
    not consulted first: on a host with no home directory, a `password` with
    no `user` used to be reported as a missing datadir -- an error about the
    machine, for a call that was wrong on any machine.

    So the home is not made to fail here, it is made to *fail the test* if it
    is looked at: a stub that raises would leave the pinned property implied
    by a line the run never reaches, where this states it.
    """
    monkeypatch.setattr(Path, "home", lambda: pytest.fail("home consulted"))
    for kwargs in ({"password": RPC_PASSWORD}, {"user": RPC_USER}):
        with pytest.raises(BTClibValueError, match="go together"):
            BitcoinCoreRpcClient.from_network(**kwargs)  # type: ignore[arg-type]


def test_no_absolute_home_is_no_default_datadir_and_no_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both ways a home is not a datadir answer with None, and neither raises.

    `DEFAULT_DATADIR` is computed at import and `btclib.exceptions` imports
    the module it is in, so an exception here would fail an import of most of
    btclib on a host that was never going to fetch anything: a container run
    under an arbitrary uid, where `HOME` is unset and the passwd file has no
    entry to fall back to, is where `Path.home()` raises. A `HOME` that holds
    a relative path is the other way, and it raises nothing at all.

    `Path.home` is patched, and not the `os.path.expanduser` under it. Some
    interpreters of the matrix call that function while resolving the home;
    others bound it to a pathlib accessor when the class was created, and
    there patching the module attribute is invisible -- written that way,
    this passed on 3.14 and did not raise at all on 3.10. What
    `_default_datadir` reads is `Path.home`, so that is what this arranges.
    """

    def no_home() -> Path:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "home", no_home)
    assert _default_datadir() is None

    monkeypatch.setattr(Path, "home", lambda: Path("relative/home"))
    assert Path.home().is_absolute() is False
    assert _default_datadir() is None


def test_from_network_refuses_a_datadir_it_cannot_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No default datadir is a refusal, and never a path read against the cwd.

    The end of the same path as the test above, and the reason None is the
    answer there rather than an unexpanded `~/.bitcoin`: that is a relative
    path, `pathlib` expands no tilde, and `from_network` handed it to the
    cookie reader unchanged -- so a `./~/.bitcoin/.cookie` that the working
    directory happened to contain became the credential this client presents
    to the node. Planted below, exactly as it was when that was reproduced.

    A refusal naming `cookie_path` instead, before any file is opened. The
    explicit path still works, the refusal being about the default alone.

    `Path.home` is what raises here, not a patched `DEFAULT_DATADIR`: the
    derivation asks at the call, so this is the whole path a host with no
    home directory takes.
    """

    def no_home() -> Path:
        raise RuntimeError("Could not determine home directory.")

    planted = tmp_path / "~" / ".bitcoin" / ".cookie"
    planted.parent.mkdir(parents=True)
    planted.write_text(f"{COOKIE_USER}:planted\n", encoding="ascii")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", no_home)

    with pytest.raises(BTClibValueError, match="pass cookie_path"):
        BitcoinCoreRpcClient.from_network()

    # the file is there and readable, so the refusal above is what kept it
    # out and not an absent path: through an explicit `cookie_path` the very
    # same file is the credential
    explicit = BitcoinCoreRpcClient.from_network("mainnet", cookie_path=planted)
    assert (
        b64decode(explicit.auth_header().split()[1])
        == f"{COOKIE_USER}:planted".encode()
    )

    # and credentials need no datadir at all
    assert (
        BitcoinCoreRpcClient.from_network(
            "regtest", user=RPC_USER, password=RPC_PASSWORD
        ).cookie_path
        is None
    )


def test_from_network_takes_credentials_instead_of_a_cookie() -> None:
    """Credentials given, no cookie path derived: the two are exclusive."""
    endpoint = BitcoinCoreRpcClient.from_network(
        "regtest", user=RPC_USER, password=RPC_PASSWORD
    )
    assert endpoint.cookie_path is None
    assert endpoint.user == RPC_USER


def test_connection_controls_are_keyword_only() -> None:
    """Credentials cannot be mistaken for positional connection arguments."""
    constructor: Any = BitcoinCoreRpcClient
    with pytest.raises(TypeError):
        constructor(URL, RPC_USER, RPC_PASSWORD)

    from_network: Any = BitcoinCoreRpcClient.from_network
    with pytest.raises(TypeError):
        from_network("regtest", RPC_USER, RPC_PASSWORD)


def test_a_colon_in_the_user_is_refused_and_one_in_the_password_is_not() -> None:
    """The credential is `user:password`, and the node splits at the first.

    A user of `alice:admin` and a user of `alice` whose credential begins
    `admin:` encode to the same `Basic` header, so nothing downstream can
    tell them apart: Core reads both as the user `alice` --
    `RPCAuthorized` in src/httprpc.cpp -- which is a different rpc user, and
    a different `-rpcwhitelist`, than the first caller wrote. Refused where
    it is written rather than authenticated as somebody else.

    A colon on the other side of the credential is unambiguous: everything
    after the first one belongs to the second field by definition, so it
    stays valid, and the assertion here is what keeps the refusal from
    spreading to it.
    """
    with pytest.raises(BTClibValueError, match="colon in the rpc user"):
        BitcoinCoreRpcClient(URL, user="alice:admin", password=RPC_PASSWORD)

    ambiguous = f"admin:{RPC_PASSWORD}"
    endpoint = BitcoinCoreRpcClient(URL, user="alice", password=ambiguous)
    credential = b64decode(endpoint.auth_header().split()[1])
    assert credential == f"alice:{ambiguous}".encode()


@pytest.mark.parametrize("method", [7, None, b"getblockcount", ["getblockcount"]])
def test_a_method_that_is_not_a_string_is_refused(method: object) -> None:
    """json-rpc's `method` is a string, and the annotation is not a check.

    `call(7)` used to build `"method": 7` and send it, which is this client
    constructing a request json-rpc has no reading of -- while it walks the
    caller's `params` to refuse exactly that. An unknown method is a value
    the node answers for, which is why it is an argument; a number is not
    one.
    """
    with pytest.raises(BTClibTypeError, match="rpc method that is not a string"):
        client().call(method)  # type: ignore[arg-type]


def test_from_network_refuses_a_network_core_has_no_port_for() -> None:
    """The five names are Core's chainparamsbase, not btclib's registry."""
    with pytest.raises(BTClibValueError, match="unknown network: testnet5"):
        BitcoinCoreRpcClient.from_network("testnet5")


def test_the_url_carries_no_network_and_no_registry() -> None:
    """A signet of one's own reaches the constructor, which asks no name.

    The connection is a url and credentials; which chain the node serves
    is `BitcoinCoreFetcher`'s label. A custom signet -- a network btclib can
    be taught and Core has no default port for -- is exactly the case a
    client validating chain names would have refused.
    """
    endpoint = BitcoinCoreRpcClient(
        "http://node.example:39332", user=RPC_USER, password=RPC_PASSWORD
    )
    assert endpoint.url == "http://node.example:39332"
    assert not hasattr(endpoint, "network")


@pytest.mark.parametrize(
    ("url", "match"),
    [
        ("ftp://127.0.0.1:8332", "invalid rpc url scheme"),
        ("file:///etc/passwd", "invalid rpc url scheme"),
        ("127.0.0.1:8332", "invalid rpc url scheme"),
        ("http://", "no host in the rpc url"),
        ("http://127.0.0.1:8332?wallet=hot", "query or fragment in the rpc url"),
        ("http://127.0.0.1:8332#wallet", "query or fragment in the rpc url"),
        ("http://127.0.0.1:https", "invalid port in the rpc url"),
    ],
)
def test_an_endpoint_that_is_not_one_is_refused_at_construction(
    url: str, match: str
) -> None:
    """A url is configuration: it is refused where it was written.

    Not at the first call, which is where `urlopen` would refuse most of
    these -- by then the line that supplied it is somewhere else.
    """
    with pytest.raises(BTClibValueError, match=match):
        BitcoinCoreRpcClient(url, user=RPC_USER, password=RPC_PASSWORD)


@pytest.mark.parametrize(
    "url",
    [
        f"http://{RPC_USER}:{RPC_PASSWORD}@127.0.0.1:8332",
        f"http://{RPC_USER}@127.0.0.1:8332",
    ],
)
def test_credentials_in_the_url_are_refused(url: str) -> None:
    """The spelling python-bitcoinrpc requires, and the reason to refuse it.

    A url is the thing that gets written into a config file, printed in
    a traceback and pasted into an issue; a password in one has been
    disclosed before anybody meant to disclose it.
    """
    with pytest.raises(BTClibValueError, match="credentials in the rpc url"):
        BitcoinCoreRpcClient(url, cookie_path="/nowhere/.cookie")


@pytest.mark.parametrize(("user", "password"), [(RPC_USER, None), (None, RPC_PASSWORD)])
def test_a_user_without_a_password_is_refused(
    user: str | None, password: str | None
) -> None:
    """Refuse a user without a password, and the other way round."""
    with pytest.raises(BTClibValueError, match="go together"):
        BitcoinCoreRpcClient(URL, user=user, password=password)


def test_credentials_and_a_cookie_path_together_are_refused() -> None:
    """Either of them says who is calling, so both would have to be ranked.

    Silently preferring one leaves a caller with a mistaken idea of which
    credential the node is shown, which is the failure that costs an
    afternoon: the cookie was rotated, the password was stale, and
    nothing said which of the two was in use.
    """
    with pytest.raises(BTClibValueError, match="both rpc credentials and a cookie"):
        BitcoinCoreRpcClient(
            URL,
            user=RPC_USER,
            password=RPC_PASSWORD,
            cookie_path="/nowhere/.cookie",
        )


def test_neither_credentials_nor_a_cookie_path_is_refused() -> None:
    """A client with no way to authenticate is refused where it is built."""
    with pytest.raises(BTClibValueError, match="no rpc credentials"):
        BitcoinCoreRpcClient(URL)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_a_timeout_that_is_no_duration_is_refused(timeout: float) -> None:
    """A zero, a negative, an infinity and a nan are not seconds to wait."""
    with pytest.raises(BTClibValueError, match="rpc timeout is not a positive"):
        BitcoinCoreRpcClient(URL, user=RPC_USER, password=RPC_PASSWORD, timeout=timeout)


@pytest.mark.parametrize("timeout", [True, "30", None])
def test_a_non_numeric_timeout_is_refused(timeout: object) -> None:
    """A bool is not a duration: `timeout=True` would be one second."""
    with pytest.raises(BTClibTypeError, match="non-numeric rpc timeout"):
        BitcoinCoreRpcClient(
            URL,
            user=RPC_USER,
            password=RPC_PASSWORD,
            timeout=timeout,  # type: ignore[arg-type]
        )


def test_the_default_timeout_is_the_one_the_module_documents() -> None:
    """Verify a client with no timeout argument carries the module default."""
    assert BitcoinCoreRpcClient(URL, cookie_path="/nowhere/.cookie").timeout == (
        DEFAULT_TIMEOUT
    )


def test_the_basic_credential_is_the_user_and_password_given() -> None:
    """Verify the Authorization header is Basic over user:password."""
    header = BitcoinCoreRpcClient(
        URL, user=RPC_USER, password=RPC_PASSWORD
    ).auth_header()
    scheme, encoded = header.split(" ")
    assert scheme == "Basic"
    assert b64decode(encoded).decode() == f"{RPC_USER}:{RPC_PASSWORD}"


def test_a_non_ascii_password_is_utf_8() -> None:
    """What a shell and a bitcoin.conf would have written."""
    umlauts = "pässwörd"
    header = BitcoinCoreRpcClient(URL, user=RPC_USER, password=umlauts).auth_header()
    assert b64decode(header.split(" ")[1]) == f"{RPC_USER}:{umlauts}".encode()


def test_the_cookie_file_is_the_credential_when_there_is_no_user(
    tmp_path: Path,
) -> None:
    """Verify the cookie line becomes the Basic credential, no user given."""
    cookie = tmp_path / ".cookie"
    cookie.write_text(COOKIE_LINE)
    header = BitcoinCoreRpcClient(URL, cookie_path=cookie).auth_header()
    assert b64decode(header.split(" ")[1]).decode() == COOKIE_LINE


def test_the_cookie_is_read_at_every_call_not_at_construction(
    tmp_path: Path,
) -> None:
    """Because a node restart rotates it.

    A client built once and used for an hour would otherwise answer 401
    for the rest of the process. Constructing one touches no file at all,
    which is the other half of the same decision: building a client
    should not raise FileNotFoundError.
    """
    cookie = tmp_path / ".cookie"
    endpoint = BitcoinCoreRpcClient(
        URL, cookie_path=cookie, transport=Echoing((200, b"{}"))
    )
    assert not cookie.exists()

    cookie.write_text(COOKIE_LINE)
    first = endpoint.auth_header()
    cookie.write_text(f"{COOKIE_USER}:" + "cd" * 32)
    assert endpoint.auth_header() != first


def test_an_absent_cookie_file_says_which_file(tmp_path: Path) -> None:
    """Verify the unreadable-cookie error names the missing file.

    Which is also what tells a caller on macOS or Windows to pass a
    `cookie_path`: the default is `~/.bitcoin`, Core's datadir on Linux
    and on neither of those.
    """
    absent = tmp_path / "no-such-datadir" / ".cookie"
    # escaped because `match` is a regex and a path is not: the windows
    # separator is a backslash, so a tmp_path under C:\Users carries an
    # incomplete \U escape and the pattern does not even compile
    expected = re.escape(f"unreadable rpc cookie file {absent}")
    with pytest.raises(FetchError, match=expected):
        cookie_auth(absent)


def test_a_cookie_file_without_a_colon_is_not_one(tmp_path: Path) -> None:
    """Refuse a cookie file carrying no colon as malformed."""
    cookie = tmp_path / ".cookie"
    cookie.write_text("nonsense\n")
    with pytest.raises(FetchError, match="no ':' in it"):
        cookie_auth(cookie)


def test_a_cookie_file_of_several_lines_is_not_one(tmp_path: Path) -> None:
    """One line is what bitcoind writes, so more than one is another file."""
    cookie = tmp_path / ".cookie"
    cookie.write_text(f"{COOKIE_LINE}\nand a second line\n")
    with pytest.raises(FetchError, match="several lines"):
        cookie_auth(cookie)


def test_a_cookie_file_that_is_not_ascii_is_not_one(tmp_path: Path) -> None:
    """A binary file at the cookie path is a FetchError, not a decode error.

    The wrong path is the ordinary mistake here, and everything it can
    point at has to arrive through the same contract: naming the file,
    and never rendering what was in it.
    """
    cookie = tmp_path / ".cookie"
    cookie.write_bytes(b"\x80\x81:not ascii")
    with pytest.raises(FetchError, match="non-ascii rpc cookie file"):
        cookie_auth(cookie)


@pytest.mark.parametrize("size", [4096, 4097])
def test_the_cookie_size_boundary_is_4096_bytes(tmp_path: Path, size: int) -> None:
    """The largest permitted cookie is accepted and the next byte is not."""
    line = "u:" + "x" * (size - 2)
    cookie = tmp_path / ".cookie"
    cookie.write_text(line, encoding="ascii")

    if size == 4096:
        assert cookie_auth(cookie) == line
    else:
        with pytest.raises(FetchError, match="oversized rpc cookie file"):
            cookie_auth(cookie)


def test_the_cookie_read_stops_after_the_sentinel_octet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checking the bound reads 4096 bytes and only one byte beyond it."""

    class MeasuredCookie(BytesIO):
        def __init__(self) -> None:
            super().__init__(COOKIE_LINE.encode("ascii"))
            self.reads: list[int | None] = []

        def read(self, size: int | None = -1, /) -> bytes:
            self.reads.append(size)
            return super().read(size)

    measured = MeasuredCookie()

    def open_cookie(path: Path, mode: str) -> MeasuredCookie:
        assert path == Path("measured.cookie")
        assert mode == "rb"
        return measured

    monkeypatch.setattr(Path, "open", open_cookie)
    assert cookie_auth(Path("measured.cookie")) == COOKIE_LINE
    assert measured.reads == [4097]


def test_an_enormous_cookie_file_is_refused_rather_than_held(
    tmp_path: Path,
) -> None:
    """The read is bounded, so a wrong path costs no memory.

    A cookie is seventy octets; anything three orders of magnitude larger
    is another file, and finding that out should not mean holding it.
    """
    cookie = tmp_path / ".cookie"
    cookie.write_text(f"{COOKIE_LINE}\n" + "x" * 8192)
    with pytest.raises(FetchError, match="oversized rpc cookie file"):
        cookie_auth(cookie)


def test_the_request_is_a_json_rpc_2_0_post() -> None:
    """2.0, so that an rpc error is not an HTTP 500 like a real one."""
    endpoint = client((200, recorded_body("getblockcount.json")))
    assert endpoint.call("getblockcount") == TIP_HEIGHT

    request = recording(endpoint).request
    assert request.get_method() == "POST"
    assert request.full_url == URL
    assert request.get_header("Content-type") == "application/json"
    authorization = request.get_header("Authorization")
    assert authorization is not None
    assert authorization.startswith("Basic ")

    body = sent(endpoint)
    assert body["jsonrpc"] == "2.0"
    assert body["method"] == "getblockcount"
    assert body["params"] == []


def test_positional_parameters_go_through_in_order() -> None:
    """An array, which is one of json-rpc's two parameter structures."""
    endpoint = client((200, recorded_body("getrawtransaction.json")))
    endpoint.call("getrawtransaction", [TX_ID, 0, TIP_ID])
    assert sent(endpoint)["params"] == [TX_ID, 0, TIP_ID]


def test_named_parameters_go_through_as_an_object() -> None:
    """The other structure: Core reads an object by parameter name."""
    endpoint = client((200, recorded_body("getrawtransaction.json")))
    endpoint.call("getrawtransaction", {"txid": TX_ID, "verbosity": 0})
    assert sent(endpoint)["params"] == {"txid": TX_ID, "verbosity": 0}


def test_cores_args_convention_needs_nothing_here() -> None:
    """A named call carrying an array of leading positional values.

    Core accepts `args` in the object as the positional parameters before
    the named ones, which is why btclib needs no third parameter form:
    the convention is one key of the caller's mapping.
    """
    endpoint = client((200, recorded_body("getrawtransaction.json")))
    endpoint.call("getrawtransaction", {"args": [TX_ID], "verbosity": 0})
    assert sent(endpoint)["params"] == {"args": [TX_ID], "verbosity": 0}


def test_a_parameter_named_like_a_control_reaches_the_node() -> None:
    """`timeout` is a parameter of Core methods and a control of this one.

    Keyword-only controls are what keep the two apart: `request_timeout`
    is this client's and never leaves it, while a `timeout` in `params`
    is the node's and goes through untouched. A signature spreading
    parameters as keywords would have had to choose.
    """
    endpoint = client((200, recorded_body("getblockcount.json")), timeout=5.0)
    endpoint.call("waitfornewblock", {"timeout": 1000}, request_timeout=2.5)
    assert sent(endpoint)["params"] == {"timeout": 1000}
    assert recording(endpoint).timeouts == [2.5]


def test_a_string_is_not_a_sequence_of_parameters() -> None:
    """`call("getblock", block_id)` means one parameter, not sixty-four.

    A str satisfies `Sequence[Any]`, so this one is not even a type error
    to a checker: it is a refusal at run time or a request with sixty-four
    parameters in it.
    """
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibTypeError, match="not a sequence of parameters"):
        endpoint.call("getblock", TX_ID)


@pytest.mark.parametrize("params", [b"bytes", bytearray(b"bytes")])
def test_bytes_are_not_a_sequence_of_parameters(params: object) -> None:
    """Bytes are a Sequence too, and are a value and not a list of them."""
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibTypeError, match="not a sequence of parameters"):
        endpoint.call("getblock", params)  # type: ignore[arg-type]


def test_params_that_are_neither_a_sequence_nor_a_mapping() -> None:
    """An int is not a parameter structure json-rpc has."""
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibTypeError, match="neither a sequence nor a mapping"):
        endpoint.call("getblock", 481824)  # type: ignore[arg-type]


def test_a_parameter_name_that_is_not_a_string() -> None:
    """A json object is keyed by strings, and a mapping here may not be."""
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibTypeError, match="non-string rpc parameter name"):
        endpoint.call("getblock", {1: TX_ID})  # type: ignore[dict-item]


def test_a_nested_parameter_name_that_is_not_a_string() -> None:
    """The check is the whole structure, because the encoder rewrites keys.

    `json.dumps` renders `{1: "a"}` as `{"1": "a"}`: an int, a float, a
    bool or None as a key is silently turned into a string rather than
    refused. Only the outermost mapping is a set of names a caller wrote
    by hand, so a check that stopped there would let every nested value
    reach the node changed from what was passed.
    """
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibTypeError, match="non-string rpc parameter name"):
        endpoint.call("importdescriptors", [{"nested": {1: "value"}}])


@pytest.mark.parametrize(
    "params",
    [
        [{"nested": {"amount": Decimal("0.1")}}],
        [[[Decimal("0.1")]]],
        {"outputs": [{"bc1qexample": Decimal("0.1")}]},
    ],
)
def test_a_decimal_anywhere_in_the_parameters_is_refused(params: object) -> None:
    """A Decimal is refused wherever it is, not only at the top level.

    Which is where one would actually be passed: an amount belongs to an
    output of `send`, an entry of `sendmany`, a field of a descriptor
    request -- never to the array itself.
    """
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibTypeError, match="Decimal rpc parameter"):
        endpoint.call("send", params)  # type: ignore[arg-type]


def test_a_non_finite_number_nested_in_the_parameters_is_refused() -> None:
    """The same walk, and the same diagnosis, for a nan inside a structure."""
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibValueError, match="not a json number in the rpc params"):
        endpoint.call("send", [{"fee_rate": float("inf")}])


def test_bytes_nested_in_the_parameters_are_not_a_list_of_octets() -> None:
    """A `bytes` is a Sequence, and walking it would send the ints in it.

    Refused as the value it is instead, which is the same answer the top
    level gives: btclib takes hex where Core takes hex.
    """
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibTypeError, match="not a json value"):
        endpoint.call("sendrawtransaction", [b"\x01\x00"])


def test_parameters_that_contain_themselves_are_refused() -> None:
    """A cycle is a ValueError out of the encoder, and not about a number.

    `json.dumps` says "Circular reference detected" with the same
    exception type a nan raises, so leaving it to the encoder would report
    a structure that has no json as a number that is not one.
    """
    cyclic: list[Any] = [1]
    cyclic.append(cyclic)
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibValueError, match="contains itself"):
        endpoint.call("send", cyclic)


@pytest.mark.parametrize("kind", ["sequence", "mapping"])
def test_the_parameter_depth_bound_is_inclusive(kind: str) -> None:
    """One hundred containers fit; the next one is refused before encoding."""

    def wrap(value: Any) -> Any:
        return [value] if kind == "sequence" else {"level": value}

    at_limit: Any = "bottom"
    for _ in range(100):
        at_limit = wrap(at_limit)

    endpoint = client((200, recorded_body("getblockcount.json")))
    assert endpoint.call("send", at_limit) == TIP_HEIGHT

    with pytest.raises(BTClibValueError, match="nested deeper than"):
        endpoint.call("send", wrap(at_limit))


def test_something_that_walks_as_json_and_has_none_is_still_refused() -> None:
    """The backstop under the walk, reached by a Sequence json cannot write.

    `range(3)` is a Sequence of three json numbers and has no json of its
    own, so it passes a walk that checks what a structure contains and
    fails in the encoder. What the backstop buys is that it fails as a
    btclib refusal naming the value, rather than as a TypeError from
    inside the standard library.
    """
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibTypeError, match="not a json value: range"):
        endpoint.call("send", [range(3)])


def test_a_decimal_parameter_is_refused_and_not_rounded() -> None:
    """An amount does not become binary floating point on the way out.

    Which is the whole policy: json carries no exact decimal, so a
    Decimal cannot be sent as one -- and rounding it through `float`
    silently is how a payment becomes a different payment. What the
    method documents is what goes: satoshis as an int, or the string
    Core accepts for the field.
    """
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibTypeError, match="Decimal rpc parameter"):
        endpoint.call("sendtoaddress", ["bc1qexample", Decimal("0.1")])


def test_a_parameter_json_cannot_carry_at_all() -> None:
    """Anything else with no json rendering is refused by name."""
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibTypeError, match="not a json value"):
        endpoint.call("sendtoaddress", [OutPoint(TX_ID, 0)])


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_number_is_not_a_json_number(number: float) -> None:
    """`NaN` and `Infinity` are Python's spelling and json has neither.

    Python writes them by default and a node parsing strictly rejects
    the whole request for one, so the refusal belongs here, beside the
    parameter that caused it.
    """
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibValueError, match="not a json number in the rpc params"):
        endpoint.call("settxfee", [number])


def test_a_number_in_a_reply_is_a_decimal_not_a_float() -> None:
    """An amount arrives exact, which binary floating point cannot be.

    0.1 is the standard demonstration: as a float it is a little more
    than a tenth, and the difference is what accumulates over a wallet's
    worth of outputs.
    """
    body = json.dumps({"jsonrpc": "2.0", "result": {"mine": 0.1}, "id": "x"}).encode()
    amount = client((200, body)).call("getbalances")["mine"]
    assert isinstance(amount, Decimal)
    assert amount == Decimal("0.1")
    assert amount != 0.1


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_a_non_number_in_a_reply_is_refused(constant: str) -> None:
    """Python reads back what it writes, and a node sends none of it.

    A nan arriving as an amount compares false against itself for the
    rest of its life, so it is refused where it decodes.
    """
    body = b'{"jsonrpc":"2.0","result":' + constant.encode() + b',"id":"x"}'
    with pytest.raises(
        FetchError, match=f"not a json number in the reply: {constant}"
    ) as exc:
        client((200, body)).call("getbalance")

    # and it is not its own cause. This refusal is btclib's, raised from
    # inside `json.loads` and re-raised as it stands, so a `from` here
    # would have made `__cause__` point at the exception itself -- which
    # anything walking that chain, a log formatter or a reporter, follows
    # round for as long as it is willing to
    assert exc.value.__cause__ is not exc.value
    assert exc.value.__context__ is not exc.value


def test_the_clients_timeout_reaches_the_transport() -> None:
    """Verify the constructor's timeout is what a call inherits."""
    endpoint = client((200, recorded_body("getblockcount.json")), timeout=2.5)
    endpoint.call("getblockcount")
    assert recording(endpoint).timeouts == [2.5]


def test_a_call_can_widen_the_timeout_for_itself() -> None:
    """What `rescanblockchain` needs, and what nothing else should pay for.

    The alternative is a second client whose wider timeout applies to
    every call made through it, including the ones that should fail fast.
    """
    endpoint = client((200, recorded_body("getblockcount.json")), timeout=2.5)
    endpoint.call("rescanblockchain", request_timeout=3600.0)
    assert recording(endpoint).timeouts == [3600.0]
    assert endpoint.timeout == 2.5


def test_one_second_is_a_positive_timeout() -> None:
    """The lower boundary excludes zero, not the first positive second."""
    endpoint = client((200, recorded_body("getblockcount.json")), timeout=1)
    endpoint.call("getblockcount", request_timeout=1)
    assert recording(endpoint).timeouts == [1]


@pytest.mark.parametrize("timeout", [0, -1, float("inf")])
def test_a_per_call_timeout_that_is_no_duration_is_refused(timeout: float) -> None:
    """The same check as the constructor's, at the other place it is set."""
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibValueError, match="request_timeout is not a positive"):
        endpoint.call("getblockcount", request_timeout=timeout)


def test_every_call_asks_with_an_id_of_its_own() -> None:
    """Which is what makes the echo check able to catch anything.

    A fixed id is echoed by the right reply and by a cached one alike, so
    it cannot tell them apart -- and a counter would be shared mutable
    state, the one thing that would make a client unsafe to call from two
    threads.
    """
    endpoint = client((200, recorded_body("getblockcount.json")))
    endpoint.call("getblockcount")
    endpoint.call("getblockcount")
    ids = [asked_id(request) for request in recording(endpoint).requests]
    assert len(set(ids)) == 2
    assert all(re.fullmatch(r"btclib-[0-9a-f]{16}", id_) for id_ in ids)


def test_a_call_writes_nothing_on_the_client() -> None:
    """The other half of what makes concurrent calls safe.

    No counter, no cached credential, no connection kept: the state after
    a call is the configuration it started with, so two threads sharing a
    client cannot interleave into each other's request.
    """
    endpoint = client((200, recorded_body("getblockcount.json")))
    before = dict(vars(endpoint))
    endpoint.call("getblockcount")
    assert dict(vars(endpoint)) == before


@pytest.mark.parametrize("other_id", ["another call", "z-another-call"])
def test_a_reply_to_someone_elses_request_is_refused(other_id: str) -> None:
    """What a caching proxy in the way looks like from here."""
    body = json.dumps({"jsonrpc": "2.0", "result": 1, "id": other_id}).encode()
    with pytest.raises(FetchError, match=rf"reply id {other_id!r} is not the"):
        verbatim((200, body)).call("getblockcount")


def test_an_error_for_someone_elses_request_is_refused() -> None:
    """The correlation is checked on the error path too.

    An error object arriving with another call's id is not this call's
    answer, and reporting its code as this method's would attribute a
    failure to a transaction that was never asked about.
    """
    error = {"code": -5, "message": "No such mempool transaction"}
    body = json.dumps({"jsonrpc": "2.0", "error": error, "id": "another"}).encode()
    with pytest.raises(FetchError, match="reply id 'another' is not the") as exc:
        verbatim((200, body)).call("getrawtransaction", [TX_ID])
    assert not isinstance(exc.value, RpcError)


def test_a_legacy_reply_to_someone_elses_request_is_refused() -> None:
    """The correlation is checked on the path that reads a 1.1 reply too.

    A 200 rules out the status being the failure, so what is left to say
    about a reply carrying another call's id is that it is not this call's
    answer -- the same conclusion the 2.0 path reaches, by a different
    route through the same two facts.
    """
    body = json.dumps({"result": 1, "error": None, "id": "another"}).encode()
    with pytest.raises(FetchError, match="reply id 'another' is not the"):
        verbatim((200, body)).call("getblockcount")


def test_an_rpc_error_object_is_an_rpc_error_with_the_code() -> None:
    """Core's own message for a node without -txindex, and its code."""
    body = recorded_body("getrawtransaction_error.json")
    with pytest.raises(RpcError, match="rpc error code -5") as exc:
        client((200, body)).call("getrawtransaction", [TX_ID])
    assert exc.value.code == -5
    assert exc.value.data is None
    assert "-txindex" in str(exc.value)


def test_the_data_member_of_an_error_object_is_kept() -> None:
    """json-rpc's optional third member, which Core does not send today.

    A method that starts sending one, or a proxy adding its own, would
    otherwise have it dropped where it cannot be recovered from.
    """
    error = {"code": -8, "message": "Invalid parameter", "data": {"field": "txid"}}
    body = json.dumps({"jsonrpc": "2.0", "error": error, "id": "x"}).encode()
    with pytest.raises(RpcError) as exc:
        client((200, body)).call("getrawtransaction", [TX_ID])
    assert exc.value.data == {"field": "txid"}


def test_an_rpc_error_arriving_with_a_500_is_still_an_rpc_error() -> None:
    """A node older than v28 does not know the 2.0 marker and answers 1.1.

    The 1.1 reply puts the error object in the body of an HTTP 500, so
    the status has to be read after the body and not before it -- or
    every "no such transaction" from an old node would be reported as a
    server fault. No `jsonrpc` member is what says the reply is 1.1.
    """
    body = json.dumps(
        {
            "result": None,
            "error": {"code": -5, "message": "No such mempool or blockchain"},
            "id": "x",
        }
    ).encode()
    with pytest.raises(RpcError, match="rpc error code -5"):
        client((500, body)).call("getrawtransaction", [TX_ID])


def test_a_legacy_reply_with_a_result_is_the_result() -> None:
    """v27 and older answer every request this way: no marker, both members."""
    body = json.dumps({"result": TIP_HEIGHT, "error": None, "id": "x"}).encode()
    assert client((200, body)).call("getblockcount") == TIP_HEIGHT


def test_a_500_from_something_in_the_way_is_not_an_rpc_error() -> None:
    """A json body with somebody else's id does not make a 500 the node's.

    Which is why the id is checked before the error object is believed: a
    proxy answering 500 with an error object of its own would otherwise
    be reported as a bitcoin error the node never computed.
    """
    error = {"code": -32603, "message": "upstream said no"}
    body = json.dumps({"result": None, "error": error, "id": "proxy"}).encode()
    with pytest.raises(HttpError, match="HTTP 500") as exc:
        verbatim((500, body)).call("getblockcount")
    assert exc.value.status == 500
    assert not isinstance(exc.value, RpcError)


def test_a_2_0_reply_on_a_non_200_is_an_http_failure() -> None:
    """Under 2.0 an rpc error is a 200, so a 503 is the exchange failing.

    A body shaped like an rpc error beside a 503 is something in front of
    the node explaining itself, and reporting a full work queue as a
    bitcoin error would send the caller looking at the wrong layer.
    """
    error = {"code": -32603, "message": "Work queue depth exceeded"}
    body = json.dumps({"jsonrpc": "2.0", "error": error, "id": "x"}).encode()
    with pytest.raises(HttpError, match="HTTP 503") as exc:
        client((503, body)).call("getblockcount")
    assert exc.value.status == 503
    assert not isinstance(exc.value, RpcError)


def test_the_status_of_a_full_work_queue_is_a_field() -> None:
    """Which is what a caller's retry policy reads, btclib retrying nothing.

    503 with an empty body is what a node whose `rpcworkqueue` is full
    answers; the same request works when the queue drains, and telling it
    from a 401 -- which never will -- is the whole use of the field.
    """
    with pytest.raises(HttpError) as exc:
        client((503, b"")).call("getblockcount")
    assert exc.value.status == 503


def test_a_401_says_it_is_the_credentials() -> None:
    """Core answers an unauthorized request with the status and no body.

    Reporting "not json" would name the symptom and hide the cause,
    which is the whole reason the status is consulted in the except.
    """
    with pytest.raises(HttpError, match="HTTP 401, the node refused") as exc:
        client((401, b"")).call("getblockcount")
    assert exc.value.status == 401


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_redirect_is_refused_and_not_answered(code: int) -> None:
    """An rpc call meeting a 30x fails; the credential stays on one url.

    Nothing follows a redirect (issue #358), so a `Location` is a header on
    a status like any other and the body beside it -- here the html of
    whatever answered instead of the node -- is not a reply. What the
    caller gets is the status, which is what says the endpoint is not the
    node any more; the `Authorization` reached the url they wrote down and
    no second one.
    """
    endpoint = client((code, b"<html><title>Moved</title></html>"))
    with pytest.raises(HttpError, match=f"HTTP {code}") as exc:
        endpoint.call("getblockcount")
    assert exc.value.status == code

    transport = recording(endpoint)
    assert len(transport.requests) == 1
    assert transport.request.full_url == endpoint.url
    assert transport.request.get_header("Authorization") == endpoint.auth_header()


def test_a_body_that_is_not_json_says_so() -> None:
    """A proxy or a web server on the rpc port, answering 200 with html."""
    with pytest.raises(FetchError, match="not json"):
        client((200, b"<html><title>nginx</title></html>")).call("getblockcount")


def test_a_body_that_is_not_utf_8_says_so() -> None:
    """Json is utf-8, and a body that is not is the backend's failure."""
    with pytest.raises(FetchError, match="not utf-8"):
        client((200, b'{"result": "\xff\xfe"}')).call("getblockcount")


# a json number of more digits than `sys.get_int_max_str_digits` allows,
# which `int` refuses with a bare ValueError that is not a
# JSONDecodeError: valid json that this interpreter will not read
_TOO_MANY_DIGITS = b'{"jsonrpc":"2.0","result":' + b"9" * 5000 + b',"id":"x"}'

# the same kind of thing on the other side of the number: json's grammar
# accepts the exponent, and the exact-decimal parser this client asks for
# answers with `decimal.InvalidOperation` -- an ArithmeticError, so neither
# the ValueError nor the RecursionError the rest of this list raises
_HUGE_EXPONENT = b'{"jsonrpc":"2.0","result":1e999999999999999999999999999,"id":"x"}'


@pytest.mark.parametrize(
    "body",
    [
        b'{"result": "\xff\xfe"}',
        b"[" * 200_000 + b"]" * 200_000,
        _TOO_MANY_DIGITS,
        b'{"jsonrpc":"2.0","result":NaN,"id":"x"}',
        b"[1, 2, 3]",
        b'"a string"',
        b"",
        b'{"jsonrpc":"1.0","id":"x","result":1}',
    ],
    ids=[
        "not utf-8",
        "too deep",
        "too many digits",
        "NaN",
        "array",
        "string",
        "empty",
        "a version this module does not read",
    ],
)
def test_a_status_survives_a_body_that_is_no_reply(body: bytes) -> None:
    """A body that is no reply cannot be correlated, so the status wins.

    Whatever stands in front of a node explains itself in its own words,
    and those words are not json-rpc: reporting "not utf-8" for a 503, or
    "not a json-rpc reply", would name the symptom and lose the one thing
    a caller acts on. Every way a body can fail to be a reply keeps the
    status, and they are not one exception type nor even all of them
    failures of the parse -- a decode error, a recursion error, the bare
    ValueError of the integer digit limit, btclib's own refusal of the three
    non-numbers Python decodes, a body that parses perfectly into something
    that is not an object, and an object naming a protocol version this
    module does not read. The decimal parser's own refusal is the same case
    and is tested apart, `Echoing` not being able to carry that body.

    The last one is not a parse failure at all: it is a well-formed object
    that cannot be an answer, which makes it the same case. `Echoing` puts
    this request's id in it, so it is even correlated -- and still not an
    answer, since nothing here knows what a `"1.0"` reply means.
    """
    with pytest.raises(HttpError) as exc:
        client((503, body)).call("getblockcount")
    assert exc.value.status == 503


def test_a_correlated_legacy_error_that_is_no_error_object_keeps_the_status() -> None:
    """An `error` that is not an object is no rpc error, so the status wins.

    The one case the id check alone does not cover: a legacy reply carrying
    *this* request's id and `"error": "bad"`. Correlated, so it is not
    somebody else's answer, and still nothing the node computed -- a string
    is no json-rpc error object -- so what is left to report is the status a
    caller has a policy for. Under a 200 there is no status to report and
    the shape of the body is the whole diagnosis, which is the other half
    asserted here.
    """
    # `Echoing` overwrites the id with this request's, so the reply is
    # correlated whatever is written here
    body = b'{"id":"x","error":"bad"}'
    with pytest.raises(HttpError) as exc:
        client((503, body)).call("getblockcount")
    assert exc.value.status == 503

    with pytest.raises(FetchError, match="unreadable rpc error 'bad'"):
        client((200, body)).call("getblockcount")


def test_a_real_legacy_rpc_error_still_outranks_its_status() -> None:
    """Which is what the two tests above must not have cost.

    Core's legacy 1.1 sends a genuine rpc error with an HTTP 500, so the
    error object has to be read before the status -- otherwise every "no
    such transaction" from a node older than v28 is reported as a server
    fault. Only an *unreadable* error gives the status precedence.
    """
    body = (
        b'{"id":"x","result":null,"error":'
        b'{"code":-5,"message":"No such mempool transaction"}}'
    )
    with pytest.raises(RpcError) as exc:
        client((500, body)).call("getrawtransaction")
    assert exc.value.code == -5
    assert not hasattr(exc.value, "status")


@pytest.mark.parametrize(
    "body",
    [
        b'{"jsonrpc":"2.0","result":NaN,"id":"x"}',
        b"not json",
        b"[1, 2, 3]",
        json.dumps({"result": TIP_HEIGHT, "error": None, "id": "x"}).encode(),
        json.dumps({"jsonrpc": "2.0", "result": TIP_HEIGHT, "id": "x"}).encode(),
    ],
    ids=["non-number", "not-json", "array", "legacy", "version-2"],
)
def test_every_status_other_than_200_precedes_the_reply_shape(body: bytes) -> None:
    """A status below 200 is no more an RPC answer than one above 200."""
    with pytest.raises(HttpError) as exc:
        client((199, body)).call("getblockcount")
    assert exc.value.status == 199


def test_a_number_too_long_for_this_interpreter_to_write() -> None:
    """The mirror of the reply-side limit, on the way out.

    json has the number and Python will not render it, so this is a value
    of a type json takes rather than one of a type it refuses -- which is
    why the walk over the parameters cannot catch it and the encoder is
    where it surfaces.
    """
    endpoint = client((200, recorded_body("getblockcount.json")))
    with pytest.raises(BTClibValueError, match="rpc params json cannot carry"):
        endpoint.call("send", [10**5000])


def test_a_number_too_long_for_this_interpreter_to_read() -> None:
    """Valid json, and `int` refuses it: `sys.get_int_max_str_digits`.

    Not a JSONDecodeError, so it escaped as a bare ValueError from
    underneath the library rather than through btclib's contract, where a
    caller catching FetchError would not see it at all.
    """
    with pytest.raises(FetchError, match="the json parser refused"):
        client((200, _TOO_MANY_DIGITS)).call("getblockcount")


def test_a_reply_nested_too_deeply_to_parse() -> None:
    """A hundred thousand `[` is a recursion error out of the parser.

    Which the bound on the body leaves ample room for, so it arrives as
    the FetchError every other unusable answer does rather than as a
    RecursionError from inside the standard library.
    """
    body = b"[" * 200_000 + b"]" * 200_000
    with pytest.raises(FetchError, match="nested too deeply"):
        client((200, body)).call("getblockcount")


def test_a_number_the_exact_decimal_parser_will_not_build() -> None:
    """`1e999999999999999999999999999` is json, and no Decimal of any size.

    The price of `parse_float=Decimal`, which is what keeps an amount off
    binary floating point: the exponent is past what the decimal module will
    construct, so it answers `InvalidOperation` -- an ArithmeticError, and
    therefore neither the ValueError nor the RecursionError every other
    unreadable body raises. It used to escape `call` as that, past the
    promise this client makes about a reply it cannot read.

    `verbatim` and not `client`: `Echoing` reads the body to put this
    request's id in it, and reading it is what cannot be done -- with the
    default `parse_float` the exponent becomes `inf` and comes back out as
    `Infinity`, so the harness would hand the client a different failure
    than the one under test. The id is never reached here anyway, the parse
    being what fails.
    """
    with pytest.raises(FetchError, match="the json parser refused"):
        verbatim((200, _HUGE_EXPONENT)).call("getbalance")

    with pytest.raises(HttpError) as exc:
        verbatim((503, _HUGE_EXPONENT)).call("getbalance")
    assert exc.value.status == 503


def test_a_json_body_that_is_not_a_reply_object() -> None:
    """Refuse a json body that is not a json-rpc reply object."""
    with pytest.raises(FetchError, match="not a json-rpc reply, but a list"):
        client((200, b"[1, 2, 3]")).call("getblockcount")


@pytest.mark.parametrize("marker", ["1.0", "1.1", "2", 2.0, None])
def test_a_version_marker_that_is_neither_2_0_nor_absent(marker: object) -> None:
    """Absent means 1.1 and `"2.0"` means 2.0; anything else is neither.

    The two protocols differ on where an error is reported, so a marker
    naming no protocol leaves nothing to decide that by. `null` is such a
    marker: a reply carrying it is not the same as one with no member at
    all, which is what says 1.1.
    """
    body = json.dumps({"jsonrpc": marker, "result": 1, "id": "x"}).encode()
    with pytest.raises(FetchError, match="json-rpc version"):
        client((200, body)).call("getblockcount")


@pytest.mark.parametrize(
    "error", [{"code": -5, "message": "not found"}, None], ids=["error", "null"]
)
def test_a_2_0_reply_with_both_result_and_error(error: object) -> None:
    """2.0 says exactly one of them, which is what tells it from 1.1.

    Which member is *present*, and not which is non-null: `"error": null`
    beside a result is the 1.1 shape, and a 1.1 reply wearing the 2.0
    marker is one whose errors would be looked for in the wrong place --
    under 2.0 they never arrive with a 500, and under 1.1 they do.
    """
    body = json.dumps(
        {"jsonrpc": "2.0", "result": 1, "error": error, "id": "x"}
    ).encode()
    with pytest.raises(FetchError, match="both result and error"):
        client((200, body)).call("getblockcount")


def test_a_reply_with_neither_result_nor_error() -> None:
    """Refuse a 2.0 reply object with neither result nor error."""
    body = json.dumps({"jsonrpc": "2.0", "id": "x"}).encode()
    with pytest.raises(FetchError, match="neither result nor error"):
        client((200, body)).call("getblockcount")


def test_a_legacy_reply_with_neither_result_nor_error() -> None:
    """The same refusal on the path that reads a reply with no marker."""
    body = json.dumps({"id": "x"}).encode()
    with pytest.raises(FetchError, match="neither result nor error"):
        client((200, body)).call("getblockcount")


@pytest.mark.parametrize(
    "error",
    [
        "a string",
        {"message": "no code"},
        {"code": "-5"},
        {"code": True},
        [],
        {"code": -1},
        {"code": -1, "message": ["not", "a", "string"]},
        {"code": -1, "message": None},
    ],
)
def test_an_error_member_that_is_not_one(error: object) -> None:
    """Not every non-null `error` carries a code and a message to report.

    A bool among the codes, `true` being what a json `code` of one decodes
    to and a bool not being another spelling of a number anywhere else in
    the library. And a message that is absent or is not a string: a caller
    acts on the code and reads the message, so formatting a list into the
    exception, or reporting an empty message, would have the node saying
    something it did not say.
    """
    body = json.dumps({"jsonrpc": "2.0", "error": error, "id": "x"}).encode()
    with pytest.raises(FetchError, match="unreadable rpc error"):
        client((200, body)).call("getblockcount")


def test_a_wallet_endpoint_is_the_path_core_documents() -> None:
    """How a node with several wallets loaded is told which one is meant."""
    endpoint = BitcoinCoreRpcClient(
        URL, user=RPC_USER, password=RPC_PASSWORD
    ).for_wallet("hot")
    assert endpoint.url == f"{URL}/wallet/hot"
    assert endpoint.user == RPC_USER


@pytest.mark.parametrize(
    ("name", "path"),
    [
        ("my wallet", "my%20wallet"),
        ("a/b", "a%2Fb"),
        ("#1", "%231"),
        ("100%", "100%25"),
        ("cold?", "cold%3F"),
        ("", ""),
    ],
)
def test_a_wallet_name_is_percent_encoded(name: str, path: str) -> None:
    """A wallet is a directory and may be called anything a filesystem takes.

    Written into the path unencoded, a space, a `/`, a `#` or a `?`
    addresses a different endpoint or none -- and the caller who named
    the wallet is not the one who should have to know that.
    """
    endpoint = BitcoinCoreRpcClient(URL, user=RPC_USER, password=RPC_PASSWORD)
    assert endpoint.for_wallet(name).url == f"{URL}/wallet/{path}"


def test_a_wallet_client_keeps_the_credentials_and_the_transport() -> None:
    """The endpoint is the only difference, so one client derives the rest."""
    cookie = Path("/nowhere/.cookie")
    transport = Echoing((200, recorded_body("getblockcount.json")))
    endpoint = BitcoinCoreRpcClient(
        URL, cookie_path=cookie, timeout=7.0, transport=transport
    ).for_wallet("hot")
    assert endpoint.cookie_path == cookie
    assert endpoint.timeout == 7.0
    assert endpoint.transport is transport
    assert endpoint.user is None


def test_get_tx_parses_the_serialization_the_node_sent() -> None:
    """Verbosity 0, so the id is recomputed rather than taken on trust."""
    tx = fetcher((200, recorded_body("getrawtransaction.json"))).get_tx(TX_ID)
    assert tx.id.hex() == TX_ID
    assert len(tx.vin) == 1
    assert [out.value for out in tx.vout] == [10_00000000, 40_00000000]


def test_get_tx_asks_for_the_id_it_was_given() -> None:
    """Verify get_tx sends getrawtransaction with the hex id it was given."""
    endpoint = client((200, recorded_body("getrawtransaction.json")))
    BitcoinCoreFetcher(endpoint).get_tx(bytes.fromhex(TX_ID))
    body = sent(endpoint)
    assert body["method"] == "getrawtransaction"
    assert body["params"] == [TX_ID]


def test_get_tx_labels_the_outputs_for_the_fetchers_network() -> None:
    """The network is the fetcher's: the client knows a url and no chain."""
    endpoint = client((200, recorded_body("getrawtransaction.json")))
    tx = BitcoinCoreFetcher(endpoint, "testnet").get_tx(TX_ID)
    assert [out.script_pub_key.network for out in tx.vout] == ["testnet"] * 2


def test_the_fetchers_network_is_btclibs_registry_not_cores() -> None:
    """Which is the point of the split: `Fetcher` validates against NETWORKS.

    The client refuses no name at all, and `from_network` refuses one Core
    has no port for -- neither of which is the question this label answers.
    """
    with pytest.raises(BTClibValueError, match="unknown network"):
        BitcoinCoreFetcher(
            BitcoinCoreRpcClient(URL, user=RPC_USER, password=RPC_PASSWORD), "nowhere"
        )


def test_get_tx_out_reads_one_output_of_the_previous_transaction() -> None:
    """Verify get_tx_out answers with the one output the OutPoint names."""
    out = fetcher((200, recorded_body("getrawtransaction.json"))).get_tx_out(
        OutPoint(TX_ID, 1)
    )
    assert out.value == 40_00000000


def test_get_block_count_and_get_best_block_id() -> None:
    """Verify the height and the tip id are read off recorded replies."""
    assert fetcher((200, recorded_body("getblockcount.json"))).get_block_count() == (
        TIP_HEIGHT
    )
    tip = fetcher((200, recorded_body("getbestblockhash.json"))).get_best_block_id()
    assert tip.hex() == TIP_ID


@pytest.mark.parametrize("result", ["not a number", None, [1]])
def test_a_height_that_is_not_one(result: object) -> None:
    """Refuse a getblockcount result that is not an int."""
    body = json.dumps({"jsonrpc": "2.0", "result": result, "id": "x"}).encode()
    with pytest.raises(FetchError, match="getblockcount:"):
        fetcher((200, body)).get_block_count()


@pytest.mark.parametrize("result", ["", "00" * 31, 481824, None])
def test_a_tip_hash_that_is_not_one(result: object) -> None:
    """Refuse a getbestblockhash result that is not a block id."""
    body = json.dumps({"jsonrpc": "2.0", "result": result, "id": "x"}).encode()
    with pytest.raises(FetchError, match="getbestblockhash:"):
        fetcher((200, body)).get_best_block_id()


@pytest.mark.parametrize("result", ["not hex", "", None, 170, {"hex": "0100"}])
def test_a_raw_transaction_that_is_not_one(result: object) -> None:
    """Refuse a getrawtransaction result that is not a hex tx."""
    body = json.dumps({"jsonrpc": "2.0", "result": result, "id": "x"}).encode()
    with pytest.raises(FetchError, match=f"transaction {TX_ID}:"):
        fetcher((200, body)).get_tx(TX_ID)


def test_a_small_reply_carries_a_small_limit() -> None:
    """A height and a tip hash are bounded by what they are.

    `call` defaults to the widest answer a fetcher asks for, a raw
    transaction as hex inside a json envelope, because it is public and
    takes any method -- `getblock` on a large block is a legitimate call.
    The two answers that are a number and a hash say so instead.
    """
    oversized = b'{"result":' + b"9" * 1100 + b',"error":null,"id":"x"}'
    with pytest.raises(FetchError, match="more than the 1024 allowed"):
        fetcher((200, oversized)).get_block_count()

    # the recorded answers are well inside it, which is the other half of
    # the claim
    assert fetcher((200, recorded_body("getblockcount.json"))).get_block_count() == (
        TIP_HEIGHT
    )

    # and `call` itself keeps the wide default, being public and taking
    # any method: `getblock` on a large block is a legitimate call. The
    # timeout defaults to the client's, which is what None means here
    defaults = BitcoinCoreRpcClient.call.__kwdefaults__
    assert defaults is not None
    assert defaults["max_body_size"] == DEFAULT_MAX_BODY_SIZE
    assert defaults["request_timeout"] is None


def test_a_custom_transport_owns_its_allocation_bound() -> None:
    """The two bounds are not one bound, and this is the one btclib keeps.

    A transport of a caller's own is handed the request and a timeout and
    nothing else: it cannot see what this call allowed, so what it holds
    in memory before answering is its own bound to set. What btclib
    promises for one is the per-call limit applied afterwards -- an
    oversized answer goes no further, having already been read.
    """
    body = b'{"jsonrpc":"2.0","result":"' + b"a" * 2048 + b'","id":"x"}'
    endpoint = client((200, body))
    with pytest.raises(FetchError, match="more than the 1024 allowed"):
        endpoint.call("getblockcount", max_body_size=1024)

    # and the same answer is fine when the call allows its weight, which
    # is what says the limit is the caller's and not the transport's
    assert len(endpoint.call("getblockcount", max_body_size=4096)) == 2048
