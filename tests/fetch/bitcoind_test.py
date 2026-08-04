#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for btclib.fetch.bitcoind, against recorded replies.

Every AuthProxy here is built with a transport, so no test reaches a
node. The recorded bodies under `_data` are Core's, shape and newline
included; the failure bodies a node cannot be asked to produce on demand
-- a 401, a proxy's html -- are written inline, where what they are is
visible beside the assertion.
"""

from __future__ import annotations

import json
import re
from base64 import b64decode
from pathlib import Path

import pytest

from btclib.exceptions import BTClibValueError, FetchError, RpcError
from btclib.fetch.bitcoind import (
    COOKIE_USER,
    DEFAULT_DATADIR,
    AuthProxy,
    BitcoindFetcher,
    cookie_auth,
)
from btclib.fetch.transport import DEFAULT_MAX_BODY_SIZE
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


def proxy(*answers: tuple[int, bytes] | Exception, **kwargs: object) -> AuthProxy:
    """Return an AuthProxy over a recording, with credentials of no node."""
    transport = Recorded(*answers)
    return AuthProxy(
        user=RPC_USER,
        password=RPC_PASSWORD,
        transport=transport,
        **kwargs,  # type: ignore[arg-type]
    )


def test_the_default_endpoint_is_the_local_node_of_that_network() -> None:
    """The rpc port and the datadir subdirectory of Core's chainparamsbase."""
    assert AuthProxy().url == "http://127.0.0.1:8332"
    assert AuthProxy(network="testnet").url == "http://127.0.0.1:18332"
    assert AuthProxy(network="testnet4").url == "http://127.0.0.1:48332"
    assert AuthProxy(network="signet").url == "http://127.0.0.1:38332"
    assert AuthProxy(network="regtest").url == "http://127.0.0.1:18443"

    assert AuthProxy().cookie_path == DEFAULT_DATADIR / ".cookie"
    assert AuthProxy(network="testnet").cookie_path == (
        DEFAULT_DATADIR / "testnet3" / ".cookie"
    )
    assert AuthProxy(network="regtest").cookie_path == (
        DEFAULT_DATADIR / "regtest" / ".cookie"
    )


def test_an_unknown_network_is_refused() -> None:
    """Refuse a network name Core's chainparamsbase does not know."""
    with pytest.raises(BTClibValueError, match="unknown network: testnet5"):
        AuthProxy(network="testnet5")


@pytest.mark.parametrize(
    "url",
    [
        f"http://{RPC_USER}:{RPC_PASSWORD}@127.0.0.1:8332",
        f"http://{RPC_USER}@127.0.0.1:8332",
    ],
)
def test_credentials_in_the_url_are_refused(url: str) -> None:
    """python-bitcoinrpc's spelling, and the reason for not taking it.

    A url is the thing that gets written into a config file, printed in
    a traceback and pasted into an issue; a password in one has been
    disclosed before anybody meant to disclose it.
    """
    with pytest.raises(BTClibValueError, match="credentials in the rpc url"):
        AuthProxy(url)


@pytest.mark.parametrize(("user", "password"), [(RPC_USER, None), (None, RPC_PASSWORD)])
def test_a_user_without_a_password_is_refused(
    user: str | None, password: str | None
) -> None:
    """Refuse a user without a password, and the other way round."""
    with pytest.raises(BTClibValueError, match="go together"):
        AuthProxy(user=user, password=password)


def test_the_basic_credential_is_the_user_and_password_given() -> None:
    """Verify the Authorization header is Basic over user:password."""
    header = AuthProxy(user=RPC_USER, password=RPC_PASSWORD).auth_header()
    scheme, encoded = header.split(" ")
    assert scheme == "Basic"
    assert b64decode(encoded).decode() == f"{RPC_USER}:{RPC_PASSWORD}"


def test_a_non_ascii_password_is_utf_8() -> None:
    """What a shell and a bitcoin.conf would have written."""
    umlauts = "pässwörd"
    header = AuthProxy(user=RPC_USER, password=umlauts).auth_header()
    assert b64decode(header.split(" ")[1]) == f"{RPC_USER}:{umlauts}".encode()


def test_the_cookie_file_is_the_credential_when_there_is_no_user(
    tmp_path: Path,
) -> None:
    """Verify the cookie line becomes the Basic credential, no user given."""
    cookie = tmp_path / ".cookie"
    cookie.write_text(COOKIE_LINE)
    header = AuthProxy(cookie_path=cookie).auth_header()
    assert b64decode(header.split(" ")[1]).decode() == COOKIE_LINE


def test_the_cookie_is_read_at_every_call_not_at_construction(
    tmp_path: Path,
) -> None:
    """Because a node restart rotates it.

    A proxy built once and used for an hour would otherwise answer 401
    for the rest of the process. Constructing one touches no file at all,
    which is the other half of the same decision: building a client
    should not raise FileNotFoundError.
    """
    cookie = tmp_path / ".cookie"
    endpoint = AuthProxy(cookie_path=cookie, transport=Recorded((200, b"{}")))
    assert not cookie.exists()

    cookie.write_text(COOKIE_LINE)
    first = endpoint.auth_header()
    cookie.write_text(f"{COOKIE_USER}:" + "cd" * 32)
    assert endpoint.auth_header() != first


def test_an_absent_cookie_file_says_which_file(tmp_path: Path) -> None:
    """Verify the unreadable-cookie error names the missing file."""
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
    with pytest.raises(FetchError, match="malformed rpc cookie file"):
        cookie_auth(cookie)


def test_the_request_is_a_json_rpc_2_0_post() -> None:
    """2.0, so that an rpc error is not an HTTP 500 like a real one."""
    transport = Recorded((200, recorded_body("getblockcount.json")))
    endpoint = AuthProxy(user=RPC_USER, password=RPC_PASSWORD, transport=transport)
    assert endpoint.call("getblockcount") == TIP_HEIGHT

    assert transport.request.get_method() == "POST"
    assert transport.request.full_url == "http://127.0.0.1:8332"
    assert transport.request.get_header("Content-type") == "application/json"
    authorization = transport.request.get_header("Authorization")
    assert authorization is not None
    assert authorization.startswith("Basic ")
    assert json.loads(transport.body) == {
        "jsonrpc": "2.0",
        "id": "btclib",
        "method": "getblockcount",
        "params": [],
    }


def test_the_parameters_go_through_in_order() -> None:
    """Positional, as Core takes them: `call` is any method, not three."""
    transport = Recorded((200, recorded_body("getrawtransaction.json")))
    endpoint = AuthProxy(user=RPC_USER, password=RPC_PASSWORD, transport=transport)
    endpoint.call("getrawtransaction", TX_ID, 0, TIP_ID)
    assert json.loads(transport.body)["params"] == [TX_ID, 0, TIP_ID]


def test_the_timeout_reaches_the_transport() -> None:
    """Verify the constructor's timeout is handed to the transport."""
    transport = Recorded((200, recorded_body("getblockcount.json")))
    AuthProxy(
        user=RPC_USER, password=RPC_PASSWORD, timeout=2.5, transport=transport
    ).call("getblockcount")
    assert transport.timeouts == [2.5]


def test_an_rpc_error_object_is_an_rpc_error_with_the_code() -> None:
    """Core's own message for a node without -txindex, and its code."""
    body = recorded_body("getrawtransaction_error.json")
    with pytest.raises(RpcError, match="rpc error code -5") as exc:
        proxy((200, body)).call("getrawtransaction", TX_ID)
    assert exc.value.code == -5
    assert "-txindex" in str(exc.value)


def test_an_rpc_error_arriving_with_a_500_is_still_an_rpc_error() -> None:
    """A node older than v28 does not know the 2.0 marker and answers 1.0.

    The 1.0 reply puts the error object in the body of an HTTP 500, so
    the status has to be read after the body and not before it -- or
    every "no such transaction" from an old node would be reported as a
    server fault.
    """
    body = json.dumps(
        {
            "result": None,
            "error": {"code": -5, "message": "No such mempool or blockchain"},
            "id": "btclib",
        }
    ).encode()
    with pytest.raises(RpcError, match="rpc error code -5"):
        proxy((500, body)).call("getrawtransaction", TX_ID)


def test_a_401_says_it_is_the_credentials() -> None:
    """Core answers an unauthorized request with the status and no body.

    Reporting "not json" would name the symptom and hide the cause,
    which is the whole reason the status is consulted in the except.
    """
    with pytest.raises(FetchError, match="HTTP 401, the node refused"):
        proxy((401, b"")).call("getblockcount")


def test_a_body_that_is_not_json_says_so() -> None:
    """A proxy or a web server on the rpc port, answering 200 with html."""
    with pytest.raises(FetchError, match="not json"):
        proxy((200, b"<html><title>nginx</title></html>")).call("getblockcount")


def test_a_json_body_that_is_not_a_reply_object() -> None:
    """Refuse a json body that is not a json-rpc reply object."""
    with pytest.raises(FetchError, match="not a json-rpc reply"):
        proxy((200, b"[1, 2, 3]")).call("getblockcount")


def test_a_non_200_with_no_error_object_reports_the_status() -> None:
    """Verify a non-200 with no error object reports the status."""
    body = json.dumps({"jsonrpc": "2.0", "result": None, "id": "btclib"}).encode()
    with pytest.raises(FetchError, match="HTTP 503"):
        proxy((503, body)).call("getblockcount")


def test_a_reply_to_someone_elses_request_is_refused() -> None:
    """What a caching proxy in the way looks like from here."""
    body = json.dumps({"jsonrpc": "2.0", "result": 1, "id": "other"}).encode()
    with pytest.raises(FetchError, match="reply id 'other' is not ours"):
        proxy((200, body)).call("getblockcount")


def test_a_reply_with_neither_result_nor_error() -> None:
    """Refuse a reply object with neither result nor error."""
    body = json.dumps({"jsonrpc": "2.0", "id": "btclib"}).encode()
    with pytest.raises(FetchError, match="neither result nor error"):
        proxy((200, body)).call("getblockcount")


@pytest.mark.parametrize(
    "error", ["a string", {"message": "no code"}, {"code": "-5"}, []]
)
def test_an_error_member_that_is_not_one(error: object) -> None:
    """Not every non-null `error` carries a code to report."""
    body = json.dumps({"jsonrpc": "2.0", "error": error, "id": "btclib"}).encode()
    with pytest.raises(FetchError, match="unreadable rpc error"):
        proxy((200, body)).call("getblockcount")


def fetcher(
    *answers: tuple[int, bytes] | Exception, **kwargs: object
) -> BitcoindFetcher:
    """Return a BitcoindFetcher over a recorded AuthProxy."""
    return BitcoindFetcher(proxy(*answers, **kwargs))


def test_get_tx_parses_the_serialization_the_node_sent() -> None:
    """Verbosity 0, so the id is recomputed rather than taken on trust."""
    tx = fetcher((200, recorded_body("getrawtransaction.json"))).get_tx(TX_ID)
    assert tx.id.hex() == TX_ID
    assert len(tx.vin) == 1
    assert [out.value for out in tx.vout] == [10_00000000, 40_00000000]


def test_get_tx_asks_for_the_id_it_was_given() -> None:
    """Verify get_tx sends getrawtransaction with the hex id it was given."""
    transport = Recorded((200, recorded_body("getrawtransaction.json")))
    endpoint = AuthProxy(user=RPC_USER, password=RPC_PASSWORD, transport=transport)
    BitcoindFetcher(endpoint).get_tx(bytes.fromhex(TX_ID))
    assert json.loads(transport.body) == {
        "jsonrpc": "2.0",
        "id": "btclib",
        "method": "getrawtransaction",
        "params": [TX_ID],
    }


def test_get_tx_labels_the_outputs_for_the_proxies_network() -> None:
    """The network is the proxy's, so a fetcher cannot disagree with it."""
    endpoint = proxy((200, recorded_body("getrawtransaction.json")), network="testnet")
    tx = BitcoindFetcher(endpoint).get_tx(TX_ID)
    assert [out.script_pub_key.network for out in tx.vout] == ["testnet"] * 2


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


@pytest.mark.parametrize(
    ("result", "match"),
    [
        ("not a number", "getblockcount:"),
        (None, "getblockcount:"),
        ([1], "getblockcount:"),
    ],
)
def test_a_height_that_is_not_one(result: object, match: str) -> None:
    """Refuse a getblockcount result that is not an int."""
    body = json.dumps({"jsonrpc": "2.0", "result": result, "id": "btclib"}).encode()
    with pytest.raises(FetchError, match=match):
        fetcher((200, body)).get_block_count()


@pytest.mark.parametrize("result", ["", "00" * 31, 481824, None])
def test_a_tip_hash_that_is_not_one(result: object) -> None:
    """Refuse a getbestblockhash result that is not a block id."""
    body = json.dumps({"jsonrpc": "2.0", "result": result, "id": "btclib"}).encode()
    with pytest.raises(FetchError, match="getbestblockhash:"):
        fetcher((200, body)).get_best_block_id()


@pytest.mark.parametrize("result", ["not hex", "", None, 170, {"hex": "0100"}])
def test_a_raw_transaction_that_is_not_one(result: object) -> None:
    """Refuse a getrawtransaction result that is not a hex tx."""
    body = json.dumps({"jsonrpc": "2.0", "result": result, "id": "btclib"}).encode()
    with pytest.raises(FetchError, match=f"transaction {TX_ID}:"):
        fetcher((200, body)).get_tx(TX_ID)


def test_a_small_reply_carries_a_small_limit() -> None:
    """A height and a tip hash are bounded by what they are.

    `call` defaults to the widest answer a fetcher asks for, a raw
    transaction as hex inside a json envelope, because it is public and
    takes any method -- `getblock` on a large block is a legitimate call.
    The two answers that are a number and a hash say so instead.
    """
    oversized = b'{"result":' + b"9" * 1100 + b',"error":null,"id":"btclib"}'
    with pytest.raises(FetchError, match="more than the 1024 allowed"):
        fetcher((200, oversized)).get_block_count()

    # the recorded answers are well inside it, which is the other half of
    # the claim
    assert fetcher((200, recorded_body("getblockcount.json"))).get_block_count() == (
        TIP_HEIGHT
    )

    # and `call` itself keeps the wide default, being public and taking
    # any method: `getblock` on a large block is a legitimate call
    defaults = AuthProxy.call.__kwdefaults__
    assert defaults is not None
    assert defaults["max_body_size"] == DEFAULT_MAX_BODY_SIZE
