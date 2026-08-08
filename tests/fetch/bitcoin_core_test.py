# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `BitcoinCoreFetcher`, against recorded replies.

What the client itself does with a request and a reply is the
`bitcoin-core-rpc` package's, and is tested there. What is left here is
btclib's half: the answers turned into btclib transactions, the outputs
labelled for the network the fetcher was built for, and `assert_network`
comparing that label with the chain the node reports.

Every client here is built with a transport, so no test reaches a node.
The recorded bodies under `_data` are Core's, shape and newline included;
the replies a node cannot be asked to produce on demand are written
inline, where what they are is visible beside the assertion.

The recorded bodies carry the id of the call they answered, and `call`
sends a fresh one per request: `Echoing` puts the request's id in the
reply the way a node does, so that a test about the *reply* is not also a
test about the id.
"""

from __future__ import annotations

import json
from urllib.request import Request

import bitcoin_core_rpc as rpc
import pytest
from bitcoin_core_rpc import (
    BitcoinCoreRpcClient,
    chain_from_network,
    network_from_chain,
)

from btclib.exceptions import BTClibValueError, FetchError, HttpError, RpcError
from btclib.fetch.bitcoin_core import BitcoinCoreFetcher, _signet_magic
from btclib.fetch.transport import DEFAULT_MAX_BODY_SIZE
from btclib.network import NETWORKS, Network
from btclib.tx import OutPoint
from tests.fetch import TIP_HEIGHT, TIP_ID, TX_ID, Recorded, recorded_body

# the rpc credentials every test here passes. Named once rather than
# written at each call, which is what keeps the string out of a
# `password=` argument: the two secret scanners read a literal there as a
# credential, and they are right to -- a real one belongs in neither
RPC_USER = "rpcuser"
RPC_PASSWORD = "rpcpassword"  # noqa: S105  # pragma: allowlist secret

# the endpoint the tests build against, written once
URL = "http://127.0.0.1:8332"


def asked_id(request: Request) -> str:
    """Return the json-rpc id a recorded request was sent with."""
    data = request.data
    assert isinstance(data, bytes)
    request_id = json.loads(data)["id"]
    assert isinstance(request_id, str)
    return request_id


def echoed(body: bytes, request_id: str) -> bytes:
    """Return a recorded reply carrying the id of the request it answers.

    Every reply here is a json object, an empty body being the one
    exception and one no id belongs in: what a client does with a body
    that is not a reply at all is the package's question, and is asked
    there.
    """
    if not body:
        return body
    reply = json.loads(body)
    assert isinstance(reply, dict)
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

    The client refuses no name at all, and `from_chain` refuses one Core
    has no port for -- neither of which is the question this label answers.
    """
    with pytest.raises(BTClibValueError, match="unknown network"):
        BitcoinCoreFetcher(
            BitcoinCoreRpcClient(URL, user=RPC_USER, password=RPC_PASSWORD), "nowhere"
        )


# a block challenge that is not Core's, which is the whole of what makes a
# signet a different one. Any script serves: what the check reads from it
# is a hash, and this is a p2wpkh of a public key hash nobody holds
CUSTOM_CHALLENGE = "0014" + "ab" * 20
OTHER_CHALLENGE = "0014" + "cd" * 20


def blockchaininfo(**members: object) -> tuple[int, bytes]:
    """Return a 200 answer whose result is a getblockchaininfo of these members.

    Written here rather than recorded: the reply carries a dozen members
    beyond the two this question reads, so a recording of it would be a
    fixture to re-take whenever Core adds one, and every test below would
    then be edited to change the one member it is about.
    """
    body = json.dumps({"jsonrpc": "2.0", "result": members, "id": "x"}).encode()
    return 200, body


def custom_signet(challenge: str) -> Network:
    """Return a Network like the default signet, with this challenge's magic.

    What a caller registers for a signet of their own -- issue #207 -- and
    the magic is derived by the function the check itself uses. What that
    derivation is worth is settled elsewhere, in
    `tests/network_test.py`, against the magic Core publishes for its own
    signet; here it is the pairing of a challenge with a Network that
    matters.
    """
    return Network.from_dict(
        {**NETWORKS["signet"].to_dict(), "magic_bytes": _signet_magic(challenge).hex()}
    )


def test_every_network_btclib_ships_has_a_chain_name() -> None:
    """The coupling between two vocabularies kept in two repositories.

    What the pairing *is* belongs to `bitcoin-core-rpc`, which owns both
    tables and tests them; what belongs here is that btclib's own registry
    is covered by them. A network added to `NETWORKS` and unknown to the
    package is an `assert_network` that cannot answer for it -- and the
    round trip is what says the two tables agree in both directions rather
    than merely having an entry each.

    `NETWORKS` is a dict a caller adds to, so this reads the shipped
    registry: the four names of `_data/`, not whatever a test registered.
    """
    for network in NETWORKS:
        assert network_from_chain(chain_from_network(network)) == network


@pytest.mark.parametrize("network, chain", [("mainnet", "main"), ("testnet", "test")])
def test_assert_network_accepts_the_chain_the_node_reports(
    network: str, chain: str
) -> None:
    """The two names that differ, which are the two a mismatch hides behind."""
    fetcher(blockchaininfo(chain=chain), network=network).assert_network()


def test_assert_network_refuses_a_node_on_another_chain() -> None:
    """The silent failure this exists for: a testnet node under a mainnet label.

    A client with an explicit url reaches a testnet node with no port
    default in the way, and every address rendered from what that fetcher
    returns is then a mainnet address for coins that are not there.
    Nothing else in the exchange says so.
    """
    with pytest.raises(
        BTClibValueError, match="node is on test, this fetcher on mainnet"
    ):
        fetcher(blockchaininfo(chain="test"), network="mainnet").assert_network()


def test_assert_network_tells_two_signets_apart() -> None:
    """`signet` is the name of every signet, so the challenge is the identity.

    Core reports `signet` for the default one and for a custom one alike,
    so the name comparison passes here and the check has to go further:
    the magic the challenge derives is what a fetcher for the default
    signet does not share with a node on someone else's.
    """
    answer = blockchaininfo(chain="signet", signet_challenge=CUSTOM_CHALLENGE)
    with pytest.raises(BTClibValueError, match="signet this fetcher is not"):
        fetcher(answer, network="signet").assert_network()


def test_assert_network_checks_a_caller_registered_signet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Network a caller built is checkable, which is what the magic buys.

    Its name is btclib's alone and means nothing to a node, so the name is
    not what is compared. `NETWORKS` is a dict a caller adds to, and
    `monkeypatch.setitem` is how this one is taken back out.
    """
    monkeypatch.setitem(NETWORKS, "custom-signet", custom_signet(CUSTOM_CHALLENGE))

    answer = blockchaininfo(chain="signet", signet_challenge=CUSTOM_CHALLENGE)
    fetcher(answer, network="custom-signet").assert_network()

    other = blockchaininfo(chain="signet", signet_challenge=OTHER_CHALLENGE)
    with pytest.raises(BTClibValueError, match="signet this fetcher is not"):
        fetcher(other, network="custom-signet").assert_network()


def test_assert_network_has_nothing_to_compare_for_a_custom_name_off_signet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller's own network against a node on main: a refusal, not a pass.

    Only a signet answers with an identity, so a name Core never heard of
    has nothing to be held against -- and passing silently is the failure
    this method exists to catch.
    """
    monkeypatch.setitem(NETWORKS, "custom-signet", custom_signet(CUSTOM_CHALLENGE))
    with pytest.raises(BTClibValueError, match="no chain of Core's"):
        fetcher(blockchaininfo(chain="main"), network="custom-signet").assert_network()


@pytest.mark.parametrize(
    "result, message",
    [
        pytest.param(3, "not a JSON object: int", id="not-an-object"),
        pytest.param({}, "no chain name in the reply: None", id="no-chain"),
        pytest.param(
            {"chain": 5}, "no chain name in the reply: 5", id="chain-not-a-string"
        ),
        pytest.param(
            {"chain": "signet"}, "no signet_challenge", id="signet-with-no-challenge"
        ),
        pytest.param(
            {"chain": "signet", "signet_challenge": "not hex"},
            "getblockchaininfo",
            id="challenge-that-is-not-hex",
        ),
    ],
)
def test_assert_network_refuses_a_malformed_reply(result: object, message: str) -> None:
    """A reply that is not an answer is a FetchError naming the method.

    The same treatment every other answer here gets, and what tells it
    apart from the case above: a node that said something unreadable is a
    fetch that did not happen, where a node that named another chain
    answered exactly what was asked.
    """
    body = json.dumps({"jsonrpc": "2.0", "result": result, "id": "x"}).encode()
    with pytest.raises(FetchError, match=message):
        fetcher((200, body), network="mainnet").assert_network()


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
    with pytest.raises(FetchError, match="more than the max_body_size of 1024"):
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


def test_a_status_from_the_client_arrives_as_btclibs_http_error() -> None:
    """The package raises its own `HttpError`; a fetcher raises btclib's.

    Both classes carry a `status` and neither is the other, so what this
    pins is the translation `client_errors` performs: the type a caller
    catches, and the field that is the whole reason the type exists. A 503
    from a full work queue is the case the field is for -- the same
    request works when the queue drains, where a 401 never will.
    """
    with pytest.raises(HttpError) as exc:
        fetcher((503, b"")).get_block_count()
    assert exc.value.status == 503
    assert not isinstance(exc.value, rpc.HttpError)


def test_an_error_the_client_raises_without_a_status_is_a_fetch_error() -> None:
    """A refused connection has no status, and is a plain `FetchError`.

    The transport raises rather than answering, which is what a socket
    that never connected does; the client turns it into its own
    `FetchError`, and this is the third branch of the translation -- the
    one with no field to carry.
    """
    refused = rpc.FetchError("no answer from http://127.0.0.1:8332: refused")
    with pytest.raises(FetchError, match="refused") as exc:
        fetcher(refused).get_block_count()
    assert not isinstance(exc.value, rpc.FetchError)
    assert type(exc.value) is FetchError


def test_an_rpc_error_keeps_its_code_and_its_data_across_the_translation() -> None:
    """The other two fields, and the message composed once rather than twice.

    Both classes append `(rpc error code N)` in `__str__`, so a
    translation handing the composed message back in would say it again
    per hop. `args[0]` is what it passes instead, and this is the
    assertion that says so.
    """
    error = {"code": -5, "message": "No such mempool transaction", "data": {"tx": 1}}
    body = json.dumps({"jsonrpc": "2.0", "error": error, "id": "x"}).encode()
    with pytest.raises(RpcError) as exc:
        fetcher((200, body)).get_tx(TX_ID)
    assert exc.value.code == -5
    assert exc.value.data == {"tx": 1}
    assert not isinstance(exc.value, rpc.RpcError)
    assert str(exc.value).count("rpc error code") == 1
