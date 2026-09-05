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
    DEFAULT_SIGNET_CHALLENGE,
    BitcoinCoreRpcClient,
    RPCErrorCode,
    SessionTransport,
    chain_from_network,
    network_from_chain,
)
from typing_extensions import override

from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    FetchError,
    HttpError,
    RpcError,
)
from btclib.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib.fetch.transport import DEFAULT_MAX_BODY_SIZE
from btclib.network import NETWORKS
from btclib.tx import OutPoint, Tx
from tests.fetch import (
    LATER_TX_ID,
    SEGWIT_TX_RAW,
    TIP_HEIGHT,
    TIP_ID,
    TX_ID,
    Recorded,
    recorded_body,
)

# the rpc credentials every test here passes. Named once rather than
# written at each call, which is what keeps the string out of a
# `password=` argument: the secret scanners read a literal there as a
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

    @override
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
    """Return a BitcoinCoreFetcher over a recorded client.

    `verify_network=False` unless a test says otherwise: the scripted
    replies are consumed in order, so a fetcher that asked the node which
    chain it serves would eat the reply the test wrote for the call it is
    about. The tests that *are* about the question say so and script the
    `getblockchaininfo` reply first.
    """
    network = kwargs.pop("network", "mainnet")
    assert isinstance(network, str)
    verify_network = kwargs.pop("verify_network", False)
    assert isinstance(verify_network, bool)
    challenge = kwargs.pop("signet_challenge", None)
    assert challenge is None or isinstance(challenge, (str, bytes))
    return BitcoinCoreFetcher(
        client(*answers, **kwargs),
        network,
        verify_network=verify_network,
        signet_challenge=challenge,
    )


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


def asked(endpoint: BitcoinCoreRpcClient) -> list[str]:
    """Return the method of every call a client made, in order."""
    methods = []
    for request in recording(endpoint).requests:
        data = request.data
        assert isinstance(data, bytes)
        body = json.loads(data)
        assert isinstance(body, dict)
        methods.append(str(body["method"]))
    return methods


def broadcast_tx() -> Tx:
    """Return the transaction the broadcast tests announce, parsed.

    A segwit spend and not the transaction `getrawtransaction.json`
    answers `get_tx` with: what `sendrawtransaction` carries is the wire
    serialization, and a transaction with no witness has one
    serialization rather than two.
    """
    return Tx.parse(SEGWIT_TX_RAW)


def test_get_tx_parses_the_serialization_the_node_sent() -> None:
    """Verbosity 0, so the id is recomputed rather than taken on trust."""
    tx = fetcher((200, recorded_body("getrawtransaction.json"))).get_tx(TX_ID)
    assert tx.id.hex() == TX_ID
    assert len(tx.vin) == 1
    assert [out.value for out in tx.vout] == [10_00000000, 40_00000000]


def test_get_tx_asks_for_the_id_it_was_given() -> None:
    """Verify get_tx sends getrawtransaction with the hex id it was given."""
    endpoint = client((200, recorded_body("getrawtransaction.json")))
    BitcoinCoreFetcher(endpoint, verify_network=False).get_tx(bytes.fromhex(TX_ID))
    body = sent(endpoint)
    assert body["method"] == "getrawtransaction"
    assert body["params"] == [TX_ID]


def test_a_session_transport_can_drive_the_fetcher() -> None:
    """`BitcoinCoreFetcher` takes a client, so its transport is the client's.

    Nothing here is the fetcher's to wire: `SessionTransport`'s
    constructor opens no connection, so building one and handing it to
    the client this fetcher is built over is the whole of driving one
    fetcher through it -- no round trip, and no code of this class's own
    to reach.
    """
    session = SessionTransport()
    endpoint = BitcoinCoreRpcClient(
        URL, user=RPC_USER, password=RPC_PASSWORD, transport=session
    )
    assert (
        BitcoinCoreFetcher(endpoint, verify_network=False).client.transport is session
    )


def test_get_tx_labels_the_outputs_for_the_fetchers_network() -> None:
    """The network is the fetcher's: the client knows a url and no chain."""
    endpoint = client((200, recorded_body("getrawtransaction.json")))
    tx = BitcoinCoreFetcher(endpoint, "testnet", verify_network=False).get_tx(TX_ID)
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
    beyond the ones this question reads, so a recording of it would be a
    fixture to re-take whenever Core adds one, and every test below would
    then be edited to change the one member it is about.
    """
    body = json.dumps({"jsonrpc": "2.0", "result": members, "id": "x"}).encode()
    return 200, body


def test_every_network_btclib_ships_has_a_chain_name() -> None:
    """The coupling between two vocabularies kept in two repositories.

    What the pairing *is* belongs to `bitcoin-core-rpc`, which owns both
    tables and tests them; what belongs here is that btclib's own registry
    is covered by them. A network added to `NETWORKS` and unknown to the
    package is an `assert_network` that cannot answer for it -- and the
    round trip is what says the two tables agree in both directions rather
    than merely having an entry each.

    `assert_network` relies on this: `NETWORKS` is fixed at import, so a
    name a fetcher is allowed to carry is one `chain_from_network` can
    translate, and there is no branch there for a name it cannot.
    """
    for network in NETWORKS:
        assert network_from_chain(chain_from_network(network)) == network


@pytest.mark.parametrize("network, chain", [("mainnet", "main"), ("testnet", "test")])
def test_assert_network_accepts_the_chain_the_node_reports(
    network: str, chain: str
) -> None:
    """The names that differ, which are what a mismatch hides behind."""
    fetcher(blockchaininfo(chain=chain), network=network).assert_network()


def test_assert_network_refuses_a_node_on_another_chain() -> None:
    """The silent failure this exists for: a testnet node under a mainnet label.

    A client with an explicit url reaches a testnet node with no port
    default in the way, and every address rendered from what that fetcher
    returns is then a mainnet address for coins that are not there.
    Nothing else in the exchange says so.
    """
    with pytest.raises(BTClibValueError, match="reports chain 'test', not the 'main'"):
        fetcher(blockchaininfo(chain="test"), network="mainnet").assert_network()


def test_assert_network_refuses_a_chain_that_sorts_before_the_label() -> None:
    """The mismatch the other direction: `main` sorts before every label here.

    The sibling test asks for mainnet and gets `test`, which sorts after
    it -- a comparison weakened from "not equal" to "sorts after" would
    still refuse that one. Asking for testnet and getting `main`, which
    sorts before it, is the half only a real inequality catches.
    """
    with pytest.raises(BTClibValueError, match="reports chain 'main', not the 'test'"):
        fetcher(blockchaininfo(chain="main"), network="testnet").assert_network()


def test_assert_network_tells_two_signets_apart() -> None:
    """`signet` is the name of every signet, so the challenge is the identity.

    Core reports `signet` for the default one and for a custom one alike,
    so the name comparison passes here and the check has to go further:
    the magic the challenge derives is what a fetcher for the default
    signet does not share with a node on someone else's.
    """
    answer = blockchaininfo(chain="signet", signet_challenge=CUSTOM_CHALLENGE)
    with pytest.raises(BTClibValueError, match="signet this client is not"):
        fetcher(answer, network="signet").assert_network()

    default = blockchaininfo(chain="signet", signet_challenge=DEFAULT_SIGNET_CHALLENGE)
    fetcher(default, network="signet").assert_network()


def test_assert_network_checks_the_signet_the_fetcher_was_given() -> None:
    """A signet of the caller's own, which is what `signet_challenge` is for.

    No entry in `NETWORKS` and no `Network` built by hand: a custom signet
    differs from the default one in its p2p magic alone, which is a fact
    about the node and not about how an address is spelled -- so the
    challenge is an argument to this class, and the encoding table stays
    signet's.
    """
    answer = blockchaininfo(chain="signet", signet_challenge=CUSTOM_CHALLENGE)
    endpoint = fetcher(
        answer, network="signet", verify_network=True, signet_challenge=CUSTOM_CHALLENGE
    )
    endpoint.assert_network()

    other = blockchaininfo(chain="signet", signet_challenge=OTHER_CHALLENGE)
    with pytest.raises(BTClibValueError, match="signet this client is not"):
        fetcher(
            other,
            network="signet",
            verify_network=True,
            signet_challenge=CUSTOM_CHALLENGE,
        ).assert_network()


def test_a_challenge_is_refused_where_it_would_check_nothing() -> None:
    """Two combinations that are a check the caller expects and would not get.

    A network that is no signet has no challenge to be held to, and
    `verify_network` off is the comparison not being made -- so both are
    refused at construction, where the mistake was written, rather than at
    a fetch that would pass.
    """
    with pytest.raises(BTClibValueError, match="challenge for mainnet"):
        fetcher(
            network="mainnet", verify_network=True, signet_challenge=CUSTOM_CHALLENGE
        )
    with pytest.raises(BTClibValueError, match="checks nothing with it off"):
        fetcher(network="signet", signet_challenge=CUSTOM_CHALLENGE)


@pytest.mark.parametrize("network", ["testnet", "testnet4"])
def test_a_challenge_is_refused_for_a_testnet_too(network: str) -> None:
    """The refusal is inequality with signet, not an ordering against it.

    The chain names are compared as strings, and `main` and `regtest` both
    sort before `signet` where an ordering and an inequality agree. The
    testnets sort after it, so they are the networks a comparison
    would accept a challenge for -- one that could never be checked,
    because there is no signet challenge in a testnet's genesis to hold it
    to.
    """
    with pytest.raises(BTClibValueError, match=f"challenge for {network}"):
        fetcher(network=network, verify_network=True, signet_challenge=CUSTOM_CHALLENGE)


def test_a_challenge_that_is_no_script_is_refused_at_construction() -> None:
    """Derived once here, so that the failure is at the line that wrote it.

    A challenge is hex or the bytes it spells; anything else would
    otherwise reach the node's reply and be reported as the *node*
    answering something unreadable.
    """
    with pytest.raises(BTClibValueError, match="no hex"):
        fetcher(network="signet", verify_network=True, signet_challenge="not hex")


@pytest.mark.parametrize(
    "result, message, network",
    [
        pytest.param(
            3, "no string chain in the int result", "mainnet", id="not-an-object"
        ),
        pytest.param(
            {}, "no string chain in the dict result", "mainnet", id="no-chain"
        ),
        pytest.param(
            {"chain": 5},
            "no string chain in the dict result",
            "mainnet",
            id="chain-not-a-string",
        ),
        # a signet fetcher for the two below: the chain name is compared
        # first, so a mainnet one would disagree about the name and never
        # read the member these are about
        pytest.param(
            {"chain": "signet"},
            "no string signet_challenge",
            "signet",
            id="signet-no-challenge",
        ),
        pytest.param(
            {"chain": "signet", "signet_challenge": "not hex"},
            "unreadable signet_challenge",
            "signet",
            id="challenge-that-is-not-hex",
        ),
    ],
)
def test_assert_network_refuses_a_malformed_reply(
    result: object, message: str, network: str
) -> None:
    """A reply that is not an answer is a FetchError naming the method.

    The same treatment every other answer here gets, and what tells it
    apart from the case above: a node that said something unreadable is a
    fetch that did not happen, where a node that named another chain
    answered exactly what was asked.
    """
    body = json.dumps({"jsonrpc": "2.0", "result": result, "id": "x"}).encode()
    with pytest.raises(FetchError, match=message):
        fetcher((200, body), network=network).assert_network()


def test_the_first_fetch_asks_the_node_which_chain_it_serves() -> None:
    """Which is what `verify_network` buys, and it is on by default."""
    endpoint = client(
        blockchaininfo(chain="main"), (200, recorded_body("getrawtransaction.json"))
    )
    assert BitcoinCoreFetcher(endpoint).get_tx(TX_ID).id.hex() == TX_ID
    assert asked(endpoint) == ["getblockchaininfo", "getrawtransaction"]


def test_the_chain_is_asked_for_once_and_not_per_fetch() -> None:
    """A node does not change chain under a client pointing at it."""
    endpoint = client(
        blockchaininfo(chain="main"),
        (200, recorded_body("getblockcount.json")),
        (200, recorded_body("getbestblockhash.json")),
    )
    core = BitcoinCoreFetcher(endpoint)
    assert core.get_block_count() == TIP_HEIGHT
    assert core.get_best_block_id().hex() == TIP_ID
    assert asked(endpoint) == ["getblockchaininfo", "getblockcount", "getbestblockhash"]


def test_a_node_on_another_chain_answers_no_fetch_at_all() -> None:
    """The failure the option exists for, and it does not wear off.

    A fetcher that asked once, was refused once and then served an
    address on the next call would be the silent failure with an extra
    step, so the disagreement is remembered -- and remembered rather than
    re-asked, which is what the second call proves by adding no request.
    """
    endpoint = client(blockchaininfo(chain="test"))
    core = BitcoinCoreFetcher(endpoint, "mainnet")
    for _ in range(2):
        with pytest.raises(BTClibValueError, match="reports chain 'test'"):
            core.get_tx(TX_ID)
    assert asked(endpoint) == ["getblockchaininfo"]


def test_a_node_that_could_not_be_asked_is_asked_again() -> None:
    """A node that did not answer said nothing about which chain it is on.

    The distinction the remembering rests on: a chain that disagrees is a
    fact about a configuration, where a socket that did not connect is a
    request to make again.
    """
    endpoint = client(
        rpc.FetchError("no answer from http://127.0.0.1:8332: refused"),
        blockchaininfo(chain="main"),
        (200, recorded_body("getrawtransaction.json")),
    )
    core = BitcoinCoreFetcher(endpoint)
    with pytest.raises(FetchError, match="refused"):
        core.get_tx(TX_ID)
    assert core.get_tx(TX_ID).id.hex() == TX_ID
    assert asked(endpoint) == [
        "getblockchaininfo",
        "getblockchaininfo",
        "getrawtransaction",
    ]


def test_verify_network_false_asks_the_node_nothing() -> None:
    """The opt-out is one round trip, and is what this class did before."""
    endpoint = client((200, recorded_body("getrawtransaction.json")))
    core = BitcoinCoreFetcher(endpoint, verify_network=False)
    assert core.get_tx(TX_ID).id.hex() == TX_ID
    assert asked(endpoint) == ["getrawtransaction"]


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


def test_get_block_header_asks_getblockhash_then_getblockheader() -> None:
    """Two calls, in order: the height maps to a hash before a header answers.

    `getblockheader`'s second parameter is `false`, so the reply is the
    serialization and not a rendering of it -- the same shape
    `getrawtransaction`'s no-verbosity reply answers `get_tx` with.
    """
    endpoint = client(
        (200, recorded_body("getblockhash.json")),
        (200, recorded_body("getblockheader.json")),
    )
    header = BitcoinCoreFetcher(endpoint, verify_network=False).get_block_header(
        TIP_HEIGHT
    )
    assert header.hash.hex() == TIP_ID
    assert asked(endpoint) == ["getblockhash", "getblockheader"]

    requests = recording(endpoint).requests
    hash_request_data = requests[0].data
    header_request_data = requests[1].data
    assert isinstance(hash_request_data, bytes)
    assert isinstance(header_request_data, bytes)
    assert json.loads(hash_request_data)["params"] == [TIP_HEIGHT]
    assert json.loads(header_request_data)["params"] == [TIP_ID, False]


@pytest.mark.parametrize("height", [-1, -481824])
def test_get_block_header_refuses_a_negative_height(height: int) -> None:
    """Refused before any request, both calls mapping a height to a block."""
    endpoint = client()
    with pytest.raises(BTClibValueError, match="invalid height"):
        BitcoinCoreFetcher(endpoint, verify_network=False).get_block_header(height)
    assert asked(endpoint) == []


@pytest.mark.parametrize("height", ["481824", 481824.5, None])
def test_get_block_header_refuses_a_non_integer_height(height: object) -> None:
    """Refused before any request, the same as a negative one."""
    endpoint = client()
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        BitcoinCoreFetcher(endpoint, verify_network=False).get_block_header(
            height  # type: ignore[arg-type]
        )
    assert asked(endpoint) == []


def test_get_block_header_verifies_the_chain_once_like_the_others() -> None:
    """`get_block_header` goes through `_verify_once`, as the others do."""
    endpoint = client(
        blockchaininfo(chain="main"),
        (200, recorded_body("getblockhash.json")),
        (200, recorded_body("getblockheader.json")),
    )
    core = BitcoinCoreFetcher(endpoint)
    assert core.get_block_header(TIP_HEIGHT).hash.hex() == TIP_ID
    assert asked(endpoint) == ["getblockchaininfo", "getblockhash", "getblockheader"]


def test_a_small_reply_carries_a_small_limit() -> None:
    """A height and a tip hash are bounded by what they are.

    `call` defaults to the widest answer a fetcher asks for, a raw
    transaction as hex inside a json envelope, because it is public and
    takes any method -- `getblock` on a large block is a legitimate call.
    The answers that are a number and a hash say so instead.
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
    # the message translated across, not the status carried beside it
    # under the same positional index the message also answers to
    assert "getblockcount" in str(exc.value)


def test_an_error_the_client_raises_without_a_status_is_a_fetch_error() -> None:
    """A refused connection has no status, and is a plain `FetchError`.

    The transport raises rather than answering, which is what a socket
    that never connected does; the client turns it into its own
    `FetchError`, and this is the branch of the translation with no field
    to carry.
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
    # the message itself, and not the code or the data carried beside it
    # under the same positional index once `args` holds all three
    assert "No such mempool transaction" in str(exc.value)


def test_broadcast_sends_the_wire_serialization_and_returns_the_txid() -> None:
    """`sendrawtransaction` with the hex serialization, and no maxfeerate.

    `maxfeerate` absent from `params` and not defaulted to `None`: json
    has no null the way `sendrawtransaction`'s optional parameter reads
    it, so a caller who passed nothing gets a request with one parameter,
    not two.

    The witness is in that serialization: the two serializations of this
    transaction are different bytes under one id, so a broadcast
    stripping it announces a transaction carrying none of the signatures
    and the node confirms the same id either way.
    """
    tx = broadcast_tx()
    endpoint = client(
        (200, json.dumps({"jsonrpc": "2.0", "result": tx.id.hex(), "id": "x"}).encode())
    )
    txid = BitcoinCoreFetcher(endpoint, verify_network=False).broadcast(tx)
    assert txid == tx.id
    assert asked(endpoint) == ["sendrawtransaction"]
    body = sent(endpoint)
    assert body["params"] == [tx.serialize(include_witness=True).hex()]
    # the vector tells the two serializations apart, which is the other
    # half of the claim
    assert tx.serialize(include_witness=False) != tx.serialize(include_witness=True)


def test_broadcast_passes_maxfeerate_only_when_given() -> None:
    """`maxfeerate` rides as a second positional parameter, never a default."""
    tx = broadcast_tx()
    endpoint = client(
        (200, json.dumps({"jsonrpc": "2.0", "result": tx.id.hex(), "id": "x"}).encode())
    )
    BitcoinCoreFetcher(endpoint, verify_network=False).broadcast(tx, maxfeerate=0.02)
    body = sent(endpoint)
    assert body["params"] == [tx.serialize(include_witness=True).hex(), 0.02]


@pytest.mark.parametrize(
    "confirmed",
    # the coinbase of block 170, whose id sorts before the transaction
    # announced, and one of block 481824's, whose id sorts after it
    ["b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082", LATER_TX_ID],
)
def test_broadcast_refuses_a_success_naming_another_txid(confirmed: str) -> None:
    """The node answered for a transaction that is not the one it was sent.

    One wrong id on each side of the one announced: the check is
    inequality, and a guard written `<` hands the second back as the id
    of a broadcast the node never confirmed.
    """
    tx = broadcast_tx()
    endpoint = client(
        (200, json.dumps({"jsonrpc": "2.0", "result": confirmed, "id": "x"}).encode())
    )
    with pytest.raises(FetchError, match=f"the node confirmed {confirmed}"):
        BitcoinCoreFetcher(endpoint, verify_network=False).broadcast(tx)


@pytest.mark.parametrize(
    "code", [RPCErrorCode.VERIFY_REJECTED, RPCErrorCode.VERIFY_ALREADY_IN_UTXO_SET]
)
def test_broadcast_reports_the_nodes_refusal_with_its_own_reason(
    code: RPCErrorCode,
) -> None:
    """A refusal keeps Core's code and message, through `client_errors`.

    `-26` is a policy rejection and `-27` a transaction already
    confirmed: two different refusals, and the message is what a caller
    tells them apart with, not a code flattened to "broadcast failed".
    """
    tx = broadcast_tx()
    message = (
        "min relay fee not met" if code == -26 else "Transaction already in block chain"
    )
    error = {"code": int(code), "message": message}
    body = json.dumps({"jsonrpc": "2.0", "error": error, "id": "x"}).encode()
    with pytest.raises(RpcError) as exc:
        BitcoinCoreFetcher(client((200, body)), verify_network=False).broadcast(tx)
    assert exc.value.code == code
    assert message in str(exc.value)


def test_broadcast_verifies_the_network_before_sending_anything() -> None:
    """A wrong-chain node is refused before the transaction ever leaves.

    The worst version of the silent failure `verify_network` exists to
    catch: `sendrawtransaction` is never called at all, `assert_network`
    consuming the one scripted reply.
    """
    endpoint = client(blockchaininfo(chain="test"))
    with pytest.raises(BTClibValueError, match="reports chain 'test', not the 'main'"):
        BitcoinCoreFetcher(endpoint, network="mainnet").broadcast(broadcast_tx())
    assert asked(endpoint) == ["getblockchaininfo"]


def test_broadcast_verifies_the_network_once_like_the_other_methods() -> None:
    """Agreeing once, `broadcast` goes straight through as the questions do."""
    tx = broadcast_tx()
    endpoint = client(
        blockchaininfo(chain="main"),
        (
            200,
            json.dumps({"jsonrpc": "2.0", "result": tx.id.hex(), "id": "x"}).encode(),
        ),
    )
    core = BitcoinCoreFetcher(endpoint)
    assert core.broadcast(tx) == tx.id
    assert asked(endpoint) == ["getblockchaininfo", "sendrawtransaction"]
