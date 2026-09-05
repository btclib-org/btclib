# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `ElectrumFetcher`, against a scripted `LineTransport`.

No socket anywhere here, `LineRecorded` below being the whole of what
answers: this half ships no implementation of `LineTransport`, so a test
reaching a real server is not merely undesirable, it is not possible.
`tests/electrum_test.py` is the codec these calls are built on; the
literals below are that module's own, repeated rather than imported, so
that the two suites agree on what a real server would answer without one
importing the other.
"""

from __future__ import annotations

import json

import pytest
from bitcoin_core_rpc import FetchError as RpcFetchError

from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibValueError, FetchError, RpcError
from btclib.fetch.electrum import ElectrumFetcher
from btclib.network import NETWORKS
from btclib.tx import OutPoint
from tests.fetch import TIP_HEADER_RAW, TIP_HEIGHT, TIP_ID, TX_ID

# block 481824's transaction at index 1 -- see tests/electrum_test.py for
# how the branch below was derived and its own positive control against
# the real header
MERKLE_TX_ID = "c2bfb6f1bf791308c6b8f73f5d4181be9aa490da6e73c188f9ebd0723e8531b6"
MERKLE_TX_RAW = (
    "0200000001d40c5407d03e50fdfbdaa1ec97b3ce0cc29d72e7ca360c18221cf903d8b5f51b"
    "010000006a47304402203dad2ca83215b123c8c89bfd161b519033eb1c049935e06358"
    "9f265e05640371022064e64c030368b78ac842d4dd6a2b9959afc2e46ea78f011dcb9d"
    "b3bbdae23651012103d20c7990a9cccd9d1346d2d1bfa7270030209e73810edd9a33fe"
    "d28ad1409b50feffffff02400d0300000000001976a9145f8c60ce58c1791c2df2040e"
    "f8a086e948f2f22588ac0c7cb132000000001976a914f3f79e50b1556826355864c4da"
    "ca603e52e50b4888ac1f5a0700"
)
MERKLE_TX_POS = 1
MERKLE_BRANCH = [
    "da917699942e4a96272401b534381a75512eeebe8403084500bd637bd47168b3",
    "392b569a882bc6252cc5fef0c2b420fcbad0c568ba70df3d6cff11b2ea1d3351",
    "9aec6f7d8292ddbc922e608a2be69b2ab74675c1e1d1d4156339f831ab8a1458",
    "015365e7ce124037203a131573c77c1d54f5fef5fb77baba2ab202ccd4e133f8",
    "af310a3344d96e14141142e334552ad1fa75a4a365cd895c1cfbd0961de6cd41",
    "2812b22e24414bae49286160a78ef765848b375bde5b67f2fd7209f07a24902d",
    "d0da4f69356c1c7739a1971f76384829ebe1517635778d4ce0b0a91b56d282cc",
    "0cfa885934de2d374d14ecdcf1f2a03dba36fbe6ca034202ca17a0a58aefa9bf",
    "6632f3c95dcf284f86569018d081853473c1f8416009856103384e218e412df5",
    "b3c8b80f3aca397fba2062b35cc042ff806655d0e593c5ef50d6df48d7360836",
    "66532296fd04814bf47c9b0bbe2760262d5e452a77671c5cac90624d6d8c8554",
]

# the eighty bytes `blockchain.block.header` answers for height 0 on each
# chain: the first eighty of the genesis block serializations this tree
# already carries, mainnet's in tests/block/_data/checkblock_valid.json and
# testnet's in tests/block/_data/blockfilters.json. What makes them vectors
# rather than literals to trust is that their hashes are the ones
# `NETWORKS[network].genesis_block` holds, which is what the first test of
# the network check asserts before any of the others rests on it
MAINNET_GENESIS_HEADER = (
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49"
    "ffff001d1dac2b7c"
)
TESTNET_GENESIS_HEADER = (
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494d"
    "ffff001d1aa4ae18"
)
MAINNET_GENESIS = NETWORKS["mainnet"].genesis_block.hex()
TESTNET_GENESIS = NETWORKS["testnet"].genesis_block.hex()


class RpcErrorAnswer:
    """A scripted JSON-RPC error object, for `LineRecorded` to answer with."""

    def __init__(self, message: str, code: int, data: object = None) -> None:
        self.message = message
        self.code = code
        self.data = data


class LineRecorded:
    """A LineTransport answering from a script, remembering the requests.

    Each answer is a `result` value, an `RpcErrorAnswer`, raw `bytes`, or
    an `Exception`, consumed in order; the last one repeats. A `result`
    or `RpcErrorAnswer` answer has this request's own id spliced in
    before it is returned, the way a real server's reply carries the id
    it was asked with -- so a test scripts a result and never a rendered
    one. Raw `bytes` is returned exactly as scripted, unmodified id
    included or not, which is how a test reaches "the line does not
    decode" and "the id does not match" without this class fixing either.
    """

    def __init__(self, *answers: object) -> None:
        self.answers = list(answers)
        self.requests: list[bytes] = []
        self.timeouts: list[float] = []

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Record the request and answer with the next scripted answer."""
        self.requests.append(request)
        self.timeouts.append(timeout)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, bytes):
            return answer
        request_id = json.loads(request)["id"]
        if isinstance(answer, RpcErrorAnswer):
            error: dict[str, object] = {"code": answer.code, "message": answer.message}
            if answer.data is not None:
                error["data"] = answer.data
            body: dict[str, object] = {"id": request_id, "error": error}
        else:
            body = {"id": request_id, "result": answer}
        return json.dumps(body).encode()

    @property
    def methods(self) -> list[str]:
        """The `method` field of every request made, in order."""
        return [json.loads(request)["method"] for request in self.requests]


def fetcher(*answers: object, **kwargs: object) -> ElectrumFetcher:
    """Return an ElectrumFetcher over a scripted LineTransport.

    `verify_network=False` unless a test says otherwise: the scripted
    answers are consumed in order, so a fetcher that asked the server
    which chain it serves would eat the answer the test wrote for the
    call it is about. The tests that *are* about the question build the
    fetcher themselves -- one of them passing no `verify_network` at all,
    which is what pins the default.
    """
    network = kwargs.pop("network", "mainnet")
    assert isinstance(network, str)
    verify_network = kwargs.pop("verify_network", False)
    assert isinstance(verify_network, bool)
    transport = LineRecorded(*answers)
    return ElectrumFetcher(
        network,
        transport=transport,
        verify_network=verify_network,
        **kwargs,  # type: ignore[arg-type]
    )


def transport_of(endpoint: ElectrumFetcher) -> LineRecorded:
    """Return the transport a fetcher was built with, as one."""
    assert isinstance(endpoint.transport, LineRecorded)
    return endpoint.transport


def test_transport_is_required() -> None:
    """No default in this half: no transport is a `TypeError`, no fallback."""
    with pytest.raises(TypeError, match="transport"):
        ElectrumFetcher()  # type: ignore[call-arg]


def test_get_tx_parses_the_serialization_the_server_sent() -> None:
    """`transaction.get`'s hex, decoded and checked against the id asked for."""
    endpoint = fetcher(MERKLE_TX_RAW)
    tx = endpoint.get_tx(MERKLE_TX_ID)
    assert tx.id.hex() == MERKLE_TX_ID
    assert transport_of(endpoint).methods == ["blockchain.transaction.get"]


def test_get_tx_asks_the_display_order_id() -> None:
    """`get_tx` accepts bytes and sends the display-order hex on the wire."""
    endpoint = fetcher(MERKLE_TX_RAW)
    endpoint.get_tx(bytes.fromhex(MERKLE_TX_ID))
    request = json.loads(transport_of(endpoint).requests[0])
    assert request["params"] == [MERKLE_TX_ID]


def test_get_tx_refuses_the_answer_to_another_question() -> None:
    """The id is recomputed from the serialization and checked against it."""
    with pytest.raises(FetchError, match="the answer is"):
        fetcher(MERKLE_TX_RAW).get_tx(TX_ID)


def test_get_tx_out_derives_the_output() -> None:
    """`get_tx_out` is not overridden: it reads off the fetched transaction."""
    out = fetcher(MERKLE_TX_RAW).get_tx_out(OutPoint(MERKLE_TX_ID, 0))
    assert out.value == 200_000


def test_a_truncated_transaction_is_refused() -> None:
    """A body cut off in transit is caught by `Tx.parse`, not by the codec."""
    truncated = MERKLE_TX_RAW[:20]
    with pytest.raises(FetchError, match=f"transaction {MERKLE_TX_ID}:"):
        fetcher(truncated).get_tx(MERKLE_TX_ID)


def test_get_block_count_and_get_best_block_id() -> None:
    """Both answers are read from the same `headers.subscribe` reply."""
    tip = {"height": TIP_HEIGHT, "hex": TIP_HEADER_RAW}
    assert fetcher(tip).get_block_count() == TIP_HEIGHT
    assert fetcher(tip).get_best_block_id().hex() == TIP_ID


def test_get_block_count_asks_headers_subscribe() -> None:
    """`get_block_count` asks `blockchain.headers.subscribe`, nothing else."""
    endpoint = fetcher({"height": TIP_HEIGHT, "hex": TIP_HEADER_RAW})
    endpoint.get_block_count()
    assert transport_of(endpoint).methods == ["blockchain.headers.subscribe"]


def test_get_best_block_id_is_not_the_servers_word() -> None:
    """The id is recomputed from the header bytes, not read off a field."""
    tip = {"height": TIP_HEIGHT, "hex": TIP_HEADER_RAW}
    header = BlockHeader.parse(TIP_HEADER_RAW)
    assert fetcher(tip).get_best_block_id() == header.hash


@pytest.mark.parametrize(
    "tip",
    [
        {"height": "not an int", "hex": TIP_HEADER_RAW},
        {"height": TIP_HEIGHT},  # no "hex" member at all
        {"height": TIP_HEIGHT, "hex": "not hex at all!!"},
        "not an object",
    ],
)
def test_a_headers_subscribe_answer_that_is_not_one(tip: object) -> None:
    """A missing or wrongly typed member, or no object at all, is refused."""
    with pytest.raises(FetchError, match="headers.subscribe:"):
        fetcher(tip).get_block_count()


def test_get_block_header_asks_block_header() -> None:
    """`blockchain.block.header`, the height alone, no `cp_height`."""
    endpoint = fetcher(TIP_HEADER_RAW)
    header = endpoint.get_block_header(TIP_HEIGHT)
    assert header.hash.hex() == TIP_ID
    request = json.loads(transport_of(endpoint).requests[0])
    assert request["method"] == "blockchain.block.header"
    assert request["params"] == [TIP_HEIGHT]


@pytest.mark.parametrize("height", [-1, -481824])
def test_get_block_header_refuses_a_negative_height(height: int) -> None:
    """Refused before any request, the same guard every backend shares."""
    endpoint = fetcher()
    with pytest.raises(BTClibValueError, match="invalid height"):
        endpoint.get_block_header(height)
    assert transport_of(endpoint).requests == []


def test_get_tx_merkle_round_trips_the_proof() -> None:
    """`get_tx_merkle` is the question no other backend can answer."""
    endpoint = fetcher(
        {"block_height": TIP_HEIGHT, "merkle": MERKLE_BRANCH, "pos": MERKLE_TX_POS}
    )
    proof = endpoint.get_tx_merkle(MERKLE_TX_ID, TIP_HEIGHT)
    assert proof.pos == MERKLE_TX_POS
    assert proof.branch == tuple(bytes.fromhex(h) for h in MERKLE_BRANCH)
    request = json.loads(transport_of(endpoint).requests[0])
    assert request["method"] == "blockchain.transaction.get_merkle"
    assert request["params"] == [MERKLE_TX_ID, TIP_HEIGHT]


def test_verify_tx_accepts_the_real_proof() -> None:
    """The header and the branch, fetched separately, agree on the vector."""
    endpoint = fetcher(
        TIP_HEADER_RAW,
        {"block_height": TIP_HEIGHT, "merkle": MERKLE_BRANCH, "pos": MERKLE_TX_POS},
    )
    assert endpoint.verify_tx(MERKLE_TX_ID, TIP_HEIGHT) is True


def test_verify_tx_refuses_a_wrong_branch() -> None:
    """A substituted sibling answers False, not an exception."""
    wrong_branch = ["00" * 32, *MERKLE_BRANCH[1:]]
    endpoint = fetcher(
        TIP_HEADER_RAW,
        {"block_height": TIP_HEIGHT, "merkle": wrong_branch, "pos": MERKLE_TX_POS},
    )
    assert endpoint.verify_tx(MERKLE_TX_ID, TIP_HEIGHT) is False


def test_verify_tx_refuses_a_wrong_position() -> None:
    """The real branch at the wrong position answers False too."""
    endpoint = fetcher(
        TIP_HEADER_RAW,
        {
            "block_height": TIP_HEIGHT,
            "merkle": MERKLE_BRANCH,
            "pos": MERKLE_TX_POS ^ 1,
        },
    )
    assert endpoint.verify_tx(MERKLE_TX_ID, TIP_HEIGHT) is False


def test_a_response_whose_id_does_not_match_is_refused() -> None:
    """A line answering a different request is refused, not returned."""
    wrong_id = json.dumps({"id": 999999, "result": MERKLE_TX_RAW}).encode()
    with pytest.raises(FetchError, match="does not answer request"):
        fetcher(wrong_id).get_tx(MERKLE_TX_ID)


def test_a_line_that_is_not_json_is_refused() -> None:
    """A line a server never sends, refused rather than misread."""
    with pytest.raises(FetchError, match="not a JSON-RPC line"):
        fetcher(b"this is not json\n").get_tx(MERKLE_TX_ID)


def test_a_json_rpc_error_object_is_refused() -> None:
    """A JSON-RPC error object reaches the caller as `RpcError`, code kept."""
    endpoint = fetcher(RpcErrorAnswer("no such transaction", -32000))
    with pytest.raises(RpcError, match="no such transaction") as exc_info:
        endpoint.get_tx(MERKLE_TX_ID)
    assert exc_info.value.code == -32000


def test_a_json_rpc_error_objects_data_member_is_kept() -> None:
    """`data` is JSON-RPC's optional third member, carried across when sent."""
    endpoint = fetcher(RpcErrorAnswer("busy", -32001, data={"retry_after": 5}))
    with pytest.raises(RpcError) as exc_info:
        endpoint.get_tx(MERKLE_TX_ID)
    assert exc_info.value.data == {"retry_after": 5}


def test_the_timeout_is_passed_to_the_transport() -> None:
    """The fetcher's own `timeout`, not `LineTransport`'s default."""
    endpoint = fetcher(TIP_HEADER_RAW, timeout=12.5)
    endpoint.get_block_header(TIP_HEIGHT)
    assert transport_of(endpoint).timeouts == [12.5]


def test_a_transport_failure_is_translated() -> None:
    """`LineTransport`'s exception contract, translated by `client_errors`."""
    with pytest.raises(FetchError, match="connection refused"):
        fetcher(RpcFetchError("connection refused")).get_tx(MERKLE_TX_ID)


@pytest.mark.parametrize(
    "network, raw",
    [("mainnet", MAINNET_GENESIS_HEADER), ("testnet", TESTNET_GENESIS_HEADER)],
)
def test_the_genesis_headers_hash_to_what_networks_carries(
    network: str, raw: str
) -> None:
    """The control the two vectors above rest on, for both chains.

    `assert_network` compares the hash of the eighty bytes the server
    sent, so a header vector that hashed to something else would make
    every test below agree about the wrong thing.
    """
    assert BlockHeader.parse(raw).hash == NETWORKS[network].genesis_block


def test_assert_network_accepts_the_genesis_of_the_network_given() -> None:
    """The check that passes: the server answers the genesis expected."""
    endpoint = fetcher(MAINNET_GENESIS_HEADER)
    endpoint.assert_network()
    request = json.loads(transport_of(endpoint).requests[0])
    assert request["method"] == "blockchain.block.header"
    assert request["params"] == [0]


def test_assert_network_refuses_a_different_genesis() -> None:
    """The silent failure this exists for: a testnet server, a mainnet label.

    Both hashes are in the message, so the caller can see which is which.
    """
    with pytest.raises(BTClibValueError, match=f"{TESTNET_GENESIS}.*{MAINNET_GENESIS}"):
        fetcher(TESTNET_GENESIS_HEADER).assert_network()


def test_a_header_that_is_not_the_genesis_of_any_chain_is_refused() -> None:
    """A server answering height 0 with some other block it mined is refused.

    The tip header is well-formed and cost real work, so
    `block_header_from_raw` passes it: what refuses it is the comparison.
    """
    with pytest.raises(BTClibValueError, match=f"{TIP_ID}.*{MAINNET_GENESIS}"):
        fetcher(TIP_HEADER_RAW).assert_network()


def test_the_first_fetch_asks_the_server_which_chain_it_serves() -> None:
    """Which is what `verify_network` buys, and it is on by default.

    No `verify_network` argument here on purpose: this is the test that
    would fail if the default were flipped.
    """
    transport = LineRecorded(MAINNET_GENESIS_HEADER, MERKLE_TX_RAW)
    endpoint = ElectrumFetcher("mainnet", transport=transport)
    assert endpoint.get_tx(MERKLE_TX_ID).id.hex() == MERKLE_TX_ID
    assert transport.methods == [
        "blockchain.block.header",
        "blockchain.transaction.get",
    ]
    assert json.loads(transport.requests[0])["params"] == [0]


def test_the_chain_is_asked_for_once_and_not_per_fetch() -> None:
    """A server does not change chain under a client pointing at it.

    Built with no `verify_network` argument, like the test above: the
    default is what these two pin.
    """
    tip = {"height": TIP_HEIGHT, "hex": TIP_HEADER_RAW}
    transport = LineRecorded(MAINNET_GENESIS_HEADER, tip)
    endpoint = ElectrumFetcher("mainnet", transport=transport)
    assert endpoint.get_block_count() == TIP_HEIGHT
    assert endpoint.get_best_block_id().hex() == TIP_ID
    assert transport.methods == [
        "blockchain.block.header",
        "blockchain.headers.subscribe",
        "blockchain.headers.subscribe",
    ]


def test_a_server_on_another_chain_answers_no_fetch_at_all() -> None:
    """The failure the option exists for, and it does not wear off.

    A fetcher that asked once, was refused once and then served an
    address on the next call would be the silent failure with an extra
    step, so the disagreement is remembered -- and remembered rather than
    re-asked, which is what the second call proves by adding no request.
    """
    transport = LineRecorded(TESTNET_GENESIS_HEADER)
    endpoint = ElectrumFetcher("mainnet", transport=transport, verify_network=True)
    for _ in range(2):
        with pytest.raises(BTClibValueError, match=TESTNET_GENESIS):
            endpoint.get_block_count()
    assert len(transport.requests) == 1


def test_get_tx_merkle_and_verify_tx_are_refused_on_another_chain_too() -> None:
    """`get_tx_merkle` asks first, as every question `Fetcher` declares does.

    The proof is the answer a caller is likeliest to trust, so a branch
    from a server on the wrong chain is the one worth never returning.
    """
    transport = LineRecorded(TESTNET_GENESIS_HEADER)
    endpoint = ElectrumFetcher("mainnet", transport=transport, verify_network=True)
    with pytest.raises(BTClibValueError, match=TESTNET_GENESIS):
        endpoint.get_tx_merkle(MERKLE_TX_ID, TIP_HEIGHT)
    with pytest.raises(BTClibValueError, match=TESTNET_GENESIS):
        endpoint.verify_tx(MERKLE_TX_ID, TIP_HEIGHT)


def test_a_server_that_could_not_be_asked_is_asked_again() -> None:
    """A server that did not answer said nothing about which chain it is on.

    The distinction the remembering rests on: a chain that disagrees is a
    fact about a configuration, where a request that did not answer is
    one to make again.
    """
    tip = {"height": TIP_HEIGHT, "hex": TIP_HEADER_RAW}
    transport = LineRecorded(
        RpcFetchError("connection refused"), MAINNET_GENESIS_HEADER, tip
    )
    endpoint = ElectrumFetcher("mainnet", transport=transport, verify_network=True)
    with pytest.raises(FetchError, match="connection refused"):
        endpoint.get_block_count()
    assert endpoint.get_block_count() == TIP_HEIGHT
    assert len(transport.requests) == 3


def test_verify_network_false_asks_the_server_nothing() -> None:
    """With the opt-out taken, the fetch is the only request made."""
    tip = {"height": TIP_HEIGHT, "hex": TIP_HEADER_RAW}
    transport = LineRecorded(tip)
    endpoint = ElectrumFetcher("mainnet", transport=transport, verify_network=False)
    assert endpoint.get_block_count() == TIP_HEIGHT
    assert transport.methods == ["blockchain.headers.subscribe"]
