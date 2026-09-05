# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `BitcoinCoreRestFetcher`, against recorded replies.

`-rest` answers with no envelope, unlike the JSON-RPC server
`tests/fetch/bitcoin_core_test.py` exercises, so a plain `Recorded`
drives every fetcher here -- there is no request id to echo back, which
is the whole reason that module's `Echoing` exists and this one has no
equivalent of it.

Every client here is built with a transport, so no test reaches a node.
The recorded bodies under `_data` are Core's own shapes, byte for byte;
`tests/_data/README.md` says where each came from and how it relates to
the JSON-RPC and Esplora fixtures beside it.
"""

from __future__ import annotations

import json

import pytest
from bitcoin_core_rpc import (
    DEFAULT_SIGNET_CHALLENGE,
    BitcoinCoreRestClient,
    SessionTransport,
)

from btclib.exceptions import BTClibTypeError, BTClibValueError, FetchError, HttpError
from btclib.fetch.bitcoin_core_rest import BitcoinCoreRestFetcher
from btclib.fetch.broadcaster import Broadcaster
from btclib.tx import OutPoint
from tests.fetch import TIP_HEIGHT, TIP_ID, TX_ID, Recorded, recorded_body

# a custom signet differs from the default one in its challenge alone,
# which is what the name `signet` cannot separate; the default one is the
# client's own constant rather than a second copy of it here
CUSTOM_CHALLENGE = "0014" + "ab" * 20
OTHER_CHALLENGE = "0014" + "cd" * 20

# the endpoint the tests build against, written once
URL = "http://127.0.0.1:8332"

# the coinbase of block 170: a transaction with the same provenance as
# the recorded one, and not the one asked for
OTHER_ID = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082"


def client(
    *answers: tuple[int, bytes] | Exception, **kwargs: object
) -> BitcoinCoreRestClient:
    """Return a BitcoinCoreRestClient over a recorded transport."""
    return BitcoinCoreRestClient(
        URL,
        transport=Recorded(*answers),
        **kwargs,  # type: ignore[arg-type]
    )


def fetcher(
    *answers: tuple[int, bytes] | Exception, **kwargs: object
) -> BitcoinCoreRestFetcher:
    """Return a BitcoinCoreRestFetcher over a recorded client, chain unasked.

    `verify_network=False` here, as `bitcoin_core_test.py`'s helper has
    it: the recorded answer is the fetch under test, and a chain check in
    front of it would consume that answer as chaininfo. The tests of the
    check itself build the fetcher by hand.
    """
    network = kwargs.pop("network", "mainnet")
    assert isinstance(network, str)
    return BitcoinCoreRestFetcher(
        client(*answers, **kwargs), network, verify_network=False
    )


def recording(endpoint: BitcoinCoreRestClient) -> Recorded:
    """Return the recording a client was built with, as one."""
    transport = endpoint.transport
    assert isinstance(transport, Recorded)
    return transport


def urls(endpoint: BitcoinCoreRestClient) -> list[str]:
    """Return the full url of every request a client made, in order."""
    return [request.full_url for request in recording(endpoint).requests]


def chaininfo(**members: object) -> bytes:
    """Return a `-rest` chaininfo body carrying these members, no envelope."""
    return json.dumps(members).encode()


def test_a_session_transport_can_drive_the_fetcher() -> None:
    """`BitcoinCoreRestFetcher` takes a client, so its transport is one too.

    Nothing here is the fetcher's to wire: `SessionTransport`'s
    constructor opens no connection, so building one and handing it to
    the client this fetcher is built over is the whole of driving one
    fetcher through it.
    """
    session = SessionTransport()
    endpoint = BitcoinCoreRestClient(URL, transport=session)
    assert BitcoinCoreRestFetcher(endpoint).client.transport is session


def test_an_unknown_network_is_refused() -> None:
    """Refuse a network name `NETWORKS` does not carry, before any request."""
    with pytest.raises(BTClibValueError, match="unknown network: 'nowhere'"):
        BitcoinCoreRestFetcher(client(), network="nowhere")


def test_get_tx_parses_the_serialization_the_node_sent() -> None:
    """`.bin` returns the serialization, so the id is recomputed from it."""
    tx = fetcher((200, recorded_body("rest_tx.bin"))).get_tx(TX_ID)
    assert tx.id.hex() == TX_ID
    assert len(tx.vin) == 1
    assert [out.value for out in tx.vout] == [10_00000000, 40_00000000]


def test_get_tx_asks_for_the_display_order_id() -> None:
    """Verify get_tx builds `/tx/<TX-HASH>.bin` with the hex it was given."""
    endpoint = client((200, recorded_body("rest_tx.bin")))
    BitcoinCoreRestFetcher(endpoint, verify_network=False).get_tx(bytes.fromhex(TX_ID))
    assert urls(endpoint) == [f"{URL}/rest/tx/{TX_ID}.bin"]


def test_get_tx_refuses_the_answer_to_another_question() -> None:
    """The id is recomputed from the serialization and checked against it."""
    with pytest.raises(FetchError, match="the answer is"):
        fetcher((200, recorded_body("rest_tx.bin"))).get_tx(OTHER_ID)


def test_get_tx_out_derives_the_output() -> None:
    """`get_tx_out` is not overridden: it reads off the fetched transaction."""
    out = fetcher((200, recorded_body("rest_tx.bin"))).get_tx_out(OutPoint(TX_ID, 0))
    assert out.value == 10_00000000


def test_get_tx_labels_the_outputs_for_the_fetchers_network() -> None:
    """The network is the fetcher's own label, with the chain check off."""
    tx = fetcher((200, recorded_body("rest_tx.bin")), network="testnet").get_tx(TX_ID)
    assert [out.script_pub_key.network for out in tx.vout] == ["testnet"] * 2


def test_a_truncated_transaction_is_refused() -> None:
    """A body cut off in transit is caught the same as a substituted one."""
    truncated = recorded_body("rest_tx.bin")[:-1]
    with pytest.raises(FetchError, match=f"transaction {TX_ID}:"):
        fetcher((200, truncated)).get_tx(TX_ID)


def test_get_block_count_and_get_best_block_id() -> None:
    """Both answers are members of the same `/chaininfo.json` reply."""
    tip_height = fetcher((200, recorded_body("rest_chaininfo.json"))).get_block_count()
    assert tip_height == TIP_HEIGHT
    tip_id = fetcher((200, recorded_body("rest_chaininfo.json"))).get_best_block_id()
    assert tip_id.hex() == TIP_ID


def test_get_block_count_asks_chaininfo() -> None:
    """Both `get_block_count` and `get_best_block_id` ask `/chaininfo.json`."""
    endpoint = client((200, recorded_body("rest_chaininfo.json")))
    BitcoinCoreRestFetcher(endpoint, verify_network=False).get_block_count()
    assert urls(endpoint) == [f"{URL}/rest/chaininfo.json"]

    endpoint = client((200, recorded_body("rest_chaininfo.json")))
    BitcoinCoreRestFetcher(endpoint, verify_network=False).get_best_block_id()
    assert urls(endpoint) == [f"{URL}/rest/chaininfo.json"]


@pytest.mark.parametrize(
    "body",
    [
        chaininfo(bestblockhash=TIP_ID),  # no "blocks" member at all
        chaininfo(blocks="not a number", bestblockhash=TIP_ID),
        chaininfo(blocks=None, bestblockhash=TIP_ID),
        chaininfo(blocks=[1], bestblockhash=TIP_ID),
        b"3",  # a reply that is not an object at all
    ],
)
def test_a_block_count_that_is_not_one(body: bytes) -> None:
    """Refuse a chaininfo reply whose 'blocks' is missing or not an int."""
    with pytest.raises(FetchError, match="chaininfo:"):
        fetcher((200, body)).get_block_count()


@pytest.mark.parametrize(
    "body",
    [
        chaininfo(blocks=TIP_HEIGHT),  # no "bestblockhash" member at all
        chaininfo(blocks=TIP_HEIGHT, bestblockhash="not hex"),
        chaininfo(blocks=TIP_HEIGHT, bestblockhash="00" * 31),
        chaininfo(blocks=TIP_HEIGHT, bestblockhash=170),
        b"[]",  # a reply that is not an object at all
    ],
)
def test_a_tip_hash_that_is_not_one(body: bytes) -> None:
    """Refuse a chaininfo reply whose 'bestblockhash' is missing or not one."""
    with pytest.raises(FetchError, match="chaininfo:"):
        fetcher((200, body)).get_best_block_id()


def test_get_block_header_asks_blockhashbyheight_then_headers() -> None:
    """Two requests: the height maps to a hash before a header answers.

    The second url carries `TIP_ID`'s display-order hex, which is what
    says the reversal of the first answer's internal byte order
    happened -- `rest_blockhashbyheight.bin` is `TIP_ID` reversed, so a
    fetcher that forgot to reverse it would ask for a different hash
    entirely. `?count=1` and not `/headers/1/<hash>`, the deprecated
    spelling `doc/REST-interface.md` still answers but a fetcher written
    today has no reason to send.
    """
    endpoint = client(
        (200, recorded_body("rest_blockhashbyheight.bin")),
        (200, recorded_body("rest_headers.bin")),
    )
    header = BitcoinCoreRestFetcher(endpoint, verify_network=False).get_block_header(
        TIP_HEIGHT
    )
    assert header.hash.hex() == TIP_ID
    assert urls(endpoint) == [
        f"{URL}/rest/blockhashbyheight/{TIP_HEIGHT}.bin",
        f"{URL}/rest/headers/{TIP_ID}.bin?count=1",
    ]


def test_get_block_header_refuses_a_height_with_no_block() -> None:
    """A height past the tip is a 404, naming the height and not a hash."""
    with pytest.raises(HttpError) as exc:
        fetcher((404, b"Block height out of range")).get_block_header(999_999_999)
    assert exc.value.status == 404


@pytest.mark.parametrize("height", [-1, -481824])
def test_get_block_header_refuses_a_negative_height(height: int) -> None:
    """Refused before any request, both calls mapping a height to a block."""
    endpoint = client()
    with pytest.raises(BTClibValueError, match="invalid height"):
        BitcoinCoreRestFetcher(endpoint, verify_network=False).get_block_header(height)
    assert urls(endpoint) == []


@pytest.mark.parametrize("height", ["481824", 481824.5, None])
def test_get_block_header_refuses_a_non_integer_height(height: object) -> None:
    """Refused before any request, the same as a negative one."""
    endpoint = client()
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        BitcoinCoreRestFetcher(endpoint, verify_network=False).get_block_header(
            height  # type: ignore[arg-type]
        )
    assert urls(endpoint) == []


@pytest.mark.parametrize(
    "body",
    [b"not thirty-two bytes", b"", b"\x00" * 31],
)
def test_a_blockhashbyheight_answer_that_is_not_a_hash(body: bytes) -> None:
    """Refuse a `.bin` reply that is not thirty-two bytes."""
    with pytest.raises(FetchError, match="blockhashbyheight:"):
        fetcher((200, body)).get_block_header(TIP_HEIGHT)


def test_a_404_is_the_status_and_not_a_parsed_diagnosis() -> None:
    """`-rest` answers a missing transaction with a 404 and prose, not json."""
    with pytest.raises(HttpError) as exc:
        fetcher((404, b"Transaction not found")).get_tx(TX_ID)
    assert exc.value.status == 404


@pytest.mark.parametrize("status", [404, 500, 503])
def test_the_status_of_a_failure_is_a_field(status: int) -> None:
    """The field a caller reads to tell a missing answer from a busy node."""
    with pytest.raises(HttpError) as exc:
        fetcher((status, b"")).get_block_count()
    assert exc.value.status == status


def test_the_first_fetch_asks_the_node_which_chain_it_serves() -> None:
    """Which is what `verify_network` buys, and it is on by default."""
    endpoint = client(
        (200, recorded_body("rest_chaininfo.json")),
        (200, recorded_body("rest_tx.bin")),
    )
    assert BitcoinCoreRestFetcher(endpoint).get_tx(TX_ID).id.hex() == TX_ID
    assert urls(endpoint) == [
        f"{URL}/rest/chaininfo.json",
        f"{URL}/rest/tx/{TX_ID}.bin",
    ]


def test_the_chain_is_asked_for_once_and_not_per_fetch() -> None:
    """A node does not change chain under a client pointing at it.

    `get_block_count` reads `/chaininfo.json` for its own answer too, so
    the recorded document serves both the check and the fetch; what the
    url list proves is that the check is not repeated by the third call.
    """
    endpoint = client((200, recorded_body("rest_chaininfo.json")))
    rest = BitcoinCoreRestFetcher(endpoint)
    assert rest.get_block_count() == TIP_HEIGHT
    assert rest.get_best_block_id().hex() == TIP_ID
    assert urls(endpoint) == [f"{URL}/rest/chaininfo.json"] * 3


def test_a_node_on_another_chain_answers_no_fetch_at_all() -> None:
    """The failure the option exists for, remembered rather than re-asked."""
    endpoint = client((200, chaininfo(chain="test", blocks=TIP_HEIGHT)))
    rest = BitcoinCoreRestFetcher(endpoint, "mainnet")
    for _ in range(2):
        with pytest.raises(BTClibValueError, match="reports chain 'test'"):
            rest.get_tx(TX_ID)
    assert urls(endpoint) == [f"{URL}/rest/chaininfo.json"]


def test_a_node_that_could_not_be_asked_is_asked_again() -> None:
    """A node that did not answer said nothing about which chain it is on."""
    endpoint = client(
        (503, b""),
        (200, recorded_body("rest_chaininfo.json")),
        (200, recorded_body("rest_tx.bin")),
    )
    rest = BitcoinCoreRestFetcher(endpoint)
    with pytest.raises(HttpError):
        rest.get_tx(TX_ID)
    assert rest.get_tx(TX_ID).id.hex() == TX_ID
    assert urls(endpoint) == [
        f"{URL}/rest/chaininfo.json",
        f"{URL}/rest/chaininfo.json",
        f"{URL}/rest/tx/{TX_ID}.bin",
    ]


@pytest.mark.parametrize(
    "body",
    [
        chaininfo(blocks=TIP_HEIGHT),  # no "chain" member at all
        chaininfo(chain=None, blocks=TIP_HEIGHT),
        chaininfo(chain=["main"], blocks=TIP_HEIGHT),
        b"[]",
    ],
)
def test_assert_network_refuses_a_malformed_reply(body: bytes) -> None:
    """A chaininfo with no string `chain` is no answer, not a disagreement."""
    with pytest.raises(FetchError, match="chaininfo:"):
        BitcoinCoreRestFetcher(client((200, body))).assert_network()


def test_verify_network_false_asks_the_node_nothing() -> None:
    """The opt-out is one request, `BitcoinCoreFetcher`'s same switch."""
    endpoint = client((200, recorded_body("rest_tx.bin")))
    rest = BitcoinCoreRestFetcher(endpoint, verify_network=False)
    assert rest.get_tx(TX_ID).id.hex() == TX_ID
    assert urls(endpoint) == [f"{URL}/rest/tx/{TX_ID}.bin"]


def test_get_block_header_verifies_the_chain_once_like_the_others() -> None:
    """`get_block_header` asks first too, and before the height is mapped."""
    endpoint = client(
        (200, recorded_body("rest_chaininfo.json")),
        (200, recorded_body("rest_blockhashbyheight.bin")),
        (200, recorded_body("rest_headers.bin")),
    )
    header = BitcoinCoreRestFetcher(endpoint).get_block_header(TIP_HEIGHT)
    assert header.hash.hex() == TIP_ID
    assert urls(endpoint)[0] == f"{URL}/rest/chaininfo.json"


def test_assert_network_tells_two_signets_apart() -> None:
    """`signet` is the name of every signet, so the challenge is the identity.

    `/chaininfo.json` carries `signet_challenge` because `rest_chaininfo`
    writes out `getblockchaininfo`'s object whole, so the check that
    separates two signets is available over `-rest` exactly as it is over
    the JSON-RPC server.
    """
    answer = chaininfo(chain="signet", signet_challenge=CUSTOM_CHALLENGE)
    with pytest.raises(BTClibValueError, match="signet this fetcher is not"):
        BitcoinCoreRestFetcher(client((200, answer)), "signet").assert_network()

    default = chaininfo(chain="signet", signet_challenge=DEFAULT_SIGNET_CHALLENGE)
    BitcoinCoreRestFetcher(client((200, default)), "signet").assert_network()


def test_assert_network_checks_the_signet_the_fetcher_was_given() -> None:
    """A signet of the caller's own, which is what `signet_challenge` is for."""
    answer = chaininfo(chain="signet", signet_challenge=CUSTOM_CHALLENGE)
    BitcoinCoreRestFetcher(
        client((200, answer)), "signet", signet_challenge=CUSTOM_CHALLENGE
    ).assert_network()

    other = chaininfo(chain="signet", signet_challenge=OTHER_CHALLENGE)
    with pytest.raises(BTClibValueError, match="signet this fetcher is not"):
        BitcoinCoreRestFetcher(
            client((200, other)), "signet", signet_challenge=CUSTOM_CHALLENGE
        ).assert_network()


@pytest.mark.parametrize(
    "body",
    [
        chaininfo(chain="signet"),  # no member at all: a node too old to report it
        chaininfo(chain="signet", signet_challenge=None),
        chaininfo(chain="signet", signet_challenge=["00"]),
        chaininfo(chain="signet", signet_challenge="not hex"),
    ],
)
def test_a_signet_challenge_that_cannot_be_read_is_no_answer(body: bytes) -> None:
    """A challenge this cannot derive a magic from is a reply it cannot read.

    Not a pass and not a disagreement: a node too old to report the
    member, and one reporting something that is no script, are both
    nodes this cannot answer for.
    """
    with pytest.raises(FetchError, match="chaininfo:"):
        BitcoinCoreRestFetcher(client((200, body)), "signet").assert_network()


def test_a_challenge_is_refused_where_it_would_check_nothing() -> None:
    """Refused at construction, where the mistake was written."""
    with pytest.raises(BTClibValueError, match="challenge for mainnet"):
        BitcoinCoreRestFetcher(client(), signet_challenge=CUSTOM_CHALLENGE)
    with pytest.raises(BTClibValueError, match="checks nothing with it off"):
        BitcoinCoreRestFetcher(
            client(), "signet", verify_network=False, signet_challenge=CUSTOM_CHALLENGE
        )


@pytest.mark.parametrize("network", ["testnet", "testnet4"])
def test_a_challenge_is_refused_for_a_testnet_too(network: str) -> None:
    """The refusal is inequality with signet, not an ordering against it.

    `main` and `regtest` sort before `signet`, so a guard written as `<`
    refuses them and would accept the testnets, which sort after --
    a challenge that could never be checked. The mainnet case above
    passes under that weakening and these two do not.
    """
    with pytest.raises(BTClibValueError, match=f"challenge for {network}"):
        BitcoinCoreRestFetcher(client(), network, signet_challenge=CUSTOM_CHALLENGE)


def test_the_body_bound_admits_a_maximal_signet_challenge() -> None:
    """A challenge is a script, and the bound is what a maximal one needs.

    A script above `MAX_SCRIPT_SIZE` validates no block, so twice that in
    hex is the largest challenge a running signet can have; a bound the
    default signet fits and a custom one does not would fail
    `verify_network` on exactly the deployment a challenge exists to
    check.
    """
    maximal = "00" * 10000
    answer = chaininfo(chain="signet", signet_challenge=maximal)
    BitcoinCoreRestFetcher(
        client((200, answer)), "signet", signet_challenge=maximal
    ).assert_network()


def test_a_challenge_that_is_no_script_fails_at_the_constructor() -> None:
    """Derived and thrown away there, so it fails where it was written."""
    with pytest.raises((BTClibValueError, FetchError)):
        BitcoinCoreRestFetcher(client(), "signet", signet_challenge="not hex")


def test_bitcoin_core_rest_fetcher_does_not_satisfy_broadcaster() -> None:
    """A mypy fact and not a runtime one: `-rest` has no write method.

    `Broadcaster` is not `runtime_checkable`, so an `isinstance` check
    would either raise or, marked checkable, pass on the method name
    `broadcast` alone without asking about the contract behind it --
    neither is the question. What actually says this class is not one is
    the assignment below failing under `strict = true`'s
    `warn_unused_ignores`: the `# type: ignore[assignment]` is only valid
    while `BitcoinCoreRestFetcher` really has no `broadcast`, and mypy
    fails the line the day that stops being true.
    """
    rest = BitcoinCoreRestFetcher(client(), verify_network=False)
    _not_a_broadcaster: Broadcaster = rest  # type: ignore[assignment]
