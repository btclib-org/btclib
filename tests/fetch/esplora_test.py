# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for btclib.fetch.esplora, against recorded bodies.

`BLOCKSTREAM_INFO` appears here as a value, never as a host reached: the
transport is a recording in every test, so what is checked about the
constant is what it says, and nothing resolves it.
"""

from __future__ import annotations

import pytest

from btclib.exceptions import BTClibValueError, FetchError, HttpError
from btclib.fetch.esplora import BLOCKSTREAM_INFO, EsploraFetcher
from btclib.fetch.transport import SessionTransport
from btclib.tx import OutPoint
from tests.fetch import TIP_HEIGHT, TIP_ID, TX_ID, Recorded, recorded_body

BASE = "https://esplora.example/api"
# the coinbase of block 170: a transaction with the same provenance as
# the recorded one, and not the one asked for
OTHER_ID = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082"


def fetcher(
    *answers: tuple[int, bytes] | Exception, **kwargs: object
) -> EsploraFetcher:
    """Build an EsploraFetcher whose transport replays the answers."""
    return EsploraFetcher(
        BASE,
        transport=Recorded(*answers),
        **kwargs,  # type: ignore[arg-type]
    )


def test_the_reference_deployment_is_a_value_to_pass_not_a_default() -> None:
    """No endpoint is baked in: which host sees the queries is the caller's.

    `base_url` has no default, so `EsploraFetcher()` is a TypeError
    rather than a connection to somebody's server.
    """
    with pytest.raises(TypeError):
        EsploraFetcher()  # type: ignore[call-arg]

    assert set(BLOCKSTREAM_INFO) == {"mainnet", "testnet", "signet"}
    for network, url in BLOCKSTREAM_INFO.items():
        assert url.startswith("https://")
        assert url.endswith("/api")
        assert (network == "mainnet") != (network in url)


def test_a_session_transport_can_drive_the_fetcher() -> None:
    """`transport=` takes `SessionTransport` exactly as it takes `Recorded`.

    Construction opens no connection -- `SessionTransport`'s own docstring
    says so -- so this is the wiring and not a round trip: the object
    passed in is the one the fetcher keeps and would call.
    """
    session = SessionTransport()
    assert EsploraFetcher(BASE, transport=session).transport is session


def test_an_unknown_network_is_refused() -> None:
    """Refuse a network name that is none of the three known ones."""
    with pytest.raises(BTClibValueError, match="unknown network: liquid"):
        EsploraFetcher(BASE, network="liquid")


def test_a_trailing_slash_does_not_double_up() -> None:
    """Verify a base URL with a trailing slash builds a clean request."""
    transport = Recorded((200, recorded_body("esplora_blocks_tip_height.txt")))
    EsploraFetcher(BASE + "/", transport=transport).get_block_count()
    assert transport.request.full_url == f"{BASE}/blocks/tip/height"


def test_get_tx_asks_for_the_serialization_not_the_rendering() -> None:
    """`/hex`, which is what lets the id be recomputed from the answer."""
    transport = Recorded((200, recorded_body("esplora_tx_hex.txt")))
    tx = EsploraFetcher(BASE, transport=transport).get_tx(TX_ID)
    assert transport.request.full_url == f"{BASE}/tx/{TX_ID}/hex"
    assert transport.request.get_method() == "GET"
    assert tx.id.hex() == TX_ID
    assert [out.value for out in tx.vout] == [10_00000000, 40_00000000]


def test_get_tx_refuses_the_answer_to_another_question() -> None:
    """An explorer is a host that says it validated the chain.

    The id is the one claim it cannot make falsely: recomputing it from
    the bytes is the whole of what this backend verifies, and it is what
    the module docstring promises and does not promise.
    """
    with pytest.raises(FetchError, match="the answer is"):
        fetcher((200, recorded_body("esplora_tx_hex.txt"))).get_tx(OTHER_ID)


def test_get_tx_out_derives_the_output() -> None:
    """Verify get_tx_out reads the output off the fetched transaction."""
    out = fetcher((200, recorded_body("esplora_tx_hex.txt"))).get_tx_out(
        OutPoint(TX_ID, 0)
    )
    assert out.value == 10_00000000


def test_get_tx_labels_the_outputs_for_the_network_given() -> None:
    """Verify the outputs carry the network the fetcher was given."""
    tx = fetcher((200, recorded_body("esplora_tx_hex.txt")), network="signet").get_tx(
        TX_ID
    )
    assert [out.script_pub_key.network for out in tx.vout] == ["signet"] * 2


def test_the_tip_is_two_endpoints_and_not_one() -> None:
    """Height and hash are separate requests, so they are separate answers.

    One `ChainTip` built from both would read as an atomic fact and be a
    pair of round trips that a reorg can fall between.
    """
    height = Recorded((200, recorded_body("esplora_blocks_tip_height.txt")))
    assert EsploraFetcher(BASE, transport=height).get_block_count() == TIP_HEIGHT
    assert height.request.full_url == f"{BASE}/blocks/tip/height"

    tip = Recorded((200, recorded_body("esplora_blocks_tip_hash.txt")))
    assert EsploraFetcher(BASE, transport=tip).get_best_block_id().hex() == TIP_ID
    assert tip.request.full_url == f"{BASE}/blocks/tip/hash"


def test_a_404_carries_what_the_explorer_said() -> None:
    """Esplora answers an unknown txid with a status and a sentence."""
    with pytest.raises(FetchError, match="HTTP 404 .*: Transaction not found"):
        fetcher((404, b"Transaction not found")).get_tx(TX_ID)


@pytest.mark.parametrize("status", [100, 404, 429, 503])
def test_the_status_of_a_failure_is_a_field(status: int) -> None:
    """Which is what tells a rate limit from a missing transaction.

    Every answer here is a GET of an immutable value, so a 429 or a 503
    from a public deployment is worth another attempt and a 404 is not.
    btclib retries neither -- an explorer's rate limit is the caller's
    budget to spend -- so the status has to reach them as a value.

    100 is below 200, not above it: `!= 200` weakened to `> 200` would
    still refuse every status above, and only one below tells them apart.
    """
    with pytest.raises(HttpError) as exc:
        fetcher((status, b"no")).get_tx(TX_ID)
    assert exc.value.status == status


def test_a_body_that_is_not_utf_8_is_still_reported() -> None:
    """What is in the way when it fails is not always something that speaks.

    Decoding with `replace` is why: a UnicodeDecodeError here would
    replace the diagnosis with a second failure, of the client.
    """
    with pytest.raises(FetchError, match="HTTP 502"):
        fetcher((502, b"\xff\xfe not text")).get_tx(TX_ID)


@pytest.mark.parametrize("body", [b"not a number", b"", b"1e6"])
def test_a_height_that_is_not_one(body: bytes) -> None:
    """Refuse a tip-height body that is not a decimal integer."""
    with pytest.raises(FetchError, match="blocks/tip/height:"):
        fetcher((200, body)).get_block_count()


@pytest.mark.parametrize("body", [b"not hex", b"", b"00" * 31])
def test_a_tip_hash_that_is_not_one(body: bytes) -> None:
    """Refuse a tip-hash body that is not 32 bytes of hex."""
    with pytest.raises(FetchError, match="blocks/tip/hash:"):
        fetcher((200, body)).get_best_block_id()


def test_whitespace_around_an_answer_is_not_part_of_it() -> None:
    """A deployment behind a proxy that adds a newline is still readable."""
    assert fetcher((200, b"  481824\n")).get_block_count() == TIP_HEIGHT


def test_each_answer_is_bounded_by_what_it_is() -> None:
    """A height is not megabytes, and the limit says so per endpoint.

    One limit for all three would have to be the widest of them -- a raw
    transaction in hex -- so a host answering `blocks/tip/height` with a
    transaction's worth of digits would be held in memory and only then
    refused by `int`. The narrow answers carry narrow limits, with room
    for the newline a proxy adds and for nothing else.
    """
    height = fetcher((200, b"9" * 65))
    with pytest.raises(
        FetchError, match="response of 65 bytes, more than the max_body_size of 64"
    ):
        height.get_block_count()

    tip = fetcher((200, b"a" * 129))
    with pytest.raises(
        FetchError, match="response of 129 bytes, more than the max_body_size of 128"
    ):
        tip.get_best_block_id()

    # and the recorded answers are inside their limits, which is the other
    # half of the claim
    assert fetcher((200, b"481824\n")).get_block_count() == TIP_HEIGHT
    assert fetcher((200, TIP_ID.encode() + b"\n")).get_best_block_id().hex() == TIP_ID


def test_the_body_of_a_failure_is_not_held_to_the_answer_limit() -> None:
    """A 404 page is longer than a height, and is still the diagnosis.

    The bound on an error body is `MAX_ERROR_BODY_SIZE` and truncation,
    not the caller's limit for the answer that did not arrive: an explorer
    saying "Block not found" in a paragraph of html is worth reading.
    """
    page = b"<html><body>Block not found, and here is why: " + b"x" * 200 + b"</body>"
    with pytest.raises(FetchError, match="HTTP 404"):
        fetcher((404, page)).get_block_count()
