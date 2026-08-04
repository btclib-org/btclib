#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for btclib.fetch.esplora, against recorded bodies.

`BLOCKSTREAM_INFO` appears here as a value, never as a host reached: the
transport is a recording in every test, so what is checked about the
constant is what it says, and nothing resolves it.
"""

from __future__ import annotations

import pytest

from btclib.exceptions import BTClibValueError, FetchError
from btclib.fetch.esplora import BLOCKSTREAM_INFO, EsploraFetcher
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
