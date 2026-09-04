# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib.electrum`, the Electrum protocol codec.

No transport anywhere here -- there is none in this module to test, by
design -- so every case is a line built or read by hand. The transaction
and header vectors are `tests/fetch/__init__.py`'s TX_ID and
TIP_HEADER_RAW, block 481824; the merkle branch is a second vector from
the same block, `tests/block/_data/block_481824_complete.bin`'s
transaction at index 1, computed with the sibling-walk
`tests/block/merkle_proof_test.py` already uses and checked here against
`btclib.block.merkle_proof.assert_as_valid` directly rather than
recomputed at collection time -- `tests/fetch/electrum_test.py` shares
the same four literals so that a fetcher test and a codec test agree on
what a real server would have answered without importing one another.
"""

from __future__ import annotations

import json

import pytest

from btclib.block.block_header import BlockHeader
from btclib.electrum import (
    HeaderTip,
    MerkleProof,
    assert_merkle_proof,
    block_header_request,
    block_header_response,
    decode_response,
    encode_request,
    headers_subscribe_request,
    headers_subscribe_response,
    transaction_get_merkle_request,
    transaction_get_merkle_response,
    transaction_get_request,
    transaction_get_response,
    verify_merkle_proof,
)
from btclib.exceptions import BTClibTypeError, BTClibValueError, RpcError
from tests.fetch import TIP_HEADER_RAW, TIP_HEIGHT, TIP_ID, TX_ID

# block 481824's transaction at index 1: 225 bytes, no witness, so its
# hash and its id are the same value. The branch is the eleven siblings
# met climbing to the header's merkle_root, deepest first -- computed
# once from tests/block/_data/block_481824_complete.bin with the same
# construction tests/block/merkle_proof_test.py's `_branch` performs, and
# checked below against the real header rather than trusted on arrival
MERKLE_TX_ID = "c2bfb6f1bf791308c6b8f73f5d4181be9aa490da6e73c188f9ebd0723e8531b6"
MERKLE_TX_RAW = bytes.fromhex(
    "0200000001d40c5407d03e50fdfbdaa1ec97b3ce0cc29d72e7ca360c18221cf903d8b5f51b"
    "010000006a47304402203dad2ca83215b123c8c89bfd161b519033eb1c049935e06358"
    "9f265e05640371022064e64c030368b78ac842d4dd6a2b9959afc2e46ea78f011dcb9d"
    "b3bbdae23651012103d20c7990a9cccd9d1346d2d1bfa7270030209e73810edd9a33fe"
    "d28ad1409b50feffffff02400d0300000000001976a9145f8c60ce58c1791c2df2040e"
    "f8a086e948f2f22588ac0c7cb132000000001976a914f3f79e50b1556826355864c4da"
    "ca603e52e50b4888ac1f5a0700"
)
MERKLE_TX_POS = 1
MERKLE_BRANCH = (
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
)


def reply(**members: object) -> bytes:
    """Return a JSON-RPC response line carrying these members."""
    return json.dumps(members).encode() + b"\n"


def test_the_merkle_vector_proves_against_the_real_header() -> None:
    """The literals above are consistent with each other, not asserted blind.

    `assert_as_valid` is `btclib.block.merkle_proof`'s own, not this
    module's -- this is the positive control the branch below is
    measured against, so a typo in either literal fails here first.
    """
    header = BlockHeader.parse(TIP_HEADER_RAW)
    proof = MerkleProof(
        TIP_HEIGHT, tuple(bytes.fromhex(h) for h in MERKLE_BRANCH), MERKLE_TX_POS
    )
    assert_merkle_proof(MERKLE_TX_ID, proof, header)


def test_encode_request_is_one_newline_terminated_json_object() -> None:
    """The wire shape: an id, a method and a params list, one line."""
    line = encode_request(7, "server.version", ["btclib", "1.4"])
    assert line.endswith(b"\n")
    assert json.loads(line) == {
        "id": 7,
        "method": "server.version",
        "params": ["btclib", "1.4"],
    }


def test_decode_response_returns_the_result() -> None:
    """A well-formed reply answers with its own `result`."""
    assert decode_response(reply(id=3, result="ok"), 3) == "ok"


def test_decode_response_refuses_a_line_that_is_not_json() -> None:
    """A line a server never sends, refused rather than misread."""
    with pytest.raises(BTClibValueError, match="not a JSON-RPC line"):
        decode_response(b"not json at all\n", 1)


def test_decode_response_refuses_a_json_value_that_is_not_an_object() -> None:
    """Valid JSON, the wrong shape: a JSON-RPC reply is an object."""
    with pytest.raises(BTClibTypeError, match="not a JSON-RPC response object"):
        decode_response(b"[1, 2, 3]\n", 1)


def test_decode_response_refuses_a_mismatched_id() -> None:
    """A reply answering a different request is refused, not returned."""
    with pytest.raises(BTClibValueError, match="does not answer request 1"):
        decode_response(reply(id=2, result="ok"), 1)


def test_decode_response_refuses_a_reply_with_neither_result_nor_error() -> None:
    """A JSON-RPC object with neither member is not an answer to anything."""
    with pytest.raises(BTClibValueError, match="neither a result nor an error"):
        decode_response(reply(id=1), 1)


def test_decode_response_raises_rpc_error_for_an_error_object() -> None:
    """A JSON-RPC 2.0 error object: `code` and `message`, both kept."""
    line = reply(id=1, error={"code": -32601, "message": "unknown method"})
    with pytest.raises(RpcError, match="unknown method") as exc_info:
        decode_response(line, 1)
    assert exc_info.value.code == -32601


def test_decode_response_raises_rpc_error_for_a_bare_error() -> None:
    """Protocol 1.0's shape: `error` is a string, not an object."""
    line = reply(id=1, error="no such transaction")
    with pytest.raises(RpcError, match="no such transaction") as exc_info:
        decode_response(line, 1)
    assert exc_info.value.code == 0


def test_transaction_get_round_trips_the_raw_transaction() -> None:
    """The request names the id; the response decodes the hex it answers."""
    tx_hex = "aabbcc"
    request = transaction_get_request(1, TX_ID)
    assert json.loads(request)["params"] == [TX_ID]

    raw = transaction_get_response(reply(id=1, result=tx_hex), 1)
    assert raw == bytes.fromhex(tx_hex)


def test_transaction_get_response_refuses_a_non_string_result() -> None:
    """The wire answer is hex text; anything else is not a transaction."""
    with pytest.raises(BTClibTypeError, match="not a hex string"):
        transaction_get_response(reply(id=1, result=1234), 1)


def test_headers_subscribe_round_trips_height_and_header() -> None:
    """The request needs no argument; the response carries height and header."""
    request = headers_subscribe_request(9)
    assert json.loads(request)["method"] == "blockchain.headers.subscribe"

    line = reply(id=9, result={"height": TIP_HEIGHT, "hex": TIP_HEADER_RAW})
    tip = headers_subscribe_response(line, 9)
    assert tip == HeaderTip(TIP_HEIGHT, bytes.fromhex(TIP_HEADER_RAW))
    assert BlockHeader.parse(tip.header).hash.hex() == TIP_ID


@pytest.mark.parametrize(
    "members",
    [
        {"height": "not an int", "hex": TIP_HEADER_RAW},
        {"height": TIP_HEIGHT, "hex": 12345},
        {"height": True, "hex": TIP_HEADER_RAW},
    ],
)
def test_headers_subscribe_response_refuses_a_malformed_object(
    members: dict[str, object],
) -> None:
    """A missing or wrongly typed member is refused, `bool` height included."""
    with pytest.raises(BTClibTypeError):
        headers_subscribe_response(reply(id=1, result=members), 1)


def test_block_header_round_trips_the_raw_header() -> None:
    """No `cp_height` sent; the answer is the raw header hex alone."""
    request = block_header_request(4, TIP_HEIGHT)
    assert json.loads(request)["params"] == [TIP_HEIGHT]

    raw = block_header_response(reply(id=4, result=TIP_HEADER_RAW), 4)
    assert raw == bytes.fromhex(TIP_HEADER_RAW)
    assert BlockHeader.parse(raw).hash.hex() == TIP_ID


def test_block_header_response_refuses_a_non_string_result() -> None:
    """The wire answer, with no `cp_height`, is hex text and nothing else."""
    with pytest.raises(BTClibTypeError, match="not a hex string"):
        block_header_response(reply(id=4, result=None), 4)


def test_transaction_get_merkle_round_trips_the_proof() -> None:
    """The request names the height too; the response is branch, pos, height."""
    request = transaction_get_merkle_request(2, MERKLE_TX_ID, TIP_HEIGHT)
    assert json.loads(request)["params"] == [MERKLE_TX_ID, TIP_HEIGHT]

    line = reply(
        id=2,
        result={
            "block_height": TIP_HEIGHT,
            "merkle": list(MERKLE_BRANCH),
            "pos": MERKLE_TX_POS,
        },
    )
    proof = transaction_get_merkle_response(line, 2)
    assert proof.block_height == TIP_HEIGHT
    assert proof.pos == MERKLE_TX_POS
    assert proof.branch == tuple(bytes.fromhex(h) for h in MERKLE_BRANCH)


def test_transaction_get_merkle_response_refuses_a_non_object() -> None:
    """A `get_merkle` reply has three members, not a bare list or scalar."""
    with pytest.raises(BTClibTypeError, match="not an object"):
        transaction_get_merkle_response(reply(id=1, result=[1, 2, 3]), 1)


@pytest.mark.parametrize(
    "members",
    [
        {"merkle": list(MERKLE_BRANCH), "pos": MERKLE_TX_POS},  # no block_height
        {"block_height": "not an int", "merkle": list(MERKLE_BRANCH), "pos": 0},
        {"block_height": TIP_HEIGHT, "pos": MERKLE_TX_POS},  # no merkle
        {"block_height": TIP_HEIGHT, "merkle": "not a list", "pos": 0},
        {"block_height": TIP_HEIGHT, "merkle": list(MERKLE_BRANCH)},  # no pos
        {"block_height": TIP_HEIGHT, "merkle": list(MERKLE_BRANCH), "pos": "0"},
    ],
)
def test_transaction_get_merkle_response_refuses_a_malformed_object(
    members: dict[str, object],
) -> None:
    """A missing or wrongly typed member is refused before a branch is built."""
    with pytest.raises(BTClibTypeError):
        transaction_get_merkle_response(reply(id=1, result=members), 1)


def test_the_accepted_proof_verifies_against_the_real_header() -> None:
    """`verify_merkle_proof`, not `assert_as_valid`, over the real branch."""
    header = BlockHeader.parse(TIP_HEADER_RAW)
    proof = MerkleProof(
        TIP_HEIGHT, tuple(bytes.fromhex(h) for h in MERKLE_BRANCH), MERKLE_TX_POS
    )
    assert verify_merkle_proof(MERKLE_TX_ID, proof, header)


def test_a_wrong_branch_is_refused() -> None:
    """A substituted sibling fails the check, `verify` and `assert` alike."""
    header = BlockHeader.parse(TIP_HEADER_RAW)
    wrong_branch = (b"\x00" * 32, *(bytes.fromhex(h) for h in MERKLE_BRANCH[1:]))
    proof = MerkleProof(TIP_HEIGHT, wrong_branch, MERKLE_TX_POS)
    assert not verify_merkle_proof(MERKLE_TX_ID, proof, header)
    with pytest.raises(BTClibValueError, match="invalid merkle branch"):
        assert_merkle_proof(MERKLE_TX_ID, proof, header)


def test_a_wrong_position_is_refused() -> None:
    """The real branch at the wrong position does not recompute the root."""
    header = BlockHeader.parse(TIP_HEADER_RAW)
    proof = MerkleProof(
        TIP_HEIGHT,
        tuple(bytes.fromhex(h) for h in MERKLE_BRANCH),
        MERKLE_TX_POS ^ 1,
    )
    assert not verify_merkle_proof(MERKLE_TX_ID, proof, header)


def test_a_truncated_transaction_decodes_to_short_octets() -> None:
    """The codec decodes the hex; a whole transaction is not its question.

    `Tx.parse`, reached through `btclib.fetch.fetcher.tx_from_raw`, is
    what refuses a serialization that stops early -- exercised in
    `tests/fetch/electrum_test.py`, over the fetcher that calls it.
    """
    raw = transaction_get_response(reply(id=1, result=MERKLE_TX_RAW.hex()[:20]), 1)
    assert raw == MERKLE_TX_RAW[:10]
