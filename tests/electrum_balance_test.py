# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Single and batched balances over Electrum's transport-free codec.

The positive balance is the example in ElectrumX's protocol-methods.rst,
under blockchain.scripthash.get_balance. The negative delta case pins a
mempool spend: treating it as an unsigned amount loses that spend.
"""

from __future__ import annotations

import json

import pytest

from btclib import electrum
from btclib.exceptions import BTClibTypeError, BTClibValueError, RpcError
from tests.secret_free import assert_secret_free

# ElectrumX protocol-basics.rst's P2PKH genesis-address script hash, already
# reversed as it goes on the wire, rather than a hash recomputed by this test.
SCRIPT_HASH = "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161"
BALANCE = {"confirmed": 103873966, "unconfirmed": 23684400}


def _line(value: object) -> bytes:
    """Write one scripted server message."""
    return json.dumps(value).encode() + b"\n"


def test_single_balance_keeps_confirmed_satoshis_and_signed_mempool_delta() -> None:
    """Both values remain exact integers, including a spend's negative delta."""
    balance = electrum.scripthash_get_balance_response(
        _line({"id": 7, "result": BALANCE}), 7
    )
    assert balance.confirmed == 103873966
    assert balance.unconfirmed == 23684400
    spent = electrum.scripthash_get_balance_response(
        _line({"id": 8, "result": {"confirmed": 1000, "unconfirmed": -700}}), 8
    )
    assert spent == electrum.ScriptBalance(1000, -700)
    assert spent.confirmed + spent.unconfirmed == 300


def test_balance_request_preserves_the_script_hash_and_frames_one_line() -> None:
    """No implicit byte reversal or whitespace reaches the request."""
    line = electrum.scripthash_get_balance_request(7, SCRIPT_HASH.upper())
    assert line.count(b"\n") == 1
    assert line.endswith(b"\n")
    assert json.loads(line) == {
        "id": 7,
        "method": "blockchain.scripthash.get_balance",
        "params": [SCRIPT_HASH.upper()],
    }


@pytest.mark.parametrize("script_hash", [None, 1, b"00" * 32])
def test_balance_request_refuses_a_non_string_hash(script_hash: object) -> None:
    """The wire carries a string, not something a caller meant as one."""
    with pytest.raises(BTClibTypeError, match="scripthash type"):
        electrum.scripthash_get_balance_request(7, script_hash)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "script_hash",
    ["", "ab" * 31, "ab" * 33, "gh" * 32, " " + SCRIPT_HASH, SCRIPT_HASH + "\n"],
)
def test_balance_request_refuses_a_malformed_hash(script_hash: str) -> None:
    """Exactly 64 hex characters go on the wire."""
    with pytest.raises(BTClibValueError, match="invalid scripthash"):
        electrum.scripthash_get_balance_request(7, script_hash)


@pytest.mark.parametrize("request_id", [True, None, "7", 7.0])
def test_balance_helpers_refuse_non_integer_request_ids(request_id: object) -> None:
    """Equality with an integer id does not make a bool or float one."""
    with pytest.raises(BTClibTypeError, match="request_id type"):
        electrum.scripthash_get_balance_request(request_id, SCRIPT_HASH)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="request_id type"):
        electrum.scripthash_get_balance_response(b"{}", request_id)  # type: ignore[arg-type]


@pytest.mark.parametrize("result", [None, [], 0, "balance"])
def test_balance_response_refuses_a_non_object(result: object) -> None:
    """A missing answer is not a zero balance."""
    with pytest.raises(BTClibTypeError, match="not an object"):
        electrum.scripthash_get_balance_response(_line({"id": 7, "result": result}), 7)


@pytest.mark.parametrize("field", ["confirmed", "unconfirmed"])
@pytest.mark.parametrize("value", [None, True, False, 1.5, "100"])
def test_balance_response_refuses_inexact_or_missing_fields(
    field: str, value: object
) -> None:
    """A bool, float or absent amount is refused without coercion."""
    result: dict[str, object] = dict(BALANCE)
    result[field] = value
    with pytest.raises(BTClibTypeError, match=f"{field} balance type"):
        electrum.scripthash_get_balance_response(_line({"id": 7, "result": result}), 7)
    del result[field]
    with pytest.raises(BTClibTypeError, match=f"{field} balance type"):
        electrum.scripthash_get_balance_response(_line({"id": 7, "result": result}), 7)


def test_balance_response_refuses_a_negative_confirmed_balance() -> None:
    """Only the mempool delta can be negative."""
    with pytest.raises(BTClibValueError, match="confirmed balance"):
        electrum.scripthash_get_balance_response(
            _line({"id": 7, "result": {"confirmed": -1, "unconfirmed": 0}}), 7
        )


def test_balance_shape_refusals_keep_no_refused_value() -> None:
    """An incorrectly supplied secret is absent from the exception graph."""
    secret = int("7f" * 32, 16)
    spelling = str(secret)
    with pytest.raises(BTClibValueError) as refused_hash:
        electrum.scripthash_get_balance_request(7, spelling)
    assert_secret_free(refused_hash.value, [spelling])
    for result in (spelling, {"confirmed": -secret, "unconfirmed": 0}):
        for batch in (False, True):
            reply = {"id": 7, "result": result}
            with pytest.raises((BTClibTypeError, BTClibValueError)) as refused:
                if batch:
                    electrum.scripthash_get_balance_batch_response(_line([reply]), [7])
                else:
                    electrum.scripthash_get_balance_response(_line(reply), 7)
            assert_secret_free(refused.value, [spelling])


def test_balance_response_matches_its_request_and_preserves_rpc_errors() -> None:
    """An answer for another script or a server refusal is never a balance."""
    with pytest.raises(BTClibValueError, match="does not answer request"):
        electrum.scripthash_get_balance_response(_line({"id": 8, "result": BALANCE}), 7)
    with pytest.raises(RpcError, match="script refused") as exc:
        electrum.scripthash_get_balance_response(
            _line(
                {
                    "id": 7,
                    "error": {
                        "code": -32602,
                        "message": "script refused",
                        "data": "detail",
                    },
                }
            ),
            7,
        )
    assert exc.value.code == -32602
    assert exc.value.data == "detail"


def test_batch_request_is_one_array_with_distinct_ids() -> None:
    """Several requests share one newline, with one id per script hash."""
    line = electrum.scripthash_get_balance_batch_request(
        {7: SCRIPT_HASH, -2: "00" * 32}
    )
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    assert json.loads(line) == [
        {
            "id": 7,
            "method": "blockchain.scripthash.get_balance",
            "params": [SCRIPT_HASH],
        },
        {
            "id": -2,
            "method": "blockchain.scripthash.get_balance",
            "params": ["00" * 32],
        },
    ]


def test_batch_response_matches_ids_instead_of_trusting_reply_order() -> None:
    """A server may reorder its replies; the caller's order is restored."""
    balances = electrum.scripthash_get_balance_batch_response(
        _line(
            [
                {"id": -2, "result": {"confirmed": 0, "unconfirmed": 0}},
                {"id": 7, "result": BALANCE},
            ]
        ),
        [7, -2],
    )
    assert balances == (
        electrum.ScriptBalance(103873966, 23684400),
        electrum.ScriptBalance(0, 0),
    )
    assert (
        electrum.scripthash_get_balance_batch_response(
            _line([{"id": 7, "result": BALANCE}]), (7,)
        )
        == balances[:1]
    )


@pytest.mark.parametrize("requests", [None, [], "requests", 7])
def test_batch_request_refuses_a_non_mapping(requests: object) -> None:
    """Ids must name their hashes explicitly."""
    with pytest.raises(BTClibTypeError, match="not a mapping"):
        electrum.scripthash_get_balance_batch_request(requests)  # type: ignore[arg-type]


def test_batch_request_validates_every_id_and_hash() -> None:
    """An invalid member cannot hide behind a valid first request."""
    with pytest.raises(BTClibValueError, match="no requests"):
        electrum.scripthash_get_balance_batch_request({})
    with pytest.raises(BTClibTypeError, match="request_id type"):
        electrum.scripthash_get_balance_batch_request({True: SCRIPT_HASH})
    with pytest.raises(BTClibValueError, match="invalid scripthash"):
        electrum.scripthash_get_balance_batch_request({7: SCRIPT_HASH, 8: "bad"})


@pytest.mark.parametrize("ids", [None, 7, "7", b"7", iter([7])])
def test_batch_response_refuses_an_id_argument_that_is_not_a_sequence(
    ids: object,
) -> None:
    """The order must be repeatable when the answers are returned."""
    with pytest.raises(BTClibTypeError, match="not a sequence"):
        electrum.scripthash_get_balance_batch_response(b"[]", ids)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "ids, error, message",
    [
        ([], BTClibValueError, "no requests"),
        ([7, 7], BTClibValueError, "repeated request id"),
        ([True], BTClibTypeError, "request_id type"),
        ([7.0], BTClibTypeError, "request_id type"),
    ],
)
def test_batch_response_refuses_invalid_expected_ids(
    ids: object, error: type[Exception], message: str
) -> None:
    """Distinct integer ids define the complete set of expected answers."""
    with pytest.raises(error, match=message):
        electrum.scripthash_get_balance_batch_response(b"[]", ids)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "replies, error, message",
    [
        ([], BTClibValueError, "missing response id"),
        ([{"id": 7, "result": BALANCE}], BTClibValueError, "missing response id"),
        (
            [{"id": 7, "result": BALANCE}, {"id": 7, "result": BALANCE}],
            BTClibValueError,
            "repeated response id",
        ),
        ([{"id": 9, "result": BALANCE}], BTClibValueError, "unasked response id"),
        ([{"id": True, "result": BALANCE}], BTClibTypeError, "response id type"),
        ([{"id": 7.0, "result": BALANCE}], BTClibTypeError, "response id type"),
        ([{"result": BALANCE}], BTClibTypeError, "response id type"),
        ([None], BTClibTypeError, "not a response object"),
        ({"id": 7, "result": BALANCE}, BTClibTypeError, "not a response array"),
        ({"id": None}, BTClibTypeError, "not a response array"),
        (None, BTClibTypeError, "not a response array"),
    ],
)
def test_batch_response_refuses_incomplete_ambiguous_or_unasked_answers(
    replies: object, error: type[Exception], message: str
) -> None:
    """No partial result escapes as a complete address balance answer."""
    with pytest.raises(error, match=message):
        electrum.scripthash_get_balance_batch_response(_line(replies), [7, 8])


def test_batch_response_raises_an_individual_or_whole_batch_rpc_error() -> None:
    """Preserve the server's code and data whichever scope it refuses."""
    error = {"code": -32600, "message": "batch refused", "data": "detail"}
    for payload in ([{"id": 7, "error": error}], {"id": None, "error": error}):
        with pytest.raises(RpcError, match="batch refused") as exc:
            electrum.scripthash_get_balance_batch_response(_line(payload), [7])
        assert exc.value.code == -32600
        assert exc.value.data == "detail"


@pytest.mark.parametrize(
    "line", [b"not json", b"[NaN]", b"[" * 17 + b"]" * 17, b"\xff"]
)
def test_batch_response_keeps_the_single_reply_json_hardening(line: bytes) -> None:
    """Non-JSON constants, excessive nesting and invalid UTF-8 stay refused."""
    with pytest.raises(BTClibValueError, match="not a JSON-RPC line"):
        electrum.scripthash_get_balance_batch_response(line, [7])
