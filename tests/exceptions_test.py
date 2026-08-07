# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib.exceptions`, and for what an exception carries.

The classes with nothing added to their base need no test of their own:
what they are is the base, and every module raising one asserts the
message it raised. What is tested here is the four carrying a field --
`HttpError`, `RpcError`, `ScriptError` and `InvalidContributionError` --
and specifically that a field survives leaving the process it was raised
in, which is the case the field exists for and the one nothing else in
the suite exercises: pytest-xdist sends a report as text, so no exception
object crosses between workers (issue #391).
"""

from __future__ import annotations

import copy
import pickle
from concurrent.futures import ProcessPoolExecutor
from typing import Any

import pytest

from btclib.exceptions import (
    BTClibValueError,
    FetchError,
    HttpError,
    InvalidContributionError,
    RpcError,
    ScriptError,
)

HTTP_MESSAGE = "getblockcount at http://127.0.0.1:8332: HTTP 503"

# the exception, the `args` it is expected to carry, its message, and the
# fields a caller reads. Constructed here and shared by every test below:
# none of them mutates one, and an exception that a test could mutate is
# an exception this module would have to say more about
CASES = [
    pytest.param(
        HttpError(HTTP_MESSAGE, 503),
        (HTTP_MESSAGE, 503),
        HTTP_MESSAGE,
        {"status": 503},
        id="HttpError",
    ),
    pytest.param(
        RpcError("getrawtransaction: not found", -5, {"txid": "00"}),
        ("getrawtransaction: not found", -5, {"txid": "00"}),
        "getrawtransaction: not found (rpc error code -5)",
        {"code": -5, "data": {"txid": "00"}},
        id="RpcError",
    ),
    pytest.param(
        RpcError("getblock: block not found", -5),
        ("getblock: block not found", -5, None),
        "getblock: block not found (rpc error code -5)",
        {"code": -5, "data": None},
        id="RpcError-without-data",
    ),
    pytest.param(
        ScriptError("unbalanced conditional", 3, 2),
        ("unbalanced conditional", 3, 2),
        "unbalanced conditional (command 3, stack depth 2)",
        {"index": 3, "stack_depth": 2},
        id="ScriptError",
    ),
    pytest.param(
        InvalidContributionError(2, "psig"),
        (2, "psig"),
        "invalid psig from signer 2",
        {"signer": 2, "contrib": "psig"},
        id="InvalidContributionError",
    ),
    pytest.param(
        InvalidContributionError(None, "aggnonce"),
        (None, "aggnonce"),
        "invalid aggnonce from the aggregator",
        {"signer": None, "contrib": "aggnonce"},
        id="InvalidContributionError-aggregator",
    ),
]


def _assert_same(back: BaseException, error: BaseException, fields: Any) -> None:
    assert type(back) is type(error)
    assert str(back) == str(error)
    assert back.args == error.args
    for name, value in fields.items():
        assert getattr(back, name) == value


@pytest.mark.parametrize("error, args, message, fields", CASES)
def test_a_field_carrying_exception_says_what_it_carries(
    error: BaseException, args: tuple[Any, ...], message: str, fields: Any
) -> None:
    """`args` is the constructor's arguments and `str` is the message."""
    assert error.args == args
    assert str(error) == message
    for name, value in fields.items():
        assert getattr(error, name) == value
    # `repr` names the fields with the message, which is the visible half
    # of `args` holding them: rebuilding the class from what it prints is
    # what a one-tuple of the composed message could not offer
    assert repr(error) == f"{type(error).__name__}{args!r}"


@pytest.mark.parametrize("error, args, message, fields", CASES)
def test_a_field_carrying_exception_survives_pickle(
    error: BaseException, args: tuple[Any, ...], message: str, fields: Any
) -> None:
    """The class, the message and every field come back from `pickle`."""
    back = pickle.loads(pickle.dumps(error))  # noqa: S301
    _assert_same(back, error, fields)
    assert back.args == args
    assert str(back) == message


@pytest.mark.parametrize("error, args, message, fields", CASES)
def test_a_field_carrying_exception_survives_copy(
    error: BaseException, args: tuple[Any, ...], message: str, fields: Any
) -> None:
    """`copy` and `deepcopy` need no process, and used to fail the same way."""
    for back in (copy.copy(error), copy.deepcopy(error)):
        _assert_same(back, error, fields)
        assert back.args == args
        assert str(back) == message


@pytest.mark.parametrize("error, args, message, fields", CASES)
def test_the_message_is_composed_once(
    error: BaseException, args: tuple[Any, ...], message: str, fields: Any
) -> None:
    """A round trip of a round trip still says what one raise said.

    The trap this pins is composing in `__init__` from an argument that is
    itself a composed message: the message grows a second `(rpc error code
    -5)` per round trip, so a single one shows it and a second makes what
    is accumulating unmistakable.
    """
    back: BaseException = error
    for _ in range(2):
        back = pickle.loads(pickle.dumps(back))  # noqa: S301
        assert str(back) == message
    assert back.args == args
    _assert_same(back, error, fields)


@pytest.mark.parametrize(
    "error",
    [FetchError("no answer from http://127.0.0.1:8332"), BTClibValueError("bad")],
    ids=["FetchError", "BTClibValueError"],
)
def test_an_exception_adding_nothing_round_trips_too(error: BaseException) -> None:
    """The control: a class taking a message alone was never affected."""
    for back in (pickle.loads(pickle.dumps(error)), copy.copy(error)):  # noqa: S301
        assert type(back) is type(error)
        assert str(back) == str(error)
        assert back.args == error.args


def _raise_http_error() -> None:
    raise HttpError(HTTP_MESSAGE, 503)


def test_a_field_carrying_exception_crosses_a_process_boundary() -> None:
    """What the field is for: a fetch fanned out across processes.

    A worker that cannot send its exception back does not merely lose the
    diagnosis -- `ProcessPoolExecutor` reports a `BrokenProcessPool`, so
    the pool dies wherever the node answers 503 and works wherever it does
    not. The same raise in this process is the control: the two have to
    agree on the class, the message and the status.
    """
    with pytest.raises(HttpError) as local:
        _raise_http_error()

    with ProcessPoolExecutor(max_workers=1) as pool, pytest.raises(HttpError) as remote:
        pool.submit(_raise_http_error).result()

    assert type(remote.value) is type(local.value)
    assert str(remote.value) == str(local.value)
    assert remote.value.status == local.value.status == 503
