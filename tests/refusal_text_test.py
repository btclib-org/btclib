# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a refusal does not carry the key it was handed.

A key passed where a network name belongs, or a WIF with a non-ASCII
character, must reach neither the message of the exception nor any
exception it chains.
"""

from collections.abc import Callable, Iterator
from typing import Any

import pytest

from btclib.b58 import prv_key_data_from_wif, wif_from_prv_key
from btclib.base58 import decode
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData
from btclib.network import NETWORKS, validated_network_name
from btclib.utils import str_from_string

KEY = 0x1D2F3E4D5C6B7A8998A7B6C5D4E3F20112233445566778899AABBCCDDEEFF0A1
WIF = wif_from_prv_key(KEY)


def _chain(exc: BaseException) -> Iterator[BaseException]:
    seen: set[int] = set()
    todo: list[BaseException | None] = [exc]
    while todo:
        e = todo.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        todo += [e.__cause__, e.__context__]


def _assert_secret_free(exc: BaseException, secrets: list[str]) -> None:
    for e in _chain(exc):
        text = " ".join([str(e), repr(e), repr(e.args), str(vars(e))]).lower()
        for secret in secrets:
            assert secret.lower() not in text
            assert secret.lower()[:12] not in text


SWAPPED: list[tuple[Callable[[], Any], list[str]]] = [
    (lambda: wif_from_prv_key("mainnet", KEY), [str(KEY)]),  # type: ignore[arg-type]
    (lambda: wif_from_prv_key(KEY, WIF), [str(KEY), WIF]),
    (lambda: PrvKeyData(KEY, WIF), [str(KEY), WIF]),
    (lambda: prv_key_data_from_wif(WIF, KEY), [str(KEY), WIF]),  # type: ignore[arg-type]
]


@pytest.mark.parametrize("call, secrets", SWAPPED)
def test_swapped_arguments_do_not_quote_the_key(
    call: Callable[[], Any], secrets: list[str]
) -> None:
    """A key in the network position is not repeated by the refusal."""
    with pytest.raises((BTClibTypeError, BTClibValueError)) as refusal:
        call()
    _assert_secret_free(refusal.value, secrets)


def test_refused_network_name() -> None:
    """A short typo is quoted; a long name and a non-string are not."""
    with pytest.raises(BTClibValueError, match="unknown network: 'mainnt'"):
        validated_network_name("mainnt")

    long_name = "x" * 17
    with pytest.raises(BTClibValueError, match="too long to quote") as refusal:
        validated_network_name(long_name)
    assert long_name not in str(refusal.value)
    assert str(sorted(NETWORKS)) in str(refusal.value)

    with pytest.raises(
        BTClibTypeError, match="not a network name: int"
    ) as type_refusal:
        validated_network_name(KEY)  # type: ignore[arg-type]
    assert str(KEY) not in str(type_refusal.value)


def test_non_ascii_base58_chains_nothing() -> None:
    """A non-ASCII base58 string is refused with no cause or context."""
    bad = WIF[:-1] + "\u00e9"
    with pytest.raises(BTClibValueError, match="non-ascii character") as refusal:
        decode(bad)
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None


def test_non_ascii_wif_chains_nothing() -> None:
    """A WIF with a non-ASCII character is refused without a cause."""
    bad = WIF[:-1] + "é"
    with pytest.raises(BTClibValueError, match="non-ascii character") as refusal:
        prv_key_data_from_wif(bad)
    _assert_secret_free(refusal.value, [WIF, bad])
    _assert_secret_free(refusal.value, [WIF[:20]])


def test_non_ascii_bytes_chain_nothing() -> None:
    """Non-ASCII bytes are refused without a cause."""
    bad = WIF.encode()[:-1] + b"\xc3\xa9"
    with pytest.raises(BTClibValueError, match="non-ascii character in") as refusal:
        str_from_string(bad, "WIF")
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    _assert_secret_free(refusal.value, [WIF])
