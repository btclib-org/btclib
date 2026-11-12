# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a refusal does not carry the key it was handed.

A key passed where a network name belongs, or a WIF with a non-ASCII
character, must reach neither the message of the exception nor any
exception it chains.
"""

from collections.abc import Callable
from typing import Any

import pytest
from base58_bech32.base58 import b58decode_check
from base58_bech32.exceptions import Base58Bech32ValueError
from typing_extensions import override

from btclib.b58 import h160_from_address, prv_key_data_from_wif, wif_from_prv_key
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256
from btclib.key import PrvKeyData, PubKeyData
from btclib.network import NETWORKS, validated_network_name
from btclib.script.script_pub_key import ScriptPubKey
from btclib.utils import str_from_string
from tests.network_argument_test import OTHER
from tests.secret_free import assert_secret_free, text_of

KEY = 0x1D2F3E4D5C6B7A8998A7B6C5D4E3F20112233445566778899AABBCCDDEEFF0A1
WIF = wif_from_prv_key(KEY)


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
    assert_secret_free(refusal.value, secrets)


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


def test_non_ascii_base58_chains_only_the_codec_refusal() -> None:
    """A non-ASCII base58 address is refused, its chain holding no string.

    The cause is the codec's own refusal, which btclib re-raises as a
    `BTClibValueError`; the codec chains nothing behind it.
    """
    bad = WIF[:-1] + "\u00e9"
    with pytest.raises(BTClibValueError, match="non-ascii character") as refusal:
        h160_from_address(bad)
    where = len(WIF) - 1
    assert str(refusal.value) == (
        f"non-ascii character in base58 string at position {where}"
    )
    cause = refusal.value.__cause__
    assert isinstance(cause, Base58Bech32ValueError)
    assert cause.__cause__ is None
    assert cause.__context__ is None
    assert_secret_free(refusal.value, [WIF, bad])


def test_non_ascii_wif_chain_holds_no_key() -> None:
    """A WIF with a non-ASCII character is refused.

    No exception in the chain holds it.
    """
    bad = f"{WIF[:-1]}é"
    with pytest.raises(BTClibValueError, match="non-ascii character") as refusal:
        prv_key_data_from_wif(bad)
    where = len(WIF) - 1
    assert str(refusal.value) == (
        f"not a WIF (non-ascii character in base58 string at position {where})"
    )
    assert_secret_free(refusal.value, [WIF, bad])
    assert_secret_free(refusal.value, [WIF[:20]])


def test_bad_checksum_does_not_quote_the_expected_one() -> None:
    """A WIF mistyped in its last character does not confirm a guess."""
    bad = WIF[:-1] + ("2" if WIF[-1] != "2" else "3")
    with pytest.raises(BTClibValueError) as refusal:
        prv_key_data_from_wif(bad)
    assert str(refusal.value) == "not a WIF (invalid checksum)"
    expected = hash256(b58decode_check(WIF))[:4]
    assert_secret_free(refusal.value, [expected, f"0x{expected.hex()}", expected.hex()])


def test_non_ascii_bytes_chain_nothing() -> None:
    """Non-ASCII bytes are refused without a cause."""
    bad = WIF.encode()[:-1] + b"\xc3\xa9"
    with pytest.raises(BTClibValueError, match="non-ascii character in") as refusal:
        str_from_string(bad, "WIF")
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert_secret_free(refusal.value, [WIF])


def test_unchecked_prv_key_data_repr_hides_a_swapped_key() -> None:
    """A key in the network position is not shown by the repr."""
    swapped = PrvKeyData(KEY, WIF, check_validity=False)
    assert WIF.lower() not in repr(swapped)
    assert repr(swapped) == "PrvKeyData(q=..., network=..., compressed=True)"
    assert "network='mainnet'" in repr(PrvKeyData(KEY))


class _HostileEq:
    @override
    def __eq__(self, other: object) -> bool:  # pragma: no cover -- must stay uncalled
        msg = "__eq__ called"
        raise RuntimeError(msg)

    __hash__ = None  # type: ignore[assignment]


@pytest.mark.parametrize("network", [_HostileEq(), b"mainnet", [WIF]])
@pytest.mark.parametrize(
    "make, shown",
    [
        (
            lambda net: PrvKeyData(KEY, net, check_validity=False),
            "PrvKeyData(q=..., network=..., compressed=True)",
        ),
        (
            lambda net: PubKeyData(_PUB, net, check_validity=False),
            "PubKeyData(sec=..., network=...)",
        ),
        (
            lambda net: ScriptPubKey(b"", net, check_validity=False),
            "ScriptPubKey(script=..., network=...)",
        ),
    ],
    ids=["PrvKeyData", "PubKeyData", "ScriptPubKey"],
)
def test_an_unchecked_repr_runs_no_foreign_code(
    make: Callable[[Any], object], shown: str, network: Any
) -> None:
    """A non-string network is hidden without comparing or hashing it."""
    unchecked = make(network)
    assert repr(unchecked) == shown
    assert str(unchecked) == shown


_UNCHECKED_KEY = bytes.fromhex(
    "9ed7f12938cd646f2866d454cc247f688b857424cc4ee6bec49c16f1200bd5b9"
)
_UNCHECKED_INT = int.from_bytes(_UNCHECKED_KEY, "big")
_UNCHECKED_WIF = wif_from_prv_key(_UNCHECKED_INT)
_PUB: bytes = PrvKeyData(_UNCHECKED_INT).pub.sec

_KEY_IN_AN_UNCHECKED_POSITION: list[tuple[str, Callable[[], object], str]] = [
    (
        "prv-q",
        lambda: PrvKeyData(_UNCHECKED_INT),
        "PrvKeyData(q=..., network='mainnet', compressed=True)",
    ),
    (
        "prv-compressed-int",
        lambda: PrvKeyData(1, "mainnet", _UNCHECKED_INT, check_validity=False),  # type: ignore[arg-type]
        "PrvKeyData(q=..., network='mainnet', compressed=...)",
    ),
    (
        "prv-compressed-bytes",
        lambda: PrvKeyData(1, "mainnet", _UNCHECKED_KEY, check_validity=False),  # type: ignore[arg-type]
        "PrvKeyData(q=..., network='mainnet', compressed=...)",
    ),
    (
        "prv-network-wif",
        lambda: PrvKeyData(1, _UNCHECKED_WIF, check_validity=False),
        "PrvKeyData(q=..., network=..., compressed=True)",
    ),
    (
        "pub-sec-key",
        lambda: PubKeyData(_UNCHECKED_KEY, check_validity=False),
        "PubKeyData(sec=..., network='mainnet')",
    ),
    (
        "pub-sec-xprv-key-field",
        lambda: PubKeyData(b"\x00" + _UNCHECKED_KEY, check_validity=False),
        "PubKeyData(sec=..., network='mainnet')",
    ),
    (
        "pub-sec-compressed-prefix-short",
        lambda: PubKeyData(b"\x02" + _UNCHECKED_KEY[1:], check_validity=False),
        "PubKeyData(sec=..., network='mainnet')",
    ),
    (
        "pub-sec-uncompressed-prefix-short",
        lambda: PubKeyData(b"\x04" + _UNCHECKED_KEY, check_validity=False),
        "PubKeyData(sec=..., network='mainnet')",
    ),
    (
        "pub-network-wif",
        lambda: PubKeyData(_PUB, _UNCHECKED_WIF, check_validity=False),
        "PubKeyData(sec=..., network=...)",
    ),
    (
        "pub-network-decimal",
        lambda: PubKeyData(_PUB, str(_UNCHECKED_INT), check_validity=False),
        "PubKeyData(sec=..., network=...)",
    ),
    (
        "spk-script-key",
        lambda: ScriptPubKey(_UNCHECKED_KEY),
        "ScriptPubKey(script=..., network='mainnet')",
    ),
    (
        "spk-script-key-nulldata",
        lambda: ScriptPubKey(b"\x6a\x1e" + _UNCHECKED_KEY[2:]),
        "ScriptPubKey(script=..., network='mainnet')",
    ),
    (
        "spk-script-key-witness-unknown",
        lambda: ScriptPubKey(b"\x51\x1e" + _UNCHECKED_KEY[2:]),
        "ScriptPubKey(script=..., network='mainnet')",
    ),
    (
        "spk-script-prefixed-key-witness-unknown",
        lambda: ScriptPubKey(b"\x60\x1f" + _UNCHECKED_KEY[1:]),
        "ScriptPubKey(script=..., network='mainnet')",
    ),
    (
        "spk-network-wif",
        lambda: ScriptPubKey(b"", _UNCHECKED_WIF, check_validity=False),
        "ScriptPubKey(script=..., network=...)",
    ),
    (
        "spk-network-decimal",
        lambda: ScriptPubKey(b"", str(_UNCHECKED_INT), check_validity=False),
        "ScriptPubKey(script=..., network=...)",
    ),
]


@pytest.mark.parametrize(
    "make, shown",
    [case[1:] for case in _KEY_IN_AN_UNCHECKED_POSITION],
    ids=[case[0] for case in _KEY_IN_AN_UNCHECKED_POSITION],
)
def test_a_key_repr_hides_a_key_in_any_position(
    make: Callable[[], object], shown: str
) -> None:
    """A key passed unchecked in any position reaches neither repr nor str.

    `assert_secret_free` reads an exception, so one carries the two texts.
    It looks for pieces whose length `WINDOW` gives
    (`tests/secret_free/__init__.py`), so each byte of the key is also
    looked for as `0x` and its hex.
    """
    key = make()
    assert repr(key) == shown
    assert str(key) == shown
    texts = Exception(repr(key), str(key))
    assert_secret_free(texts, [_UNCHECKED_KEY, str(_UNCHECKED_INT), _UNCHECKED_WIF])
    text = text_of(texts)
    assert all(f"0x{byte:02x}" not in text for byte in _UNCHECKED_KEY)


_UNCOMPRESSED_PUB = PrvKeyData(_UNCHECKED_INT, compressed=False).pub.sec
_P2WPKH = ScriptPubKey.p2wpkh(PubKeyData(_PUB)).script
_P2PKH = ScriptPubKey.p2pkh(PubKeyData(_PUB)).script
# the lengths either side of a key's 32 and 33 bytes
_NULLDATA = b"\x6a\x1d" + bytes(29)
_WITNESS_UNKNOWN = b"\x52\x20" + bytes(32)


@pytest.mark.parametrize(
    "key, shown",
    [
        (
            PrvKeyData(_UNCHECKED_INT, compressed=False),
            "PrvKeyData(q=..., network='mainnet', compressed=False)",
        ),
        (
            PrvKeyData(1, "mainnet", 1, check_validity=False),  # type: ignore[arg-type]
            "PrvKeyData(q=..., network='mainnet', compressed=...)",
        ),
        (
            PrvKeyData(1, "mainnet", 0, check_validity=False),  # type: ignore[arg-type]
            "PrvKeyData(q=..., network='mainnet', compressed=...)",
        ),
        (PubKeyData(_PUB), f"PubKeyData(sec={_PUB!r}, network='mainnet')"),
        (
            PubKeyData(_UNCOMPRESSED_PUB, "testnet"),
            f"PubKeyData(sec={_UNCOMPRESSED_PUB!r}, network='testnet')",
        ),
        (
            PubKeyData(b"\x02" + _UNCOMPRESSED_PUB[1:], check_validity=False),
            "PubKeyData(sec=..., network='mainnet')",
        ),
        (
            PubKeyData(b"\x03" + _UNCOMPRESSED_PUB[1:], check_validity=False),
            "PubKeyData(sec=..., network='mainnet')",
        ),
        (PubKeyData(_PUB, OTHER), "PubKeyData(sec=..., network=...)"),
        (
            ScriptPubKey(_P2WPKH, "testnet"),
            f"ScriptPubKey(script={_P2WPKH!r}, network='testnet')",
        ),
        (
            ScriptPubKey(_P2PKH),
            f"ScriptPubKey(script={_P2PKH!r}, network='mainnet')",
        ),
        (
            ScriptPubKey(_NULLDATA),
            f"ScriptPubKey(script={_NULLDATA!r}, network='mainnet')",
        ),
        (
            ScriptPubKey(_WITNESS_UNKNOWN),
            f"ScriptPubKey(script={_WITNESS_UNKNOWN!r}, network='mainnet')",
        ),
        (
            PubKeyData(b"", check_validity=False),
            "PubKeyData(sec=..., network='mainnet')",
        ),
    ],
    ids=[
        "compressed-false",
        "compressed-one",
        "compressed-zero",
        "sec-compressed",
        "sec-uncompressed",
        "sec-compressed-prefix-long",
        "sec-odd-prefix-long",
        "sec-other-network",
        "script-p2wpkh",
        "script-p2pkh",
        "script-nulldata",
        "script-witness-unknown",
        "sec-empty",
    ],
)
def test_a_key_repr_shows_what_its_format_defines(key: object, shown: str) -> None:
    """A key repr shows a bool, SEC-shaped octets and a classified script.

    An int is hidden even where it reads as a bool, and so are octets whose
    prefix is one SEC defines for the other length, and octets on a Network
    NETWORKS does not hold.
    """
    assert repr(key) == shown
    assert str(key) == shown
