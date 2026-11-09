# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a refused string is quoted only where it is a short name.

Section 7 of the btclib-org standard, *A refusal carries no secret*, is
the rule, and `btclib.utils._name_text` is where this library applies
it to a name; any other string is described by its length. Each case
below puts a fixed random key, in one of its spellings, where a name, a
command, a time, an ip, a base64 text or an address belongs, and checks
the exact text and every exception of the chain (issues #3014 and
#3015). `tests/refused_octets_test.py` is the same check for octets.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from base58_bech32.bech32 import BECH32_1_CONST, bech32_encode, convertbits
from base58_bech32.exceptions import Base58Bech32ValueError
from typing_extensions import override

from btclib import bms
from btclib.b32 import witness_from_address
from btclib.b58 import address_from_h160, p2pkh, prv_key_data_from_wif, wif_from_prv_key
from btclib.block import BlockHeader
from btclib.bms import Sig
from btclib.exceptions import BTClibValueError
from btclib.key import PubKeyData
from btclib.network import (
    _NETWORK_FIELDS,
    NETWORKS,
    Network,
    networks_from_key_value,
    validated_network_name,
)
from btclib.p2p.address import NetworkAddress
from btclib.p2p.message import Message
from btclib.script import taproot
from btclib.script.engine.flags import to_script_flags
from btclib.script.script import serialize
from btclib.script.script_pub_key import ScriptPubKey, script_from_script_pub_key
from btclib.script.solver import get_txn_output_type
from btclib.testing.blocks import read_bytes
from btclib.utils import _name_text
from tests.secret_free import assert_secret_free, chained, text_of

# a fixed random key, as `assert_secret_free` asks, and its spellings
_KEY = bytes.fromhex("9ed7f12938cd646f2866d454cc247f688b857424cc4ee6bec49c16f1200bd5b9")
_HEX = _KEY.hex()
_B64 = base64.b64encode(_KEY).decode("ascii")
_DECIMAL = str(int.from_bytes(_KEY, "big"))

_MAINNET = NETWORKS["mainnet"]
_MAINNET_DICT = _MAINNET.to_dict()


def _address(hrp: str) -> str:
    """Return a p2wpkh-shaped bech32 address of the hrp."""
    data = [0, *convertbits(bytes(20), 8, 5)]
    return bech32_encode(hrp, data, m=BECH32_1_CONST).decode("ascii")


class _Lying(str):
    """A str whose own methods hide its length, its text and its octets."""

    __slots__ = ()

    @override
    def __len__(self) -> int:
        return 1

    @override
    def __repr__(self) -> str:
        return "'short'"

    @override
    def __format__(self, format_spec: str) -> str:
        return "short"

    @override
    def isascii(self) -> bool:
        return True

    @override
    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        return b""


# the generator's sec, a key other than the one that signs below
_G_SEC = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
# a p2pkh address, but not the signer's
_OTHER_ADDRESS = p2pkh(PubKeyData(_G_SEC))


def _bms_sig() -> Sig:
    """Return a mainnet p2pkh message signature of the key 2."""
    return bms.sign(b"msg", wif_from_prv_key(2))


class _Stripping(str):
    """A str whose own strip answers an address that is not its text."""

    __slots__ = ()

    @override
    def strip(self, chars: str | None = None) -> str:
        return _OTHER_ADDRESS


class _Testnet(str):
    """A str whose own methods claim it is the name testnet."""

    __slots__ = ()

    @override
    def strip(self, chars: str | None = None) -> str:
        return self

    @override
    def lower(self) -> str:
        return self

    @override
    def __eq__(self, other: object) -> bool:
        return other == "testnet"

    @override
    def __hash__(self) -> int:
        return hash("testnet")


class _Quoting(str):
    """A str whose own repr is the key's hex."""

    __slots__ = ()

    @override
    def __repr__(self) -> str:
        return repr(_HEX)


def _header_dict(time: str) -> dict[str, object]:
    """Return the dict of a header whose time is the string."""
    time_ = datetime(2009, 1, 9, tzinfo=UTC)
    header = BlockHeader(1, bytes(32), bytes(32), time_, "1d00ffff", 0)
    return {**header.to_dict(), "time": time}


# each case: id, call, exact text, and the type of each exception of the
# chain after the refusal
_CASES: list[tuple[str, Callable[[], object], str, list[type[BaseException]]]] = [
    (
        "script flag",
        lambda: to_script_flags(_HEX),
        "unknown script flag: a str of length 64",
        [],
    ),
    (
        "script flag among others",
        lambda: to_script_flags(["P2SH", _HEX]),
        "unknown script flag: a str of length 64",
        [],
    ),
    (
        "network type",
        lambda: Network.from_dict({**_MAINNET_DICT, "network_type": _HEX}),
        "invalid network type: a str of length 64",
        [],
    ),
    (
        "network field",
        lambda: networks_from_key_value(_HEX, b"\x80"),  # type: ignore[arg-type]
        (
            "unknown network field: a str of length 64"
            f"; it must be one of {sorted(_NETWORK_FIELDS)}"
        ),
        [],
    ),
    (
        "curve name",
        lambda: Network.from_dict({**_MAINNET_DICT, "curve": _HEX}),
        "unknown curve: a str of length 64",
        [],
    ),
    (
        "consensus name",
        lambda: Network.from_dict({**_MAINNET_DICT, "consensus": _HEX}),
        "unknown consensus parameters: a str of length 64",
        [],
    ),
    # forty characters of the key are an hrp short enough for an address
    (
        "hrp of no network",
        lambda: witness_from_address(_address(_HEX[:40])),
        "invalid hrp: a str of length 40",
        [],
    ),
    (
        "hrp of another network",
        lambda: witness_from_address(_address(_HEX[:40]), _MAINNET),
        "invalid hrp: a str of length 40",
        [],
    ),
    (
        "script type",
        lambda: address_from_h160(_HEX, bytes(20)),  # type: ignore[arg-type]
        "invalid script type: a str of length 64",
        [],
    ),
    (
        "output type",
        lambda: get_txn_output_type(_HEX),  # type: ignore[arg-type]
        "invalid TxoutType: a str of length 64",
        [],
    ),
    (
        "block file",
        lambda: read_bytes(_HEX),
        "unknown block file: a str of length 64",
        [],
    ),
    # "zz" is no hex, so the key is neither an op code nor data
    (
        "script command",
        lambda: serialize(["zz" + _HEX]),
        "invalid string command: a str of length 66",
        [ValueError],
    ),
    (
        "tapscript command",
        lambda: taproot.serialize(["zz" + _HEX]),
        "invalid string command: a str of length 66",
        [ValueError],
    ),
    (
        "OP_SUCCESS not a number",
        lambda: taproot.serialize(["OP_SUCCESSx" + _HEX, b"\x01"]),
        "invalid string command: a str of length 75",
        [],
    ),
    (
        "OP_SUCCESS number",
        lambda: taproot.serialize(["OP_SUCCESS" + _DECIMAL, b"\x01"]),
        f"invalid OP_SUCCESS number: {len(_DECIMAL)} digits",
        [],
    ),
    (
        "header time",
        lambda: BlockHeader.from_dict(_header_dict(_HEX)),
        "invalid time: a str of length 64",
        [],
    ),
    (
        "ip",
        lambda: NetworkAddress(ip=_HEX),
        "invalid ip: a str of length 64",
        [],
    ),
    (
        "base64 non-ascii",
        lambda: Sig.b64decode(" " + _B64 + "\u00e9"),
        f"invalid base64 encoding: non-ascii character at position {len(_B64) + 1}",
        [],
    ),
    # a subclass that says it is ascii is read with str's own encode
    (
        "base64 non-ascii of a str subclass",
        lambda: Sig.b64decode(_Lying(_B64 + "\u00e9")),
        f"invalid base64 encoding: non-ascii character at position {len(_B64)}",
        [],
    ),
    # a subclass that says it is short is measured with str's own length
    (
        "network name of a str subclass",
        lambda: validated_network_name(_Lying(_HEX)),
        f"unknown network (too long to quote); it must be one of {sorted(NETWORKS)}",
        [],
    ),
    (
        "message command of a str subclass",
        lambda: Message(bytes(4), _Lying("\x00" + _HEX)),
        "invalid command: 65 characters instead of at most 12",
        [],
    ),
    # the address is decoded as the plain str of its characters
    (
        "bms address of a str subclass",
        lambda: bms.assert_as_valid(b"msg", _Stripping(_HEX), _bms_sig()),
        "Base58 string contains invalid characters",
        [Base58Bech32ValueError],
    ),
    # a stored network name is the plain str of its characters
    (
        "WIF network of a str subclass",
        lambda: prv_key_data_from_wif(wif_from_prv_key(1), _Testnet(_HEX)),
        f"unknown network (too long to quote); it must be one of {sorted(NETWORKS)}",
        [],
    ),
    (
        "m-of-n network of a str subclass",
        lambda: ScriptPubKey.p2ms(
            1, [PubKeyData(_G_SEC, _Testnet(_HEX)), PubKeyData(_G_SEC)]
        ),
        f"unknown network (too long to quote); it must be one of {sorted(NETWORKS)}",
        [],
    ),
    # binascii's own text, which holds no character of the input
    (
        "base64 alphabet",
        lambda: Sig.b64decode(_HEX + "!"),
        "invalid base64 encoding: Only base64 data is allowed",
        [binascii.Error],
    ),
    # "0" is no base58 character
    (
        "WIF",
        lambda: prv_key_data_from_wif(_HEX),
        "not a WIF (Base58 string contains invalid characters)",
        [Base58Bech32ValueError],
    ),
    (
        "script or address",
        lambda: script_from_script_pub_key("zz" + _HEX),
        "neither a script nor an address",
        [BTClibValueError, Base58Bech32ValueError],
    ),
    (
        "bech32 then base58 address",
        lambda: ScriptPubKey.from_address("bc1" + _HEX, _MAINNET),
        "invalid character in checksum",
        [BTClibValueError, Base58Bech32ValueError],
    ),
]


@pytest.mark.parametrize(
    "call, err_msg, chain",
    [case[1:] for case in _CASES],
    ids=[case[0] for case in _CASES],
)
def test_a_refusal_quotes_no_string_that_may_be_a_key(
    call: Callable[[], object], err_msg: str, chain: list[type[BaseException]]
) -> None:
    """The refusal describes the string by its length, and chains no copy of it.

    `assert_secret_free` looks for pieces whose length `WINDOW` gives
    (`tests/secret_free/__init__.py`), so each byte of the key is also
    looked for as `0x` and its hex, and the text is compared whole.
    """
    with pytest.raises(BTClibValueError) as refusal:
        call()
    assert str(refusal.value) == err_msg
    # a cause or a context holding the string, a Unicode error for one,
    # would be text the whole comparison does not see
    assert [type(e) for e in chained(refusal.value)][1:] == chain
    assert_secret_free(refusal.value, [_KEY, _HEX, _B64, _DECIMAL])
    for e in chained(refusal.value):
        text = text_of(e)
        assert all(f"0x{byte:02x}" not in text for byte in _KEY)


def test_a_name_is_quoted_up_to_16_characters() -> None:
    """Sixteen characters are quoted, seventeen described by their length."""
    with pytest.raises(BTClibValueError) as refusal:
        to_script_flags("A" * 16)
    assert str(refusal.value) == f"unknown script flag: {'A' * 16!r}"

    with pytest.raises(BTClibValueError) as refusal:
        to_script_flags("A" * 17)
    assert str(refusal.value) == "unknown script flag: a str of length 17"

    # what is not a str is described as `_message_text` describes it
    with pytest.raises(BTClibValueError) as refusal:
        networks_from_key_value(5, b"\x80")  # type: ignore[arg-type]
    assert str(refusal.value).startswith("unknown network field: an int of 3 bits;")


def test_a_name_is_read_with_the_methods_of_str() -> None:
    """A subclass's length and repr decide neither the quote nor the text."""

    class Disguised(str):
        __slots__ = ()

        @override
        def __len__(self) -> int:
            return 1

        @override
        def __repr__(self) -> str:
            return "'short'"

    disguised = Disguised("A" * 16)
    assert (len(disguised), repr(disguised)) == (1, "'short'")
    assert _name_text(disguised) == f"{'A' * 16!r}"
    # the description past the bound is _message_text's, which reads len()
    assert _name_text(Disguised("A" * 17)) == "a Disguised of length 1"


def test_a_short_name_is_quoted_with_the_methods_of_str() -> None:
    """Within the bound, the quote is str's text and repr, not a subclass's."""
    # what the subclass says of itself, which no refusal above repeats
    lying = _Lying(_HEX + "é")
    said = (len(lying), repr(lying), f"{lying}", lying.isascii(), lying.encode())
    assert said == (1, "'short'", "short", True, b"")

    with pytest.raises(BTClibValueError) as refusal:
        validated_network_name(_Lying("A" * 16))
    assert str(refusal.value).startswith(f"unknown network: '{'A' * 16}';")

    command = "\x00ab"
    with pytest.raises(BTClibValueError) as refusal:
        Message(bytes(4), _Lying(command))
    assert str(refusal.value) == f"non-printable character in command: {command!r}"


def test_a_str_subclass_is_read_as_its_characters() -> None:
    """A refused address is quoted as it decoded, never as it was passed."""
    # what each subclass says of itself, which no refusal above repeats
    assert _Stripping(_HEX).strip() == _OTHER_ADDRESS
    testnet = _Testnet(_HEX)
    said = (testnet.strip(), testnet.lower(), testnet == "testnet", hash(testnet))
    assert said == (testnet, testnet, True, hash("testnet"))
    assert repr(_Quoting(_OTHER_ADDRESS)) == repr(_HEX)

    with pytest.raises(BTClibValueError) as refusal:
        bms.assert_as_valid(b"msg", _Quoting(_OTHER_ADDRESS), _bms_sig())
    assert str(refusal.value) == f"invalid p2pkh address: {_OTHER_ADDRESS!r}"
    assert_secret_free(refusal.value, [_KEY, _HEX])
