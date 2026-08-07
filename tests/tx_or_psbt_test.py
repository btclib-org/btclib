# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.tx_or_psbt` module."""

from __future__ import annotations

import base64

import pytest

from btclib.alias import String
from btclib.exceptions import BTClibValueError
from btclib.psbt import Psbt
from btclib.tx import Tx
from btclib.tx_or_psbt import _octets_from_text, tx_or_psbt_from_any

# BIP174's creator output, the psbt with nothing in it but the unsigned
# transaction, and block 170's transaction: one of each, at the shortest
# each can be
PSBT_B64 = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="
TX_HEX = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"

PSBT = Psbt.b64decode(PSBT_B64)
TX = Tx.parse(TX_HEX)


def wrapped(text: str, width: int = 64) -> str:
    """Wrap the base64 in lines: what a psbt out of an email looks like."""
    return "\n".join(text[i : i + width] for i in range(0, len(text), width))


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(PSBT_B64, id="base64"),
        pytest.param(PSBT_B64.encode("ascii"), id="base64 as bytes"),
        pytest.param(f"  {PSBT_B64}\n", id="base64 with blanks around it"),
        pytest.param(wrapped(PSBT_B64), id="base64 wrapped in lines"),
        pytest.param(PSBT.serialize().hex(), id="hex"),
        pytest.param(PSBT.serialize().hex().upper(), id="hex in upper case"),
        pytest.param(PSBT.serialize().hex().encode("ascii"), id="hex as bytes"),
        pytest.param(PSBT.serialize(), id="bytes"),
    ],
)
def test_a_psbt_in_any_encoding(data: String) -> None:
    """Parse the BIP174 creator psbt from every encoding offered."""
    parsed = tx_or_psbt_from_any(data)
    assert isinstance(parsed, Psbt)
    assert parsed == PSBT


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(TX_HEX, id="hex"),
        pytest.param(TX_HEX.upper(), id="hex in upper case"),
        pytest.param(f"\n{TX_HEX}  ", id="hex with blanks around it"),
        pytest.param(TX_HEX.encode("ascii"), id="hex as bytes"),
        pytest.param(TX.serialize(include_witness=True), id="bytes"),
    ],
)
def test_a_transaction_in_any_encoding(data: String) -> None:
    """Parse block 170's transaction from every encoding offered."""
    parsed = tx_or_psbt_from_any(data)
    assert isinstance(parsed, Tx)
    assert parsed == TX


def test_the_magic_is_what_tells_the_two_apart() -> None:
    """The five bytes, and not the shape of what follows them."""
    psbt_bin = PSBT.serialize()
    assert psbt_bin[:5] == b"psbt\xff"

    # the same bytes with the magic gone are read as a transaction, and
    # are not one: what the dispatcher decides is which parser answers,
    # and the parser is what refuses
    with pytest.raises(BTClibValueError):
        tx_or_psbt_from_any(psbt_bin[5:])


def test_check_validity_reaches_the_parser() -> None:
    """The flag is the parsers', and is passed on rather than acted on."""
    # a transaction with no outputs: Tx.assert_valid refuses it, and
    # parsing it without the check does not
    truncated = Tx.parse(TX_HEX, check_validity=False)
    truncated.vout = []
    octets = truncated.serialize(include_witness=False, check_validity=False)

    assert tx_or_psbt_from_any(octets, check_validity=False) == truncated
    with pytest.raises(BTClibValueError, match="Missing outputs"):
        tx_or_psbt_from_any(octets)


@pytest.mark.parametrize(
    "data, err_msg",
    [
        pytest.param("", "no data", id="an empty string"),
        pytest.param(b"", "no data", id="empty bytes"),
        pytest.param("   \n ", "no data", id="blanks"),
        pytest.param("not hex and not base64!", "neither hex nor base64", id="text"),
        pytest.param(
            # ascii, and neither encoding: read as the bytes it is, which
            # is where a transaction parser gives up -- on the outpoint of
            # the first of the inputs the fifth byte says are coming
            b"not hex and not base64!",
            "not enough data for the outpoint tx_id",
            id="text as bytes",
        ),
        pytest.param(
            b"\xff\xfe\x00 not text",
            "not enough data for the outpoint tx_id",
            id="bytes",
        ),
        pytest.param("70736274ff", "at least a map is missing", id="the magic alone"),
    ],
)
def test_what_is_neither(data: String, err_msg: str) -> None:
    """Refuse what is neither, with the message naming the failure."""
    with pytest.raises(BTClibValueError, match=err_msg):
        tx_or_psbt_from_any(data)


def test_hex_is_read_before_base64() -> None:
    """A hex-string of the right length is base64 of something else."""
    both = "deadbeef"
    # base64 reads four characters as three bytes, so a hex-string whose
    # length is divisible by four is one it can read whole -- into
    # something else, and there is no telling the two apart afterwards
    assert len(both) % 4 == 0
    assert base64.b64decode(both, validate=True) != bytes.fromhex(both)

    assert _octets_from_text(both) == bytes.fromhex(both)
