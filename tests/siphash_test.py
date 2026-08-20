# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core's SipHash-2-4 vectors.

The vectors are Core's `src/test/data/siphash.json`, entire; each row
splits its input into blocks that, joined back together, are the octets
`hashes.siphash` is called on -- `tests/_data/README.md` pins the
revision. A row also carries `expected.siphash13uj`, Core's unpadded
jumbo-block SipHash-1-3 (`crypto/siphash.h`'s `SipHasher13UJ`); btclib
implements no such hasher, so only `expected.siphash24` is read here.
"""

from __future__ import annotations

import pytest

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import siphash
from tests import load, vector_id

_VECTORS = load("_data", "siphash.json")

_MASK64 = 0xFFFFFFFFFFFFFFFF

VECTORS = [
    pytest.param(
        int(row["key"][0], 16),
        int(row["key"][1], 16),
        b"".join(bytes.fromhex(block) for block in row["input"]),
        int(row["expected"]["siphash24"], 16),
        id=vector_id(index, f"{sum(len(b) for b in row['input']) // 2}-bytes"),
    )
    for index, row in enumerate(_VECTORS)
]


@pytest.mark.parametrize("k0, k1, data, expected", VECTORS)
def test_vectors(k0: int, k1: int, data: bytes, expected: int) -> None:
    """Every one of Core's 146 SipHash-2-4 rows, byte for byte."""
    assert siphash(k0, k1, data) == expected


def test_empty_input() -> None:
    """The first three vectors are the empty message, under three keys."""
    assert siphash(0, 0, b"") == 0x1E924B9D737700D7
    assert siphash(0x0706050403020100, 0x0F0E0D0C0B0A0908, b"") == 0x726FDB47DD0E0E31
    assert siphash(_MASK64, _MASK64, b"") == 0x35DD279EE86CE565


def test_partial_and_multiple_words() -> None:
    """One byte short of a word, one word, and several words together.

    `siphash(k0, k1, b"".join(chunks))` for a multi-block vector row is
    the join every row above already exercises; this checks the two ends
    of that range directly, against the same key `_VECTORS` uses for its
    single-block rows.
    """
    k0, k1 = 0x0706050403020100, 0x0F0E0D0C0B0A0908
    one_word = bytes.fromhex("0001020304050607")
    assert siphash(k0, k1, one_word) == 0x93F5F5799A932462
    assert siphash(k0, k1, one_word[:7]) != siphash(k0, k1, one_word)
    two_words = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    assert siphash(k0, k1, two_words) == 0x3F2ACC7F57C29BDB


def test_key_boundaries() -> None:
    """k0 and k1 each accept 0 and 2**64 - 1, refusing one bit wider."""
    assert siphash(0, 0, b"") != siphash(_MASK64, _MASK64, b"")
    with pytest.raises(BTClibValueError, match="k0"):
        siphash(_MASK64 + 1, 0, b"")
    with pytest.raises(BTClibValueError, match="k0"):
        siphash(-1, 0, b"")
    with pytest.raises(BTClibValueError, match="k1"):
        siphash(0, _MASK64 + 1, b"")
    with pytest.raises(BTClibValueError, match="k1"):
        siphash(0, -1, b"")


def test_invalid_key_type() -> None:
    """A key word that is not an integer is a type error, not a value one.

    `bool` is excluded along with every other non-`int`: `is_integer`
    refuses it for the reason `var_int.serialize` does, a flag is not a
    number written down as one.
    """
    with pytest.raises(BTClibTypeError, match="k0"):
        siphash("0", 0, b"")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="k1"):
        siphash(0, True, b"")  # bool is an int, and not one is_integer allows


def test_invalid_input_type() -> None:
    """Octets that are neither bytes nor a hex string raise, as elsewhere."""
    with pytest.raises(BTClibTypeError, match="octets"):
        siphash(0, 0, ["not", "octets"])  # type: ignore[arg-type]


def test_hex_string_input() -> None:
    """A hex-string is one of the two spellings Octets accepts."""
    assert siphash(0, 0, "") == 0x1E924B9D737700D7
    assert (
        siphash(0x0706050403020100, 0x0F0E0D0C0B0A0908, "0001020304050607")
        == 0x93F5F5799A932462
    )
