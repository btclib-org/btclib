# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bip32.der_path` module."""

import pytest

from btclib.bip32 import (
    bytes_from_der_path,
    hardenings_from_der_path,
    indexes_from_der_path,
    int_from_index_str,
    str_from_der_path,
    str_from_index_int,
)
from btclib.bip32.der_path import _HARDENING, _indexes_from_der_path_str
from btclib.exceptions import BTClibValueError


def test_from_der_path_str() -> None:
    """Convert der paths between str, ints and bytes; refuse bad indexes."""
    test_reg_str_vectors = [
        # account 0, external branch, address_index 463
        (f"m/0{_HARDENING}/0/463", [0x80000000, 0, 463]),
        # account 0, internal branch, address_index 267
        (f"m/0{_HARDENING}/1/267", [0x80000000, 1, 267]),
    ]

    for der_path_str, der_path_ints in test_reg_str_vectors:
        # recover ints from str
        assert der_path_ints == _indexes_from_der_path_str(der_path_str)
        assert der_path_ints == indexes_from_der_path(der_path_str)
        # recover ints from ints
        assert der_path_ints == indexes_from_der_path(der_path_ints)
        # recover str from str
        assert der_path_str == str_from_der_path(der_path_str)
        # recover str from ints
        assert der_path_str == str_from_der_path(der_path_ints)
        # ensure bytes from ints == bytes from str
        der_path_bytes = bytes_from_der_path(der_path_ints)
        assert der_path_bytes == bytes_from_der_path(der_path_str)
        # recover ints from bytes
        assert der_path_ints == indexes_from_der_path(der_path_bytes)
        # recover str from bytes
        assert der_path_str == str_from_der_path(der_path_bytes)

    test_irregular_str_vectors = [
        # account 0, external branch, address_index 463
        ("m / 0 h / 0 / 463", [0x80000000, 0, 463]),
        ("m / 0 H / 0 / 463", [0x80000000, 0, 463]),
        ("m // 0' / 0 / 463", [0x80000000, 0, 463]),
        # account 0, internal branch, address_index 267
        ("m / 0 h / 1 / 267", [0x80000000, 1, 267]),
        ("m / 0 H / 1 / 267", [0x80000000, 1, 267]),
        ("m // 0' / 1 / 267", [0x80000000, 1, 267]),
    ]

    for der_path_str, der_path_ints in test_irregular_str_vectors:
        # recover ints from str
        assert der_path_ints == _indexes_from_der_path_str(der_path_str)
        assert der_path_ints == indexes_from_der_path(der_path_str)
        # recover ints from ints
        assert der_path_ints == indexes_from_der_path(der_path_ints)
        # irregular str != normalized str
        assert der_path_str != str_from_der_path(der_path_str)
        # irregular str != normalized str from ints
        assert der_path_str != str_from_der_path(der_path_ints)
        # ensure bytes from ints == bytes from str
        der_path_bytes = bytes_from_der_path(der_path_ints)
        assert der_path_bytes == bytes_from_der_path(der_path_str)
        # recover ints from bytes
        assert der_path_ints == indexes_from_der_path(der_path_bytes)
        # irregular str != normalized str from bytes
        assert der_path_str != str_from_der_path(der_path_bytes)

    with pytest.raises(BTClibValueError, match="invalid index: "):
        _indexes_from_der_path_str("m/1/2/-3h/4")

    with pytest.raises(BTClibValueError, match="invalid index: "):
        _indexes_from_der_path_str("m/1/2/-3/4")

    i = 0x80000000

    with pytest.raises(BTClibValueError, match="invalid index: "):
        _indexes_from_der_path_str(f"m/1/2/{i}/4")

    with pytest.raises(BTClibValueError, match="invalid index: "):
        _indexes_from_der_path_str(f"m/1/2/{i}h/4")


def test_index_int_to_from_str() -> None:
    """Round-trip indexes at the 32-bit bounds; refuse what lies beyond."""
    for i in (0, 1, 0x80000000 - 1, 0x80000000, 0xFFFFFFFF):
        assert i == int_from_index_str(str_from_index_int(i))

    for i in (-1, 0xFFFFFFFF + 1):
        with pytest.raises(BTClibValueError, match="invalid index: "):
            str_from_index_int(i)

    for s in ("-1", "-1h", f"{0x80000000}h", f"{0xFFFFFFFF + 1}"):
        with pytest.raises(BTClibValueError, match="invalid index: "):
            int_from_index_str(s)

    with pytest.raises(BTClibValueError, match="invalid hardening symbol: "):
        str_from_index_int(0x80000000, "hardened")


def test_str_from_der_path() -> None:
    """Prefix the path with m or the fingerprint; refuse a bad fingerprint."""
    der_path = "/44h/0h"
    assert str_from_der_path(der_path) == f"m{der_path}"
    m_fngrprnt = "deadbeef"
    assert str_from_der_path(der_path, m_fngrprnt) == m_fngrprnt + der_path

    err_msg = "invalid master fingerprint length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        str_from_der_path(der_path, "baaaad")


def test_three_symbols_are_read_and_two_are_written() -> None:
    """Read h, H and ', write the two BIP380 allows."""
    for symbol in ("h", "H", "'"):
        assert int_from_index_str(f"0{symbol}") == 0x80000000

    for hardening in ("h", "'"):
        step = str_from_index_int(0x80000000, hardening)
        assert step == f"0{hardening}"
        assert int_from_index_str(step) == 0x80000000

    # BIP380 lists an uppercase H among its invalid hardened indicators,
    # so it is a step this module reads and never writes
    with pytest.raises(BTClibValueError, match="invalid hardening symbol: "):
        str_from_index_int(0x80000000, "H")


def test_bip380_enforced_reads_two_symbols() -> None:
    """Refuse under BIP380 what the BIP32 reading takes."""
    for step in ("0h", "0'", "2147483647h", "0"):
        assert int_from_index_str(step) == int_from_index_str(
            step, bip380_enforced=True
        )

    # what the BIP32 reading takes and BIP380's grammar does not: its own
    # invalid hardened indicators, and the numbers `int` alone accepts
    for step in ("0H", "-0", "+1", "1_0", " 0 h"):
        assert isinstance(int_from_index_str(step), int)
        with pytest.raises(BTClibValueError, match="invalid derivation index: "):
            int_from_index_str(step, bip380_enforced=True)

    # and what neither reading takes, as an error of its own rather than
    # as the bare ValueError of `int`
    for step in ("0f", "", "0hh"):
        for enforced in (False, True):
            with pytest.raises(BTClibValueError, match="invalid derivation index: "):
                int_from_index_str(step, bip380_enforced=enforced)

    # the number is still held to a BIP32 index
    with pytest.raises(BTClibValueError, match="invalid index: "):
        int_from_index_str("2147483648", bip380_enforced=True)

    # BIP380's grammar has neither a leading m nor an empty step, both of
    # which the lenient reading of a whole path drops
    assert indexes_from_der_path("m/0h/") == [0x80000000]
    for path in ("m/0h", "0h/"):
        with pytest.raises(BTClibValueError, match="invalid derivation index: "):
            indexes_from_der_path(path, bip380_enforced=True)


def test_hardenings_from_der_path() -> None:
    """Report the symbol each step was spelled with, "" where there is none."""
    # BIP380's own valid vector with mixed indicators
    assert hardenings_from_der_path("0'/0h/0'") == ["'", "h", "'"]
    assert indexes_from_der_path("0'/0h/0'") == [0x80000000] * 3

    assert hardenings_from_der_path("m/44h/0'/1H/0/10") == ["h", "'", "H", "", ""]
    assert hardenings_from_der_path("m/44h/0'/1h") == ["h", "'", "h"]
    assert hardenings_from_der_path("0/1") == ["", ""]
    assert hardenings_from_der_path("") == []

    # only a string spells anything: every other DerPath says nothing,
    # one entry per index all the same
    for der_path in ([0x80000000, 1], 0x80000000, bytes.fromhex("00000080")):
        indexes = indexes_from_der_path(der_path)
        assert hardenings_from_der_path(der_path) == [""] * len(indexes)

    assert hardenings_from_der_path("0h/1", bip380_enforced=True) == ["h", ""]
    with pytest.raises(BTClibValueError, match="invalid derivation index: "):
        hardenings_from_der_path("0H/1", bip380_enforced=True)
