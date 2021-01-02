#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.bip32_path` module."


import pytest

from btclib.bip32.der_path import (
    _HARDENING,
    _indexes_from_bip32_path_str,
    bytes_from_bip32_path,
    indexes_from_bip32_path,
    int_from_index_str,
    str_from_bip32_path,
    str_from_index_int,
)
from btclib.exceptions import BTClibValueError


def test_from_bip32_path_str() -> None:

    test_reg_str_vectors = [
        # account 0, external branch, address_index 463
        ("m/0" + _HARDENING + "/0/463", [0x80000000, 0, 463]),
        # account 0, internal branch, address_index 267
        ("m/0" + _HARDENING + "/1/267", [0x80000000, 1, 267]),
    ]

    for bip32_path_str, bip32_path_ints in test_reg_str_vectors:
        # recover ints from str
        assert bip32_path_ints == _indexes_from_bip32_path_str(bip32_path_str)
        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_str)
        # recover ints from ints
        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_ints)
        # recover str from str
        assert bip32_path_str == str_from_bip32_path(bip32_path_str)
        # recover str from ints
        assert bip32_path_str == str_from_bip32_path(bip32_path_ints)
        # ensure bytes from ints == bytes from str
        bip32_path_bytes = bytes_from_bip32_path(bip32_path_ints)
        assert bip32_path_bytes == bytes_from_bip32_path(bip32_path_str)
        # recover ints from bytes
        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_bytes)
        # recover str from bytes
        assert bip32_path_str == str_from_bip32_path(bip32_path_bytes)

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

    for bip32_path_str, bip32_path_ints in test_irregular_str_vectors:
        # recover ints from str
        assert bip32_path_ints == _indexes_from_bip32_path_str(bip32_path_str)
        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_str)
        # recover ints from ints
        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_ints)
        # irregular str != normalized str
        assert bip32_path_str != str_from_bip32_path(bip32_path_str)
        # irregular str != normalized str from ints
        assert bip32_path_str != str_from_bip32_path(bip32_path_ints)
        # ensure bytes from ints == bytes from str
        bip32_path_bytes = bytes_from_bip32_path(bip32_path_ints)
        assert bip32_path_bytes == bytes_from_bip32_path(bip32_path_str)
        # recover ints from bytes
        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_bytes)
        # irregular str != normalized str from bytes
        assert bip32_path_str != str_from_bip32_path(bip32_path_bytes)

    with pytest.raises(BTClibValueError, match="invalid index: "):
        _indexes_from_bip32_path_str("m/1/2/-3h/4")

    with pytest.raises(BTClibValueError, match="invalid index: "):
        _indexes_from_bip32_path_str("m/1/2/-3/4")

    i = 0x80000000

    with pytest.raises(BTClibValueError, match="invalid index: "):
        _indexes_from_bip32_path_str("m/1/2/" + str(i) + "/4")

    with pytest.raises(BTClibValueError, match="invalid index: "):
        _indexes_from_bip32_path_str("m/1/2/" + str(i) + "h/4")


def test_index_int_to_from_str() -> None:

    for i in (0, 1, 0x80000000 - 1, 0x80000000, 0xFFFFFFFF):
        assert i == int_from_index_str(str_from_index_int(i))

    for i in (-1, 0xFFFFFFFF + 1):
        with pytest.raises(BTClibValueError):
            str_from_index_int(i)

    for s in ("-1", "-1h", str(0x80000000) + "h", str(0xFFFFFFFF + 1)):
        with pytest.raises(BTClibValueError):
            int_from_index_str(s)

    with pytest.raises(BTClibValueError, match="invalid hardening symbol: "):
        str_from_index_int(0x80000000, "hardened")


def test_str_from_bip32_path() -> None:
    der_path = "/44h/0h"
    assert str_from_bip32_path(der_path) == "m" + der_path
    m_fngrprnt = "deadbeef"
    assert str_from_bip32_path(der_path, m_fngrprnt) == m_fngrprnt + der_path

    err_msg = "invalid master fingerprint length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        str_from_bip32_path(der_path, "baaaad")
