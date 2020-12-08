#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.bip32_path` module."

import json
from os import path

import pytest

from btclib.bip32_path import (
    BIP32KeyOrigin,
    _indexes_from_bip32_path_str,
    _int_from_index_str,
    _str_from_index_int,
    bytes_from_bip32_path,
    indexes_from_bip32_path,
    str_from_bip32_path,
)
from btclib.exceptions import BTClibValueError


def test_indexes_from_bip32_path_str() -> None:

    test_vectors = [
        # account 0, external branch, address_index 463
        ("m / 0 h / 0 / 463", [0x80000000, 0, 463]),
        ("m / 0 H / 0 / 463", [0x80000000, 0, 463]),
        ("m // 0' / 0 / 463", [0x80000000, 0, 463]),
        # account 0, internal branch, address_index 267
        ("m / 0 h / 1 / 267", [0x80000000, 1, 267]),
        ("m / 0 H / 1 / 267", [0x80000000, 1, 267]),
        ("m // 0' / 1 / 267", [0x80000000, 1, 267]),
    ]

    for bip32_path_str, bip32_path_ints in test_vectors:
        assert bip32_path_ints == _indexes_from_bip32_path_str(bip32_path_str)

        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_str, "big")
        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_str, "little")

        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_ints, "big")
        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_ints, "little")

        bip32_path_bytes = bytes_from_bip32_path(bip32_path_ints, "big")
        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_bytes, "big")
        bip32_path_bytes = bytes_from_bip32_path(bip32_path_ints, "little")
        assert bip32_path_ints == indexes_from_bip32_path(bip32_path_bytes, "little")
        assert bip32_path_ints != indexes_from_bip32_path(bip32_path_bytes, "big")

        bip32_path_str = str_from_bip32_path(bip32_path_str, "little")
        assert bip32_path_str == str_from_bip32_path(bip32_path_ints, "little")
        assert bip32_path_str == str_from_bip32_path(bip32_path_bytes, "little")

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
        assert i == _int_from_index_str(_str_from_index_int(i))

    for i in (-1, 0xFFFFFFFF + 1):
        with pytest.raises(BTClibValueError):
            _str_from_index_int(i)

    for s in ("-1", "-1h", str(0x80000000) + "h", str(0xFFFFFFFF + 1)):
        with pytest.raises(BTClibValueError):
            _int_from_index_str(s)

    with pytest.raises(BTClibValueError, match="invalid hardening symbol: "):
        _str_from_index_int(0x80000000, "hardened")


def test_bip32_key_origin() -> None:

    with pytest.raises(BTClibValueError, match="invalid master fingerprint length: "):
        BIP32KeyOrigin()

    with pytest.raises(BTClibValueError, match="invalid der_path size: "):
        BIP32KeyOrigin(bytes.fromhex("deadbeef"), [0] * 256)

    with pytest.raises(BTClibValueError, match="invalid der_path element"):
        BIP32KeyOrigin(bytes.fromhex("deadbeef"), [0xFFFFFFFF + 1])

    fingerprint = "deadbeef"
    description = fingerprint
    key_origin = BIP32KeyOrigin.from_description(description)
    key_origin2 = BIP32KeyOrigin.from_description(description + "/")
    assert key_origin == key_origin2
    assert key_origin.description == description
    assert key_origin.fingerprint == bytes.fromhex(fingerprint)
    assert key_origin.der_path == []
    assert BIP32KeyOrigin.deserialize(key_origin.serialize()) == key_origin

    description = fingerprint + "/44'/0'/1'/0/10"
    key_origin = BIP32KeyOrigin.from_description(description)
    key_origin2 = BIP32KeyOrigin.from_description("deadbeef//44h/0'/1H/0/10/")
    assert key_origin == key_origin2
    assert key_origin.description == description
    assert key_origin.fingerprint == bytes.fromhex(fingerprint)
    assert key_origin.der_path == [
        44 + 0x80000000,
        0 + 0x80000000,
        1 + 0x80000000,
        0,
        10,
    ]
    assert BIP32KeyOrigin.deserialize(key_origin.serialize()) == key_origin


def test_dataclasses_json_dict() -> None:

    key_origin = BIP32KeyOrigin.from_description("deadbeef//44h/0'/1H/0/10/")

    # BIP32KeyOrigin dataclass
    assert isinstance(key_origin, BIP32KeyOrigin)
    assert key_origin.fingerprint
    assert key_origin.description

    # BIP32KeyOrigin dataclass to dict
    key_origin_dict = key_origin.to_dict()
    assert isinstance(key_origin_dict, dict)
    assert key_origin_dict["fingerprint"]
    assert key_origin_dict["der_path"]

    # BIP32KeyOrigin dataclass dict to file
    datadir = path.join(path.dirname(__file__), "generated_files")
    filename = path.join(datadir, "key_origin.json")
    with open(filename, "w") as file_:
        json.dump(key_origin_dict, file_, indent=4)

    # BIP32KeyOrigin dataclass dict from file
    with open(filename, "r") as file_:
        key_origin_dict2 = json.load(file_)
    assert isinstance(key_origin_dict2, dict)
    assert key_origin_dict["fingerprint"]
    assert key_origin_dict["der_path"]

    assert key_origin_dict == key_origin_dict2

    # BIP32KeyOrigin dataclass from dict
    key_origin2 = BIP32KeyOrigin.from_dict(key_origin_dict)
    assert isinstance(key_origin2, BIP32KeyOrigin)
    assert key_origin.fingerprint
    assert key_origin.description

    assert key_origin == key_origin2
