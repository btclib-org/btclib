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

from btclib import bip32, hashes
from btclib.bip32_path import (
    _HARDENING,
    BIP32KeyOrigin,
    BIP32KeyPath,
    BIP32KeyPaths,
    _assert_valid_hd_key_paths,
    _decode_hd_key_paths,
    _indexes_from_bip32_path_str,
    _int_from_index_str,
    _serialize_hd_key_paths,
    _str_from_index_int,
    bytes_from_bip32_path,
    indexes_from_bip32_path,
    str_from_bip32_path,
)
from btclib.exceptions import BTClibValueError


def test_indexes_from_bip32_path_str() -> None:

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

    invalid_key_origin = BIP32KeyOrigin(
        bytes.fromhex("badbad"), [0], check_validity=False
    )
    with pytest.raises(BTClibValueError, match="invalid master fingerprint length: "):
        invalid_key_origin.assert_valid()

    invalid_key_origin = BIP32KeyOrigin(
        bytes.fromhex("deadbeef"), [0] * 256, check_validity=False
    )
    with pytest.raises(BTClibValueError, match="invalid der_path size: "):
        invalid_key_origin.assert_valid()

    invalid_key_origin = BIP32KeyOrigin(
        bytes.fromhex("deadbeef"), [0xFFFFFFFF + 1], check_validity=False
    )
    with pytest.raises(BTClibValueError, match="invalid der_path element"):
        invalid_key_origin.assert_valid()

    fingerprint = "deadbeef"
    description = fingerprint
    key_origin = BIP32KeyOrigin.from_description(description)
    key_origin2 = BIP32KeyOrigin.from_description(description + "/")
    assert key_origin == key_origin2
    assert key_origin.description == description
    assert key_origin.fingerprint == bytes.fromhex(fingerprint)
    assert key_origin.der_path == []
    assert BIP32KeyOrigin.deserialize(key_origin.serialize()) == key_origin

    description = (  # use the hardening convention of the normalized der_path
        fingerprint
        + "/44"
        + _HARDENING
        + "/0"
        + _HARDENING
        + "/1"
        + _HARDENING
        + "/0/10"
    )
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
    assert len(key_origin) == 5


def test_dataclasses_json_dict_key_origin() -> None:

    key_origin = BIP32KeyOrigin.from_description("deadbeef//44h/0'/1H/0/10/")

    # BIP32KeyOrigin dataclass
    assert isinstance(key_origin, BIP32KeyOrigin)
    key_origin.assert_valid()

    # BIP32KeyOrigin dataclass to dict
    key_origin_dict = key_origin.to_dict()
    assert isinstance(key_origin_dict, dict)
    assert key_origin_dict["master_fingerprint"]
    assert key_origin_dict["path"]

    # BIP32KeyOrigin dataclass dict to file
    datadir = path.join(path.dirname(__file__), "generated_files")
    filename = path.join(datadir, "key_origin.json")
    with open(filename, "w") as file_:
        json.dump(key_origin_dict, file_, indent=4)

    # BIP32KeyOrigin dataclass dict from file
    with open(filename, "r") as file_:
        key_origin_dict2 = json.load(file_)
    assert isinstance(key_origin_dict2, dict)
    assert key_origin_dict["master_fingerprint"]
    assert key_origin_dict["path"]

    assert key_origin_dict == key_origin_dict2

    # BIP32KeyOrigin dataclass from dict
    key_origin2 = BIP32KeyOrigin.from_dict(key_origin_dict)
    assert isinstance(key_origin2, BIP32KeyOrigin)
    key_origin2.assert_valid()

    assert key_origin == key_origin2


def test_bip32_key_path() -> None:

    pub_key = bytes.fromhex(
        "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    )
    invalid_key_origin = BIP32KeyOrigin(
        bytes.fromhex("badbad"), [0], check_validity=False
    )
    invalid_key_path = BIP32KeyPath(pub_key, invalid_key_origin, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid master fingerprint length: "):
        invalid_key_path.assert_valid()

    fingerprint = "deadbeef"
    der_path = "/44h/0h/1h/0/10"
    description = fingerprint + der_path
    key_origin = BIP32KeyOrigin.from_description(description)
    assert len(key_origin) == 5

    key_path = BIP32KeyPath(pub_key, key_origin)
    assert key_path == BIP32KeyPath.deserialize(key_path.serialize())
    assert len(key_path) == len(key_origin)


def test_dataclasses_json_dict_key_path() -> None:

    fingerprint = "deadbeef"
    der_path = "/44'/0'/1'/0/10"
    description = fingerprint + der_path
    key_origin = BIP32KeyOrigin.from_description(description)
    pub_key = bytes.fromhex(
        "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    )
    key_path = BIP32KeyPath(pub_key, key_origin)

    # BIP32KeyPath dataclass
    assert isinstance(key_path, BIP32KeyPath)

    # BIP32KeyPath dataclass to dict
    key_path_dict = key_path.to_dict()
    assert isinstance(key_path_dict, dict)
    assert key_path_dict["pub_key"]
    assert key_path_dict["key_origin"]

    # BIP32KeyPath dataclass dict to file
    datadir = path.join(path.dirname(__file__), "generated_files")
    filename = path.join(datadir, "key_path.json")
    with open(filename, "w") as file_:
        json.dump(key_path_dict, file_, indent=4)

    # BIP32KeyPath dataclass dict from file
    with open(filename, "r") as file_:
        key_path_dict2 = json.load(file_)
    assert isinstance(key_path_dict2, dict)
    assert key_path_dict2["pub_key"]
    assert key_path_dict2["key_origin"]

    assert key_path_dict == key_path_dict2

    # BIP32KeyPath dataclass from dict
    key_path2 = BIP32KeyPath.from_dict(key_path_dict)
    assert isinstance(key_path2, BIP32KeyPath)

    assert key_path == key_path2


_MARKER = b"\x11"


def test_bip32_derivs() -> None:
    # the basic type dict representation
    encoded_data = [
        {
            "pub_key": "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f",
            "key_origin": {
                "master_fingerprint": "d90c6a4f",
                "path": "m/0" + _HARDENING + "/0/0",
            },
        },
        {
            "pub_key": "02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7",
            "key_origin": {
                "master_fingerprint": "d90c6a4f",
                "path": "m/0" + _HARDENING + "/0/1",
            },
        },
    ]
    data = _decode_hd_key_paths(encoded_data)
    _assert_valid_hd_key_paths(data)
    # assert encoded_data == _encode_hd_key_paths(data)

    _serialize_hd_key_paths(_MARKER, data)
    # TODO: check deserialization


def test_bip32_key_paths() -> None:

    master_xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    fingerprint = hashes.fingerprint(master_xprv)

    der_path0 = "m/44h/0h/1h/0/0"
    der_path1 = "m/44h/0h/1h/0/1"
    der_path2 = "m/44h/0h/1h/0/2"

    pub_key0 = bip32._xpub_from_xprv(bip32._derive(master_xprv, der_path0))
    pub_key1 = bip32._xpub_from_xprv(bip32._derive(master_xprv, der_path1))
    pub_key2 = bip32._xpub_from_xprv(bip32._derive(master_xprv, der_path2))

    hd_key_paths = {
        # FIXME: allow BIP32KeyOrigin with der_path string
        pub_key0.key: BIP32KeyOrigin(fingerprint, indexes_from_bip32_path(der_path0)),
        pub_key1.key: BIP32KeyOrigin(fingerprint, indexes_from_bip32_path(der_path1)),
        pub_key2.key: BIP32KeyOrigin(fingerprint, indexes_from_bip32_path(der_path2)),
    }

    key_paths = BIP32KeyPaths(hd_key_paths)
    assert len(key_paths) == len(hd_key_paths)

    key_paths_bin = key_paths.serialize(b"\x00")
    key_paths_deser = BIP32KeyPaths.deserialize(key_paths_bin, b"\x00")
    assert len(key_paths_deser) == len(hd_key_paths)
    assert key_paths == key_paths_deser

    with pytest.raises(BTClibValueError, match="invalid type marker"):
        key_paths.serialize(b"\x00\x00")
    with pytest.raises(BTClibValueError, match="invalid type marker"):
        BIP32KeyPaths.deserialize(key_paths_bin, b"\x00\x00")


def test_dataclasses_json_dict_key_paths() -> None:

    master_xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    fingerprint = hashes.fingerprint(master_xprv)

    der_path0 = "m/44h/0h/1h/0/0"
    der_path1 = "m/44h/0h/1h/0/1"
    der_path2 = "m/44h/0h/1h/0/2"

    pub_key0 = bip32._xpub_from_xprv(bip32._derive(master_xprv, der_path0))
    pub_key1 = bip32._xpub_from_xprv(bip32._derive(master_xprv, der_path1))
    pub_key2 = bip32._xpub_from_xprv(bip32._derive(master_xprv, der_path2))

    hd_key_paths = {
        # FIXME: allow BIP32KeyOrigin with der_path string
        pub_key0.key: BIP32KeyOrigin(fingerprint, indexes_from_bip32_path(der_path0)),
        pub_key1.key: BIP32KeyOrigin(fingerprint, indexes_from_bip32_path(der_path1)),
        pub_key2.key: BIP32KeyOrigin(fingerprint, indexes_from_bip32_path(der_path2)),
    }

    key_paths = BIP32KeyPaths(hd_key_paths)

    # BIP32KeyPaths dataclass
    assert isinstance(key_paths, BIP32KeyPaths)

    # BIP32KeyPaths dataclass to dict
    key_path_dicts = key_paths.to_dict()
    assert isinstance(key_path_dicts, dict)

    # BIP32KeyPaths dataclass dict to file
    datadir = path.join(path.dirname(__file__), "generated_files")
    filename = path.join(datadir, "key_paths.json")
    with open(filename, "w") as file_:
        json.dump(key_path_dicts, file_, indent=4)

    # BIP32KeyPaths dataclass dict from file
    with open(filename, "r") as file_:
        key_path_dict2 = json.load(file_)
    assert isinstance(key_path_dict2, dict)

    assert key_path_dicts == key_path_dict2

    # BIP32KeyPaths dataclass from dict
    key_path2 = BIP32KeyPaths.from_dict(key_path_dicts)
    assert isinstance(key_path2, BIP32KeyPaths)

    assert key_paths == key_path2
