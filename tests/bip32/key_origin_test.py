# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bip32.key_origin` module."""

import pytest

from btclib.bip32 import (
    BIP32KeyOrigin,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    encode_to_bip32_derivs,
)
from btclib.bip32.der_path import _HARDENING
from btclib.exceptions import BTClibValueError
from tests.conftest import JsonGolden


def test_bip32_key_origin() -> None:
    """Parse descriptions in every hardening spelling; refuse bad ones."""
    with pytest.raises(BTClibValueError, match="invalid master fingerprint length: "):
        BIP32KeyOrigin("badbad", [0])

    with pytest.raises(BTClibValueError, match="invalid der_path size: "):
        BIP32KeyOrigin("deadbeef", [0] * 256)

    with pytest.raises(BTClibValueError, match="invalid der_path element"):
        BIP32KeyOrigin("deadbeef", [0xFFFFFFFF + 1])

    description = master_fingerprint = "deadbeef"
    key_origin = BIP32KeyOrigin.from_description(description)
    assert len(key_origin) == 0
    key_origin2 = BIP32KeyOrigin.from_description(f"{description}/")
    assert len(key_origin) == 0
    assert key_origin == key_origin2
    assert key_origin.description == description
    assert key_origin.master_fingerprint == bytes.fromhex(master_fingerprint)
    assert not key_origin.der_path
    assert BIP32KeyOrigin.parse(key_origin.serialize()) == key_origin
    assert BIP32KeyOrigin.from_dict(key_origin.to_dict()) == key_origin

    description = (  # use the hardening convention of the normalized der_path
        master_fingerprint
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
    assert key_origin.master_fingerprint == bytes.fromhex(master_fingerprint)
    assert key_origin.der_path == [
        44 + 0x80000000,
        0 + 0x80000000,
        1 + 0x80000000,
        0,
        10,
    ]
    assert BIP32KeyOrigin.parse(key_origin.serialize()) == key_origin
    assert BIP32KeyOrigin.from_dict(key_origin.to_dict()) == key_origin
    assert len(key_origin) == 5


def test_dataclasses_json_dict_key_origin(json_golden: JsonGolden) -> None:
    """Round-trip a BIP32KeyOrigin through dict, against the golden json."""
    key_origin = BIP32KeyOrigin.from_description("deadbeef//44h/0'/1H/0/10/")

    # BIP32KeyOrigin dataclass
    assert isinstance(key_origin, BIP32KeyOrigin)
    key_origin.assert_valid()

    # BIP32KeyOrigin dataclass to dict
    key_origin_dict = key_origin.to_dict()
    assert isinstance(key_origin_dict, dict)
    assert key_origin_dict["master_fingerprint"]
    assert key_origin_dict["path"]

    # against the json committed beside this module, not written to it
    json_golden("key_origin.json", key_origin_dict)

    # BIP32KeyOrigin dataclass from dict
    key_origin2 = BIP32KeyOrigin.from_dict(key_origin_dict)
    assert isinstance(key_origin2, BIP32KeyOrigin)
    key_origin2.assert_valid()

    assert key_origin == key_origin2


def test_bip32_derivs() -> None:
    """Round-trip bip32_derivs dicts; refuse duplicated key origins."""
    # the basic type dict representation
    bip32_derivs = [
        {
            "pub_key": "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f",
            "master_fingerprint": "d90c6a4f",
            "path": f"m/0{_HARDENING}/0/0",
        },
        {
            "pub_key": "02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7",
            "master_fingerprint": "d90c6a4f",
            "path": f"m/0{_HARDENING}/0/1",
        },
    ]
    hd_key_paths = decode_from_bip32_derivs(bip32_derivs)
    assert bip32_derivs == encode_to_bip32_derivs(hd_key_paths)

    assert_valid_hd_key_paths(hd_key_paths)

    bip32_derivs = [
        {
            "pub_key": "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f",
            "master_fingerprint": "d90c6a4f",
            "path": f"m/0{_HARDENING}/0/0",
        },
        {
            "pub_key": "02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7",
            "master_fingerprint": "d90c6a4f",
            "path": f"m/0{_HARDENING}/0/0",
        },
    ]
    hd_key_paths = decode_from_bip32_derivs(bip32_derivs)
    with pytest.raises(
        BTClibValueError, match="Duplicated key origin values in hd_key_paths"
    ):
        assert_valid_hd_key_paths(hd_key_paths)


def test_bip32_derivs_check_validity() -> None:
    """Check check_validity=False defers the fingerprint check (issue 264)."""
    # issue 264: check_validity=False lets a malformed master_fingerprint
    # through decode_from_bip32_derivs, the way every other check_validity
    # does -- deferred to assert_valid_hd_key_paths rather than refused here
    bip32_derivs = [
        {
            "pub_key": "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f",
            "master_fingerprint": "d90c6a",
            "path": f"m/0{_HARDENING}/0/0",
        },
    ]
    with pytest.raises(BTClibValueError, match="invalid size: "):
        decode_from_bip32_derivs(bip32_derivs)

    hd_key_paths = decode_from_bip32_derivs(bip32_derivs, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid master fingerprint length: "):
        assert_valid_hd_key_paths(hd_key_paths)
