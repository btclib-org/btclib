#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.psbt_out` module"

from typing import Dict, List

from btclib.bip32_path import _HARDENING
from btclib.psbt_out import (
    PSBT_OUT_BIP32_DERIVATION,
    _assert_valid_hd_keypaths,
    _assert_valid_unknown,
    _decode_dict_bytes_bytes,
    _decode_hd_keypaths,
    _encode_dict_bytes_bytes,
    _encode_hd_keypaths,
    _serialize_dict_bytes_bytes,
)


def test_bip32_derivs() -> None:
    # the basic type dict representation
    encoded_data: List[Dict[str, str]] = [
        {
            "pub_key": "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f",
            "master_fingerprint": "d90c6a4f",
            "path": "m/0" + _HARDENING + "/0/0",
        },
        {
            "pub_key": "02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7",
            "master_fingerprint": "d90c6a4f",
            "path": "m/0" + _HARDENING + "/0/1",
        },
    ]
    data = _decode_hd_keypaths(encoded_data)
    _assert_valid_hd_keypaths(data)
    assert encoded_data == _encode_hd_keypaths(data)

    _serialize_dict_bytes_bytes(PSBT_OUT_BIP32_DERIVATION, data)
    # TODO: check deserialization


def test_unknown() -> None:
    # the json representation
    data: Dict[str, str] = {
        "baad": "deadbeef",
        "abadbabe": "cafebabe",
    }
    decoded_data: Dict[bytes, bytes] = _decode_dict_bytes_bytes(data)
    assert data == _encode_dict_bytes_bytes(decoded_data)

    _assert_valid_unknown(decoded_data)

    _serialize_dict_bytes_bytes(b"", decoded_data)
    # TODO: check deserialization
