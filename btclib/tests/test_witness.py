#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.witness` module."

import json
from os import path
from typing import List

import pytest

from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError
from btclib.witness import Witness


def test_serialization() -> None:
    items: List[Octets] = [
        "",
        "3045022100a2c452a28dc58984d809e445bc9429d2e5023eafc6b070e64655928034409b7e022071de7f967b0f2e3e99d636b6e5497197cd2d4dbea81c8b42f8f0a9a8709987b701",
        "3045022100cace5cc666336fd9b620f5853d0e344da3bf2face0ac28c968240a635efe71ea022000c8bf8aafeab9c62a0815efcbc11890a742d0baee9be652b316060be54dde7501",
        "304402202ed13a2a660020e030c40a49378c507e86ec73d05c59b045b8502126630a03e3022051b6160547ac9604cc30ecfbdab66545783182b8ea30ceac657366ccea08575b01",
        "01",
        "63532102ccb438a1d9fae7aaff5c058949f0768d4fa24671f1c43643f194098316a854752102f3448accdbf6e648ff8c9c591797b57ebfbd7bab0e2a4fcaeba686f9a9df58e121033a1229e67ad80e37234edafda3fc9dc02a2e5d70e7d861c11c94515d178edaf52103519b8d8f86813e07852728d31338f1d1d772865bf4792aa87d6f1ceb1e348fcd2103cd36dabe3dfd4e473a5a62a97a40b2e6bb47bb502bcf13163c91262f0604a06855ae67029000b27552210219d79d15338a4596b2a5dc88d191e0ae85fbfdd30802a18b3c3ff0d1c1c7c6f121025dedb64d7e5046f62b506ae9ec391ab15e70acb8d3d98c5527a481526a25d4f62103cee6fe19333a1b2e11e424bb106dfe4bc61daa273badb1de86c19dbc9037cdcd53ae68",
    ]
    witness = Witness(items)
    witness_bin = witness.serialize()
    assert Witness().deserialize(witness_bin) == witness


def test_exceptions() -> None:
    witness = Witness("bad script")  # type: ignore
    with pytest.raises(BTClibTypeError, match="invalid witness"):
        witness.assert_valid()

    witness = Witness([b"", "", (32, 33)])  # type: ignore
    with pytest.raises(AttributeError, match="has no attribute 'hex'"):
        witness.assert_valid()


def test_dataclasses_json_dict() -> None:
    witness_bytes = "0600483045022100a2c452a28dc58984d809e445bc9429d2e5023eafc6b070e64655928034409b7e022071de7f967b0f2e3e99d636b6e5497197cd2d4dbea81c8b42f8f0a9a8709987b701483045022100cace5cc666336fd9b620f5853d0e344da3bf2face0ac28c968240a635efe71ea022000c8bf8aafeab9c62a0815efcbc11890a742d0baee9be652b316060be54dde750147304402202ed13a2a660020e030c40a49378c507e86ec73d05c59b045b8502126630a03e3022051b6160547ac9604cc30ecfbdab66545783182b8ea30ceac657366ccea08575b010101fd1e0163532102ccb438a1d9fae7aaff5c058949f0768d4fa24671f1c43643f194098316a854752102f3448accdbf6e648ff8c9c591797b57ebfbd7bab0e2a4fcaeba686f9a9df58e121033a1229e67ad80e37234edafda3fc9dc02a2e5d70e7d861c11c94515d178edaf52103519b8d8f86813e07852728d31338f1d1d772865bf4792aa87d6f1ceb1e348fcd2103cd36dabe3dfd4e473a5a62a97a40b2e6bb47bb502bcf13163c91262f0604a06855ae67029000b27552210219d79d15338a4596b2a5dc88d191e0ae85fbfdd30802a18b3c3ff0d1c1c7c6f121025dedb64d7e5046f62b506ae9ec391ab15e70acb8d3d98c5527a481526a25d4f62103cee6fe19333a1b2e11e424bb106dfe4bc61daa273badb1de86c19dbc9037cdcd53ae68"

    # dataclass
    witness_data = Witness.deserialize(witness_bytes)
    assert isinstance(witness_data, Witness)

    # Witness to/from dict
    witness_dict = witness_data.to_dict()
    assert isinstance(witness_dict, dict)
    assert witness_data == Witness.from_dict(witness_dict)

    datadir = path.join(path.dirname(__file__), "generated_files")

    # Witness dict to/from dict file
    filename = path.join(datadir, "witness.json")
    with open(filename, "w") as file_:
        json.dump(witness_dict, file_, indent=4)
    with open(filename, "r") as file_:
        witness_dict2 = json.load(file_)
    assert isinstance(witness_dict2, dict)
    assert witness_dict == witness_dict2
