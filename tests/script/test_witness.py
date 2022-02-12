#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.script.witness` module."

import json
from os import path

from btclib.script.witness import Witness


def test_witness() -> None:
    witness = Witness()
    assert not witness.stack
    assert len(witness) == 0
    witness.assert_valid()
    assert witness == Witness.parse(witness.serialize())
    assert witness == Witness.from_dict(witness.to_dict())

    stack = [
        "",
        "3044022077ecafa04bc23f87057bd54b572a473cf5cc6a945c167fcefe561618b86d097002200eb7c62a855295c8c288ff972c58905861a98260dafb6f8b7587cfda3091e00d01",
        "3045022100f20ba32865985e66985ba2d7ad11950309e253788b2edb27ccf5899e806f43ef02202899d98360f6476fcefbbf1dc1813595f4d0807d13237218de5ffaaeaa85640101",
        "304402206f7f5b0723d61f5d9f2ecbae448646d4cf0cf3ecade5ab50867fdfe8e131ce8f02207f0c260620e41dbdecd6ce574bf2773de248178d33f24aee71627843560137cd01",
        "01",
        "635321024713c6e66da107644c64ab84189840e78310b247cc7fa563d6f98f2a46900a0d21026cb4cc5bbde0e59806657b1780a9a3b333a8acb6fcac48ade7d52e2b34aa30042102b6615b55426b7362cd82897db26b1423e3732f98eaea5cd2c150c49a46003c6521033557edc1a6aec5a28648f6e22deb542e9ee8c9219d5bb5e81d0fe23c8f955ad221039d7f91444b2d4c4e89a1f550fa7d32c5d9b75a49b14c54f10109d95f637bb7de2103d9cdf5c6da8b2fd66fa918916cc93d831f16781c01ca759c9cf60acf94268bbd56ae67029000b275522102d02570ed9db9ee6abd13a6c269758debcfaa1aa6d0857553e5b6a5cf764ffe0a21030968209ccaaae1c0f8ee7a4a3594b3504fd3f89db1c259aedbdce3aba29f219321036069299a8a990474eb34786bf446e724088896a54bf848650c9543f18af602dc53ae68",
    ]
    witness = Witness(stack)
    assert len(witness) == 6
    witness.assert_valid()
    assert witness == Witness.parse(witness.serialize())
    assert witness == Witness.from_dict(witness.to_dict())


def test_dataclasses_json_dict() -> None:
    witness_bytes = "0600483045022100a2c452a28dc58984d809e445bc9429d2e5023eafc6b070e64655928034409b7e022071de7f967b0f2e3e99d636b6e5497197cd2d4dbea81c8b42f8f0a9a8709987b701483045022100cace5cc666336fd9b620f5853d0e344da3bf2face0ac28c968240a635efe71ea022000c8bf8aafeab9c62a0815efcbc11890a742d0baee9be652b316060be54dde750147304402202ed13a2a660020e030c40a49378c507e86ec73d05c59b045b8502126630a03e3022051b6160547ac9604cc30ecfbdab66545783182b8ea30ceac657366ccea08575b010101fd1e0163532102ccb438a1d9fae7aaff5c058949f0768d4fa24671f1c43643f194098316a854752102f3448accdbf6e648ff8c9c591797b57ebfbd7bab0e2a4fcaeba686f9a9df58e121033a1229e67ad80e37234edafda3fc9dc02a2e5d70e7d861c11c94515d178edaf52103519b8d8f86813e07852728d31338f1d1d772865bf4792aa87d6f1ceb1e348fcd2103cd36dabe3dfd4e473a5a62a97a40b2e6bb47bb502bcf13163c91262f0604a06855ae67029000b27552210219d79d15338a4596b2a5dc88d191e0ae85fbfdd30802a18b3c3ff0d1c1c7c6f121025dedb64d7e5046f62b506ae9ec391ab15e70acb8d3d98c5527a481526a25d4f62103cee6fe19333a1b2e11e424bb106dfe4bc61daa273badb1de86c19dbc9037cdcd53ae68"
    witness = Witness.parse(witness_bytes)

    # Witness dataclass
    assert isinstance(witness, Witness)
    assert witness.stack
    assert len(witness.stack) > 0

    # Witness dataclass to dict
    witness_dict = witness.to_dict()
    assert isinstance(witness_dict, dict)
    assert witness_dict["stack"]
    assert len(witness_dict["stack"]) > 0  # type: ignore

    # Witness dataclass dict to file
    datadir = path.join(path.dirname(__file__), "_generated_files")
    filename = path.join(datadir, "witness.json")
    with open(filename, "w", encoding="ascii") as file_:
        json.dump(witness_dict, file_, indent=4)

    # Witness dataclass dict from file
    with open(filename, "r", encoding="ascii") as file_:
        witness_dict2 = json.load(file_)
    assert isinstance(witness_dict2, dict)
    assert witness_dict2["stack"]
    assert len(witness_dict2["stack"]) > 0  # type: ignore

    assert witness_dict == witness_dict2

    # Witness dataclass from dict
    witness2 = Witness.from_dict(witness_dict)
    assert isinstance(witness2, Witness)
    assert witness2.stack
    assert len(witness2.stack) > 0

    assert witness == witness2
