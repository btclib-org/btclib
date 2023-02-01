#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for the `btclib.script.taproot` module."""

import json
from os import path

import pytest

from btclib import b32
from btclib.ec import mult
from btclib.exceptions import BTClibValueError
from btclib.script import (
    TaprootScriptTree,
    Witness,
    check_output_pubkey,
    input_script_sig,
    is_p2tr,
    output_prvkey,
    output_pubkey,
    parse,
    serialize,
    type_and_payload,
)
from btclib.tx import TxOut


def test_valid_script_path() -> None:
    fname = "tapscript_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, encoding="ascii") as file_:
        data = json.load(file_)

    for x in data:
        prevouts = [TxOut.parse(prevout) for prevout in x["prevouts"]]
        index = x["index"]

        if not is_p2tr(prevouts[index].script_pub_key.script):
            continue

        script_sig = x["success"]["scriptSig"]
        assert not script_sig

        witness = Witness(x["success"]["witness"])
        if len(witness.stack) >= 2 and witness.stack[-1][0] == 0x50:
            witness.stack = witness.stack[:-1]

        # check script paths
        if len(witness.stack) < 2:
            continue

        Q = type_and_payload(prevouts[index].script_pub_key.script)[1]

        script = witness.stack[-2]
        control = witness.stack[-1]

        assert check_output_pubkey(Q, script, control)


def test_taproot_key_tweaking() -> None:
    prv_key = 123456
    pub_key = mult(prv_key)

    script_trees = [
        None,
        [(0xC0, ["OP_1"])],
        [[(0xC0, ["OP_2"])], [(0xC0, ["OP_3"])]],
    ]

    for script_tree in script_trees:
        tweaked_prvkey = output_prvkey(prv_key, script_tree)
        tweaked_pubkey = output_pubkey(pub_key, script_tree)[0]

        assert tweaked_pubkey == mult(tweaked_prvkey)[0].to_bytes(32, "big")


def test_invalid_control_block() -> None:
    err_msg = "control block too long"
    with pytest.raises(BTClibValueError, match=err_msg):
        check_output_pubkey(b"\x00" * 32, b"\x00", b"\x00" * 4130)

    err_msg = "invalid control block length"
    with pytest.raises(BTClibValueError, match=err_msg):
        check_output_pubkey(b"\x00" * 32, b"\x00", b"\x00" * 100)


def test_unspendable_script() -> None:
    err_msg = "missing data"
    with pytest.raises(BTClibValueError, match=err_msg):
        output_pubkey()


def test_control_block() -> None:
    script_tree = [[(0xC0, ["OP_2"])], [(0xC0, ["OP_3"])]]
    pub_key = output_pubkey(None, script_tree)[0]
    script, control = input_script_sig(None, script_tree, 0)
    assert check_output_pubkey(pub_key, serialize(script), control)

    prv_key = 123456
    internal_pubkey = mult(prv_key)
    script_tree = [[(0xC0, ["OP_2"])], [(0xC0, ["OP_3"])]]
    pub_key = output_pubkey(internal_pubkey, script_tree)[0]
    script, control = input_script_sig(internal_pubkey, script_tree, 0)
    assert check_output_pubkey(pub_key, serialize(script), control)


def convert_script_tree(script_tree: TaprootScriptTree) -> TaprootScriptTree:
    if isinstance(script_tree, list):
        return [convert_script_tree(x) for x in script_tree]
    if isinstance(script_tree, dict):
        return [[script_tree["leafVersion"], parse(script_tree["script"])]]
    return []


def test_bip_test_vector() -> None:
    fname = "taproot_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, encoding="ascii") as file_:
        data = json.load(file_)["scriptPubKey"]

    for test in data:
        pub_key = test["given"]["internalPubkey"]
        script_tree = convert_script_tree(test["given"]["scriptTree"])

        tweaked_pubkey = output_pubkey(f"02{pub_key}", script_tree)[0]
        address = b32.p2tr(f"02{pub_key}", script_tree)

        assert tweaked_pubkey.hex() == test["intermediary"]["tweakedPubkey"]
        assert address == test["expected"]["bip350Address"]
