#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.script.script` module."

from typing import List

import pytest

from btclib.exceptions import BTClibValueError
from btclib.script import script


def test_simple_scripts() -> None:
    script_list: List[List[script.Command]] = [
        [2, 3, "OP_ADD", 5, "OP_EQUAL"],
        ["1ADD", "OP_1ADD", "1ADE", "OP_EQUAL"],
        [hex(26)[2:].upper(), -1, "OP_ADD", hex(26)[2:].upper(), "OP_EQUAL"],
        [
            hex(0xFFFFFFFF)[2:].upper(),
            -1,
            "OP_ADD",
            hex(0xFFFFFFFF)[2:].upper(),
            "OP_EQUAL",
        ],
        ["1F" * 250, "OP_DROP"],
        ["1F" * 520, "OP_DROP"],
    ]
    for script_pub_key in script_list:
        assert script_pub_key == script.parse(script.serialize(script_pub_key))
        assert script_pub_key == script.parse(script.serialize(script_pub_key).hex())


def test_exceptions() -> None:

    script_pub_key: List[script.Command] = [2, 3, "OP_ADD", 5, "OP_RETURN_244"]
    err_msg = "invalid string command: OP_RETURN_244"
    with pytest.raises(BTClibValueError, match=err_msg):
        script.serialize(script_pub_key)

    with pytest.raises(TypeError):
        script.serialize([2, 3, "OP_ADD", 5, script.serialize])  # type: ignore

    err_msg = "Too many bytes for OP_PUSHDATA: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pub_key = ["1f" * 521, "OP_DROP"]
        script.serialize(script_pub_key)

    # A script_pub_key with OP_PUSHDATA4 can be decoded
    script_bytes = "4e09020000" + "00" * 521 + "75"  # ['00'*521, 'OP_DROP']
    script_pub_key_ = script.parse(script_bytes)
    # but it cannot be encoded
    err_msg = "Too many bytes for OP_PUSHDATA: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script.serialize(script_pub_key_)


def test_nulldata() -> None:

    scripts: List[List[script.Command]] = [
        ["OP_RETURN", "11" * 79],
        ["OP_RETURN", "00" * 79],
    ]
    for script_pub_key in scripts:
        assert script_pub_key == script.parse(script.serialize(script_pub_key))
        assert script_pub_key == script.parse(script.serialize(script_pub_key).hex())


def test_encoding():
    script_bytes = b"jKBIP141 \\o/ Hello SegWit :-) keep it strong! LLAP Bitcoin twitter.com/khs9ne"
    assert script.serialize(script.parse(script_bytes)) == script_bytes
