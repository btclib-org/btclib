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
from btclib.script.script import Command, Script, parse, serialize


def test_add_and_eq() -> None:
    script_1 = serialize(["OP_2", "OP_3", "OP_ADD", "OP_5"])
    script_2 = serialize(["OP_EQUAL"])
    assert Script(script_1) + Script(script_2) == Script(script_1 + script_2)

    with pytest.raises(TypeError):
        _ = Script(script_1) + script_2


def test_simple_scripts() -> None:
    script_list: List[List[Command]] = [
        ["OP_2", "OP_3", "OP_ADD", "OP_5", "OP_EQUAL"],
        [0x1ADD, "OP_1ADD", 0x1ADE, "OP_EQUAL"],
        [26, "OP_1NEGATE", "OP_ADD", 26, "OP_EQUAL"],
        [0x7FFFFFFF, "OP_1NEGATE", "OP_ADD", 0x7FFFFFFF, "OP_EQUAL"],
        [0x80000000, "OP_1NEGATE", "OP_ADD", 0x7FFFFFFF, "OP_EQUAL"],
        [0xFFFFFFFF - 1, "OP_1NEGATE", "OP_ADD", 0x7FFFFFFF, "OP_EQUAL"],
        [0xFFFFFFFF, "OP_1NEGATE", "OP_ADD", 0x7FFFFFFF, "OP_EQUAL"],
        ["1F" * 250, "OP_DROP"],
        ["1F" * 520, "OP_DROP"],
    ]
    for script_pub_key in script_list:
        assert script_pub_key == parse(serialize(script_pub_key))
        assert script_pub_key == parse(serialize(script_pub_key).hex())


def test_exceptions() -> None:

    script_pub_key: List[Command] = ["OP_2", "OP_3", "OP_ADD", "OP_5", "OP_RETURN_244"]
    err_msg = "invalid string command: OP_RETURN_244"
    with pytest.raises(BTClibValueError, match=err_msg):
        serialize(script_pub_key)

    with pytest.raises(TypeError):
        serialize(["OP_2", "OP_3", "OP_ADD", "OP_5", serialize])  # type: ignore

    err_msg = "too many bytes for OP_PUSHDATA: "
    with pytest.raises(BTClibValueError, match=err_msg):
        script_pub_key = ["1f" * 521, "OP_DROP"]
        serialize(script_pub_key)

    # A script_pub_key with OP_PUSHDATA4 can be decoded
    script_bytes = "4e09020000" + "00" * 521 + "75"  # ['00'*521, 'OP_DROP']
    script_pub_key_ = parse(script_bytes)
    # but it cannot be encoded
    err_msg = "too many bytes for OP_PUSHDATA: "
    with pytest.raises(BTClibValueError, match=err_msg):
        serialize(script_pub_key_)


def test_nulldata() -> None:

    scripts: List[List[Command]] = [["OP_RETURN", "11" * 79], ["OP_RETURN", "00" * 79]]
    for script_pub_key in scripts:
        assert script_pub_key == parse(serialize(script_pub_key))
        assert script_pub_key == parse(serialize(script_pub_key).hex())


def test_encoding():
    script_bytes = b"jKBIP141 \\o/ Hello SegWit :-) keep it strong! LLAP Bitcoin twitter.com/khs9ne"
    assert serialize(parse(script_bytes)) == script_bytes
