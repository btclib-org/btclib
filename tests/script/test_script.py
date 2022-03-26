#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.script.script` module."

import warnings
from typing import List

import pytest

from btclib.script.script import (
    BYTE_FROM_OP_CODE_NAME,
    OP_CODE_NAME_FROM_INT,
    BTClibValueError,
    Command,
    Script,
    _serialize_str_command,
    op_int,
    parse,
    serialize,
)
from btclib.utils import hex_string


def test_operators() -> None:
    for i, name in OP_CODE_NAME_FROM_INT.items():
        b = BYTE_FROM_OP_CODE_NAME[name]
        assert i == b[0]
    for name, code in BYTE_FROM_OP_CODE_NAME.items():
        # skip duplicated
        if name in ("OP_FALSE", "OP_TRUE", "OP_NOP2", "OP_NOP3"):
            continue
        i = code[0]
        assert name == OP_CODE_NAME_FROM_INT[i]
    for i in range(76, 186):
        # skip disabled 'splice' opcodes
        if i in (126, 127, 128, 129):
            continue
        # skip disabled 'bitwise logic' opcodes
        if i in (131, 132, 133, 134):
            continue
        # skip disabled 'splice' opcodes
        if i in (141, 142, 149, 150, 151, 152, 152, 153):
            continue
        # skip 'reserved' opcodes
        if i in (80, 98, 101, 102, 137, 138):
            continue
        assert i in OP_CODE_NAME_FROM_INT


def test_op_int() -> None:
    assert op_int(-1) == "OP_1NEGATE"
    for i in range(17):
        assert op_int(i) == f"OP_{i}"

    err_msg = "invalid OP_INT: "
    with pytest.raises(BTClibValueError, match=err_msg):
        op_int(17)


def test_serialize_bytes_command() -> None:
    length = 75
    b = b"\x0A" * length
    assert len(serialize([b])) == length + 1
    b = b"\x0A" * (length + 1)
    assert len(serialize([b])) == (length + 1) + 2

    length = 255
    b = b"\x0A" * length
    assert len(serialize([b])) == length + 2
    b = b"\x0A" * (length + 1)
    assert len(serialize([b])) == (length + 1) + 3


def test_invalid_op_success() -> None:
    err_msg = "invalid OP_SUCCESS number:"
    with pytest.raises(BTClibValueError, match=err_msg):
        _serialize_str_command("OP_SUCCESS1")
    err_msg = "invalid OP_SUCCESS number:"
    with pytest.raises(BTClibValueError, match=err_msg):
        _serialize_str_command("OP_SUCCESS173")

    assert _serialize_str_command("OP_SUCCESS80") == b"\x50"


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
        serialized_script = serialize(script_pub_key)
        assert serialized_script == serialize(parse(serialized_script))
        assert serialized_script == serialize(parse(serialized_script.hex()))


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

    # A script_pub_key with OP_PUSHDATA4 can't be decoded
    script_bytes = "4e09020000" + "0A" * 521 + "75"  # ['0A'*521, 'OP_DROP']
    err_msg = "Invalid pushdata length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(script_bytes)

    # and can't be encoded
    script_pub_key_ = ["0A" * 521, "OP_DROP"]
    err_msg = "too many bytes for OP_PUSHDATA: "
    with pytest.raises(BTClibValueError, match=err_msg):
        serialize(script_pub_key_)


def test_nulldata() -> None:

    scripts: List[List[Command]] = [["OP_RETURN", "1A" * 79], ["OP_RETURN", "0A" * 79]]
    for script_pub_key in scripts:
        assert script_pub_key == parse(serialize(script_pub_key))
        assert script_pub_key == parse(serialize(script_pub_key).hex())


def test_encoding() -> None:
    script_bytes = b"jKBIP141 \\o/ Hello SegWit :-) keep it strong! LLAP Bitcoin twitter.com/khs9ne"
    assert serialize(parse(script_bytes)) == script_bytes


def test_opcode_length() -> None:
    err_msg = "Not enough data for pushdata length"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(b"\x4e\x00")
    err_msg = "Not enough data for pushdata"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(b"\x40\x00")

    assert parse(b"\x01\x00\x50")[1] == "OP_SUCCESS80"
    assert parse(b"\x01\x00\x50", exit_on_op_success=True) == ["OP_SUCCESS"]


def test_regressions() -> None:
    script_list: List[List[Command]] = [
        [1],
        ["OP_1"],
        [51],
        [b"\x01"],
        ["01"],
        ["AA"],
        ["aa"],
        ["AAAA"],
        [0],
        [""],
        [b""],
        ["OP_0"],
        [-1],
        ["OP_1NEGATE"],
        [0x81],
        ["81"],
    ]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        for s in script_list:
            serialized = serialize(s)
            assert serialize(parse(serialized)) == serialized


def test_null_serialization() -> None:

    empty_script: List[Command] = []
    assert empty_script == parse(b"")
    assert serialize(empty_script) == b""

    assert parse(serialize([""])) == ["OP_0"]
    assert parse(serialize([" "])) == ["OP_0"]
    assert parse(serialize([b""])) == ["OP_0"]
    assert parse(serialize([b" "])) == ["20"]

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        assert serialize([0]) == b"\x01\x00"
        assert parse(serialize([0])) == ["00"]

        assert serialize([16]) == b"\x01\x10"
        assert serialize([17]) == b"\x01\x11"
        assert parse(serialize([16])) == ["10"]
        assert parse(serialize([17])) == ["11"]

    assert serialize(["10"]) == b"\x01\x10"
    assert serialize(["11"]) == b"\x01\x11"

    assert serialize(["OP_16"]) == b"\x60"
    assert parse(serialize(["OP_16"])) == ["OP_16"]


def test_op_int_serialization() -> None:

    for i in range(-1, 17):
        op_int_str = f"OP_{i}" if i > -1 else "OP_1NEGATE"
        serialized_op_int = serialize([op_int_str])
        assert len(serialized_op_int) == 1
        assert [op_int_str] == parse(serialized_op_int)


def test_integer_serialization() -> None:

    assert ["OP_0"] == parse(b"\x00")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert serialize([0]) != b"\x00"
        for i in range(1, 17):
            serialized_int = serialize([i])
            assert [hex_string(i)] == parse(serialized_int)

    for i in range(17, 128):
        serialized_int = serialize([i])  # e.g., i = 26
        assert [hex_string(i)] == parse(serialized_int)

    for i in range(128, 256):
        serialized_int = serialize([i])


def test_single_byte_serialization() -> None:

    for i in range(256):
        hex_str = hex_string(i)  # e.g., "1A"
        serialized_byte = serialize([hex_str])
        assert len(serialized_byte) == 2
        assert serialized_byte[0] == 1
        assert [hex_str] == parse(serialized_byte)
