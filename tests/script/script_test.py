#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.script.script` module."""

from __future__ import annotations

import pytest

from btclib.alias import ScriptList
from btclib.exceptions import BTClibValueError
from btclib.script import Script, op_int, parse, serialize
from btclib.script.script import (
    BYTE_FROM_OP_CODE_NAME,
    ERROR_COMMAND,
    OP_CODE_NAME_FROM_INT,
    op_code_spans,
    read_op_code,
)
from btclib.utils import hex_string
from tests.script import serialize_non_canonical


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
    b = b"\x0a" * length
    assert len(serialize([b])) == length + 1
    b = b"\x0a" * (length + 1)
    assert len(serialize([b])) == (length + 1) + 2

    length = 255
    b = b"\x0a" * length
    assert len(serialize([b])) == length + 2
    b = b"\x0a" * (length + 1)
    assert len(serialize([b])) == (length + 1) + 3


def test_add_and_eq() -> None:
    script_1 = serialize(["OP_2", "OP_3", "OP_ADD", "OP_5"])
    script_2 = serialize(["OP_EQUAL"])
    assert Script(script_1) + Script(script_2) == Script(script_1 + script_2)

    with pytest.raises(TypeError):
        _ = Script(script_1) + script_2  # type: ignore[operator]


def test_simple_scripts() -> None:
    script_list: list[ScriptList] = [
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
    script_pub_key: ScriptList = ["OP_2", "OP_3", "OP_ADD", "OP_5", "OP_RETURN_244"]
    err_msg = "invalid string command: OP_RETURN_244"
    with pytest.raises(BTClibValueError, match=err_msg):
        serialize(script_pub_key)

    with pytest.raises(TypeError):
        serialize(["OP_2", "OP_3", "OP_ADD", "OP_5", serialize])  # type: ignore[list-item]


def test_pushdata4_and_the_only_length_left_to_refuse() -> None:
    """All four push widths are written, and read back.

    A push over 520 bytes is one the stack cannot hold, i.e. a script
    nobody can spend, and there are such scripts on chain (issue #123):
    unspendable is not unencodable, so what serialize refuses is only a
    length no length field can carry.
    """
    for length, op_code, head in ((65535, 0x4D, 3), (65536, 0x4E, 5)):
        data = b"\x0a" * length
        script = serialize([data])
        assert script[0] == op_code
        assert len(script) == length + head
        assert parse(script) == [data.hex().upper()]

    # __len__ lies rather than have the test allocate four gibibytes
    class TooLong(bytes):
        def __len__(self) -> int:
            return 4294967296

    err_msg = "too many bytes for OP_PUSHDATA: "
    with pytest.raises(BTClibValueError, match=err_msg):
        serialize([TooLong()])


def test_nulldata() -> None:
    scripts: list[ScriptList] = [["OP_RETURN", "1A" * 79], ["OP_RETURN", "0A" * 79]]
    for script_pub_key in scripts:
        assert script_pub_key == parse(serialize(script_pub_key))
        assert script_pub_key == parse(serialize(script_pub_key).hex())


def test_encoding() -> None:
    script_bytes = b"jKBIP141 \\o/ Hello SegWit :-) keep it strong! LLAP Bitcoin twitter.com/khs9ne"
    assert serialize(parse(script_bytes)) == script_bytes


def test_truncated_push_ends_the_parse() -> None:
    """A push running past the end stops the walk, and marks the place.

    Core's GetOp returns false there and its ScriptToAsmStr appends the
    literal "[error]"; both are the only refusal a decode has, and this
    is that refusal. What follows the mark is not decoded, because there
    is nothing to decode it as -- and Esplora prints "<push past end>"
    at the same offset for the very scripts of issue #123.
    """
    # a length field cut short, and data short of its length
    assert parse(b"\x4e\x00") == [ERROR_COMMAND]
    assert parse(b"\x40\x00") == [ERROR_COMMAND]

    # what came before it is kept, and the mark is terminal
    assert parse(b"\x51\x4c\x05\xaa\xbb") == ["OP_1", ERROR_COMMAND]

    # the mark cannot be serialized back: it is a place, not a command,
    # where UNKNOWN_OP_CODE_n is a byte of an executable script and must
    # round-trip
    with pytest.raises(BTClibValueError, match=r"invalid string command: \[ERROR\]"):
        serialize([ERROR_COMMAND])

    # 0xff, Core's OP_INVALIDOPCODE, which no soft fork can name: an op
    # code all the same, refused by the interpreter that executes it and
    # named here so that serialize writes it back unchanged
    assert parse(b"\x01\x00\xff") == ["00", "UNKNOWN_OP_CODE_255"]
    assert serialize(parse(b"\x01\x00\xff")) == b"\x01\x00\xff"


def test_regressions() -> None:
    script_list: list[ScriptList] = [
        ["OP_1"],
        [51],
        [b"\x01"],
        ["01"],
        ["AA"],
        ["aa"],
        ["AAAA"],
        [""],
        [b""],
        ["OP_0"],
        ["OP_1NEGATE"],
        [0x81],
        ["81"],
    ]
    for s in script_list:
        serialized = serialize(s)
        assert serialize(parse(serialized)) == serialized

    # the three regressions that serialize() warns about, kept apart from
    # the others so that the warning is asserted rather than ignored: a
    # simplefilter("ignore") around the loop above would hide it, and
    # with it any other warning the loop raises
    non_canonical: list[ScriptList] = [[1], [0], [-1]]
    for s in non_canonical:
        serialized = serialize_non_canonical(s)
        assert serialize(parse(serialized)) == serialized


def test_null_serialization() -> None:
    empty_script: ScriptList = []
    assert empty_script == parse(b"")
    assert serialize(empty_script) == b""

    assert parse(serialize([""])) == ["OP_0"]
    assert parse(serialize([" "])) == ["OP_0"]
    assert parse(serialize([b""])) == ["OP_0"]
    assert parse(serialize([b" "])) == ["20"]

    # 0 and 16 have a one-byte op code, so pushing them as data warns
    assert serialize_non_canonical([0]) == b"\x01\x00"
    assert parse(serialize_non_canonical([0])) == ["00"]

    assert serialize_non_canonical([16]) == b"\x01\x10"
    assert parse(serialize_non_canonical([16])) == ["10"]

    # 17 has none, and warns not
    assert serialize([17]) == b"\x01\x11"
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

    # [0, 16] is exactly the range with a shorter op code form, so every
    # serialize() below warns; from 17 on, none does
    assert serialize_non_canonical([0]) != b"\x00"
    for i in range(1, 17):
        serialized_int = serialize_non_canonical([i])
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


def test_read_op_code() -> None:
    """The walk agrees with parse on where each op code ends.

    Which is all that is asked of it, and what makes a script code a
    slice: parse says what the op codes are, this says where they are.
    """
    for script, expected in (
        (b"", []),
        (b"\xac", [(0xAC, 0, 1)]),
        (b"\x00\x51", [(0x00, 0, 1), (0x51, 1, 2)]),  # OP_0 is not a push
        (b"\x01\xff\xac", [(0x01, 0, 2), (0xAC, 2, 3)]),
        (b"\x4c\x01\xff", [(0x4C, 0, 3)]),  # OP_PUSHDATA1 of the same byte
        (b"\x4d\x01\x00\xff", [(0x4D, 0, 4)]),  # OP_PUSHDATA2
        (b"\x4e\x01\x00\x00\x00\xff", [(0x4E, 0, 6)]),  # OP_PUSHDATA4
    ):
        spans = list(op_code_spans(script))
        assert spans == expected
        # the spans tile the script, and there are as many of them as
        # parse finds commands
        assert b"".join(script[start:stop] for _, start, stop in spans) == script
        assert len(spans) == len(parse(script))

    # nothing whole to read: past the end, and three ways to be truncated
    assert read_op_code(b"\xac", 1) is None
    assert read_op_code(b"\x02\xff", 0) is None  # data short of its length
    assert read_op_code(b"\x4c", 0) is None  # no length byte at all
    assert read_op_code(b"\x4d\x01", 0) is None  # half a length
    # a push over 520 bytes is not this walk's to refuse, as it is not
    # Core's GetOp's: the limit is on what reaches the stack
    assert read_op_code(b"\x4d\x09\x02" + b"\x00" * 521, 0) == (0x4D, 524)
