#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.script` module."

import pytest

from btclib.script import (
    OP_CODE_NAMES,
    OP_CODES,
    _op_int,
    _op_pushdata,
    decode,
    deserialize,
    encode,
    serialize,
)


def test_operators():
    for i in OP_CODE_NAMES.keys():
        b = OP_CODES[OP_CODE_NAMES[i]]
        assert i == b[0]
    for name in OP_CODES.keys():
        # skip duplicated
        if name in ("OP_FALSE", "OP_TRUE", "OP_NOP2", "OP_NOP3"):
            continue
        i = OP_CODES[name][0]
        assert name == OP_CODE_NAMES[i]
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
        assert i in OP_CODE_NAMES.keys()


def test_simple():
    script_list = [
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
    for script in script_list:
        script_bytes = encode(script)
        script2 = decode(script_bytes)
        assert script == script2
        script_bytes2 = encode(script2)
        assert script_bytes == script_bytes2
        script_serialized = serialize(script)
        script3 = deserialize(script_serialized)
        assert script == script3
        script4 = deserialize(script_serialized.hex())
        assert script == script4


def test_exceptions():

    script = [2, 3, "OP_ADD", 5, "OP_VERIF"]
    err_msg = "invalid string token: OP_VERIF"
    with pytest.raises(ValueError, match=err_msg):
        encode(script)

    script = [2, 3, "OP_ADD", 5, encode]
    err_msg = "Unmanaged <class 'function'> token type"
    with pytest.raises(ValueError, match=err_msg):
        encode(script)

    script = ["1f" * 521, "OP_DROP"]
    err_msg = "Too many bytes for OP_PUSHDATA: "
    with pytest.raises(ValueError, match=err_msg):
        encode(script)

    # A script with OP_PUSHDATA4 can be decoded
    script_bytes = "4e09020000" + "00" * 521 + "75"  # ['00'*521, 'OP_DROP']
    script = decode(script_bytes)
    # but it cannot be encoded
    err_msg = "Too many bytes for OP_PUSHDATA: "
    with pytest.raises(ValueError, match=err_msg):
        encode(script)


def test_nulldata():

    scripts = [["OP_RETURN", "11" * 79], ["OP_RETURN", "00" * 79]]
    for script in scripts:
        bscript = encode(script)
        assert script == decode(bscript)


def test_op_int():
    i = 0b01111111
    assert len(_op_int(i)) == 2
    i = 0b11111111
    assert len(_op_int(i)) == 3
    i = 0b0111111111111111
    assert len(_op_int(i)) == 3
    i = 0b1111111111111111
    assert len(_op_int(i)) == 4


def test_encoding():
    script_bytes = b"jKBIP141 \\o/ Hello SegWit :-) keep it strong! LLAP Bitcoin twitter.com/khs9ne"
    assert encode(decode(script_bytes)) == script_bytes


def test_op_pushdata():
    length = 75
    b = "00" * length
    assert len(_op_pushdata(b)) == length + 1
    b = "00" * (length + 1)
    assert len(_op_pushdata(b)) == (length + 1) + 2

    length = 255
    b = "00" * length
    assert len(_op_pushdata(b)) == length + 2
    b = "00" * (length + 1)
    assert len(_op_pushdata(b)) == (length + 1) + 3
