#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.script.op_codes` module."

import pytest

from btclib.script.op_codes import (
    OP_CODE_NAMES,
    OP_CODES,
    BTClibValueError,
    decode_num,
    encode_num,
    op_int,
    op_num,
    op_pushdata,
)


def test_operators() -> None:
    for i in OP_CODE_NAMES:
        b = OP_CODES[OP_CODE_NAMES[i]]
        assert i == b[0]
    for name in OP_CODES:
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


def test_op_num() -> None:
    "test correct number of bytes in integer encoding"

    # 7 bits + sign bit = 8 bits = 1 byte (plus 1 byte for length)
    i = 0b01111111
    assert len(op_num(i)) == 2
    # 8 bits + sign bit = 9 bits = 2 byte (plus 1 byte for length)
    i = 0b11111111
    assert len(op_num(i)) == 3
    # 15 bits + sign bit = 16 bits = 2 byte (plus 1 byte for length)
    i = 0b0111111111111111
    assert len(op_num(i)) == 3
    # 16 bits + sign bit = 17 bits = 3 byte (plus 1 byte for length)
    i = 0b1111111111111111
    assert len(op_num(i)) == 4


def test_op_int() -> None:
    assert op_int(-1) == "OP_1NEGATE"
    for i in range(17):
        assert op_int(i) == "OP_" + str(i)

    err_msg = "invalid OP_INT: "
    with pytest.raises(BTClibValueError, match=err_msg):
        op_int(17)


def test_encode_num() -> None:

    for i in range(-255, 256):
        assert decode_num(encode_num(i)) == i

    for i in [
        0x80FF,
        0xFFFF,
        0x80FFFF,
        0xFFFFFF,
        0x80FFFFFF,
        0xFFFFFFFF,
        0x80FFFFFFFF,
        0xFFFFFFFFFF,
    ]:
        assert decode_num(encode_num(i - 1)) == i - 1
        assert decode_num(encode_num(i)) == i
        assert decode_num(encode_num(i + 1)) == i + 1

        assert decode_num(encode_num(-i - 1)) == -i - 1
        assert decode_num(encode_num(-i)) == -i
        assert decode_num(encode_num(-i + 1)) == -i + 1


def test_op_pushdata() -> None:
    length = 75
    b = "00" * length
    assert len(op_pushdata(b)) == length + 1
    b = "00" * (length + 1)
    assert len(op_pushdata(b)) == (length + 1) + 2

    length = 255
    b = "00" * length
    assert len(op_pushdata(b)) == length + 2
    b = "00" * (length + 1)
    assert len(op_pushdata(b)) == (length + 1) + 3
