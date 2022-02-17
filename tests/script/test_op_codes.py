#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.script.op_codes` module."

import pytest

from btclib.script.op_codes import (
    BYTE_FROM_OP_CODE_NAME,
    OP_CODE_NAME_FROM_INT,
    BTClibValueError,
    op_int,
    op_pushdata,
    op_str,
)


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


def test_op_pushdata() -> None:
    length = 75
    b = "0A" * length
    assert len(op_pushdata(b)) == length + 1
    b = "0A" * (length + 1)
    assert len(op_pushdata(b)) == (length + 1) + 2

    length = 255
    b = "0A" * length
    assert len(op_pushdata(b)) == length + 2
    b = "0A" * (length + 1)
    assert len(op_pushdata(b)) == (length + 1) + 3


def test_invalid_op_success() -> None:
    err_msg = "invalid OP_SUCCESS number:"
    with pytest.raises(BTClibValueError, match=err_msg):
        op_str("OP_SUCCESS1")
    err_msg = "invalid OP_SUCCESS number:"
    with pytest.raises(BTClibValueError, match=err_msg):
        op_str("OP_SUCCESS173")

    assert op_str("OP_SUCCESS80") == b"\x50"
