#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for the `btclib.script.op_codes_tapscript` module."""


import pytest

from btclib.exceptions import BTClibValueError
from btclib.script.op_codes_tapscript import _serialize_str_command


def test_invalid_op_success() -> None:
    err_msg = "invalid OP_SUCCESS number:"
    with pytest.raises(BTClibValueError, match=err_msg):
        _serialize_str_command("OP_SUCCESS1")
    err_msg = "invalid OP_SUCCESS number:"
    with pytest.raises(BTClibValueError, match=err_msg):
        _serialize_str_command("OP_SUCCESS173")

    assert _serialize_str_command("OP_SUCCESS80") == b"\x50"
