# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.script.op_codes_tapscript` module."""

import pytest

from btclib.exceptions import BTClibValueError
from btclib.script.op_codes_tapscript import _serialize_str_command


def test_invalid_op_success() -> None:
    """Refuse OP_SUCCESS numbers BIP342 does not define; 80 is 0x50."""
    err_msg = "invalid OP_SUCCESS number:"
    with pytest.raises(BTClibValueError, match=err_msg):
        _serialize_str_command("OP_SUCCESS1")
    err_msg = "invalid OP_SUCCESS number:"
    with pytest.raises(BTClibValueError, match=err_msg):
        _serialize_str_command("OP_SUCCESS173")

    assert _serialize_str_command("OP_SUCCESS80") == b"\x50"
