# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.script.op_codes_tapscript` module.

Two of these hold the tables to each other rather than to a copy of
BIP342's own numbers, which is what a table can be held to at all: a
transcription checked against a transcription answers whichever of the
two the reader trusted, and the numbers are the one thing here nobody
re-derives by eye.
"""

import pytest

from btclib.exceptions import BTClibValueError
from btclib.script.op_codes_tapscript import (
    OP_CODE_NAMES,
    OP_CODES,
    OP_SUCCESS,
    _serialize_str_command,
)

# a push of its own length, 0x01 to 0x4b, which is neither a named op code
# nor an OP_SUCCESS: the byte is the length and the data follows it
_DATA_PUSHES = frozenset(range(1, 0x4C))


def test_invalid_op_success() -> None:
    """Refuse OP_SUCCESS numbers BIP342 does not define; 80 is 0x50."""
    err_msg = "invalid OP_SUCCESS number:"
    with pytest.raises(BTClibValueError, match=err_msg):
        _serialize_str_command("OP_SUCCESS1")
    err_msg = "invalid OP_SUCCESS number:"
    with pytest.raises(BTClibValueError, match=err_msg):
        _serialize_str_command("OP_SUCCESS173")

    assert _serialize_str_command("OP_SUCCESS80") == b"\x50"


def test_the_two_tables_are_each_other_inverted() -> None:
    """Every name answers the code that names it back, and all of them do.

    `OP_CODES` maps a name to its byte and `OP_CODE_NAMES` the byte back
    to a name, so a number wrong in either is a script serialized as one
    thing and parsed as another. Both directions are asserted because
    each catches what the other cannot: a changed key in `OP_CODE_NAMES`
    fails the first, an entry dropped from it the second.

    `OP_CODES` holds the more entries of the two, and the difference is
    the aliases -- OP_FALSE for OP_0, OP_TRUE for OP_1, OP_NOP2 and
    OP_NOP3 for the two timelock verifications -- which share a byte with
    the name that byte answers to.
    """
    for code, name in OP_CODE_NAMES.items():
        assert OP_CODES[name] == bytes([code]), name

    named = {byte for (byte,) in OP_CODES.values()}
    assert named == set(OP_CODE_NAMES)


def test_op_success_is_what_the_tables_leave_over() -> None:
    """OP_SUCCESSx is every byte that is not a push and not a named code.

    BIP342 lists them -- 80, 98, 126-129, 131-134, 137-138, 141-142,
    149-153 and 187-254 -- and that list is the complement of what a
    tapscript may otherwise hold, which is what this asserts instead of
    the list: the opcodes disabled or undefined before taproot are
    exactly the ones it makes succeed. Written the other way round it
    would be BIP342's numbers checked against BIP342's numbers.

    0xFF is the one byte in neither set, and it is why the range above
    stops at 254: Core reads it as OP_INVALIDOPCODE, a value no script
    can carry rather than one a tapscript spends.
    """
    named = {byte for (byte,) in OP_CODES.values()}
    assert set(OP_SUCCESS) == set(range(0xFF)) - _DATA_PUSHES - named
    # a list rather than a set in the module, so it can hold a number
    # twice and cover for one it lost
    assert len(OP_SUCCESS) == len(set(OP_SUCCESS))
    assert 0xFF not in OP_SUCCESS
