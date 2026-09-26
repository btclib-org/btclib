# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""btclib's input coercions and btclib_ecc's copies of them agree.

A value a caller hands to btclib may be read by either package: by
`btclib.utils` where btclib reads it, by `btclib_ecc._utils` where a
name bound again from btclib_ecc does (issue #2282). Two copies of one
coercion that answer one input differently would make the same argument
valid through one import path and refused through the other. So each
vector below goes through both, and each must come back with the same value,
or be refused by both with the same message and a class of the same
built-in family: `BTClibValueError` against `BTClibEccValueError`, and
so on, the two packages' bases being different by design.

`btclib_ecc._utils` is private, and this test reaches it anyway: its
subject is the agreement of the two copies, and publishing the coercions
would make them btclib_ecc API for a test's sake.
"""

from __future__ import annotations

from collections.abc import Callable
from inspect import isfunction
from io import BytesIO
from typing import Any

import pytest

# private on purpose: two copies' agreement is the subject (issue #2282, Rule 3)
from btclib_ecc import _utils as btclib_ecc_utils

from btclib import utils as btclib_utils

_FAMILIES = (ValueError, TypeError, RuntimeError)


def _stream_read_once(octets: bytes) -> BytesIO:
    """Return a stream of `octets` with its first octet already read."""
    stream = BytesIO(octets)
    stream.read(1)
    return stream


# (the function's name, a factory of its arguments): a factory, because a
# stream is consumed by the first copy that reads it and the second copy
# has to be handed one of its own
_VECTORS: tuple[tuple[str, Callable[[], tuple[Any, ...]]], ...] = (
    ("bytes_from_octets", lambda: (b"\x01\x02",)),
    ("bytes_from_octets", lambda: ("0102",)),
    ("bytes_from_octets", lambda: (" 01 02 ",)),
    ("bytes_from_octets", lambda: ("",)),
    ("bytes_from_octets", lambda: ("not hex at all",)),
    ("bytes_from_octets", lambda: ("012",)),
    ("bytes_from_octets", lambda: (bytearray(b"ab"),)),
    ("bytes_from_octets", lambda: (memoryview(b"ab"),)),
    ("bytes_from_octets", lambda: (None,)),
    ("bytes_from_octets", lambda: (1.5,)),
    ("bytes_from_octets", lambda: (True,)),
    ("bytes_from_octets", lambda: ((1, 2),)),
    ("bytes_from_octets", lambda: (b"ab", 2)),
    ("bytes_from_octets", lambda: (b"ab", 3)),
    ("bytes_from_octets", lambda: (b"ab", (2, 3))),
    ("bytes_from_octets", lambda: (b"ab", (1, 3))),
    ("bytesio_from_binarydata", lambda: (b"ab",)),
    ("bytesio_from_binarydata", lambda: ("6162",)),
    ("bytesio_from_binarydata", lambda: (BytesIO(b"ab"),)),
    ("bytesio_from_binarydata", lambda: (None,)),
    ("bytesio_from_binarydata", lambda: ("zz",)),
    ("hex_string", lambda: (0,)),
    ("hex_string", lambda: (1,)),
    ("hex_string", lambda: (2**64 + 1,)),
    ("hex_string", lambda: (-1,)),
    ("hex_string", lambda: ("ff",)),
    ("hex_string", lambda: (b"\x01\x00",)),
    ("hex_string", lambda: (True,)),
    ("hex_string", lambda: (None,)),
    ("hex_string", lambda: (1.5,)),
    ("int_from_bits", lambda: (b"\xff", 4)),
    ("int_from_bits", lambda: (b"\xff\x00", 4)),
    ("int_from_bits", lambda: (b"\xff", 16)),
    ("int_from_bits", lambda: ("ff", 8)),
    ("int_from_bits", lambda: (None, 8)),
    ("int_from_integer", lambda: (0,)),
    ("int_from_integer", lambda: (-1,)),
    ("int_from_integer", lambda: ("ff",)),
    ("int_from_integer", lambda: (b"\x01\x00",)),
    ("int_from_integer", lambda: ("not hex at all",)),
    ("int_from_integer", lambda: (True,)),
    ("int_from_integer", lambda: (None,)),
    ("int_from_integer", lambda: (1.5,)),
    ("is_integer", lambda: (1,)),
    ("is_integer", lambda: (True,)),
    ("is_integer", lambda: (1.0,)),
    ("is_integer", lambda: ("1",)),
    ("is_octets", lambda: (b"a",)),
    ("is_octets", lambda: ("61",)),
    ("is_octets", lambda: (bytearray(b"a"),)),
    ("is_octets", lambda: (memoryview(b"a"),)),
    ("is_octets", lambda: (1,)),
    ("is_octets", lambda: (None,)),
    ("str_from_string", lambda: ("abc", "label")),
    ("str_from_string", lambda: (b"abc", "label")),
    ("str_from_string", lambda: (bytearray(b"abc"), "label")),
    ("str_from_string", lambda: (b"\xff", "label")),
    ("str_from_string", lambda: (None, "label")),
    ("str_from_string", lambda: (1, "label")),
    ("assert_type", lambda: (1, int, "count")),
    ("assert_type", lambda: ("1", int, "count")),
    ("assert_type", lambda: (True, int, "count")),
    ("read_exactly", lambda: (BytesIO(b"abc"), 2, "field")),
    ("read_exactly", lambda: (BytesIO(b"a"), 2, "field")),
    ("read_exactly", lambda: (BytesIO(b""), 0, "field")),
    ("assert_no_trailing", lambda: (b"ab", _stream_read_once(b"ab"), "object")),
    ("assert_no_trailing", lambda: (b"a", _stream_read_once(b"a"), "object")),
)


def _outcome(function: Callable[..., Any], args: tuple[Any, ...]) -> tuple[Any, ...]:
    """Return the answer, or the refusal's built-in family and message."""
    try:
        answer = function(*args)
    except _FAMILIES as e:
        family = next(f for f in _FAMILIES if isinstance(e, f))
        return "refused", family, str(e)
    if isinstance(answer, BytesIO):
        return "answered", answer.getvalue()
    return "answered", answer


@pytest.mark.parametrize(
    "name, args",
    _VECTORS,
    ids=[f"{name}-{index}" for index, (name, _) in enumerate(_VECTORS)],
)
def test_both_copies_answer_alike(
    name: str, args: Callable[[], tuple[Any, ...]]
) -> None:
    """The same value, or the same refusal, from either package's copy."""
    ours = _outcome(getattr(btclib_utils, name), args())
    theirs = _outcome(getattr(btclib_ecc_utils, name), args())
    assert ours == theirs


def test_every_shared_coercion_has_a_vector() -> None:
    """A coercion the two copies share and no vector drives is not held.

    Found rather than listed: a function added to both modules has to gain
    a vector here. The private helpers are left out, being what the public
    ones call, and so are the type aliases the two modules both name.
    """
    shared = {
        n
        for n in btclib_utils.__all__
        if isfunction(getattr(btclib_utils, n)) and hasattr(btclib_ecc_utils, n)
    }
    assert shared == {name for name, _ in _VECTORS}
