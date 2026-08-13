# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Non-regression tests for btclib.script."""

from collections.abc import Callable

import pytest

from btclib.alias import ScriptList
from btclib.exceptions import BTClibUserWarning
from btclib.script.script import serialize


def serialize_non_canonical(
    script: ScriptList, serializer: Callable[[ScriptList], bytes] = serialize
) -> bytes:
    """Serialize a number in [-1, 16] as data, asserting the warning.

    Zero excepted: its encoding is the empty vector, so its push is
    OP_0's byte already and `serialize` writes it without a word --
    calling this for it fails on the warning that never comes.

    Both serializers suggest the one-byte op code that means the same,
    and the tests calling this push the number as data on purpose;
    `serializer` says which of the two is under test. Asserting the
    suggestion at the single call that provokes it keeps
    `filterwarnings = ["error"]` in force everywhere else, which a
    `simplefilter("ignore")` around the caller did not: that hid every
    other warning raised in there as well.
    """
    with pytest.warns(BTClibUserWarning, match="consider using OP_"):
        return serializer(script)
