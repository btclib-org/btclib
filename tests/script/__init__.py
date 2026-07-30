#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
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
