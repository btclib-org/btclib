#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Btclib.script.engine non-regression tests."""

import warnings

from btclib.exceptions import BTClibUserWarning
from btclib.script.script import BYTE_FROM_OP_CODE_NAME, serialize


def parse_script(bitcoin_core_script: str) -> str:
    script_pub_key = ""
    for y in bitcoin_core_script.split():
        if y[:2] == "0x":
            script_pub_key += y[2:]
        elif y[1:].isdigit():
            # a vector spelling a number in [-1, 16] as a decimal is
            # asking for the data push, not for the op code that means
            # the same, so the suggestion serialize() emits is noise
            # here. It is silenced at the one call that provokes it, and
            # by category: with filterwarnings = ["error"] anything else
            # any vector raises still fails the suite, which a
            # simplefilter("ignore") around the loop did not
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", BTClibUserWarning)
                script_pub_key += serialize([int(y)]).hex()
        elif y[0] == "'" and y[-1] == "'":
            script_pub_key += serialize([bytes(y[1:-1], "ascii")]).hex()
        else:
            if y[:3] != "OP_":
                y = f"OP_{y}"
            script_pub_key += BYTE_FROM_OP_CODE_NAME[y].hex()
    return script_pub_key


# A second copy of the whole function used to sit here, commented out,
# carrying the one thing worth keeping from it: a "Fixme" saying that its
# `0x` branch turned 0xbb into "bb00" instead of "bb". That is the reason
# the branch above slices the prefix off the token and takes the rest as
# hex, rather than parsing it to an int and asking serialize() to write it
# back -- a round trip through a number cannot preserve which byte width
# the vector wrote, and Core's vectors mean exactly the bytes they spell.
