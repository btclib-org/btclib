# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Btclib.script.engine non-regression tests."""

import warnings

from btclib.exceptions import BTClibUserWarning
from btclib.script.script import BYTE_FROM_OP_CODE_NAME, serialize


def parse_script(bitcoin_core_script: str) -> str:
    """Compile Bitcoin Core's script notation into serialized hex."""
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
                y = f"OP_{y}"  # noqa: PLW2901
            script_pub_key += BYTE_FROM_OP_CODE_NAME[y].hex()
    return script_pub_key


# The `0x` branch above slices the prefix off the token and takes the
# rest as hex, rather than parsing it to an int and asking serialize() to
# write it back: a round trip through a number cannot preserve which byte
# width the vector wrote (0xbb comes back as "bb00" instead of "bb"), and
# Core's vectors mean exactly the bytes they spell.
