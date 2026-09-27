# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Btclib.script.engine non-regression tests."""

from btclib.script.script import BYTE_FROM_OP_CODE_NAME, serialize


def parse_script(bitcoin_core_script: str) -> str:
    """Compile Bitcoin Core's script notation into serialized hex."""
    script_pub_key = ""
    for y in bitcoin_core_script.split():
        if y[:2] == "0x":
            script_pub_key += y[2:]
        elif y.removeprefix("-").isdigit():
            # a decimal is Core's `CScript() << int64`, which writes -1 and
            # 1..16 as the op codes OP_1NEGATE and OP_1..OP_16 and any other
            # number as its minimal push: "16 0x021234" is a version-16
            # witness program, and a push of 0x10 in front of it is not
            n = int(y)
            if n == -1 or 1 <= n <= 16:
                name = "OP_1NEGATE" if n == -1 else f"OP_{n}"
                script_pub_key += BYTE_FROM_OP_CODE_NAME[name].hex()
            else:
                script_pub_key += serialize([n]).hex()
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
