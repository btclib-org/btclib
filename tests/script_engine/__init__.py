#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""btclib.script.engine non-regression tests."""

from btclib.script.op_codes import OP_CODES
from btclib.script.script import serialize


def parse_script(bitcoin_core_script):
    script_pub_key = ""
    for y in bitcoin_core_script.split():
        if y[:2] == "0x":
            script_pub_key += y[2:]
        elif y[1:].isdigit():
            script_pub_key += serialize([int(y)]).hex()
        elif y[0] == "'" and y[-1] == "'":
            script_pub_key += serialize([bytes(y[1:-1], "ascii")]).hex()
        else:
            if y[:3] != "OP_":
                y = "OP_" + y
            script_pub_key += OP_CODES[y].hex()
    return script_pub_key


# def parse_script(bitcoin_core_script):
#     script_pub_key = ""
#     for y in bitcoin_core_script.split():
#         if y[:2] == "0x":
#             # Fixme: 0xbb becomes 'bb00' instead of 'bb'
#             script_pub_key += serialize([int(y, 16)]).hex()
#         elif y[1:].isdigit():
#             script_pub_key += serialize([int(y)]).hex()
#         elif y[0] == "'" and y[-1] == "'":
#             script_pub_key += serialize([bytes(y[1:-1], "ascii")]).hex()
#         else:
#             if y[:3] != "OP_":
#                 y = "OP_" + y
#             script_pub_key += OP_CODES[y].hex()
#     return script_pub_key
