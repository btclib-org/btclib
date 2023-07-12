#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Descriptors util functions.

BIP 380: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
"""

from btclib.exceptions import BTClibValueError

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]


def __descsum_polymod(symbols):
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7FFFFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def __descsum_expand(descriptor_string: str):
    """Perform the character to symbol expansion."""
    groups = []
    symbols = []
    for char in descriptor_string:
        if char not in INPUT_CHARSET:
            raise BTClibValueError()
        index = INPUT_CHARSET.find(char)
        symbols.append(index & 31)
        groups.append(index >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def descriptor_checksum(descriptor: str) -> str:
    """Compute the descriptor checksum."""
    symbols = __descsum_expand(descriptor) + [0, 0, 0, 0, 0, 0, 0, 0]
    checksum = __descsum_polymod(symbols) ^ 1
    return "".join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))


def descriptor_from_address(address: str) -> str:
    descriptor = f"addr({address})"
    return f"{descriptor}#{descriptor_checksum(descriptor)}"
