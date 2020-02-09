#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Entropy conversions from/to binary 0/1 string, bytes-like, and int.

Input entropy can be expressed as
binary 0/1 string, bytes-like, or integer.

Output entropy is always a binary 0/1 string.
"""

import math
import random
import secrets
from typing import Iterable, List, Optional, Union

from btclib.utils import ensure_is_power_of_two

BinStr = str  # binary 0/1 string
Entropy = Union[BinStr, int, bytes]

_bits = 128, 160, 192, 224, 256


def binstr_from_entropy(entr: Entropy,
                        bits: Union[int, Iterable[int]] = _bits) -> BinStr:
    """Convert the input entropy to binary 0/1 string.

    Input entropy can be expressed as
    binary 0/1 string, bytes-like, or integer;
    by default, it must be 128, 160, 192, 224, or 256 bits.

    In the case of binary 0/1 string and bytes-like
    leading zeros are not considered redundant padding.
    In the case of integer, where leading zeros cannot be represented,
    if the bit length is not an allowed value, then the binary 0/1
    string is padded with leading zeros up to the first allowed bit
    length; if the integer bit length is longer than the maximum
    length, then only the leftmost bits are retained.
    """

    if isinstance(bits, int):
        bits = (bits, )       # if a single int, make it a tuple
    bits = sorted(set(bits))  # ascending unique sorting of allowed bits

    if isinstance(entr, str):
        binstr_entr = entr.strip()
        if binstr_entr[:2] == '0b':
            binstr_entr = binstr_entr[2:]
        int(binstr_entr, 2)  # check that entr is a valid binary string
        nbits = len(binstr_entr)
        # no length adjustment
    elif isinstance(entr, bytes):
        nbits = len(entr) * 8
        int_entr = int.from_bytes(entr, 'big')
        binstr_entr = bin(int_entr)[2:]  # remove '0b'
        # no length adjustment
    elif isinstance(entr, int):
        if entr < 0:
            raise ValueError(f"negative entropy ({entr})")
        binstr_entr = bin(entr)[2:]  # remove '0b'
        nbits = len(binstr_entr)
        if nbits > bits[-1]:
            # only the leftmost bits are retained
            binstr_entr = binstr_entr[:bits[-1]]
            nbits = bits[-1]
        elif nbits not in bits:
            # next allowed bit length
            nbits = next(v for i, v in enumerate(bits) if v > nbits)
    else:
        m = "entropy must be binary 0/1 string, bytes-like, or int; "
        m += f"not '{type(entr).__name__}'"
        raise TypeError(m)

    if nbits not in bits:
        raise ValueError(f"{nbits} bits entropy provided; expected: {bits}")
    return binstr_entr.zfill(nbits)  # might need padding with leading zeros


def generate_entropy(base: int, rolls: List[int],
                     shuffle: bool = True, xor: bool = True,
                     target_bits: int = 256) -> BinStr:

    ensure_is_power_of_two(target_bits, "target bits")

    bits_per_roll = math.floor(math.log2(base))
    base = 2 ** bits_per_roll
    min_roll_number = math.ceil(target_bits/bits_per_roll)

    if shuffle:
        random.seed(secrets.token_bytes(32))
        random.shuffle(rolls)

    i = 0
    for r in rolls:
        # collect only valid rolls
        if 0 < r and r <= base:
            i *= base
            i += r-1
            min_roll_number -= 1
    if min_roll_number > 0:
        msg = f"too few rolls, missing {min_roll_number} "
        msg += f"valid [1-{base}] rolls"
        raise ValueError(msg)

    if xor:
        i ^= secrets.randbits(target_bits)

    # convert to binary string
    binstr = bin(i)
    # remove leading 0b
    binstr = binstr[2:]
    # fill with leading zero if needed
    binstr = binstr.zfill(target_bits)
    # take only the (possibly xor-ed) rightmost bits
    return binstr[-target_bits:]
