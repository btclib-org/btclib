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
import secrets
from hashlib import sha256
from typing import Iterable, List, Optional, Union

from .alias import BinStr, Entropy

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


def generate(bits: int, dice_base: int = 0,
             rolls: Optional[List[int]] = None, shuffle: bool = True,
             hash: bool = True, xor: bool = True) -> BinStr:
    """Return CSPRNG system entropy mixed with exogenous roll-based entropy.

    If no exogenous entropy is provided, then entropy generated with the
    system cryptographically strong pseudo-random number generator (CSPRNG)
    is returned.

    Instead, if exogenous entropy is provided, then it is possibly manipulated
    and, finally, XOR-ed with the CSPRNG system entropy.

    The optional exogenous roll-based entropy must consist of integers in the
    [1-dice_base] range; anyway, only rolls having value in the [1-base] range
    are used, with base being the highest power of 2 lower than the dice_base
    (e.g. for a traditional D6 dice, only rolls having value in [1-4] are
    used; for a D20 dice, only rolls having value in [1-16] are used; etc.).

    If provided, the exogenous roll-based entropy must supply at least the
    required number of bits.
    Rolls can be shuffled,
    resulting entropy can be hashed,
    and it is finally XOR-ed with the CSPRNG system entropy.
    If not shuffled, hashed, and/or XOR-ed, then the function returns the
    rightmost required number of bits from the unaltered exogenous entropy.
    """

    if bits not in _bits:
        raise ValueError(f"Number of bits ({bits}) must be in {_bits}")

    i = 0
    # start with the exogenously provided roll-based entropy
    if rolls is not None:
        if dice_base < 2:
            raise ValueError(f"Invalid dice base ({dice_base}): must be >= 2")
        bits_per_roll = math.floor(math.log2(dice_base))
        # used base
        base = 2 ** bits_per_roll

        if shuffle:
            secrets.SystemRandom().shuffle(rolls)

        min_roll_number = math.ceil(bits / bits_per_roll)
        for r in rolls:
            # collect only usable rolls in [1-base)]
            if 0 < r and r <= base:
                i *= base
                i += r - 1
                min_roll_number -= 1
            # reject invalid rolls not in [1-dice_base)]
            elif r < 1 or r > dice_base:
                msg = f"invalid ({r}) roll, not in [1-{dice_base}]"
                raise ValueError(msg)
        if min_roll_number > 0:
            msg = f"too few usable [1-{base}] rolls, missing {min_roll_number}"
            raise ValueError(msg)

        # hash the (possibly shuffled) exogenous entropy
        if hash:
            if i.bit_length() > 256:
                i >>= i.bit_length() - 256
            h256 = sha256(i.to_bytes(32, byteorder='big')).digest()
            i = int.from_bytes(h256, byteorder='big')

    # XOR the (possibly shuffled and/or hashed) exogenous entropy
    # with CSPRNG system entropy
    if xor:
        i ^= secrets.randbits(bits)

    # convert to binary string
    binstr = bin(i)
    # remove leading '0b'
    binstr = binstr[2:]
    # do not lose leading zeros
    binstr = binstr.zfill(bits)
    # take only the (possibly XOR-ed) rightmost bits
    return binstr[-bits:]
