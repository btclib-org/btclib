#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Entropy conversions from/to binary string, int, and bytes.

Input raw entropy (*GenericEntropy*) can be expressed as
binary 0/1 string, bytes-like, or integer; by default, it must be
128, 160, 192, 224, or 256 bits. In the case of integer,
if the equivalent binary 0/1 string is shorter than 256 bits, then
it is padded with leading zeros up to the next allowed bit length;
if longer, then only the leftmost 256 bits are retained.

Output entropy (*Entropy*) should always be a binary 0/1 string.
"""

from typing import Union, Optional, Sequence

Entropy = str  # binary 0/1 string
GenericEntropy = Union[Entropy, int, bytes]

_bits = (128, 160, 192, 224, 256)


def str_from_entropy(entr: GenericEntropy,
                     bits: Optional[Union[int, Sequence]] = _bits) -> Entropy:
    if type(bits) == int:
        bits = (bits, )
    bits = sorted(set(bits))  # ascending sort unique

    if type(entr) == str:
        int(entr, 2)  # check that entr is a valid binary string
        nbits = len(entr)
        # no length adjustment
    elif type(entr) == bytes:
        nbits = len(entr) * 8
        entr = int.from_bytes(entr, 'big')
        entr = bin(entr)[2:]  # remove '0b'
        # no length adjustment
    elif type(entr) == int:
        if entr < 0:
            raise ValueError(f"negative entropy {entr}")
        entr = bin(entr)[2:]  # remove '0b'
        nbits = len(entr)
        if nbits > bits[-1]:
            # only the leftmost bits are retained
            entr = entr[:bits[-1]]
            nbits = bits[-1]
        elif nbits not in bits:
            # next allowed bit length
            nbits = next(v for i, v in enumerate(bits) if v > nbits)
    else:
        m = "entropy must be binary 0/1 string, bytes-like, or int; "
        m += f"not '{type(entr).__name__}'"
        raise TypeError(m)

    if nbits not in bits:
        raise ValueError(f"{nbits} bits provided; expected: {bits}")
    return entr.zfill(nbits)  # pad with leading zeros


def int_from_entropy(entr: GenericEntropy,
                     bits: Optional[Union[int, tuple]] = _bits) -> int:
    entr = str_from_entropy(entr, bits)
    return int(entr, 2)


def bytes_from_entropy(entr: GenericEntropy,
                       bits: Optional[Union[int, tuple]] = _bits) -> bytes:
    entr = str_from_entropy(entr, bits)
    nbits = len(entr)
    nbytes = (nbits+7)//8
    entr = int(entr, 2)
    return entr.to_bytes(nbytes, 'big')
