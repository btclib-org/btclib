#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""
Entropy convertions from/to binary string, int, and bytes
"""

from typing import Union, Optional

Entropy = str  # binary 0/1 string
GenericEntropy = Union[Entropy, int, bytes]


def str_from_entropy(entr: GenericEntropy, required_bits: Optional[Union[int, tuple]] = None) -> Entropy:
    if type(required_bits) == int:
        required_bits = (required_bits, )

    if type(entr) == str:
        int(entr, 2)            # check that entr is a valid binary string
        if required_bits is not None:
            if len(entr) not in required_bits:
                m = f"{len(entr)} bits provided; expected: {required_bits}"
                raise ValueError(m)
        return entr
    elif type(entr) == bytes:
        bits = len(entr) * 8
        if required_bits is not None:
            if bits not in required_bits:
                m = f"{bits} bits provided, {required_bits} expected"
                raise ValueError(m)
        entr = int.from_bytes(entr, 'big')
        entr = bin(entr)[2:]    # remove '0b'
        return entr.zfill(bits)  # pad with lost leading zeros
    elif type(entr) == int:
        if entr < 0:
            raise ValueError(f"negative entropy {entr}")
        entr = bin(entr)[2:]    # remove '0b'
        if required_bits is not None:
            if len(entr) not in required_bits:
                m = f"{len(entr)} bits provided; expected: {required_bits}"
                raise ValueError(m)
        return entr
    else:
        m = "entropy must be binary string, int, or bytes; "
        m += f"not '{type(entr).__name__}'"
        raise TypeError(m)


def int_from_entropy(entr: GenericEntropy) -> int:
    if type(entr) == str:
        return int(entr, 2)
    elif type(entr) == int:
        if entr < 0:
            raise ValueError(f"negative entropy {entr}")
        return entr
    elif type(entr) == bytes:
        return int.from_bytes(entr, 'big')
    else:
        m = "entropy must be binary string, int, or bytes; "
        m += f"not '{type(entr).__name__}'"
        raise TypeError(m)


def bytes_from_entropy(entr: GenericEntropy, required_bits=None) -> bytes:
    if type(required_bits) == int:
        required_bits = (required_bits, )

    if type(entr) == bytes:
        if required_bits is not None:
            if len(entr)*8 not in required_bits:
                m = f"{len(entr)*8} bits provided; expected: {required_bits}"
                raise ValueError(m)
        return entr
    elif type(entr) == str:
        bits = len(entr)
        if required_bits is not None:
            if bits not in required_bits:
                m = f"{bits} bits provided; expected: {required_bits}"
                raise ValueError(m)
        entr = int(entr, 2)
        return entr.to_bytes((bits+7)//8, 'big')
    elif type(entr) == int:
        if entr < 0:
            raise ValueError(f"negative entropy {entr}")
        bits = entr.bit_length()
        if required_bits is not None:
            if bits not in required_bits:
                m = f"{bits} bits provided; expected: {required_bits}"
                raise ValueError(m)
        return entr.to_bytes((bits+7)//8, 'big')
    else:
        m = "entropy must be binary string, int, or bytes; "
        m += f"not '{type(entr).__name__}'"
        raise TypeError(m)
