#!/usr/bin/env python3

"""
Entropy convertions from/to binary string, int, and bytes
"""

from typing import Union

Entropy = str # binary 0/1 string
GenericEntropy = Union[Entropy, int, bytes]

def str_from_entropy(entr: GenericEntropy, required_bits = None) -> Entropy:
    if type(entr) == str:
        int(entr, 2)            # check that entr is a valid binary string
        if required_bits is not None:
            assert len(entr) in required_bits, "wrong number of bits"
        return entr
    elif type(entr) == bytes:
        bits = len(entr) * 8
        if required_bits is not None:
            assert bits in required_bits, "wrong number of bits"
        entr = int.from_bytes(entr, 'big')
        entr = bin(entr)[2:]    # remove '0b'
        return entr.zfill(bits) # pad with lost leading zeros
    elif type(entr) == int:
        if entr < 0:
            raise ValueError("negative entropy %s" % entr)
        entr = bin(entr)[2:]    # remove '0b'
        if required_bits is not None:
            assert len(entr) in required_bits, "wrong number of bits"
        return entr
    else:
        raise TypeError("entropy must be binary string, int, or bytes;",
                        "not '%s'" % type(entr).__name__)

def int_from_entropy(entr: GenericEntropy) -> int:
    if type(entr) == str:
        return int(entr, 2)
    elif type(entr) == int:
        if entr < 0:
            raise ValueError("negative entropy %s" % entr)
        return entr
    elif type(entr) == bytes:
        return int.from_bytes(entr, 'big')
    else:
        raise TypeError("entropy must be binary string, int, or bytes;",
                        "not '%s'" % type(entr).__name__)

def bytes_from_entropy(entr: GenericEntropy, required_bits = None) -> bytes:
    if type(entr) == bytes:
        if required_bits is not None:
            assert len(entr)*8 in required_bits, "wrong number of bits"
        return entr
    elif type(entr) == str:
        bits = len(entr)
        if required_bits is not None:
            assert bits in required_bits, "wrong number of bits"
        entr = int(entr, 2)
        return entr.to_bytes(bits//8, 'big')
    elif type(entr) == int:
        if entr < 0:
            raise ValueError("negative entropy %s" % entr)
        bits = entr.bit_length()
        if required_bits is not None:
            for i in required_bits:
                if bits < i:
                    bits = i
                    break
            assert bits in required_bits, "wrong number of bits"
        return entr.to_bytes((bits+7)//8, 'big')
    else:
        raise TypeError("entropy must be binary string, int, or bytes;",
                        "not '%s'" % type(entr).__name__)
