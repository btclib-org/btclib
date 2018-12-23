#!/usr/bin/env python3

from typing import Tuple, Union

Message = Union[str, bytes]
Signature = Tuple[int, int]

default_size = 32

def check_hash(hash: bytes, size: int = default_size) -> None:
    """check that hash is a bytes-like object of correct length
    """
    if not isinstance(hash, bytes):
        m = "hash must be a bytes-like object, not '%s'" % type(hash).__name__
        raise TypeError(m)

    if len(hash) > size:
        m = "hash lenght %s must be <= size %s" % (len(hash), size)
        raise ValueError(m)


def int_from_hash(hash: bytes, order: int, size: int = default_size) -> int:
    """from hash digest to int"""
    check_hash(hash, size)
    h_len = len(hash) * 8
    L_n = order.bit_length() # use the L_n leftmost bits of the hash
    n = (h_len - L_n) if h_len >= L_n else 0
    return int.from_bytes(hash, "big") >> n
