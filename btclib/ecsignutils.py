#!/usr/bin/env python3

from typing import Tuple, Union

Message = Union[str, bytes]
Signature = Tuple[int, int]

def int_from_hash(hash_digest, order, size=32):
    """from hash digest to int"""
    assert type(hash_digest) == bytes, "hash_digest must be bytes"
    assert len(hash_digest) <= size, "hash_digest must have correct bytes length"
    h_len = len(hash_digest) * 8
    L_n = order.bit_length() # use the L_n leftmost bits of the hash
    n = (h_len - L_n) if h_len >= L_n else 0
    return int.from_bytes(hash_digest, "big") >> n
