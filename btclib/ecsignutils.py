#!/usr/bin/env python3

from typing import Tuple, Union
from hashlib import sha256

Message = bytes
HashDigest = Union[str, bytes]
Signature = Tuple[int, int]

default_size = 32

def check_hash(hash_digest: bytes,
               digest_size: int = default_size) -> None:
    """check that hash is a bytes-like object of correct length
    """
    if not isinstance(hash_digest, bytes):
        m = "hash digest must be a bytes-like object, not "
        m += "'%s'" % type(hash_digest).__name__
        raise TypeError(m)

    if len(hash_digest) > digest_size:
        m = "hash digest lenght %s must be <= digest size" % len(hash_digest)
        m += " %s" % digest_size
        raise ValueError(m)

def bytes_from_hash(hash_digest: HashDigest,
                    hash_function = sha256) -> bytes:
    """check that hash digest is a bytes-like object of right size
    """

    if isinstance(hash_digest, str):
        hash_digest = bytes.fromhex(hash_digest)
    elif not isinstance(hash_digest, bytes):
        m = "hash digest must be a bytes-like object, not "
        m += "'%s'" % type(hash_digest).__name__
        raise TypeError(m)

    if len(hash_digest) != hash_function().digest_size:
        errmsg = 'message digest of wrong size: %s' % len(hash_digest)
        errmsg += ' instead of %s' % hash_function().digest_size
        raise ValueError(errmsg)
    
    return hash_digest

def int_from_hash(hash_digest: bytes,
                  group_order: int,
                  digest_size: int = default_size) -> int:
    """from hash digest to int"""
    check_hash(hash_digest, digest_size)
    h_len = len(hash_digest) * 8
    L_n = group_order.bit_length() # use the L_n leftmost bits of the hash
    n = (h_len - L_n) if h_len >= L_n else 0
    return int.from_bytes(hash_digest, "big") >> n
