#!/usr/bin/env python3

from typing import Tuple, Union
from hashlib import sha256

from btclib.ellipticcurves import EllipticCurve, secp256k1

HashDigest = Union[str, bytes]
Signature = Tuple[int, int]

def bytes_from_hash(hdigest: HashDigest,
                    hfunction = sha256) -> bytes:
    """check that hash digest is a bytes-like object of right size"""

    if isinstance(hdigest, str):
        hdigest = bytes.fromhex(hdigest)
    elif not isinstance(hdigest, bytes):
        m = "hash digest must be a bytes-like object, not "
        m += "'%s'" % type(hdigest).__name__
        raise TypeError(m)

    if len(hdigest) != hfunction().digest_size:
        errmsg = 'message digest of wrong size: %s' % len(hdigest)
        errmsg += ' instead of %s' % hfunction().digest_size
        raise ValueError(errmsg)
    
    return hdigest

def int_from_hash(hdigest: HashDigest,
                  ec: EllipticCurve = secp256k1,
                  hfunction = sha256) -> int:
    """return an int from a hash digest"""

    h = bytes_from_hash(hdigest, hfunction)

    h_len = 8 * hfunction().digest_size
    q_len = 8 * ec.bytesize
    # use the q_len leftmost bits of the hash
    n = (h_len - q_len) if h_len >= q_len else 0

    return int.from_bytes(h, "big") >> n
