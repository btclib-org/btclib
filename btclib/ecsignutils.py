#!/usr/bin/env python3

from typing import Tuple, Union

from btclib.ellipticcurves import EllipticCurve

def int2octets(x: int, maxbytesize: int) -> bytes:
    return x.to_bytes(maxbytesize, byteorder='big')

def bits2int(b: bytes, maxbytesize: int) -> int:
    bytesize = len(b)

    """
    i = int.from_bytes(b, 'big')
    # retain the leftmost bits only
    if bytesize > maxbytesize:
        i >>= (bytesize - maxbytesize) * 8
    return i
    """
    # retain the leftmost bytes only
    if bytesize > maxbytesize:
        return int.from_bytes(b[:maxbytesize], 'big')
    else:
        return int.from_bytes(b, 'big')

def bits2octets(b: bytes, maxbytesize: int) -> bytes:
    z1 = bits2int(b, maxbytesize)
    return int2octets(z1, maxbytesize)

HashDigest = Union[str, bytes]
Signature = Tuple[int, int]

def bytes_from_hash(hdigest: HashDigest,
                    hfunction) -> bytes:
    """check that hash digest is of right size"""

    if isinstance(hdigest, str):
        hdigest = bytes.fromhex(hdigest)

    if len(hdigest) != hfunction().digest_size:
        errmsg = 'message digest of wrong size: %s' % len(hdigest)
        errmsg += ' instead of %s' % hfunction().digest_size
        raise ValueError(errmsg)
    
    return hdigest

def int_from_hash(hdigest: HashDigest,
                  ec: EllipticCurve,
                  hfunction) -> int:
    """return an int from a hash digest"""

    h = bytes_from_hash(hdigest, hfunction)
    i = bits2int(h, ec.bytesize)
    return i
