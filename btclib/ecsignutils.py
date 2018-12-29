#!/usr/bin/env python3

# Copyright (C) 2017-2019 The bbtlib developers
#
# This file is part of bbtlib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of bbtlib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Tuple, Union

from btclib.ellipticcurves import EllipticCurve


def int2octets(x: int, bytesize: int) -> bytes:
    return x.to_bytes(bytesize, byteorder='big')


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


HashLengthBytes = Union[str, bytes]


def bytes_from_hlenbytes(hlb: HashLengthBytes,
                         hfunction) -> bytes:
    """check that hash digest is of right size"""

    if isinstance(hlb, str):
        hlb = bytes.fromhex(hlb)

    if len(hlb) != hfunction().digest_size:
        errmsg = 'message of wrong size: %s' % len(hlb)
        errmsg += ' instead of %s' % hfunction().digest_size
        raise ValueError(errmsg)

    return hlb


def int_from_hlenbytes(hlb: HashLengthBytes,
                       ec: EllipticCurve,
                       hfunction) -> int:
    """return an int from a hash digest, reducing it to EC bytesize"""

    hlb = bytes_from_hlenbytes(hlb, hfunction)  # hlen bytes
    i = bits2int(hlb, ec.bytesize)             # qlen bytes
    return i
