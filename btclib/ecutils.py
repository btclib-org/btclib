#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Tuple, Union

from btclib.ec import EC, Point, BytesLike


def int2octets(i: int, bytesize: int) -> bytes:
    """SEC 1 v.2, section 2.3.7"""
    # bytesize = rlen * 8
    # rlen = 8*ceil(qlen/8)
    # qlen = ec.n.bitlength()
    # raise an error if i too big
    # as of now does not raise an error if q <= i
    return i.to_bytes(bytesize, byteorder='big')

def octets2int(b: BytesLike, cap: int = None) -> int:
    """SEC 1 v.2, section 2.3.8"""
    if isinstance(b, str):
        b = bytes.fromhex(b)
    i = int.from_bytes(b, 'big')
    if cap and i>cap:
        raise ValueError("invalid integer %s, not in [0, cap-1]" % i)
    return i





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




def bytes_from_hlenbytes(hlb: BytesLike,
                         hfunction) -> bytes:
    """check that hash digest is of right size"""

    if isinstance(hlb, str):
        hlb = bytes.fromhex(hlb)

    if len(hlb) != hfunction().digest_size:
        errmsg = 'message of wrong size: %s' % len(hlb)
        errmsg += ' instead of %s' % hfunction().digest_size
        raise ValueError(errmsg)

    return hlb


def int_from_hlenbytes(hlb: BytesLike, ec: EC, hf) -> int:
    """return an int from a hash digest, reducing it to EC bytesize"""

    hlb = bytes_from_hlenbytes(hlb, hf)  # hlen bytes
    i = bits2int(hlb, ec.bytesize)       # qlen bytes
    return i
