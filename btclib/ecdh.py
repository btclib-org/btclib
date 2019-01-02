#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from btclib.ec import int2octets, EC, Point, octets2int, \
    int2octets, pointMult


def kdf(zbytes: bytes, keydatalen: int, ec: EC, hf) -> bytes:
    """ ANS-X9.63-KDF - SEC 1 specification

    source: http://www.secg.org/sec1-v2.pdf, section 3.6.1
    """
    hlen = hf().digest_size
    assert keydatalen < hlen * (2**32 - 1), "invalid"
    counter = 1
    counter_bytes = counter.to_bytes(4, 'big')
    K_temp = []
    for i in range((keydatalen+1) // hlen):
        K_temp.append(hf(zbytes + counter_bytes).digest())
        counter += 1
        counter_bytes = counter.to_bytes(4, 'big')
        i += 1
    K_bytes = b''.join(K_temp[i] for i in range(keydatalen // hlen))
    K = octets2int(K_bytes) >> (keydatalen - hlen)
    return int2octets(ec, K)


def key_agreement(dUV: int,
                  QVU: Point,
                  keydatalen: int,
                  ec: EC,
                  hf) -> bytes:
    P = pointMult(ec, dUV, QVU)
    if P == (1, 0):
        "invalid (zero) private key"
    z = P[0]
    zbytes = int2octets(ec, z)
    k = kdf(zbytes, keydatalen, ec, hf)
    return k
