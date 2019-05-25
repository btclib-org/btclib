#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from .curve import Curve, Point, mult
from .utils import octets_from_int, int_from_octets

def kdf(zbytes: bytes, keydatasize: int, ec: Curve, hf) -> bytes:
    """ ANS-X9.63-KDF - SEC 1 specification

    source: http://www.secg.org/sec1-v2.pdf, section 3.6.1
    """
    hsize = hf().digest_size
    assert keydatasize < hsize * (2**32 - 1), "invalid"
    counter = 1
    counter_bytes = counter.to_bytes(4, 'big')
    K_temp = []
    for i in range((keydatasize+1) // hsize):
        K_temp.append(hf(zbytes + counter_bytes).digest())
        counter += 1
        counter_bytes = counter.to_bytes(4, 'big')
        i += 1
    K_bytes = b''.join(K_temp[i] for i in range(keydatasize // hsize))
    K = int_from_octets(K_bytes) >> (keydatasize - hsize)
    return octets_from_int(K, ec.psize)


def key_agreement(dUV: int,
                  QVU: Point,
                  keydatasize: int,
                  ec: Curve,
                  hf) -> bytes:
    P = mult(ec, dUV, QVU)
    if P[1] == 0:
        "invalid (zero) private key"
    z = P[0]
    zbytes = octets_from_int(z, ec.psize)
    k = kdf(zbytes, keydatasize, ec, hf)
    return k
