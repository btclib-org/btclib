#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Deterministic generation of the nonce following rfc6979

rfc6979 specification:
https://tools.ietf.org/html/rfc6979#section-3.2
code adapted from:
https://github.com/AntonKueltz/fastecdsa/blob/master/fastecdsa/util.py
"""

from struct import pack
import hmac

from btclib.ecutils import EC, octets, _bits2int, int2octets, bits2octets


def rfc6979(prv: int, h1: bytes, ec: EC, hf) -> int:

    if not 0 < prv < ec.n:
        raise ValueError("invalid private key %X" %prv)

    # h1 = hf(m)
    hlen = hf().digest_size
    bytesize = (hlen + 7) // 8
    v = b'\x01' * bytesize * 8
    k = b'\x00' * bytesize * 8

    # bytesize or ec.bytesize ?
    qlen = ec.bytesize
    prv_and_m = int2octets(prv, qlen)
    prv_and_m += bits2octets(ec, h1)
    k = hmac.new(k, v + b'\x00' + prv_and_m, hf).digest()
    v = hmac.new(k, v, hf).digest()
    k = hmac.new(k, v + b'\x01' + prv_and_m, hf).digest()
    v = hmac.new(k, v, hf).digest()

    while True:
        t = b''
        while len(t) < qlen:
            v = hmac.new(k, v, hf).digest()
            t = t + v
        nonce = _bits2int(ec, t)
        # k should also be checked not to yield an invalid signature
        if 0 < nonce < ec.n:
            return nonce
        k = hmac.new(k, v + b'\x00', hf).digest()
        v = hmac.new(k, v, hf).digest()
