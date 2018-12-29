#!/usr/bin/env python3

# Copyright (C) 2017-2019 The bbtlib developers
#
# This file is part of bbtlib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of bbtlib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Deterministic generation of the nonce following rfc6979

rfc6979 specification:
https://tools.ietf.org/html/rfc6979#section-3.2
code adapted from:
https://github.com/AntonKueltz/fastecdsa/blob/master/fastecdsa/util.py
"""

from struct import pack
import hmac

from btclib.ellipticcurves import EllipticCurve
from btclib.ecsignutils import bits2octets, bits2int, int2octets, \
    HashLengthBytes, bytes_from_hlenbytes


def rfc6979(prv: int,
            hdigest: HashLengthBytes,
            ec: EllipticCurve,
            Hash) -> int:

    if not (0 < prv < ec.n):
        raise ValueError("invalid prv: %s" % prv)

    hash_size = Hash().digest_size
    v = b'\x01' * hash_size
    k = b'\x00' * hash_size

    hdigest = bytes_from_hlenbytes(hdigest, Hash)
    # hlen or qlen ?
    prv_and_m = int2octets(prv, hash_size) + bits2octets(hdigest, hash_size)
    k = hmac.new(k, v + b'\x00' + prv_and_m, Hash).digest()
    v = hmac.new(k, v, Hash).digest()
    k = hmac.new(k, v + b'\x01' + prv_and_m, Hash).digest()
    v = hmac.new(k, v, Hash).digest()

    qlen = ec.bytesize
    while True:
        t = b''
        while len(t) < qlen:
            v = hmac.new(k, v, Hash).digest()
            t = t + v
        nonce = bits2int(t, qlen)
        if nonce > 0 and nonce < ec.n:
            # here it should be checked that nonce do not yields a invalid signature
            # but then I should put the signature generation here
            return nonce
        k = hmac.new(k, v + b'\x00', Hash).digest()
        v = hmac.new(k, v, Hash).digest()
