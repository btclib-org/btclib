#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from hashlib import sha1, sha256
from btclib.ec import EC, Scalar, XPoint, int_from_Scalar, \
    to_Point, bytes_from_Scalar, pointMult
from btclib.ecsigutils import int2octets


def ecdh(ec: EC, prv_sender: Scalar, pub_recv: XPoint) -> int:
    shared_point = pointMult(ec, prv_sender, pub_recv)
    shared_pubkey = to_Point(ec, shared_point)
    return shared_pubkey[0]


def key_setup(hd_size: int):
    if hd_size == 20:
        return sha1
    return sha256


def key_derivation(ec: EC,
                   shared_secret: bytes,
                   key_data_len: int,
                   hd_size: int,
                   hlen_max = 2**61 - 1) -> bytes:
    """ ANS X9.63 kdf - SEC 1 specification

    source: http://www.secg.org/sec1-v2.pdf, section 6.1
    """
    hf = key_setup(hd_size)
    assert len(shared_secret) + 4 < hlen_max, "invalid"
    assert key_data_len < hd_size * (2**32 - 1), "invalid"
    counter = 1
    counter_bytes = counter.to_bytes(4, 'big')
    K_temp = []
    for i in range(key_data_len // hd_size):
        K_temp.append(hf(shared_secret + counter_bytes).digest())
        counter += 1
        counter_bytes = counter.to_bytes(4, 'big')
        i += 1
    K_bytes = b''.join(K_temp[i]
                       for i in range(key_data_len // hd_size))
    K = int_from_Scalar(ec, K_bytes) >> (key_data_len - hd_size)
    return bytes_from_Scalar(ec, K)


def key_agreement(ec: EC,
                  key_data_len: int,
                  prv_sender: Scalar,
                  pub_recv: XPoint,
                  hd_size: int) -> bytes:
    shared_secret = ecdh(ec, prv_sender, pub_recv)
    shared_secret_bytes = int2octets(shared_secret, ec.bytesize)
    K = key_derivation(ec, shared_secret_bytes, key_data_len, hd_size)
    return K
