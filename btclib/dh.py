#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Diffie-Hellman elliptic curve key agreement scheme.

Implementation of the Diffie-Hellman key agreement scheme using
elliptic curve cryptography. A key agreement scheme is used
by two entities to establish shared keying data, which will be
later utilized e.g. in symmetric cryptographic scheme.

The two entities must agree on the elliptic curve and key derivation
function to use.
"""

from typing import Callable, Any

from .utils import octets_from_int, int_from_octets, HashF
from .curve import Curve, Point, mult

KDF = Callable[[Curve, HashF, bytes, int], Any]


def ansi_x963_kdf(ec: Curve, hf: HashF, z: bytes, size: int) -> bytes:
    """Return keying data according to ANS-X9.63-KDF.

    Return a keying data octet sequence of the requested size according
    to ANS-X9.63-KDF specifications for the key derivation function.

    http://www.secg.org/sec1-v2.pdf, section 3.6.1
    """
    hsize = hf().digest_size
    assert size < hsize * (2**32 - 1), "invalid"
    counter = 1
    counter_bytes = counter.to_bytes(4, 'big')
    K_temp = []
    for i in range((size+1) // hsize):
        K_temp.append(hf(z + counter_bytes).digest())
        counter += 1
        counter_bytes = counter.to_bytes(4, 'big')
        i += 1
    K_bytes = b''.join(K_temp[i] for i in range(size // hsize))
    K = int_from_octets(K_bytes) >> (size - hsize)
    return octets_from_int(K, ec.psize)


def diffie_hellman(ec: Curve, hf: HashF, kdf: KDF,
                   dU: int, QV: Point, size: int) -> bytes:
    """

    Diffie-Hellman elliptic curve key agreement scheme.

    http://www.secg.org/sec1-v2.pdf, section 6.1
    """

    P = mult(ec, dU, QV)
    if P[1] == 0:
        "invalid (zero) private key"
    shared_secret = P[0]  # shared secret field element
    z = octets_from_int(shared_secret, ec.psize)
    return kdf(ec, hf, z, size)
