#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Deterministic generation of the ephemeral key following RFC6979.

https://tools.ietf.org/html/rfc6979:

ECDSA and ECSSA need to produce, for each signature generation,
a fresh random value (ephemeral key, hereafter designated as k).
For effective security, k must be chosen randomly and uniformly
from a set of modular integers, using a cryptographically secure
process. Even slight biases in that process may be turned into
attacks on the signature schemes.

The need for a cryptographically secure source of randomness proves
to be a hindranceand and makes implementations harder to test.
Moreover, reusing the same ephemeral key for a different message
signed with the same private key reveal the private key!

RFC6979 turns ECDSA into deterministic schemes by using a
deterministic process for generating the "random" value k.
The process fulfills the cryptographic characteristics in order to
maintain the properties of verifiability and unforgeability
expected from signature schemes; namely, for whoever does not know
the signature private key, the mapping from input messages to the
corresponding k values is computationally indistinguishable from
what a randomly and uniformly chosen function (from the set of
messages to the set of possible k values) would return.
"""

import hmac

from btclib.utils import Octets, _int_from_bits, int_from_bits, \
    octets_from_int, HashF
from btclib.curve import Curve


def rfc6979(ec: Curve, hf: HashF, mhd: bytes, q: int) -> int:
    """Return a deterministic ephemeral key following RFC 6979."""

    if not 0 < q < ec.n:
        raise ValueError(f"private key {hex(q)} not in [1, n-1]")

    hsize = hf().digest_size
    if len(mhd) != hsize:
        errMsg = f"mismatch between hf digest size ({hsize}) and "
        errMsg += f"hashed message size ({len(mhd)})"
        raise ValueError(errMsg)

    c = int_from_bits(ec, mhd)          # leftmost ec.nlen bits %= ec.n
    return _rfc6979(ec, hf, c, q)


def _rfc6979(ec: Curve, hf: HashF, c: int, q: int) -> int:
    # https://tools.ietf.org/html/rfc6979 section 3.2

    # c = hf(m)                                            # 3.2.a

    # convert the private key q to an octet sequence of size nsize
    bprv = octets_from_int(q, ec.nsize)  # bprv = q.to_bytes(nsize, 'big')
    # truncate and/or expand c: encoding size is driven by nsize
    bc = octets_from_int(c, ec.nsize)    # bc = c.to_bytes(nsize, 'big')
    bprvbm = bprv + bc

    hsize = hf().digest_size
    V = b'\x01' * hsize                                    # 3.2.b
    K = b'\x00' * hsize                                    # 3.2.c

    K = hmac.new(K, V + b'\x00' + bprvbm, hf).digest()     # 3.2.d
    V = hmac.new(K, V, hf).digest()                        # 3.2.e
    K = hmac.new(K, V + b'\x01' + bprvbm, hf).digest()     # 3.2.f
    V = hmac.new(K, V, hf).digest()                        # 3.2.g

    while True:                                            # 3.2.h
        T = b''                                            # 3.2.h.1
        while len(T) < ec.nsize:                           # 3.2.h.2
            V = hmac.new(K, V, hf).digest()
            T += V
        k = _int_from_bits(ec, T)  # candidate             # 3.2.h.3
        if 0 < k < ec.n:           # acceptable values for k
            return k               # successful candidate
        K = hmac.new(K, V + b'\x00', hf).digest()
        V = hmac.new(K, V, hf).digest()
