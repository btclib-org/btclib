#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
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
from hashlib import sha256

from .alias import HashF, Octets, String
from .curve import Curve, secp256k1
from .hashes import reduce_to_hlen
from .to_prvkey import PrvKey, int_from_prvkey
from .utils import bytes_from_octets, int_from_bits


def rfc6979(
    msg: String, prvkey: PrvKey, ec: Curve = secp256k1, hf: HashF = sha256
) -> int:
    """Return a deterministic ephemeral key following RFC 6979.

    see https://tools.ietf.org/html/rfc6979 section 3.2
    """

    m = reduce_to_hlen(msg, hf)  # 3.2.a
    return _rfc6979(m, prvkey, ec, hf)


def _rfc6979(
    m: Octets, prvkey: PrvKey, ec: Curve = secp256k1, hf: HashF = sha256
) -> int:
    """Return a deterministic ephemeral key following RFC 6979."""

    # The message m: a hlen array
    hlen = hf().digest_size
    m = bytes_from_octets(m, hlen)

    # leftmost ec.nlen bits %= ec.n
    c = int_from_bits(m, ec.nlen) % ec.n  # 5

    q = int_from_prvkey(prvkey, ec)

    return __rfc6979(c, q, ec, hf)


def __rfc6979(c: int, q: int, ec: Curve, hf: HashF) -> int:
    # https://tools.ietf.org/html/rfc6979 section 3.2

    # convert the private key q to an octet sequence of size nsize
    bprv = q.to_bytes(ec.nsize, "big")
    # truncate and/or expand c: encoding size is driven by nsize
    bc = c.to_bytes(ec.nsize, "big")
    bprvbm = bprv + bc

    hsize = hf().digest_size
    V = b"\x01" * hsize  # 3.2.b
    K = b"\x00" * hsize  # 3.2.c

    K = hmac.new(K, V + b"\x00" + bprvbm, hf).digest()  # 3.2.d
    V = hmac.new(K, V, hf).digest()  # 3.2.e
    K = hmac.new(K, V + b"\x01" + bprvbm, hf).digest()  # 3.2.f
    V = hmac.new(K, V, hf).digest()  # 3.2.g

    while True:  # 3.2.h
        T = b""  # 3.2.h.1
        while len(T) < ec.nsize:  # 3.2.h.2
            V = hmac.new(K, V, hf).digest()
            T += V
        # The following line would introduce a bias
        # k = int.from_bytes(T, 'big') % ec.n
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hlen,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        k = int_from_bits(T, ec.nlen)  # candidate k           # 3.2.h.3
        if 0 < k < ec.n:  # acceptable values for k
            return k  # successful candidate
        K = hmac.new(K, V + b"\x00", hf).digest()
        V = hmac.new(K, V, hf).digest()
