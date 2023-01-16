#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Deterministic generation of the ephemeral key following BIP340.

https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

The BIP340-Schnorr scheme advocates a custom deterministic algorithm
for the ephemeral key (nonce) used for signing,
instead of the RFC6979 standard:

nonce = TaggedHash('BIPSchnorrDerive', q||msg)

Where:

TaggedHash(tag, x) = SHA256(SHA256(tag)||SHA256(tag)||x)
"""

from __future__ import annotations

import secrets
from hashlib import sha256

from btclib.alias import HashF, Octets
from btclib.ec import Curve, mult, secp256k1
from btclib.hashes import tagged_hash
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.utils import bytes_from_octets, int_from_bits


def _bip340_nonce_(
    msg_hash: bytes, q: int, Q: int, aux: bytes, ec: Curve, hf: HashF
) -> int:
    # assume the random oracle model for the hash function,
    # i.e. hash values can be considered uniformly random

    # Note that in general, taking a uniformly random integer
    # modulo the curve order n would produce a biased result.
    # However, if the order n is sufficiently close to 2^hf_len,
    # then the bias is not observable:
    # e.g. for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
    #
    # the unbiased implementation is provided here,
    # which works also for very-low-cardinality test curves
    randomizer = tagged_hash(b"BIP0340/aux", aux, hf)
    xor = q ^ int.from_bytes(randomizer, "big", signed=False)
    max_len = max(ec.n_size, hf().digest_size)
    t = b"".join(
        [
            xor.to_bytes(max_len, byteorder="big", signed=False),
            Q.to_bytes(ec.p_size, byteorder="big", signed=False),
            msg_hash,
        ]
    )

    nonce_tag = b"BIP0340/nonce"
    while True:
        t = tagged_hash(nonce_tag, t, hf)
        # The following lines would introduce a bias
        # nonce = int.from_bytes(t, 'big') % ec.n
        # nonce = int_from_bits(t, ec.nlen) % ec.n
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hf_len,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        nonce = int_from_bits(t, ec.nlen)  # candidate nonce
        if 0 < nonce < ec.n:  # acceptable value for nonce
            return nonce  # successful candidate


def bip340_nonce_(
    msg_hash: Octets,
    prv_key: PrvKey,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> tuple[int, int, int, int]:
    """Return a BIP340 deterministic ephemeral key (nonce)."""
    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    q = int_from_prv_key(prv_key, ec)

    x_Q, y_Q = mult(q, ec=ec)
    if y_Q % 2:
        q = ec.n - q

    aux = secrets.token_bytes(hf_len) if aux is None else bytes_from_octets(aux, hf_len)

    k = _bip340_nonce_(msg_hash, q, x_Q, aux, ec, hf)
    x_K, y_K = mult(k, ec=ec)
    if y_K % 2:
        k = ec.n - k

    return k, x_K, q, x_Q
