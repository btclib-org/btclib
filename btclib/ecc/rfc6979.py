#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Deterministic generation of the ephemeral key following RFC6979.

https://tools.ietf.org/html/rfc6979:

ECDSA and ECSSA need to produce, for each signature generation,
a fresh random value (ephemeral key, hereafter designated as nonce).
For effective security, nonce must be chosen randomly and uniformly
from a set of modular integers, using a cryptographically secure
process. Even slight biases in that process may be turned into
attacks on the signature schemes.

The need for a cryptographically secure source of randomness proves
to be a hindranceand and makes implementations harder to test.
Moreover, reusing the same ephemeral key for a different message
signed with the same private key reveal the private key!

RFC6979 turns ECDSA into deterministic schemes by using a
deterministic process for generating the nonce.
The process fulfills the cryptographic characteristics in order to
maintain the properties of verifiability and unforgeability
expected from signature schemes; namely, for whoever does not know
the signature private key, the mapping from input messages to the
corresponding nonce values is computationally indistinguishable from
what a randomly and uniformly chosen function (from the set of
messages to the set of possible nonce values) would return.
"""

import hmac
from hashlib import sha256

from btclib.alias import HashF, Octets
from btclib.ecc.curve import Curve, secp256k1
from btclib.hashes import challenge_
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.utils import int_from_bits


def _rfc6979_(c: int, q: int, ec: Curve, hf: HashF) -> int:
    # https://tools.ietf.org/html/rfc6979 section 3.2

    # convert the private key q to an octet sequence of size n_size
    q_bytes = q.to_bytes(ec.n_size, byteorder="big", signed=False)
    # truncate and/or expand c: encoding size is driven by n_size
    c_bytes = c.to_bytes(ec.n_size, byteorder="big", signed=False)
    bprvbm = q_bytes + c_bytes

    hf_size = hf().digest_size
    v = b"\x01" * hf_size  # 3.2.b
    k = b"\x00" * hf_size  # 3.2.c

    k = hmac.new(k, v + b"\x00" + bprvbm, hf).digest()  # 3.2.d
    v = hmac.new(k, v, hf).digest()  # 3.2.e
    k = hmac.new(k, v + b"\x01" + bprvbm, hf).digest()  # 3.2.f
    v = hmac.new(k, v, hf).digest()  # 3.2.g

    while True:  # 3.2.h
        t = b""  # 3.2.h.1
        while len(t) < ec.n_size:  # 3.2.h.2
            v = hmac.new(k, v, hf).digest()
            t += v
        # The following line would introduce a bias
        # det_nonce = int.from_bytes(t, 'big') % ec.n
        # det_nonce = int_from_bits(t, ec.nlen) % ec.n
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hf_len,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        det_nonce = int_from_bits(t, ec.nlen)  # candidate det_nonce           # 3.2.h.3
        if 0 < det_nonce < ec.n:  # acceptable values for det_nonce
            return det_nonce  # successful candidate
        k = hmac.new(k, v + b"\x00", hf).digest()
        v = hmac.new(k, v, hf).digest()


def rfc6979_(
    msg_hash: Octets, prv_key: PrvKey, ec: Curve = secp256k1, hf: HashF = sha256
) -> int:
    """Return a deterministic ephemeral key following RFC 6979.

    see https://tools.ietf.org/html/rfc6979 section 3.2
    """

    c = challenge_(msg_hash, ec, hf)
    q = int_from_prv_key(prv_key, ec)

    return _rfc6979_(c, q, ec, hf)
