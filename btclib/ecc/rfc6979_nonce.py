#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Deterministic generation of the ephemeral key following RFC6979.

https://www.rfc-editor.org/rfc/rfc6979.html

Every ECDSA and ECSSA signature needs a fresh ephemeral key (nonce),
chosen randomly and uniformly from the scalars by a cryptographically
secure process: even a slight bias in that process can be turned into
an attack on the scheme, and reusing a nonce across two messages
signed with one private key reveals the key -- dsa.crack_prv_key is
that computation.

RFC6979 removes the need for a randomness source by deriving the
nonce deterministically from the private key and the message, which
also makes signing testable against fixed vectors. The derivation
keeps the properties a signature scheme expects: to whoever does not
know the private key, the message-to-nonce mapping is computationally
indistinguishable from a uniformly random function.

BIP340 uses a different algorithm for the generation of the
ephemeral key: bip340_nonce.py.
"""

import hashlib
import hmac
from hashlib import sha256

from btclib.alias import HashF, Octets
from btclib.curves import Curve, secp256k1
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.utils import bytes_from_octets, int_from_bits


def challenge_(
    msg_hash: Octets, ec: Curve = secp256k1, hf: HashF = hashlib.sha256
) -> int:
    """Return the ECDSA challenge scalar from a message hash.

    Bits2int of SEC 1 and RFC6979: the leftmost nlen bits of the hash,
    reduced mod n. The message enters already reduced -- a digest of
    hf's size, which is what the trailing underscore says.
    """
    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    # leftmost ec.nlen bits %= ec.n
    return int_from_bits(msg_hash, ec.nlen) % ec.n


def _rfc6979_nonce_(
    c: int, q: int, ec: Curve, hf: HashF, extra_entropy: bytes = b""
) -> int:
    # https://www.rfc-editor.org/rfc/rfc6979.html section 3.2

    # convert the private key q to an octet sequence of size n_size
    q_bytes = q.to_bytes(ec.n_size, byteorder="big", signed=False)
    # truncate and/or expand c: encoding size is driven by n_size
    c_bytes = c.to_bytes(ec.n_size, byteorder="big", signed=False)
    # section 3.6 additional data k', appended to the key and the message
    # rather than mixed in: the RFC leaves the encoding to the caller and
    # libsecp256k1 appends its 32-byte ndata here, which is what makes the
    # sign-to-contract vectors of commit_nonce reproducible
    bprvbm = q_bytes + c_bytes + extra_entropy

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
        # reducing the hash mod n -- whether the whole of it or its
        # leftmost nlen bits -- would introduce a bias, which is why
        # neither is done here.
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hf_len,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        nonce = int_from_bits(t, ec.nlen)  # candidate nonce           # 3.2.h.3
        if 0 < nonce < ec.n:  # acceptable values for nonce
            return nonce  # successful candidate
        k = hmac.new(k, v + b"\x00", hf).digest()
        v = hmac.new(k, v, hf).digest()


def rfc6979_nonce_(
    msg_hash: Octets,
    prv_key: PrvKey,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
    extra_entropy: Octets | None = None,
) -> int:
    """Return an RFC6979 deterministic ephemeral key (nonce).

    see https://www.rfc-editor.org/rfc/rfc6979.html section 3.2

    extra_entropy is the section 3.6 additional data: two callers with
    the same key and message reach different nonces by passing different
    values, and the derivation stays deterministic in all of its inputs.
    It is what a commitment travels through in commit_nonce, and what
    libsecp256k1 calls ndata.
    """
    c = challenge_(msg_hash, ec, hf)
    q = int_from_prv_key(prv_key, ec)
    extra = b"" if extra_entropy is None else bytes_from_octets(extra_entropy)

    return _rfc6979_nonce_(c, q, ec, hf, extra)
