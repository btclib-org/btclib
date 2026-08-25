# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Generation of the ephemeral key (nonce) following BIP340.

https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

BIP340 derives the nonce from the private key, the public key, and
the message, all behind a tagged hash, plus auxiliary randomness a:

nonce = TaggedHash('BIP0340/nonce', t||x_Q||msg)
with t = q xor TaggedHash('BIP0340/aux', a)

Where:

TaggedHash(tag, x) = SHA256(SHA256(tag)||SHA256(tag)||x)

This is the synthetic nonce: the deterministic derivation is the
security floor -- with no randomness at signing time (a counter as a,
even all zeros) a nonce still cannot repeat across different messages
-- and fresh randomness is the hardening BIP340 recommends on top,
against fault injection and side-channel attacks. The key is masked
with the hashed randomness by xor, rather than hashed together with
it, to keep the number of operations touching the actual secret low.
The dedicated tag is domain separation: RFC6979 is not reused because
sharing a derivation (and a key) with deterministic ECDSA could leak
the key through nonce reuse across the two schemes. Any deterministic
derivation, BIP340 warns, remains insecure in multi-party signing.
"""

from __future__ import annotations

import secrets
from hashlib import sha256

from btclib.alias import HashF, Integer, Octets
from btclib.curves import Curve, mult, scalar_from_prv_key, secp256k1
from btclib.hashes import tagged_hash
from btclib.utils import bytes_from_octets, int_from_bits

__all__ = [
    "bip340_nonce_",
]


def _bip340_nonce_(msg: bytes, q: int, Q: int, aux: bytes, ec: Curve, hf: HashF) -> int:
    # assume the random oracle model for the hash function,
    # i.e. hash values can be considered uniformly random

    # In general, taking a uniformly random integer modulo the
    # curve order n would produce a biased result.
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
            msg,
        ]
    )

    nonce_tag = b"BIP0340/nonce"
    while True:
        t = tagged_hash(nonce_tag, t, hf)
        # reducing the hash mod n -- whether the whole of it or its
        # leftmost nlen bits -- would introduce a bias, which is why
        # neither is done here.
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
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> tuple[int, int, int, int]:
    """Return a BIP340 ephemeral key (nonce), synthetic by default.

    The message is of any size: BIP340 puts no size restriction on it,
    and the nonce tagged hash absorbs any length just as the challenge
    does.
    """
    hf_len = hf().digest_size
    msg = bytes_from_octets(msg)

    q = scalar_from_prv_key(prv_key, ec)

    x_Q, y_Q = mult(q, ec=ec)
    if y_Q % 2:
        q = ec.n - q

    aux = secrets.token_bytes(hf_len) if aux is None else bytes_from_octets(aux, hf_len)

    k = _bip340_nonce_(msg, q, x_Q, aux, ec, hf)
    x_K, y_K = mult(k, ec=ec)
    if y_K % 2:
        k = ec.n - k

    return k, x_K, q, x_Q
