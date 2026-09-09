# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Deterministic generation of the ephemeral key following RFC6979.

https://www.rfc-editor.org/rfc/rfc6979.html

Every ECDSA and ECSSA signature needs a fresh ephemeral key (nonce),
chosen randomly and uniformly from the scalars by a cryptographically
secure process: even a slight bias in that process can be turned into
an attack on the scheme, and reusing a nonce across two messages
signed with one private key reveals the key -- dsa.crack_prv_key_var is
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

from btclib.alias import HashF, Integer, Octets
from btclib.curves import Curve, scalar_from_prv_key, secp256k1
from btclib.curves.curve import _assert_valid_ec
from btclib.utils import bytes_from_octets, int_from_bits

__all__ = [
    "challenge_",
    "rfc6979_nonce_",
]


def challenge_(
    msg_hash: Octets, ec: Curve = secp256k1, hf: HashF = hashlib.sha256
) -> int:
    """Return the ECDSA challenge scalar from a message hash.

    Bits2int of SEC 1 and RFC6979: the leftmost nlen bits of the hash,
    reduced mod n. The message enters already reduced -- a digest of
    hf's size, which is what the trailing underscore says.
    """
    # the challenge is the first thing `rfc6979_nonce_` and dsa's signing
    # and anti-exfil entry points compute, so the curve they were handed
    # is read here first
    _assert_valid_ec(ec)

    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    # leftmost ec.nlen bits %= ec.n
    return int_from_bits(msg_hash, ec.nlen) % ec.n


class _HmacDrbg:
    """RFC6979 section 3.2's K and V machine, seeded with octets.

    Sections 3.2.b to 3.2.g are the seeding, 3.2.h.2 is `generate`, and
    the K and V update between two draws is `reseed`. Neither when to
    reseed nor what makes a draw acceptable is settled here, and the
    second is not one rule per caller:
    `_rfc6979_nonce_` below reseeds after a candidate outside 1..n-1 and
    asks the chain again, and `secp256k1_rangeproof_genrand` does that
    too for the ring blinding factors a proof of more than one ring
    draws, while failing outright on a ring member's own draw.
    `ecc.rangeproof` takes one draw and it is of that second kind, a
    single ring drawing no blinding factor at all; it seeds this with a
    commitment and a proof header rather than with a key and a message.
    secp256k1-zkp's `secp256k1_rfc6979_hmac_sha256` reseeds between
    every pair of draws whichever kind they are.
    """

    def __init__(self, seed: bytes, hf: HashF) -> None:
        self.hf = hf
        hf_size = hf().digest_size
        self.v = b"\x01" * hf_size  # 3.2.b
        self.k = b"\x00" * hf_size  # 3.2.c

        self.k = hmac.new(self.k, self.v + b"\x00" + seed, hf).digest()  # 3.2.d
        self.v = hmac.new(self.k, self.v, hf).digest()  # 3.2.e
        self.k = hmac.new(self.k, self.v + b"\x01" + seed, hf).digest()  # 3.2.f
        self.v = hmac.new(self.k, self.v, hf).digest()  # 3.2.g

    def generate(self, size: int) -> bytes:
        """Return that many octets, whole hash outputs cut to length.

        `secp256k1_rfc6979_hmac_sha256_generate` sets its retry flag at
        the end of every call and runs `reseed`'s update at the start of
        every call after the first, so a caller mirroring
        `secp256k1_rangeproof_genrand` over more than one draw calls
        `reseed` between them. Leaving that to the caller is what lets
        `_rfc6979_nonce_` reseed only where RFC6979 says to.
        """
        t = b""  # 3.2.h.1
        while len(t) < size:  # 3.2.h.2
            self.v = hmac.new(self.k, self.v, self.hf).digest()
            t += self.v
        return t[:size]

    def reseed(self) -> None:
        """Advance K and V: 3.2.h.3's step, and zkp's between two draws."""
        self.k = hmac.new(self.k, self.v + b"\x00", self.hf).digest()
        self.v = hmac.new(self.k, self.v, self.hf).digest()


def _rfc6979_nonce_(
    c: int, q: int, ec: Curve, hf: HashF, extra_entropy: bytes | None
) -> int:
    # https://www.rfc-editor.org/rfc/rfc6979.html section 3.2

    # convert the private key q to an octet sequence of size n_size
    q_bytes = q.to_bytes(ec.n_size, byteorder="big", signed=False)
    # truncate and/or expand c: encoding size is driven by n_size
    c_bytes = c.to_bytes(ec.n_size, byteorder="big", signed=False)
    # section 3.6 additional data k', appended to the key and the message
    # rather than mixed in: the RFC leaves the encoding to the caller and
    # libsecp256k1's default nonce function appends its 32 octets here,
    # which is what makes the sign-to-contract vectors of commit_nonce
    # reproducible. `ndata` is the C spelling of those octets, and
    # `aux_rand32` the bindings' -- BIP340's name for the same argument,
    # given to all five entry points that take entropy -- so it is the
    # second that a call from this library names.
    # None and b"" are the same absence of additional data here, appending
    # nothing being appending nothing; the bindings take None alone -- 32
    # bytes or no argument, a shorter one being a caller mistake and not
    # less entropy -- so a caller holding either passes it unchanged
    bprvbm = q_bytes + c_bytes + (extra_entropy or b"")

    drbg = _HmacDrbg(bprvbm, hf)
    while True:  # 3.2.h
        # reducing the hash mod n -- whether the whole of it or its
        # leftmost nlen bits -- would introduce a bias, which is why
        # neither is done here.
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hf_len,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        candidate = drbg.generate(ec.n_size)
        nonce = int_from_bits(candidate, ec.nlen)  # candidate nonce    # 3.2.h.3
        if 0 < nonce < ec.n:  # acceptable values for nonce
            return nonce  # successful candidate
        drbg.reseed()


def rfc6979_nonce_(
    msg_hash: Octets,
    prv_key: Integer,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
    extra_entropy: Octets | None = None,
) -> int:
    """Return an RFC6979 deterministic ephemeral key (nonce).

    see https://www.rfc-editor.org/rfc/rfc6979.html section 3.2

    extra_entropy is the section 3.6 additional data: two callers with
    the same key and message reach different nonces by passing different
    values, and the derivation stays deterministic in all of its inputs.
    It is what a commitment travels through in commit_nonce, what the
    low-R grinding of ``dsa.sign_`` puts its counter in, and what the
    bindings take as ``aux_rand32`` -- `ndata` being the name the C
    function underneath it gives the same 32 octets.
    """
    c = challenge_(msg_hash, ec, hf)
    q = scalar_from_prv_key(prv_key, ec)
    extra = None if extra_entropy is None else bytes_from_octets(extra_entropy)

    return _rfc6979_nonce_(c, q, ec, hf, extra)
