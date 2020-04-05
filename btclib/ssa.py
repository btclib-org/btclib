#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Schnorr Signature Algorithm (ECSSA).

This implementation is according to BIP340-Schnorr:

https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

Differently from ECDSA, the BIP340-Schnorr scheme supports
messages of size hsize only.

It also uses as public key the x-coordinate (field element)
of the curve point associated to the private key 0 < q < n.
As such, both q and n-q share the same public key. 
For sepcp256k1 the public key size is 32 bytes.

To allow for efficient batch verification of multiple signatures,
BIP340-Schnorr uses a challenge that prevents public key recovery
from signature.
    
BIP340-Schnorr advocates a custom deterministic algorithm
for the ephemeral key (nonce) used for signing,
instead of the RFC6979 standard.

BIP340-Schnorr adopts a robust [r][s] custom serialization
format, instead of the loosely specified ASN.1 DER standard.
The signature size is p-size*n-size, where p-size is the
byte size of a field element (point coordinate) and n-size is the
byte size of a scalar (point multiplication coefficient).
For sepcp256k1 the resulting signature size is 64 bytes.
"""

import heapq
import secrets
from hashlib import sha256
from typing import List, Optional, Sequence, Tuple, Union

from btclib import bip32

from .alias import HashF, JacPoint, Octets, Point, PubKey, SSASig
from .curve import Curve
from .curvemult import (_double_mult, _jac_from_aff, _mult_jac, _multi_mult,
                        double_mult, mult)
from .curves import secp256k1
from .numbertheory import mod_inv
from .to_prvkey import to_prvkey_int
from .to_pubkey import to_pub_bytes, to_pub_tuple
from .utils import (_int_from_bits, bytes_from_octets, bytes_from_point,
                    int_from_bits, point_from_octets)

# TODO use _mult and _double_mult to avoid useless checks
# TODO remove the p_ThreeModFour requirement


def serialize(x_K: int, s: int, ec: Curve = secp256k1) -> bytes:
    """Return a BIP340-Schnorr signature serialization."""

    # BIP340-Schnorr is only defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    _validate_sig(x_K, s, ec)
    sig = x_K.to_bytes(ec.psize, 'big') + s.to_bytes(ec.nsize, 'big')
    return sig


def deserialize(sig: Octets, ec: Curve = secp256k1) -> Tuple[int, int]:
    """Return a BIP340-Schnorr signature as (r, s) tuple."""

    # BIP340-Schnorr is only defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    sig = bytes_from_octets(sig, ec.psize+ec.nsize)

    r = int.from_bytes(sig[:ec.psize], byteorder='big')
    s = int.from_bytes(sig[ec.psize:], byteorder='big')
    _validate_sig(r, s, ec)
    return r, s


def k(mhd: Octets, prvkey: Union[int, bytes, str, bip32.XkeyDict],
      ec: Curve = secp256k1, hf: HashF = sha256) -> int:
    """Return a BIP340-Schnorr deterministic ephemeral key (nonce)."""

    # The message mhd: a hlen array
    mhd = bytes_from_octets(mhd, hf().digest_size)

    # The secret key d: an integer in the range 1..n-1.
    q = to_prvkey_int(prvkey, ec)

    return _k(mhd, q, ec, hf)


def _k(mhd: bytes, q: int, ec: Curve, hf: HashF) -> int:

    t = q.to_bytes(ec.nsize, 'big') + mhd
    while True:
        t = _tagged_hash("BIPSchnorrDerive", t, hf)
        # The following line would introduce a bias
        # k = int.from_bytes(t, 'big') % ec.n
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hlen,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        k = _int_from_bits(t, ec)  # candidate k
        if 0 < k < ec.n:           # acceptable value for k
            return k               # successful candidate


def pubkey_gen(prvkey: Union[int, bytes, str, bip32.XkeyDict],
               ec: Curve = secp256k1) -> bytes:
    """Return a BIP340-Schnorr p-size public key."""
    # BIP340-Schnorr is only defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    x = to_prvkey_int(prvkey, ec)
    Q = mult(x, ec.G, ec)
    return Q[0].to_bytes(ec.psize, byteorder="big")


# This implementation can be sped up by storing the midstate after hashing
# tag_hash instead of rehashing it all the time.
def _tagged_hash(tag: str, mhd: bytes, hf: HashF) -> bytes:
    t = tag.encode()
    h1 = hf()
    h1.update(t)
    tag_hash = h1.digest()
    h2 = hf()
    h2.update(tag_hash + tag_hash + mhd)
    return h2.digest()


def _challenge(r: int, x_Q: int, mhd: bytes, ec: Curve, hf: HashF) -> int:

    # note that only x_Q is needed
    # if Q is Jacobian Q_y calculation can be avoided

    t = r.to_bytes(ec.psize, 'big')
    t += x_Q.to_bytes(ec.psize, 'big')
    # mhd size must have been already checked to be equal to hsize
    t += mhd
    t = _tagged_hash("BIPSchnorr", t, hf)
    c = int_from_bits(t, ec)
    if c == 0:
        raise ValueError("Invalid (zero) challenge")
    return c


def sign(mhd: Octets, prvkey: Union[int, bytes, str, bip32.XkeyDict],
         k: Optional[Union[int, Octets]] = None,
         ec: Curve = secp256k1, hf: HashF = sha256) -> SSASig:
    """Sign message according to BIP340-Schnorr signature algorithm."""

    # BIP340-Schnorr is only defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    # The message mhd: a hlen array
    mhd = bytes_from_octets(mhd, hf().digest_size)

    # The secret key d: an integer in the range 1..n-1.
    q = to_prvkey_int(prvkey, ec)
    QJ = _mult_jac(q, ec.GJ, ec)
    x_Q = (QJ[0]*mod_inv(QJ[2]*QJ[2], ec._p)) % ec._p
    if not ec.has_square_y(QJ):
        q = ec.n - q

    # Fail if k' = 0.
    if k is None:
        k = _k(mhd, q, ec, hf)
    else:
        k = to_prvkey_int(k, ec)

    # Let K = kG
    KJ = _mult_jac(k, ec.GJ, ec)
    x_K = (KJ[0]*mod_inv(KJ[2]*KJ[2], ec._p)) % ec._p
    # Let k = k' if jacobi(y_K) = 1, otherwise let k = n - k'.
    if not ec.has_square_y(KJ):
        k = ec.n - k

    # Let c = int(hf(bytes(x_K) || bytes(Q) || mhd)) mod n.
    c = _challenge(x_K, x_Q, mhd, ec, hf)

    # s=0 is ok: in verification there is no inverse of s
    s = (k + c*q) % ec.n

    # The signature is bytes(x_K || bytes((k + ed) mod n)).
    return x_K, s


def verify(mhd: Octets, Q: Union[Octets, Point], sig: SSASig,
           ec: Curve = secp256k1, hf: HashF = sha256) -> bool:
    """Verify the BIP340-Schnorr signature of the provided message."""

    # try/except wrapper for the Errors raised by _verify
    try:
        _verify(mhd, Q, sig, ec, hf)
    except Exception:
        return False
    else:
        return True


def _verify(mhd: Octets, Q: Union[Octets, Point], sig: SSASig,
            ec: Curve, hf: HashF) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # BIP340-Schnorr is only defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    # The message mhd: a hlen array
    mhd = bytes_from_octets(mhd, hf().digest_size)

    r, s = _to_sig(sig, ec)

    if isinstance(Q, tuple):
        x_Q = Q[0]
    else:
        Q = bytes_from_octets(Q, ec.psize)
        x_Q = int.from_bytes(Q, 'big')
    QJ = x_Q, ec.y_quadratic_residue(x_Q, True), 1

    # Let c = int(hf(bytes(r) || bytes(Q) || mhd)) mod n.
    c = _challenge(r, x_Q, mhd, ec, hf)

    # Let K = sG - eQ.
    # in Jacobian coordinates
    KJ = _double_mult(-c, QJ, s, ec.GJ, ec)

    # Fail if infinite(KJ).
    # Fail if jacobi(y_K) ≠ 1.
    ec.require_square_y(KJ)

    # Fail if x_K ≠ r
    assert KJ[0] == KJ[2]*KJ[2]*r % ec._p, "Signature verification failed"


def _recover_pubkeys(c: int, r: int, s: int, ec: Curve) -> int:
    # Private function provided for testing purposes only.

    K = r, ec.y_quadratic_residue(r, True)

    e1 = mod_inv(c, ec.n)
    Q = double_mult(-e1, K, e1*s, ec.G, ec)
    assert Q[1] != 0, "how did you do that?!?"
    return Q[0]


def _validate_sig(r: int, s: int, ec: Curve) -> None:
    # check that the SSA signature is correct

    # Fail if r is not a field element, i.e. not a valid x-coordinate
    ec.y(r)

    # Fail if s is not [0, n-1].
    if not 0 <= s < ec.n:
        raise ValueError(f"s ({hex(s)}) not in [0, n-1]")


def _to_sig(sig: SSASig, ec: Curve) -> Tuple[int, int]:
    if isinstance(sig, tuple):
        r, s = sig
        _validate_sig(r, s, ec)
    else:
        # it is a serialized signature
        r, s = deserialize(sig, ec)
    return r, s


def batch_verify(ms: Sequence[Octets],
                 Qs: Sequence[Union[Octets, Point]],
                 sigs: Sequence[SSASig],
                 ec: Curve = secp256k1, hf: HashF = sha256) -> bool:
    """Batch verification of BIP340-Schnorr signatures."""

    # try/except wrapper for the Errors raised by _batch_verify
    try:
        _batch_verify(ms, Qs, sigs, ec, hf)
    except Exception:
        return False
    else:
        return True


def _batch_verify(ms: Sequence[Octets],
                  Qs: Sequence[Union[Octets, Point]],
                  sigs: Sequence[SSASig],
                  ec: Curve, hf: HashF) -> None:

    # BIP340-Schnorr is only defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    batch_size = len(Qs)
    if len(ms) != batch_size:
        errMsg = f"mismatch between number of pubkeys ({batch_size}) "
        errMsg += f"and number of messages ({len(ms)})"
        raise ValueError(errMsg)
    if len(sigs) != batch_size:
        errMsg = f"mismatch between number of pubkeys ({batch_size}) "
        errMsg += f"and number of signatures ({len(sigs)})"
        raise ValueError(errMsg)

    if batch_size < 2:
        return _verify(ms[0], Qs[0], sigs[0], ec, hf)

    t = 0
    scalars: List[int] = list()
    points: List[JacPoint] = list()
    for i, (m, Q, sig) in enumerate(zip(ms, Qs, sigs)):
        m = bytes_from_octets(m, hf().digest_size)

        r, s = _to_sig(sig, ec)
        KJ = r, ec.y_quadratic_residue(r, True), 1

        if isinstance(Q, tuple):
            x_Q = Q[0]
        else:
            Q = bytes_from_octets(Q, ec.psize)
            x_Q = int.from_bytes(Q, 'big')
        QJ = x_Q, ec.y_quadratic_residue(x_Q, True), 1

        c = _challenge(r, x_Q, m, ec, hf)

        # a in [1, n-1]
        # deterministically generated using a CSPRNG seeded by a
        # cryptographic hash (e.g., SHA256) of all inputs of the
        # algorithm, or randomly generated independently for each
        # run of the batch verification algorithm
        a = (1 if i == 0 else 1+secrets.randbelow(ec.n-1))
        scalars.append(a)
        points.append(KJ)
        scalars.append(a * c % ec.n)
        points.append(QJ)
        t += a * s

    TJ = _mult_jac(t, ec.GJ, ec)
    RHSJ = _multi_mult(scalars, points, ec)

    # return T == RHS, checked in Jacobian coordinates
    RHSZ2 = RHSJ[2] * RHSJ[2]
    TZ2 = TJ[2] * TJ[2]
    precondition = TJ[0]*RHSZ2 % ec._p == RHSJ[0]*TZ2 % ec._p
    assert precondition, "Signature verification precondition failed"

    valid_sig = TJ[1]*RHSZ2*RHSJ[2] % ec._p == RHSJ[1]*TZ2*TJ[2] % ec._p
    assert valid_sig, "Signature verification failed"
