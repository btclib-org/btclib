#!/usr/bin/env python3

""" Elliptic Curve Schnorr Signature Algorithm

https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
"""

import heapq
from hashlib import sha256
from typing import List

from btclib.ellipticcurves import Union, Tuple, Optional, \
                                  Scalar as PrvKey, Point as PubKey, \
                                  GenericPoint as GenericPubKey, \
                                  mod_inv, \
                                  EllipticCurve, secp256k1, jac_from_affine, \
                                  DoubleScalarMultiplication, \
                                  int_from_Scalar, tuple_from_Point, \
                                  bytes_from_Point
from btclib.rfc6979 import rfc6979
from btclib.ecsignutils import Message, Signature, int_from_hash

def ecssa_sign(M: Message,
               q: PrvKey,
               k: Optional[PrvKey] = None,
               ec: EllipticCurve = secp256k1,
               Hash = sha256) -> Signature:
    """ECSSA signing operation according to bip-schnorr"""
    m = Hash(M).digest()
    q = int_from_Scalar(ec, q)
    k = None if k is None else int_from_Scalar(ec, k)
    return _ecssa_sign(m, q, k, ec, Hash)

# Private function provided for testing purposes only.
# To avoid forgeable signature, sign and verify should
# always use the message, not its hash digest.
def _ecssa_sign(m: bytes,
                d: int,
                k: Optional[int] = None,
                ec: EllipticCurve = secp256k1,
                Hash = sha256) -> Signature:
    #ECSSA signing operation according to bip-schnorr

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    # The message digest m: a 32-byte array
    if len(m) != Hash().digest_size:
        errmsg = 'message digest of wrong size %s' % len(m)
        raise ValueError(errmsg)

    # The secret key d: an integer in the range 1..n-1.
    G = jac_from_affine(ec.G) 
    Q = ec.pointMultiplyJacobian(d, G)
    if Q is None:
        raise ValueError("invalid (zero) private key")

    # Fail if k' = 0.
    if k is None:
        k = rfc6979(d, m, Hash)
    k = k % ec.n

    # Let R = k'G.
    R = ec.pointMultiplyJacobian(k, G)
    if R is None: # this makes mypy happy in R[0]
        raise ValueError("ephemeral key k=0 in ecssa sign operation")

    # Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k' .
    # break the simmetry: any criteria might have been used,
    # jacobi is the proposed bitcoin standard
    if ec.jacobi(R[1]) != 1:
        # no need to actually change R[1], as it is not used anymore
        # let just fix k instead, as it is used later
        k = ec.n - k

    # Let e = int(hash(bytes(x(R)) || bytes(dG) || m)) mod n.
    ebytes  = R[0].to_bytes(ec.bytesize, byteorder="big")
    ebytes += bytes_from_Point(ec, Q, True)
    ebytes += m
    ebytes = Hash(ebytes).digest()
    e = int_from_hash(ebytes, ec.n, Hash().digest_size)

    # The signature is bytes(x(R)) || bytes(k + ed mod n).
    s = (k + e*d) % ec.n
    # no need for s!=0, as in verification there will be no inverse of s
    return R[0], s

def ecssa_verify(M: Message,
                 ssasig: Signature,
                 Q: GenericPubKey,
                 ec: EllipticCurve = secp256k1,
                 Hash = sha256) -> bool:
    """ECSSA veryfying operation according to bip-schnorr"""
    try:
        m = Hash(M).digest()
        Q =  tuple_from_Point(ec, Q)
        return _ecssa_verify(m, ssasig, Q, ec, Hash)
    except Exception:
        return False

# Private function provided for testing purposes only.
# To avoid forgeable signature, sign and verify should
# always use the message, not its hash digest.
def _ecssa_verify(m: bytes,
                  ssasig: Signature,
                  P: PubKey,
                  ec: EllipticCurve = secp256k1,
                  Hash = sha256) -> bool:
    # ECSSA veryfying operation according to bip-schnorr

    # Let P = point(pk); fail if point(pk) fails.
    # already satisfied!

    # The message digest m: a 32-byte array
    if len(m) != Hash().digest_size:
        errmsg = 'message digest of wrong size %s' % len(m)
        raise ValueError(errmsg)

    try:
        # Let r = int(sig[0:32]); fail if r ≥ p.
        # Let s = int(sig[32:64]); fail if s ≥ n.
        r, s = check_ssasig(ssasig, ec)
        # Let e = int(hash(bytes(r) || bytes(P) || m)) mod n.
        ebytes  = r.to_bytes(ec.bytesize, byteorder="big")
        ebytes += bytes_from_Point(ec, P, True)
        ebytes += m
        ebytes  = Hash(ebytes).digest()
        e = int_from_hash(ebytes, ec.n, Hash().digest_size)
        # Let R = sG - eP.
        R = DoubleScalarMultiplication(ec, s, -e, ec.G, P)
        # Fail if infinite(R) or jacobi(y(R)) ≠ 1 or x(R) ≠ r.
        if R is None:
            return False
        if ec.jacobi(R[1]) != 1:
            return False
        return R[0] == r
    except Exception:
        return False

def ecssa_pubkey_recovery(e: bytes,
                          ssasig: Signature,
                          ec: EllipticCurve = secp256k1,
                          Hash = sha256) -> PubKey:
    assert len(e) == 32
    # check that e is bytes
    return ecssa_pubkey_recovery(e, ssasig, ec, Hash)

def _ecssa_pubkey_recovery(ebytes: bytes,
                           ssasig: Signature,
                           ec: EllipticCurve = secp256k1,
                           Hash = sha256) -> PubKey:
    r, s = check_ssasig(ssasig, ec)
    K = (r, ec.yQuadraticResidue(r, True))
    e = int_from_hash(ebytes, ec.n, Hash().digest_size)
    assert e != 0, "invalid challenge e"
    e1 = mod_inv(e, ec.n)
    Q = DoubleScalarMultiplication(ec, e1*s, -e1, ec.G, K)
    assert Q is not None, "failed"
    return Q

def check_ssasig(ssasig: Signature,
                 ec: EllipticCurve = secp256k1) -> Signature:
    """check SSA signature format is correct and return the signature itself"""

    # A signature sig: a 64-byte array.
    if len(ssasig) != 2:
        m = "invalid length %s for ECSSA signature" % len(ssasig)
        raise TypeError(m)

    # Let r = int(sig[0:32]); fail if r ≥ p.
    r = int(ssasig[0])
    ec.checkPointCoordinate(r) # r is in [0, p-1]

    # R.x is valid iif R.y does exist and it is a quadratic residue;
    # this might be too much,
    # but it also perform the mandatory check that ec.pIsThreeModFour
    ec.yQuadraticResidue(r, False)

    # Let s = int(sig[32:64]); fail if s ≥ n.
    s = int(ssasig[1])
    if not (0 <= s < ec.n):
        raise ValueError("s not in [0, n-1]")

    return r, s

def ecssa_batch_validation(ms: List[bytes],
                           sig: List[Signature],
                           Q: List[PubKey],
                           a: List[int],
                           ec: EllipticCurve = secp256k1,
                           Hash = sha256) -> bool:
    u = len(Q)
    # initialization
    mult = 0
    points = list()
    factors = list()

    for i in range(0, u):
        r, s = sig[i]
        ebytes = r.to_bytes(32, byteorder="big")
        ebytes += bytes_from_Point(ec, Q[i], True)
        ebytes += ms[i]
        ebytes = Hash(ebytes).digest()
        e = int_from_hash(ebytes, ec.n, Hash().digest_size)

        # FIXME: curve prime
        p = ec._p
        c = (pow(r, 3) + 7) % p
        y = pow(c, (p + 1) // 4, p)
        assert pow(y, 2, p) == c

        mult += a[i] * s % ec.n
        points.append(jac_from_affine((r, y)))
        factors.append(a[i])
        points.append(jac_from_affine(Q[i]))
        factors.append(a[i] * e % ec.n)

    # Bos-coster's algorithm, source:
    # https://cr.yp.to/badbatch/boscoster2.py
    boscoster = list(zip([-n for n in factors], points))
    heapq.heapify(boscoster)
    while len(boscoster) > 1:
        aK1 = heapq.heappop(boscoster)
        aK2 = heapq.heappop(boscoster)
        a1, K1 = -aK1[0], aK1[1]
        a2, K2 = -aK2[0], aK2[1]
        K2 = ec.pointAddJacobian(K1, K2)
        a1 -= a2
        if a1 > 0: 
            heapq.heappush(boscoster,(-a1, K1))
        heapq.heappush(boscoster,(-a2, K2))
        
    aK = heapq.heappop(boscoster)
    RHS = ec.pointMultiplyJacobian(-aK[0], aK[1])
    
    return ec.pointMultiplyJacobian(mult, jac_from_affine(ec.G)) == RHS
