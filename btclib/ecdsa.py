#!/usr/bin/env python3

""" Elliptic Curve Digital Signature Algorithm
"""

from hashlib import sha256
from typing import List

from btclib.ellipticcurves import Union, Tuple, Optional, \
                                  Scalar as PrvKey, Point as PubKey, \
                                  GenericPoint as GenericPubKey, \
                                  mod_inv, \
                                  EllipticCurve, secp256k1, jac_from_affine, \
                                  DoubleScalarMultiplication, \
                                  int_from_Scalar, tuple_from_Point
from btclib.rfc6979 import rfc6979
from btclib.ecsignutils import Message, Signature, \
                               bytes_from_msg, int_from_hash

def ecdsa_sign(msg: Message,
               q: PrvKey,
               eph: Optional[PrvKey] = None,
               ec: EllipticCurve = secp256k1,
               Hash = sha256) -> Signature:
    """ECDSA signing operation according to SEC 2

    Here input parameters are converted,
    the actual signing operation is delegated to ecdsa_sign_raw
    """
    M = bytes_from_msg(msg)
    q = int_from_Scalar(ec, q)
    eph = None if eph is None else int_from_Scalar(ec, eph)
    return ecdsa_sign_raw(M, q, eph, ec, Hash)

def ecdsa_sign_raw(M: bytes,
                   d: int,
                   k: Optional[int] = None,
                   ec: EllipticCurve = secp256k1,
                   Hash = sha256) -> Signature:
    """ECDSA signing operation according to SEC 2

    See section 4.1.3
    """
    H = Hash(M).digest()
    return _ecdsa_sign_raw(H, d, k, ec, Hash)

# Private function provided for testing purposes only.
# To avoid forgeable signature, sign and verify should
# always use the message, not its hash digest.
def _ecdsa_sign_raw(H: bytes,
                    d: int,
                    k: Optional[int] = None,
                    ec: EllipticCurve = secp256k1,
                    Hash = sha256) -> Signature:
    # ECDSA signing operation according to SEC 2
    # See section 4.1.3

    if len(H) != Hash().digest_size:
        errmsg = 'message digest of wrong size %s' % len(H)
        raise ValueError(errmsg)

    # The secret key d: an integer in the range 1..n-1.
    if 0 == d % ec.n:
        raise ValueError("invalid (zero) private key")

    # Fail if k' = 0.
    if k is None:
        k = rfc6979(d, H, Hash)                            # 1
    k = k % ec.n

    R = ec.pointMultiplyJacobian(k, jac_from_affine(ec.G)) # 1
    if R is None: # this makes mypy happy in R[0]
        raise ValueError("ephemeral key k=0 in ecdsa sign operation")

    xR = R[0]                                              # 2
    r = xR % ec.n                                          # 3
    if r==0:
        raise ValueError("r = 0, failed to sign")
    # already got H as input                               # 4
    e = int_from_hash(H, ec.n)                             # 5
    s = mod_inv(k, ec.n) * (e + r*d) % ec.n                # 6
    if s==0: # required as in verification the inverse of s is needed
        raise ValueError("s = 0, failed to sign")
    return r, s

def ecdsa_verify(msg: Message,
                 dsasig: Signature,
                 Q: GenericPubKey,
                 ec: EllipticCurve = secp256k1,
                 Hash = sha256) -> bool:
    """ECDSA veryfying operation to SEC 2

    Here input parameters are converted,
    the actual veryfying operation is delegated to ecdsa_verify_raw
    """
    try:
        M = bytes_from_msg(msg)
        Q = tuple_from_Point(ec, Q)
        return ecdsa_verify_raw(M, dsasig, Q, ec, Hash)
    except Exception:
        return False

def ecdsa_verify_raw(M: bytes,
                     dsasig: Signature,
                     Q: PubKey,
                     ec: EllipticCurve = secp256k1,
                     Hash = sha256) -> bool:
    """ECDSA veryfying operation to SEC 2

    See section 4.1.4
    """
    try:
        H = Hash(M).digest()
        return _ecdsa_verify_raw(H, dsasig, Q, ec, Hash)
    except Exception:
        return False

# Private function provided for testing purposes only.
# To avoid forgeable signature, sign and verify should
# always use the message, not its hash digest.
def _ecdsa_verify_raw(H: bytes,
                      dsasig: Signature,
                      Q: PubKey,
                      ec: EllipticCurve = secp256k1,
                      Hash = sha256) -> bool:
    # ECDSA veryfying operation to SEC 2
    # See section 4.1.4
    try:
        r, s = check_dsasig(dsasig, ec)                     # 1
        # H already provided as input                       # 2
        e = int_from_hash(H, ec.n)                          # 3
        s1 = mod_inv(s, ec.n); u1 = e*s1; u2 = r*s1         # 4
        R = DoubleScalarMultiplication(ec, u1, u2, ec.G, Q) # 5
        if R is None:
            return False
        xR = R[0]                                           # 6
        v = xR % ec.n                                       # 7
        return v == r                                       # 8
    except Exception:
        return False

def ecdsa_pubkey_recovery(msg: Message,
                          dsasig: Signature,
                          ec: EllipticCurve = secp256k1,
                          Hash = sha256) -> List[PubKey]:
    """ECDSA public key recovery operation according to SEC 2

    Here input parameters are converted,
    the actual public key recovery operation is delegated to ecdsa_pubkey_recovery_raw
    """
    M = bytes_from_msg(msg)
    return ecdsa_pubkey_recovery_raw(M, dsasig, ec, Hash)

def ecdsa_pubkey_recovery_raw(M: bytes,
                              dsasig: Signature,
                              ec: EllipticCurve = secp256k1,
                              Hash = sha256) -> List[PubKey]:
    """ECDSA public key recovery operation according to SEC 2

    See section 4.1.6
    """
    H = Hash(M).digest()
    return _ecdsa_pubkey_recovery_raw(H, dsasig, ec)

# Private function provided for testing purposes only.
# To avoid forgeable signature, sign and verify should
# always use the message, not its hash digest.
def _ecdsa_pubkey_recovery_raw(H: bytes,
                               dsasig: Signature,
                               ec: EllipticCurve = secp256k1) -> List[PubKey]:
    # ECDSA public key recovery operation according to SEC 2
    # See section 4.1.6
 
    r, s = check_dsasig(dsasig, ec)

    # precomputations
    e = int_from_hash(H, ec.n)      # ECDSA verification step 3
    r1 = mod_inv(r, ec.n)
    r1s = r1*s
    r1e =-r1*e
    keys = []
    for j in range(0, 2): # FIXME: use ec.cofactor+1 instead of 2
        x = r + j*ec.n # 1.1
        try:
            R = (x, ec.yOdd(x, 1)) # 1.2, 1.3, and 1.4
            # 1.5 already taken care outside this for loop
            Q = DoubleScalarMultiplication(ec, r1s, r1e, R, ec.G) # 1.6.1
            # 1.6.2 is always satisfied for us, and we do not stop here
            keys.append(Q)
            R = ec.opposite(R)                                    # 1.6.3
            Q = DoubleScalarMultiplication(ec, r1s, r1e, R, ec.G)
            keys.append(Q)
        except Exception: # can't get a curve's point
            pass
    return keys

def check_dsasig(dsasig: Signature, ec: EllipticCurve) -> Signature:
    """check signature format is correct and return the signature itself"""

    if len(dsasig) != 2:
        m = "invalid length %s for ECDSA signature" % len(dsasig)
        raise TypeError(m)

    r = int(dsasig[0])
    if r<0 or r>=ec.n:
        raise ValueError("r not in [1, n-1]")

    s = int(dsasig[1])
    if s<0 or s>=ec.n:
        raise ValueError("s not in [1, n-1]")

    return r, s
