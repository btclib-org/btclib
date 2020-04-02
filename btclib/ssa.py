#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Schnorr Signature Algorithm (ECSSA).

Implementation according to bip-schnorr:

https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki.
"""

import heapq
import random
from hashlib import sha256
from typing import List, Optional, Sequence, Tuple, Union

from .alias import HashF, Octets, Point, PubKey, SSASig, _JacPoint
from .curve import Curve
from .curvemult import (_double_mult, _jac_from_aff, _mult_jac, _multi_mult,
                        double_mult, mult)
from .curves import secp256k1
from .to_pubkey import to_pub_bytes, to_pub_tuple
from .numbertheory import legendre_symbol, mod_inv
from .rfc6979 import rfc6979
from .utils import (bytes_from_hexstring, int_from_bits, int_from_prvkey,
                    octets_from_point, point_from_octets)


def _k(d: int, mhd: Octets, hf: HashF = sha256) -> int:
    mhd = bytes_from_hexstring(mhd, hf().digest_size)
    t = d.to_bytes(32, byteorder='big') + mhd
    h = hf()
    h.update(t)
    # FIXME: 0 < k < ec.n
    return int.from_bytes(h.digest(), byteorder='big')


def _e(r: int, P: PubKey, mhd: Octets,
       ec: Curve = secp256k1, hf: HashF = sha256) -> int:

    # Let e = int(hf(bytes(x(R)) || bytes(dG) || mhd)) mod n.
    h = hf()
    h.update(r.to_bytes(ec.psize, 'big'))
    P = to_pub_bytes(P, True, ec)
    h.update(P)
    h.update(bytes_from_hexstring(mhd, hf().digest_size))
    e = int_from_bits(h.digest(), ec)
    return e


def sign(mhd: Octets, d: Union[int, Octets], k: Optional[int] = None,
         ec: Curve = secp256k1, hf: HashF = sha256) -> SSASig:
    """ECSSA signing operation according to bip-schnorr.

    This signature scheme supports only 32-byte messages.
    Differently from ECDSA, the 32-byte message can be a
    digest of other messages, but it does not need to.
    """

    # The message mhd: a 32-byte array
    mhd = bytes_from_hexstring(mhd, hf().digest_size)

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    # The secret key d: an integer in the range 1..n-1.
    d = int_from_prvkey(d, ec)

    P = mult(d, ec.G, ec)

    # Fail if k' = 0.
    if k is None:
        k = rfc6979(mhd, d, ec, hf)
    if not 0 < k < ec.n:
        raise ValueError(f"ephemeral key {hex(k)} not in [1, n-1]")

    # Let R = k'G.
    RJ = _mult_jac(k, ec.GJ, ec)

    # break the simmetry: any criteria might have been used,
    # jacobi is the proposed bitcoin standard
    # Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k'.
    if legendre_symbol(RJ[1]*RJ[2] % ec._p, ec._p) != 1:
        k = ec.n - k

    Z2 = RJ[2]*RJ[2]
    r = (RJ[0]*mod_inv(Z2, ec._p)) % ec._p

    # Let e = int(hf(bytes(x(R)) || bytes(dG) || mhd)) mod n.
    e = _e(r, P, mhd, ec, hf)

    s = (k + e*d) % ec.n  # s=0 is ok: in verification there is no inverse of s
    # The signature is bytes(x(R) || bytes((k + ed) mod n)).
    return r, s


def verify(mhd: Octets, P: PubKey, sig: SSASig,
           ec: Curve = secp256k1, hf: HashF = sha256) -> bool:
    """ECSSA signature verification according to bip-schnorr."""

    # try/except wrapper for the Errors raised by _verify
    try:
        _verify(mhd, P, sig, ec, hf)
    except Exception:
        return False
    else:
        return True


def _verify(mhd: Octets, P: PubKey, sig: SSASig,
            ec: Curve = secp256k1, hf: HashF = sha256) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    # The message mhd: a 32-byte array
    mhd = bytes_from_hexstring(mhd, hf().digest_size)

    r, s = sig
    _check_sig(r, s, ec)

    # Let P = point(pk); fail if point(pk) fails.
    P = to_pub_tuple(P, ec)
    if P[1] == 0:
        raise ValueError("public key is infinite")

    # Let e = int(hf(bytes(r) || bytes(P) || mhd)) mod n.
    e = _e(r, P, mhd, ec, hf)

    # Let R = sG - eP.
    # in Jacobian coordinates
    R = _double_mult(-e, (P[0], P[1], 1), s, ec.GJ, ec)

    # Fail if infinite(R).
    if R[2] == 0:
        raise ValueError("sG - eP is infinite")

    # Fail if jacobi(R.y) ≠ 1.
    if legendre_symbol(R[1]*R[2] % ec._p, ec._p) != 1:
        raise ValueError("(sG - eP).y is not a quadratic residue")

    # Fail if R.x ≠ r.
    assert R[0] == R[2]*R[2]*r % ec._p, "Invalid signature"


def _pubkey_recovery(e: int, sig: SSASig, ec: Curve = secp256k1) -> Point:
    # Private function provided for testing purposes only.
    # TODO: use _double_mult instead of double_mult

    r, s = sig
    _check_sig(r, s, ec)

    K = r, ec.y_quadratic_residue(r, True)
    # FIXME: y_quadratic_residue in Jacobian coordinates?

    if e == 0:
        raise ValueError("invalid (zero) challenge e")
    e1 = mod_inv(e, ec.n)
    P = double_mult(-e1, K, e1*s, ec.G, ec)
    assert P[1] != 0, "how did you do that?!?"
    return P


def _check_sig(r: int, s: int, ec: Curve = secp256k1) -> None:
    # check that the SSA signature is correct

    # Fail if r is not a field element, i.e. a valid x-coordinate
    ec.y(r)

    # Fail if s is not [0, n-1].
    if not 0 <= s < ec.n:
        raise ValueError(f"s ({hex(s)}) not in [0, n-1]")


def batch_verify(ms: Sequence[bytes], P: Sequence[Point], sig: Sequence[SSASig],
                 ec: Curve = secp256k1, hf: HashF = sha256) -> bool:
    """ECSSA batch signature verification according to bip-schnorr."""

    # try/except wrapper for the Errors raised by _batch_verify
    try:
        if len(P) < 2:
            _verify(ms[0], P[0], sig[0], ec, hf)
        else:
            _batch_verify(ms, P, sig, ec, hf)
    except Exception:
        return False
    else:
        return True


def _batch_verify(ms: Sequence[bytes], P: Sequence[Point], sig: Sequence[SSASig],
                  ec: Curve = secp256k1, hf: HashF = sha256) -> None:

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    batch_size = len(P)
    if len(ms) != batch_size:
        errMsg = f"mismatch between number of pubkeys ({batch_size}) "
        errMsg += f"and number of messages ({len(ms)})"
        raise ValueError(errMsg)
    if len(sig) != batch_size:
        errMsg = f"mismatch between number of pubkeys ({batch_size}) "
        errMsg += f"and number of signatures ({len(sig)})"
        raise ValueError(errMsg)

    t = 0
    scalars: List[int] = list()
    points: List[_JacPoint] = list()
    for i in range(batch_size):
        r, s = sig[i]
        _check_sig(r, s, ec)
        m = bytes_from_hexstring(ms[i], hf().digest_size)
        ec.require_on_curve(P[i])
        e = _e(r, P[i], m, ec, hf)
        # raises an error if y does not exist
        # no need to check for quadratic residue
        y = ec.y(r)

        # a in [1, n-1]
        # deterministically generated using a CSPRNG seeded by a
        # cryptographic hash (e.g., SHA256) of all inputs of the
        # algorithm, or randomly generated independently for each
        # run of the batch verification algorithm
        a = (1 if i == 0 else (1+random.getrandbits(ec.nlen)) % ec.n)
        scalars.append(a)
        points.append(_jac_from_aff((r, y)))
        scalars.append(a * e % ec.n)
        points.append(_jac_from_aff(P[i]))
        t += a * s

    TJ = _mult_jac(t, ec.GJ, ec)
    RHSJ = _multi_mult(scalars, points, ec)

    # return T == RHS, checked in Jacobian coordinates
    RHSZ2 = RHSJ[2] * RHSJ[2]
    TZ2 = TJ[2] * TJ[2]
    precondition = TJ[0]*RHSZ2 % ec._p == RHSJ[0]*TZ2 % ec._p
    assert precondition, "Invalid precondition"

    valid_sig = TJ[1]*RHSZ2*RHSJ[2] % ec._p == RHSJ[1]*TZ2*TJ[2] % ec._p
    assert valid_sig, "Invalid signature"
