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

from .alias import HashF, Octets, Point, PubKey, SSASig, JacPoint
from .curve import Curve
from .curvemult import (_double_mult, _jac_from_aff, _mult_jac, _multi_mult,
                        double_mult, mult)
from .curves import secp256k1
from .to_pubkey import to_pub_bytes, to_pub_tuple
from .numbertheory import legendre_symbol, mod_inv
from .rfc6979 import rfc6979
from .utils import (bytes_from_hexstring, int_from_bits, int_from_prvkey,
                    octets_from_point, point_from_octets)

# TODO use _mult and _double_mult to avoid useless checks

def _k(d: int, mhd: Octets, hf: HashF = sha256) -> int:
    mhd = bytes_from_hexstring(mhd, hf().digest_size)
    t = d.to_bytes(32, byteorder='big') + mhd
    h = hf()
    h.update(t)
    # FIXME: 0 < k < ec.n
    return int.from_bytes(h.digest(), byteorder='big')


def _e(r: int, Q: PubKey, mhd: Octets,
       ec: Curve = secp256k1, hf: HashF = sha256) -> int:

    # remove PubKey and Octets for bytes
    # note that only Q_x is needed
    # if Q is Jacobian Q_y calculation can be avoided

    # Let e = int(hf(bytes(K_x) || bytes(Q) || mhd)) mod n.
    h = hf()
    h.update(r.to_bytes(ec.psize, 'big'))
    Q = to_pub_bytes(Q, True, ec)
    h.update(Q)
    h.update(bytes_from_hexstring(mhd, hf().digest_size))
    e = int_from_bits(h.digest(), ec)
    return e

# TODO make k Union[int, Octets]
# TODO allow to sign also with WIF: String
# TODO allow to sign also with BIP32key: Union[XkeyDict, String]
def sign(mhd: Octets, prvkey: Union[int, Octets], k: Optional[int] = None,
         ec: Curve = secp256k1, hf: HashF = sha256) -> SSASig:
    """ECSSA signing operation according to bip-schnorr.

    This signature scheme supports only 32-byte messages.
    Differently from ECDSA, the 32-byte message can be a
    digest of other messages, but it does not need to.
    """

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    # The message mhd: a 32-byte array
    mhd = bytes_from_hexstring(mhd, hf().digest_size)

    # The secret key d: an integer in the range 1..n-1.
    q = int_from_prvkey(prvkey, ec)
    Q = mult(q, ec.G, ec)

    # Fail if k' = 0.
    if k is None:
        k = rfc6979(mhd, q, ec, hf)
    if not 0 < k < ec.n:
        raise ValueError(f"ephemeral key {hex(k)} not in [1, n-1]")

    # Let K = kG
    KJ = _mult_jac(k, ec.GJ, ec)
    Z2 = KJ[2]*KJ[2]
    r = (KJ[0]*mod_inv(Z2, ec._p)) % ec._p

    # break the simmetry: any criteria might have been used,
    # jacobi is the proposed bitcoin standard
    # Let k = k' if jacobi(y(K)) = 1, otherwise let k = n - k'.
    if legendre_symbol(KJ[1]*KJ[2] % ec._p, ec._p) != 1:
        k = ec.n - k

    # Let e = int(hf(bytes(K_x) || bytes(Q) || mhd)) mod n.
    e = _e(r, Q, mhd, ec, hf)

    s = (k + e*q) % ec.n  # s=0 is ok: in verification there is no inverse of s
    # The signature is bytes(K_x || bytes((k + ed) mod n)).
    return r, s


def verify(mhd: Octets, Q: PubKey, sig: SSASig,
           ec: Curve = secp256k1, hf: HashF = sha256) -> bool:
    """ECSSA signature verification according to bip-schnorr."""

    # try/except wrapper for the Errors raised by _verify
    try:
        _verify(mhd, Q, sig, ec, hf)
    except Exception:
        return False
    else:
        return True


def _verify(mhd: Octets, Q: PubKey, sig: SSASig,
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

    r, s = _to_sig(sig, ec)

    Q = to_pub_tuple(Q, ec)
    QJ = Q[0], Q[1], 1 if Q[1] else 0
    # TODO is this really required?
    if Q[1] == 0:
        raise ValueError("Public key is infinite")

    # Let e = int(hf(bytes(r) || bytes(Q) || mhd)) mod n.
    e = _e(r, Q, mhd, ec, hf)

    # Let K = sG - eQ.
    # in Jacobian coordinates
    KJ = _double_mult(-e, QJ, s, ec.GJ, ec)

    # Fail if infinite(KJ).
    if KJ[2] == 0:
        raise ValueError("sG - eQ is infinite")

    # Fail if jacobi(K_y) ≠ 1.
    if legendre_symbol(KJ[1]*KJ[2] % ec._p, ec._p) != 1:
        raise ValueError("(sG - eQ)_y is not a quadratic residue")

    # Fail if r ≠ K_x.
    assert KJ[0] == KJ[2]*KJ[2]*r % ec._p, "Invalid signature"


def _recover_pubkeys(e: int, sig: SSASig, ec: Curve = secp256k1) -> Point:
    # Private function provided for testing purposes only.

    r, s = _to_sig(sig)

    K = r, ec.y_quadratic_residue(r, True)
    # FIXME: y_quadratic_residue in Jacobian coordinates?

    if e == 0:
        raise ValueError("Invalid (zero) challenge e")
    e1 = mod_inv(e, ec.n)
    Q = double_mult(-e1, K, e1*s, ec.G, ec)
    assert Q[1] != 0, "how did you do that?!?"
    return Q


def _validate_sig(r: int, s: int, ec: Curve = secp256k1) -> None:
    # check that the SSA signature is correct

    # Fail if r is not a field element, i.e. a valid x-coordinate
    ec.y(r)

    # Fail if s is not [0, n-1].
    if not 0 <= s < ec.n:
        raise ValueError(f"s ({hex(s)}) not in [0, n-1]")


def _to_sig(sig: SSASig, ec: Curve = secp256k1) -> Tuple[int, int]:
    if isinstance(sig, tuple):
        r, s = sig
        _validate_sig(r, s, ec)
    else:
        # it is a serialized sig
        # serialization has not been implemented yet
        # deserialization will go here
        pass
    return r, s


def batch_verify(ms: Sequence[bytes], Q: Sequence[Point], sig: Sequence[SSASig],
                 ec: Curve = secp256k1, hf: HashF = sha256) -> bool:
    """ECSSA batch signature verification according to bip-schnorr."""

    # try/except wrapper for the Errors raised by _batch_verify
    try:
        if len(Q) < 2:
            _verify(ms[0], Q[0], sig[0], ec, hf)
        else:
            _batch_verify(ms, Q, sig, ec, hf)
    except Exception:
        return False
    else:
        return True


def _batch_verify(ms: Sequence[bytes], Q: Sequence[Point], sig: Sequence[SSASig],
                  ec: Curve = secp256k1, hf: HashF = sha256) -> None:

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    batch_size = len(Q)
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
    points: List[JacPoint] = list()
    for i in range(batch_size):
        r, s = sig[i]
        _validate_sig(r, s, ec)
        m = bytes_from_hexstring(ms[i], hf().digest_size)
        ec.require_on_curve(Q[i])
        e = _e(r, Q[i], m, ec, hf)
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
        points.append(_jac_from_aff(Q[i]))
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
