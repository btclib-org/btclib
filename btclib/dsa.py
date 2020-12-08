#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Digital Signature Algorithm (ECDSA).

   Implementation according to SEC 1 v.2:

   http://www.secg.org/sec1-v2.pdf

   specialized with bitcoin canonical 'low-s' encoding.
"""

import secrets
from hashlib import sha256
from typing import List, Optional, Tuple, Union

from .alias import HashF, JacPoint, Octets, Point, String
from .curve import Curve, secp256k1
from .curve_group import _double_mult, _mult
from .der import Sig
from .exceptions import BTClibRuntimeError, BTClibValueError
from .hashes import reduce_to_hlen
from .number_theory import mod_inv
from .rfc6979 import __rfc6979
from .to_prv_key import PrvKey, int_from_prv_key
from .to_pub_key import Key, point_from_key
from .utils import bytes_from_octets, int_from_bits


def gen_keys(prv_key: PrvKey = None, ec: Curve = secp256k1) -> Tuple[int, Point]:
    "Return a private/public (int, Point) key-pair."

    if prv_key is None:
        # q in the range [1, ec.n-1]
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = int_from_prv_key(prv_key, ec)

    QJ = _mult(q, ec.GJ, ec)
    Q = ec._aff_from_jac(QJ)
    # q.to_bytes(ec.nsize, byteorder="big", signed=False)
    # bytes_from_point(Q, ec, compressed)
    return q, Q


def _challenge(m: Octets, ec: Curve = secp256k1, hf: HashF = sha256) -> int:

    # The message m: a hlen array
    hlen = hf().digest_size
    m = bytes_from_octets(m, hlen)

    # leftmost ec.nlen bits %= ec.n
    c = int_from_bits(m, ec.nlen) % ec.n  # 5
    return c


def challenge(msg: String, ec: Curve = secp256k1, hf: HashF = sha256) -> int:

    m = reduce_to_hlen(msg, hf)
    return _challenge(m, ec, hf)


def __sign(c: int, q: int, k: int, low_s: bool, ec: Curve) -> Sig:
    # Private function for testing purposes: it allows to explore all
    # possible value of the challenge c (for low-cardinality curves).
    # It assume that c is in [0, n-1], while q and k are in [1, n-1]

    # Steps numbering follows SEC 1 v.2 section 4.1.3

    KJ = _mult(k, ec.GJ, ec)  # 1

    # affine x_K-coordinate of K (field element)
    x_K = (KJ[0] * mod_inv(KJ[2] * KJ[2], ec.p)) % ec.p
    # mod n makes it a scalar
    r = x_K % ec.n  # 2, 3
    if r == 0:  # r≠0 required as it multiplies the public key
        raise BTClibRuntimeError("failed to sign: r = 0")

    s = mod_inv(k, ec.n) * (c + r * q) % ec.n  # 6
    if s == 0:  # s≠0 required as verify will need the inverse of s
        raise BTClibRuntimeError("failed to sign: s = 0")

    # bitcoin canonical 'low-s' encoding for ECDSA signatures
    # it removes signature malleability as cause of transaction malleability
    # see https://github.com/bitcoin/bitcoin/pull/6769
    if low_s and s > ec.n / 2:
        s = ec.n - s  # s = - s % ec.n

    return Sig(r, s, ec)


def _sign(
    m: Octets,
    prv_key: PrvKey,
    k: Optional[PrvKey] = None,
    low_s: bool = True,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """Sign a hlen bytes message according to ECDSA signature algorithm.

    If the deterministic nonce is not provided,
    the RFC6979 specification is used.
    """

    # the message m: a hlen array
    hlen = hf().digest_size
    m = bytes_from_octets(m, hlen)

    # the secret key q: an integer in the range 1..n-1.
    # SEC 1 v.2 section 3.2.1
    q = int_from_prv_key(prv_key, ec)

    # the challenge
    c = _challenge(m, ec, hf)  # 4, 5

    # the nonce k: an integer in the range 1..n-1.
    if k is None:
        k = __rfc6979(c, q, ec, hf)  # 1
    else:
        k = int_from_prv_key(k, ec)

    # second part delegated to helper function
    return __sign(c, q, k, low_s, ec)


def sign(
    msg: String,
    prv_key: PrvKey,
    low_s: bool = True,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """ECDSA signature with canonical low-s preference.

    Implemented according to SEC 1 v.2
    The message msg is first processed by hf, yielding the value

        m = hf(msg),

    a sequence of bits of length *hlen*.

    Normally, hf is chosen such that its output length *hlen* is
    roughly equal to *nlen*, the bit-length of the group order *n*,
    since the overall security of the signature scheme will depend on
    the smallest of *hlen* and *nlen*; however, the ECDSA standard
    supports all combinations of *hlen* and *nlen*.

    RFC6979 is used for deterministic nonce.

    See https://tools.ietf.org/html/rfc6979#section-3.2
    """

    m = reduce_to_hlen(msg, hf)
    return _sign(m, prv_key, None, low_s, ec, hf)


def __assert_as_valid(c: int, QJ: JacPoint, r: int, s: int, ec: Curve) -> None:
    # Private function for test/dev purposes

    w = mod_inv(s, ec.n)
    u = c * w % ec.n
    v = r * w % ec.n  # 4
    # Let K = u*G + v*Q.
    KJ = _double_mult(v, QJ, u, ec.GJ, ec)  # 5

    # Fail if infinite(K).
    # edge case that cannot be reproduced in the test suite
    if KJ[2] == 0:  # 5
        err_msg = "invalid (INF) key"  # pragma: no cover
        raise BTClibRuntimeError(err_msg)  # pragma: no cover

    # affine x_K-coordinate of K
    x_K = (KJ[0] * mod_inv(KJ[2] * KJ[2], ec.p)) % ec.p
    # Fail if r ≠ x_K %n.
    if r != x_K % ec.n:  # 6, 7, 8
        raise BTClibRuntimeError("signature verification failed")


def _assert_as_valid(
    m: Octets, key: Key, sig: Union[Sig, Octets], hf: HashF = sha256
) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    if not isinstance(sig, Sig):
        sig = Sig.deserialize(sig)
    else:
        sig.assert_valid()  # 1

    # The message m: a hlen array
    m = bytes_from_octets(m, hf().digest_size)
    c = _challenge(m, sig.ec, hf)  # 2, 3

    Q = point_from_key(key, sig.ec)
    QJ = Q[0], Q[1], 1

    # second part delegated to helper function
    __assert_as_valid(c, QJ, sig.r, sig.s, sig.ec)


def assert_as_valid(
    msg: String, key: Key, sig: Union[Sig, Octets], hf: HashF = sha256
) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    m = reduce_to_hlen(msg, hf)
    _assert_as_valid(m, key, sig, hf)


def _verify(m: Octets, key: Key, sig: Union[Sig, Octets], hf: HashF = sha256) -> bool:
    """ECDSA signature verification (SEC 1 v.2 section 4.1.4)."""

    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        _assert_as_valid(m, key, sig, hf)
    except Exception:  # pylint: disable=broad-except
        return False
    else:
        return True


def verify(msg: String, key: Key, sig: Union[Sig, Octets], hf: HashF = sha256) -> bool:
    """ECDSA signature verification (SEC 1 v.2 section 4.1.4)."""

    m = reduce_to_hlen(msg, hf)
    return _verify(m, key, sig, hf)


def recover_pub_keys(
    msg: String, sig: Union[Sig, Octets], hf: HashF = sha256
) -> List[Point]:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See also:
    https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106
    """

    m = reduce_to_hlen(msg, hf)
    return _recover_pub_keys(m, sig, hf)


def _recover_pub_keys(
    m: Octets, sig: Union[Sig, Octets], hf: HashF = sha256
) -> List[Point]:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See also:
    https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106
    """

    if not isinstance(sig, Sig):
        sig = Sig.deserialize(sig)
    else:
        sig.assert_valid()  # 1

    # The message m: a hlen array
    hlen = hf().digest_size
    m = bytes_from_octets(m, hlen)

    c = _challenge(m, sig.ec, hf)  # 1.5

    QJs = __recover_pub_keys(c, sig.r, sig.s, sig.ec)
    return [sig.ec._aff_from_jac(QJ) for QJ in QJs]


# TODO: use __recover_pub_key to avoid code duplication
def __recover_pub_keys(c: int, r: int, s: int, ec: Curve) -> List[JacPoint]:
    # Private function provided for testing purposes only.

    # precomputations
    r_1 = mod_inv(r, ec.n)
    r1s = r_1 * s % ec.n
    r1e = -r_1 * c % ec.n
    keys: List[JacPoint] = []
    # r = K[0] % ec.n
    # if ec.n < K[0] < ec.p (likely when cofactor ec.cofactor > 1)
    # then both x_K=r and x_K=r+ec.n must be tested
    for j in range(ec.cofactor + 1):  # 1
        # affine x_K-coordinate of K (field element)
        x_K = (r + j * ec.n) % ec.p  # 1.1
        # two possible y_K-coordinates, i.e. two possible keys for each cycle
        try:
            # even root first for bitcoin message signing compatibility
            yodd = ec.y_even(x_K)
            KJ = x_K, yodd, 1  # 1.2, 1.3, and 1.4
            # 1.5 has been performed in the recover_pub_keys calling function
            QJ = _double_mult(r1s, KJ, r1e, ec.GJ, ec)  # 1.6.1
            try:
                __assert_as_valid(c, QJ, r, s, ec)  # 1.6.2
            except (BTClibValueError, BTClibRuntimeError):
                pass
            else:
                keys.append(QJ)  # 1.6.2
            KJ = x_K, ec.p - yodd, 1  # 1.6.3
            QJ = _double_mult(r1s, KJ, r1e, ec.GJ, ec)
            try:
                __assert_as_valid(c, QJ, r, s, ec)  # 1.6.2
            except (BTClibValueError, BTClibRuntimeError):
                pass
            else:
                keys.append(QJ)  # 1.6.2
        except (BTClibValueError, BTClibRuntimeError):  # K is not a curve point
            pass
    return keys


def __recover_pub_key(key_id: int, c: int, r: int, s: int, ec: Curve) -> JacPoint:
    # Private function provided for testing purposes only.

    # precomputations
    r_1 = mod_inv(r, ec.n)
    r1s = r_1 * s % ec.n
    r1e = -r_1 * c % ec.n
    # r = K[0] % ec.n
    # if ec.n < K[0] < ec.p (likely when cofactor ec.cofactor > 1)
    # then both x_K=r and x_K=r+ec.n must be tested
    j = key_id & 0b110  # allow for key_id in [0, 7]
    x_K = (r + j * ec.n) % ec.p  # 1.1

    # even root first for Bitcoin Core compatibility
    i = key_id & 0b01
    y_even = ec.y_even(x_K)
    y_K = ec.p - y_even if i else y_even
    KJ = x_K, y_K, 1  # 1.2, 1.3, and 1.4
    # 1.5 has been performed in the recover_pub_keys calling function
    QJ = _double_mult(r1s, KJ, r1e, ec.GJ, ec)  # 1.6.1
    __assert_as_valid(c, QJ, r, s, ec)  # 1.6.2
    return QJ


def _crack_prv_key(
    m_1: Octets,
    sig1: Union[Sig, Octets],
    m_2: Octets,
    sig2: Union[Sig, Octets],
    hf: HashF = sha256,
) -> Tuple[int, int]:

    if not isinstance(sig1, Sig):
        sig1 = Sig.deserialize(sig1)
    else:
        sig1.assert_valid()  # 1

    if not isinstance(sig2, Sig):
        sig2 = Sig.deserialize(sig2)
    else:
        sig2.assert_valid()  # 1

    ec = sig2.ec
    if sig1.ec != ec:
        raise BTClibValueError("not the same curve in signatures")
    if sig1.r != sig2.r:
        raise BTClibValueError("not the same r in signatures")
    if sig1.s == sig2.s:
        raise BTClibValueError("identical signatures")

    hlen = hf().digest_size
    m_1 = bytes_from_octets(m_1, hlen)
    m_2 = bytes_from_octets(m_2, hlen)

    c_1 = _challenge(m_1, ec, hf)
    c_2 = _challenge(m_2, ec, hf)

    k = (c_1 - c_2) * mod_inv(sig1.s - sig2.s, ec.n) % ec.n
    q = (sig2.s * k - c_2) * mod_inv(sig1.r, ec.n) % ec.n
    return q, k


def crack_prv_key(
    msg1: String,
    sig1: Union[Sig, Octets],
    msg2: String,
    sig2: Union[Sig, Octets],
    hf: HashF = sha256,
) -> Tuple[int, int]:

    m_1 = reduce_to_hlen(msg1, hf)
    m_2 = reduce_to_hlen(msg2, hf)

    return _crack_prv_key(m_1, sig1, m_2, sig2, hf)
