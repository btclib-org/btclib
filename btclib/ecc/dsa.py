#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Digital Signature Algorithm (ECDSA).

   Implementation according to SEC 1 v.2:

   http://www.secg.org/sec1-v2.pdf

   specialized with bitcoin canonical 'lower-s' form
   to avoid accepting malleable signatures.
"""

import secrets
from hashlib import sha256
from typing import List, Optional, Tuple, Union

from btclib.alias import HashF, JacPoint, Octets, Point
from btclib.ecc.curve import Curve, secp256k1
from btclib.ecc.curve_group import _double_mult, _mult
from btclib.ecc.der import Sig
from btclib.ecc.number_theory import mod_inv
from btclib.ecc.rfc6979 import _rfc6979_
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.hashes import challenge_, reduce_to_hlen
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.to_pub_key import Key, point_from_key
from btclib.utils import bytes_from_octets


def gen_keys(
    prv_key: Optional[PrvKey] = None, ec: Curve = secp256k1
) -> Tuple[int, Point]:
    "Return a private/public (int, Point) key-pair."

    if prv_key is None:
        # q in the range [1, ec.n-1]
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = int_from_prv_key(prv_key, ec)

    QJ = _mult(q, ec.GJ, ec)
    Q = ec.aff_from_jac(QJ)
    return q, Q


def _sign_(c: int, q: int, nonce: int, lower_s: bool, ec: Curve) -> Sig:
    # Private function for testing purposes: it allows to explore all
    # possible value of the challenge c (for low-cardinality curves).
    # It assume that c is in [0, n-1], while q and nonce are in [1, n-1]

    # Steps numbering follows SEC 1 v.2 section 4.1.3

    KJ = _mult(nonce, ec.GJ, ec)  # 1

    # affine x_K-coordinate of K (field element)
    x_K = (KJ[0] * mod_inv(KJ[2] * KJ[2], ec.p)) % ec.p
    # mod n makes it a scalar
    r = x_K % ec.n  # 2, 3
    if r == 0:  # r≠0 required as it multiplies the public key
        raise BTClibRuntimeError("failed to sign: r = 0")

    s = mod_inv(nonce, ec.n) * (c + r * q) % ec.n  # 6
    if s == 0:  # s≠0 required as verify will need the inverse of s
        raise BTClibRuntimeError("failed to sign: s = 0")

    # bitcoin canonical 'low-s' encoding for ECDSA signatures
    # it removes signature malleability as cause of transaction malleability
    # see https://github.com/bitcoin/bitcoin/pull/6769
    if lower_s and s > ec.n / 2:
        s = ec.n - s  # s = - s % ec.n

    return Sig(r, s, ec)


def sign_(
    msg_hash: Octets,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    lower_s: bool = True,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """Sign a hf_len bytes message according to ECDSA signature algorithm.

    If the deterministic nonce is not provided,
    the RFC6979 specification is used.
    """

    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    # the secret key q: an integer in the range 1..n-1.
    # SEC 1 v.2 section 3.2.1
    q = int_from_prv_key(prv_key, ec)

    # the challenge
    c = challenge_(msg_hash, ec, hf)  # 4, 5

    # nonce: an integer in the range 1..n-1.
    if nonce is None:
        nonce = _rfc6979_(c, q, ec, hf)  # 1
    else:
        nonce = int_from_prv_key(nonce, ec)

    # second part delegated to helper function
    return _sign_(c, q, nonce, lower_s, ec)


def sign(
    msg: Octets,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    lower_s: bool = True,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """ECDSA signature with canonical low-s preference.

    Implemented according to SEC 1 v.2
    The message msg is first processed by hf, yielding the value

        msg_hash = hf(msg),

    a sequence of bits of length *hf_len*.

    Normally, hf is chosen such that its output length *hf_len* is
    roughly equal to *nlen*, the bit-length of the group order *n*,
    since the overall security of the signature scheme will depend on
    the smallest of *hf_len* and *nlen*; however, the ECDSA standard
    supports all combinations of *hf_len* and *nlen*.

    RFC6979 is used for deterministic nonce.

    See https://tools.ietf.org/html/rfc6979#section-3.2
    """

    msg_hash = reduce_to_hlen(msg, hf)
    return sign_(msg_hash, prv_key, nonce, lower_s, ec, hf)


def _assert_as_valid_(
    c: int, QJ: JacPoint, r: int, s: int, lower_s: bool, ec: Curve
) -> None:
    # Private function for test/dev purposes

    if lower_s and s > ec.n / 2:
        raise BTClibValueError("not a low s")

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


def assert_as_valid_(
    msg_hash: Octets,
    key: Key,
    sig: Union[Sig, Octets],
    lower_s: bool = True,
    hf: HashF = sha256,
) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    c = challenge_(msg_hash, sig.ec, hf)  # 2, 3

    Q = point_from_key(key, sig.ec)
    QJ = Q[0], Q[1], 1

    # second part delegated to helper function
    _assert_as_valid_(c, QJ, sig.r, sig.s, lower_s, sig.ec)


def assert_as_valid(
    msg: Octets,
    key: Key,
    sig: Union[Sig, Octets],
    lower_s: bool = True,
    hf: HashF = sha256,
) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    msg_hash = reduce_to_hlen(msg, hf)
    assert_as_valid_(msg_hash, key, sig, lower_s, hf)


def verify_(
    msg_hash: Octets,
    key: Key,
    sig: Union[Sig, Octets],
    lower_s: bool = True,
    hf: HashF = sha256,
) -> bool:
    """ECDSA signature verification (SEC 1 v.2 section 4.1.4)."""

    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        assert_as_valid_(msg_hash, key, sig, lower_s, hf)
    except Exception:  # pylint: disable=broad-except
        return False
    else:
        return True


def verify(
    msg: Octets,
    key: Key,
    sig: Union[Sig, Octets],
    lower_s: bool = True,
    hf: HashF = sha256,
) -> bool:
    """ECDSA signature verification (SEC 1 v.2 section 4.1.4)."""

    msg_hash = reduce_to_hlen(msg, hf)
    return verify_(msg_hash, key, sig, lower_s, hf)


# TODO: use _recover_pub_key_ to avoid code duplication
def _recover_pub_keys_(
    c: int, r: int, s: int, lower_s: bool, ec: Curve
) -> List[JacPoint]:
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
                _assert_as_valid_(c, QJ, r, s, lower_s, ec)  # 1.6.2
            except (BTClibValueError, BTClibRuntimeError):
                pass
            else:
                keys.append(QJ)  # 1.6.2
            KJ = x_K, ec.p - yodd, 1  # 1.6.3
            QJ = _double_mult(r1s, KJ, r1e, ec.GJ, ec)
            try:
                _assert_as_valid_(c, QJ, r, s, lower_s, ec)  # 1.6.2
            except (BTClibValueError, BTClibRuntimeError):
                pass
            else:
                keys.append(QJ)  # 1.6.2
        except (BTClibValueError, BTClibRuntimeError):  # K is not a curve point
            pass
    return keys


def recover_pub_keys_(
    msg_hash: Octets, sig: Union[Sig, Octets], lower_s: bool = True, hf: HashF = sha256
) -> List[Point]:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See also:
    https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106
    """

    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    # The message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    c = challenge_(msg_hash, sig.ec, hf)  # 1.5

    QJs = _recover_pub_keys_(c, sig.r, sig.s, lower_s, sig.ec)
    return [sig.ec.aff_from_jac(QJ) for QJ in QJs]


def recover_pub_keys(
    msg: Octets, sig: Union[Sig, Octets], lower_s: bool = True, hf: HashF = sha256
) -> List[Point]:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See also:
    https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106
    """

    msg_hash = reduce_to_hlen(msg, hf)
    return recover_pub_keys_(msg_hash, sig, lower_s, hf)


def _recover_pub_key_(
    key_id: int, c: int, r: int, s: int, lower_s: bool, ec: Curve
) -> JacPoint:
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
    _assert_as_valid_(c, QJ, r, s, lower_s, ec)  # 1.6.2
    return QJ


def recover_pub_key_(
    key_id: int,
    msg_hash: Octets,
    sig: Union[Sig, Octets],
    lower_s: bool = True,
    hf: HashF = sha256,
) -> Point:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See also:
    https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106
    """

    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    # The message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    c = challenge_(msg_hash, sig.ec, hf)  # 1.5

    QJ = _recover_pub_key_(key_id, c, sig.r, sig.s, lower_s, sig.ec)
    return sig.ec.aff_from_jac(QJ)


def recover_pub_key(
    key_id: int,
    msg: Octets,
    sig: Union[Sig, Octets],
    lower_s: bool = True,
    hf: HashF = sha256,
) -> Point:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See also:
    https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106
    """

    msg_hash = reduce_to_hlen(msg, hf)
    return recover_pub_key_(key_id, msg_hash, sig, lower_s, hf)


def crack_prv_key_(
    msg_hash1: Octets,
    sig1: Union[Sig, Octets],
    msg_hash2: Octets,
    sig2: Union[Sig, Octets],
    hf: HashF = sha256,
) -> Tuple[int, int]:

    if isinstance(sig1, Sig):
        sig1.assert_valid()
    else:
        sig1 = Sig.parse(sig1)

    if isinstance(sig2, Sig):
        sig2.assert_valid()
    else:
        sig2 = Sig.parse(sig2)

    ec = sig2.ec
    if sig1.ec != ec:
        raise BTClibValueError("not the same curve in signatures")
    if sig1.r != sig2.r:
        raise BTClibValueError("not the same r in signatures")
    if sig1.s == sig2.s:
        raise BTClibValueError("identical signatures")

    c_1 = challenge_(msg_hash1, ec, hf)
    c_2 = challenge_(msg_hash2, ec, hf)

    nonce = (c_1 - c_2) * mod_inv(sig1.s - sig2.s, ec.n) % ec.n
    q = (sig2.s * nonce - c_2) * mod_inv(sig1.r, ec.n) % ec.n
    return q, nonce


def crack_prv_key(
    msg1: Octets,
    sig1: Union[Sig, Octets],
    msg2: Octets,
    sig2: Union[Sig, Octets],
    hf: HashF = sha256,
) -> Tuple[int, int]:

    msg_hash1 = reduce_to_hlen(msg1, hf)
    msg_hash2 = reduce_to_hlen(msg2, hf)

    return crack_prv_key_(msg_hash1, sig1, msg_hash2, sig2, hf)
