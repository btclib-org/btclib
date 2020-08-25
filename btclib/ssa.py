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
Therefore, for sepcp256k1 the public key size is 32 bytes.
Arguably, the knowledge of q as the discrete logarithm of Q
also implies the knowledge of n-q as discrete logarithm of -Q.
As such, {q, n-q} can be considered a single private key and
{Q, -Q} the associated public key characterized by the shared x_Q.

Also, BIP340 advocates its own SHA256 modification as hash function:
TaggedHash(tag, x) = SHA256(SHA256(tag)||SHA256(tag)||x)
The rationale is to make BIP340 signatures invalid for anything else
but Bitcoin and vice versa.

TaggedHash is used for both the challenge (with tag 'BIPSchnorr')
and the deterministic nonce (with tag 'BIPSchnorrDerive').

To allow for secure batch verification of multiple signatures,
BIP340-Schnorr uses a challenge that prevents public key recovery
from signature: c = TaggedHash('BIPSchnorr', x_k||x_Q||msg).

A custom deterministic algorithm for the ephemeral key (nonce)
is used for signing, instead of the RFC6979 standard:
k = TaggedHash('BIPSchnorrDerive', q||msg)

Finally, BIP340-Schnorr adopts a robust [r][s] custom serialization
format, instead of the loosely specified ASN.1 DER standard.
The signature size is p-size*n-size, where p-size is the field element
(curve point coordinate) byte size and n-size is the scalar
(curve point multiplication coefficient) byte size.
For sepcp256k1 the resulting signature size is 64 bytes.
"""

import secrets
from hashlib import sha256
from typing import List, Optional, Sequence, Tuple, Union

from .alias import (
    BIP32Key,
    HashF,
    Integer,
    JacPoint,
    Octets,
    Point,
    PrvKey,
    SSASig,
    SSASigTuple,
    String,
)
from .curve import Curve
from .curvemult import _double_mult, _mult_jac, _multi_mult
from .curves import secp256k1
from .hashes import reduce_to_hlen
from .numbertheory import mod_inv
from .to_prvkey import int_from_prvkey
from .to_pubkey import point_from_pubkey
from .utils import bytes_from_octets, hex_string, int_from_bits

# TODO relax the p_ThreeModFour requirement

# hex-string or bytes representation of an int
# 33 or 65 bytes or hex-string
# BIP32Key as dict or String
# tuple Point
BIP340PubKey = Union[Integer, Octets, BIP32Key, Point]


def point_from_bip340pubkey(x_Q: BIP340PubKey, ec: Curve = secp256k1) -> Point:
    """Return a verified-as-valid BIP340 public key as Point tuple.

    It supports:

    - BIP32 extended keys (bytes, string, or BIP32KeyDict)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - BIP340 Octets (bytes or hex-string, p-size Point x-coordinate)
    - native tuple
    """

    # BIP 340 key as integer
    if isinstance(x_Q, int):
        y_Q = ec.y_quadratic_residue(x_Q, True)
        return x_Q, y_Q
    else:
        # (tuple) Point, (dict or str) BIP32Key, or 33/65 bytes
        try:
            x_Q = point_from_pubkey(x_Q, ec)[0]
            y_Q = ec.y_quadratic_residue(x_Q, True)
            return x_Q, y_Q
        except Exception:
            pass

    # BIP 340 key as bytes or hex-string
    if isinstance(x_Q, str) or isinstance(x_Q, bytes):
        Q = bytes_from_octets(x_Q, ec.psize)
        x_Q = int.from_bytes(Q, "big")
        y_Q = ec.y_quadratic_residue(x_Q, True)
        return x_Q, y_Q

    raise ValueError("not a BIP340 public key")


def _validate_sig(r: int, s: int, ec: Curve) -> None:

    # BIP340 is defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    # Fail if r is not a field element, i.e. not a valid x-coordinate
    ec.y(r)

    # Fail if s is not [0, n-1].
    if not 0 <= s < ec.n:
        err_msg = "scalar s not in 0..n-1: "
        err_msg += f"'{hex_string(s)}'" if s > 0xFFFFFFFF else f"{s}"
        raise ValueError(err_msg)


def deserialize(sig: SSASig, ec: Curve = secp256k1) -> SSASigTuple:
    """Return the verified components of the provided BIP340 signature.

    The BIP340 signature can be represented as (r, s) tuple
    or as binary [r][s] compact representation.
    """

    if isinstance(sig, tuple):
        r, s = sig
    else:
        if isinstance(sig, str):
            # hex-string of the serialized signature
            sig2 = bytes.fromhex(sig)
        else:
            sig2 = bytes_from_octets(sig, ec.psize + ec.nsize)

        r = int.from_bytes(sig2[: ec.psize], byteorder="big")
        s = int.from_bytes(sig2[ec.nsize :], byteorder="big")

    _validate_sig(r, s, ec)
    return r, s


def serialize(x_K: int, s: int, ec: Curve = secp256k1) -> bytes:
    "Return the BIP340 signature as [r][s] compact representation."

    _validate_sig(x_K, s, ec)
    return x_K.to_bytes(ec.psize, "big") + s.to_bytes(ec.nsize, "big")


def gen_keys(prvkey: PrvKey = None, ec: Curve = secp256k1) -> Tuple[int, int]:
    "Return a BIP340 private/public (int, int) key-pair."
    # BIP340 is defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    if prvkey is None:
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = int_from_prvkey(prvkey, ec)

    QJ = _mult_jac(q, ec.GJ, ec)
    x_Q = ec._x_aff_from_jac(QJ)
    if not ec.has_square_y(QJ):
        q = ec.n - q

    return q, x_Q


# TODO move to hashes
# This implementation can be sped up by storing the midstate after hashing
# tag_hash instead of rehashing it all the time.
def _tagged_hash(tag: str, m: bytes, hf: HashF) -> bytes:
    t = tag.encode()
    h1 = hf()
    h1.update(t)
    tag_hash = h1.digest()
    h2 = hf()
    h2.update(tag_hash + tag_hash + m)
    return h2.digest()


def __det_nonce(m: bytes, q: int, ec: Curve, hf: HashF) -> Tuple[int, int]:

    # assume the random oracle model for the hash function,
    # i.e. hash values can be considered uniformly random

    # Note that in general, taking a uniformly random integer
    # modulo the curve order n would produce a biased result.
    # However, if the order n is sufficiently close to 2^hlen,
    # then the bias is not observable:
    # e.g. for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128

    # the unbiased implementation is provided here,
    # which works also for very-low-cardinality test curves
    t = q.to_bytes(ec.nsize, "big") + m
    while True:
        t = _tagged_hash("BIPSchnorrDerive", t, hf)
        # The following lines would introduce a bias
        # k = int.from_bytes(t, 'big') % ec.n
        # k = int_from_bits(t, ec.nlen) % ec.n
        k = int_from_bits(t, ec.nlen)  # candidate k
        if 0 < k < ec.n:  # acceptable value for k
            return gen_keys(k, ec)  # successful candidate


def _det_nonce(
    m: Octets, prvkey: PrvKey, ec: Curve = secp256k1, hf: HashF = sha256
) -> Tuple[int, int]:
    """Return a BIP340 deterministic ephemeral key (nonce)."""

    # The message m: a hlen array
    hlen = hf().digest_size
    m = bytes_from_octets(m, hlen)

    q, _ = gen_keys(prvkey, ec)

    return __det_nonce(m, q, ec, hf)


def det_nonce(
    msg: String, prvkey: PrvKey, ec: Curve = secp256k1, hf: HashF = sha256
) -> Tuple[int, int]:
    """Return a BIP340 deterministic ephemeral key (nonce)."""

    m = reduce_to_hlen(msg, hf)
    return _det_nonce(m, prvkey, ec, hf)


def __challenge(m: bytes, x_Q: int, r: int, ec: Curve, hf: HashF) -> int:

    # note that only x_Q is needed
    # if Q is Jacobian y_Q calculation can be avoided

    t = r.to_bytes(ec.psize, "big")
    t += x_Q.to_bytes(ec.psize, "big")
    # m size must have been already checked to be equal to hsize
    t += m
    t = _tagged_hash("BIPSchnorr", t, hf)
    # if c == 0 then private key is removed from the equations,
    # so the signature is valid for any private/public key pair
    # if c == 0:
    #    raise RuntimeError("invalid zero challenge")
    return int_from_bits(t, ec.nlen) % ec.n


def _challenge(
    m: Octets, xQ: BIP340PubKey, r: int, ec: Curve = secp256k1, hf: HashF = sha256
) -> int:

    # The message m: a hlen array
    hlen = hf().digest_size
    m = bytes_from_octets(m, hlen)

    x_Q, _ = point_from_bip340pubkey(xQ, ec)

    return __challenge(m, x_Q, r, ec, hf)


def challenge(
    msg: String, xQ: BIP340PubKey, r: int, ec: Curve = secp256k1, hf: HashF = sha256
) -> int:

    m = reduce_to_hlen(msg, hf)
    return _challenge(m, xQ, r, ec, hf)


def __sign(c: int, q: int, k: int, x_K: int, ec: Curve) -> SSASigTuple:
    # s=0 is ok: in verification there is no inverse of s
    s = (k + c * q) % ec.n

    return x_K, s


def _sign(
    m: Octets,
    prvkey: PrvKey,
    k: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> SSASigTuple:
    """Sign message according to BIP340 signature algorithm."""

    # BIP340 is defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    # The message m: a hlen array
    hlen = hf().digest_size
    m = bytes_from_octets(m, hlen)

    q, x_Q = gen_keys(prvkey, ec)

    # The nonce k: an integer in the range 1..n-1.
    k, x_K = __det_nonce(m, q, ec, hf) if k is None else gen_keys(k, ec)
    # Let c = int(hf(bytes(x_K) || bytes(x_Q) || m)) mod n.
    c = __challenge(m, x_Q, x_K, ec, hf)

    return __sign(c, q, k, x_K, ec)


def sign(
    msg: String,
    prvkey: PrvKey,
    k: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> SSASigTuple:
    """Sign message according to BIP340 signature algorithm.

    The message msg is first processed by hf, yielding the value

        m = hf(msg),

    a sequence of bits of length *hlen*.

    Normally, hf is chosen such that its output length *hlen* is
    roughly equal to *nlen*, the bit-length of the group order *n*,
    since the overall security of the signature scheme will depend on
    the smallest of *hlen* and *nlen*; however, ECSSA
    supports all combinations of *hlen* and *nlen*.
    """

    m = reduce_to_hlen(msg, hf)
    return _sign(m, prvkey, k, ec, hf)


def __assert_as_valid(c: int, QJ: JacPoint, r: int, s: int, ec: Curve) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # BIP340 is defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    # Let K = sG - eQ.
    # in Jacobian coordinates
    KJ = _double_mult(ec.n - c, QJ, s, ec.GJ, ec)

    # Fail if infinite(KJ).
    # Fail if jacobi(y_K) ≠ 1.
    if not ec.has_square_y(KJ):
        raise RuntimeError("y_K is not a quadratic residue")

    # Fail if x_K ≠ r
    assert KJ[0] == KJ[2] * KJ[2] * r % ec.p, "signature verification failed"


def _assert_as_valid(
    m: Octets, Q: BIP340PubKey, sig: SSASig, ec: Curve = secp256k1, hf: HashF = sha256
) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    r, s = deserialize(sig, ec)

    x_Q, y_Q = point_from_bip340pubkey(Q, ec)

    # Let c = int(hf(bytes(r) || bytes(Q) || m)) mod n.
    c = _challenge(m, x_Q, r, ec, hf)

    __assert_as_valid(c, (x_Q, y_Q, 1), r, s, ec)


def assert_as_valid(
    msg: String, Q: BIP340PubKey, sig: SSASig, ec: Curve = secp256k1, hf: HashF = sha256
) -> None:

    m = reduce_to_hlen(msg, hf)
    _assert_as_valid(m, Q, sig, ec, hf)


def _verify(
    m: Octets, Q: BIP340PubKey, sig: SSASig, ec: Curve = secp256k1, hf: HashF = sha256
) -> bool:
    """Verify the BIP340 signature of the provided message."""

    # try/except wrapper for the Errors raised by _assert_as_valid
    try:
        _assert_as_valid(m, Q, sig, ec, hf)
    except Exception:
        return False
    else:
        return True


def verify(
    msg: String, Q: BIP340PubKey, sig: SSASig, ec: Curve = secp256k1, hf: HashF = sha256
) -> bool:
    """ECDSA signature verification (SEC 1 v.2 section 4.1.4)."""

    m = reduce_to_hlen(msg, hf)
    return _verify(m, Q, sig, ec, hf)


def __recover_pubkey(c: int, r: int, s: int, ec: Curve) -> int:
    # Private function provided for testing purposes only.

    if c == 0:
        raise ValueError("invalid zero challenge")

    KJ = r, ec.y_quadratic_residue(r, True), 1

    e1 = mod_inv(c, ec.n)
    QJ = _double_mult(ec.n - e1, KJ, e1 * s, ec.GJ, ec)
    assert QJ[2] != 0, "how did you do that?!?"
    return ec._x_aff_from_jac(QJ)


# FIXME add crack_prvkey
def _crack_prvkey(
    m1: Octets,
    sig1: SSASig,
    m2: Octets,
    sig2: SSASig,
    Q: BIP340PubKey,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Tuple[int, int]:

    m1 = bytes_from_octets(m1, hf().digest_size)
    m2 = bytes_from_octets(m2, hf().digest_size)

    r1, s1 = deserialize(sig1, ec)
    r2, s2 = deserialize(sig2, ec)
    if r1 != r2:
        raise ValueError("not the same r in signatures")
    if s1 == s2:
        raise ValueError("identical signatures")

    x_Q = point_from_bip340pubkey(Q, ec)[0]

    c1 = _challenge(m1, x_Q, r1, ec, hf)
    c2 = _challenge(m2, x_Q, r2, ec, hf)
    q = (s1 - s2) * mod_inv(c2 - c1, ec.n) % ec.n
    k = (s1 + c1 * q) % ec.n
    return q, k


def _batch_verify(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[SSASig],
    ec: Curve,
    hf: HashF,
) -> None:

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
        return _assert_as_valid(ms[0], Qs[0], sigs[0], ec, hf)

    # BIP340 is defined for curves whose field prime p = 3 % 4
    ec.require_p_ThreeModFour()

    t = 0
    scalars: List[int] = list()
    points: List[JacPoint] = list()
    for i, (m, Q, sig) in enumerate(zip(ms, Qs, sigs)):
        m = bytes_from_octets(m, hf().digest_size)

        r, s = deserialize(sig, ec)
        KJ = r, ec.y_quadratic_residue(r, True), 1

        x_Q, y_Q = point_from_bip340pubkey(Q, ec)
        QJ = x_Q, y_Q, 1

        c = _challenge(m, x_Q, r, ec, hf)

        # a in [1, n-1]
        # deterministically generated using a CSPRNG seeded by a
        # cryptographic hash (e.g., SHA256) of all inputs of the
        # algorithm, or randomly generated independently for each
        # run of the batch verification algorithm
        a = 1 if i == 0 else 1 + secrets.randbelow(ec.n - 1)
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
    precondition = TJ[0] * RHSZ2 % ec.p == RHSJ[0] * TZ2 % ec.p
    if not precondition:
        raise ValueError("signature verification precondition failed")

    valid_sig = TJ[1] * RHSZ2 * RHSJ[2] % ec.p == RHSJ[1] * TZ2 * TJ[2] % ec.p
    assert valid_sig, "signature verification failed"


def batch_verify(
    m: Sequence[Octets],
    Q: Sequence[BIP340PubKey],
    sig: Sequence[SSASig],
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> bool:
    """Batch verification of BIP340 signatures."""

    # try/except wrapper for the Errors raised by _batch_verify
    try:
        _batch_verify(m, Q, sig, ec, hf)
    except Exception:
        return False
    else:
        return True
