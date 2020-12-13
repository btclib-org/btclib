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
from dataclasses import InitVar, dataclass, field
from hashlib import sha256
from typing import List, Optional, Sequence, Tuple, Type, TypeVar, Union

from dataclasses_json import DataClassJsonMixin, config

from .alias import BinaryData, HashF, Integer, JacPoint, Octets, Point, String
from .bip32 import BIP32Key
from .curve import Curve, secp256k1
from .curve_group import _double_mult, _mult, _multi_mult
from .exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from .hashes import reduce_to_hlen, tagged_hash
from .number_theory import mod_inv
from .to_prv_key import PrvKey, int_from_prv_key
from .to_pub_key import point_from_pub_key
from .utils import (
    bytes_from_octets,
    bytesio_from_binarydata,
    hex_string,
    int_from_bits,
)

_Sig = TypeVar("_Sig", bound="Sig")


@dataclass(frozen=True)
class Sig(DataClassJsonMixin):
    """BIP340-Schnorr signature.

    r is a _field_element_, 0 <= r < ec.p
    s is a scalar, 0 <= s < ec.n (yes, for BIP340-Schnorr it can be zero)
    (p is the field prime, n is the curve order)
    """

    # 32 bytes
    r: int = field(
        default=-1, metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    # 32 bytes
    s: int = field(
        default=-1, metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    ec: Curve = field(
        default=secp256k1,
        metadata=config(encoder=lambda v: v.name(), decoder=bytes.fromhex),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        # Fail if r is not a field element, i.e. not a valid x-coordinate
        self.ec.y(self.r)

        # Fail if s is not [0, n-1].
        if not 0 <= self.s < self.ec.n:
            err_msg = "scalar s not in 0..n-1: "
            err_msg += f"'{hex_string(self.s)}'" if self.s > 0xFFFFFFFF else f"{self.s}"
            raise BTClibValueError(err_msg)

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        out = self.r.to_bytes(self.ec.psize, byteorder="big", signed=False)
        out += self.s.to_bytes(self.ec.nsize, byteorder="big", signed=False)
        return out

    @classmethod
    def deserialize(
        cls: Type[_Sig], data: BinaryData, check_validity: bool = True
    ) -> _Sig:

        stream = bytesio_from_binarydata(data)
        ec = secp256k1
        r = int.from_bytes(stream.read(ec.psize), byteorder="big", signed=False)
        s = int.from_bytes(stream.read(ec.nsize), byteorder="big", signed=False)
        return cls(r, s, ec, check_validity)


# hex-string or bytes representation of an int
# 33 or 65 bytes or hex-string
# BIP32Key as dict or String
# tuple Point
BIP340PubKey = Union[Integer, Octets, BIP32Key, Point]


def point_from_bip340pub_key(x_Q: BIP340PubKey, ec: Curve = secp256k1) -> Point:
    """Return a verified-as-valid BIP340 public key as Point tuple.

    It supports:

    - BIP32 extended keys (bytes, string, or BIP32KeyData)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - BIP340 Octets (bytes or hex-string, p-size Point x-coordinate)
    - native tuple
    """

    # BIP 340 key as integer
    if isinstance(x_Q, int):
        return x_Q, ec.y_even(x_Q)

    # (tuple) Point, (dict or str) BIP32Key, or 33/65 bytes
    try:
        x_Q = point_from_pub_key(x_Q, ec)[0]
        return x_Q, ec.y_even(x_Q)
    except BTClibValueError:
        pass

    # BIP 340 key as bytes or hex-string
    if isinstance(x_Q, (str, bytes)):
        Q = bytes_from_octets(x_Q, ec.psize)
        x_Q = int.from_bytes(Q, "big", signed=False)
        return x_Q, ec.y_even(x_Q)

    raise BTClibTypeError("not a BIP340 public key")


def gen_keys_(
    prv_key: PrvKey = None, ec: Curve = secp256k1
) -> Tuple[int, int, JacPoint]:
    "Return a BIP340 private/public (int, JacPoint) key-pair."

    if prv_key is None:
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = int_from_prv_key(prv_key, ec)

    QJ = _mult(q, ec.GJ, ec)
    x_Q, y_Q = ec._aff_from_jac(QJ)
    if y_Q % 2:
        q = ec.n - q
        QJ = ec.negate_jac(QJ)

    return q, x_Q, QJ


def gen_keys(prv_key: PrvKey = None, ec: Curve = secp256k1) -> Tuple[int, int]:
    "Return a BIP340 private/public (int, int) key-pair."

    if prv_key is None:
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = int_from_prv_key(prv_key, ec)

    QJ = _mult(q, ec.GJ, ec)
    x_Q, y_Q = ec._aff_from_jac(QJ)
    if y_Q % 2:
        q = ec.n - q

    return q, x_Q


def __det_nonce(m: bytes, q: int, Q: int, aux: bytes, ec: Curve, hf: HashF) -> int:

    # assume the random oracle model for the hash function,
    # i.e. hash values can be considered uniformly random

    # Note that in general, taking a uniformly random integer
    # modulo the curve order n would produce a biased result.
    # However, if the order n is sufficiently close to 2^hlen,
    # then the bias is not observable:
    # e.g. for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
    #
    # the unbiased implementation is provided here,
    # which works also for very-low-cardinality test curves

    randomizer = tagged_hash("BIP0340/aux", aux, hf)
    xor = q ^ int.from_bytes(randomizer, "big", signed=False)
    max_len = max(ec.nsize, hf().digest_size)
    t = xor.to_bytes(max_len, byteorder="big", signed=False)

    t += Q.to_bytes(ec.psize, byteorder="big", signed=False) + m

    while True:
        t = tagged_hash("BIP0340/nonce", t, hf)
        # The following lines would introduce a bias
        # k = int.from_bytes(t, 'big') % ec.n
        # k = int_from_bits(t, ec.nlen) % ec.n
        k = int_from_bits(t, ec.nlen)  # candidate k
        if 0 < k < ec.n:  # acceptable value for k
            return k  # successful candidate


def _det_nonce(
    m: Octets,
    prv_key: PrvKey,
    aux: Optional[Octets] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> int:
    """Return a BIP340 deterministic ephemeral key (nonce)."""

    # the message m: a hlen array
    hlen = hf().digest_size
    m = bytes_from_octets(m, hlen)

    q, Q = gen_keys(prv_key, ec)

    # the auxiliary random component
    aux = secrets.token_bytes(hlen) if aux is None else bytes_from_octets(aux)

    return __det_nonce(m, q, Q, aux, ec, hf)


def det_nonce(
    msg: String, prv_key: PrvKey, ec: Curve = secp256k1, hf: HashF = sha256
) -> int:
    """Return a BIP340 deterministic ephemeral key (nonce)."""

    m = reduce_to_hlen(msg, hf)
    return _det_nonce(m, prv_key, None, ec, hf)


def __challenge(m: bytes, x_Q: int, x_K: int, ec: Curve, hf: HashF) -> int:

    t = x_K.to_bytes(ec.psize, byteorder="big", signed=False)
    t += x_Q.to_bytes(ec.psize, byteorder="big", signed=False)
    t += m
    t = tagged_hash("BIP0340/challenge", t, hf)
    c = int_from_bits(t, ec.nlen) % ec.n
    if c == 0:
        raise BTClibRuntimeError("invalid zero challenge")  # pragma: no cover
    return c


def _challenge(
    m: Octets,
    Q: BIP340PubKey,
    K: BIP340PubKey,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> int:

    # the message m: a hlen array
    hlen = hf().digest_size
    m = bytes_from_octets(m, hlen)

    x_Q, _ = point_from_bip340pub_key(Q, ec)
    x_K, _ = point_from_bip340pub_key(K, ec)

    return __challenge(m, x_Q, x_K, ec, hf)


def challenge(
    msg: String,
    Q: BIP340PubKey,
    K: BIP340PubKey,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> int:

    m = reduce_to_hlen(msg, hf)
    return _challenge(m, Q, K, ec, hf)


def __sign(c: int, q: int, k: int, r: int, ec: Curve) -> Sig:
    # Private function for testing purposes: it allows to explore all
    # possible value of the challenge c (for low-cardinality curves).
    # It assume that c is in [1, n-1], while q and k are in [1, n-1]

    if c == 0:  # c≠0 required as it multiplies the private key
        raise BTClibRuntimeError("invalid zero challenge")

    # s=0 is ok: in verification there is no inverse of s
    s = (k + c * q) % ec.n

    return Sig(r, s, ec)


def _sign(
    m: Octets,
    prv_key: PrvKey,
    k: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """Sign a hlen bytes message according to BIP340 signature algorithm.

    If the deterministic nonce is not provided,
    the BIP340 specification (not RFC6979) is used.
    """

    # the message m: a hlen array
    hlen = hf().digest_size
    m = bytes_from_octets(m, hlen)

    # private and public keys
    q, x_Q = gen_keys(prv_key, ec)

    # the nonce k: an integer in the range 1..n-1.
    if k is None:
        k = __det_nonce(m, q, x_Q, secrets.token_bytes(hlen), ec, hf)

    k, x_K = gen_keys(k, ec)

    # the challenge
    c = __challenge(m, x_Q, x_K, ec, hf)

    return __sign(c, q, k, x_K, ec)


def sign(
    msg: String, prv_key: PrvKey, ec: Curve = secp256k1, hf: HashF = sha256
) -> Sig:
    """Sign message according to BIP340 signature algorithm.

    The message msg is first processed by hf, yielding the value

        m = hf(msg),

    a sequence of bits of length *hlen*.

    Normally, hf is chosen such that its output length *hlen* is
    roughly equal to *nlen*, the bit-length of the group order *n*,
    since the overall security of the signature scheme will depend on
    the smallest of *hlen* and *nlen*; however, ECSSA
    supports all combinations of *hlen* and *nlen*.

    The BIP340 deterministic nonce (not RFC6979) is used.
    """

    m = reduce_to_hlen(msg, hf)
    return _sign(m, prv_key, None, ec, hf)


def __assert_as_valid(c: int, QJ: JacPoint, r: int, s: int, ec: Curve) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # Let K = sG - eQ.
    # in Jacobian coordinates
    KJ = _double_mult(ec.n - c, QJ, s, ec.GJ, ec)

    # Fail if infinite(KJ).
    # Fail if y_K is odd.
    if ec._y_aff_from_jac(KJ) % 2:
        raise BTClibRuntimeError("y_K is odd")

    # Fail if x_K ≠ r
    if KJ[0] != KJ[2] * KJ[2] * r % ec.p:
        raise BTClibRuntimeError("signature verification failed")


def _assert_as_valid(
    m: Octets, Q: BIP340PubKey, sig: Union[Sig, Octets], hf: HashF = sha256
) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    if not isinstance(sig, Sig):
        sig = Sig.deserialize(sig)
    else:
        sig.assert_valid()  # 1

    x_Q, y_Q = point_from_bip340pub_key(Q, sig.ec)

    # Let c = int(hf(bytes(r) || bytes(Q) || m)) mod n.
    c = _challenge(m, x_Q, sig.r, sig.ec, hf)

    __assert_as_valid(c, (x_Q, y_Q, 1), sig.r, sig.s, sig.ec)


def assert_as_valid(
    msg: String, Q: BIP340PubKey, sig: Union[Sig, Octets], hf: HashF = sha256
) -> None:

    m = reduce_to_hlen(msg, hf)
    _assert_as_valid(m, Q, sig, hf)


def _verify(
    m: Octets, Q: BIP340PubKey, sig: Union[Sig, Octets], hf: HashF = sha256
) -> bool:
    """Verify the BIP340 signature of the provided message."""

    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        _assert_as_valid(m, Q, sig, hf)
    except Exception:  # pylint: disable=broad-except
        return False
    else:
        return True


def verify(
    msg: String, Q: BIP340PubKey, sig: Union[Sig, Octets], hf: HashF = sha256
) -> bool:
    """ECDSA signature verification (SEC 1 v.2 section 4.1.4)."""

    m = reduce_to_hlen(msg, hf)
    return _verify(m, Q, sig, hf)


def __recover_pub_key(c: int, r: int, s: int, ec: Curve) -> int:
    # Private function provided for testing purposes only.

    if c == 0:
        raise BTClibRuntimeError("invalid zero challenge")

    KJ = r, ec.y_even(r), 1

    e1 = mod_inv(c, ec.n)
    QJ = _double_mult(ec.n - e1, KJ, e1 * s, ec.GJ, ec)
    # edge case that cannot be reproduced in the test suite
    if QJ[2] == 0:
        err_msg = "invalid (INF) key"  # pragma: no cover
        raise BTClibRuntimeError(err_msg)  # pragma: no cover
    return ec._x_aff_from_jac(QJ)


def _crack_prv_key(
    m_1: Octets,
    sig1: Union[Sig, Octets],
    m_2: Octets,
    sig2: Union[Sig, Octets],
    Q: BIP340PubKey,
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

    x_Q = point_from_bip340pub_key(Q, ec)[0]

    c_1 = _challenge(m_1, x_Q, sig1.r, ec, hf)
    c_2 = _challenge(m_2, x_Q, sig2.r, ec, hf)
    q = (sig1.s - sig2.s) * mod_inv(c_2 - c_1, ec.n) % ec.n
    k = (sig1.s + c_1 * q) % ec.n
    q, _ = gen_keys(q)
    k, _ = gen_keys(k)
    return q, k


def crack_prv_key(
    msg1: String,
    sig1: Union[Sig, Octets],
    msg2: String,
    sig2: Union[Sig, Octets],
    Q: BIP340PubKey,
    hf: HashF = sha256,
) -> Tuple[int, int]:

    m_1 = reduce_to_hlen(msg1, hf)
    m_2 = reduce_to_hlen(msg2, hf)

    return _crack_prv_key(m_1, sig1, m_2, sig2, Q, hf)


def _assert_batch_as_valid(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:

    batch_size = len(Qs)
    if batch_size == 0:
        raise BTClibValueError("no signatures provided")

    if len(ms) != batch_size:
        err_msg = f"mismatch between number of pub_keys ({batch_size}) "
        err_msg += f"and number of messages ({len(ms)})"
        raise BTClibValueError(err_msg)
    if len(sigs) != batch_size:
        err_msg = f"mismatch between number of pub_keys ({batch_size}) "
        err_msg += f"and number of signatures ({len(sigs)})"
        raise BTClibValueError(err_msg)

    if batch_size == 1:
        _assert_as_valid(ms[0], Qs[0], sigs[0], hf)
        return None

    ec = sigs[0].ec
    if any(sig.ec != ec for sig in sigs):
        raise BTClibValueError("not the same curve for all signatures")
    t = 0
    scalars: List[int] = []
    points: List[JacPoint] = []
    for i, (m, Q, sig) in enumerate(zip(ms, Qs, sigs)):
        m = bytes_from_octets(m, hf().digest_size)

        KJ = sig.r, ec.y_even(sig.r), 1

        x_Q, y_Q = point_from_bip340pub_key(Q, ec)
        QJ = x_Q, y_Q, 1

        c = _challenge(m, x_Q, sig.r, ec, hf)

        # rand in [1, n-1]
        # deterministically generated using a CSPRNG seeded by a
        # cryptographic hash (e.g., SHA256) of all inputs of the
        # algorithm, or randomly generated independently for each
        # run of the batch verification algorithm
        rand = 1 if i == 0 else 1 + secrets.randbelow(ec.n - 1)
        scalars.append(rand)
        points.append(KJ)
        scalars.append(rand * c % ec.n)
        points.append(QJ)
        t += rand * sig.s

    TJ = _mult(t, ec.GJ, ec)
    RHSJ = _multi_mult(scalars, points, ec)

    # return T == RHS, checked in Jacobian coordinates
    RHSZ2 = RHSJ[2] * RHSJ[2]
    TZ2 = TJ[2] * TJ[2]
    if (TJ[0] * RHSZ2 % ec.p != RHSJ[0] * TZ2 % ec.p) or (
        TJ[1] * RHSZ2 * RHSJ[2] % ec.p != RHSJ[1] * TZ2 * TJ[2] % ec.p
    ):
        raise BTClibRuntimeError("signature verification failed")
    return None


def assert_batch_as_valid(
    ms: Sequence[String],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:

    ms = [reduce_to_hlen(m, hf) for m in ms]
    return _assert_batch_as_valid(ms, Qs, sigs, hf)


def _batch_verify(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:

    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        _assert_batch_as_valid(ms, Qs, sigs, hf)
    except Exception:  # pylint: disable=broad-except
        return False

    return True


def batch_verify(
    ms: Sequence[String],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:
    """Batch verification of BIP340 signatures."""

    ms = [reduce_to_hlen(m, hf) for m in ms]
    return _batch_verify(ms, Qs, sigs, hf)
