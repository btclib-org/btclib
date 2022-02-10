#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
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
messages of size hf_size only.

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
nonce = TaggedHash('BIPSchnorrDerive', q||msg)

Finally, BIP340-Schnorr adopts a robust [r][s] custom serialization
format, instead of the loosely specified ASN.1 DER standard.
The signature size is p-size*n-size, where p-size is the field element
(curve point coordinate) byte size and n-size is the scalar
(curve point multiplication coefficient) byte size.
For sepcp256k1 the resulting signature size is 64 bytes.
"""

import secrets
from dataclasses import InitVar, dataclass
from hashlib import sha256
from typing import List, Optional, Sequence, Tuple, Type, Union

from btclib.alias import BinaryData, HashF, Integer, JacPoint, Octets, Point
from btclib.bip32.bip32 import BIP32Key
from btclib.ecc.curve import Curve, secp256k1
from btclib.ecc.curve_group import _double_mult, _mult, _multi_mult
from btclib.ecc.number_theory import mod_inv
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.hashes import reduce_to_hlen, tagged_hash
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.to_pub_key import point_from_pub_key
from btclib.utils import (
    bytes_from_octets,
    bytesio_from_binarydata,
    hex_string,
    int_from_bits,
)


@dataclass(frozen=True)
class Sig:
    """BIP340-Schnorr signature.

    - r is an x-coordinate _field_element_, 0 <= r < ec.p
    - s is a scalar, 0 <= s < ec.n (yes, for BIP340-Schnorr it can be zero)

    (ec.p is the field prime, ec.n is the curve order)
    """

    # 32 bytes x-coordinate field element
    r: int
    # 32 bytes scalar
    s: int
    ec: Curve = secp256k1
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        # r is a field element, fail if r is not a valid x-coordinate
        self.ec.y(self.r)

        # s is a scalar, fail if s is not in [0, n-1]
        if not 0 <= self.s < self.ec.n:
            err_msg = "scalar s not in 0..n-1: "
            err_msg += f"'{hex_string(self.s)}'" if self.s > 0xFFFFFFFF else f"{self.s}"
            raise BTClibValueError(err_msg)

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        out = self.r.to_bytes(self.ec.p_size, byteorder="big", signed=False)
        out += self.s.to_bytes(self.ec.n_size, byteorder="big", signed=False)
        return out

    @classmethod
    def parse(cls: Type["Sig"], data: BinaryData, check_validity: bool = True) -> "Sig":

        stream = bytesio_from_binarydata(data)
        ec = secp256k1
        r = int.from_bytes(stream.read(ec.p_size), byteorder="big", signed=False)
        s = int.from_bytes(stream.read(ec.n_size), byteorder="big", signed=False)
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
        Q = bytes_from_octets(x_Q, ec.p_size)
        x_Q = int.from_bytes(Q, "big", signed=False)
        return x_Q, ec.y_even(x_Q)

    raise BTClibTypeError("not a BIP340 public key")


def gen_keys_(
    prv_key: Optional[PrvKey] = None, ec: Curve = secp256k1
) -> Tuple[int, int, JacPoint]:
    "Return a BIP340 private/public (int, JacPoint) key-pair."

    if prv_key is None:
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = int_from_prv_key(prv_key, ec)

    QJ = _mult(q, ec.GJ, ec)
    x_Q, y_Q = ec.aff_from_jac(QJ)
    if y_Q % 2:
        q = ec.n - q
        QJ = ec.negate_jac(QJ)

    return q, x_Q, QJ


def gen_keys(
    prv_key: Optional[PrvKey] = None, ec: Curve = secp256k1
) -> Tuple[int, int]:
    "Return a BIP340 private/public (int, int) key-pair."

    q, x_Q, _ = gen_keys_(prv_key, ec)
    return q, x_Q


def _det_nonce_(
    msg_hash: bytes, q: int, Q: int, aux: bytes, ec: Curve, hf: HashF
) -> int:

    # assume the random oracle model for the hash function,
    # i.e. hash values can be considered uniformly random

    # Note that in general, taking a uniformly random integer
    # modulo the curve order n would produce a biased result.
    # However, if the order n is sufficiently close to 2^hf_len,
    # then the bias is not observable:
    # e.g. for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
    #
    # the unbiased implementation is provided here,
    # which works also for very-low-cardinality test curves

    randomizer = tagged_hash("BIP0340/aux".encode(), aux, hf)
    xor = q ^ int.from_bytes(randomizer, "big", signed=False)
    max_len = max(ec.n_size, hf().digest_size)
    t = b"".join(
        [
            xor.to_bytes(max_len, byteorder="big", signed=False),
            Q.to_bytes(ec.p_size, byteorder="big", signed=False),
            msg_hash,
        ]
    )

    nonce_tag = "BIP0340/nonce".encode()
    while True:
        t = tagged_hash(nonce_tag, t, hf)
        # The following lines would introduce a bias
        # nonce = int.from_bytes(t, 'big') % ec.n
        # nonce = int_from_bits(t, ec.nlen) % ec.n
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hf_len,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        nonce = int_from_bits(t, ec.nlen)  # candidate nonce
        if 0 < nonce < ec.n:  # acceptable value for nonce
            return nonce  # successful candidate


def det_nonce_(
    msg_hash: Octets,
    prv_key: PrvKey,
    aux: Optional[Octets] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> int:
    "Return a BIP340 deterministic ephemeral key (nonce)."

    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    q, Q = gen_keys(prv_key, ec)

    # the auxiliary random component
    aux = secrets.token_bytes(hf_len) if aux is None else bytes_from_octets(aux)

    return _det_nonce_(msg_hash, q, Q, aux, ec, hf)


def challenge_(msg_hash: Octets, x_Q: int, x_K: int, ec: Curve, hf: HashF) -> int:

    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    t = b"".join(
        [
            x_K.to_bytes(ec.p_size, byteorder="big", signed=False),
            x_Q.to_bytes(ec.p_size, byteorder="big", signed=False),
            msg_hash,
        ]
    )
    t = tagged_hash("BIP0340/challenge".encode(), t, hf)

    c = int_from_bits(t, ec.nlen) % ec.n
    if c == 0:
        raise BTClibRuntimeError("invalid zero challenge")  # pragma: no cover
    return c


def _sign_(c: int, q: int, nonce: int, r: int, ec: Curve) -> Sig:
    # Private function for testing purposes: it allows to explore all
    # possible value of the challenge c (for low-cardinality curves).
    # It assume that c is in [1, n-1], while q and nonce are in [1, n-1]

    if c == 0:  # c≠0 required as it multiplies the private key
        raise BTClibRuntimeError("invalid zero challenge")

    # s=0 is ok: in verification there is no inverse of s
    s = (nonce + c * q) % ec.n

    return Sig(r, s, ec)


def sign_(
    msg_hash: Octets,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """Sign a hf_len bytes message according to BIP340 signature algorithm.

    If the deterministic nonce is not provided,
    the BIP340 specification (not RFC6979) is used.
    """

    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    # private and public keys
    q, x_Q = gen_keys(prv_key, ec)

    # nonce: an integer in the range 1..n-1.
    if nonce is None:
        nonce = _det_nonce_(msg_hash, q, x_Q, secrets.token_bytes(hf_len), ec, hf)

    nonce, x_K = gen_keys(nonce, ec)

    # the challenge
    c = challenge_(msg_hash, x_Q, x_K, ec, hf)

    return _sign_(c, q, nonce, x_K, ec)


def sign(
    msg: Octets,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """Sign message according to BIP340 signature algorithm.

    The message msg is first processed by hf, yielding the value

        msg_hash = hf(msg),

    a sequence of bits of length *hf_len*.

    Normally, hf is chosen such that its output length *hf_len* is
    roughly equal to *nlen*, the bit-length of the group order *n*,
    since the overall security of the signature scheme will depend on
    the smallest of *hf_len* and *nlen*; however, ECSSA
    supports all combinations of *hf_len* and *nlen*.

    The BIP340 deterministic nonce (not RFC6979) is used.
    """

    msg_hash = reduce_to_hlen(msg, hf)
    return sign_(msg_hash, prv_key, nonce, ec, hf)


def _assert_as_valid_(c: int, QJ: JacPoint, r: int, s: int, ec: Curve) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # Let K = sG - eQ.
    # in Jacobian coordinates
    KJ = _double_mult(ec.n - c, QJ, s, ec.GJ, ec)

    # Fail if infinite(KJ).
    # Fail if y_K is odd.
    if ec.y_aff_from_jac(KJ) % 2:
        raise BTClibRuntimeError("y_K is odd")

    # Fail if x_K ≠ r
    if KJ[0] != KJ[2] * KJ[2] * r % ec.p:
        raise BTClibRuntimeError("signature verification failed")


def assert_as_valid_(
    msg_hash: Octets, Q: BIP340PubKey, sig: Union[Sig, Octets], hf: HashF = sha256
) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    x_Q, y_Q = point_from_bip340pub_key(Q, sig.ec)

    # Let c = int(hf(bytes(r) || bytes(Q) || msg_hash)) mod n.
    c = challenge_(msg_hash, x_Q, sig.r, sig.ec, hf)

    _assert_as_valid_(c, (x_Q, y_Q, 1), sig.r, sig.s, sig.ec)


def assert_as_valid(
    msg: Octets, Q: BIP340PubKey, sig: Union[Sig, Octets], hf: HashF = sha256
) -> None:

    msg_hash = reduce_to_hlen(msg, hf)
    assert_as_valid_(msg_hash, Q, sig, hf)


def verify_(
    msg_hash: Octets, Q: BIP340PubKey, sig: Union[Sig, Octets], hf: HashF = sha256
) -> bool:
    "Verify the BIP340 signature of the provided message."

    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        assert_as_valid_(msg_hash, Q, sig, hf)
    except Exception:  # pylint: disable=broad-except
        return False
    else:
        return True


def verify(
    msg: Octets, Q: BIP340PubKey, sig: Union[Sig, Octets], hf: HashF = sha256
) -> bool:
    "Verify the BIP340 signature of the provided message."

    msg_hash = reduce_to_hlen(msg, hf)
    return verify_(msg_hash, Q, sig, hf)


def _recover_pub_key_(c: int, r: int, s: int, ec: Curve) -> int:
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
    return ec.x_aff_from_jac(QJ)


def crack_prv_key_(
    msg_hash1: Octets,
    sig1: Union[Sig, Octets],
    msg_hash2: Octets,
    sig2: Union[Sig, Octets],
    Q: BIP340PubKey,
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

    x_Q = point_from_bip340pub_key(Q, ec)[0]

    c_1 = challenge_(msg_hash1, x_Q, sig1.r, ec, hf)
    c_2 = challenge_(msg_hash2, x_Q, sig2.r, ec, hf)
    q = (sig1.s - sig2.s) * mod_inv(c_2 - c_1, ec.n) % ec.n
    nonce = (sig1.s + c_1 * q) % ec.n
    q, _ = gen_keys(q)
    nonce, _ = gen_keys(nonce)
    return q, nonce


def crack_prv_key(
    msg1: Octets,
    sig1: Union[Sig, Octets],
    msg2: Octets,
    sig2: Union[Sig, Octets],
    Q: BIP340PubKey,
    hf: HashF = sha256,
) -> Tuple[int, int]:

    msg_hash1 = reduce_to_hlen(msg1, hf)
    msg_hash2 = reduce_to_hlen(msg2, hf)

    return crack_prv_key_(msg_hash1, sig1, msg_hash2, sig2, Q, hf)


def assert_batch_as_valid_(
    m_hashes: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:

    batch_size = len(Qs)
    if batch_size == 0:
        raise BTClibValueError("no signatures provided")

    if len(m_hashes) != batch_size:
        err_msg = f"mismatch between number of pub_keys ({batch_size}) "
        err_msg += f"and number of messages ({len(m_hashes)})"
        raise BTClibValueError(err_msg)
    if len(sigs) != batch_size:
        err_msg = f"mismatch between number of pub_keys ({batch_size}) "
        err_msg += f"and number of signatures ({len(sigs)})"
        raise BTClibValueError(err_msg)

    if batch_size == 1:
        assert_as_valid_(m_hashes[0], Qs[0], sigs[0], hf)
        return None

    ec = sigs[0].ec
    if any(sig.ec != ec for sig in sigs):
        raise BTClibValueError("not the same curve for all signatures")
    t = 0
    scalars: List[int] = []
    points: List[JacPoint] = []
    for i, (msg_hash, Q, sig) in enumerate(zip(m_hashes, Qs, sigs)):
        msg_hash = bytes_from_octets(msg_hash, hf().digest_size)

        KJ = sig.r, ec.y_even(sig.r), 1

        x_Q, y_Q = point_from_bip340pub_key(Q, ec)
        QJ = x_Q, y_Q, 1

        c = challenge_(msg_hash, x_Q, sig.r, ec, hf)

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
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:

    m_hashes = [reduce_to_hlen(msg, hf) for msg in ms]
    return assert_batch_as_valid_(m_hashes, Qs, sigs, hf)


def batch_verify_(
    m_hashes: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:

    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        assert_batch_as_valid_(m_hashes, Qs, sigs, hf)
    except Exception:  # pylint: disable=broad-except
        return False

    return True


def batch_verify(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:
    "Batch verification of BIP340 signatures."

    m_hashes = [reduce_to_hlen(msg, hf) for msg in ms]
    return batch_verify_(m_hashes, Qs, sigs, hf)
