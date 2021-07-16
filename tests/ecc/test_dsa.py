#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.dsa` module."

import secrets
from hashlib import sha1

import pytest
from coincurve._libsecp256k1 import (  # type: ignore # pylint: disable=no-name-in-module
    ffi,
    lib,
)

from btclib.alias import INF
from btclib.ecc import dsa
from btclib.ecc.curve import CURVES, Curve, double_mult, mult
from btclib.ecc.curve_group import _mult
from btclib.ecc.number_theory import mod_inv
from btclib.ecc.sec_point import bytes_from_point, point_from_octets
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.hashes import reduce_to_hlen
from tests.ecc.test_curve import low_card_curves

GLOBAL_CTX = ffi.gc(
    lib.secp256k1_context_create(
        lib.SECP256K1_CONTEXT_SIGN | lib.SECP256K1_CONTEXT_VERIFY
    ),
    lib.secp256k1_context_destroy,
)

CDATA_SIG_LENGTH = 64


def test_libsecp256k1() -> None:
    msg = "Satoshi Nakamoto".encode()

    q, _ = dsa.gen_keys(0x1)
    sig = dsa.sign(msg, q)

    msg_hash = reduce_to_hlen(msg)
    secret = q.to_bytes(32, "big")

    c_sig = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_sign(
        GLOBAL_CTX, c_sig, msg_hash, secret, ffi.NULL, ffi.NULL
    ):
        raise RuntimeError("libsecp256k1 signature failed")

    output = ffi.new("unsigned char[%d]" % CDATA_SIG_LENGTH)
    if not lib.secp256k1_ecdsa_signature_serialize_compact(GLOBAL_CTX, output, c_sig):
        raise RuntimeError("libsecp256k1 signature serialization failed")

    c_sig_bytes = bytes(ffi.buffer(output, CDATA_SIG_LENGTH))

    r = c_sig_bytes[:32]
    s = c_sig_bytes[32:]

    assert r.hex() == sig.r.to_bytes(32, "big").hex()
    assert s.hex() == sig.s.to_bytes(32, "big").hex()


def test_signature() -> None:
    msg = "Satoshi Nakamoto".encode()

    q, Q = dsa.gen_keys(0x1)
    sig = dsa.sign(msg, q)
    dsa.assert_as_valid(msg, Q, sig)
    assert dsa.verify(msg, Q, sig)
    assert sig == dsa.Sig.parse(sig.serialize())
    assert sig == dsa.Sig.parse(sig.serialize().hex())

    # https://bitcointalk.org/index.php?topic=285142.40
    # Deterministic Usage of DSA and ECDSA (RFC 6979)
    r = 0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8
    s = 0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5
    assert sig.r == r
    assert sig.s in (s, sig.ec.n - s)

    # malleability
    malleated_sig = dsa.Sig(sig.r, sig.ec.n - sig.s)
    assert dsa.verify(msg, Q, malleated_sig, lower_s=False)

    keys = dsa.recover_pub_keys(msg, sig)
    assert len(keys) == 2
    assert Q in keys

    keys = dsa.recover_pub_keys(msg, sig.serialize())
    assert len(keys) == 2
    assert Q in keys

    msg_fake = "Craig Wright".encode()
    assert not dsa.verify(msg_fake, Q, sig)
    err_msg = "signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        dsa.assert_as_valid(msg_fake, Q, sig)

    _, Q_fake = dsa.gen_keys()
    assert not dsa.verify(msg, Q_fake, sig)
    err_msg = "signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        dsa.assert_as_valid(msg, Q_fake, sig)

    err_msg = "not a valid public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.assert_as_valid(msg, INF, sig)

    sig_invalid = dsa.Sig(sig.ec.p, sig.s, check_validity=False)
    assert not dsa.verify(msg, Q, sig_invalid)
    err_msg = "scalar r not in 1..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.assert_as_valid(msg, Q, sig_invalid)

    sig_invalid = dsa.Sig(sig.r, sig.ec.p, check_validity=False)
    assert not dsa.verify(msg, Q, sig_invalid)
    err_msg = "scalar s not in 1..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.assert_as_valid(msg, Q, sig_invalid)

    err_msg = "private key not in 1..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign(msg, 0)

    # ephemeral key not in 1..n-1
    err_msg = "private key not in 1..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign_(reduce_to_hlen(msg), q, 0)
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.sign_(reduce_to_hlen(msg), q, sig.ec.n)


def test_gec() -> None:
    """GEC 2: Test Vectors for SEC 1, section 2

    http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
    """
    # 2.1.1 Scheme setup
    ec = CURVES["secp160r1"]
    hf = sha1

    # 2.1.2 Key Deployment for U
    dU = 971761939728640320549601132085879836204587084162
    dU, QU = dsa.gen_keys(dU, ec)
    assert (
        format(dU, str(ec.n_size) + "x") == "aa374ffc3ce144e6b073307972cb6d57b2a4e982"
    )
    assert QU == (
        466448783855397898016055842232266600516272889280,
        1110706324081757720403272427311003102474457754220,
    )
    assert (
        bytes_from_point(QU, ec).hex() == "0251b4496fecc406ed0e75a24a3c03206251419dc0"
    )

    # 2.1.3 Signing Operation for U
    msg = b"abc"
    k = 702232148019446860144825009548118511996283736794
    lower_s = False
    sig = dsa.sign_(reduce_to_hlen(msg, hf), dU, k, lower_s, ec, hf)
    assert sig.r == 0xCE2873E5BE449563391FEB47DDCBA2DC16379191
    assert sig.s == 0x3480EC1371A091A464B31CE47DF0CB8AA2D98B54
    assert sig.ec == ec

    # 2.1.4 Verifying Operation for V
    dsa.assert_as_valid(msg, QU, sig, lower_s, hf)
    assert dsa.verify(msg, QU, sig, lower_s, hf)


@pytest.mark.first
def test_low_cardinality() -> None:
    """test low-cardinality curves for all msg/key pairs."""
    # pylint: disable=protected-access

    # ec.n has to be prime to sign
    test_curves = [
        low_card_curves["ec13_11"],
        # low_card_curves["ec13_19"],
        # low_card_curves["ec17_13"],
        low_card_curves["ec17_23"],
        low_card_curves["ec19_13"],
        # low_card_curves["ec19_23"],
        low_card_curves["ec23_19"],
        low_card_curves["ec23_31"],
    ]

    lower_s = True
    # only low cardinality test curves or it would take forever
    for ec in test_curves:
        for q in range(1, ec.n):  # all possible private keys
            QJ = _mult(q, ec.GJ, ec)  # public key
            for k in range(1, ec.n):  # all possible ephemeral keys
                RJ = _mult(k, ec.GJ, ec)
                r = ec.x_aff_from_jac(RJ) % ec.n
                k_inv = mod_inv(k, ec.n)
                for e in range(ec.n):  # all possible challenges
                    s = k_inv * (e + q * r) % ec.n
                    # bitcoin canonical 'low-s' encoding for ECDSA
                    if lower_s and s > ec.n / 2:
                        s = ec.n - s
                    if r == 0 or s == 0:
                        err_msg = "failed to sign: "
                        with pytest.raises(BTClibRuntimeError, match=err_msg):
                            dsa._sign_(e, q, k, lower_s, ec)
                    else:
                        sig = dsa._sign_(e, q, k, lower_s, ec)
                        assert r == sig.r
                        assert s == sig.s
                        assert ec == sig.ec
                        # valid signature must pass verification
                        dsa._assert_as_valid_(e, QJ, r, s, lower_s, ec)

                        jac_keys = dsa._recover_pub_keys_(e, r, s, lower_s, ec)
                        # FIXME speed this up
                        Qs = [ec.aff_from_jac(key) for key in jac_keys]
                        assert ec.aff_from_jac(QJ) in Qs
                        assert len(jac_keys) in (2, 4)


def test_pub_key_recovery() -> None:

    ec = CURVES["secp112r2"]

    q = 0x10
    Q = mult(q, ec.G, ec)

    msg = "Satoshi Nakamoto".encode()
    sig = dsa.sign(msg, q, ec=ec)
    dsa.assert_as_valid(msg, Q, sig)
    assert dsa.verify(msg, Q, sig)

    keys = dsa.recover_pub_keys(msg, sig)
    assert len(keys) == 4
    assert Q in keys
    for Q in keys:
        assert dsa.verify(msg, Q, sig)


def test_crack_prv_key() -> None:

    ec = CURVES["secp256k1"]

    q, _ = dsa.gen_keys(1)
    k = 1 + secrets.randbelow(ec.n - 1)

    msg1 = "Paolo is afraid of ephemeral random numbers".encode()
    m_1 = reduce_to_hlen(msg1)
    sig1 = dsa.sign_(m_1, q, k)

    msg2 = "and Paolo is right to be afraid".encode()
    m_2 = reduce_to_hlen(msg2)
    sig2 = dsa.sign_(m_2, q, k)

    q_cracked, k_cracked = dsa.crack_prv_key(msg1, sig1.serialize(), msg2, sig2)

    #  if the lower_s convention has changed only one of s1 and s2
    sig2 = dsa.Sig(sig2.r, ec.n - sig2.s)
    qc2, kc2 = dsa.crack_prv_key(msg1, sig1, msg2, sig2.serialize())

    assert (q == q_cracked and k in (k_cracked, ec.n - k_cracked)) or (
        q == qc2 and k in (kc2, ec.n - kc2)
    )

    with pytest.raises(BTClibValueError, match="not the same r in signatures"):
        dsa.crack_prv_key(msg1, sig1, msg2, dsa.Sig(16, sig1.s))

    with pytest.raises(BTClibValueError, match="identical signatures"):
        dsa.crack_prv_key(msg1, sig1, msg1, sig1)

    a = ec._a  # pylint: disable=protected-access
    b = ec._b  # pylint: disable=protected-access
    alt_ec = Curve(ec.p, a, b, ec.double_aff(ec.G), ec.n, ec.cofactor)
    sig = dsa.Sig(sig1.r, sig1.s, alt_ec)
    with pytest.raises(BTClibValueError, match="not the same curve in signatures"):
        dsa.crack_prv_key(msg1, sig, msg2, sig2)


def test_forge_hash_sig() -> None:
    """forging valid hash signatures"""
    # pylint: disable=protected-access

    ec = CURVES["secp256k1"]

    # see https://twitter.com/pwuille/status/1063582706288586752
    # Satoshi's key
    key = "03 11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c"
    Q = point_from_octets(key, ec)

    # pick u1 and u2 at will
    u1 = 1
    u2 = 2
    R = double_mult(u2, Q, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv(u2, ec.n)
    s = r * u2inv % ec.n
    s = ec.n - s if s > ec.n / 2 else s
    e = s * u1 % ec.n
    dsa._assert_as_valid_(e, (Q[0], Q[1], 1), r, s, lower_s=True, ec=ec)

    # pick u1 and u2 at will
    u1 = 1234567890
    u2 = 987654321
    R = double_mult(u2, Q, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv(u2, ec.n)
    s = r * u2inv % ec.n
    s = ec.n - s if s > ec.n / 2 else s
    e = s * u1 % ec.n
    dsa._assert_as_valid_(e, (Q[0], Q[1], 1), r, s, lower_s=True, ec=ec)
