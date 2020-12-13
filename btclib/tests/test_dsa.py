#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
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

from btclib import dsa
from btclib.alias import INF
from btclib.curve import CURVES, double_mult, mult
from btclib.curve_group import _mult
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.hashes import reduce_to_hlen
from btclib.number_theory import mod_inv
from btclib.sec_point import bytes_from_point, point_from_octets
from btclib.tests.test_curve import low_card_curves


def test_signature() -> None:
    msg = "Satoshi Nakamoto"

    q, Q = dsa.gen_keys(0x1)
    sig = dsa.sign(msg, q)
    dsa.assert_as_valid(msg, Q, sig)
    assert dsa.verify(msg, Q, sig)
    assert sig == dsa.Sig.deserialize(sig.serialize())
    assert sig == dsa.Sig.deserialize(sig.serialize().hex())

    # https://bitcointalk.org/index.php?topic=285142.40
    # Deterministic Usage of DSA and ECDSA (RFC 6979)
    exp_sig = (
        0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8,
        0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5,
    )
    assert sig.r == exp_sig[0]
    assert sig.s in (exp_sig[1], sig.ec.n - exp_sig[1])

    # malleability
    malleated_sig = dsa.Sig(sig.r, sig.ec.n - sig.s)
    assert dsa.verify(msg, Q, malleated_sig)

    keys = dsa.recover_pub_keys(msg, sig)
    assert len(keys) == 2
    assert Q in keys

    keys = dsa.recover_pub_keys(msg, sig.serialize())
    assert len(keys) == 2
    assert Q in keys

    msg_fake = "Craig Wright"
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
        dsa._sign(reduce_to_hlen(msg), q, 0)
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa._sign(reduce_to_hlen(msg), q, sig.ec.n)


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
    assert format(dU, str(ec.nsize) + "x") == "aa374ffc3ce144e6b073307972cb6d57b2a4e982"
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
    exp_sig = (
        0xCE2873E5BE449563391FEB47DDCBA2DC16379191,
        0x3480EC1371A091A464B31CE47DF0CB8AA2D98B54,
    )
    low_s = False
    sig = dsa._sign(reduce_to_hlen(msg, hf), dU, k, low_s, ec, hf)
    assert sig.r == exp_sig[0]
    assert sig.s == exp_sig[1]
    assert sig.ec == ec

    # 2.1.4 Verifying Operation for V
    dsa.assert_as_valid(msg, QU, sig, hf)
    assert dsa.verify(msg, QU, sig, hf)


@pytest.mark.first
def test_low_cardinality() -> None:
    """test low-cardinality curves for all msg/key pairs."""

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

    low_s = True
    # only low cardinality test curves or it would take forever
    for ec in test_curves:
        for q in range(1, ec.n):  # all possible private keys
            QJ = _mult(q, ec.GJ, ec)  # public key
            for k in range(1, ec.n):  # all possible ephemeral keys
                RJ = _mult(k, ec.GJ, ec)
                r = ec._x_aff_from_jac(RJ) % ec.n
                k_inv = mod_inv(k, ec.n)
                for e in range(ec.n):  # all possible challenges
                    s = k_inv * (e + q * r) % ec.n
                    # bitcoin canonical 'low-s' encoding for ECDSA
                    if low_s and s > ec.n / 2:
                        s = ec.n - s
                    if r == 0 or s == 0:
                        err_msg = "failed to sign: "
                        with pytest.raises(BTClibRuntimeError, match=err_msg):
                            dsa.__sign(e, q, k, low_s, ec)
                    else:
                        sig = dsa.__sign(e, q, k, low_s, ec)
                        assert r == sig.r
                        assert s == sig.s
                        assert ec == sig.ec
                        # valid signature must pass verification
                        dsa.__assert_as_valid(e, QJ, r, s, ec)

                        jacobian_keys = dsa.__recover_pub_keys(e, r, s, ec)
                        # FIXME speed this up
                        Qs = [ec._aff_from_jac(key) for key in jacobian_keys]
                        assert ec._aff_from_jac(QJ) in Qs
                        assert len(jacobian_keys) in (2, 4)


def test_pub_key_recovery() -> None:

    ec = CURVES["secp112r2"]

    q = 0x10
    Q = mult(q, ec.G, ec)

    msg = "Satoshi Nakamoto"
    low_s = True
    sig = dsa.sign(msg, q, low_s, ec)
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

    msg1 = "Paolo is afraid of ephemeral random numbers"
    m_1 = reduce_to_hlen(msg1)
    sig1 = dsa._sign(m_1, q, k)

    msg2 = "and Paolo is right to be afraid"
    m_2 = reduce_to_hlen(msg2)
    sig2 = dsa._sign(m_2, q, k)

    q_cracked, k_cracked = dsa.crack_prv_key(msg1, sig1.serialize(), msg2, sig2)

    #  if the low_s convention has changed only one of s1 and s2
    sig2 = dsa.Sig(sig2.r, ec.n - sig2.s)
    qc2, kc2 = dsa.crack_prv_key(msg1, sig1, msg2, sig2.serialize())

    assert (q == q_cracked and k in (k_cracked, ec.n - k_cracked)) or (
        q == qc2 and k in (kc2, ec.n - kc2)
    )

    with pytest.raises(BTClibValueError, match="not the same r in signatures"):
        dsa.crack_prv_key(msg1, sig1, msg2, dsa.Sig(16, sig1.s))

    with pytest.raises(BTClibValueError, match="identical signatures"):
        dsa.crack_prv_key(msg1, sig1, msg1, sig1)

    sig = dsa.Sig(sig1.r, sig1.s, CURVES["secp256r1"])
    with pytest.raises(BTClibValueError, match="not the same curve in signatures"):
        dsa.crack_prv_key(msg1, sig, msg2, sig2)


def test_forge_hash_sig() -> None:
    """forging valid hash signatures"""

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
    e = s * u1 % ec.n
    dsa.__assert_as_valid(e, (Q[0], Q[1], 1), r, s, ec)

    # pick u1 and u2 at will
    u1 = 1234567890
    u2 = 987654321
    R = double_mult(u2, Q, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv(u2, ec.n)
    s = r * u2inv % ec.n
    e = s * u1 % ec.n
    dsa.__assert_as_valid(e, (Q[0], Q[1], 1), r, s, ec)
