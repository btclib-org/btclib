#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.dsa` module."

from hashlib import sha1

import pytest

from btclib import dsa
from btclib.alias import INF
from btclib.curve import CURVES, double_mult, mult
from btclib.curvegroup import _mult
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.hashes import reduce_to_hlen
from btclib.numbertheory import mod_inv
from btclib.rfc6979 import _rfc6979
from btclib.secpoint import bytes_from_point, point_from_octets
from btclib.tests.test_curve import low_card_curves


def test_signature() -> None:
    ec = CURVES["secp256k1"]
    msg = "Satoshi Nakamoto"

    q, Q = dsa.gen_keys(0x1)
    sig = dsa.sign(msg, q)
    assert dsa.verify(msg, Q, sig)

    assert sig == dsa.deserialize(sig)

    # https://bitcointalk.org/index.php?topic=285142.40
    # Deterministic Usage of DSA and ECDSA (RFC 6979)
    exp_sig = (
        0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8,
        0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5,
    )
    r, s = sig
    assert sig[0] == exp_sig[0]
    assert sig[1] in (exp_sig[1], ec.n - exp_sig[1])

    dsa.assert_as_valid(msg, Q, sig)
    dsa.assert_as_valid(msg, Q, dsa.serialize(*sig))
    dsa.assert_as_valid(msg, Q, dsa.serialize(*sig).hex())

    # malleability
    malleated_sig = (r, ec.n - s)
    assert dsa.verify(msg, Q, malleated_sig)

    keys = dsa.recover_pubkeys(msg, sig)
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

    sig_fake = (sig[0], sig[1], sig[1])
    assert not dsa.verify(msg, Q, sig_fake)  # type: ignore
    err_msg = "too many values to unpack "
    with pytest.raises(ValueError, match=err_msg):
        dsa.assert_as_valid(msg, Q, sig_fake)  # type: ignore

    sig_invalid = ec.p, sig[1]
    assert not dsa.verify(msg, Q, sig_invalid)
    err_msg = "scalar r not in 1..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        dsa.assert_as_valid(msg, Q, sig_invalid)

    sig_invalid = sig[0], ec.p
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
        dsa._sign(reduce_to_hlen(msg), q, ec.n)


def test_gec() -> None:
    """GEC 2: Test Vectors for SEC 1, section 2

    http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
    """
    # 2.1.1 Scheme setup
    ec = CURVES["secp160r1"]
    hf = sha1

    # 2.1.2 Key Deployment for U
    dU = 971761939728640320549601132085879836204587084162
    assert format(dU, str(ec.nsize) + "x") == "aa374ffc3ce144e6b073307972cb6d57b2a4e982"

    QU = mult(dU, ec.G, ec)
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
    r, s = sig
    assert r == exp_sig[0]
    assert s == exp_sig[1]

    # 2.1.4 Verifying Operation for V
    assert dsa.verify(msg, QU, sig, ec, hf)


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
                        continue

                    sig = dsa.__sign(e, q, k, low_s, ec)
                    assert (r, s) == sig
                    # valid signature must pass verification
                    dsa.__assert_as_valid(e, QJ, r, s, ec)

                    JacobianKeys = dsa.__recover_pubkeys(e, r, s, ec)
                    # FIXME speed this up
                    Qs = [ec._aff_from_jac(key) for key in JacobianKeys]
                    assert ec._aff_from_jac(QJ) in Qs
                    assert len(JacobianKeys) in (2, 4)


def test_pubkey_recovery() -> None:

    ec = CURVES["secp112r2"]

    q = 0x10
    Q = mult(q, ec.G, ec)

    msg = "Satoshi Nakamoto"
    low_s = True
    sig = dsa.sign(msg, q, low_s, ec)
    assert dsa.verify(msg, Q, sig, ec)
    dersig = dsa.serialize(*sig, ec)
    assert dsa.verify(msg, Q, dersig, ec)
    r, s = dsa.deserialize(dersig)
    assert (r, s) == sig

    keys = dsa.recover_pubkeys(msg, sig, ec)
    assert len(keys) == 4
    assert Q in keys
    for Q in keys:
        assert dsa.verify(msg, Q, sig, ec)


def test_crack_prvkey() -> None:

    ec = CURVES["secp256k1"]

    # FIXME: make it random
    q = 0x17E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725

    msg1 = "Paolo is afraid of ephemeral random numbers"
    m1 = reduce_to_hlen(msg1)
    k = _rfc6979(m1, q)
    sig1 = dsa._sign(m1, q, k)

    msg2 = "and Paolo is right to be afraid"
    m2 = reduce_to_hlen(msg2)
    # reuse same k
    sig2 = dsa._sign(m2, q, k)

    qc, kc = dsa.crack_prvkey(msg1, sig1, msg2, sig2)
    assert q in (qc, ec.n - qc)
    assert q == qc
    assert k in (kc, ec.n - kc)
    # assert k == kc

    with pytest.raises(BTClibValueError, match="not the same r in signatures"):
        dsa.crack_prvkey(msg1, sig1, msg2, (16, sig1[1]))

    with pytest.raises(BTClibValueError, match="identical signatures"):
        dsa.crack_prvkey(msg1, sig1, msg1, sig1)


def test_forge_hash_sig() -> None:
    """forging valid hash signatures"""

    ec = CURVES["secp256k1"]

    # see https://twitter.com/pwuille/status/1063582706288586752
    # Satoshi's key
    key = "03 11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c"
    P = point_from_octets(key, ec)

    # pick u1 and u2 at will
    u1 = 1
    u2 = 2
    R = double_mult(u2, P, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv(u2, ec.n)
    s = r * u2inv % ec.n
    e = s * u1 % ec.n
    dsa.__assert_as_valid(e, (P[0], P[1], 1), r, s, ec)

    # pick u1 and u2 at will
    u1 = 1234567890
    u2 = 987654321
    R = double_mult(u2, P, u1, ec.G, ec)
    r = R[0] % ec.n
    u2inv = mod_inv(u2, ec.n)
    s = r * u2inv % ec.n
    e = s * u1 % ec.n
    dsa.__assert_as_valid(e, (P[0], P[1], 1), r, s, ec)
