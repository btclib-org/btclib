#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for the `btclib.ssa` module."""

from __future__ import annotations

import csv
from hashlib import sha256 as hf
from os import path

import pytest

from btclib.alias import INF, Point, String
from btclib.bip32 import BIP32KeyData
from btclib.ec import bytes_from_point, double_mult, libsecp256k1, mult
from btclib.ec.curve import CURVES, secp256k1
from btclib.ec.curve_group import jac_from_aff
from btclib.ecc import bip340_nonce_, second_generator, ssa
from btclib.ecc.libsecp256k1 import ecssa_sign_, ecssa_verify_
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.hashes import reduce_to_hlen
from btclib.number_theory import mod_inv
from btclib.utils import int_from_bits
from tests.ec.test_curve import low_card_curves


def test_signature() -> None:
    msg = b"Satoshi Nakamoto"
    aux = b"\x00" * 32
    q = 6
    q_fixed, x_Q = ssa.gen_keys(q)
    assert q_fixed != q
    sig = ssa.sign(msg, q, aux)
    ssa.assert_as_valid(msg, x_Q, sig)
    assert ssa.verify(msg, x_Q, sig)
    assert sig == ssa.Sig.parse(sig.serialize())
    assert sig == ssa.Sig.parse(sig.serialize().hex())

    msg_fake = b"Craig Wright"
    assert not ssa.verify(msg_fake, x_Q, sig)
    err_msg = (
        "libsecp256k1.ecssa_verify_ failed"
        if libsecp256k1.is_available()
        else r"y_K is odd|signature verification failed"
    )
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        ssa.assert_as_valid(msg_fake, x_Q, sig)

    _, x_Q_fake = ssa.gen_keys(q + 2)
    assert not ssa.verify(msg, x_Q_fake, sig)
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        ssa.assert_as_valid(msg, x_Q_fake, sig)

    err_msg = "not a BIP340 public key"
    with pytest.raises(BTClibTypeError, match=err_msg):
        ssa.assert_as_valid(msg, INF, sig)
    with pytest.raises(BTClibTypeError, match=err_msg):
        ssa.point_from_bip340pub_key(INF)

    sig_invalid = ssa.Sig(sig.ec.p, sig.s, check_validity=False)
    assert not ssa.verify(msg, x_Q, sig_invalid)
    err_msg = "x-coordinate not in 0..p-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_as_valid(msg, x_Q, sig_invalid)

    sig_invalid = ssa.Sig(sig.r, sig.ec.p, check_validity=False)
    assert not ssa.verify(msg, x_Q, sig_invalid)
    err_msg = "scalar s not in 0..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_as_valid(msg, x_Q, sig_invalid)

    m_bytes = reduce_to_hlen(msg, hf)
    err_msg = "invalid size: 31 bytes instead of 32|libsecp256k1.ecssa_verify_ failed"
    with pytest.raises((BTClibValueError, BTClibRuntimeError), match=err_msg):
        ssa.assert_as_valid_(m_bytes[:31], x_Q, sig)

    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.sign_(m_bytes[:31], q)

    err_msg = "private key not in 1..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.sign(msg, 0)


def test_bip340_vectors() -> None:
    """BIP340 (Schnorr) test vectors.

    - https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    """
    fname = "bip340_test_vectors.csv"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, newline="", encoding="ascii") as csvfile:
        reader = csv.reader(csvfile)
        # skip column headers while checking that there are 7 columns
        next(reader)
        for row in reader:
            (index, seckey, pub_key, aux_rand, m, sig, result, comment) = row
            err_msg = f"Test vector #{int(index)}"
            try:
                if seckey != "":
                    _, pub_key_actual = ssa.gen_keys(seckey)
                    assert pub_key == hex(pub_key_actual).upper()[2:], err_msg

                    sig_actual = ssa.sign_(m, seckey, aux_rand)
                    ssa.assert_as_valid_(m, pub_key, sig_actual)
                    assert ssa.Sig.parse(sig) == sig_actual, err_msg

                if comment:
                    err_msg += f": {comment}"
                # TODO what's wrong with xor-ing ?
                # assert (result == "TRUE") ^ ssa.verify_(m, pub_key, sig), err_msg
                if result == "TRUE":
                    ssa.assert_as_valid_(m, pub_key, sig)
                    assert ssa.verify_(m, pub_key, sig), err_msg
                else:
                    assert not ssa.verify_(m, pub_key, sig), err_msg
            except Exception as e:  # pragma: no cover # pylint: disable=broad-except
                print(err_msg)  # pragma: no cover
                raise e  # pragma: no cover


def test_point_from_bip340pub_key() -> None:
    q, x_Q = ssa.gen_keys()
    Q = mult(q)
    # Integer (int)
    assert ssa.point_from_bip340pub_key(x_Q) == Q
    # Integer (bytes)
    x_Q_bytes = x_Q.to_bytes(32, "big", signed=False)
    assert ssa.point_from_bip340pub_key(x_Q_bytes) == Q
    # Integer (hex-str)
    assert ssa.point_from_bip340pub_key(x_Q_bytes.hex()) == Q
    # tuple Point
    assert ssa.point_from_bip340pub_key(Q) == Q
    # 33 bytes
    assert ssa.point_from_bip340pub_key(bytes_from_point(Q)) == Q
    # 33 bytes hex-string
    assert ssa.point_from_bip340pub_key(bytes_from_point(Q).hex()) == Q
    # 65 bytes
    assert ssa.point_from_bip340pub_key(bytes_from_point(Q, compressed=False)) == Q
    # 65 bytes hex-string
    assert (
        ssa.point_from_bip340pub_key(bytes_from_point(Q, compressed=False).hex()) == Q
    )

    xpub_data = BIP32KeyData.b58decode(
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
    )
    xpub_data.key = bytes_from_point(Q)
    # BIP32KeyData
    assert ssa.point_from_bip340pub_key(xpub_data) == Q
    # BIP32Key encoded str
    xpub = xpub_data.b58encode()
    assert ssa.point_from_bip340pub_key(xpub) == Q
    # BIP32Key str
    assert ssa.point_from_bip340pub_key(xpub.encode("ascii")) == Q


def test_low_cardinality() -> None:
    """Test low-cardinality curves for all msg/key pairs."""
    # pylint: disable=protected-access

    # ec.n has to be prime to sign
    test_curves = [
        low_card_curves["ec13_11"],
        low_card_curves["ec13_19"],
        low_card_curves["ec17_13"],
        low_card_curves["ec17_23"],
        low_card_curves["ec19_13"],
        low_card_curves["ec19_23"],
        low_card_curves["ec23_19"],
        low_card_curves["ec23_31"],
    ]

    aux = b"\x00" * 32
    msg = b"\x01"
    # only low cardinality test curves or it would take forever
    for ec in test_curves:
        for q in range(1, ec.n // 2):  # all possible private keys
            q_fixed, x_Q = ssa.gen_keys(q, ec)
            QJ = jac_from_aff((x_Q, ec.y_even(x_Q)))
            while True:
                try:
                    sig = ssa.sign(msg, q, aux, ec)
                    break
                except BTClibRuntimeError:  # invalid zero challenge
                    msg += b"\x01"
                    continue
            ssa.assert_as_valid(msg, x_Q, sig)
            for k in range(1, ec.n // 2):  # all possible ephemeral keys
                k_fixed, r = ssa.gen_keys(k, ec)
                for e in range(ec.n):  # all possible challenges
                    s = (k_fixed + e * q_fixed) % ec.n

                    if e == 0:
                        err_msg = "invalid zero challenge"
                        with pytest.raises(BTClibRuntimeError, match=err_msg):
                            ssa._sign_(e, q_fixed, k_fixed, r, ec)
                        # no public key can be recovered
                        with pytest.raises(BTClibRuntimeError, match=err_msg):
                            ssa._recover_pub_key_(e, r, s, ec)

                        # if e == 0 then the sig is always valid
                        ssa._assert_as_valid_(e, QJ, r, s, ec)
                        #  for all {q, Q}
                        ssa._assert_as_valid_(e, ec.GJ, r, s, ec)
                    else:
                        sig = ssa._sign_(e, q_fixed, k_fixed, r, ec)
                        # recover pub_key
                        assert x_Q == ssa._recover_pub_key_(e, r, s, ec)

                        assert ssa.Sig(r, s, ec) == sig
                        # valid signature must validate
                        ssa._assert_as_valid_(e, QJ, r, s, ec)
                        # invalid signature must raise
                        err_msg = r"y_K is odd|INF has no y-coordinate|signature verification failed"
                        with pytest.raises(
                            (BTClibRuntimeError, BTClibValueError), match=err_msg
                        ):
                            ssa._assert_as_valid_(e, QJ, r, (s - 1) % ec.n, ec)


def test_batch_validation() -> None:
    ms: list[String] = []
    Qs: list[int] = []
    sigs: list[ssa.Sig] = []
    err_msg = "no signatures provided"
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid(ms, Qs, sigs)
    assert not ssa.batch_verify(ms, Qs, sigs)

    aux = b"\x00" * 32
    # not the size of the msg_hash, just an arbitrary size for the msg
    msg_size = 16
    for i in range(1, 4):
        m = bytes(i) * msg_size
        ms.append(m)
        q, Q = ssa.gen_keys(i)
        Qs.append(Q)
        sigs.append(ssa.sign(m, q, aux))
        ssa.assert_batch_as_valid(ms, Qs, sigs)
        assert ssa.batch_verify(ms, Qs, sigs)

    ms.append(ms[0])
    sigs.append(sigs[1])
    Qs.append(Qs[0])
    err_msg = "signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        ssa.assert_batch_as_valid(ms, Qs, sigs)
    assert not ssa.batch_verify(ms, Qs, sigs)
    sigs[-1] = sigs[0]  # valid again

    ms.append(ms[0])  # add extra message
    err_msg = "mismatch between number of pub_keys "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid(ms, Qs, sigs)
    assert not ssa.batch_verify(ms, Qs, sigs)
    ms.pop()  # valid again

    sigs.append(sigs[0])  # add extra sig
    err_msg = "mismatch between number of pub_keys "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid(ms, Qs, sigs)
    assert not ssa.batch_verify(ms, Qs, sigs)
    sigs.pop()  # valid again

    sigs[0] = ssa.Sig(
        sigs[0].r, sigs[0].s, CURVES["secp256r1"], check_validity=False
    )  # different curve
    err_msg = "not the same curve for all signatures"
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid(ms, Qs, sigs)
    assert not ssa.batch_verify(ms, Qs, sigs)
    sigs[0] = ssa.Sig(sigs[0].r, sigs[0].s, CURVES["secp256k1"])  # same curve again

    ms = [reduce_to_hlen(m, hf) for m in ms]
    ms[0] = ms[0][:-1]
    err_msg = "invalid size: 31 bytes instead of 32"
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid_(ms, Qs, sigs)
    assert not ssa.batch_verify_(ms, Qs, sigs)


def test_musig() -> None:
    """Testing 3-of-3 MuSig.

    - https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/musig/musig.md
    - https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/
    - https://eprint.iacr.org/2018/068
    - https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html
    - https://medium.com/@snigirev.stepan/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
    """
    ec = CURVES["secp256k1"]

    msg_hash = hf(b"message to sign").digest()

    # the signers private and public keys,
    # including both the curve Point and the BIP340-Schnorr public key
    q1, x_Q1_int = ssa.gen_keys()
    x_Q1 = x_Q1_int.to_bytes(ec.p_size, byteorder="big", signed=False)

    q2, x_Q2_int = ssa.gen_keys()
    x_Q2 = x_Q2_int.to_bytes(ec.p_size, byteorder="big", signed=False)

    q3, x_Q3_int = ssa.gen_keys()
    x_Q3 = x_Q3_int.to_bytes(ec.p_size, byteorder="big", signed=False)

    # (non interactive) key setup
    # this is MuSig core: the rest is just Schnorr signature additivity
    # 1. lexicographic sorting of public keys
    keys = [x_Q1, x_Q2, x_Q3]
    keys.sort()
    # 2. coefficients
    prefix = b"".join(keys)
    a1 = int_from_bits(hf(prefix + x_Q1).digest(), ec.nlen) % ec.n
    a2 = int_from_bits(hf(prefix + x_Q2).digest(), ec.nlen) % ec.n
    a3 = int_from_bits(hf(prefix + x_Q3).digest(), ec.nlen) % ec.n
    # 3. aggregated public key
    Q1 = mult(q1)
    Q2 = mult(q2)
    Q3 = mult(q3)
    Q = ec.add(double_mult(a1, Q1, a2, Q2), mult(a3, Q3))
    if Q[1] % 2:
        # print("Q has been negated")
        a1 = ec.n - a1  # pragma: no cover
        a2 = ec.n - a2  # pragma: no cover
        a3 = ec.n - a3  # pragma: no cover

    # ready to sign: nonces and nonce commitments
    k1, _ = ssa.gen_keys()
    K1 = mult(k1)

    k2, _ = ssa.gen_keys()
    K2 = mult(k2)

    k3, _ = ssa.gen_keys()
    K3 = mult(k3)

    # exchange {K_i} (interactive)

    # computes s_i (non interactive)
    # WARNING: signers must exchange the nonces commitments {K_i}
    # before sharing {s_i}

    # same for all signers
    K = ec.add(ec.add(K1, K2), K3)
    if K[1] % 2:
        k1 = ec.n - k1  # pragma: no cover
        k2 = ec.n - k2  # pragma: no cover
        k3 = ec.n - k3  # pragma: no cover
    r = K[0]
    e = ssa.challenge_(msg_hash, Q[0], r, ec, hf)
    s_1 = (k1 + e * a1 * q1) % ec.n
    s_2 = (k2 + e * a2 * q2) % ec.n
    s3 = (k3 + e * a3 * q3) % ec.n

    # exchange s_i (interactive)

    # finalize signature (non interactive)
    s = (s_1 + s_2 + s3) % ec.n
    sig = ssa.Sig(r, s, ec)
    # check signature is valid
    ssa.assert_as_valid_(msg_hash, Q[0], sig, hf)


def test_threshold() -> None:
    """Testing 2-of-3 threshold signature (Pedersen secret sharing)."""
    # sourcery skip: low-code-quality

    ec = CURVES["secp256k1"]

    # parameters
    m = 2
    H = second_generator(ec)

    # FIRST PHASE: key pair generation ###################################

    # 1.1 signer one acting as the dealer
    commits1: list[Point] = []
    q1, _ = ssa.gen_keys()
    q1_prime, _ = ssa.gen_keys()
    commits1.append(double_mult(q1_prime, H, q1, ec.G))
    # sharing polynomials
    f1 = [q1]
    f1_prime = [q1_prime]
    for i in range(1, m):
        f1.append(ssa.gen_keys()[0])
        f1_prime.append(ssa.gen_keys()[0])
        commits1.append(double_mult(f1_prime[i], H, f1[i], ec.G))
    # shares of the secret
    alpha12 = 0  # share of q1 belonging to signer two
    alpha12_prime = 0
    alpha13 = 0  # share of q1 belonging to signer three
    alpha13_prime = 0
    for i in range(m):
        alpha12 += (f1[i] * pow(2, i)) % ec.n
        alpha12_prime += (f1_prime[i] * pow(2, i)) % ec.n
        alpha13 += (f1[i] * pow(3, i)) % ec.n
        alpha13_prime += (f1_prime[i] * pow(3, i)) % ec.n
    # signer two verifies consistency of his share
    RHS = INF
    for i in range(m):
        RHS = ec.add(RHS, mult(pow(2, i), commits1[i]))
    t = double_mult(alpha12_prime, H, alpha12, ec.G)
    assert t == RHS, "signer one is cheating"
    # signer three verifies consistency of his share
    RHS = INF
    for i in range(m):
        RHS = ec.add(RHS, mult(pow(3, i), commits1[i]))
    t = double_mult(alpha13_prime, H, alpha13, ec.G)
    assert t == RHS, "signer one is cheating"

    # 1.2 signer two acting as the dealer
    commits2: list[Point] = []
    q2, _ = ssa.gen_keys()
    q2_prime, _ = ssa.gen_keys()
    commits2.append(double_mult(q2_prime, H, q2, ec.G))
    # sharing polynomials
    f2 = [q2]
    f2_prime = [q2_prime]
    for i in range(1, m):
        f2.append(ssa.gen_keys()[0])
        f2_prime.append(ssa.gen_keys()[0])
        commits2.append(double_mult(f2_prime[i], H, f2[i], ec.G))
    # shares of the secret
    alpha21 = 0  # share of q2 belonging to signer one
    alpha21_prime = 0
    alpha23 = 0  # share of q2 belonging to signer three
    alpha23_prime = 0
    for i in range(m):
        alpha21 += (f2[i] * pow(1, i)) % ec.n
        alpha21_prime += (f2_prime[i] * pow(1, i)) % ec.n
        alpha23 += (f2[i] * pow(3, i)) % ec.n
        alpha23_prime += (f2_prime[i] * pow(3, i)) % ec.n
    # signer one verifies consistency of his share
    RHS = INF
    for i in range(m):
        RHS = ec.add(RHS, mult(pow(1, i), commits2[i]))
    t = double_mult(alpha21_prime, H, alpha21, ec.G)
    assert t == RHS, "signer two is cheating"
    # signer three verifies consistency of his share
    RHS = INF
    for i in range(m):
        RHS = ec.add(RHS, mult(pow(3, i), commits2[i]))
    t = double_mult(alpha23_prime, H, alpha23, ec.G)
    assert t == RHS, "signer two is cheating"

    # 1.3 signer three acting as the dealer
    commits3: list[Point] = []
    q3, _ = ssa.gen_keys()
    q3_prime, _ = ssa.gen_keys()
    commits3.append(double_mult(q3_prime, H, q3, ec.G))
    # sharing polynomials
    f3 = [q3]
    f3_prime = [q3_prime]
    for i in range(1, m):
        f3.append(ssa.gen_keys()[0])
        f3_prime.append(ssa.gen_keys()[0])
        commits3.append(double_mult(f3_prime[i], H, f3[i], ec.G))
    # shares of the secret
    alpha31 = 0  # share of q3 belonging to signer one
    alpha31_prime = 0
    alpha32 = 0  # share of q3 belonging to signer two
    alpha32_prime = 0
    for i in range(m):
        alpha31 += (f3[i] * pow(1, i)) % ec.n
        alpha31_prime += (f3_prime[i] * pow(1, i)) % ec.n
        alpha32 += (f3[i] * pow(2, i)) % ec.n
        alpha32_prime += (f3_prime[i] * pow(2, i)) % ec.n
    # signer one verifies consistency of his share
    RHS = INF
    for i in range(m):
        RHS = ec.add(RHS, mult(pow(1, i), commits3[i]))
    t = double_mult(alpha31_prime, H, alpha31, ec.G)
    assert t == RHS, "signer three is cheating"
    # signer two verifies consistency of his share
    RHS = INF
    for i in range(m):
        RHS = ec.add(RHS, mult(pow(2, i), commits3[i]))
    t = double_mult(alpha32_prime, H, alpha32, ec.G)
    assert t == RHS, "signer three is cheating"
    # shares of the secret key q = q1 + q2 + q3
    alpha1 = (alpha21 + alpha31) % ec.n
    alpha2 = (alpha12 + alpha32) % ec.n
    alpha3 = (alpha13 + alpha23) % ec.n
    for i in range(m):
        alpha1 += (f1[i] * pow(1, i)) % ec.n
        alpha2 += (f2[i] * pow(2, i)) % ec.n
        alpha3 += (f3[i] * pow(3, i)) % ec.n

    # 1.4 it's time to recover the public key
    # each participant i = 1, 2, 3 shares Qi as follows
    # Q = Q1 + Q2 + Q3 = (q1 + q2 + q3) G
    A1: list[Point] = []
    A2: list[Point] = []
    A3: list[Point] = []
    for i in range(m):
        A1.append(mult(f1[i]))
        A2.append(mult(f2[i]))
        A3.append(mult(f3[i]))
    # signer one checks others' values
    RHS2 = INF
    RHS3 = INF
    for i in range(m):
        RHS2 = ec.add(RHS2, mult(pow(1, i), A2[i]))
        RHS3 = ec.add(RHS3, mult(pow(1, i), A3[i]))
    assert mult(alpha21) == RHS2, "signer two is cheating"
    assert mult(alpha31) == RHS3, "signer three is cheating"
    # signer two checks others' values
    RHS1 = INF
    RHS3 = INF
    for i in range(m):
        RHS1 = ec.add(RHS1, mult(pow(2, i), A1[i]))
        RHS3 = ec.add(RHS3, mult(pow(2, i), A3[i]))
    assert mult(alpha12) == RHS1, "signer one is cheating"
    assert mult(alpha32) == RHS3, "signer three is cheating"
    # signer three checks others' values
    RHS1 = INF
    RHS2 = INF
    for i in range(m):
        RHS1 = ec.add(RHS1, mult(pow(3, i), A1[i]))
        RHS2 = ec.add(RHS2, mult(pow(3, i), A2[i]))
    assert mult(alpha13) == RHS1, "signer one is cheating"
    assert mult(alpha23) == RHS2, "signer two is cheating"
    # commitment at the global sharing polynomial
    A = [ec.add(A1[i], ec.add(A2[i], A3[i])) for i in range(m)]
    # aggregated public key
    Q = A[0]
    if Q[1] % 2:
        # print('Q has been negated')
        A[1] = ec.negate(A[1])  # pragma: no cover
        alpha1 = ec.n - alpha1  # pragma: no cover
        alpha2 = ec.n - alpha2  # pragma: no cover
        alpha3 = ec.n - alpha3  # pragma: no cover
        Q = ec.negate(Q)  # pragma: no cover

    # SECOND PHASE: generation of the nonces' pair  ######################
    # Assume signer one and three want to sign

    msg = b"message to sign"
    msg_hash = reduce_to_hlen(msg, hf)

    # 2.1 signer one acting as the dealer
    k1, _, _, _ = bip340_nonce_(msg_hash, q1, None, ec, hf)
    k1_prime, _, _, _ = bip340_nonce_(msg_hash, q1_prime, None, ec, hf)
    commits1 = [double_mult(k1_prime, H, k1, ec.G)]
    # sharing polynomials
    f1 = [k1]
    f1_prime = [k1_prime]
    for i in range(1, m):
        f1.append(ssa.gen_keys()[0])
        f1_prime.append(ssa.gen_keys()[0])
        commits1.append(double_mult(f1_prime[i], H, f1[i], ec.G))
    # shares of the secret
    beta13 = 0  # share of k1 belonging to signer three
    beta13_prime = 0
    for i in range(m):
        beta13 += (f1[i] * pow(3, i)) % ec.n
        beta13_prime += (f1_prime[i] * pow(3, i)) % ec.n
    # signer three verifies consistency of his share
    RHS = INF
    for i in range(m):
        RHS = ec.add(RHS, mult(pow(3, i), commits1[i]))
    t = double_mult(beta13_prime, H, beta13, ec.G)
    assert t == RHS, "signer one is cheating"

    # 2.2 signer three acting as the dealer
    k3, _, _, _ = bip340_nonce_(msg_hash, q3, None, ec, hf)
    k3_prime, _, _, _ = bip340_nonce_(msg_hash, q3_prime, None, ec, hf)
    commits3 = [double_mult(k3_prime, H, k3, ec.G)]
    # sharing polynomials
    f3 = [k3]
    f3_prime = [k3_prime]
    for i in range(1, m):
        f3.append(ssa.gen_keys()[0])
        f3_prime.append(ssa.gen_keys()[0])
        commits3.append(double_mult(f3_prime[i], H, f3[i], ec.G))
    # shares of the secret
    beta31 = 0  # share of k3 belonging to signer one
    beta31_prime = 0
    for i in range(m):
        beta31 += (f3[i] * pow(1, i)) % ec.n
        beta31_prime += (f3_prime[i] * pow(1, i)) % ec.n
    # signer one verifies consistency of his share
    RHS = INF
    for i in range(m):
        RHS = ec.add(RHS, mult(pow(1, i), commits3[i]))
    t = double_mult(beta31_prime, H, beta31, ec.G)
    assert t == RHS, "signer three is cheating"

    # 2.3 shares of the secret nonce
    beta1 = beta31 % ec.n
    beta3 = beta13 % ec.n
    for i in range(m):
        beta1 += (f1[i] * pow(1, i)) % ec.n
        beta3 += (f3[i] * pow(3, i)) % ec.n

    # 2.4 it's time to recover the public nonce
    # each participant i = 1, 3 shares Qi as follows
    B1: list[Point] = []
    B3: list[Point] = []
    for i in range(m):
        B1.append(mult(f1[i]))
        B3.append(mult(f3[i]))

    # signer one checks values from signer three
    RHS3 = INF
    for i in range(m):
        RHS3 = ec.add(RHS3, mult(pow(1, i), B3[i]))
    assert mult(beta31) == RHS3, "signer three is cheating"

    # signer three checks values from signer one
    RHS1 = INF
    for i in range(m):
        RHS1 = ec.add(RHS1, mult(pow(3, i), B1[i]))
    assert mult(beta13) == RHS1, "signer one is cheating"

    # commitment at the global sharing polynomial
    B = [ec.add(B1[i], B3[i]) for i in range(m)]
    # aggregated public nonce
    K = B[0]
    if K[1] % 2:
        # print('K has been negated')
        B[1] = ec.negate(B[1])  # pragma: no cover
        beta1 = ec.n - beta1  # pragma: no cover
        beta3 = ec.n - beta3  # pragma: no cover
        K = ec.negate(K)  # pragma: no cover

    # PHASE THREE: signature generation ###

    # partial signatures
    e = ssa.challenge_(msg_hash, Q[0], K[0], ec, hf)
    gamma1 = (beta1 + e * alpha1) % ec.n
    gamma3 = (beta3 + e * alpha3) % ec.n

    # each participant verifies the other partial signatures

    # signer one
    RHS3 = ec.add(K, mult(e, Q))
    for i in range(1, m):
        temp = double_mult(pow(3, i), B[i], e * pow(3, i), A[i])
        RHS3 = ec.add(RHS3, temp)
    assert mult(gamma3) == RHS3, "signer three is cheating"

    # signer three
    RHS1 = ec.add(K, mult(e, Q))
    for i in range(1, m):
        temp = double_mult(pow(1, i), B[i], e * pow(1, i), A[i])
        RHS1 = ec.add(RHS1, temp)
    assert mult(gamma1) == RHS1, "signer one is cheating"

    # PHASE FOUR: aggregating the signature ###
    omega1 = 3 * mod_inv(3 - 1, ec.n) % ec.n
    omega3 = 1 * mod_inv(1 - 3, ec.n) % ec.n
    sigma = (gamma1 * omega1 + gamma3 * omega3) % ec.n

    sig = ssa.Sig(K[0], sigma, ec)

    assert ssa.verify_(msg_hash, Q[0], sig)

    # ADDITIONAL PHASE: reconstruction of the private key ###
    secret = (omega1 * alpha1 + omega3 * alpha3) % ec.n
    assert (q1 + q2 + q3) % ec.n in (secret, ec.n - secret)


def test_libsecp256k1() -> None:
    msg = b"Satoshi Nakamoto"
    prvkey_int, pubkey_int = ssa.gen_keys(0x1)
    aux = b"\x00" * 32
    btclib_sig = ssa.sign(msg, prvkey_int, aux)
    pub_key = pubkey_int.to_bytes(32, "big")
    assert ssa.verify(msg, pub_key, btclib_sig.serialize())
    assert ssa.verify(msg, pub_key, btclib_sig)

    if libsecp256k1.is_available():
        msg_hash = reduce_to_hlen(msg)
        libsecp256k1_sig = ecssa_sign_(msg_hash, prvkey_int, aux)
        assert len(libsecp256k1_sig) == 64
        assert len(btclib_sig.serialize()) == 64
        assert btclib_sig.serialize() == libsecp256k1_sig
        assert ecssa_verify_(msg_hash, pub_key, libsecp256k1_sig)
        assert ssa.verify(msg, pub_key, libsecp256k1_sig)

        invalid_prvkey = secp256k1.p
        err_msg = "private key not in 1..n-1"
        with pytest.raises(BTClibValueError, match=err_msg):
            ecssa_sign_(msg_hash, invalid_prvkey)

        err_msg = "invalid size: "
        with pytest.raises(BTClibValueError, match=err_msg):
            ecssa_verify_(msg_hash, pub_key[1:], libsecp256k1_sig)
