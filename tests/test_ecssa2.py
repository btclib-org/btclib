#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
import random
from hashlib import sha256 as hf

from btclib.numbertheory import mod_inv, legendre_symbol
from btclib.ec import pointMult, DblScalarMult
from btclib.ecurves import secp256k1 as ec
from btclib.ecutils import octets2int, point2octets, bits2int
from btclib.pedersen import secondGenerator
from btclib.ecssa import ecssa_sign, ecssa_verify, _ecssa_verify, \
    ecssa_batch_validation

random.seed(42)


class TestEcssa2(unittest.TestCase):

    def test_batch_validation(self):
        m = []
        sig = []
        Q = []
        a = []

        hsize =hf().digest_size
        hlen = hsize * 8
        for i in range(10):
            m.append(random.getrandbits(hlen).to_bytes(hsize, 'big'))
            q = random.getrandbits(ec.nlen) % ec.n
            sig.append(ecssa_sign(ec, hf, m[i], q))
            Q.append(pointMult(ec, q, ec.G))
            a.append(random.getrandbits(ec.nlen) % ec.n)
        self.assertTrue(ecssa_batch_validation(ec, hf, m, Q, a, sig))

        m.append(m[0])
        sig.append(sig[1])  # invalid
        Q.append(Q[0])
        a.append(a[0])
        self.assertFalse(ecssa_batch_validation(ec, hf, m, Q, a, sig))


    def test_threshold(self):
        """testing 2-of-3 threshold signature (Pedersen secret sharing)"""
        # parameters
        t = 2
        H = secondGenerator(ec, hf)
        msg = hf('message to sign'.encode()).digest()

        ### FIRST PHASE: key pair generation ###

        # signer one acting as the dealer
        commits1 = list()
        q1 = 0  # secret value
        while q1 == 0:
            q1 = random.getrandbits(ec.nlen) % ec.n
        q1_prime = 0
        while q1_prime == 0:
            q1_prime = random.getrandbits(ec.nlen) % ec.n

        commits1.append(DblScalarMult(ec, q1, ec.G, q1_prime, H))

        # sharing polynomials
        f1 = list()
        f1.append(q1)
        f1_prime = list()
        f1_prime.append(q1_prime)
        for i in range(1, t):
            temp = 0
            while temp == 0:
                temp = random.getrandbits(ec.nlen) % ec.n
            f1.append(temp)
            temp = 0
            while temp == 0:
                temp = random.getrandbits(ec.nlen) % ec.n
            f1_prime.append(temp)
            commits1.append(DblScalarMult(
                ec, f1[i], ec.G, f1_prime[i], H))

        # shares of the secret
        alpha12 = 0  # share of q1 belonging to P2
        alpha12_prime = 0
        alpha13 = 0  # share of q1 belonging to P3
        alpha13_prime = 0
        for i in range(t):
            alpha12 += (f1[i] * pow(2, i)) % ec.n
            alpha12_prime += (f1_prime[i] * pow(2, i)) % ec.n

            alpha13 += (f1[i] * pow(3, i)) % ec.n
            alpha13_prime += (f1_prime[i] * pow(3, i)) % ec.n

        # player two verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, pointMult(ec, pow(2, i), commits1[i]))
        assert DblScalarMult(
            ec, alpha12, ec.G, alpha12_prime, H) == RHS, 'player one is cheating'

        # player three verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, pointMult(ec, pow(3, i), commits1[i]))
        assert DblScalarMult(
            ec, alpha13, ec.G, alpha13_prime, H) == RHS, 'player one is cheating'

        # signer two acting as the dealer
        commits2 = list()
        q2 = 0  # secret value
        while q2 == 0:
            q2 = random.getrandbits(ec.nlen) % ec.n
        q2_prime = 0
        while q2_prime == 0:
            q2_prime = random.getrandbits(ec.nlen) % ec.n

        commits2.append(DblScalarMult(ec, q2, ec.G, q2_prime, H))

        # sharing polynomials
        f2 = list()
        f2.append(q2)
        f2_prime = list()
        f2_prime.append(q2_prime)
        for i in range(1, t):
            temp = 0
            while temp == 0:
                temp = random.getrandbits(ec.nlen) % ec.n
            f2.append(temp)
            temp = 0
            while temp == 0:
                temp = random.getrandbits(ec.nlen) % ec.n
            f2_prime.append(temp)
            commits2.append(DblScalarMult(
                ec, f2[i], ec.G, f2_prime[i], H))

        # shares of the secret
        alpha21 = 0  # share of q2 belonging to P1
        alpha21_prime = 0
        alpha23 = 0  # share of q2 belonging to P3
        alpha23_prime = 0
        for i in range(t):
            alpha21 += (f2[i] * pow(1, i)) % ec.n
            alpha21_prime += (f2_prime[i] * pow(1, i)) % ec.n

            alpha23 += (f2[i] * pow(3, i)) % ec.n
            alpha23_prime += (f2_prime[i] * pow(3, i)) % ec.n

        # player one verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, pointMult(ec, pow(1, i), commits2[i]))
        assert DblScalarMult(ec, alpha21, ec.G, alpha21_prime, H) == RHS, 'player two is cheating'

        # player three verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, pointMult(ec, pow(3, i), commits2[i]))
        assert DblScalarMult(ec, alpha23, ec.G, alpha23_prime, H) == RHS, 'player two is cheating'

        # signer three acting as the dealer
        commits3 = list()
        q3 = 0  # secret value
        while q3 == 0:
            q3 = random.getrandbits(ec.nlen) % ec.n
        q3_prime = 0
        while q3_prime == 0:
            q3_prime = random.getrandbits(ec.nlen) % ec.n

        commits3.append(DblScalarMult(ec, q3, ec.G, q3_prime, H))

        # sharing polynomials
        f3 = list()
        f3.append(q3)
        f3_prime = list()
        f3_prime.append(q3_prime)
        for i in range(1, t):
            temp = 0
            while temp == 0:
                temp = random.getrandbits(ec.nlen) % ec.n
            f3.append(temp)
            temp = 0
            while temp == 0:
                temp = random.getrandbits(ec.nlen) % ec.n
            f3_prime.append(temp)
            commits3.append(DblScalarMult(
                ec, f3[i], ec.G, f3_prime[i], H))

        # shares of the secret
        alpha31 = 0  # share of q3 belonging to P1
        alpha31_prime = 0
        alpha32 = 0  # share of q3 belonging to P2
        alpha32_prime = 0
        for i in range(t):
            alpha31 += (f3[i] * pow(1, i)) % ec.n
            alpha31_prime += (f3_prime[i] * pow(1, i)) % ec.n

            alpha32 += (f3[i] * pow(2, i)) % ec.n
            alpha32_prime += (f3_prime[i] * pow(2, i)) % ec.n

        # player one verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, pointMult(ec, pow(1, i), commits3[i]))
        assert DblScalarMult(ec, alpha31, ec.G, alpha31_prime, H) == RHS, 'player three is cheating'

        # player two verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, pointMult(ec, pow(2, i), commits3[i]))
        assert DblScalarMult(ec, alpha32, ec.G, alpha32_prime, H) == RHS, 'player two is cheating'

        # shares of the secret key q = q1 + q2 + q3
        alpha1 = (alpha21 + alpha31) % ec.n
        alpha2 = (alpha12 + alpha32) % ec.n
        alpha3 = (alpha13 + alpha23) % ec.n
        for i in range(t):
            alpha1 += (f1[i] * pow(1, i)) % ec.n
            alpha2 += (f2[i] * pow(2, i)) % ec.n
            alpha3 += (f3[i] * pow(3, i)) % ec.n

        # it's time to recover the public key Q = Q1 + Q2 + Q3 = (q1 + q2 + q3)G
        A1 = list()
        A2 = list()
        A3 = list()

        # each participant i = 1, 2, 3 shares Qi as follows

        # he broadcasts these values
        for i in range(t):
            A1.append(pointMult(ec, f1[i], ec.G))
            A2.append(pointMult(ec, f2[i], ec.G))
            A3.append(pointMult(ec, f3[i], ec.G))

        # he checks the others' values
        # player one
        RHS2 = 1, 0
        RHS3 = 1, 0
        for i in range(t):
            RHS2 = ec.add(RHS2, pointMult(ec, pow(1, i), A2[i]))
            RHS3 = ec.add(RHS3, pointMult(ec, pow(1, i), A3[i]))
        assert pointMult(ec, alpha21, ec.G) == RHS2, 'player two is cheating'
        assert pointMult(ec, alpha31, ec.G) == RHS3, 'player three is cheating'

        # player two
        RHS1 = 1, 0
        RHS3 = 1, 0
        for i in range(t):
            RHS1 = ec.add(RHS1, pointMult(ec, pow(2, i), A1[i]))
            RHS3 = ec.add(RHS3, pointMult(ec, pow(2, i), A3[i]))
        assert pointMult(ec, alpha12, ec.G) == RHS1, 'player one is cheating'
        assert pointMult(ec, alpha32, ec.G) == RHS3, 'player three is cheating'

        # player three
        RHS1 = 1, 0
        RHS2 = 1, 0
        for i in range(t):
            RHS1 = ec.add(RHS1, pointMult(ec, pow(3, i), A1[i]))
            RHS2 = ec.add(RHS2, pointMult(ec, pow(3, i), A2[i]))
        assert pointMult(ec, alpha13, ec.G) == RHS1, 'player one is cheating'
        assert pointMult(ec, alpha23, ec.G) == RHS2, 'player two is cheating'

        A = list()  # commitment at the global sharing polynomial
        for i in range(t):
            A.append(ec.add(A1[i], ec.add(A2[i], A3[i])))

        Q = A[0]  # aggregated public key

        ### SECOND PHASE: generation of the nonces' pair ###
        # This phase follows exactly the key generation procedure
        # suppose that player one and three want to sign

        # signer one acting as the dealer
        commits1 = list()
        k1 = 0  # secret value
        while k1 == 0:
            k1 = random.getrandbits(ec.nlen) % ec.n
        k1_prime = 0
        while k1_prime == 0:
            k1_prime = random.getrandbits(ec.nlen) % ec.n

        commits1.append(DblScalarMult(ec, k1, ec.G, k1_prime, H))

        # sharing polynomials
        f1 = list()
        f1.append(k1)
        f1_prime = list()
        f1_prime.append(k1_prime)
        for i in range(1, t):
            temp = 0
            while temp == 0:
                temp = random.getrandbits(ec.nlen) % ec.n
            f1.append(temp)
            temp = 0
            while temp == 0:
                temp = random.getrandbits(ec.nlen) % ec.n
            f1_prime.append(temp)
            commits1.append(DblScalarMult(
                ec, f1[i], ec.G, f1_prime[i], H))

        # shares of the secret
        beta13 = 0  # share of k1 belonging to P3
        beta13_prime = 0
        for i in range(t):
            beta13 += (f1[i] * pow(3, i)) % ec.n
            beta13_prime += (f1_prime[i] * pow(3, i)) % ec.n

        # player three verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, pointMult(ec, pow(3, i), commits1[i]))
        assert DblScalarMult(ec, beta13, ec.G, beta13_prime, H) == RHS, 'player one is cheating'

        # signer three acting as the dealer
        commits3 = list()
        k3 = 0  # secret value
        while k3 == 0:
            k3 = random.getrandbits(ec.nlen) % ec.n
        k3_prime = 0
        while k3_prime == 0:
            k3_prime = random.getrandbits(ec.nlen) % ec.n

        commits3.append(DblScalarMult(ec, k3, ec.G, k3_prime, H))

        # sharing polynomials
        f3 = list()
        f3.append(k3)
        f3_prime = list()
        f3_prime.append(k3_prime)
        for i in range(1, t):
            temp = 0
            while temp == 0:
                temp = random.getrandbits(ec.nlen) % ec.n
            f3.append(temp)
            temp = 0
            while temp == 0:
                temp = random.getrandbits(ec.nlen) % ec.n
            f3_prime.append(temp)
            commits3.append(DblScalarMult(ec, f3[i], ec.G, f3_prime[i], H))

        # shares of the secret
        beta31 = 0  # share of k3 belonging to P1
        beta31_prime = 0
        for i in range(t):
            beta31 += (f3[i] * pow(1, i)) % ec.n
            beta31_prime += (f3_prime[i] * pow(1, i)) % ec.n

        # player one verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, pointMult(ec, pow(1, i), commits3[i]))
        assert DblScalarMult(ec, beta31, ec.G, beta31_prime, H) == RHS, 'player three is cheating'

        # shares of the secret nonce
        beta1 = beta31 % ec.n
        beta3 = beta13 % ec.n
        for i in range(t):
            beta1 += (f1[i] * pow(1, i)) % ec.n
            beta3 += (f3[i] * pow(3, i)) % ec.n

        # it's time to recover the public nonce
        B1 = list()
        B3 = list()

        # each participant i = 1, 3 shares Qi as follows

        # he broadcasts these values
        for i in range(t):
            B1.append(pointMult(ec, f1[i], ec.G))
            B3.append(pointMult(ec, f3[i], ec.G))

        # he checks the others' values
        # player one
        RHS3 = 1, 0
        for i in range(t):
            RHS3 = ec.add(RHS3, pointMult(ec, pow(1, i), B3[i]))
        assert pointMult(ec, beta31, ec.G) == RHS3, 'player three is cheating'

        # player three
        RHS1 = 1, 0
        for i in range(t):
            RHS1 = ec.add(RHS1, pointMult(ec, pow(3, i), B1[i]))
        assert pointMult(ec, beta13, ec.G) == RHS1, 'player one is cheating'

        B = list()  # commitment at the global sharing polynomial
        for i in range(t):
            B.append(ec.add(B1[i], B3[i]))

        K = B[0]  # aggregated public nonce
        if legendre_symbol(K[1], ec._p) != 1:
            beta1 = ec.n - beta1
            beta3 = ec.n - beta3

        ### PHASE THREE: signature generation ###

        # partial signatures
        ebytes = K[0].to_bytes(32, byteorder="big") 
        ebytes += point2octets(ec, Q, True)
        ebytes += msg
        e = bits2int(ec, hf(ebytes).digest())
        gamma1 = (beta1 + e * alpha1) % ec.n
        gamma3 = (beta3 + e * alpha3) % ec.n

        # each participant verifies the other partial signatures

        # player one
        if legendre_symbol(K[1], ec._p) == 1:
            RHS3 = ec.add(K, pointMult(ec, e, Q))
            for i in range(1, t):
                RHS3 = ec.add(RHS3,
                              DblScalarMult(ec, pow(3, i), B[i], e * pow(3, i), A[i]))
        else:
            assert legendre_symbol(K[1], ec._p) != 1
            RHS3 = ec.add(ec.opposite(K), pointMult(ec, e, Q))
            for i in range(1, t):
                RHS3 = ec.add(RHS3,
                              DblScalarMult(ec, pow(3, i), ec.opposite(B[i]), e * pow(3, i), A[i]))

        assert pointMult(
            ec, gamma3, ec.G) == RHS3, 'player three is cheating'

        # player three
        if legendre_symbol(K[1], ec._p) == 1:
            RHS1 = ec.add(K, pointMult(ec, e, Q))
            for i in range(1, t):
                RHS1 = ec.add(RHS1,
                              DblScalarMult(ec, pow(1, i), B[i], e * pow(1, i), A[i]))
        else:
            assert legendre_symbol(K[1], ec._p) != 1
            RHS1 = ec.add(ec.opposite(K), pointMult(ec, e, Q))
            for i in range(1, t):
                RHS1 = ec.add(RHS1,
                              DblScalarMult(ec, pow(1, i), ec.opposite(B[i]), e * pow(1, i), A[i]))

        assert pointMult(ec, gamma1, ec.G) == RHS1, 'player two is cheating'

        ### PHASE FOUR: aggregating the signature ###
        omega1 = 3 * mod_inv(3 - 1, ec.n) % ec.n
        omega3 = 1 * mod_inv(1 - 3, ec.n) % ec.n
        sigma = (gamma1 * omega1 + gamma3 * omega3) % ec.n

        ecssa = (K[0], sigma)

        self.assertTrue(_ecssa_verify(ec, hf, msg, Q, ecssa))

        ### ADDITIONAL PHASE: reconstruction of the private key ###
        secret = (omega1 * alpha1 + omega3 * alpha3) % ec.n
        self.assertEqual((q1 + q2 + q3) % ec.n, secret)

    def test_musig(self):
        """testing 3-of-3 MuSig

        Resources:
        https://eprint.iacr.org/2018/068
        https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html
        https://medium.com/@snigirev.stepan/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
        """
        L = list()  # multiset of public keys
        M = hf('message to sign'.encode()).digest()

        # first signer
        q1 = octets2int('0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d92ad1d')
        Q1 = pointMult(ec, q1, ec.G)
        L.append(point2octets(ec, Q1, False))

        # ephemeral private nonce
        k1 = 0x012a2a833eac4e67e06611aba01345b85cdd4f5ad44f72e369ef0dd640424dbb
        K1 = pointMult(ec, k1, ec.G)
        K1_x = K1[0]
        if legendre_symbol(K1[1], ec._p) != 1:
            k1 = ec.n - k1
            K1 = K1_x, ec.yQuadraticResidue(K1_x, True)
            #K1 = pointMult(ec, k1, ec.G)

        # second signer
        q2 = octets2int('0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d')
        Q2 = pointMult(ec, q2, ec.G)
        L.append(point2octets(ec, Q2, False))

        k2 = 0x01a2a0d3eac4e67e06611aba01345b85cdd4f5ad44f72e369ef0dd640424dbdb
        K2 = pointMult(ec, k2, ec.G)
        K2_x = K2[0]
        if legendre_symbol(K2[1], ec._p) != 1:
            k2 = ec.n - k2
            K2 = K2_x, ec.yQuadraticResidue(K2_x, True)
            #K2 = pointMult(ec, k2, ec.G)

        # third signer
        q3 = random.getrandbits(ec.nlen) % ec.n
        Q3 = pointMult(ec, q3, ec.G)
        while Q3 == None:  # plausible only for small (test) cardinality groups
            q3 = random.getrandbits(ec.nlen) % ec.n
            Q3 = pointMult(ec, q3, ec.G)
        L.append(point2octets(ec, Q3, False))

        k3 = random.getrandbits(ec.nlen) % ec.n
        K3 = pointMult(ec, k3, ec.G)
        while K3 == None:  # plausible only for small (test) cardinality groups
            k3 = random.getrandbits(ec.nlen) % ec.n
            K3 = pointMult(ec, k3, ec.G)
        K3_x = K3[0]
        if legendre_symbol(K3[1], ec._p) != 1:
            k3 = ec.n - k3
            K3 = K3_x, ec.yQuadraticResidue(K3_x, True)
            #K3 = pointMult(ec, k3, ec.G)

        L.sort()  # using lexicographic ordering
        L_brackets = b''
        for i in range(len(L)):
            L_brackets += L[i]

        h1 = hf(L_brackets + point2octets(ec, Q1, False)).digest()
        a1 = bits2int(ec, h1)
        h2 = hf(L_brackets + point2octets(ec, Q2, False)).digest()
        a2 = bits2int(ec, h2)
        h3 = hf(L_brackets + point2octets(ec, Q3, False)).digest()
        a3 = bits2int(ec, h3)
        # aggregated public key
        Q_All = DblScalarMult(ec, a1, Q1, a2, Q2)
        Q_All = ec.add(Q_All, pointMult(ec, a3, Q3))
        Q_All_bytes = point2octets(ec, Q_All, True)

        ########################
        # exchange K_x, compute s
        # WARNING: the signers should exchange commitments to the public
        #          nonces before sending the nonces themselves

        # first signer use K2_x and K3_x
        y = ec.yQuadraticResidue(K2_x, True)
        K2_recovered = (K2_x, y)
        y = ec.yQuadraticResidue(K3_x, True)
        K3_recovered = (K3_x, y)
        K1_All = ec.add(ec.add(K1, K2_recovered), K3_recovered)
        if legendre_symbol(K1_All[1], ec._p) != 1:
            # no need to actually change K1_All[1], as it is not used anymore
            # let's fix k1 instead, as it is used later
            k1 = ec.n - k1
        K1_All0_bytes = K1_All[0].to_bytes(32, byteorder="big")
        h1 = hf(K1_All0_bytes + Q_All_bytes + M).digest()
        c1 = bits2int(ec, h1)
        assert 0 < c1 and c1 < ec.n, "sign fail"
        s1 = (k1 + c1*a1*q1) % ec.n

        # second signer use K1_x and K3_x
        y = ec.yQuadraticResidue(K1_x, True)
        K1_recovered = (K1_x, y)
        y = ec.yQuadraticResidue(K3_x, True)
        K3_recovered = (K3_x, y)
        K2_All = ec.add(ec.add(K2, K1_recovered), K3_recovered)
        if legendre_symbol(K2_All[1], ec._p) != 1:
            # no need to actually change K2_All[1], as it is not used anymore
            # let's fix k2 instead, as it is used later
            k2 = ec.n - k2
        K2_All0_bytes = K2_All[0].to_bytes(32, byteorder="big")
        h2 = hf(K2_All0_bytes + Q_All_bytes + M).digest()
        c2 = bits2int(ec, h2)
        assert 0 < c2 and c2 < ec.n, "sign fail"
        s2 = (k2 + c2*a2*q2) % ec.n

        # third signer use K1_x and K2_x
        y = ec.yQuadraticResidue(K1_x, True)
        K1_recovered = (K1_x, y)
        y = ec.yQuadraticResidue(K2_x, True)
        K2_recovered = (K2_x, y)
        K3_All = ec.add(ec.add(K1_recovered, K2_recovered), K3)
        if legendre_symbol(K3_All[1], ec._p) != 1:
            # no need to actually change K3_All[1], as it is not used anymore
            # let's fix k3 instead, as it is used later
            k3 = ec.n - k3
        K3_All0_bytes = K3_All[0].to_bytes(32, byteorder="big")
        h3 = hf(K3_All0_bytes + Q_All_bytes + M).digest()
        c3 = bits2int(ec, h3)
        assert 0 < c3 and c3 < ec.n, "sign fail"
        s3 = (k3 + c3*a3*q3) % ec.n

        ############################################
        # combine signatures into a single signature

        # anyone can do the following
        assert K1_All[0] == K2_All[0], "sign fail"
        assert K2_All[0] == K3_All[0], "sign fail"
        s_All = (s1 + s2 + s3) % ec.n
        sig = (K1_All[0], s_All)

        self.assertTrue(ecssa_verify(ec, hf, M, Q_All, sig))


    if __name__ == "__main__":
        # execute only if run as a script
        unittest.main()
