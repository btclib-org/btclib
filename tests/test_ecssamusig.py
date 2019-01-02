#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""First attempt at multisig using Schnorr Signature Algoritm

To be improved and refactored

Resources:
https://eprint.iacr.org/2018/068
https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html
https://medium.com/@snigirev.stepan/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
"""

import random
import unittest
from hashlib import sha256

from btclib.numbertheory import legendre_symbol
from btclib.ec import secp256k1, pointMult, DblScalarMult
from btclib.ecutils import octets2int, point2octets, bits2int
from btclib.ecssa import ecssa_verify

random.seed(42)

class TestEcssaMuSig(unittest.TestCase):

    def test_ecssamusig(self):
        ec = secp256k1
        bits = ec.bytesize * 8
        L = list()  # multiset of public keys
        M = sha256('message to sign'.encode()).digest()

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
        q3 = random.getrandbits(bits) % ec.n
        Q3 = pointMult(ec, q3, ec.G)
        while Q3 == None:  # plausible only for small (test) cardinality groups
            q3 = random.getrandbits(bits) % ec.n
            Q3 = pointMult(ec, q3, ec.G)
        L.append(point2octets(ec, Q3, False))

        k3 = random.getrandbits(bits) % ec.n
        K3 = pointMult(ec, k3, ec.G)
        while K3 == None:  # plausible only for small (test) cardinality groups
            k3 = random.getrandbits(bits) % ec.n
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

        h1 = sha256(L_brackets + point2octets(ec, Q1, False)).digest()
        a1 = bits2int(ec, h1)
        h2 = sha256(L_brackets + point2octets(ec, Q2, False)).digest()
        a2 = bits2int(ec, h2)
        h3 = sha256(L_brackets + point2octets(ec, Q3, False)).digest()
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
        h1 = sha256(K1_All0_bytes + Q_All_bytes + M).digest()
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
        h2 = sha256(K2_All0_bytes + Q_All_bytes + M).digest()
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
        h3 = sha256(K3_All0_bytes + Q_All_bytes + M).digest()
        c3 = bits2int(ec, h3)
        assert 0 < c3 and c3 < ec.n, "sign fail"
        s3 = (k3 + c3*a3*q3) % ec.n

        ############################################
        # combine signatures into a single signature

        # anyone can do the following
        assert K1_All[0] == K2_All[0], "sign fail"
        assert K2_All[0] == K3_All[0], "sign fail"
        s_All = (s1 + s2 + s3) % ec.n
        ssasig = (K1_All[0], s_All)

        self.assertTrue(ecssa_verify(ssasig, M, Q_All, ec, sha256))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
