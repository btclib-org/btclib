#!/usr/bin/env python3
"""First attempt at multisig using Schnorr Signature Algoritm

To be improved and refactored

Resources:
https://eprint.iacr.org/2018/068
https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html
https://medium.com/@snigirev.stepan/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
"""

import unittest
from btclib.ellipticcurves import int_from_Scalar, bytes_from_Point, pointAdd, pointMultiplyJacobian
from btclib.ecssa import sha256, ec, int_from_hash, ecssa_verify
import os

class TestEcssaMuSig(unittest.TestCase):

    def test_ecssamusig(self):
        L = list() # multiset of public keys
        msg = 'message to sign'
        m = sha256(msg.encode()).digest()

        # first signer (is the message needed here? maybe for rfc6979?)
        q1 = int_from_Scalar(ec, '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d92ad1d')
        Q1 = pointMultiplyJacobian(ec, q1, ec.G)
        L.append(bytes_from_Point(ec, Q1, False))

        k1 = 0x012a2a833eac4e67e06611aba01345b85cdd4f5ad44f72e369ef0dd640424dbb # ephemeral private nonce
        K1 = pointMultiplyJacobian(ec, k1, ec.G)
        K1_x = K1[0]
        # break the simmetry: any criteria could be used, jacobi is standard
        if ec.jacobi(K1[1]) != 1:
            k1 = ec.n - k1
            K1 = K1_x, ec.yQuadraticResidue(K1_x, True)
            #K1 = pointMultiplyJacobian(ec, k1, ec.G)

        # second signer (is the message needed here? maybe for rfc6979?)
        q2 = int_from_Scalar(ec, '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d')
        Q2 = pointMultiplyJacobian(ec, q2, ec.G)
        L.append(bytes_from_Point(ec, Q2, False))

        k2 = 0x01a2a0d3eac4e67e06611aba01345b85cdd4f5ad44f72e369ef0dd640424dbdb
        K2 = pointMultiplyJacobian(ec, k2, ec.G)
        K2_x = K2[0]
        # break the simmetry: any criteria could be used, jacobi is standard
        if ec.jacobi(K2[1]) != 1:
            k2 = ec.n - k2
            K2 = K2_x, ec.yQuadraticResidue(K2_x, True)
            #K2 = pointMultiplyJacobian(ec, k2, ec.G)

        # third signer
        q3 = int.from_bytes(os.urandom(ec.bytesize), 'big')
        Q3 = pointMultiplyJacobian(ec, q3, ec.G)
        while Q3 == None:
            q3 = int.from_bytes(os.urandom(ec.bytesize), 'big')
            Q3 = pointMultiplyJacobian(ec, q3, ec.G)
        L.append(bytes_from_Point(ec, Q3, False))

        k3 = int.from_bytes(os.urandom(ec.bytesize), 'big')
        K3 = pointMultiplyJacobian(ec, k3, ec.G)
        while K3 == None:
            k3 = int.from_bytes(os.urandom(ec.bytesize), 'big')
            K3 = pointMultiplyJacobian(ec, k3, ec.G)
        K3_x = K3[0]
        if ec.jacobi(K3[1]) != 1:
            k3 = ec.n - k3
            K3 = K3_x, ec.yQuadraticResidue(K3_x, True)
            #K3 = pointMultiplyJacobian(ec, k3, ec.G)

        L.sort() # using lexicographic ordering
        L_brackets = b''
        for i in range(0, len(L)):
            L_brackets += L[i]

        a1 = int_from_hash(sha256(L_brackets + bytes_from_Point(ec, Q1, False)).digest(), ec.n)
        a2 = int_from_hash(sha256(L_brackets + bytes_from_Point(ec, Q2, False)).digest(), ec.n)
        a3 = int_from_hash(sha256(L_brackets + bytes_from_Point(ec, Q3, False)).digest(), ec.n)
        # aggregated public key
        Q_All = pointAdd(ec, pointAdd(ec, pointMultiplyJacobian(ec, a1, Q1), pointMultiplyJacobian(ec, \
                                                            a2, Q2)), pointMultiplyJacobian(ec, a3, Q3))

        ########################
        # exchange K_x, compute s
        # WARNING: the signers should exchange commitments to the public nonces
        #          before sending the nonces themselves

        # first signer use K2_x and K3_x
        # break the simmetry: any criteria could be used, jacobi is standard
        y = ec.yQuadraticResidue(K2_x, True)
        K2_recovered = (K2_x, y)
        y = ec.yQuadraticResidue(K3_x, True)
        K3_recovered = (K3_x, y)
        K1_All = pointAdd(ec, pointAdd(ec, K1, K2_recovered), K3_recovered)
        # break the simmetry: any criteria could be used, jacobi is standard
        if ec.jacobi(K1_All[1]) != 1:
            # no need to actually change K1_All[1], as it is not used anymore
            # let's fix k1 instead, as it is used later
            k1 = ec.n - k1
        c1 = int_from_hash(sha256(K1_All[0].to_bytes(32, byteorder="big") + bytes_from_Point(ec, Q_All, True) + m).digest(), ec.n)
        assert c1 != 0 and c1 < ec.n, "sign fail"
        s1 = (k1 + c1*a1*q1) % ec.n

        # second signer use K1_x and K3_x
        # break the simmetry: any criteria could be used, jacobi is standard
        y = ec.yQuadraticResidue(K1_x, True)
        K1_recovered = (K1_x, y)
        y = ec.yQuadraticResidue(K3_x, True)
        K3_recovered = (K3_x, y)
        K2_All = pointAdd(ec, pointAdd(ec, K2, K1_recovered), K3_recovered)
        # break the simmetry: any criteria could be used, jacobi is standard
        if ec.jacobi(K2_All[1]) != 1:
            # no need to actually change K2_All[1], as it is not used anymore
            # let's fix k2 instead, as it is used later
            k2 = ec.n - k2
        c2 = int_from_hash(sha256(K2_All[0].to_bytes(32, byteorder="big") + bytes_from_Point(ec, Q_All, True) + m).digest(), ec.n)
        assert c2 != 0 and c2 < ec.n, "sign fail"
        s2 = (k2 + c2*a2*q2) % ec.n

        # third signer use K1_x and K2_x
        # break the simmetry: any criteria could be used, jacobi is standard
        y = ec.yQuadraticResidue(K1_x, True)
        K1_recovered = (K1_x, y)
        y = ec.yQuadraticResidue(K2_x, True)
        K2_recovered = (K2_x, y)
        K3_All = pointAdd(ec, pointAdd(ec, K1_recovered, K2_recovered), K3)
        # break the simmetry: any criteria could be used, jacobi is standard
        if ec.jacobi(K3_All[1]) != 1:
            # no need to actually change K3_All[1], as it is not used anymore
            # let's fix k3 instead, as it is used later
            k3 = ec.n - k3
        c3 = int_from_hash(sha256(K3_All[0].to_bytes(32, byteorder="big") + bytes_from_Point(ec, Q_All, True) + m).digest(), ec.n)
        assert c3 != 0 and c3 < ec.n, "sign fail"
        s3 = (k3 + c3*a3*q3) % ec.n

        ############################################
        # combine signatures into a single signature

        # anyone can do the following
        assert K1_All[0] == K2_All[0], "sign fail"
        assert K2_All[0] == K3_All[0], "sign fail"
        s_All = (s1 + s2 + s3) % ec.n
        ssasig = (K1_All[0], s_All)

        self.assertTrue(ecssa_verify(msg, ssasig, Q_All, sha256))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
