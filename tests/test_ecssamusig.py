#!/usr/bin/env python3
"""First attempt at multisig using Schnorr Signature Algoritm

To be improved and refactored

Resources:
https://eprint.iacr.org/2018/068
https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html
https://medium.com/@snigirev.stepan/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
"""

import unittest
from btclib.ellipticcurves import int_from_Scalar, bytes_from_Point
from btclib.ecssa import sha256, int_from_hash, ecssa_verify
from btclib.ellipticcurves import secp256k1 as ec

class TestEcssaMuSig(unittest.TestCase):

    def test_ecssamusig(self):
        msg = 'message to sign'
        m = sha256(msg.encode()).digest()

        # first signer (is the message needed here? maybe for rfc6979?)
        prv1 = int_from_Scalar(ec, '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d92ad1d')
        Q1 = ec.pointMultiply(prv1, ec.G)
        HQ1 = int_from_hash(sha256(bytes_from_Point(ec, Q1, False)).digest(), ec.n)
        prv1 = HQ1* prv1

        eph_prv1 = 0x012a2a833eac4e67e06611aba01345b85cdd4f5ad44f72e369ef0dd640424dbb
        R1 = ec.pointMultiply(eph_prv1, ec.G)
        R1_x = R1[0]
        # break the simmetry: any criteria could be used, jacobi is standard
        if ec.jacobi(R1[1]) != 1:
            eph_prv1 = ec.n - eph_prv1
            R1 = R1_x, ec.yQuadraticResidue(R1_x, True)
            #R1 = ec.pointMultiply(eph_prv1, ec.G)

        # second signer (is the message needed here? maybe for rfc6979?)
        prv2 = int_from_Scalar(ec, '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d')
        Q2 = ec.pointMultiply(prv2, ec.G)
        HQ2 = int_from_hash(sha256(bytes_from_Point(ec, Q2, False)).digest(), ec.n)
        prv2 = HQ2* prv2

        eph_prv2 = 0x01a2a0d3eac4e67e06611aba01345b85cdd4f5ad44f72e369ef0dd640424dbdb
        R2 = ec.pointMultiply(eph_prv2, ec.G)
        R2_x = R2[0]
        # break the simmetry: any criteria could be used, jacobi is standard
        if ec.jacobi(R2[1]) != 1:
            eph_prv2 = ec.n - eph_prv2
            R2 = R2_x, ec.yQuadraticResidue(R2_x, True)
            #R2 = ec.pointMultiply(eph_prv2, ec.G)

        Q_All = ec.pointAdd(ec.pointMultiply(HQ1, Q1), ec.pointMultiply(HQ2, Q2))  # joint public key

        ########################
        # exchange Rx, compute s

        # first signer use R2_x
        # break the simmetry: any criteria could be used, jacobi is standard
        y = ec.yQuadraticResidue(R2_x, True)
        R2_recovered = (R2_x, y)
        R1_All = ec.pointAdd(R1, R2_recovered)
        # break the simmetry: any criteria could be used, jacobi is standard
        if ec.jacobi(R1_All[1]) != 1:
            # no need to actually change R1_All[1], as it is not used anymore
            # let's fix eph_prv1 instead, as it is used later
            eph_prv1 = ec.n - eph_prv1
        e1 = int_from_hash(sha256(R1_All[0].to_bytes(32, byteorder="big") + bytes_from_Point(ec, Q_All, True) + m).digest(), ec.n)
        assert e1 != 0 and e1 < ec.n, "sign fail"
        s1 = (eph_prv1 + e1 * prv1) % ec.n

        # second signer use R1_x
        # break the simmetry: any criteria could be used, jacobi is standard
        y = ec.yQuadraticResidue(R1_x, True)
        R1_recovered = (R1_x, y)
        R2_All = ec.pointAdd(R2, R1_recovered)
        # break the simmetry: any criteria could be used, jacobi is standard
        if ec.jacobi(R2_All[1]) != 1:
            # no need to actually change R2_All[1], as it is not used anymore
            # let's fix eph_prv2 instead, as it is used later
            eph_prv2 = ec.n - eph_prv2
        e2 = int_from_hash(sha256(R2_All[0].to_bytes(32, byteorder="big") + bytes_from_Point(ec, Q_All, True) + m).digest(), ec.n)
        assert e2 != 0 and e2 < ec.n, "sign fail"
        s2 = (eph_prv2 + e2 * prv2) % ec.n

        ############################################
        # combine signatures into a single signature

        # anyone can do the following
        assert R1_All[0] == R2_All[0], "sign fail"
        s_All = (s1 + s2) % ec.n
        ssasig = (R1_All[0], s_All)

        self.assertTrue(ecssa_verify(ec, msg, ssasig, Q_All, sha256))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
