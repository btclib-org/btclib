#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import random
import unittest
from hashlib import sha256 as hf

from btclib.numbertheory import mod_inv, legendre_symbol
from btclib.ec import pointMult, DblScalarMult
from btclib.curves import secp256k1, secp224k1, low_card_curves
from btclib.utils import octets2int, octets2point, point2octets, bits2int
from btclib.pedersen import secondGenerator
from btclib.rfc6979 import rfc6979
from btclib.ssa import ecssa_sign, ecssa_verify, \
    _ecssa_e, _ecssa_verify, _ecssa_pubkey_recovery, ecssa_batch_verification

random.seed(42)

class TestEcssa(unittest.TestCase):

    def test_ecssa(self):
        """Basic tests"""
        ec = secp256k1
        q = 0x1
        Q = pointMult(ec, q, ec.G)
        msg = hf('Satoshi Nakamoto'.encode()).digest()
        sig = ecssa_sign(ec, hf, msg, q, None)
        # no source for the following... but
        # https://bitcointalk.org/index.php?topic=285142.40
        # same r because of rfc6979
        exp_sig = (0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8,
                   0x2DF2423F70563E3C4BD0E00BDEF658081613858F110ECF937A2ED9190BF4A01A)
        self.assertEqual(sig[0], exp_sig[0])
        self.assertEqual(sig[1], exp_sig[1])

        _ecssa_verify(ec, hf, msg, Q, sig)
        self.assertTrue(ecssa_verify(ec, hf, msg, Q, sig))
        self.assertTrue(_ecssa_verify(ec, hf, msg, Q, sig))

        fmsg = hf('Craig Wright'.encode()).digest()
        self.assertFalse(ecssa_verify(ec, hf, fmsg, Q, sig))
        self.assertFalse(_ecssa_verify(ec, hf, fmsg, Q, sig))

        fssasig = (sig[0], sig[1], sig[1])
        self.assertFalse(ecssa_verify(ec, hf, msg, Q, fssasig))
        self.assertRaises(TypeError, _ecssa_verify, ec, hf, msg, Q, fssasig)

        # y(sG - eP) is not a quadratic residue
        fq = 0x2
        fQ = pointMult(ec, fq, ec.G)
        self.assertFalse(ecssa_verify(ec, hf, msg, fQ, sig))
        self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, fQ, sig)

        fq = 0x4
        fQ = pointMult(ec, fq, ec.G)
        self.assertFalse(ecssa_verify(ec, hf, msg, fQ, sig))
        self.assertFalse(_ecssa_verify(ec, hf, msg, fQ, sig))

        # not ec.pIsThreeModFour
        self.assertFalse(ecssa_verify(secp224k1, hf, msg, Q, sig))
        self.assertRaises(ValueError, _ecssa_verify, secp224k1, hf, msg, Q, sig)

        # verify: message of wrong size
        wrongmsg = msg[:-1]
        self.assertFalse(ecssa_verify(ec, hf, wrongmsg, Q, sig))
        self.assertRaises(ValueError, _ecssa_verify, ec, hf, wrongmsg, Q, sig)
        #_ecssa_verify(ec, hf, wrongmsg, Q, sig)

        # sign: message of wrong size
        self.assertRaises(ValueError, ecssa_sign, ec, hf, wrongmsg, q, None)
        #ecssa_sign(ec, hf, wrongmsg, q, None)

        # invalid (zero) challenge e
        self.assertRaises(ValueError, _ecssa_pubkey_recovery, ec, hf, 0, sig)
        #_ecssa_pubkey_recovery(ec, hf, 0, sig)

    def test_schnorr_bip_tv(self):
        """Bip-Schnorr Test Vectors

        https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
        """
        ec = secp256k1
        # test vector 1
        prv = bits2int(ec, b'\x00' * 31 + b'\x01')
        pub = pointMult(ec, prv, ec.G)
        msg = b'\x00' * 32
        expected_sig = (0x787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6,
                        0x7031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05)
        eph_prv = int.from_bytes(hf(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")
        sig = ecssa_sign(ec, hf, msg, prv, eph_prv)
        self.assertTrue(_ecssa_verify(ec, hf, msg, pub, sig))
        self.assertEqual(sig, expected_sig)
        e = _ecssa_e(ec, hf, sig[0], pub, msg)
        self.assertEqual(_ecssa_pubkey_recovery(ec, hf, e, sig), pub)

        # test vector 2
        prv = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
        pub = pointMult(ec, prv, ec.G)
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        expected_sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
                        0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        eph_prv = int.from_bytes(hf(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")
        sig = ecssa_sign(ec, hf, msg, prv, eph_prv)
        self.assertTrue(_ecssa_verify(ec, hf, msg, pub, sig))
        self.assertEqual(sig, expected_sig)
        e = _ecssa_e(ec, hf, sig[0], pub, msg)
        self.assertEqual(_ecssa_pubkey_recovery(ec, hf, e, sig), pub)

        # test vector 3
        prv = 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7
        pub = pointMult(ec, prv, ec.G)
        msg = bytes.fromhex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
        expected_sig = (0x00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE,
                        0x00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380)
        eph_prv = int.from_bytes(hf(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")
        sig = ecssa_sign(ec, hf, msg, prv, eph_prv)
        self.assertTrue(_ecssa_verify(ec, hf, msg, pub, sig))
        self.assertEqual(sig, expected_sig)
        e = _ecssa_e(ec, hf, sig[0], pub, msg)
        self.assertEqual(_ecssa_pubkey_recovery(ec, hf, e, sig), pub)

        # test vector 4
        pub = octets2point(ec, "03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
        msg = bytes.fromhex("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
        sig = (0x00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63,
               0x02A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D)
        self.assertTrue(_ecssa_verify(ec, hf, msg, pub, sig))
        e = _ecssa_e(ec, hf, sig[0], pub, msg)
        self.assertEqual(_ecssa_pubkey_recovery(ec, hf, e, sig), pub)

        # test vector 5
        # test would fail if jacobi symbol of x(R) instead of y(R) is used
        pub = octets2point(ec, "031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F")
        msg = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        sig = (0x52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E35,
               0x30B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187)
        self.assertTrue(_ecssa_verify(ec, hf, msg, pub, sig))
        e = _ecssa_e(ec, hf, sig[0], pub, msg)
        self.assertEqual(_ecssa_pubkey_recovery(ec, hf, e, sig), pub)

        # test vector 6
        # test would fail if msg is reduced
        pub = octets2point(ec, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
        sig = (0x570DD4CA83D4E6317B8EE6BAE83467A1BF419D0767122DE409394414B05080DC,
               0xE9EE5F237CBD108EABAE1E37759AE47F8E4203DA3532EB28DB860F33D62D49BD)
        self.assertTrue(_ecssa_verify(ec, hf, msg, pub, sig))
        e = _ecssa_e(ec, hf, sig[0], pub, msg)
        self.assertEqual(_ecssa_pubkey_recovery(ec, hf, e, sig), pub)

        # new proposed test: test would fail if msg is reduced
        pub = octets2point(ec, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex("000008D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A5000000")
        sig = (0x3598678C6C661F02557E2F5614440B53156997936FE54A90961CFCC092EF789D,
               0x41E4E4386E54C924251679ADD3D837367EECBFF248A3DE7C2DB4CE52A3D6192A)
        self.assertTrue(_ecssa_verify(ec, hf, msg, pub, sig))
        e = _ecssa_e(ec, hf, sig[0], pub, msg)
        self.assertEqual(_ecssa_pubkey_recovery(ec, hf, e, sig), pub)

        # new proposed test: genuine failure
        pub = octets2point(ec, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        sig = (0x3598678C6C661F02557E2F5614440B53156997936FE54A90961CFCC092EF789D,
               0x41E4E4386E54C924251679ADD3D837367EECBFF248A3DE7C2DB4CE52A3D6192A)
        self.assertFalse(_ecssa_verify(ec, hf, msg, pub, sig))

        # new proposed test: P = infinite
        pub = 1, 0
        msg = bytes.fromhex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
        sig = (0x00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE,
               0x00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380)
        self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, pub, sig)

        # test vector 7
        # public key not on the curve
        # impossible to verify with btclib analytics as it at Point conversion
        self.assertRaises(ValueError, octets2point, ec, "03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
        # msg = bytes.fromhex("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
        # sig = (0x00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63, 0x02A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D)
        # self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, pub, sig)

        # test vector 8
        # Incorrect sig: incorrect R residuosity
        pub = octets2point(ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0xFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7)
        self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, pub, sig)

        # test vector 9
        # Incorrect sig: negated message hash
        pub = octets2point(ec, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
        sig = (0x00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE,
               0xD092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC)
        self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, pub, sig)

        # test vector 10
        # Incorrect sig: negated s value
        pub = octets2point(ec, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
        msg = b'\x00' * 32
        sig = (0x787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6,
               0x8FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C)
        self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, pub, sig)

        # test vector 11
        # Incorrect sig: negated public key
        pub = octets2point(ec, "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D, 0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, pub, sig)

        # test vector 12
        # sG - eP is infinite.
        # Test fails in single verification if jacobi(y(inf)) is defined as 1 and x(inf) as 0
        pub = octets2point(ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x0000000000000000000000000000000000000000000000000000000000000000,
               0x9E9D01AF988B5CEDCE47221BFA9B222721F3FA408915444A4B489021DB55775F)
        self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, pub, sig)

        # test vector 13
        # sG - eP is infinite.
        # Test fails in single verification if jacobi(y(inf)) is defined as 1 and x(inf) as 1"""
        pub = octets2point(ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x0000000000000000000000000000000000000000000000000000000000000001,
               0xD37DDF0254351836D84B1BD6A795FD5D523048F298C4214D187FE4892947F728)
        self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, pub, sig)

        # test vector 14
        # sig[0:32] is not an X coordinate on the curve
        pub = octets2point(ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        self.assertFalse(_ecssa_verify(ec, hf, msg, pub, sig))

        # test vector 15
        # sig[0:32] is equal to field size
        pub = octets2point(ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F,
               0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        #self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, pub, sig)
        self.assertFalse(_ecssa_verify(ec, hf, msg, pub, sig))

        # test vector 16
        # sig[32:64] is equal to curve order
        pub = octets2point(ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
        self.assertRaises(ValueError, _ecssa_verify, ec, hf, msg, pub, sig)

    def test_low_cardinality(self):
        """test all msg/key pairs of low cardinality elliptic curves"""

        # ec.n has to be prime to sign
        prime = [11,  13,  17,  19]

        # all possible hashed messages
        hsize = 32
        H = [i.to_bytes(hsize, 'big') for i in range(max(prime)*2)]

        # only low card curves or it would take forever
        for ec in low_card_curves:
            if ec._p in prime:  # only few curves or it would take too long
                # Schnorr-bip only applies to curve whose prime p = 3 %4
                if not ec.pIsThreeModFour:
                    self.assertRaises(ValueError, ecssa_sign, ec, hf, H[0], 1, None)
                    continue
                for q in range(ec.n):  # all possible private keys
                    if q == 0:  # invalid prvkey=0
                        self.assertRaises(ValueError, ecssa_sign, ec, hf, H[0], q, None)
                        self.assertRaises(ValueError, rfc6979, ec, hf, H[0], q)
                        continue
                    Q = pointMult(ec, q, ec.G)  # public key
                    for h in H:  # all possible hashed messages
                        # k = 0
                        self.assertRaises(ValueError, ecssa_sign, ec, hf, h, q, 0)
                        k = rfc6979(ec, hf, h, q)
                        K = pointMult(ec, k, ec.G)
                        if legendre_symbol(K[1], ec._p) != 1:
                            k = ec.n - k

                        e = _ecssa_e(ec, hf, K[0], Q, h)
                        s = (k + e * q) % ec.n
                        # valid signature
                        sig = ecssa_sign(ec, hf, h, q, k)
                        self.assertEqual((K[0], s), sig)
                        # valid signature must validate
                        self.assertTrue(_ecssa_verify(ec, hf, h, Q, sig))

    def test_batch_validation(self):
        ec = secp256k1
        m = []
        sig = []
        Q = []

        hsize =hf().digest_size
        hlen = hsize * 8
        for i in range(10):
            m.append(random.getrandbits(hlen).to_bytes(hsize, 'big'))
            q = random.getrandbits(ec.nlen) % ec.n
            sig.append(ecssa_sign(ec, hf, m[i], q))
            Q.append(pointMult(ec, q, ec.G))
        self.assertTrue(ecssa_batch_verification(ec, hf, m, Q, sig))

        m.append(m[0])
        sig.append(sig[1])  # invalid
        Q.append(Q[0])
        self.assertFalse(ecssa_batch_verification(ec, hf, m, Q, sig))

        sig[-1] = sig[0]  # valid
        m[-1] = m[0][:-1]  # invalid 31 bytes message
        self.assertFalse(ecssa_batch_verification(ec, hf, m, Q, sig))

    def test_threshold(self):
        """testing 2-of-3 threshold signature (Pedersen secret sharing)"""

        ec = secp256k1
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

        ssa = (K[0], sigma)

        self.assertTrue(_ecssa_verify(ec, hf, msg, Q, ssa))

        ### ADDITIONAL PHASE: reconstruction of the private key ###
        secret = (omega1 * alpha1 + omega3 * alpha3) % ec.n
        self.assertEqual((q1 + q2 + q3) % ec.n, secret)

    def test_musig(self):
        """ testing 3-of-3 MuSig
        
            https://eprint.iacr.org/2018/068
            https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html
            https://medium.com/@snigirev.stepan/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
        """
        ec = secp256k1
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
