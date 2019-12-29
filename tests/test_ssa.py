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
from typing import List

from btclib.numbertheory import mod_inv, legendre_symbol
from btclib.curve import Point, mult, double_mult
from btclib.curves import secp256k1, secp224k1, low_card_curves
from btclib.utils import int_from_octets, point_from_octets, octets_from_point, int_from_bits
from btclib.pedersen import second_generator
from btclib.rfc6979 import rfc6979
from btclib import ssa

random.seed(42)


class TestEcssa(unittest.TestCase):

    def test_ecssa(self):
        """Basic tests"""
        ec = secp256k1
        q = 0x1
        Q = mult(ec, q)
        msg = hf(b'Satoshi Nakamoto').digest()
        sig = ssa.sign(ec, hf, msg, q, None)
        # no source for the following... but
        # https://bitcointalk.org/index.php?topic=285142.40
        # same r because of rfc6979
        exp_sig = (0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8,
                   0x2DF2423F70563E3C4BD0E00BDEF658081613858F110ECF937A2ED9190BF4A01A)
        self.assertEqual(sig[0], exp_sig[0])
        self.assertEqual(sig[1], exp_sig[1])

        ssa._verify(ec, hf, msg, Q, sig)
        self.assertTrue(ssa.verify(ec, hf, msg, Q, sig))
        self.assertTrue(ssa._verify(ec, hf, msg, Q, sig))

        fmsg = hf(b'Craig Wright').digest()
        self.assertFalse(ssa.verify(ec, hf, fmsg, Q, sig))
        self.assertFalse(ssa._verify(ec, hf, fmsg, Q, sig))

        fssasig = (sig[0], sig[1], sig[1])
        self.assertFalse(ssa.verify(ec, hf, msg, Q, fssasig))
        self.assertRaises(TypeError, ssa._verify, ec, hf, msg, Q, fssasig)

        # y(sG - eP) is not a quadratic residue
        fq = 0x2
        fQ = mult(ec, fq)
        self.assertFalse(ssa.verify(ec, hf, msg, fQ, sig))
        self.assertRaises(ValueError, ssa._verify, ec, hf, msg, fQ, sig)

        fq = 0x4
        fQ = mult(ec, fq)
        self.assertFalse(ssa.verify(ec, hf, msg, fQ, sig))
        self.assertFalse(ssa._verify(ec, hf, msg, fQ, sig))

        # not ec.pIsThreeModFour
        self.assertFalse(ssa.verify(secp224k1, hf, msg, Q, sig))
        self.assertRaises(ValueError, ssa._verify, secp224k1, hf, msg, Q, sig)

        # verify: message of wrong size
        wrongmsg = msg[:-1]
        self.assertFalse(ssa.verify(ec, hf, wrongmsg, Q, sig))
        self.assertRaises(ValueError, ssa._verify, ec, hf, wrongmsg, Q, sig)
        #ssa._verify(ec, hf, wrongmsg, Q, sig)

        # sign: message of wrong size
        self.assertRaises(ValueError, ssa.sign, ec, hf, wrongmsg, q, None)
        #ssa.sign(ec, hf, wrongmsg, q, None)

        # invalid (zero) challenge e
        self.assertRaises(ValueError, ssa._pubkey_recovery, ec, hf, 0, sig)
        #ssa._pubkey_recovery(ec, hf, 0, sig)

    def test_schnorr_bip_tv(self):
        """Bip-Schnorr Test Vectors

        https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
        """
        ec = secp256k1
        # test vector 1
        prv = int_from_bits(ec, b'\x00' * 31 + b'\x01')
        pub = mult(ec, prv)
        msg = b'\x00' * 32
        expected_sig = (0x787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6,
                        0x7031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05)
        eph_prv = int.from_bytes(
            hf(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")
        sig = ssa.sign(ec, hf, msg, prv, eph_prv)
        self.assertTrue(ssa._verify(ec, hf, msg, pub, sig))
        self.assertEqual(sig, expected_sig)
        e = ssa._e(ec, hf, sig[0], pub, msg)
        self.assertEqual(ssa._pubkey_recovery(ec, hf, e, sig), pub)

        # test vector 2
        prv = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
        pub = mult(ec, prv)
        msg = bytes.fromhex(
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        expected_sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
                        0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        eph_prv = int.from_bytes(
            hf(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")
        sig = ssa.sign(ec, hf, msg, prv, eph_prv)
        self.assertTrue(ssa._verify(ec, hf, msg, pub, sig))
        self.assertEqual(sig, expected_sig)
        e = ssa._e(ec, hf, sig[0], pub, msg)
        self.assertEqual(ssa._pubkey_recovery(ec, hf, e, sig), pub)

        # test vector 3
        prv = 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7
        pub = mult(ec, prv)
        msg = bytes.fromhex(
            "5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
        expected_sig = (0x00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE,
                        0x00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380)
        eph_prv = int.from_bytes(
            hf(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")
        sig = ssa.sign(ec, hf, msg, prv, eph_prv)
        self.assertTrue(ssa._verify(ec, hf, msg, pub, sig))
        self.assertEqual(sig, expected_sig)
        e = ssa._e(ec, hf, sig[0], pub, msg)
        self.assertEqual(ssa._pubkey_recovery(ec, hf, e, sig), pub)

        # test vector 4
        pub = point_from_octets(
            ec, "03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
        msg = bytes.fromhex(
            "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
        sig = (0x00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63,
               0x02A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D)
        self.assertTrue(ssa._verify(ec, hf, msg, pub, sig))
        e = ssa._e(ec, hf, sig[0], pub, msg)
        self.assertEqual(ssa._pubkey_recovery(ec, hf, e, sig), pub)

        # test vector 5
        # test would fail if jacobi symbol of x(R) instead of y(R) is used
        pub = point_from_octets(
            ec, "031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F")
        msg = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000")
        sig = (0x52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E35,
               0x30B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187)
        self.assertTrue(ssa._verify(ec, hf, msg, pub, sig))
        e = ssa._e(ec, hf, sig[0], pub, msg)
        self.assertEqual(ssa._pubkey_recovery(ec, hf, e, sig), pub)

        # test vector 6
        # test would fail if msg is reduced
        pub = point_from_octets(
            ec, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
        sig = (0x570DD4CA83D4E6317B8EE6BAE83467A1BF419D0767122DE409394414B05080DC,
               0xE9EE5F237CBD108EABAE1E37759AE47F8E4203DA3532EB28DB860F33D62D49BD)
        self.assertTrue(ssa._verify(ec, hf, msg, pub, sig))
        e = ssa._e(ec, hf, sig[0], pub, msg)
        self.assertEqual(ssa._pubkey_recovery(ec, hf, e, sig), pub)

        # new proposed test: test would fail if msg is reduced
        pub = point_from_octets(
            ec, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex(
            "000008D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A5000000")
        sig = (0x3598678C6C661F02557E2F5614440B53156997936FE54A90961CFCC092EF789D,
               0x41E4E4386E54C924251679ADD3D837367EECBFF248A3DE7C2DB4CE52A3D6192A)
        self.assertTrue(ssa._verify(ec, hf, msg, pub, sig))
        e = ssa._e(ec, hf, sig[0], pub, msg)
        self.assertEqual(ssa._pubkey_recovery(ec, hf, e, sig), pub)

        # new proposed test: genuine failure
        pub = point_from_octets(
            ec, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000")
        sig = (0x3598678C6C661F02557E2F5614440B53156997936FE54A90961CFCC092EF789D,
               0x41E4E4386E54C924251679ADD3D837367EECBFF248A3DE7C2DB4CE52A3D6192A)
        self.assertFalse(ssa._verify(ec, hf, msg, pub, sig))

        # new proposed test: P = infinite
        pub = 1, 0
        msg = bytes.fromhex(
            "5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
        sig = (0x00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE,
               0x00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380)
        self.assertRaises(ValueError, ssa._verify, ec, hf, msg, pub, sig)

        # test vector 7
        # public key not on the curve
        # impossible to verify with btclib analytics as it at Point conversion
        self.assertRaises(ValueError, point_from_octets, ec,
                          "03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
        # msg = bytes.fromhex("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
        # sig = (0x00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63, 0x02A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D)
        # self.assertRaises(ValueError, ssa._verify, ec, hf, msg, pub, sig)

        # test vector 8
        # Incorrect sig: incorrect R residuosity
        pub = point_from_octets(
            ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex(
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0xFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7)
        self.assertRaises(ValueError, ssa._verify, ec, hf, msg, pub, sig)

        # test vector 9
        # Incorrect sig: negated message hash
        pub = point_from_octets(
            ec, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex(
            "5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
        sig = (0x00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE,
               0xD092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC)
        self.assertRaises(ValueError, ssa._verify, ec, hf, msg, pub, sig)

        # test vector 10
        # Incorrect sig: negated s value
        pub = point_from_octets(
            ec, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
        msg = b'\x00' * 32
        sig = (0x787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6,
               0x8FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C)
        self.assertRaises(ValueError, ssa._verify, ec, hf, msg, pub, sig)

        # test vector 11
        # Incorrect sig: negated public key
        pub = point_from_octets(
            ec, "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex(
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        self.assertRaises(ValueError, ssa._verify, ec, hf, msg, pub, sig)

        # test vector 12
        # sG - eP is infinite.
        # Test fails in single verification if jacobi(y(inf)) is defined as 1 and x(inf) as 0
        pub = point_from_octets(
            ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex(
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x0000000000000000000000000000000000000000000000000000000000000000,
               0x9E9D01AF988B5CEDCE47221BFA9B222721F3FA408915444A4B489021DB55775F)
        self.assertRaises(ValueError, ssa._verify, ec, hf, msg, pub, sig)

        # test vector 13
        # sG - eP is infinite.
        # Test fails in single verification if jacobi(y(inf)) is defined as 1 and x(inf) as 1"""
        pub = point_from_octets(
            ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex(
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x0000000000000000000000000000000000000000000000000000000000000001,
               0xD37DDF0254351836D84B1BD6A795FD5D523048F298C4214D187FE4892947F728)
        self.assertRaises(ValueError, ssa._verify, ec, hf, msg, pub, sig)

        # test vector 14
        # sig[0:32] is not an X coordinate on the curve
        pub = point_from_octets(
            ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex(
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        self.assertFalse(ssa._verify(ec, hf, msg, pub, sig))

        # test vector 15
        # sig[0:32] is equal to field size
        pub = point_from_octets(
            ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex(
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F,
               0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        #self.assertRaises(ValueError, ssa._verify, ec, hf, msg, pub, sig)
        self.assertFalse(ssa._verify(ec, hf, msg, pub, sig))

        # test vector 16
        # sig[32:64] is equal to curve order
        pub = point_from_octets(
            ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex(
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
        self.assertRaises(ValueError, ssa._verify, ec, hf, msg, pub, sig)

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
                    self.assertRaises(ValueError, ssa.sign,
                                      ec, hf, H[0], 1, None)
                    continue
                for q in range(ec.n):  # all possible private keys
                    if q == 0:  # invalid prvkey=0
                        self.assertRaises(ValueError, ssa.sign,
                                          ec, hf, H[0], q, None)
                        self.assertRaises(ValueError, rfc6979, ec, hf, H[0], q)
                        continue
                    Q = mult(ec, q)  # public key
                    for h in H:  # all possible hashed messages
                        # k = 0
                        self.assertRaises(
                            ValueError, ssa.sign, ec, hf, h, q, 0)
                        k = rfc6979(ec, hf, h, q)
                        K = mult(ec, k)
                        if legendre_symbol(K[1], ec._p) != 1:
                            k = ec.n - k

                        e = ssa._e(ec, hf, K[0], Q, h)
                        s = (k + e * q) % ec.n
                        # valid signature
                        sig = ssa.sign(ec, hf, h, q, k)
                        self.assertEqual((K[0], s), sig)
                        # valid signature must validate
                        self.assertTrue(ssa._verify(ec, hf, h, Q, sig))

    def test_batch_validation(self):
        ec = secp256k1
        m = []
        sig = []
        Q = []

        hsize = hf().digest_size
        hlen = hsize * 8
        m.append(random.getrandbits(hlen).to_bytes(hsize, 'big'))
        q = (1+random.getrandbits(ec.nlen)) % ec.n
        sig.append(ssa.sign(ec, hf, m[0], q))
        Q.append(mult(ec, q))
        # test with only 1 sig
        self.assertTrue(ssa.batch_verify(ec, hf, m, Q, sig))
        for i in range(1, 4):
            m.append(random.getrandbits(hlen).to_bytes(hsize, 'big'))
            q = (1+random.getrandbits(ec.nlen)) % ec.n
            sig.append(ssa.sign(ec, hf, m[i], q))
            Q.append(mult(ec, q))
        self.assertTrue(ssa.batch_verify(ec, hf, m, Q, sig))

        # invalid sig
        m.append(m[0])
        sig.append(sig[1])
        Q.append(Q[0])
        self.assertFalse(ssa.batch_verify(ec, hf, m, Q, sig))
        #ssa._batch_verify(ec, hf, m, Q, sig)
        sig[-1] = sig[0]  # valid again

        # invalid 31 bytes message
        m[-1] = m[0][:-1]
        self.assertFalse(ssa.batch_verify(ec, hf, m, Q, sig))
        #ssa._batch_verify(ec, hf, m, Q, sig)
        m[-1] = m[0]  # valid again

        # mismatch between number of pubkeys and number of messages
        m.append(m[0])  # add extra message
        self.assertRaises(ValueError, ssa._batch_verify, ec, hf, m, Q, sig)
        #ssa._batch_verify(ec, hf, m, Q, sig)
        m.pop()  # valid again

        # mismatch between number of pubkeys and number of signatures
        sig.append(sig[0])  # add extra sig
        self.assertRaises(ValueError, ssa._batch_verify, ec, hf, m, Q, sig)
        #ssa._batch_verify(ec, hf, m, Q, sig)
        sig.pop()  # valid again

        # curve prime p must be equal to 3 (mod 4)
        ec = secp224k1
        self.assertRaises(ValueError, ssa._batch_verify, ec, hf, m, Q, sig)
        #ssa._batch_verify(ec, hf, m, Q, sig)

    def test_threshold(self):
        """testing 2-of-3 threshold signature (Pedersen secret sharing)"""

        ec = secp256k1
        # parameters
        t = 2
        H = second_generator(ec, hf)
        msg = hf(b'message to sign').digest()

        ### FIRST PHASE: key pair generation ###

        # signer one acting as the dealer
        commits1: List[Point] = list()
        q1 = (1+random.getrandbits(ec.nlen)) % ec.n
        q1_prime = (1+random.getrandbits(ec.nlen)) % ec.n
        commits1.append(double_mult(ec, q1_prime, H, q1))

        # sharing polynomials
        f1: List[int] = list()
        f1.append(q1)
        f1_prime: List[int] = list()
        f1_prime.append(q1_prime)
        for i in range(1, t):
            temp = (1+random.getrandbits(ec.nlen)) % ec.n
            f1.append(temp)
            temp = (1+random.getrandbits(ec.nlen)) % ec.n
            f1_prime.append(temp)
            commits1.append(double_mult(ec, f1_prime[i], H, f1[i]))

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
            RHS = ec.add(RHS, mult(ec, pow(2, i), commits1[i]))
        assert double_mult(ec, alpha12_prime, H,
                           alpha12) == RHS, 'player one is cheating'

        # player three verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, mult(ec, pow(3, i), commits1[i]))
        assert double_mult(ec, alpha13_prime, H,
                           alpha13) == RHS, 'player one is cheating'

        # signer two acting as the dealer
        commits2: List[Point] = list()
        q2 = (1+random.getrandbits(ec.nlen)) % ec.n
        q2_prime = (1+random.getrandbits(ec.nlen)) % ec.n
        commits2.append(double_mult(ec, q2_prime, H, q2))

        # sharing polynomials
        f2: List[int] = list()
        f2.append(q2)
        f2_prime: List[int] = list()
        f2_prime.append(q2_prime)
        for i in range(1, t):
            temp = (1+random.getrandbits(ec.nlen)) % ec.n
            f2.append(temp)
            temp = (1+random.getrandbits(ec.nlen)) % ec.n
            f2_prime.append(temp)
            commits2.append(double_mult(ec, f2_prime[i], H, f2[i]))

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
            RHS = ec.add(RHS, mult(ec, pow(1, i), commits2[i]))
        assert double_mult(ec, alpha21_prime, H,
                           alpha21) == RHS, 'player two is cheating'

        # player three verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, mult(ec, pow(3, i), commits2[i]))
        assert double_mult(ec, alpha23_prime, H,
                           alpha23) == RHS, 'player two is cheating'

        # signer three acting as the dealer
        commits3: List[Point] = list()
        q3 = (1+random.getrandbits(ec.nlen)) % ec.n
        q3_prime = (1+random.getrandbits(ec.nlen)) % ec.n
        commits3.append(double_mult(ec, q3_prime, H, q3))

        # sharing polynomials
        f3: List[int] = list()
        f3.append(q3)
        f3_prime: List[int] = list()
        f3_prime.append(q3_prime)
        for i in range(1, t):
            temp = (1+random.getrandbits(ec.nlen)) % ec.n
            f3.append(temp)
            temp = (1+random.getrandbits(ec.nlen)) % ec.n
            f3_prime.append(temp)
            commits3.append(double_mult(ec, f3_prime[i], H, f3[i]))

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
            RHS = ec.add(RHS, mult(ec, pow(1, i), commits3[i]))
        assert double_mult(ec, alpha31_prime, H,
                           alpha31) == RHS, 'player three is cheating'

        # player two verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, mult(ec, pow(2, i), commits3[i]))
        assert double_mult(ec, alpha32_prime, H,
                           alpha32) == RHS, 'player two is cheating'

        # shares of the secret key q = q1 + q2 + q3
        alpha1 = (alpha21 + alpha31) % ec.n
        alpha2 = (alpha12 + alpha32) % ec.n
        alpha3 = (alpha13 + alpha23) % ec.n
        for i in range(t):
            alpha1 += (f1[i] * pow(1, i)) % ec.n
            alpha2 += (f2[i] * pow(2, i)) % ec.n
            alpha3 += (f3[i] * pow(3, i)) % ec.n

        # it's time to recover the public key Q = Q1 + Q2 + Q3 = (q1 + q2 + q3)G
        A1: List[Point] = list()
        A2: List[Point] = list()
        A3: List[Point] = list()

        # each participant i = 1, 2, 3 shares Qi as follows

        # he broadcasts these values
        for i in range(t):
            A1.append(mult(ec, f1[i]))
            A2.append(mult(ec, f2[i]))
            A3.append(mult(ec, f3[i]))

        # he checks the others' values
        # player one
        RHS2 = 1, 0
        RHS3 = 1, 0
        for i in range(t):
            RHS2 = ec.add(RHS2, mult(ec, pow(1, i), A2[i]))
            RHS3 = ec.add(RHS3, mult(ec, pow(1, i), A3[i]))
        assert mult(ec, alpha21) == RHS2, 'player two is cheating'
        assert mult(ec, alpha31) == RHS3, 'player three is cheating'

        # player two
        RHS1 = 1, 0
        RHS3 = 1, 0
        for i in range(t):
            RHS1 = ec.add(RHS1, mult(ec, pow(2, i), A1[i]))
            RHS3 = ec.add(RHS3, mult(ec, pow(2, i), A3[i]))
        assert mult(ec, alpha12) == RHS1, 'player one is cheating'
        assert mult(ec, alpha32) == RHS3, 'player three is cheating'

        # player three
        RHS1 = 1, 0
        RHS2 = 1, 0
        for i in range(t):
            RHS1 = ec.add(RHS1, mult(ec, pow(3, i), A1[i]))
            RHS2 = ec.add(RHS2, mult(ec, pow(3, i), A2[i]))
        assert mult(ec, alpha13) == RHS1, 'player one is cheating'
        assert mult(ec, alpha23) == RHS2, 'player two is cheating'

        A: List[Point] = list()  # commitment at the global sharing polynomial
        for i in range(t):
            A.append(ec.add(A1[i], ec.add(A2[i], A3[i])))

        Q = A[0]  # aggregated public key

        ### SECOND PHASE: generation of the nonces' pair ###
        # This phase follows exactly the key generation procedure
        # suppose that player one and three want to sign

        # signer one acting as the dealer
        commits1: List[Point] = list()
        k1 = (1+random.getrandbits(ec.nlen)) % ec.n
        k1_prime = (1+random.getrandbits(ec.nlen)) % ec.n
        commits1.append(double_mult(ec, k1_prime, H, k1))

        # sharing polynomials
        f1: List[int] = list()
        f1.append(k1)
        f1_prime: List[int] = list()
        f1_prime.append(k1_prime)
        for i in range(1, t):
            temp = (1+random.getrandbits(ec.nlen)) % ec.n
            f1.append(temp)
            temp = (1+random.getrandbits(ec.nlen)) % ec.n
            f1_prime.append(temp)
            commits1.append(double_mult(ec, f1_prime[i], H, f1[i]))

        # shares of the secret
        beta13 = 0  # share of k1 belonging to P3
        beta13_prime = 0
        for i in range(t):
            beta13 += (f1[i] * pow(3, i)) % ec.n
            beta13_prime += (f1_prime[i] * pow(3, i)) % ec.n

        # player three verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, mult(ec, pow(3, i), commits1[i]))
        assert double_mult(ec, beta13_prime, H,
                           beta13) == RHS, 'player one is cheating'

        # signer three acting as the dealer
        commits3: List[Point] = list()
        k3 = (1+random.getrandbits(ec.nlen)) % ec.n
        k3_prime = (1+random.getrandbits(ec.nlen)) % ec.n
        commits3.append(double_mult(ec, k3_prime, H, k3))

        # sharing polynomials
        f3: List[int] = list()
        f3.append(k3)
        f3_prime: List[int] = list()
        f3_prime.append(k3_prime)
        for i in range(1, t):
            temp = (1+random.getrandbits(ec.nlen)) % ec.n
            f3.append(temp)
            temp = (1+random.getrandbits(ec.nlen)) % ec.n
            f3_prime.append(temp)
            commits3.append(double_mult(ec, f3_prime[i], H, f3[i]))

        # shares of the secret
        beta31 = 0  # share of k3 belonging to P1
        beta31_prime = 0
        for i in range(t):
            beta31 += (f3[i] * pow(1, i)) % ec.n
            beta31_prime += (f3_prime[i] * pow(1, i)) % ec.n

        # player one verifies consistency of his share
        RHS = 1, 0
        for i in range(t):
            RHS = ec.add(RHS, mult(ec, pow(1, i), commits3[i]))
        assert double_mult(ec, beta31_prime, H,
                           beta31) == RHS, 'player three is cheating'

        # shares of the secret nonce
        beta1 = beta31 % ec.n
        beta3 = beta13 % ec.n
        for i in range(t):
            beta1 += (f1[i] * pow(1, i)) % ec.n
            beta3 += (f3[i] * pow(3, i)) % ec.n

        # it's time to recover the public nonce
        B1: List[Point] = list()
        B3: List[Point] = list()

        # each participant i = 1, 3 shares Qi as follows

        # he broadcasts these values
        for i in range(t):
            B1.append(mult(ec, f1[i]))
            B3.append(mult(ec, f3[i]))

        # he checks the others' values
        # player one
        RHS3 = 1, 0
        for i in range(t):
            RHS3 = ec.add(RHS3, mult(ec, pow(1, i), B3[i]))
        assert mult(ec, beta31) == RHS3, 'player three is cheating'

        # player three
        RHS1 = 1, 0
        for i in range(t):
            RHS1 = ec.add(RHS1, mult(ec, pow(3, i), B1[i]))
        assert mult(ec, beta13) == RHS1, 'player one is cheating'

        B: List[Point] = list()  # commitment at the global sharing polynomial
        for i in range(t):
            B.append(ec.add(B1[i], B3[i]))

        K = B[0]  # aggregated public nonce
        if legendre_symbol(K[1], ec._p) != 1:
            beta1 = ec.n - beta1
            beta3 = ec.n - beta3

        ### PHASE THREE: signature generation ###

        # partial signatures
        ebytes = K[0].to_bytes(32, byteorder="big")
        ebytes += octets_from_point(ec, Q, True)
        ebytes += msg
        e = int_from_bits(ec, hf(ebytes).digest())
        gamma1 = (beta1 + e * alpha1) % ec.n
        gamma3 = (beta3 + e * alpha3) % ec.n

        # each participant verifies the other partial signatures

        # player one
        if legendre_symbol(K[1], ec._p) == 1:
            RHS3 = ec.add(K, mult(ec, e, Q))
            for i in range(1, t):
                temp = double_mult(ec, pow(3, i), B[i], e * pow(3, i), A[i])
                RHS3 = ec.add(RHS3, temp)
        else:
            assert legendre_symbol(K[1], ec._p) != 1
            RHS3 = ec.add(ec.opposite(K), mult(ec, e, Q))
            for i in range(1, t):
                temp = double_mult(ec, pow(3, i), ec.opposite(
                    B[i]), e * pow(3, i), A[i])
                RHS3 = ec.add(RHS3, temp)

        assert mult(ec, gamma3) == RHS3, 'player three is cheating'

        # player three
        if legendre_symbol(K[1], ec._p) == 1:
            RHS1 = ec.add(K, mult(ec, e, Q))
            for i in range(1, t):
                temp = double_mult(ec, pow(1, i), B[i], e * pow(1, i), A[i])
                RHS1 = ec.add(RHS1, temp)
        else:
            assert legendre_symbol(K[1], ec._p) != 1
            RHS1 = ec.add(ec.opposite(K), mult(ec, e, Q))
            for i in range(1, t):
                temp = double_mult(ec, pow(1, i), ec.opposite(
                    B[i]), e * pow(1, i), A[i])
                RHS1 = ec.add(RHS1, temp)

        assert mult(ec, gamma1) == RHS1, 'player two is cheating'

        ### PHASE FOUR: aggregating the signature ###
        omega1 = 3 * mod_inv(3 - 1, ec.n) % ec.n
        omega3 = 1 * mod_inv(1 - 3, ec.n) % ec.n
        sigma = (gamma1 * omega1 + gamma3 * omega3) % ec.n

        sig = K[0], sigma

        self.assertTrue(ssa._verify(ec, hf, msg, Q, sig))

        ### ADDITIONAL PHASE: reconstruction of the private key ###
        secret = (omega1 * alpha1 + omega3 * alpha3) % ec.n
        self.assertEqual((q1 + q2 + q3) % ec.n, secret)

    def test_musig(self):
        """testing 3-of-3 MuSig

            https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/musig/musig.md
            https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/
            https://eprint.iacr.org/2018/068
            https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html
            https://medium.com/@snigirev.stepan/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
        """
        ec = secp256k1
        M = hf(b'message to sign').digest()

        # key setup is not interactive

        # first signer
        q1 = int_from_octets(
            '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d92ad1d')
        Q1 = mult(ec, q1)
        k1 = rfc6979(ec, hf, M, q1)
        K1 = mult(ec, k1)

        # second signer
        q2 = int_from_octets(
            '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d')
        Q2 = mult(ec, q2)
        k2 = rfc6979(ec, hf, M, q2)
        K2 = mult(ec, k2)

        # third signer
        q3 = int_from_octets(
            '0c28fca386c7aff7600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d')
        Q3 = mult(ec, q3)
        k3 = rfc6979(ec, hf, M, q3)
        K3 = mult(ec, k3)

        # this is MuSig core: the rest is just Schnorr signature additivity
        L: List[Point] = list()  # multiset of public keys
        L.append(octets_from_point(ec, Q1, False))
        L.append(octets_from_point(ec, Q2, False))
        L.append(octets_from_point(ec, Q3, False))
        L.sort()                 # using lexicographic ordering
        L_brackets = b''
        for i in range(len(L)):
            L_brackets += L[i]
        h1 = hf(L_brackets + octets_from_point(ec, Q1, False)).digest()
        a1 = int_from_bits(ec, h1)
        h2 = hf(L_brackets + octets_from_point(ec, Q2, False)).digest()
        a2 = int_from_bits(ec, h2)
        h3 = hf(L_brackets + octets_from_point(ec, Q3, False)).digest()
        a3 = int_from_bits(ec, h3)
        # aggregated public key
        Q = ec.add(double_mult(ec, a1, Q1, a2, Q2), mult(ec, a3, Q3))
        Q_bytes = octets_from_point(ec, Q, True)

        ########################
        # interactive signature: exchange K, compute s
        # WARNING: the signers should exchange commitments to the public
        #          nonces before sending the nonces themselves

        # first signer
        # K, r_bytes, and e as calculated by any signer
        # are the same as the ones by the other signers
        K = ec.add(ec.add(K1, K2), K3)
        r_bytes = K[0].to_bytes(32, byteorder="big")
        e = int_from_bits(ec, hf(r_bytes + Q_bytes + M).digest())
        if legendre_symbol(K[1], ec._p) != 1:
            # no need to actually change K[1], as it is not used anymore
            # let's fix k1 instead, as it is used later
            # note that all other signers will change their k too
            k1 = ec.n - k1
        s1 = (k1 + e*a1*q1) % ec.n

        # second signer
        # K, r_bytes, and e as calculated by any signer
        # are the same as the ones by the other signers
        if legendre_symbol(K[1], ec._p) != 1:
            # no need to actually change K[1], as it is not used anymore
            # let's fix k2 instead, as it is used later
            # note that all other signers will change their k too
            k2 = ec.n - k2
        s2 = (k2 + e*a2*q2) % ec.n

        # third signer
        # K, r_bytes, and e as calculated by any signer
        # are the same as the ones by the other signers
        if legendre_symbol(K[1], ec._p) != 1:
            # no need to actually change K[1], as it is not used anymore
            # let's fix k3 instead, as it is used later
            # note that all other signers will change their k too
            k3 = ec.n - k3
        s3 = (k3 + e*a3*q3) % ec.n

        ############################################
        # interactive signature: exchange signatures
        # combine all (K[0], s) signatures into a single signature
        # anyone can do the following
        sig = K[0], (s1 + s2 + s3) % ec.n

        self.assertTrue(ssa.verify(ec, hf, M, Q, sig))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
