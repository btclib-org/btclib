#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.numbertheory import mod_sqrt
from btclib.ellipticcurves import EllipticCurve, sha256, bytes_from_Point, \
    to_Point, pointMult, DblScalarMult, _jac_from_aff, \
    _pointMultJacobian, _pointMultAffine, secondGenerator, \
    secp256k1, secp256r1, secp384r1, SEC_curves
from btclib.ecsignutils import int_from_hlenbytes

# low cardinality curves p<100
ec11_7 = EllipticCurve(11, 2, 7, (6,   9),   7, False)
ec11_17 = EllipticCurve(11, 2, 4, (0,   9),  17, False)
ec13_11 = EllipticCurve(13, 7, 6, (1,   1),  11, False)
ec13_19 = EllipticCurve(13, 0, 2, (1,   9),  19, False)
ec17_13 = EllipticCurve(17, 6, 8, (0,  12),  13, False)
ec17_23 = EllipticCurve(17, 3, 5, (1,  14),  23, False)
ec19_13 = EllipticCurve(19, 0, 2, (4,  16),  13, False)
ec19_23 = EllipticCurve(19, 2, 9, (0,  16),  23, False)
ec23_19 = EllipticCurve(23, 9, 7, (5,   4),  19, False)
ec23_31 = EllipticCurve(23, 5, 1, (0,   1),  31, False)
ec29_37 = EllipticCurve(29, 4, 9, (0,  26),  37, False)
ec31_23 = EllipticCurve(31, 4, 7, (0,  10),  23, False)
ec31_43 = EllipticCurve(31, 0, 3, (1,   2),  43, False)
ec37_31 = EllipticCurve(37, 2, 8, (1,  23),  31, False)
ec37_43 = EllipticCurve(37, 2, 9, (0,  34),  43, False)
ec41_37 = EllipticCurve(41, 2, 6, (1,  38),  37, False)
ec41_53 = EllipticCurve(41, 4, 4, (0,   2),  53, False)
ec43_37 = EllipticCurve(43, 1, 5, (2,  31),  37, False)
ec43_47 = EllipticCurve(43, 1, 3, (2,  23),  47, False)
ec47_41 = EllipticCurve(47, 3, 9, (0,   3),  41, False)
ec47_61 = EllipticCurve(47, 3, 5, (1,   3),  61, False)
ec53_47 = EllipticCurve(53, 9, 4, (0,  51),  47, False)
ec53_61 = EllipticCurve(53, 1, 8, (1,  13),  61, False)
ec59_53 = EllipticCurve(59, 9, 3, (0,  48),  53, False)
ec59_73 = EllipticCurve(59, 3, 3, (0,  48),  73, False)
ec61_59 = EllipticCurve(61, 2, 5, (0,  35),  59, False)
ec61_73 = EllipticCurve(61, 1, 9, (0,  58),  73, False)
ec67_61 = EllipticCurve(67, 3, 8, (2,  25),  61, False)
ec67_83 = EllipticCurve(67, 5, 9, (0,  64),  83, False)
ec71_67 = EllipticCurve(71, 7, 7, (1,  50),  67, False)
ec71_79 = EllipticCurve(71, 1, 8, (0,  24),  79, False)
ec73_61 = EllipticCurve(73, 6, 5, (1,  42),  61, False)
ec73_83 = EllipticCurve(73, 3, 9, (0,   3),  83, False)
ec79_71 = EllipticCurve(79, 2, 5, (0,  20),  71, False)
ec79_97 = EllipticCurve(79, 0, 3, (1,   2),  97, False)
ec83_79 = EllipticCurve(83, 1, 7, (0,  16),  79, False)
ec83_101 = EllipticCurve(83, 5, 7, (0,  16), 101, False)
ec89_83 = EllipticCurve(89, 6, 4, (0,   2),  83, False)
ec89_101 = EllipticCurve(89, 1, 9, (0,  86), 101, False)
ec97_89 = EllipticCurve(97, 1, 4, (0,  95),  89, False)
ec97_103 = EllipticCurve(97, 3, 2, (0,  83), 103, False)

low_card_curves_1 = [
    ec11_7, ec11_17,
    ec13_11, ec13_19,
    ec17_13, ec17_23,
    ec19_13, ec19_23,
    ec23_19, ec23_31,
    ec29_37,
    ec31_23, ec31_43,
    ec37_31, ec37_43,
    ec41_37, ec41_53,
    ec43_37, ec43_47,
    ec47_41, ec47_61,
    ec53_47, ec53_61,
    ec59_53, ec59_73,
    ec61_59, ec61_73,
    ec67_61, ec67_83,
    ec71_67, ec71_79,
    ec73_61, ec73_83,
    ec79_71, ec79_97,
    ec83_79, ec83_101,
    ec89_83, ec89_101,
    ec97_89, ec97_103
]

# low cardinality curves 100<p<300
ec101_97 = EllipticCurve(101, 7, 4, (0,  99),  97, False)
ec103_101 = EllipticCurve(103, 6, 2, (0,  38), 101, False)
ec103_113 = EllipticCurve(103, 4, 4, (0,   2), 113, False)
ec107_103 = EllipticCurve(107, 5, 2, (3,  30), 103, False)
ec107_113 = EllipticCurve(107, 7, 9, (0,   3), 113, False)
ec109_107 = EllipticCurve(109, 8, 1, (0,   1), 107, False)
ec109_127 = EllipticCurve(109, 2, 4, (0, 107), 127, False)
ec113_103 = EllipticCurve(113, 4, 6, (1,  89), 103, False)
ec113_127 = EllipticCurve(113, 5, 7, (0,  32), 127, False)
ec127_113 = EllipticCurve(127, 5, 9, (0, 124), 113, False)
ec127_139 = EllipticCurve(127, 3, 2, (0,  16), 139, False)
ec131_127 = EllipticCurve(131, 8, 5, (0, 108), 127, False)
ec131_137 = EllipticCurve(131, 1, 9, (0,   3), 137, False)
ec137_127 = EllipticCurve(137, 3, 9, (0, 134), 127, False)
ec137_157 = EllipticCurve(137, 4, 1, (0,   1), 157, False)
ec139_131 = EllipticCurve(139, 1, 3, (1, 127), 131, False)
ec139_163 = EllipticCurve(139, 0, 2, (3,  86), 163, False)
ec149_139 = EllipticCurve(149, 2, 8, (2, 136), 139, False)
ec149_173 = EllipticCurve(149, 6, 5, (0,  81), 173, False)
ec151_149 = EllipticCurve(151, 1, 7, (1, 148), 149, False)
ec151_167 = EllipticCurve(151, 1, 3, (1,  55), 167, False)
ec157_151 = EllipticCurve(157, 1, 4, (0, 155), 151, False)
ec157_181 = EllipticCurve(157, 1, 7, (1, 154), 181, False)
ec163_157 = EllipticCurve(163, 5, 9, (0, 160), 157, False)
ec163_181 = EllipticCurve(163, 0, 3, (1, 161), 181, False)
ec167_163 = EllipticCurve(167, 4, 2, (0, 154), 163, False)
ec167_181 = EllipticCurve(167, 1, 3, (0,  62), 181, False)
ec173_167 = EllipticCurve(173, 5, 5, (2,  14), 167, False)
ec173_197 = EllipticCurve(173, 3, 7, (2,  59), 197, False)
ec179_173 = EllipticCurve(179, 7, 5, (0, 149), 173, False)
ec179_181 = EllipticCurve(179, 8, 2, (6,  83), 181, False)
ec181_163 = EllipticCurve(181, 6, 2, (1,   3), 163, False)
ec181_199 = EllipticCurve(181, 1, 5, (0,  27), 199, False)
ec191_179 = EllipticCurve(191, 6, 9, (0,   3), 179, False)
ec191_197 = EllipticCurve(191, 1, 6, (0, 160), 197, False)
ec193_191 = EllipticCurve(193, 2, 7, (0, 134), 191, False)
ec193_211 = EllipticCurve(193, 7, 1, (0,   1), 211, False)
ec197_191 = EllipticCurve(197, 5, 4, (0, 195), 191, False)
ec197_199 = EllipticCurve(197, 2, 6, (0,  20), 199, False)
ec199_197 = EllipticCurve(199, 1, 3, (1, 123), 197, False)
ec199_211 = EllipticCurve(199, 0, 3, (1,   2), 211, False)
ec211_199 = EllipticCurve(211, 0, 2, (4,  53), 199, False)
ec211_229 = EllipticCurve(211, 7, 2, (2, 119), 229, False)
ec223_241 = EllipticCurve(223, 8, 7, (0, 197), 241, False)
ec227_241 = EllipticCurve(227, 1, 9, (0,   3), 241, False)
ec229_227 = EllipticCurve(229, 6, 6, (2,  22), 227, False)
ec229_239 = EllipticCurve(229, 7, 7, (1, 123), 239, False)
ec233_229 = EllipticCurve(233, 8, 6, (1,  99), 229, False)
ec233_257 = EllipticCurve(233, 1, 4, (0,   2), 257, False)
ec239_233 = EllipticCurve(239, 6, 5, (0,  31), 233, False)
ec239_257 = EllipticCurve(239, 2, 1, (0,   1), 257, False)
ec241_229 = EllipticCurve(241, 6, 2, (0, 219), 229, False)
ec241_257 = EllipticCurve(241, 2, 4, (0,   2), 257, False)
ec251_233 = EllipticCurve(251, 4, 3, (0, 175), 233, False)
ec251_271 = EllipticCurve(251, 1, 4, (0, 249), 271, False)
ec257_241 = EllipticCurve(257, 8, 5, (2,  85), 241, False)
ec257_281 = EllipticCurve(257, 1, 7, (1, 254), 281, False)
ec263_257 = EllipticCurve(263, 7, 6, (0, 100), 257, False)
ec263_283 = EllipticCurve(263, 5, 3, (0,  23), 283, False)
ec269_241 = EllipticCurve(269, 9, 4, (0, 267), 241, False)
ec269_293 = EllipticCurve(269, 7, 9, (0, 266), 293, False)
ec271_269 = EllipticCurve(271, 5, 2, (0, 175), 269, False)
ec271_277 = EllipticCurve(271, 5, 8, (0,  79), 277, False)
ec277_263 = EllipticCurve(277, 6, 9, (0,   3), 263, False)
ec277_307 = EllipticCurve(277, 9, 9, (0,   3), 307, False)
ec281_311 = EllipticCurve(281, 1, 4, (0, 279), 311, False)
ec283_281 = EllipticCurve(283, 2, 7, (0,  63), 281, False)
ec293_281 = EllipticCurve(293, 8, 6, (0,  42), 281, False)
ec293_311 = EllipticCurve(293, 1, 4, (0, 291), 311, False)

low_card_curves_2 = [
    ec101_97,
    ec103_101, ec103_113,
    ec107_103, ec107_113,
    ec109_107, ec109_127,
    ec113_103, ec113_127,
    ec127_113, ec127_139,
    ec131_127, ec131_137,
    ec137_127, ec137_157,
    ec139_131, ec139_163,
    ec149_139, ec149_173,
    ec151_149, ec151_167,
    ec157_151, ec157_181,
    ec163_157, ec163_181,
    ec167_163, ec167_181,
    ec173_167, ec173_197,
    ec179_173, ec179_181,
    ec181_163, ec181_199,
    ec191_179, ec191_197,
    ec193_191, ec193_211,
    ec197_191, ec197_199,
    ec199_197, ec199_211,
    ec211_199, ec211_229,
    ec223_241, ec227_241,
    ec229_227, ec229_239,
    ec233_229, ec233_257,
    ec239_233, ec239_257,
    ec241_229, ec241_257,
    ec251_233, ec251_271,
    ec257_241, ec257_281,
    ec263_257, ec263_283,
    ec269_241, ec269_293,
    ec271_269, ec271_277,
    ec277_263, ec277_307,
    ec281_311,
    ec283_281,
    ec293_281, ec293_311
]

low_card_curves = low_card_curves_1 + low_card_curves_2
all_curves = low_card_curves + SEC_curves

Inf = 1, 0  # Infinity point in affine coordinates
InfJ = 1, 1, 0  # Infinity point in jacobian coordinates


class TestEllipticCurve(unittest.TestCase):
    def test_exceptions(self):
        # good
        EllipticCurve(11, 2, 7, (6,   9),   7, False)
        # p not odd
        self.assertRaises(ValueError, EllipticCurve,
                          10, 2, 7, (6, 9),   7, False)
        # p not prime
        self.assertRaises(ValueError, EllipticCurve,
                          15, 2, 7, (6, 9),   7, False)
        # zero discriminant
        self.assertRaises(ValueError, EllipticCurve,
                          11, 7, 7, (6, 9),   7, False)
        # G not Tuple (int, int)
        self.assertRaises(ValueError, EllipticCurve, 11,
                          2, 7, (6, 9,  1),   7, False)
        # G not on curve
        self.assertRaises(ValueError, EllipticCurve,
                          11, 2, 7, (7, 9),   7, False)
        # n not prime
        self.assertRaises(ValueError, EllipticCurve,
                          11, 2, 7, (6, 9),   8, False)
        # n not Hesse
        self.assertRaises(ValueError, EllipticCurve,
                          11, 2, 7, (6, 9),   71, False)
        # n not group order
        self.assertRaises(ValueError, EllipticCurve,
                          11, 2, 7, (6, 9),   13, False)
        # n=p -> weak curve
        # missing
        # weak curve
        self.assertRaises(UserWarning, EllipticCurve, 13, 7, 6, (1, 1),  11)

    def test_all_curves(self):
        for ec in all_curves:
            self.assertEqual(pointMult(ec, 0, ec.G), Inf)
            self.assertEqual(pointMult(ec, 0, ec.G), Inf)

            self.assertEqual(pointMult(ec, 1, ec.G), ec.G)
            self.assertEqual(pointMult(ec, 1, ec.G), ec.G)

            Gy_odd = ec.yOdd(ec.G[0], True)
            self.assertEqual(Gy_odd % 2, 1)
            Gy_even = ec.yOdd(ec.G[0], False)
            self.assertEqual(Gy_even % 2, 0)
            self.assertTrue(ec.G[1] in (Gy_odd, Gy_even))

            Gbytes = bytes_from_Point(ec, ec.G, True)
            Gbytes = bytes_from_Point(ec, Gbytes, True)
            G2 = to_Point(ec, Gbytes)
            G2 = to_Point(ec, G2)
            self.assertEqual(ec.G, G2)

            Gbytes = bytes_from_Point(ec, ec.G, False)
            Gbytes = bytes_from_Point(ec, Gbytes, False)
            G2 = to_Point(ec, Gbytes)
            G2 = to_Point(ec, G2)
            self.assertEqual(ec.G, G2)

            P = ec.add(Inf, ec.G)
            self.assertEqual(P, ec.G)
            P = ec.add(ec.G, Inf)
            self.assertEqual(P, ec.G)
            P = ec.add(Inf, Inf)
            self.assertEqual(P, Inf)

            P = ec.add(ec.G, ec.G)
            self.assertEqual(P, pointMult(ec, 2, ec.G))

            P = pointMult(ec, ec.n-1, ec.G)
            self.assertEqual(ec.add(P, ec.G), Inf)
            self.assertEqual(pointMult(ec, ec.n, ec.G), Inf)

            self.assertEqual(pointMult(ec, 0, Inf), Inf)
            self.assertEqual(pointMult(ec, 1, Inf), Inf)
            self.assertEqual(pointMult(ec, 25, Inf), Inf)

            ec_repr = repr(ec)
            if ec in low_card_curves:
                ec_repr = ec_repr[:-1] + ", False)"
            ec2 = eval(ec_repr)
            self.assertEqual(str(ec), str(ec2))

    def test_to_point(self):
        ec = secp256k1
        Q = pointMult(ec, ec._p, ec.G)

        Q_bytes = b'\x03' + Q[0].to_bytes(32, "big")
        R = to_Point(ec, Q_bytes)
        self.assertEqual(R, Q)
        self.assertEqual(bytes_from_Point(ec, R, True), Q_bytes)

        Q_hex_str = Q_bytes.hex()
        R = to_Point(ec, Q_hex_str)
        self.assertEqual(R, Q)

        Q_bytes = b'\x04' + Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
        R = to_Point(ec, Q_bytes)
        self.assertEqual(R, Q)
        self.assertEqual(bytes_from_Point(ec, R, False), Q_bytes)

        Q_hex_str = Q_bytes.hex()
        R = to_Point(ec, Q_hex_str)
        self.assertEqual(R, Q)

        # infinity point
        self.assertEqual(to_Point(ec, b'\x00'), Inf)
        self.assertEqual(bytes_from_Point(ec, Inf, True),  b'\x00')
        self.assertEqual(bytes_from_Point(ec, Inf, False), b'\x00')
        Inf_hex_str = b'\x00'.hex()
        self.assertEqual(to_Point(ec, Inf_hex_str), Inf)

        # scalar in point multiplication can be int, str, or bytes
        t = tuple()
        self.assertRaises(TypeError, pointMult, ec, t, ec.G)

        # not a compressed point
        Q_bytes = b'\x01' * 33
        self.assertRaises(ValueError, to_Point, ec, Q_bytes)
        # not a point
        Q_bytes += b'\x01'
        self.assertRaises(ValueError, to_Point, ec, Q_bytes)
        # not an uncompressed point
        Q_bytes += b'\x01' * 31
        self.assertRaises(ValueError, to_Point, ec, Q_bytes)
        # binary point not on curve
        OffCurve = Q[0], ec._p - Q[1] - 1
        Q_bytes = b'\x04' + Q[0].to_bytes(ec.bytesize, byteorder='big')
        Q_bytes += OffCurve[1].to_bytes(ec.bytesize, byteorder='big')
        self.assertRaises(ValueError, to_Point, ec, Q_bytes)
        # tuple point not on curve
        self.assertRaises(ValueError, to_Point, ec, OffCurve)

    def test_second_generator(self):
        """
        important remark on secp256-zkp prefix for compressed encoding of the second generator:
        https://github.com/garyyu/rust-secp256k1-zkp/wiki/Pedersen-Commitment
        """
        H = secondGenerator(secp256k1, sha256)
        H = bytes_from_Point(secp256k1, H, True)
        self.assertEqual(
            H.hex(), '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')

        # 0*G + 1*H
        T = DblScalarMult(secp256k1, 0, secp256k1.G, 1, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')

        # 0*G + 2*H
        T = DblScalarMult(secp256k1, 0, secp256k1.G, 2, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '03fad265e0a0178418d006e247204bcf42edb6b92188074c9134704c8686eed37a')
        T = pointMult(secp256k1, 2, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '03fad265e0a0178418d006e247204bcf42edb6b92188074c9134704c8686eed37a')

        # 0*G + 3*H
        T = DblScalarMult(secp256k1, 0, secp256k1.G, 3, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '025ef47fcde840a435e831bbb711d466fc1ee160da3e15437c6c469a3a40daacaa')
        T = pointMult(secp256k1, 3, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '025ef47fcde840a435e831bbb711d466fc1ee160da3e15437c6c469a3a40daacaa')

        # 1*G+0*H
        T = DblScalarMult(secp256k1, 1, secp256k1.G, 0, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        T = pointMult(secp256k1, 1, secp256k1.G)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')

        # 2*G+0*H
        T = DblScalarMult(secp256k1, 2, secp256k1.G, 0, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
        T = pointMult(secp256k1, 2, secp256k1.G)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')

        # 3*G+0*H
        T = DblScalarMult(secp256k1, 3, secp256k1.G, 0, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9')
        T = pointMult(secp256k1, 3, secp256k1.G)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9')

        # 0*G+5*H
        T = DblScalarMult(secp256k1, 0, secp256k1.G, 5, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '039e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e')
        T = pointMult(secp256k1, 5, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '039e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e')

        # 0*G-5*H
        T = DblScalarMult(secp256k1, 0, secp256k1.G, -5, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '029e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e')
        T = pointMult(secp256k1, -5, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(
            T.hex(), '029e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e')

        # 1*G-5*H
        U = DblScalarMult(secp256k1, 1, secp256k1.G, -5, H)
        U = bytes_from_Point(secp256k1, U, True)
        self.assertEqual(
            U.hex(), '02b218ddacb34d827c71760e601b41d309bc888cf7e3ab7cc09ec082b645f77e5a')
        U = secp256k1.add(secp256k1.G, T)  # reusing previous T value
        U = bytes_from_Point(secp256k1, U, True)
        self.assertEqual(
            U.hex(), '02b218ddacb34d827c71760e601b41d309bc888cf7e3ab7cc09ec082b645f77e5a')

        H = secondGenerator(secp256r1, sha256)
        H = secondGenerator(secp384r1, sha256)

    def test_opposite(self):
        for ec in all_curves:
            # random point
            Q = pointMult(ec, ec._p, ec.G)
            minus_Q = ec.opposite(Q)
            self.assertEqual(ec.add(Q, minus_Q), Inf)
            # jacobian coordinates
            Qjac = _jac_from_aff(Q)
            minus_Qjac = _jac_from_aff(minus_Q)
            self.assertEqual(ec._addJacobian(Qjac, minus_Qjac), (1, 1, 0))

            # opposite of Inf is Inf
            Q = Inf
            minus_Q = ec.opposite(Q)
            self.assertEqual(minus_Q, Inf)

    def test_symmetry(self):
        """Methods to break simmetry: quadratic residue, odd/even, low/high"""
        for ec in low_card_curves[:4]:

            # setup phase
            # compute quadratic residues
            hasRoot = set()
            hasRoot.add(1)

            for i in range(2, ec._p):
                hasRoot.add(i*i % ec._p)

            # test phase

            # random point
            Q = pointMult(ec, ec._p, ec.G)  # just a random point

            x = Q[0]
            if ec._p % 4 == 3:
                quad_res = ec.yQuadraticResidue(x, 1)
                not_quad_res = ec.yQuadraticResidue(x, 0)
                # in this case only quad_res is a quadratic residue
                self.assertIn(quad_res, hasRoot)
                root = mod_sqrt(quad_res, ec._p)
                self.assertEqual(quad_res, (root*root) % ec._p)
                root = ec._p - root
                self.assertEqual(quad_res, (root*root) % ec._p)

                self.assertTrue(not_quad_res == ec._p - quad_res)
                self.assertNotIn(not_quad_res, hasRoot)
                self.assertRaises(ValueError, mod_sqrt, not_quad_res, ec._p)

                yOdd = ec.yOdd(x, 1)
                self.assertTrue(yOdd in (quad_res, not_quad_res))
                self.assertTrue(yOdd % 2 == 1)
                yEven = ec.yOdd(x, 0)
                self.assertTrue(yEven in (quad_res, not_quad_res))
                self.assertTrue(yEven % 2 == 0)

                yLow = ec.yHigh(x, 0)
                self.assertTrue(yLow in (yOdd, yEven))
                yHigh = ec.yHigh(x, 1)
                self.assertTrue(yHigh in (yOdd, yEven))
                self.assertTrue(yLow < yHigh)
            else:
                self.assertTrue(ec._p % 4 == 1)
                # cannot use yQuadraticResidue in this case
                self.assertRaises(ValueError, ec.yQuadraticResidue, x, 1)
                self.assertRaises(ValueError, ec.yQuadraticResidue, x, 0)

                yOdd = ec.yOdd(x, 1)
                self.assertTrue(yOdd % 2 == 1)
                yEven = ec.yOdd(x, 0)
                self.assertTrue(yEven % 2 == 0)
                # in this case neither or both are quadratic residues
                self.assertTrue((yOdd in hasRoot and yEven in hasRoot) or
                                (yOdd not in hasRoot and yEven not in hasRoot))
                if yOdd in hasRoot and yEven in hasRoot:
                    root = mod_sqrt(yOdd, ec._p)
                    self.assertEqual(yOdd, (root*root) % ec._p)
                    root = ec._p - root
                    self.assertEqual(yOdd, (root*root) % ec._p)
                    root = mod_sqrt(yEven, ec._p)
                    self.assertEqual(yEven, (root*root) % ec._p)
                    root = ec._p - root
                    self.assertEqual(yEven, (root*root) % ec._p)
                else:
                    self.assertTrue(
                        yOdd not in hasRoot and yEven not in hasRoot)
                    self.assertRaises(ValueError, mod_sqrt, yOdd, ec._p)
                    self.assertRaises(ValueError, mod_sqrt, yEven, ec._p)

                yLow = ec.yHigh(x, 0)
                self.assertTrue(yLow in (yOdd, yEven))
                yHigh = ec.yHigh(x, 1)
                self.assertTrue(yHigh in (yOdd, yEven))
                self.assertTrue(yLow < yHigh)
        # with the last curve
        self.assertRaises(ValueError, ec.yHigh, x, 2)
        self.assertRaises(ValueError, ec.yOdd, x, 2)
        self.assertRaises(ValueError, ec.yQuadraticResidue, x, 2)

    def test_affine_jac_conversions(self):
        for ec in all_curves:
            Q = pointMult(ec, ec._p, ec.G)  # random point
            checkQ = ec._affine_from_jac(_jac_from_aff(Q))
            self.assertEqual(Q, checkQ)
        # with only the last curve
        checkInf = ec._affine_from_jac(_jac_from_aff(Inf))
        self.assertEqual(Inf, checkInf)
        self.assertRaises(ValueError, ec._affine_from_jac, (1, 1, 1, 0))
        self.assertRaises(ValueError, _jac_from_aff, (1, 1, 0))

    def test_Add(self):
        for ec in all_curves:
            Q1 = pointMult(ec, ec._p, ec.G)  # just a random point
            Q1J = _jac_from_aff(Q1)

            Q2 = ec.G
            Q2J = _jac_from_aff(Q2)

            # distinct points
            Q3 = ec._addAffine(Q1,  Q2)
            Q3jac = ec._addJacobian(Q1J, Q2J)
            self.assertEqual(Q3, ec._affine_from_jac(Q3jac))

            # point at infinity
            Q3 = ec._addAffine(Q2,  Inf)
            Q3jac = ec._addJacobian(Q2J, InfJ)
            self.assertEqual(Q3, ec._affine_from_jac(Q3jac))
            Q3 = ec._addAffine(Inf,  Q2)
            Q3jac = ec._addJacobian(InfJ, Q2J)
            self.assertEqual(Q3, ec._affine_from_jac(Q3jac))

            # point doubling
            Q3 = ec._addAffine(Q1,  Q1)
            Q3jac = ec._addJacobian(Q1J, Q1J)
            self.assertEqual(Q3, ec._affine_from_jac(Q3jac))

            # opposite points
            Q1opp = ec.opposite(Q1)
            Q3 = ec._addAffine(Q1,  Q1opp)
            Q3jac = ec._addJacobian(Q1J, _jac_from_aff(Q1opp))
            self.assertEqual(Q3, ec._affine_from_jac(Q3jac))

    def test_Multiply(self):
        for ec in low_card_curves_1:
            Gjac = _jac_from_aff(ec.G)
            for q in range(ec.n):
                Q = _pointMultAffine(ec, q, ec.G)
                Qjac = _pointMultJacobian(ec, q, Gjac)
                Q2 = ec._affine_from_jac(Qjac)
                self.assertEqual(Q, Q2)
        # with last curve
        self.assertEqual(Inf, _pointMultAffine(ec, 3, Inf))
        self.assertEqual(InfJ, _pointMultJacobian(ec, 3, InfJ))

        # invalid scalar
        q = b'\x00' * (ec.bytesize + 1)
        self.assertRaises(ValueError, pointMult, ec, q, ec.G)

        # invalid coordinates
        Q = 1, 1, 0
        self.assertRaises(ValueError, _pointMultAffine, ec, 1, Q)
        Q = 1, 1, 1, 0
        self.assertRaises(ValueError, _pointMultJacobian, ec, 1, Q)

    def test_shamir(self):
        ec = ec29_37
        for k1 in range(ec.n):
            for k2 in range(ec.n):
                shamir = DblScalarMult(ec, k1, ec.G, k2, ec.G)
                std = ec.add(pointMult(ec, k1, ec.G),
                             pointMult(ec, k2, ec.G))
                self.assertEqual(shamir, std)
                shamir = DblScalarMult(ec, k1, Inf, k2, ec.G)
                std = ec.add(pointMult(ec, k1, Inf),
                             pointMult(ec, k2, ec.G))
                self.assertEqual(shamir, std)
                shamir = DblScalarMult(ec, k1, ec.G, k2, Inf)
                std = ec.add(pointMult(ec, k1, ec.G),
                             pointMult(ec, k2, Inf))
                self.assertEqual(shamir, std)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
