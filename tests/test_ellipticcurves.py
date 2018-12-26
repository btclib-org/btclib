#!/usr/bin/env python3

import unittest
import os

from btclib.numbertheory import mod_sqrt
from btclib.ellipticcurves import EllipticCurve, sha256, \
                                  bytes_from_Point, tuple_from_Point, \
                                  secondGenerator, \
                                  opposite, pointAdd, pointMultiply, \
                                  jac_from_affine, \
                                  pointAddJacobian, pointMultiplyJacobian, \
                                  DoubleScalarMultiplication, \
                                  secp160r1, \
                                  secp192k1, secp192r1, \
                                  secp224k1, secp224r1, \
                                  secp256k1, secp256r1, \
                                  secp384r1, secp521r1

# toy curves
ec11_13   = EllipticCurve( 1,  6,  11, (  5,  9),  13)
ec263_269 = EllipticCurve( 6,  9, 263, (  0,  3), 269)
ec263_270 = EllipticCurve( 2,  3, 263, (200, 39), 270)
ec263_280 = EllipticCurve(-7, 10, 263, (  3,  4), 280)

ec11_7    = EllipticCurve(2, 7,  11, (6,   9),   7)
ec11_17   = EllipticCurve(2, 4,  11, (0,   9),  17)
ec13_11   = EllipticCurve(7, 6,  13, (1,   1),  11)
ec13_19   = EllipticCurve(0, 2,  13, (1,   9),  19)
ec17_13   = EllipticCurve(6, 8,  17, (0,  12),  13)
ec17_23   = EllipticCurve(3, 5,  17, (1,  14),  23)
ec19_13   = EllipticCurve(0, 2,  19, (4,  16),  13)
ec19_23   = EllipticCurve(2, 9,  19, (0,  16),  23)
ec23_19   = EllipticCurve(9, 7,  23, (5,   4),  19)
ec23_31   = EllipticCurve(5, 1,  23, (0,   1),  31)
ec29_37   = EllipticCurve(4, 9,  29, (0,  26),  37)
ec31_23   = EllipticCurve(4, 7,  31, (0,  10),  23)
ec31_43   = EllipticCurve(0, 3,  31, (1,   2),  43)
ec37_31   = EllipticCurve(2, 8,  37, (1,  23),  31)
ec37_43   = EllipticCurve(2, 9,  37, (0,  34),  43)
ec41_37   = EllipticCurve(2, 6,  41, (1,  38),  37)
ec41_53   = EllipticCurve(4, 4,  41, (0,   2),  53)
ec43_37   = EllipticCurve(1, 5,  43, (2,  31),  37)
ec43_47   = EllipticCurve(1, 3,  43, (2,  23),  47)
ec47_41   = EllipticCurve(3, 9,  47, (0,   3),  41)
ec47_61   = EllipticCurve(3, 5,  47, (1,   3),  61)
ec53_47   = EllipticCurve(9, 4,  53, (0,  51),  47)
ec53_61   = EllipticCurve(1, 8,  53, (1,  13),  61)
ec59_53   = EllipticCurve(9, 3,  59, (0,  48),  53)
ec59_73   = EllipticCurve(3, 3,  59, (0,  48),  73)
ec61_59   = EllipticCurve(2, 5,  61, (0,  35),  59)
ec61_73   = EllipticCurve(1, 9,  61, (0,  58),  73)
ec67_61   = EllipticCurve(3, 8,  67, (2,  25),  61)
ec67_83   = EllipticCurve(5, 9,  67, (0,  64),  83)
ec71_67   = EllipticCurve(7, 7,  71, (1,  50),  67)
ec71_79   = EllipticCurve(1, 8,  71, (0,  24),  79)
ec73_61   = EllipticCurve(6, 5,  73, (1,  42),  61)
ec73_83   = EllipticCurve(3, 9,  73, (0,   3),  83)
ec79_71   = EllipticCurve(2, 5,  79, (0,  20),  71)
ec79_97   = EllipticCurve(0, 3,  79, (1,   2),  97)
ec83_79   = EllipticCurve(1, 7,  83, (0,  16),  79)
ec83_101  = EllipticCurve(5, 7,  83, (0,  16), 101)
ec89_83   = EllipticCurve(6, 4,  89, (0,   2),  83)
ec89_101  = EllipticCurve(1, 9,  89, (0,  86), 101)
ec97_89   = EllipticCurve(1, 4,  97, (0,  95),  89)
ec97_103  = EllipticCurve(3, 2,  97, (0,  83), 103)
ec101_97  = EllipticCurve(7, 4, 101, (0,  99),  97)
#ec101_101 = EllipticCurve(2, 5, 101, (0,  56), 101)
ec103_101 = EllipticCurve(6, 2, 103, (0,  38), 101)
ec103_113 = EllipticCurve(4, 4, 103, (0,   2), 113)
ec107_103 = EllipticCurve(5, 2, 107, (3,  30), 103)
ec107_113 = EllipticCurve(7, 9, 107, (0,   3), 113)
ec109_107 = EllipticCurve(8, 1, 109, (0,   1), 107)
ec109_127 = EllipticCurve(2, 4, 109, (0, 107), 127)
ec113_103 = EllipticCurve(4, 6, 113, (1,  89), 103)
ec113_127 = EllipticCurve(5, 7, 113, (0,  32), 127)
ec127_113 = EllipticCurve(5, 9, 127, (0, 124), 113)
ec127_139 = EllipticCurve(3, 2, 127, (0,  16), 139)
ec131_127 = EllipticCurve(8, 5, 131, (0, 108), 127)
ec131_137 = EllipticCurve(1, 9, 131, (0,   3), 137)
ec137_127 = EllipticCurve(3, 9, 137, (0, 134), 127)
ec137_157 = EllipticCurve(4, 1, 137, (0,   1), 157)
ec139_131 = EllipticCurve(1, 3, 139, (1, 127), 131)
ec139_163 = EllipticCurve(0, 2, 139, (3,  86), 163)
ec149_139 = EllipticCurve(2, 8, 149, (2, 136), 139)
ec149_173 = EllipticCurve(6, 5, 149, (0,  81), 173)
ec151_149 = EllipticCurve(1, 7, 151, (1, 148), 149)
ec151_167 = EllipticCurve(1, 3, 151, (1,  55), 167)
ec157_151 = EllipticCurve(1, 4, 157, (0, 155), 151)
ec157_181 = EllipticCurve(1, 7, 157, (1, 154), 181)
ec163_157 = EllipticCurve(5, 9, 163, (0, 160), 157)
ec163_181 = EllipticCurve(0, 3, 163, (1, 161), 181)
ec167_163 = EllipticCurve(4, 2, 167, (0, 154), 163)
ec167_181 = EllipticCurve(1, 3, 167, (0,  62), 181)
ec173_167 = EllipticCurve(5, 5, 173, (2,  14), 167)
ec173_197 = EllipticCurve(3, 7, 173, (2,  59), 197)
ec179_173 = EllipticCurve(7, 5, 179, (0, 149), 173)
ec179_181 = EllipticCurve(8, 2, 179, (6,  83), 181)
ec181_163 = EllipticCurve(6, 2, 181, (1,   3), 163)
ec181_199 = EllipticCurve(1, 5, 181, (0,  27), 199)
ec191_179 = EllipticCurve(6, 9, 191, (0,   3), 179)
ec191_197 = EllipticCurve(1, 6, 191, (0, 160), 197)
ec193_191 = EllipticCurve(2, 7, 193, (0, 134), 191)
ec193_211 = EllipticCurve(7, 1, 193, (0,   1), 211)
ec197_191 = EllipticCurve(5, 4, 197, (0, 195), 191)
ec197_199 = EllipticCurve(2, 6, 197, (0,  20), 199)
ec199_197 = EllipticCurve(1, 3, 199, (1, 123), 197)
ec199_211 = EllipticCurve(0, 3, 199, (1,   2), 211)
ec211_199 = EllipticCurve(0, 2, 211, (4,  53), 199)
ec211_229 = EllipticCurve(7, 2, 211, (2, 119), 229)
ec223_241 = EllipticCurve(8, 7, 223, (0, 197), 241)
ec227_241 = EllipticCurve(1, 9, 227, (0,   3), 241)
ec229_227 = EllipticCurve(6, 6, 229, (2,  22), 227)
ec229_239 = EllipticCurve(7, 7, 229, (1, 123), 239)
ec233_229 = EllipticCurve(8, 6, 233, (1,  99), 229)
ec233_257 = EllipticCurve(1, 4, 233, (0,   2), 257)
ec239_233 = EllipticCurve(6, 5, 239, (0,  31), 233)
ec239_257 = EllipticCurve(2, 1, 239, (0,   1), 257)
ec241_229 = EllipticCurve(6, 2, 241, (0, 219), 229)
ec241_257 = EllipticCurve(2, 4, 241, (0,   2), 257)
ec251_233 = EllipticCurve(4, 3, 251, (0, 175), 233)
ec251_271 = EllipticCurve(1, 4, 251, (0, 249), 271)
ec257_241 = EllipticCurve(8, 5, 257, (2,  85), 241)
ec257_281 = EllipticCurve(1, 7, 257, (1, 254), 281)
ec263_257 = EllipticCurve(7, 6, 263, (0, 100), 257)
ec263_283 = EllipticCurve(5, 3, 263, (0,  23), 283)
ec269_241 = EllipticCurve(9, 4, 269, (0, 267), 241)
ec269_293 = EllipticCurve(7, 9, 269, (0, 266), 293)
ec271_269 = EllipticCurve(5, 2, 271, (0, 175), 269)
ec271_277 = EllipticCurve(5, 8, 271, (0,  79), 277)
ec277_263 = EllipticCurve(6, 9, 277, (0,   3), 263)
ec277_307 = EllipticCurve(9, 9, 277, (0,   3), 307)
ec281_311 = EllipticCurve(1, 4, 281, (0, 279), 311)
ec283_281 = EllipticCurve(2, 7, 283, (0,  63), 281)
#ec283_283 = EllipticCurve(4, 1, 283, (0,   1), 283)
ec293_281 = EllipticCurve(8, 6, 293, (0,  42), 281)
ec293_311 = EllipticCurve(1, 4, 293, (0, 291), 311)

lowcard = [
    ec11_13, 
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
    ec97_89, ec97_103,
    ec101_97, #ec101_101,
    ec103_101, ec103_113
]

smallcurves = lowcard + [
    ec263_269, ec263_270, ec263_280,
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
    ec283_281, #ec283_283,
    ec293_281, ec293_311
    ]

allcurves = [
    secp160r1,
    secp192k1, secp192r1, secp224k1, secp224r1,
    secp256k1, secp256r1, secp384r1, secp521r1,
    ec11_13, ec263_269, ec263_270, ec263_280 # ?
    ] + smallcurves
    
class TestEllipticCurve(unittest.TestCase):
    def test_all_curves(self):
        for ec in allcurves:
            # the infinity point is represented by None
            self.assertEqual(pointMultiply(ec, 0, ec.G), None)
            self.assertEqual(pointMultiply(ec, 0, ec.G), None)

            self.assertEqual(pointMultiply(ec, 1, ec.G), ec.G)
            self.assertEqual(pointMultiply(ec, 1, ec.G), ec.G)

            Gy_odd = ec.yOdd(ec.G[0], True)
            self.assertEqual(Gy_odd % 2, 1)
            Gy_even = ec.yOdd(ec.G[0], False)
            self.assertEqual(Gy_even % 2, 0)
            self.assertTrue(ec.G[1] in (Gy_odd, Gy_even))

            Gbytes = bytes_from_Point(ec, ec.G, True)
            Gbytes = bytes_from_Point(ec, Gbytes, True)
            G2 = tuple_from_Point(ec, Gbytes)
            G2 = tuple_from_Point(ec, G2)
            self.assertEqual(ec.G, G2)

            Gbytes = bytes_from_Point(ec, ec.G, False)
            Gbytes = bytes_from_Point(ec, Gbytes, False)
            G2 = tuple_from_Point(ec, Gbytes)
            G2 = tuple_from_Point(ec, G2)
            self.assertEqual(ec.G, G2)

            P = ec.pointAdd(None, ec.G)
            self.assertEqual(P, ec.G)
            P = ec.pointAdd(ec.G, None)
            self.assertEqual(P, ec.G)
            P = ec.pointAdd(None, None)
            self.assertEqual(P, None)

            P = pointAdd(ec, None, ec.G)
            self.assertEqual(P, ec.G)
            P = pointAdd(ec, ec.G, None)
            self.assertEqual(P, ec.G)
            P = pointAdd(ec, None, None)
            self.assertEqual(P, None)

            P = ec.pointAdd(ec.G, ec.G)
            self.assertEqual(P, pointMultiply(ec, 2, ec.G))
            P = pointAdd(ec, ec.G, ec.G)
            self.assertEqual(P, pointMultiply(ec, 2, ec.G))

            P = pointMultiply(ec, ec.n-1, ec.G)
            self.assertEqual(ec.pointAdd(P, ec.G), None)
            self.assertEqual(pointMultiply(ec, ec.n, ec.G), None)
            P = pointMultiply(ec, ec.n-1, ec.G)
            self.assertEqual(pointAdd(ec, P, ec.G), None)
            self.assertEqual(pointMultiply(ec, ec.n, ec.G), None)

            self.assertEqual(pointMultiply(ec, 0, None), None)
            self.assertEqual(pointMultiply(ec, 1, None), None)
            self.assertEqual(pointMultiply(ec, 25, None), None)
            self.assertEqual(pointMultiply(ec, 0, None), None)
            self.assertEqual(pointMultiply(ec, 1, None), None)
            self.assertEqual(pointMultiply(ec, 25, None), None)

            ec2 = eval(repr(ec))
            self.assertEqual(str(ec2), str(ec2))

            if (ec.n % 2 == 0):
                P = pointMultiply(ec, ec.n//2, ec.G)
                self.assertEqual(P[1], 0)
                self.assertEqual(ec.pointAdd(P, P), None)
                P = pointMultiply(ec, ec.n//2, ec.G)
                self.assertEqual(P[1], 0)
                self.assertEqual(pointAdd(ec, P, P), None)
                
    def test_tuple_from_point(self):
        prv = 0xc28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
        Pub = pointMultiply(secp256k1, prv, secp256k1.G)
        
        Pub_bytes = b'\x02' + Pub[0].to_bytes(32, "big")
        p2 = tuple_from_Point(secp256k1, Pub_bytes)
        self.assertEqual(p2, Pub)

        Pub_hex_str = Pub_bytes.hex()
        p2 = tuple_from_Point(secp256k1, Pub_hex_str)
        self.assertEqual(p2, Pub)

        Pub_bytes = b'\x04' + Pub[0].to_bytes(32, "big") + Pub[1].to_bytes(32, "big")
        p2 = tuple_from_Point(secp256k1, Pub_bytes)
        self.assertEqual(p2, Pub)

        Pub_hex_str = Pub_bytes.hex()
        p2 = tuple_from_Point(secp256k1, Pub_hex_str)
        self.assertEqual(p2, Pub)

        # infinity point cannot be represented as tuple
        self.assertRaises(ValueError, tuple_from_Point, secp256k1, None)

        # scalar in point multiplication can be int, str, or bytes-like
        t = tuple()
        self.assertRaises(TypeError, pointMultiply, secp256k1, t, secp256k1.G)

    def test_second_generator(self):
        """
        important remark on secp256-zkp prefix for compressed encoding of the second generator:
        https://github.com/garyyu/rust-secp256k1-zkp/wiki/Pedersen-Commitment
        """
        H = secondGenerator(secp256k1, sha256)
        H = bytes_from_Point(secp256k1, H, True)
        self.assertEqual(H.hex(), '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')

        # 0*G + 1*H
        T = DoubleScalarMultiplication(secp256k1, 0, secp256k1.G, 1, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')

        # 0*G + 2*H
        T = DoubleScalarMultiplication(secp256k1, 0, secp256k1.G, 2, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '03fad265e0a0178418d006e247204bcf42edb6b92188074c9134704c8686eed37a')
        T = pointMultiply(secp256k1, 2, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '03fad265e0a0178418d006e247204bcf42edb6b92188074c9134704c8686eed37a')
        
        # 0*G + 3*H
        T = DoubleScalarMultiplication(secp256k1, 0, secp256k1.G, 3, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '025ef47fcde840a435e831bbb711d466fc1ee160da3e15437c6c469a3a40daacaa')
        T = pointMultiply(secp256k1, 3, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '025ef47fcde840a435e831bbb711d466fc1ee160da3e15437c6c469a3a40daacaa')

        # 1*G+0*H
        T = DoubleScalarMultiplication(secp256k1, 1, secp256k1.G, 0, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        T = pointMultiply(secp256k1, 1, secp256k1.G)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')

        # 2*G+0*H
        T = DoubleScalarMultiplication(secp256k1, 2, secp256k1.G, 0, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
        T = pointMultiply(secp256k1, 2, secp256k1.G)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')

        # 3*G+0*H
        T = DoubleScalarMultiplication(secp256k1, 3, secp256k1.G, 0, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9')
        T = pointMultiply(secp256k1, 3, secp256k1.G)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9')

        # 0*G+5*H
        T = DoubleScalarMultiplication(secp256k1, 0, secp256k1.G, 5, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '039e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e')
        T = pointMultiply(secp256k1, 5, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '039e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e')

        # 0*G-5*H
        T = DoubleScalarMultiplication(secp256k1, 0, secp256k1.G, -5, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '029e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e')
        T = pointMultiply(secp256k1, -5, H)
        T = bytes_from_Point(secp256k1, T, True)
        self.assertEqual(T.hex(), '029e431be0851721f9ce35cc0f718fce7d6d970e3ddd796643d71294d7a09b554e')

        # 1*G-5*H
        U = DoubleScalarMultiplication(secp256k1, 1, secp256k1.G, -5, H)
        U = bytes_from_Point(secp256k1, U, True)
        self.assertEqual(U.hex(), '02b218ddacb34d827c71760e601b41d309bc888cf7e3ab7cc09ec082b645f77e5a')
        U = pointAdd(secp256k1, secp256k1.G, T) # reusing previous T value
        U = bytes_from_Point(secp256k1, U, True)
        self.assertEqual(U.hex(), '02b218ddacb34d827c71760e601b41d309bc888cf7e3ab7cc09ec082b645f77e5a')

        H = secondGenerator(secp256r1, sha256)
        H = secondGenerator(secp384r1, sha256)

    def test_opposite(self): 
        for ec in allcurves:
            # random point
            q = os.urandom(ec.bytesize)
            Q = pointMultiply(ec, q, ec.G)
            while Q == None:
                q = os.urandom(ec.bytesize)
                Q = pointMultiply(ec, q, ec.G)
            minus_Q = opposite(ec, Q)
            inf = pointAdd(ec, Q, minus_Q)
            self.assertEqual(inf, None)
            # jacobian coordinates
            Qjac = jac_from_affine(Q)
            minus_Qjac = opposite(ec, Qjac)
            inf = pointAddJacobian(ec, Qjac, minus_Qjac)
            self.assertEqual(inf, (1,1,0))

    # FIXME remove urandom from tests
    def test_quad_res(self):
        for ec in smallcurves:

            ## setup phase
            # compute quadratic residues
            hasRoot = set()
            hasRoot.add(1)

            for i in range(2, ec._p):
                hasRoot.add(i*i % ec._p)

            ## test phase

            # random point
            inf = True
            while inf:
                q = os.urandom(ec.bytesize)
                Q = pointMultiply(ec, q, ec.G)
                if Q is not None:
                    inf = False
        
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
            else:
                # cannot use yQuadraticResidue in this case
                self.assertTrue(ec._p % 4 == 1)
                yOdd = ec.yOdd(x, 1)
                yEven = ec.yOdd(x, 0)

                # in this case neither or both are quadratic residues
                self.assertRaises(AssertionError, ec.yQuadraticResidue, x, 1)
                self.assertRaises(AssertionError, ec.yQuadraticResidue, x, 0)
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
                    self.assertTrue(yOdd not in hasRoot and yEven not in hasRoot)
                    self.assertRaises(ValueError, mod_sqrt, yOdd, ec._p)
                    self.assertRaises(ValueError, mod_sqrt, yEven, ec._p)

    def test_affine_from_jac_conversion(self):
        for ec in allcurves:
            # random point
            q = os.urandom(ec.bytesize)
            Q = pointMultiply(ec, q, ec.G)
            checkQ = ec.affine_from_jac(jac_from_affine(Q))
            self.assertEqual(Q, checkQ)

    def test_AddJacobian(self):
        for ec in allcurves:
            q1 = os.urandom(ec.bytesize)
            Q1 = pointMultiply(ec, q1, ec.G)
            q2 = os.urandom(ec.bytesize)
            Q2 = pointMultiply(ec, q2, ec.G)
        
            # distinct points
            Q3 = pointAdd(ec, Q1, Q2)
            Q3jac = pointAddJacobian(ec, Q1, Q2) 
            Q3jac = ec.affine_from_jac(Q3jac)
        
            self.assertEqual(Q3, Q3jac)
            # point at infinity
            Q3 = pointAdd(ec, Q2, None)
            Q3jac = pointAddJacobian(ec, Q2, None)
            Q3jac = ec.affine_from_jac(Q3jac)
            self.assertEqual(Q3, Q3jac)
        
            # point doubling 
            Q3 = pointAdd(ec, Q1, Q1)
            Q3jac = pointAddJacobian(ec, Q1, Q1) 
            # affine coord
            Q3jac = ec.affine_from_jac(Q3jac)
        
            self.assertEqual(Q3, Q3jac)
            # opposite points
            Q1opp = opposite(ec, Q1)
            Q3 = pointAdd(ec, Q1, Q1opp)
            Q3jac = pointAddJacobian(ec, Q1, Q1opp) 
            # affine coord
            Q3jac = ec.affine_from_jac(Q3jac)
        
            self.assertEqual(Q3, Q3jac)
            # point in bytes format
            Q1 = pointMultiply(ec, q1, ec.G)
            if Q1 is not None: Q1 = b'\x02' + Q1[0].to_bytes(ec.bytesize, 'big')
            Q2 = pointMultiply(ec, q2, ec.G)
            if Q2 is not None: Q2 = b'\x03' + Q2[0].to_bytes(ec.bytesize, 'big')
        
            # distinct points
            Q3 = pointAdd(ec, Q1, Q2)
            Q3jac = pointAddJacobian(ec, Q1, Q2) 
            Q3jac = ec.affine_from_jac(Q3jac)
        
            self.assertEqual(Q3, Q3jac)
            # point at infinity
            Q3 = pointAdd(ec, Q2, None)
            Q3jac = pointAddJacobian(ec, Q2, None)
            Q3jac = ec.affine_from_jac(Q3jac)
            self.assertEqual(Q3, Q3jac)
        
            # point doubling 
            Q3 = pointAdd(ec, Q1, Q1)
            Q3jac = pointAddJacobian(ec, Q1, Q1) 
            # affine coord
            Q3jac = ec.affine_from_jac(Q3jac)
        
            self.assertEqual(Q3, Q3jac)
            # opposite points
            Q1opp = opposite(ec, Q1)
            Q3 = pointAdd(ec, Q1, Q1opp)
            Q3jac = pointAddJacobian(ec, Q1, Q1opp) 
            # affine coord
            Q3jac = ec.affine_from_jac(Q3jac)
        
            self.assertEqual(Q3, Q3jac)

    def test_MultiplyJacobian(self):
        for ec in allcurves:
            n = os.urandom(ec.bytesize)
        
            nQ = pointMultiply(ec, n, ec.G)
            nQjac = pointMultiplyJacobian(ec, n, ec.G)
            self.assertEqual(nQ, nQjac)

    def test_shamir(self):
        for ec in smallcurves:
            k1 = int.from_bytes(os.urandom(ec.bytesize), 'big')
            k2 = int.from_bytes(os.urandom(ec.bytesize), 'big')

            q = os.urandom(ec.bytesize)
            Q = pointMultiplyJacobian(ec, q, ec.G)

            shamir = DoubleScalarMultiplication(ec, k1, ec.G, k2, Q)
            std = pointAdd(ec, pointMultiplyJacobian(ec, k1, ec.G), pointMultiplyJacobian(ec, k2, Q))

            self.assertEqual(shamir, std)

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
