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
from typing import List

from btclib.numbertheory import mod_sqrt
from btclib.curve import Curve, Point, mult, double_mult, \
    _jac_from_aff, _mult_jac, _mult_aff, multi_mult
from btclib.curves import secp256k1, secp256r1, secp384r1, secp160r1, \
    secp112r1, all_curves, low_card_curves, ec23_31
from btclib.utils import octets_from_point, point_from_octets
from btclib.pedersen import second_generator

random.seed(42)
 
Inf = Point()  # Infinity point in affine coordinates
InfJ = 1, 1, 0  # Infinity point in jacobian coordinates


class TestEllipticCurve(unittest.TestCase):
    def test_exceptions(self):
        # good
        Curve(11, 2, 7, (6, 9), 7, 2, 0, False)

        # p not odd
        self.assertRaises(ValueError, Curve, 10, 2, 7, (6, 9),    7, 1, 0, False)

        # p not prime
        self.assertRaises(ValueError, Curve, 15, 2, 7, (6, 9),    7, 1, 0, False)

        # required security level not in the allowed range
        ec = secp112r1
        p = ec._p
        a = ec._a
        b = ec._b
        G = ec.G
        n = ec.n
        t = ec.t
        h = ec.h
        self.assertRaises(UserWarning, Curve, p, a, b, G, n, h, 273)
        #Curve(p, a, b, G, n, h, 273)

        # not enough bits for required security level
        ec = secp160r1
        p = ec._p
        a = ec._a
        b = ec._b
        G = ec.G
        n = ec.n
        t = ec.t
        h = ec.h
        self.assertRaises(UserWarning, Curve, p, a, b, G, n, h, 2*t)
        #Curve(p, a, b, G, n, h, 2*t)

        # a > p
        self.assertRaises(ValueError, Curve, 11, 12, 7, (6, 9),   13, 1, 0, False)

        # b > p
        self.assertRaises(ValueError, Curve, 11, 2, 12, (6, 9),   13, 1, 0, False)

        # zero discriminant
        self.assertRaises(ValueError, Curve, 11, 7, 7, (6, 9),    7, 1, 0, False)

        # G not Tuple (int, int)
        self.assertRaises(ValueError, Curve, 11, 2, 7, (6, 9, 1), 7, 1, 0, False)

        # G not on curve
        self.assertRaises(ValueError, Curve, 11, 2, 7, (7, 9),    7, 1, 0, False)

        # n not prime
        self.assertRaises(ValueError, Curve, 11, 2, 7, (6, 9),    8, 1, 0, False)

        # n not Hesse
        self.assertRaises(ValueError, Curve, 11, 2, 7, (6, 9),   71, 1, 0, True)

        # h not as expected
        self.assertRaises(ValueError, Curve, 11, 2, 7, (6, 9),   7, 1, 0, True)
        #Curve(11, 2, 7, (6, 9), 7, 1, 0, True)

        # n not group order
        self.assertRaises(ValueError, Curve, 11, 2, 7, (6, 9),   13, 1, 0, False)

        # n=p -> weak curve
        # missing

        # weak curve
        self.assertRaises(UserWarning, Curve, 11, 2, 7, (6, 9), 7, 2, 0, True)

        # x-coordinate not in [0, p-1]
        self.assertRaises(ValueError, secp256k1.y, secp256k1._p)
        #secp256k1.y(secp256k1._p)


    def test_all_curves(self):
        for ec in all_curves:
            self.assertEqual(mult(ec, 0, ec.G), Inf)
            self.assertEqual(mult(ec, 0, ec.G), Inf)

            self.assertEqual(mult(ec, 1, ec.G), ec.G)
            self.assertEqual(mult(ec, 1, ec.G), ec.G)

            Gy_odd = ec.y_odd(ec.G[0], True)
            self.assertEqual(Gy_odd % 2, 1)
            Gy_even = ec.y_odd(ec.G[0], False)
            self.assertEqual(Gy_even % 2, 0)
            self.assertTrue(ec.G[1] in (Gy_odd, Gy_even))

            Gbytes = octets_from_point(ec, ec.G, True)
            G2 = point_from_octets(ec, Gbytes)
            self.assertEqual(ec.G, G2)

            Gbytes = octets_from_point(ec, ec.G, False)
            G2 = point_from_octets(ec, Gbytes)
            self.assertEqual(ec.G, G2)

            P = ec.add(Inf, ec.G)
            self.assertEqual(P, ec.G)
            P = ec.add(ec.G, Inf)
            self.assertEqual(P, ec.G)
            P = ec.add(Inf, Inf)
            self.assertEqual(P, Inf)

            P = ec.add(ec.G, ec.G)
            self.assertEqual(P, mult(ec, 2, ec.G))

            P = mult(ec, ec.n-1, ec.G)
            self.assertEqual(ec.add(P, ec.G), Inf)
            self.assertEqual(mult(ec, ec.n, ec.G), Inf)

            self.assertEqual(mult(ec, 0, Inf), Inf)
            self.assertEqual(mult(ec, 1, Inf), Inf)
            self.assertEqual(mult(ec, 25, Inf), Inf)

            ec_repr = repr(ec)
            if ec in low_card_curves or ec.psize < 24:
                ec_repr = ec_repr[:-1] + ", False)"
            ec2 = eval(ec_repr)
            self.assertEqual(str(ec), str(ec2))

    def test_octets2point(self):
        for ec in all_curves:
            Q = mult(ec, ec._p, ec.G)  # just a random point, not Inf

            Q_bytes = b'\x03' if Q[1] & 1 else b'\x02'
            Q_bytes += Q[0].to_bytes(ec.psize, "big")
            R = point_from_octets(ec, Q_bytes)
            self.assertEqual(R, Q)
            self.assertEqual(octets_from_point(ec, R, True), Q_bytes)

            Q_hex_str = Q_bytes.hex()
            R = point_from_octets(ec, Q_hex_str)
            self.assertEqual(R, Q)

            Q_bytes = b'\x04' + Q[0].to_bytes(ec.psize, "big")
            Q_bytes += Q[1].to_bytes(ec.psize, "big")
            R = point_from_octets(ec, Q_bytes)
            self.assertEqual(R, Q)
            self.assertEqual(octets_from_point(ec, R, False), Q_bytes)

            Q_hex_str = Q_bytes.hex()
            R = point_from_octets(ec, Q_hex_str)
            self.assertEqual(R, Q)

            # infinity point
            self.assertEqual(point_from_octets(ec, b'\x00'), Inf)
            self.assertEqual(octets_from_point(ec, Inf, True),  b'\x00')
            self.assertEqual(octets_from_point(ec, Inf, False), b'\x00')
            Inf_hex_str = b'\x00'.hex()
            self.assertEqual(point_from_octets(ec, Inf_hex_str), Inf)

            # scalar in point multiplication can be int, str, or bytes
            t = tuple()
            self.assertRaises(TypeError, mult, ec, t, ec.G)

            # not a compressed point
            Q_bytes = b'\x01' * (ec.psize+1)
            self.assertRaises(ValueError, point_from_octets, ec, Q_bytes)
            # not a point
            Q_bytes += b'\x01'
            self.assertRaises(ValueError, point_from_octets, ec, Q_bytes)
            # not an uncompressed point
            Q_bytes = b'\x01' * 2 * (ec.psize+1)
            self.assertRaises(ValueError, point_from_octets, ec, Q_bytes)
        
        # invalid x coordinate
        ec = secp256k1
        x = 0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
        xstr = format(x, '32X')
        self.assertRaises(ValueError, point_from_octets, ec, "03" + xstr)
        self.assertRaises(ValueError, point_from_octets, ec, "04" + xstr + xstr)
        self.assertRaises(ValueError, octets_from_point, ec, (x, x), True)
        self.assertRaises(ValueError, octets_from_point, ec, (x, x), False)

        # Point must be a tuple[int, int]
        P = x, x, x
        self.assertRaises(ValueError, ec.is_on_curve, P)

        # y-coordinate not in (0, p)
        P = x, ec._p+1
        self.assertRaises(ValueError, ec.is_on_curve, P)

    def test_opposite(self):
        for ec in all_curves:
            Q = mult(ec, ec._p, ec.G)  # just a random point, not Inf
            minus_Q = ec.opposite(Q)
            self.assertEqual(ec.add(Q, minus_Q), Inf)
            # jacobian coordinates
            Qjac = _jac_from_aff(Q)
            minus_Qjac = _jac_from_aff(minus_Q)
            self.assertEqual(ec._add_jac(Qjac, minus_Qjac)[2], 0)

            # opposite of Inf is Inf
            minus_Inf = ec.opposite(Inf)
            self.assertEqual(minus_Inf, Inf)

    def test_symmetry(self):
        """Methods to break simmetry: quadratic residue, odd/even, low/high"""
        for ec in low_card_curves:

            # setup phase
            # compute quadratic residues
            hasRoot = set()
            hasRoot.add(1)

            for i in range(2, ec._p):
                hasRoot.add(i*i % ec._p)

            # test phase
            Q = mult(ec, ec._p, ec.G)  # just a random point, not Inf
            x = Q[0]
            if ec._p % 4 == 3:
                quad_res = ec.y_quadratic_residue(x, True)
                not_quad_res = ec.y_quadratic_residue(x, False)
                # in this case only quad_res is a quadratic residue
                self.assertIn(quad_res, hasRoot)
                root = mod_sqrt(quad_res, ec._p)
                self.assertEqual(quad_res, (root*root) % ec._p)
                root = ec._p - root
                self.assertEqual(quad_res, (root*root) % ec._p)

                self.assertTrue(not_quad_res == ec._p - quad_res)
                self.assertNotIn(not_quad_res, hasRoot)
                self.assertRaises(ValueError, mod_sqrt, not_quad_res, ec._p)

                y_odd = ec.y_odd(x, True)
                self.assertTrue(y_odd in (quad_res, not_quad_res))
                self.assertTrue(y_odd % 2 == 1)
                y_even = ec.y_odd(x, False)
                self.assertTrue(y_even in (quad_res, not_quad_res))
                self.assertTrue(y_even % 2 == 0)

                y_low = ec.y_low(x, True)
                self.assertTrue(y_low in (y_odd, y_even))
                y_high = ec.y_low(x, False)
                self.assertTrue(y_high in (y_odd, y_even))
                self.assertTrue(y_low < y_high)
            else:
                self.assertTrue(ec._p % 4 == 1)
                # cannot use y_quadratic_residue in this case
                self.assertRaises(ValueError, ec.y_quadratic_residue, x, True)
                self.assertRaises(ValueError, ec.y_quadratic_residue, x, False)

                y_odd = ec.y_odd(x, True)
                self.assertTrue(y_odd % 2 == 1)
                y_even = ec.y_odd(x, False)
                self.assertTrue(y_even % 2 == 0)
                # in this case neither or both are quadratic residues
                self.assertTrue((y_odd in hasRoot and y_even in hasRoot) or
                                (y_odd not in hasRoot and y_even not in hasRoot))
                if y_odd in hasRoot:  # both have roots
                    root = mod_sqrt(y_odd, ec._p)
                    self.assertEqual(y_odd, (root*root) % ec._p)
                    root = ec._p - root
                    self.assertEqual(y_odd, (root*root) % ec._p)
                    root = mod_sqrt(y_even, ec._p)
                    self.assertEqual(y_even, (root*root) % ec._p)
                    root = ec._p - root
                    self.assertEqual(y_even, (root*root) % ec._p)
                else:
                    self.assertRaises(ValueError, mod_sqrt, y_odd, ec._p)
                    self.assertRaises(ValueError, mod_sqrt, y_even, ec._p)

                y_low = ec.y_low(x, True)
                self.assertTrue(y_low in (y_odd, y_even))
                y_high = ec.y_low(x, False)
                self.assertTrue(y_high in (y_odd, y_even))
                self.assertTrue(y_low < y_high)
        
        # with the last curve
        self.assertRaises(ValueError, ec.y_low, x, 2)
        self.assertRaises(ValueError, ec.y_odd, x, 2)
        self.assertRaises(ValueError, ec.y_quadratic_residue, x, 2)

    def test_aff_jac_conversions(self):
        for ec in all_curves:
            Q = mult(ec, ec._p, ec.G)  # random point
            checkQ = ec._aff_from_jac(_jac_from_aff(Q))
            self.assertEqual(Q, checkQ)
        # with only the last curve
        checkInf = ec._aff_from_jac(_jac_from_aff(Inf))
        self.assertEqual(Inf, checkInf)

    def test_add(self):
        for ec in all_curves:
            Q1 = mult(ec, ec._p, ec.G)  # just a random point, not Inf
            Q1J = _jac_from_aff(Q1)

            # distinct points
            Q3 = ec._add_aff(Q1,  ec.G)
            Q3jac = ec._add_jac(Q1J, ec.GJ)
            self.assertEqual(Q3, ec._aff_from_jac(Q3jac))

            # point at infinity
            Q3 = ec._add_aff(ec.G,  Inf)
            Q3jac = ec._add_jac(ec.GJ, InfJ)
            self.assertEqual(Q3, ec._aff_from_jac(Q3jac))
            Q3 = ec._add_aff(Inf,  ec.G)
            Q3jac = ec._add_jac(InfJ, ec.GJ)
            self.assertEqual(Q3, ec._aff_from_jac(Q3jac))

            # point doubling
            Q3 = ec._add_aff(Q1,  Q1)
            Q3jac = ec._add_jac(Q1J, Q1J)
            self.assertEqual(Q3, ec._aff_from_jac(Q3jac))

            # opposite points
            Q1opp = ec.opposite(Q1)
            Q3 = ec._add_aff(Q1,  Q1opp)
            Q3jac = ec._add_jac(Q1J, _jac_from_aff(Q1opp))
            self.assertEqual(Q3, ec._aff_from_jac(Q3jac))

    def test_mult(self):
        for ec in low_card_curves:
            for q in range(ec.n):
                Q = _mult_aff(ec, q, ec.G)
                Qjac = _mult_jac(ec, q, ec.GJ)
                Q2 = ec._aff_from_jac(Qjac)
                self.assertEqual(Q, Q2)
        # with last curve
        self.assertEqual(Inf, _mult_aff(ec, 3, Inf))
        self.assertEqual(InfJ, _mult_jac(ec, 3, InfJ))

    def test_shamir(self):
        ec = ec23_31
        for k1 in range(ec.n):
            for k2 in range(ec.n):
                shamir = double_mult(ec, k1, ec.G, k2, ec.G)
                std = ec.add(mult(ec, k1, ec.G),
                             mult(ec, k2, ec.G))
                self.assertEqual(shamir, std)
                shamir = double_mult(ec, k1, Inf, k2, ec.G)
                std = ec.add(mult(ec, k1, Inf),
                             mult(ec, k2, ec.G))
                self.assertEqual(shamir, std)
                shamir = double_mult(ec, k1, ec.G, k2, Inf)
                std = ec.add(mult(ec, k1, ec.G),
                             mult(ec, k2, Inf))
                self.assertEqual(shamir, std)

    def test_boscoster(self):
        ec = secp256k1

        k: List[int] = list()
        ksum = 0
        for i in range(11):
            k.append(random.getrandbits(ec.nlen) % ec.n)
            ksum += k[i]

        P = [ec.G] * len(k)
        boscoster = multi_mult(ec, k, P)
        self.assertEqual(boscoster, mult(ec, ksum, ec.G))

        # mismatch between scalar length and Points length
        P = [ec.G] * (len(k)-1)
        self.assertRaises(ValueError, multi_mult, ec, k, P)
        #boscoster = multi_mult(ec, k, P)

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
