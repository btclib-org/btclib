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
from btclib.ec import EC, pointMult, DblScalarMult, \
    _jac_from_aff, _pointMultJacobian, _pointMultAffine
from btclib.ecurves import secp256k1, secp256r1, secp384r1, secp160r1, \
    all_curves, low_card_curves, ec23_31
from btclib.ecutils import point2octets, octets2point

 
Inf = 1, 0  # Infinity point in affine coordinates
InfJ = 1, 1, 0  # Infinity point in jacobian coordinates


class TestEllipticCurve(unittest.TestCase):
    def test_exceptions(self):
        # good
        EC(11, 2, 7, (6, 9), 7, 2, 0, False)

        # p not odd
        self.assertRaises(ValueError, EC, 10, 2, 7, (6, 9),    7, 2, 0, False)

        # p not prime
        self.assertRaises(ValueError, EC, 15, 2, 7, (6, 9),    7, 2, 0, False)

        # zero discriminant
        self.assertRaises(ValueError, EC, 11, 7, 7, (6, 9),    7, 2, 0, False)

        # G not Tuple (int, int)
        self.assertRaises(ValueError, EC, 11, 2, 7, (6, 9, 1), 7, 2, 0, False)

        # G not on curve
        self.assertRaises(ValueError, EC, 11, 2, 7, (7, 9),    7, 2, 0, False)

        # n not prime
        self.assertRaises(ValueError, EC, 11, 2, 7, (6, 9),    8, 2, 0, False)

        # n not Hesse
        self.assertRaises(ValueError, EC, 11, 2, 7, (6, 9),   71, 2, 0, True)

        # n not group order
        self.assertRaises(ValueError, EC, 11, 2, 7, (6, 9),   13, 2, 0, False)

        # n=p -> weak curve
        # missing

        # weak curve
        self.assertRaises(UserWarning, EC, 11, 2, 7, (6, 9), 7, 2, 0, True)

        # according to SEC 1 for 80 bits of security
        # the curve should provide 192 bits
        # secp160r1 fails this requirement
        ec = secp160r1
        p = ec._p
        a = ec._a
        b = ec._b
        G = ec.G
        n = ec.n
        t = ec.t
        h = ec.h
        self.assertRaises(UserWarning, EC, p, a, b, G, n, h, t)

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

            Gbytes = point2octets(ec, ec.G, True)
            G2 = octets2point(ec, Gbytes)
            self.assertEqual(ec.G, G2)

            Gbytes = point2octets(ec, ec.G, False)
            G2 = octets2point(ec, Gbytes)
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
            if ec in low_card_curves or ec.bytesize < 24:
                ec_repr = ec_repr[:-1] + ", False)"
            ec2 = eval(ec_repr)
            self.assertEqual(str(ec), str(ec2))

    def test_octets2point(self):
        for ec in all_curves:
            bytesize = ec.bytesize
            Q = pointMult(ec, ec._p, ec.G)

            Q_bytes = (b'\x03' if (Q[1] & 1) else b'\x02') + Q[0].to_bytes(bytesize, "big")
            R = octets2point(ec, Q_bytes)
            self.assertEqual(R, Q)
            self.assertEqual(point2octets(ec, R, True), Q_bytes)

            Q_hex_str = Q_bytes.hex()
            R = octets2point(ec, Q_hex_str)
            self.assertEqual(R, Q)

            Q_bytes = b'\x04' + Q[0].to_bytes(bytesize, "big") + Q[1].to_bytes(bytesize, "big")
            R = octets2point(ec, Q_bytes)
            self.assertEqual(R, Q)
            self.assertEqual(point2octets(ec, R, False), Q_bytes)

            Q_hex_str = Q_bytes.hex()
            R = octets2point(ec, Q_hex_str)
            self.assertEqual(R, Q)

            # infinity point
            self.assertEqual(octets2point(ec, b'\x00'), Inf)
            self.assertEqual(point2octets(ec, Inf, True),  b'\x00')
            self.assertEqual(point2octets(ec, Inf, False), b'\x00')
            Inf_hex_str = b'\x00'.hex()
            self.assertEqual(octets2point(ec, Inf_hex_str), Inf)

            # scalar in point multiplication can be int, str, or bytes
            t = tuple()
            self.assertRaises(TypeError, pointMult, ec, t, ec.G)

            # not a compressed point
            Q_bytes = b'\x01' * (bytesize+1)
            self.assertRaises(ValueError, octets2point, ec, Q_bytes)
            # not a point
            Q_bytes += b'\x01'
            self.assertRaises(ValueError, octets2point, ec, Q_bytes)
            # not an uncompressed point
            Q_bytes = b'\x01' * 2 * (bytesize+1)
            self.assertRaises(ValueError, octets2point, ec, Q_bytes)
        
        # invalid x coordinate
        ec = secp256k1
        x = 0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
        xstr = format(x, '32X')
        self.assertRaises(ValueError, octets2point, ec, "03" + xstr)
        self.assertRaises(ValueError, octets2point, ec, "04" + xstr + xstr)
        self.assertRaises(ValueError, point2octets, ec, (x, x), True)
        self.assertRaises(ValueError, point2octets, ec, (x, x), False)
        P = [x, x]
        self.assertRaises(TypeError, ec.isOnCurve, P)
        P = (x, x, x)
        self.assertRaises(ValueError, ec.isOnCurve, P)
        P = (x, ec._p+1)
        self.assertRaises(ValueError, ec.isOnCurve, P)


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
        for ec in low_card_curves:

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
        for ec in low_card_curves:
            Gjac = _jac_from_aff(ec.G)
            for q in range(ec.n):
                Q = _pointMultAffine(ec, q, ec.G)
                Qjac = _pointMultJacobian(ec, q, Gjac)
                Q2 = ec._affine_from_jac(Qjac)
                self.assertEqual(Q, Q2)
        # with last curve
        self.assertEqual(Inf, _pointMultAffine(ec, 3, Inf))
        self.assertEqual(InfJ, _pointMultJacobian(ec, 3, InfJ))

    def test_shamir(self):
        ec = ec23_31
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
