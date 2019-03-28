#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from hashlib import sha1 as hf

from btclib.curve import mult
from btclib.curves import secp160r1 as ec
from btclib.utils import point_from_octets, octets_from_point, octets_from_int
from btclib import dh

class TestEcdh(unittest.TestCase):
    def test_ecdh(self):
        keydatasize = 20

        dU = 0x1
        QU = mult(ec, dU, ec.G)
        dV = 0x2
        QV = mult(ec, dV, ec.G)

        keyingdataU = dh.key_agreement(dU, QV, keydatasize, ec, hf)
        keyingdataV = dh.key_agreement(dV, QU, keydatasize, ec, hf)
        self.assertEqual(keyingdataU, keyingdataV)

    def test_key_deployment(self):
        """ GEC 2: Test Vectors for SEC 1, section 4.1

            http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
        """

        # 4.1.1
        # ec = secp160r1
        # hf = sha1

        # 4.1.2
        dU = 971761939728640320549601132085879836204587084162
        self.assertEqual(format(dU, str(ec.psize)+'x'),
                         'aa374ffc3ce144e6b073307972cb6d57b2a4e982')
        QU = mult(ec, dU, ec.G)
        self.assertEqual(QU, (466448783855397898016055842232266600516272889280, 1110706324081757720403272427311003102474457754220))
        self.assertEqual(octets_from_point(ec, QU, True).hex(),
                         '0251b4496fecc406ed0e75a24a3c03206251419dc0')

        # 4.1.3
        dV = 399525573676508631577122671218044116107572676710
        self.assertEqual(format(dV, str(ec.psize)+'x'),
                         '45fb58a92a17ad4b15101c66e74f277e2b460866')
        QV = mult(ec, dV, ec.G)
        self.assertEqual(QV, (420773078745784176406965940076771545932416607676, 221937774842090227911893783570676792435918278531))
        self.assertEqual(octets_from_point(ec, QV, True).hex(),
                         '0349b41e0e9c0369c2328739d90f63d56707c6e5bc')

        # expected results
        z_exp = 1155982782519895915997745984453282631351432623114
        zstr = 'ca7c0f8c3ffa87a96e1b74ac8e6af594347bb40a'
        keydatasize = 20
        keying_data_exp = '744ab703f5bc082e59185f6d049d2d367db245c2'

        # 4.1.4
        z, _ = mult(ec, dU, QV)
        self.assertEqual(z, z_exp)
        self.assertEqual(format(z, str(ec.psize)+'x'), zstr)
        keyingdata = dh.kdf(octets_from_int(z, ec.psize), keydatasize, ec, hf)
        self.assertEqual(keyingdata.hex(), keying_data_exp)

        # 4.1.5
        z, _ = mult(ec, dV, QU)
        self.assertEqual(z, z_exp)
        self.assertEqual(format(z, str(ec.psize)+'x'), zstr)
        keyingdata = dh.kdf(octets_from_int(z, ec.psize), keydatasize, ec, hf)
        self.assertEqual(keyingdata.hex(), keying_data_exp)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
