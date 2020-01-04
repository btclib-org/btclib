#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.curves import secp256k1 as ec
from btclib.utils import point_from_octets, octets_from_point, h160
from btclib.address import (p2pkh_address, h160_from_p2pkh_address,
                            p2sh_address, h160_from_p2sh_address)
from btclib.script import serialize


class TestAddresses(unittest.TestCase):

    def test_p2pkh_address_from_pubkey(self):
        # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        pub = '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'
        addr = p2pkh_address(pub)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        self.assertEqual(h160_from_p2pkh_address(addr), h160(pub))

        uncompressed_pub = octets_from_point(
            ec, point_from_octets(ec, pub), False)
        addr = p2pkh_address(uncompressed_pub)
        self.assertEqual(addr, b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')
        self.assertEqual(h160_from_p2pkh_address(addr), h160(uncompressed_pub))

        # trailing/leading spaces in string
        pub = '  0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'
        addr = p2pkh_address(pub)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        self.assertEqual(h160_from_p2pkh_address(addr), h160(pub))

        pub = '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352  '
        addr = p2pkh_address(pub)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        self.assertEqual(h160_from_p2pkh_address(addr), h160(pub))

        # p2pkh address for a network other than 'testnet'
        self.assertRaises(ValueError, h160_from_p2pkh_address, addr, 'testnet')
        # h160_from_p2pkh_address(addr, 'testnet')

    def test_p2sh_address_from_script(self):
        # https://medium.com/@darosior/bitcoin-raw-transactions-part-2-p2sh-94df206fee8d
        script = ['OP_2DUP', 'OP_EQUAL', 'OP_NOT', 'OP_VERIFY',
                  'OP_SHA1', 'OP_SWAP', 'OP_SHA1', 'OP_EQUAL']
        script_bytes = serialize(script)
        self.assertEqual(script_bytes.hex(), '6e879169a77ca787')

        addr = p2sh_address(script_bytes)
        self.assertEqual(addr, b'37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP')

        redeem_script_hash = h160_from_p2sh_address(addr)
        self.assertEqual(redeem_script_hash, h160(script_bytes))

        self.assertEqual(redeem_script_hash.hex(),
                         '4266fc6f2c2861d7fe229b279a79803afca7ba34')
        output_script = ['OP_HASH160', redeem_script_hash.hex(), 'OP_EQUAL']
        _ = serialize(output_script)

        # address with trailing/leading spaces
        redeem_script_hash2 = h160_from_p2sh_address(
            ' 37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP ')
        self.assertEqual(redeem_script_hash, redeem_script_hash2)

        # p2sh address for a network other than 'testnet'
        self.assertRaises(ValueError, h160_from_p2sh_address, addr, 'testnet')
        # h160_from_p2sh_address(addr, 'testnet')

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
