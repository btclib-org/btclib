#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.base58 import b58decode, b58encode
from btclib.base58address import (_b58segwitaddress,
                                  h160_from_b58address, p2pkh_address,
                                  p2sh_address, p2wpkh_p2sh_address,
                                  p2wsh_p2sh_address)
from btclib.curves import secp256k1 as ec
from btclib.script import encode
from btclib.utils import (h160_from_pubkey, hash160, sha256,
                          octets_from_point, point_from_octets)


class TestAddresses(unittest.TestCase):

    def test_p2pkh_address_from_pubkey(self):
        # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        pub = '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'
        addr = p2pkh_address(pub)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        _, hash2, _, _ = h160_from_b58address(addr)
        self.assertEqual(hash2, hash160(pub))

        uncompressed_pub = octets_from_point(
            point_from_octets(pub, ec), False, ec)
        addr = p2pkh_address(uncompressed_pub)
        self.assertEqual(addr, b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')
        _, hash2, _, _ = h160_from_b58address(addr)
        self.assertEqual(hash2, hash160(uncompressed_pub))

        # trailing/leading spaces in string
        pub = '  0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'
        addr = p2pkh_address(pub)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        _, hash2, _, _ = h160_from_b58address(addr)
        self.assertEqual(hash2, hash160(pub))

        pub = '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352  '
        addr = p2pkh_address(pub)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')

    def test_p2sh_address_from_script(self):
        # https://medium.com/@darosior/bitcoin-raw-transactions-part-2-p2sh-94df206fee8d
        script = ['OP_2DUP', 'OP_EQUAL', 'OP_NOT', 'OP_VERIFY',
                  'OP_SHA1', 'OP_SWAP', 'OP_SHA1', 'OP_EQUAL']
        script_bytes = encode(script)
        self.assertEqual(script_bytes.hex(), '6e879169a77ca787')

        network = 'mainnet'
        addr = p2sh_address(script_bytes, network)
        self.assertEqual(addr, b'37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP')

        _, redeem_script_hash, network2, is_p2sh = h160_from_b58address(addr)
        self.assertEqual(network, network2)
        self.assertTrue(is_p2sh)
        self.assertEqual(redeem_script_hash, hash160(script_bytes))

        self.assertEqual(redeem_script_hash.hex(),
                         '4266fc6f2c2861d7fe229b279a79803afca7ba34')
        output_script = ['OP_HASH160', redeem_script_hash.hex(), 'OP_EQUAL']
        _ = encode(output_script)

        # address with trailing/leading spaces
        _, h2, _, _ = h160_from_b58address(' 37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP ')
        self.assertEqual(redeem_script_hash, h2)

    def test_exceptions(self):

        # Invalid base58 address prefix b'\xf5'
        payload = b'\xf5'
        pubkey = '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'
        payload += hash160(pubkey)
        invalid_address = b58encode(payload)
        self.assertRaises(ValueError, h160_from_b58address, invalid_address)
        #_h160_from_b58address(invalid_address)

        # Invalid SEC pubkey length: 34-bytes
        self.assertRaises(ValueError, p2pkh_address, pubkey+'00')
        # p2pkh_address(pubkey+'00')

    def test_witness(self):

        pub = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        b58addr = p2wpkh_p2sh_address(pub)
        _, h160, network, is_script_hash = h160_from_b58address(b58addr)
        self.assertEqual(network, 'mainnet')
        self.assertEqual(is_script_hash, True)  #?!?!?
        self.assertEqual(len(h160), 20)

        b58addr = _b58segwitaddress(h160_from_pubkey(pub))
        _, h160_2, network, is_script_hash = h160_from_b58address(b58addr)
        self.assertEqual(network, 'mainnet')
        self.assertEqual(is_script_hash, True)  #?!?!?
        self.assertEqual(len(h160), 20)
        self.assertEqual(h160.hex(), h160_2.hex())


        wscript = "a8a58c2d034b28bf90c8803f5a53f769a4"
        b58addr = p2wsh_p2sh_address(wscript)
        _, h160, network, is_script_hash = h160_from_b58address(b58addr)
        self.assertEqual(network, 'mainnet')
        self.assertEqual(is_script_hash, True)  #?!?!?
        self.assertEqual(len(h160), 20)

        b58addr = _b58segwitaddress(sha256(wscript))
        _, h160_2, network, is_script_hash = h160_from_b58address(b58addr)
        self.assertEqual(network, 'mainnet')
        self.assertEqual(is_script_hash, True)  #?!?!?
        self.assertEqual(len(h160), 20)
        self.assertEqual(h160.hex(), h160_2.hex())

        # Invalid witness program length (19)
        self.assertRaises(ValueError, _b58segwitaddress, h160[:-1])
        #_b58segwitaddress(h160[:-1])


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
