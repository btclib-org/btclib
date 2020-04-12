#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import bip32, slip32
from btclib.base58 import b58decode, b58encode
from btclib.base58address import (_b58segwitaddress, b58address_from_h160,
                                  h160_from_b58address, p2pkh, p2sh,
                                  p2wpkh_p2sh, p2wsh_p2sh)
from btclib.base58wif import wif_from_xprv
from btclib.bech32address import p2wpkh, witness_from_b32address
from btclib.curves import secp256k1 as ec
from btclib.script import encode
from btclib.secpoint import bytes_from_point, point_from_octets
from btclib.to_prvkey import prvkey_info_from_wif
from btclib.to_pubkey import bytes_from_pubkey, pubkey_info_from_prvkey
from btclib.utils import hash160, sha256


class TestAddresses(unittest.TestCase):

    def test_b58address_from_h160(self):
        addr = b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs'
        prefix, payload, _, _ = h160_from_b58address(addr)
        self.assertEqual(addr, b58address_from_h160(prefix, payload))

        addr = b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM'
        prefix, payload, _, _ = h160_from_b58address(addr)
        self.assertEqual(addr, b58address_from_h160(prefix, payload))

        addr = b'37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP'
        prefix, payload, _, _ = h160_from_b58address(addr)
        self.assertEqual(addr, b58address_from_h160(prefix, payload))

        # Invalid base58 address prefix b'\xbb'
        bad_prefix = b'\xbb'
        self.assertRaises(ValueError, b58address_from_h160, bad_prefix, payload)
        #b58address_from_h160(bad_prefix, payload)

    def test_p2pkh_from_wif(self):
        seed = b"00"*32  # better be random
        rxprv = bip32.rootxprv_from_seed(seed)
        path = "m/0h/0h/12"
        xprv = bip32.derive(rxprv, path)
        wif = wif_from_xprv(xprv)
        self.assertEqual(wif, b'KyLk7s6Z1FtgYEVp3bPckPVnXvLUWNCcVL6wNt3gaT96EmzTKZwP')
        pubkey, _ = pubkey_info_from_prvkey(wif)
        address = p2pkh(pubkey)
        xpub = bip32.xpub_from_xprv(xprv)
        address2 = slip32.address_from_xpub(xpub)
        self.assertEqual(address, address2)

        self.assertRaises(ValueError, wif_from_xprv, xpub)

    def test_p2pkh_from_pubkey(self):
        # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        pub = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
        addr = p2pkh(pub, True)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        _, h160, _, _ = h160_from_b58address(addr)
        self.assertEqual(h160, hash160(pub))

        uncompr_pub = bytes_from_point(point_from_octets(pub, ec), False, ec)
        addr = p2pkh(uncompr_pub, False)
        self.assertEqual(addr, b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')
        _, h160, _, _ = h160_from_b58address(addr)
        self.assertEqual(h160, hash160(uncompr_pub))

        # trailing/leading spaces in string
        pub = '  02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'
        addr = p2pkh(pub, True)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        _, h160, _, _ = h160_from_b58address(addr)
        self.assertEqual(h160, hash160(pub))

        pub = '02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352  '
        addr = p2pkh(pub, True)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')

    def test_p2sh_from_script(self):
        # https://medium.com/@darosior/bitcoin-raw-transactions-part-2-p2sh-94df206fee8d
        script = ['OP_2DUP', 'OP_EQUAL', 'OP_NOT', 'OP_VERIFY',
                  'OP_SHA1', 'OP_SWAP', 'OP_SHA1', 'OP_EQUAL']
        script_bytes = encode(script)
        self.assertEqual(script_bytes.hex(), '6e879169a77ca787')

        network = 'mainnet'
        addr = p2sh(script_bytes, network)
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
        _, h160, _, _ = h160_from_b58address(' 37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP ')
        self.assertEqual(redeem_script_hash, h160)

    def test_exceptions(self):

        # Invalid base58 address prefix b'\xf5'
        payload = b'\xf5'
        pubkey = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
        payload += hash160(pubkey)
        invalid_address = b58encode(payload)
        self.assertRaises(ValueError, h160_from_b58address, invalid_address)
        #_h160_from_b58address(invalid_address)

        # Invalid SEC pubkey length: 34-bytes
        self.assertRaises(ValueError, p2pkh, pubkey+'00', True)
        # p2pkh(pubkey+'00')

    def test_witness(self):

        pub = "03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        network = 'mainnet'
        b58addr = p2wpkh_p2sh(pub, network)
        _, h160, network2, is_script_hash = h160_from_b58address(b58addr)
        self.assertEqual(network2, network)
        self.assertEqual(is_script_hash, True)  #?!?!?
        self.assertEqual(len(h160), 20)

        pubkey, _ = bytes_from_pubkey(pub, True, network)
        b58addr = _b58segwitaddress(hash160(pubkey), network)
        _, h160_2, network2, is_script_hash = h160_from_b58address(b58addr)
        self.assertEqual(network2, network)
        self.assertEqual(is_script_hash, True)  #?!?!?
        self.assertEqual(len(h160), 20)
        self.assertEqual(h160.hex(), h160_2.hex())


        wscript = "a8a58c2d034b28bf90c8803f5a53f769a4"
        b58addr = p2wsh_p2sh(wscript, network)
        _, h160, network2, is_script_hash = h160_from_b58address(b58addr)
        self.assertEqual(network2, network)
        self.assertEqual(is_script_hash, True)  #?!?!?
        self.assertEqual(len(h160), 20)

        b58addr = _b58segwitaddress(sha256(wscript), network)
        _, h160_2, network2, is_script_hash = h160_from_b58address(b58addr)
        self.assertEqual(network2, network)
        self.assertEqual(is_script_hash, True)  #?!?!?
        self.assertEqual(len(h160), 20)
        self.assertEqual(h160.hex(), h160_2.hex())

        # Invalid witness program length (19)
        self.assertRaises(ValueError, _b58segwitaddress, h160[:-1], network)
        #_b58segwitaddress(h160[:-1], network)

    def test_address_from_wif(self):
        # uncompressed mainnet
        wif1 = "5J1geo9kcAUSM6GJJmhYRX1eZEjvos9nFyWwPstVziTVueRJYvW"
        pubkey, network = pubkey_info_from_prvkey(wif1)
        b58 = p2pkh(pubkey)
        self.assertEqual(b58, b'1LPM8SZ4RQDMZymUmVSiSSvrDfj1UZY9ig')
        self.assertRaises(ValueError, p2wpkh, pubkey)
        self.assertRaises(ValueError, p2wpkh_p2sh, pubkey)

        # compressed mainnet
        wif2 = "Kx621phdUCp6sgEXPSHwhDTrmHeUVrMkm6T95ycJyjyxbDXkr162"
        pubkey, network = pubkey_info_from_prvkey(wif2)
        b58 = p2pkh(pubkey)
        self.assertEqual(b58, b'1HJC7kFvXHepkSzdc8RX6khQKkAyntdfkB')
        b32 = p2wpkh(pubkey)
        self.assertEqual(h160_from_b58address(b58)[1:], witness_from_b32address(b32)[1:])
        h160 = h160_from_b58address(b58)[1]
        b = p2wpkh_p2sh(pubkey)
        self.assertEqual(hash160(b'\x00\x14'+h160), h160_from_b58address(b)[1])

        self.assertEqual(prvkey_info_from_wif(wif1)[0], prvkey_info_from_wif(wif2)[0])

        # uncompressed testnet
        wif1 = "91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2"
        pubkey, network = pubkey_info_from_prvkey(wif1)
        b58 = p2pkh(pubkey, None, network)
        self.assertEqual(b58, b'mvgbzkCSgKbYgaeG38auUzR7otscEGi8U7')
        self.assertRaises(ValueError, p2wpkh, pubkey)
        self.assertRaises(ValueError, p2wpkh_p2sh, pubkey)

        # compressed testnet
        wif2 = "cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx"
        pubkey, network = pubkey_info_from_prvkey(wif2)
        b58 = p2pkh(pubkey, None, network)
        self.assertEqual(b58, b'n1KSZGmQgB8iSZqv6UVhGkCGUbEdw8Lm3Q')
        b32 = p2wpkh(pubkey, network)
        self.assertEqual(h160_from_b58address(b58)[1:], witness_from_b32address(b32)[1:])
        h160 = h160_from_b58address(b58)[1]
        b = p2wpkh_p2sh(pubkey, network)
        self.assertEqual(hash160(b'\x00\x14'+h160), h160_from_b58address(b)[1])

        self.assertEqual(prvkey_info_from_wif(wif1)[0], prvkey_info_from_wif(wif2)[0])

        # uncompressed mainnet, trailing/leading spaces in string
        wif1 = "  5J1geo9kcAUSM6GJJmhYRX1eZEjvos9nFyWwPstVziTVueRJYvW"
        pubkey, network = pubkey_info_from_prvkey(wif1)
        b58 = p2pkh(pubkey)
        self.assertEqual(b58, b'1LPM8SZ4RQDMZymUmVSiSSvrDfj1UZY9ig')
        self.assertRaises(ValueError, p2wpkh, pubkey)
        self.assertRaises(ValueError, p2wpkh_p2sh, pubkey)

        # compressed mainnet, trailing/leading spaces in string
        wif2 = "Kx621phdUCp6sgEXPSHwhDTrmHeUVrMkm6T95ycJyjyxbDXkr162  "
        pubkey, network = pubkey_info_from_prvkey(wif2)
        b58 = p2pkh(pubkey)
        self.assertEqual(b58, b'1HJC7kFvXHepkSzdc8RX6khQKkAyntdfkB')
        b32 = p2wpkh(pubkey)
        self.assertEqual(h160_from_b58address(b58)[1:], witness_from_b32address(b32)[1:])
        h160 = h160_from_b58address(b58)[1]
        b = p2wpkh_p2sh(pubkey)
        self.assertEqual(hash160(b'\x00\x14'+h160), h160_from_b58address(b)[1])


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
