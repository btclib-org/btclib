#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.base58address import b58address_from_h160, b58encode
from btclib.bech32address import b32address_from_witness
from btclib.network import _NETWORKS, _P2PKH_PREFIXES
from btclib.script import OP_CODE_NAMES, OP_CODES, decode, encode, serialize
from btclib.scriptpubkey import (address_from_scriptPubKey,
                                 nulldata_scriptPubKey, p2ms_scriptPubKey,
                                 p2pk_scriptPubKey, p2pkh_scriptPubKey,
                                 p2sh_scriptPubKey, p2wpkh_scriptPubKey,
                                 p2wsh_scriptPubKey, scriptPubKey_from_address)
from btclib.utils import hash160, sha256


class TestScriptPubKey(unittest.TestCase):

    def test_p2pk(self):
        # https://learnmeabitcoin.com/guide/p2pk
        # opcodes = [pubkey, 'OP_CHECKSIG']
        pubkey = "04 ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414 e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c"
        opcodes = p2pk_scriptPubKey(pubkey)
        scriptPubKey = encode(opcodes)
        self.assertEqual(scriptPubKey.hex(), "4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac")
        # no address for this script

    def test_p2pkh(self):
        # https://learnmeabitcoin.com/guide/p2pkh
        # opcodes = ['OP_DUP', 'OP_HASH160', pubkey_hash.hex(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']

        pubkey_hash = "12ab8dc588ca9d5787dde7eb29569da63c3a238c"
        opcodes = p2pkh_scriptPubKey(pubkey_hash)
        scriptPubKey = encode(opcodes)
        self.assertEqual(scriptPubKey.hex(), "76a91412ab8dc588ca9d5787dde7eb29569da63c3a238c88ac")
        addr = address_from_scriptPubKey(scriptPubKey)
        prefix = _P2PKH_PREFIXES[_NETWORKS.index('mainnet')]
        self.assertEqual(addr, b58address_from_h160(prefix, pubkey_hash))

        # Wrong size (33-bytes) for uncompressed SEC key
        pubkey = "03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        self.assertRaises(ValueError, p2pk_scriptPubKey, pubkey)
        #p2pk_scriptPubKey(pubkey)

        # Invalid size: 11 bytes instead of 20
        self.assertRaises(ValueError, p2pkh_scriptPubKey, "00"*11)
        #p2pkh_scriptPubKey("00"*11)

    def test_p2ms(self):
        # https://learnmeabitcoin.com/guide/p2ms
        # opcodes = [1, pubkey, pubKey2, 2, 'OP_CHECKMULTISIG']
        pubkey1 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        pubkey2 = "04 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765 19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
        opcodes = p2ms_scriptPubKey(1, [pubkey1, pubkey2])
        scriptPubKey = encode(opcodes)
        self.assertEqual(scriptPubKey.hex(), "514104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af52ae")
        # no address for this script

        # Impossible 3-of-2 multisignature
        self.assertRaises(ValueError, p2ms_scriptPubKey, 3, (pubkey1, pubkey2))
        #p2ms_scriptPubKey(3, [pubkey1, pubkey2])

        # Invalid m (0) in m-of-n multisignature
        self.assertRaises(ValueError, p2ms_scriptPubKey, 0, (pubkey1, pubkey2))
        #p2ms_scriptPubKey(0, (pubkey1, pubkey2))

        # Wrong size (66-bytes) for uncompressed SEC key
        self.assertRaises(ValueError, p2ms_scriptPubKey, 1, (pubkey1+"00", pubkey2))
        #p2ms_scriptPubKey(1, (pubkey1+"00", pubkey2))

        # Invalid n (17) in 3-of-17 multisignature
        self.assertRaises(ValueError, p2ms_scriptPubKey, 3, [pubkey1]*17)
        #p2ms_scriptPubKey(3, [pubkey1]*17)

    def test_p2sh(self):
        # https://learnmeabitcoin.com/guide/p2sh
        # opcodes = ['OP_HASH160', redeem_script_hash.hex(), 'OP_EQUAL']

        redeem_script_hash = "748284390f9e263a4b766a75d0633c50426eb875"
        opcodes = p2sh_scriptPubKey(redeem_script_hash)
        scriptPubKey = encode(opcodes)
        self.assertEqual(scriptPubKey.hex(), "a914748284390f9e263a4b766a75d0633c50426eb87587")
        addr = address_from_scriptPubKey(scriptPubKey)
        self.assertEqual(addr.decode(), "3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V")

        # Invalid size: 21 bytes instead of 20
        self.assertRaises(ValueError, p2sh_scriptPubKey, "00"*21)
        #p2sh_scriptPubKey("00"*21)

    def test_nulldata(self):
        # https://learnmeabitcoin.com/guide/nulldata
        # opcodes = ['OP_RETURN', data.hex()]

        data = "hello world".encode().hex()
        self.assertEqual(data, "68656c6c6f20776f726c64")
        opcodes = nulldata_scriptPubKey(data)
        scriptPubKey = encode(opcodes)
        self.assertEqual(scriptPubKey.hex(), "6a0b68656c6c6f20776f726c64")
        # no address for this script

        data = "charley loves heidi".encode().hex()
        self.assertEqual(data, "636861726c6579206c6f766573206865696469")
        opcodes = nulldata_scriptPubKey(data)
        scriptPubKey = encode(opcodes)
        self.assertEqual(scriptPubKey.hex(), "6a13636861726c6579206c6f766573206865696469")
        # no address for this script

        data = "家族も友達もみんなが笑顔の毎日がほしい".encode().hex()
        self.assertEqual(data, "e5aeb6e6978fe38282e58f8be98194e38282e381bfe38293e381aae3818ce7ac91e9a194e381aee6af8ee697a5e3818ce381bbe38197e38184")
        opcodes = nulldata_scriptPubKey(data)
        scriptPubKey = encode(opcodes)
        self.assertEqual(scriptPubKey.hex(), "6a39e5aeb6e6978fe38282e58f8be98194e38282e381bfe38293e381aae3818ce7ac91e9a194e381aee6af8ee697a5e3818ce381bbe38197e38184")
        # no address for this script

        # Invalid data lenght (81 bytes) for nulldata scriptPubKey
        data = '00'*81
        self.assertRaises(ValueError, nulldata_scriptPubKey, data)
        #nulldata_scriptPubKey(data)

    def test_selfconsistency(self):

        # OP_RETURN
        data = "time-stamped data".encode().hex()
        # opcodes = ['OP_RETURN', data.hex()]
        opcodes = nulldata_scriptPubKey(data)
        scriptPubKey = encode(opcodes)
        opcodes2 = decode(scriptPubKey)
        self.assertEqual(opcodes, opcodes2)

        # p2pk
        pubkey = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        # opcodes = [pubkey, 'OP_CHECKSIG']
        opcodes = p2pk_scriptPubKey(pubkey)
        scriptPubKey = encode(opcodes)
        opcodes2 = decode(scriptPubKey)
        self.assertEqual(opcodes, opcodes2)

        # multi-sig
        pubkey2 = "04 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765 19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
        # opcodes = [1, pubkey, pubKey2, 2, 'OP_CHECKMULTISIG']
        opcodes = p2ms_scriptPubKey(1, (pubkey, pubkey2))
        scriptPubKey = encode(opcodes)
        opcodes2 = decode(scriptPubKey)
        self.assertEqual(opcodes, opcodes2)

        # p2pkh
        pubkey_hash = hash160(pubkey).hex()
        # opcodes = ['OP_DUP', 'OP_HASH160', pubkey_hash.hex(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']
        opcodes = p2pkh_scriptPubKey(pubkey_hash)
        scriptPubKey = encode(opcodes)
        opcodes2 = decode(scriptPubKey)
        self.assertEqual(opcodes, opcodes2)

        # p2sh (p2pkh-p2sh)
        redeem_script_hash = hash160(scriptPubKey).hex()
        # opcodes = ['OP_HASH160', redeem_script_hash.hex(), 'OP_EQUAL']
        opcodes = p2sh_scriptPubKey(redeem_script_hash)
        scriptPubKey = encode(opcodes)
        opcodes2 = decode(scriptPubKey)
        self.assertEqual(opcodes, opcodes2)

        # p2wpkh
        # opcodes = [0, pubkey_hash.hex()]
        opcodes = p2wpkh_scriptPubKey(pubkey_hash)
        scriptPubKey = encode(opcodes)
        self.assertEqual(scriptPubKey.hex(), "0014"+pubkey_hash)
        opcodes2 = decode(scriptPubKey)
        self.assertEqual(opcodes, opcodes2)

        # p2wsh
        witness_script = [pubkey, 'OP_CHECKSIG']
        witness_script_bytes = encode(witness_script)
        witness_script_hash = sha256(witness_script_bytes)
        # opcodes = [0, witness_script_hash.hex()]
        opcodes = p2wsh_scriptPubKey(witness_script_hash.hex())
        scriptPubKey = encode(opcodes)
        self.assertEqual(scriptPubKey.hex(), "0020"+witness_script_hash.hex())
        opcodes2 = decode(scriptPubKey)
        self.assertEqual(opcodes, opcodes2)

    def test_exceptions(self):

        # Invalid size: 11 bytes instead of 20
        self.assertRaises(ValueError, p2wpkh_scriptPubKey, "00"*11)
        #p2wpkh_scriptPubKey("00"*11)

        # Invalid size: 33 bytes instead of 32
        self.assertRaises(ValueError, p2wsh_scriptPubKey, "00"*33)
        #p2wsh_scriptPubKey("00"*33)

    def test_CLT(self):

        vault_pubkeys = [b'\x00'*33, b'\x11'*33, b'\x22'*33]
        recovery_pubkeys = [b'\x77'*33, b'\x88'*33, b'\x99'*33]

        opcodes = [
            'OP_IF',
                2, *vault_pubkeys, 3, 'OP_CHECKMULTISIG',
            'OP_ELSE',
                500, 'OP_CHECKLOCKTIMEVERIFY', 'OP_DROP',
                2, *recovery_pubkeys, 3, 'OP_CHECKMULTISIG',
            'OP_ENDIF'
        ]
        witness_program = encode(opcodes)
        witness_hash = sha256(witness_program)

        script_pubkey = p2wsh_scriptPubKey(witness_hash)
        self.assertEqual(encode(script_pubkey).hex(), "00207b5310339c6001f75614daa5083839fa54d46165f6c56025cc54d397a85a5708")
        address = b32address_from_witness(0, witness_hash)
        self.assertEqual(address, b"bc1q0df3qvuuvqqlw4s5m2jsswpelf2dgct97mzkqfwv2nfe02z62uyq7n4zjj")

    def test_address_scriptPubKey(self):

        pubkey = "03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        pubkey_hash = hash160(pubkey).hex()

        opcodes = [0, pubkey_hash]
        address_from_scriptPubKey(opcodes)
        opcodes2, _ = scriptPubKey_from_address(address_from_scriptPubKey(opcodes))
        self.assertEqual(opcodes, opcodes2)

        opcodes = ['OP_DUP', 'OP_HASH160', pubkey_hash, 'OP_EQUALVERIFY', 'OP_CHECKSIG']
        opcodes2, _ = scriptPubKey_from_address(address_from_scriptPubKey(opcodes))
        self.assertEqual(opcodes, opcodes2)

        script_hash = hash160(encode(opcodes)).hex()
        opcodes = ['OP_HASH160',script_hash, 'OP_EQUAL']
        opcodes2, _ = scriptPubKey_from_address(address_from_scriptPubKey(opcodes))
        self.assertEqual(opcodes, opcodes2)

        script_hash = sha256(encode(opcodes)).hex()
        opcodes = [0, script_hash]
        opcodes2, _ = scriptPubKey_from_address(address_from_scriptPubKey(opcodes))
        self.assertEqual(opcodes, opcodes2)

        # Unknown script
        opcodes = [16, pubkey_hash]
        self.assertRaises(ValueError, address_from_scriptPubKey, opcodes)
        #address_from_scriptPubKey(opcodes)

        # Unhandled witness version (16)
        wp = hash160(pubkey)[2:]
        addr = b32address_from_witness(16, wp)
        self.assertRaises(ValueError, scriptPubKey_from_address, addr)
        # scriptPubKey_from_address(addr)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
