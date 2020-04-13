#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.base58address import b58address_from_h160
from btclib.bech32address import b32address_from_witness
from btclib.network import p2pkh_prefix_from_network
from btclib.script import decode, encode
from btclib.scriptpubkey import (address_from_scriptPubKey, nulldata, p2ms,
                                 p2pk, payload_from_scriptPubKey,
                                 scriptPubKey_from_address,
                                 scriptPubKey_from_payload)
from btclib.utils import hash160, sha256

# TODO reorder these tests

class TestScriptPubKey(unittest.TestCase):

    def test_p2pk(self):
        # https://learnmeabitcoin.com/guide/p2pk
        # script = [pubkey, 'OP_CHECKSIG']
        pubkey = "04 ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414 e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c"
        scriptPubKey = p2pk(pubkey)
        self.assertEqual(scriptPubKey.hex(), "4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac")
        # no address for this script

        # Wrong size (33-bytes) for uncompressed SEC key
        pubkey = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        self.assertRaises(ValueError, p2pk, pubkey)
        #p2pk(pubkey)

    def test_p2pkh(self):
        # https://learnmeabitcoin.com/guide/p2pkh
        # script = ['OP_DUP', 'OP_HASH160', pubkey_hash.hex(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']

        pubkey_hash = "12ab8dc588ca9d5787dde7eb29569da63c3a238c"
        scriptPubKey = scriptPubKey_from_payload(pubkey_hash, 'p2pkh')
        self.assertEqual(scriptPubKey.hex(), "76a91412ab8dc588ca9d5787dde7eb29569da63c3a238c88ac")

        hash, scriptPubKey_type, _ = payload_from_scriptPubKey(scriptPubKey)
        self.assertEqual(hash.hex(), pubkey_hash)
        self.assertEqual(scriptPubKey_type, "p2pkh")

        network = 'mainnet'
        addr = address_from_scriptPubKey(scriptPubKey, network)
        prefix = p2pkh_prefix_from_network(network)
        self.assertEqual(addr, b58address_from_h160(prefix, pubkey_hash))

        scriptPubKey2, network2 = scriptPubKey_from_address(addr)
        self.assertEqual(scriptPubKey2, scriptPubKey)
        self.assertEqual(network2, network)

        # Invalid size: 11 bytes instead of 20
        self.assertRaises(ValueError, scriptPubKey_from_payload, "00"*11, 'p2pkh')
        #p2pkh("00"*11)

    def test_p2ms(self):
        # https://learnmeabitcoin.com/guide/p2ms
        # script = [1, pubkey, pubKey2, 2, 'OP_CHECKMULTISIG']
        pubkey1 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        pubkey2 = "04 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765 19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
        scriptPubKey = p2ms(1, [pubkey1, pubkey2], False)
        self.assertEqual(scriptPubKey.hex(), "514104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af52ae")
        # no address for this script

        # Impossible 3-of-2 multisignature
        self.assertRaises(ValueError, p2ms, 3, (pubkey1, pubkey2))
        #p2ms(3, [pubkey1, pubkey2])

        # Invalid m (0) in m-of-n multisignature
        self.assertRaises(ValueError, p2ms, 0, (pubkey1, pubkey2))
        #p2ms(0, (pubkey1, pubkey2))

        # Wrong size (66-bytes) for uncompressed SEC key
        self.assertRaises(ValueError, p2ms, 1, (pubkey1+"00", pubkey2))
        #p2ms(1, (pubkey1+"00", pubkey2))

        # Invalid n (17) in 3-of-17 multisignature
        self.assertRaises(ValueError, p2ms, 3, [pubkey1]*17)
        #p2ms(3, [pubkey1]*17)

    def test_p2sh(self):
        # https://learnmeabitcoin.com/guide/p2sh
        # script = ['OP_HASH160', redeem_script_hash.hex(), 'OP_EQUAL']

        script_hash = "748284390f9e263a4b766a75d0633c50426eb875"
        scriptPubKey = scriptPubKey_from_payload(script_hash, 'p2sh')
        self.assertEqual(scriptPubKey.hex(), "a914748284390f9e263a4b766a75d0633c50426eb87587")

        hash, scriptPubKey_type, _ = payload_from_scriptPubKey(scriptPubKey)
        self.assertEqual(hash.hex(), script_hash)
        self.assertEqual(scriptPubKey_type, "p2sh")

        network = 'mainnet'
        addr = address_from_scriptPubKey(scriptPubKey, network)
        self.assertEqual(addr.decode(), "3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V")

        scriptPubKey2, network2 = scriptPubKey_from_address(addr)
        self.assertEqual(scriptPubKey2, scriptPubKey)
        self.assertEqual(network2, network)

        # Invalid size: 21 bytes instead of 20
        self.assertRaises(ValueError, scriptPubKey_from_payload, "00"*21, 'p2sh')
        #scriptPubKey_from_payload("00"*21, 'p2sh')

    def test_nulldata(self):
        # https://learnmeabitcoin.com/guide/nulldata
        # script = ['OP_RETURN', data.hex()]

        string = "hello world"
        data = string.encode()
        self.assertEqual(data.hex(), "68656c6c6f20776f726c64")
        scriptPubKey = scriptPubKey_from_payload(data, 'nulldata')
        self.assertEqual(scriptPubKey.hex(), "6a0b68656c6c6f20776f726c64")

        hash, scriptPubKey_type, _ = payload_from_scriptPubKey(scriptPubKey)
        self.assertEqual(hash.hex(), data.hex())
        self.assertEqual(scriptPubKey_type, "nulldata")
        self.assertEqual(hash.decode(), string)

        # no address for this script
        scriptPubKey2 = nulldata(string)
        self.assertEqual(scriptPubKey, scriptPubKey2)

        string = "charley loves heidi"
        data = string.encode()
        self.assertEqual(data.hex(), "636861726c6579206c6f766573206865696469")
        scriptPubKey = scriptPubKey_from_payload(data, 'nulldata')
        self.assertEqual(scriptPubKey.hex(), "6a13636861726c6579206c6f766573206865696469")

        hash, scriptPubKey_type, _ = payload_from_scriptPubKey(scriptPubKey)
        self.assertEqual(hash.hex(), data.hex())
        self.assertEqual(scriptPubKey_type, "nulldata")
        self.assertEqual(hash.decode(), string)

        # no address for this script
        scriptPubKey2 = nulldata(string)
        self.assertEqual(scriptPubKey, scriptPubKey2)

        string = "家族も友達もみんなが笑顔の毎日がほしい"
        data = string.encode()
        self.assertEqual(data.hex(), "e5aeb6e6978fe38282e58f8be98194e38282e381bfe38293e381aae3818ce7ac91e9a194e381aee6af8ee697a5e3818ce381bbe38197e38184")
        scriptPubKey = scriptPubKey_from_payload(data, 'nulldata')
        self.assertEqual(scriptPubKey.hex(), "6a39e5aeb6e6978fe38282e58f8be98194e38282e381bfe38293e381aae3818ce7ac91e9a194e381aee6af8ee697a5e3818ce381bbe38197e38184")

        hash, scriptPubKey_type, _ = payload_from_scriptPubKey(scriptPubKey)
        self.assertEqual(hash.hex(), data.hex())
        self.assertEqual(scriptPubKey_type, "nulldata")
        self.assertEqual(hash.decode(), string)

        # no address for this script
        scriptPubKey2 = nulldata(string)
        self.assertEqual(scriptPubKey, scriptPubKey2)

        # Invalid data lenght (81 bytes) for nulldata scriptPubKey
        data = '00'*81
        self.assertRaises(ValueError, scriptPubKey_from_payload, data, 'nulldata')
        #scriptPubKey_from_payload(data, 'nulldata')

    def test_selfconsistency0(self):

        # OP_RETURN
        string = "time-stamped data"
        data = string.encode()
        scriptPubKey = scriptPubKey_from_payload(data, 'nulldata')
        scriptPubKey2 = nulldata(string)
        self.assertEqual(scriptPubKey, scriptPubKey2)
        script = decode(scriptPubKey)
        script_exp = ['OP_RETURN', data.hex()]
        self.assertEqual(script, script_exp)
        hash, scriptPubKey_type, _ = payload_from_scriptPubKey(scriptPubKey)
        self.assertEqual(hash.hex(), data.hex())
        self.assertEqual(scriptPubKey_type, "nulldata")
        self.assertEqual(hash.decode(), string)

    def test_selfconsistency1(self):

        # p2pk
        pubkey = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        scriptPubKey = p2pk(pubkey)
        script = decode(scriptPubKey)
        script_exp = [pubkey, 'OP_CHECKSIG']
        self.assertEqual(script, script_exp)

    def test_selfconsistency2(self):

        # multi-sig (lexicographically sorted)
        pubkey1 = "0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
        pubkey2 = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        scriptPubKey = p2ms(1, (pubkey1, pubkey2))
        script = decode(scriptPubKey)
        script_exp = [1, pubkey1, pubkey2, 2, 'OP_CHECKMULTISIG']
        self.assertEqual(script, script_exp)

    def test_selfconsistency3(self):

        # p2pkh
        pubkey = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        pubkey_hash = hash160(pubkey)
        scriptPubKey = scriptPubKey_from_payload(pubkey_hash, 'p2pkh')
        script = decode(scriptPubKey)
        script_exp = ['OP_DUP', 'OP_HASH160', pubkey_hash.hex(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']
        self.assertEqual(script, script_exp)

    def test_selfconsistency4(self):

        # p2sh (p2pkh-p2sh)
        pubkey = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        pubkey_hash = hash160(pubkey)
        scriptPubKey = scriptPubKey_from_payload(pubkey_hash, 'p2pkh')

        redeem_script_hash = hash160(scriptPubKey)
        scriptPubKey = scriptPubKey_from_payload(redeem_script_hash, 'p2sh')
        script = decode(scriptPubKey)
        script_exp = ['OP_HASH160', redeem_script_hash.hex(), 'OP_EQUAL']
        self.assertEqual(script, script_exp)

    def test_selfconsistency5(self):

        # p2wpkh
        pubkey = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        pubkey_hash = hash160(pubkey)
        scriptPubKey = scriptPubKey_from_payload(pubkey_hash,'p2wpkh')
        self.assertEqual(scriptPubKey.hex(), "0014"+pubkey_hash.hex())
        script = decode(scriptPubKey)
        script_exp = [0, pubkey_hash.hex()]
        self.assertEqual(script, script_exp)

    def test_selfconsistency6(self):

        # p2wsh
        pubkey = "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        script = [pubkey, 'OP_CHECKSIG']
        script_bytes = encode(script)
        script_hash = sha256(script_bytes)
        scriptPubKey = scriptPubKey_from_payload(script_hash, 'p2wsh')
        self.assertEqual(scriptPubKey.hex(), "0020" + script_hash.hex())
        script = decode(scriptPubKey)
        script_exp = [0, script_hash.hex()]
        self.assertEqual(script, script_exp)

    def test_exceptions(self):

        # Invalid size: 11 bytes instead of 20
        self.assertRaises(ValueError, scriptPubKey_from_payload, "00"*11, 'p2wpkh')
        #scriptPubKey_from_payload("00"*11, 'p2wpkh')

        # Invalid size: 33 bytes instead of 32
        self.assertRaises(ValueError, scriptPubKey_from_payload, "00"*33, 'p2wsh')
        #scriptPubKey_from_payload("00"*33, 'p2wsh')

    def test_CLT(self):

        vault_pubkeys = [b'\x00'*33, b'\x11'*33, b'\x22'*33]
        recovery_pubkeys = [b'\x77'*33, b'\x88'*33, b'\x99'*33]

        script = [
            'OP_IF',
                2, *vault_pubkeys, 3, 'OP_CHECKMULTISIG',
            'OP_ELSE',
                500, 'OP_CHECKLOCKTIMEVERIFY', 'OP_DROP',
                2, *recovery_pubkeys, 3, 'OP_CHECKMULTISIG',
            'OP_ENDIF'
        ]
        witness_program = encode(script)
        witness_hash = sha256(witness_program)
        scriptPubKey = scriptPubKey_from_payload(witness_hash, 'p2wsh')
        self.assertEqual(scriptPubKey.hex(), "00207b5310339c6001f75614daa5083839fa54d46165f6c56025cc54d397a85a5708")
        address = b32address_from_witness(0, witness_hash)
        self.assertEqual(address, b"bc1q0df3qvuuvqqlw4s5m2jsswpelf2dgct97mzkqfwv2nfe02z62uyq7n4zjj")

    def test_address_scriptPubKey(self):

        pubkey = "03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        pubkey_hash = hash160(pubkey).hex()

        script = [0, pubkey_hash]
        addr = address_from_scriptPubKey(script)
        scriptPubKey, _ = scriptPubKey_from_address(addr)
        self.assertEqual(scriptPubKey, encode(script))

        script = [
            'OP_DUP', 'OP_HASH160', pubkey_hash,
            'OP_EQUALVERIFY', 'OP_CHECKSIG'
        ]
        addr = address_from_scriptPubKey(script)
        scriptPubKey, _ = scriptPubKey_from_address(addr)
        self.assertEqual(scriptPubKey, encode(script))

        script_hash = hash160(scriptPubKey).hex()
        script = ['OP_HASH160',script_hash, 'OP_EQUAL']
        addr = address_from_scriptPubKey(script)
        scriptPubKey, _ = scriptPubKey_from_address(addr)
        self.assertEqual(scriptPubKey, encode(script))

        script_hash = sha256(scriptPubKey).hex()
        script = [0, script_hash]
        addr = address_from_scriptPubKey(script)
        scriptPubKey, _ = scriptPubKey_from_address(addr)
        self.assertEqual(scriptPubKey, encode(script))

        # Unknown script
        script = [16, pubkey_hash]
        self.assertRaises(ValueError, address_from_scriptPubKey, script)
        #address_from_scriptPubKey(script)

        # Unhandled witness version (16)
        wp = hash160(pubkey)[2:]
        addr = b32address_from_witness(16, wp)
        self.assertRaises(ValueError, scriptPubKey_from_address, addr)
        # scriptPubKey_from_address(addr)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
