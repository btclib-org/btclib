#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.scriptpubkey` module."

import json
import unittest
from os import path

from btclib import base58address, bech32address
from btclib.base58address import (
    address_from_scriptPubKey,
    b58address_from_h160,
    b58address_from_witness,
    scriptPubKey_from_address,
)
from btclib.bech32address import b32address_from_witness
from btclib.network import NETWORKS
from btclib.script import decode, encode
from btclib.scriptpubkey import (
    nulldata,
    p2ms,
    p2pk,
    p2pkh,
    p2sh,
    p2wpkh,
    p2wsh,
    payload_from_scriptPubKey,
    scriptPubKey_from_payload,
)
from btclib.utils import hash160, sha256


class TestScriptPubKey(unittest.TestCase):
    def test_p2pk(self):

        script_type = "p2pk"

        # self-consistency
        pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
        script = encode([pubkey, "OP_CHECKSIG"]).hex()

        # straight to the scriptPubKey
        scriptPubKey = p2pk(pubkey)
        assert scriptPubKey.hex() == script

        # to the scriptPubKey in two steps (through payload)
        scriptPubKey = scriptPubKey_from_payload(script_type, pubkey)
        assert scriptPubKey.hex() == script

        # back from the scriptPubKey to the payload
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert 0 == m2
        assert bytes.fromhex(pubkey).hex() == payload2.hex()
        script_type2, payload2, m2 = payload_from_scriptPubKey(script)
        assert script_type == script_type2
        assert 0 == m2
        assert bytes.fromhex(pubkey).hex() == payload2.hex()

        # data -> payload in this case is invertible (no hash functions)

        # No address for p2pk script
        self.assertRaises(ValueError, address_from_scriptPubKey, scriptPubKey)
        # address_from_scriptPubKey(scriptPubKey)

        # documented test case: https://learnmeabitcoin.com/guide/p2pk
        pubkey = (
            "04"
            "ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414"
            "e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c"
        )
        script = "41" + pubkey + "ac"
        scriptPubKey = p2pk(pubkey)
        assert scriptPubKey.hex() == script

        # invalid size: 34 bytes instead of (33, 65)
        # fmt: off
        pubkey = (
            "03"
            "ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414"
            "14"
        )
        # fmt: on
        self.assertRaises(ValueError, p2pk, pubkey)
        # p2pk(pubkey)

    def test_p2ms(self):

        script_type = "p2ms"

        # self-consistency
        pubkey1 = (
            "04"
            "cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
            "f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        )
        pubkey2 = (
            "04"
            "61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765"
            "19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
        )
        pubkeys = [bytes.fromhex(pubkey1), bytes.fromhex(pubkey2)]
        m = 1

        # straight to the scriptPubKey
        scriptPubKey = p2ms(pubkeys, m)
        n = len(pubkeys)
        script = encode([m] + sorted(pubkeys) + [n, "OP_CHECKMULTISIG"]).hex()
        assert scriptPubKey.hex() == script

        # to the scriptPubKey in two steps (through payload)
        scriptPubKey = scriptPubKey_from_payload(script_type, pubkeys, m)
        assert scriptPubKey.hex() == script

        # back from the scriptPubKey to the payload
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert m == m2
        assert sorted(pubkeys) == payload2
        script_type2, payload2, m2 = payload_from_scriptPubKey(script)
        assert script_type == script_type2
        assert m == m2
        assert sorted(pubkeys) == payload2

        # data -> payload in this case is invertible (no hash functions)

        # No address for p2ms script
        self.assertRaises(ValueError, address_from_scriptPubKey, scriptPubKey)
        # address_from_scriptPubKey(scriptPubKey)

        # documented test case: https://learnmeabitcoin.com/guide/p2ms
        pubkeys = [bytes.fromhex(pubkey1), bytes.fromhex(pubkey2)]
        m = 1
        n = 2
        # fmt: off
        script = (
            "51"         # OP_1
            "41"         # canonical 65-bytes push
            + pubkey1 +  # noqa E148
            "41"         # canonical 65-bytes push
            + pubkey2 +  # noqa E148
            "52"         # OP_2
            "ae"         # OP_CHECKMULTISIG
        )
        # fmt: on
        scriptPubKey = p2ms(pubkeys, 1, lexicographic_sort=False)
        assert scriptPubKey.hex() == script

        # Impossible m>n 3-of-2 multisignature
        self.assertRaises(ValueError, p2ms, pubkeys, 3)
        # p2ms(pubkeys, 3)

        # Invalid m (0) for p2ms script
        self.assertRaises(ValueError, p2ms, pubkeys, 0)
        # p2ms(pubkeys, 0)

        # invalid size: 66 bytes instead of 65
        self.assertRaises(ValueError, p2ms, [pubkey1 + "00", pubkey2], 1)
        # p2ms([pubkey1 + "00", pubkey2], 1)

        # Invalid n (17) in 3-of-17 multisignature
        self.assertRaises(ValueError, p2ms, [pubkey1] * 17, 3)
        # p2ms([pubkey1]*17, 3)

        # Invalid key length (66) in p2ms
        badpubkeys = sorted(pubkeys)
        badpubkeys[0] = badpubkeys[0] + b"\x00"
        self.assertRaises(
            ValueError, scriptPubKey_from_payload, script_type, badpubkeys, m
        )
        # scriptPubKey_from_payload(script_type, badpubkeys, m)

        # Invalid key length (66) in p2ms
        script = encode([m] + sorted(badpubkeys) + [n, "OP_CHECKMULTISIG"])
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

        # Invalid key in p2ms
        script = encode([m] + [0, pubkeys[1]] + [n, "OP_CHECKMULTISIG"])
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

        # Invalid m (0) for p2ms script
        self.assertRaises(
            ValueError, scriptPubKey_from_payload, script_type, pubkeys, 17
        )
        # scriptPubKey_from_payload(script_type, pubkeys, 17)

    def test_p2ms_2(self):

        pubkey1 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        pubkey2 = "04 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765 19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
        pubkey3 = "04 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        pubkeys = [pubkey1, pubkey2, pubkey3]
        m = 1
        n = len(pubkeys)
        script = [m] + pubkeys + [n, "OP_CHECKMULTISIG"]
        payload_from_scriptPubKey(script)
        scriptPubKey_from_payload("p2ms", pubkeys, m)

        # Invalid list of Octets for p2sh script
        self.assertRaises(ValueError, scriptPubKey_from_payload, "p2sh", pubkeys, 0)
        # scriptPubKey_from_payload('p2sh', pubkeys, 0)

        # Invalid number of keys (0) in m-of-n multisignature
        script = [1, 3, "OP_CHECKMULTISIG"]
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

        # Keys (2) / n (3) mismatch in m-of-n multisignature
        script = [1, pubkey1, pubkey2, 3, "OP_CHECKMULTISIG"]
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

        # Impossible 3-of-2 multisignature
        script = [3, pubkey1, pubkey2, 2, "OP_CHECKMULTISIG"]
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

        # Invalid m (0) in 0-of-2 multisignature
        script = [0, pubkey1, pubkey2, 2, "OP_CHECKMULTISIG"]
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

        # 133-th byte in 1-of-3 multisignature payload is 0x40,
        # it should have been 0x41
        script = [1, pubkey1, pubkey2, pubkey3, 3, "OP_CHECKMULTISIG"]
        bscript = encode(script)
        script = bscript[:133] + b"\x40" + bscript[134:]
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

    def test_nulldata(self):

        script_type = "nulldata"

        # self-consistency
        string = "time-stamped data"
        payload = string.encode()
        script = encode(["OP_RETURN", payload]).hex()

        # straight to the scriptPubKey
        scriptPubKey = nulldata(string)
        assert scriptPubKey.hex() == script

        # to the scriptPubKey in two steps (through payload)
        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script

        # back from the scriptPubKey to the payload
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()
        script_type2, payload2, m2 = payload_from_scriptPubKey(script)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()

        # data -> payload in this case is invertible (no hash functions)
        assert payload.decode() == string

        # No address for null data script
        self.assertRaises(ValueError, address_from_scriptPubKey, scriptPubKey)
        # address_from_scriptPubKey(scriptPubKey)

        # documented test cases: https://learnmeabitcoin.com/guide/nulldata
        string = "hello world"
        payload = string.encode().hex()
        assert payload == "68656c6c6f20776f726c64"
        script = "6a0b" + payload
        scriptPubKey = nulldata(string)
        assert scriptPubKey.hex() == script
        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert 0 == m2
        assert payload == payload2.hex()

        # documented test cases: https://learnmeabitcoin.com/guide/nulldata
        string = "charley loves heidi"
        payload = string.encode().hex()
        assert payload == "636861726c6579206c6f766573206865696469"
        script = "6a13" + payload
        scriptPubKey = nulldata(string)
        assert scriptPubKey.hex() == script
        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert 0 == m2
        assert payload == payload2.hex()

        # documented test cases: https://learnmeabitcoin.com/guide/nulldata
        string = "家族も友達もみんなが笑顔の毎日がほしい"
        payload = string.encode().hex()
        assert (
            payload
            == "e5aeb6e6978fe38282e58f8be98194e38282e381bfe38293e381aae3818ce7ac91e9a194e381aee6af8ee697a5e3818ce381bbe38197e38184"
        )
        script = "6a39" + payload
        scriptPubKey = nulldata(string)
        assert scriptPubKey.hex() == script
        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert 0 == m2
        assert payload == payload2.hex()

    def test_nulldata3(self):

        # Invalid data lenght (81 bytes) for nulldata scriptPubKey
        payload = "00" * 81
        self.assertRaises(ValueError, scriptPubKey_from_payload, "nulldata", payload)
        # scriptPubKey_from_payload('nulldata', payload)

        # Wrong data lenght (32) in 35-bytes nulldata script:
        # it should have been 33
        script = encode(["OP_RETURN", b"\x00" * 33])
        script = script[:1] + b"\x20" + script[2:]
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

        # Wrong data lenght (32) in 83-bytes nulldata script:
        # it should have been 80
        script = encode(["OP_RETURN", b"\x00" * 80])
        script = script[:2] + b"\x20" + script[3:]
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

        # Missing OP_PUSHDATA1 (0x4c) in 83-bytes nulldata script,
        # got 0x20 instead
        script = encode(["OP_RETURN", b"\x00" * 80])
        script = script[:1] + b"\x20" + script[2:]
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

        assert len(encode(["OP_RETURN", b"\x00" * 75])) == 77
        assert len(encode(["OP_RETURN", b"\x00" * 76])) == 79
        # Invalid 78 bytes OP_RETURN script length
        script = encode(["OP_RETURN", b"\x00" * 76])[:-1]
        self.assertRaises(ValueError, payload_from_scriptPubKey, script)
        # payload_from_scriptPubKey(script)

    def test_p2pkh(self):

        script_type = "p2pkh"

        # self-consistency
        pubkey = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
        payload = hash160(pubkey)
        script = encode(
            ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
        ).hex()

        # straight to the scriptPubKey
        scriptPubKey = p2pkh(pubkey)
        assert scriptPubKey.hex() == script

        # to the scriptPubKey in two steps (through payload)
        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script

        # back from the scriptPubKey to the payload
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()
        script_type2, payload2, m2 = payload_from_scriptPubKey(script)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()

        # data -> payload is not invertible (hash functions)

        # address
        network = "mainnet"
        address = base58address.p2pkh(pubkey, network)
        address2 = address_from_scriptPubKey(scriptPubKey, network)
        assert address == address2
        prefix = NETWORKS[network]["p2pkh"]
        address2 = b58address_from_h160(prefix, payload, network)
        assert address == address2

        scriptPubKey2, network2 = scriptPubKey_from_address(address)
        assert scriptPubKey2 == scriptPubKey
        assert network2 == network

        # documented test case: https://learnmeabitcoin.com/guide/p2pkh
        payload = "12ab8dc588ca9d5787dde7eb29569da63c3a238c"
        script = "76a914" + payload + "88ac"
        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script
        network = "mainnet"
        address = b"12higDjoCCNXSA95xZMWUdPvXNmkAduhWv"
        address2 = address_from_scriptPubKey(scriptPubKey, network)
        assert address == address2
        scriptPubKey2, network2 = scriptPubKey_from_address(address)
        assert scriptPubKey2 == scriptPubKey
        assert network2 == network

        # invalid size: 11 bytes instead of 20
        self.assertRaises(ValueError, scriptPubKey_from_payload, "00" * 11, "p2pkh")
        # p2pkh("00"*11)

    def test_p2sh(self):

        script_type = "p2sh"

        # self-consistency
        pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
        pubkey_hash = hash160(pubkey)
        redeem_script = scriptPubKey_from_payload("p2pkh", pubkey_hash)
        payload = hash160(redeem_script)
        script = encode(["OP_HASH160", payload, "OP_EQUAL"]).hex()

        # straight to the scriptPubKey
        scriptPubKey = p2sh(redeem_script)
        assert scriptPubKey.hex() == script

        # to the scriptPubKey in two steps (through payload)
        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script

        # back from the scriptPubKey to the payload
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()
        script_type2, payload2, m2 = payload_from_scriptPubKey(script)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()

        # data -> payload is not invertible (hash functions)

        # address
        network = "mainnet"
        address = base58address.p2sh(decode(redeem_script), network)
        address2 = address_from_scriptPubKey(scriptPubKey, network)
        assert address == address2
        prefix = NETWORKS[network]["p2sh"]
        address2 = b58address_from_h160(prefix, payload, network)
        assert address == address2

        scriptPubKey2, network2 = scriptPubKey_from_address(address)
        assert scriptPubKey2 == scriptPubKey
        assert network2 == network

        # documented test case: https://learnmeabitcoin.com/guide/p2sh
        payload = "748284390f9e263a4b766a75d0633c50426eb875"
        script = "a914" + payload + "87"
        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script
        network = "mainnet"
        address = b"3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V"
        address2 = address_from_scriptPubKey(scriptPubKey, network)
        assert address == address2
        scriptPubKey2, network2 = scriptPubKey_from_address(address)
        assert scriptPubKey2 == scriptPubKey
        assert network2 == network

        # invalid size: 21 bytes instead of 20
        self.assertRaises(ValueError, scriptPubKey_from_payload, "00" * 21, "p2sh")
        # scriptPubKey_from_payload("00"*21, 'p2sh')

    def test_p2wpkh(self):

        script_type = "p2wpkh"

        # self-consistency
        pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
        payload = hash160(pubkey)
        script = encode([0, payload]).hex()

        # straight to the scriptPubKey
        scriptPubKey = p2wpkh(pubkey)
        assert scriptPubKey.hex() == script

        # to the scriptPubKey in two steps (through payload)
        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script

        # back from the scriptPubKey to the payload
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()
        script_type2, payload2, m2 = payload_from_scriptPubKey(script)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()

        # data -> payload is not invertible (hash functions)

        # bech32 address
        network = "mainnet"
        address = bech32address.p2wpkh(pubkey, network)
        address2 = address_from_scriptPubKey(scriptPubKey, network)
        assert address == address2
        address2 = b32address_from_witness(0, payload, network)
        assert address == address2

        scriptPubKey2, network2 = scriptPubKey_from_address(address)
        assert scriptPubKey2, scriptPubKey
        assert network2 == network

        # p2sh-wrapped base58 address
        address = base58address.p2wpkh_p2sh(pubkey, network)
        address2 = b58address_from_witness(payload, network)
        assert address == address2

    def test_p2wsh(self):

        script_type = "p2wsh"

        # self-consistency
        pubkey = "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
        pubkey_hash = hash160(pubkey)
        redeem_script = scriptPubKey_from_payload("p2pkh", pubkey_hash)
        payload = sha256(redeem_script)
        script = encode([0, payload]).hex()

        # straight to the scriptPubKey
        scriptPubKey = p2wsh(decode(redeem_script))
        assert scriptPubKey.hex() == script

        # to the scriptPubKey in two steps (through payload)
        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script

        # back from the scriptPubKey to the payload
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()
        script_type2, payload2, m2 = payload_from_scriptPubKey(script)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()

        # data -> payload is not invertible (hash functions)

        # bech32 address
        network = "mainnet"
        address = bech32address.p2wsh(redeem_script, network)
        address2 = address_from_scriptPubKey(scriptPubKey, network)
        assert address == address2
        address2 = b32address_from_witness(0, payload, network)
        assert address == address2

        scriptPubKey2, network2 = scriptPubKey_from_address(address)
        assert scriptPubKey2 == scriptPubKey
        assert network2 == network

        # p2sh-wrapped base58 address
        address = base58address.p2wsh_p2sh(redeem_script, network)
        address2 = b58address_from_witness(payload, network)
        assert address == address2

    def test_exceptions(self):

        # invalid size: 11 bytes instead of 20
        self.assertRaises(ValueError, scriptPubKey_from_payload, "00" * 11, "p2wpkh")
        # scriptPubKey_from_payload("00"*11, 'p2wpkh')

        # invalid size: 33 bytes instead of 32
        self.assertRaises(ValueError, scriptPubKey_from_payload, "00" * 33, "p2wsh")
        # scriptPubKey_from_payload("00"*33, 'p2wsh')

        # Unknown script
        script = [16, 20 * b"\x00"]
        self.assertRaises(ValueError, address_from_scriptPubKey, script)
        # address_from_scriptPubKey(script)

        # Unhandled witness version (16)
        addr = b32address_from_witness(16, 20 * b"\x00")
        self.assertRaises(ValueError, scriptPubKey_from_address, addr)
        # scriptPubKey_from_address(addr)


def test_p2ms_3():

    # mixed compressed / uncompressed public keys
    pubkey1 = "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
    pubkey2 = "03 61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765"
    pubkey3 = "02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    pubkeys = [
        bytes.fromhex(pubkey1),
        bytes.fromhex(pubkey2),
        bytes.fromhex(pubkey3),
    ]
    m = 1
    n = len(pubkeys)
    script = scriptPubKey_from_payload("p2ms", pubkeys, m)
    pubkeys.sort()
    exp_script = encode([m] + pubkeys + [n, "OP_CHECKMULTISIG"])
    assert script.hex() == exp_script.hex()
    script_type, payload, m2 = payload_from_scriptPubKey(script)
    assert script_type == "p2ms"
    assert m == m2
    assert pubkeys == payload


def test_nulldata2():

    script_type = "nulldata"

    # max length case
    byte = b"\x00"
    for length in (0, 1, 16, 17, 74, 75, 76, 77, 78, 79, 80):
        payload = byte * length
        script = encode(["OP_RETURN", payload]).hex()

        scriptPubKey = scriptPubKey_from_payload(script_type, payload)
        assert scriptPubKey.hex() == script

        # back from the scriptPubKey to the payload
        script_type2, payload2, m2 = payload_from_scriptPubKey(scriptPubKey)
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()
        script_type2, payload2, m2 = payload_from_scriptPubKey(decode(script))
        assert script_type == script_type2
        assert 0 == m2
        assert payload.hex() == payload2.hex()


def test_p2ms_p2sh():
    "BIP67 test vectors https://en.bitcoin.it/wiki/BIP_0067"

    data_folder = path.join(path.dirname(__file__), "test_data")
    filename = path.join(data_folder, "bip67_test_vectors.json")
    with open(filename, "r") as f:
        # json.dump(test_vectors, f, indent=4)
        test_vectors = json.load(f)

    m = 2
    for i in test_vectors:
        keys, address = test_vectors[i]
        errmsg = f"Test vector #{int(i)}"
        script = p2ms(keys, m)
        addr = base58address.p2sh(script)
        assert addr.decode() == address, errmsg

        script = scriptPubKey_from_payload("p2ms", keys, m)
        addr = base58address.p2sh(script)
        assert addr.decode() == address, errmsg

        script_type, payload, m2 = payload_from_scriptPubKey(script)
        assert script_type == "p2ms", errmsg
        for key, k in zip(sorted(keys), payload):
            assert key == k.hex(), errmsg
        assert m2 == m, errmsg


def test_CLT():

    network = "mainnet"

    fed_pubkeys = [b"\x00" * 33, b"\x11" * 33, b"\x22" * 33]
    rec_pubkeys = [b"\x77" * 33, b"\x88" * 33, b"\x99" * 33]
    # fmt: off
    redeem_script = encode(
        [
            "OP_IF",
                2, *fed_pubkeys, 3, "OP_CHECKMULTISIG",  # noqa E131
            "OP_ELSE",
                500, "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",  # noqa E131
                2, *rec_pubkeys, 3, "OP_CHECKMULTISIG",  # noqa E131
            "OP_ENDIF",
        ]
    )
    # fmt: on
    payload = sha256(redeem_script)
    script = "00207b5310339c6001f75614daa5083839fa54d46165f6c56025cc54d397a85a5708"

    scriptPubKey = p2wsh(redeem_script)
    assert scriptPubKey.hex() == script
    scriptPubKey = scriptPubKey_from_payload("p2wsh", payload)
    assert scriptPubKey.hex() == script

    address = b"bc1q0df3qvuuvqqlw4s5m2jsswpelf2dgct97mzkqfwv2nfe02z62uyq7n4zjj"
    address2 = address_from_scriptPubKey(scriptPubKey, network)
    assert address == address2
    address2 = b32address_from_witness(0, payload, network)
    assert address == address2


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
