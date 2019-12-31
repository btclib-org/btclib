#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.script import serialize, parse, OP_CODES, OP_CODE_NAMES
from btclib.utils import h160, sha256


class TestScript(unittest.TestCase):


    def test_operators(self):
        for i in OP_CODE_NAMES.keys():
            b = OP_CODES[OP_CODE_NAMES[i]]
            self.assertEqual(i, b[0])
        for name in OP_CODES.keys():
            # skip duplicated
            if name in ('OP_FALSE', 'OP_TRUE', 'OP_NOP2', 'OP_NOP3'):
                continue
            i = OP_CODES[name][0]
            self.assertEqual(name, OP_CODE_NAMES[i])
        for i in range(76, 186):
            # skip disabled 'splice' opcodes
            if i in (126, 127, 128, 129):
                continue
            # skip disabled 'bitwise logic' opcodes
            if i in (131, 132, 133, 134):
                continue
            # skip disabled 'splice' opcodes
            if i in (141, 142, 149, 150, 151, 152, 152, 153):
                continue
            # skip 'reserved' opcodes
            if i in (80, 98, 101, 102, 137, 138):
                continue
            self.assertTrue(i in OP_CODE_NAMES.keys())


    def test_add(self):
        script = [2, 3, 'OP_ADD', 5, 'OP_EQUAL']
        script_bytes = serialize(script)
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)


    def test_scriptpubkey(self):

        data = "time-stamped data".encode()
        # OP_RETURN
        script = ['OP_RETURN', data.hex()]
        script_bytes = serialize(script)
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        pubkey = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        # p2pk
        script = [pubkey, 'OP_CHECKSIG']
        script_bytes = serialize(script)
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        pubKey2 = "02530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7"
        # multi-sig
        script = [1, pubkey, pubKey2, 2, 'OP_CHECKMULTISIGVERIFY']
        script_bytes = serialize(script)
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        pubkey_hash = h160(pubkey)
        # p2pkh
        script = ['OP_DUP', 'OP_HASH160', pubkey_hash.hex(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']
        redeem_script_bytes = serialize(script)
        script2 = parse(redeem_script_bytes)
        self.assertEqual(script, script2)

        redeem_script_hash = h160(redeem_script_bytes)
        # p2sh
        script = ['OP_HASH160', redeem_script_hash.hex(), 'OP_EQUAL']
        script_bytes = serialize(script)
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        # p2wpkh
        script = [0, pubkey_hash.hex()]
        script_bytes = serialize(script)
        self.assertEqual(script_bytes.hex(), "0014"+pubkey_hash.hex())
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        witness_script = [pubkey, 'OP_CHECKSIG']
        witness_script_bytes = serialize(witness_script)
        witness_script_hash = sha256(witness_script_bytes)
        # p2wsh
        script = [0, witness_script_hash.hex()]
        script_bytes = serialize(script)
        self.assertEqual(script_bytes.hex(), "0020"+witness_script_hash.hex())
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)
