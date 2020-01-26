#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import segwitaddress
from btclib.script import OP_CODE_NAMES, OP_CODES, decode, encode, serialize
from btclib.scriptpubkey import (multisig_scriptPubKey, nulldata_scriptPubKey,
                                 p2pk_scriptPubKey, p2pkh_scriptPubKey,
                                 p2sh_scriptPubKey, p2wpkh_scriptPubKey,
                                 p2wsh_scriptPubKey, address_from_scriptPubKey,
                                 scriptPubKey_from_address)
from btclib.utils import h256, h160


class TestScriptPubKey(unittest.TestCase):

    def test_standards(self):

        # OP_RETURN
        data = "time-stamped data".encode().hex()
        # script = ['OP_RETURN', data.hex()]
        script = nulldata_scriptPubKey(data)
        script_bytes = encode(script)
        script2 = decode(script_bytes)
        self.assertEqual(script, script2)

        # p2pk
        pubkey = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        #script = [pubkey, 'OP_CHECKSIG']
        script = p2pk_scriptPubKey(pubkey)
        script_bytes = encode(script)
        script2 = decode(script_bytes)
        self.assertEqual(script, script2)

        # multi-sig
        pubKey2 = "02530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7"
        # script = [1, pubkey, pubKey2, 2, 'OP_CHECKMULTISIGVERIFY']
        script = multisig_scriptPubKey(1, (pubkey, pubKey2))
        script_bytes = encode(script)
        script2 = decode(script_bytes)
        self.assertEqual(script, script2)

        # p2pkh
        pubkey_hash = h160(pubkey).hex()
        # script = ['OP_DUP', 'OP_HASH160', pubkey_hash.hex(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']
        script = p2pkh_scriptPubKey(pubkey_hash)
        script_bytes = encode(script)
        script2 = decode(script_bytes)
        self.assertEqual(script, script2)

        # p2sh (p2pkh-p2sh)
        redeem_script_hash = h160(script_bytes).hex()
        # script = ['OP_HASH160', redeem_script_hash.hex(), 'OP_EQUAL']
        script = p2sh_scriptPubKey(redeem_script_hash)
        script_bytes = encode(script)
        script2 = decode(script_bytes)
        self.assertEqual(script, script2)

        # p2wpkh
        # script = [0, pubkey_hash.hex()]
        script = p2wpkh_scriptPubKey(pubkey_hash)
        script_bytes = encode(script)
        self.assertEqual(script_bytes.hex(), "0014"+pubkey_hash)
        script2 = decode(script_bytes)
        self.assertEqual(script, script2)

        # p2wsh
        witness_script = [pubkey, 'OP_CHECKSIG']
        witness_script_bytes = encode(witness_script)
        witness_script_hash = h256(witness_script_bytes)
        # script = [0, witness_script_hash.hex()]
        script = p2wsh_scriptPubKey(witness_script_hash.hex())
        script_bytes = encode(script)
        self.assertEqual(script_bytes.hex(), "0020"+witness_script_hash.hex())
        script2 = decode(script_bytes)
        self.assertEqual(script, script2)

    def test_exceptions(self):

        # Invalid data lenght (41 bytes) for nulldata scriptPubKey
        data = '00'*41
        self.assertRaises(ValueError, nulldata_scriptPubKey, data)
        #nulldata_scriptPubKey(data)

        # Invalid pubkey lenght (34 bytes) for p2pk scriptPubKey
        pubkey = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        self.assertRaises(ValueError, p2pk_scriptPubKey, pubkey+"00")
        # p2pk_scriptPubKey(pubkey+"00")

        # Invalid m (0)
        pubKey2 = "02530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7"
        self.assertRaises(ValueError, multisig_scriptPubKey, 0, (pubkey, pubKey2))
        # multisig_scriptPubKey(0, (pubkey, pubKey2))

        # Invalid pubkey lenght (34 bytes) for m-of-n multi-sig scriptPubKey
        pubKey2 = "02530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7"
        self.assertRaises(ValueError, multisig_scriptPubKey, 1, (pubkey+"00", pubKey2))
        #multisig_scriptPubKey(1, (pubkey+"00", pubKey2))

        # Invalid n (17)
        pubKey2 = "02530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7"
        self.assertRaises(ValueError, multisig_scriptPubKey, 3, [pubkey]*17)
        # multisig_scriptPubKey(3, [pubkey]*17)

        # Impossible m-of-n (3-of-2)
        pubKey2 = "02530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7"
        self.assertRaises(ValueError, multisig_scriptPubKey, 3, (pubkey, pubKey2))
        # multisig_scriptPubKey(3, (pubkey, pubKey2))

        # Invalid pubkey-hash lenght (11 bytes) for p2pkh scriptPubKey
        pubkey_hash = h160(pubkey).hex()
        self.assertRaises(ValueError, p2pkh_scriptPubKey, "00"*11)
        # p2pkh_scriptPubKey("00"*11)

        # Invalid script-hash lenght (21 bytes) for p2sh scriptPubKey
        self.assertRaises(ValueError, p2sh_scriptPubKey, "00"*21)
        # p2sh_scriptPubKey("00"*21)

        # Invalid witness program lenght (11 bytes) for p2wpkh scriptPubKey
        self.assertRaises(ValueError, p2wpkh_scriptPubKey, "00"*11)
        # p2wpkh_scriptPubKey("00"*11)

        # Invalid witness program lenght (33 bytes) for p2wsh scriptPubKey
        self.assertRaises(ValueError, p2wsh_scriptPubKey, "00"*33)
        # p2wsh_scriptPubKey("00"*33)

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
        witness_hash = h256(witness_program)

        script_pubkey = p2wsh_scriptPubKey(witness_hash)
        self.assertEqual(encode(script_pubkey).hex(), "00207b5310339c6001f75614daa5083839fa54d46165f6c56025cc54d397a85a5708")
        address = segwitaddress._encode("mainnet", 0, witness_hash)
        self.assertEqual(address, b"bc1q0df3qvuuvqqlw4s5m2jsswpelf2dgct97mzkqfwv2nfe02z62uyq7n4zjj")

    def test_address_scriptPubKey(self):

        pubkey = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        pubkey_hash = h160(pubkey).hex()

        script = [0, pubkey_hash]
        address_from_scriptPubKey(script)
        script2, _ = scriptPubKey_from_address(address_from_scriptPubKey(script))
        self.assertEqual(script, script2)

        script = ['OP_DUP', 'OP_HASH160', pubkey_hash, 'OP_EQUALVERIFY', 'OP_CHECKSIG']
        script2, _ = scriptPubKey_from_address(address_from_scriptPubKey(script))
        self.assertEqual(script, script2)

        script_hash = h160(encode(script)).hex()
        script = ['OP_HASH160',script_hash, 'OP_EQUAL']
        script2, _ = scriptPubKey_from_address(address_from_scriptPubKey(script))
        self.assertEqual(script, script2)

        script_hash = h256(encode(script)).hex()
        script = [0, script_hash]
        script2, _ = scriptPubKey_from_address(address_from_scriptPubKey(script))
        self.assertEqual(script, script2)

        # Unknown script
        script = [16, pubkey_hash]
        self.assertRaises(ValueError, address_from_scriptPubKey, script)
        #address_from_scriptPubKey(script)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
