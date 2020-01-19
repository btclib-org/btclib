#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.script import OP_CODE_NAMES, OP_CODES, parse, serialize
from btclib.scriptpubkey import (multisig_scriptPubKey, nulldata_scriptPubKey,
                                 p2pk_scriptPubKey, p2pkh_scriptPubKey,
                                 p2sh_scriptPubKey, p2wpkh_scriptPubKey,
                                 p2wsh_scriptPubKey)
from btclib.utils import _sha256, h160


class TestScriptPubKey(unittest.TestCase):

    def test_standards(self):

        data = "time-stamped data".encode()
        # OP_RETURN
        # script = ['OP_RETURN', data.hex()]
        script = nulldata_scriptPubKey(data)
        script_bytes = serialize(script)
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        pubkey = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        # p2pk
        #script = [pubkey, 'OP_CHECKSIG']
        script = p2pk_scriptPubKey(pubkey)
        script_bytes = serialize(script)
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        pubKey2 = "02530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7"
        # multi-sig
        # script = [1, pubkey, pubKey2, 2, 'OP_CHECKMULTISIGVERIFY']
        script = multisig_scriptPubKey(1, (pubkey, pubKey2))
        script_bytes = serialize(script)
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        # p2pkh
        pubkey_hash = h160(pubkey)
        # script = ['OP_DUP', 'OP_HASH160', pubkey_hash.hex(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']
        script = p2pkh_scriptPubKey(pubkey_hash)
        script_bytes = serialize(script)
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        # p2pkh-p2sh
        redeem_script_hash = h160(script_bytes)
        # script = ['OP_HASH160', redeem_script_hash.hex(), 'OP_EQUAL']
        script = p2sh_scriptPubKey(redeem_script_hash)
        script_bytes = serialize(script)
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        # p2wpkh
        # script = [0, pubkey_hash.hex()]
        script = p2wpkh_scriptPubKey(pubkey_hash)
        script_bytes = serialize(script)
        self.assertEqual(script_bytes.hex(), "0014"+pubkey_hash.hex())
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)

        # p2wsh
        witness_script = [pubkey, 'OP_CHECKSIG']
        witness_script_bytes = serialize(witness_script)
        witness_script_hash = _sha256(witness_script_bytes)
        # script = [0, witness_script_hash.hex()]
        script = p2wsh_scriptPubKey(witness_script_hash)
        script_bytes = serialize(script)
        self.assertEqual(script_bytes.hex(), "0020"+witness_script_hash.hex())
        script2 = parse(script_bytes)
        self.assertEqual(script, script2)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
