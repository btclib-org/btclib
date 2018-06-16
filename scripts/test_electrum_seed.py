#!/usr/bin/env python3

import unittest
import os
import json
from electrum_seed import bip32_xpub_from_xprv, \
                          electrum_entropy_from_mnemonic, \
                          electrum_mnemonic_from_raw_entropy, \
                          electrum_master_prvkey_from_mnemonic

class TestMnemonicDictionaries(unittest.TestCase):
    def test_electrum_wallet(self):
        lang = "en"

        raw_entropy = 0x110aaaa03974d093eda670121023cd0772
        version = 'standard'
        mnemonic = electrum_mnemonic_from_raw_entropy(raw_entropy, version, lang)
        entropy = int(electrum_entropy_from_mnemonic(mnemonic, lang), 2)
        self.assertLess(entropy-raw_entropy, 0xfff)

    def test_electrum_vectors(self):
        filename = "test_electrum_vectors.json"
        path_to_filename = os.path.join(os.path.dirname(__file__),
                                        "../data/",
                                        filename)
        with open(path_to_filename, 'r') as f:
            test_vectors = json.load(f)
        f.closed

        for test_vector in test_vectors:
            test_mnemonic = test_vector[1]
            passphrase = test_vector[2]
            test_mpub = test_vector[3]
            mprv = electrum_master_prvkey_from_mnemonic(test_mnemonic, passphrase)
            mpub = bip32_xpub_from_xprv(mprv).decode()
            self.assertEqual(mpub, test_mpub)
            
            lang = "en"
            entropy = int(electrum_entropy_from_mnemonic(test_mnemonic, lang), 2)
            version = test_vector[0]
            mnemonic = electrum_mnemonic_from_raw_entropy(entropy, version, lang)
            self.assertEqual(mnemonic, test_mnemonic)

 
if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
