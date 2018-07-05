#!/usr/bin/env python3

import unittest
import os
import json
import math
from btclib.bip39 import PRIVATE, \
                         bip39_mnemonic_from_raw_entropy, \
                         bip39_raw_entropy_from_mnemonic, \
                         bip39_master_prvkey_from_mnemonic, \
                         bip39_master_prvkey_from_raw_entropy, \
                         bip39_seed_from_mnemonic

class TestBIP39Wallet(unittest.TestCase):
    def test_bip39_wallet(self):
        lang = "en"
        raw_entr = bytes.fromhex("0000003974d093eda670121023cd0000")
        mnemonic = bip39_mnemonic_from_raw_entropy(raw_entr, lang)
        r = bip39_raw_entropy_from_mnemonic(mnemonic, lang)
        nbytes = math.ceil(len(r)/8)
        r = int(r, 2).to_bytes(nbytes, 'big')
        self.assertEqual(r, raw_entr)

        passphrase = ''
        
        mprv = bip39_master_prvkey_from_mnemonic(mnemonic, passphrase, PRIVATE[0])
        self.assertEqual(mprv, b'xprv9s21ZrQH143K3ZxBCax3Wu25iWt3yQJjdekBuGrVa5LDAvbLeCT99U59szPSFdnMe5szsWHbFyo8g5nAFowWJnwe8r6DiecBXTVGHG124G1')

        mprv2 = bip39_master_prvkey_from_raw_entropy(raw_entr, passphrase, lang, PRIVATE[0])
        self.assertEqual(mprv2, mprv)

    # Test vectors:
    # https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    def test_bip39_vectors(self):
        filename = "test_bip39_vectors.json"
        path_to_filename = os.path.join(os.path.dirname(__file__),
                                        "../data/",
                                        filename)
        with open(path_to_filename, 'r') as f:
            test_vectors = json.load(f)["english"]
        f.closed
        for test_vector in test_vectors:
            lang = "en"
            test_vector[0] = bytes.fromhex(test_vector[0])
            mnemonic = bip39_mnemonic_from_raw_entropy(test_vector[0], lang)
            self.assertEqual(mnemonic, test_vector[1])

            raw_entr = bip39_raw_entropy_from_mnemonic(mnemonic, lang)
            nbytes = math.ceil(len(raw_entr)/8)
            raw_entr = int(raw_entr, 2).to_bytes(nbytes, 'big')
            self.assertEqual(raw_entr, test_vector[0])

            seed = bip39_seed_from_mnemonic(mnemonic, "TREZOR").hex()
            self.assertEqual(seed, test_vector[2])

            # test_vector[3], i.e. the bip32 master private key from seed,
            # has been tested in bip32, as it does not belong here


if __name__ == "__main__":
    unittest.main()
