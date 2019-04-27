#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
import os
import json
import secrets

from btclib import bip32
from btclib import bip39

class TestBIP39(unittest.TestCase):
    def test_bip39(self):
        lang = "en"
        raw_entr = bytes.fromhex("0000003974d093eda670121023cd0000")
        mnemonic = bip39.mnemonic_from_raw_entropy(raw_entr, lang)
        self.assertEqual(mnemonic, "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract")
        r = bip39.raw_entropy_from_mnemonic(mnemonic, lang)
        size = (len(r)+7) // 8
        r = int(r, 2).to_bytes(size, 'big')
        self.assertEqual(r, raw_entr)

        passphrase = ''

        mprv = bip39.mprv_from_mnemonic(mnemonic, passphrase, bip32.PRV[0])
        mprv_exp = b'xprv9s21ZrQH143K3ZxBCax3Wu25iWt3yQJjdekBuGrVa5LDAvbLeCT99U59szPSFdnMe5szsWHbFyo8g5nAFowWJnwe8r6DiecBXTVGHG124G1'
        self.assertEqual(mprv, mprv_exp)

        mprv2 = bip39.mprv_from_raw_entropy(raw_entr, passphrase, lang, bip32.PRV[0])
        self.assertEqual(mprv2, mprv)

        mprv = bip39.mprv_from_mnemonic(mnemonic, passphrase, bip32.PRV[0])
        mprv_exp = b'xprv9s21ZrQH143K3ZxBCax3Wu25iWt3yQJjdekBuGrVa5LDAvbLeCT99U59szPSFdnMe5szsWHbFyo8g5nAFowWJnwe8r6DiecBXTVGHG124G1'
        self.assertEqual(mprv, mprv_exp)

        mprv2 = bip39.mprv_from_raw_entropy(raw_entr, passphrase, lang, bip32.PRV[0])
        self.assertEqual(mprv2, mprv)

        # mnemonic with wrong number of bits
        wrong_mnemonic = mnemonic + " abandon"
        self.assertRaises(ValueError, bip39.raw_entropy_from_mnemonic, wrong_mnemonic, lang)
        #bip39_raw_entropy_from_mnemonic(wrong_mnemonic, lang)

        # invalid mnemonic checksum
        wrong_mnemonic = "abandon abandon atom trust ankle walnut oil across awake bunker divorce walnut"
        self.assertRaises(ValueError, bip39.raw_entropy_from_mnemonic, wrong_mnemonic, lang)
        #bip39_raw_entropy_from_mnemonic(wrong_mnemonic, lang)


    def test_vectors(self):
        """BIP39 test vectors
           https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        """
        filename = "bip39_test_vectors.json"
        path_to_filename = os.path.join(os.path.dirname(__file__),
                                        "./data/",
                                        filename)
        with open(path_to_filename, 'r') as f:
            test_vectors = json.load(f)["english"]
        f.closed
        for test_vector in test_vectors:
            lang = "en"
            test_vector[0] = bytes.fromhex(test_vector[0])
            mnemonic = bip39.mnemonic_from_raw_entropy(test_vector[0], lang)
            self.assertEqual(mnemonic, test_vector[1])

            raw_entr = bip39.raw_entropy_from_mnemonic(mnemonic, lang)
            size =  (len(raw_entr)+7) // 8
            raw_entr = int(raw_entr, 2).to_bytes(size, 'big')
            self.assertEqual(raw_entr, test_vector[0])

            seed = bip39.seed_from_mnemonic(mnemonic, "TREZOR").hex()
            self.assertEqual(seed, test_vector[2])

            # test_vector[3], i.e. the bip32 master private key from seed,
            # has been tested in bip32, as it does not belong here

    def test_zeroleadingbit(self):
        bip39.mnemonic_from_raw_entropy(secrets.randbits(127) , 'en')


if __name__ == "__main__":
    unittest.main()
