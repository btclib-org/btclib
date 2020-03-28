#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from os import path
import json
import secrets

from btclib import bip39

class TestBIP39(unittest.TestCase):
    def test_bip39(self):
        lang = "en"
        raw_entr = bytes.fromhex("0000003974d093eda670121023cd0000")
        mnemonic = bip39.mnemonic_from_entropy(raw_entr, lang)
        self.assertEqual(
            mnemonic, "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract")
        r = bip39.entropy_from_mnemonic(mnemonic, lang)
        size = (len(r)+7) // 8
        r = int(r, 2).to_bytes(size, byteorder='big')
        self.assertEqual(r, raw_entr)

        # mnemonic with wrong number of words
        wrong_mnemonic = mnemonic + " abandon"
        self.assertRaises(ValueError, bip39.entropy_from_mnemonic, wrong_mnemonic, lang)
        #bip39_entropy_from_mnemonic(wrong_mnemonic, lang)

        # invalid mnemonic checksum
        wr_m = "abandon abandon atom trust ankle walnut oil across awake bunker divorce walnut"
        self.assertRaises(ValueError, bip39.entropy_from_mnemonic, wr_m, lang)
        #bip39_entropy_from_mnemonic(wrong_mnemonic, lang)

        # Invalid number of bits (130) for BIP39 entropy; must be in ...
        binstr_entropy = '01' * 65  # 130 bits
        self.assertRaises(ValueError, bip39._entropy_checksum, binstr_entropy)
        #bip39._entropy_checksum(binstr_entropy)

    def test_vectors(self):
        """BIP39 test vectors
           https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        """
        filename = "bip39_test_vectors.json"
        path_to_filename = path.join(path.dirname(__file__),
                                     "./data/", filename)
        with open(path_to_filename, 'r') as f:
            test_vectors = json.load(f)["english"]
        f.closed
        for test_vector in test_vectors:
            lang = "en"
            entropy = bytes.fromhex(test_vector[0])
            mnemonic = bip39.mnemonic_from_entropy(entropy, lang)
            self.assertEqual(mnemonic, test_vector[1])

            raw_entr = bip39.entropy_from_mnemonic(mnemonic, lang)
            size = (len(raw_entr)+7) // 8
            raw_entr = int(raw_entr, 2).to_bytes(size, byteorder='big')
            self.assertEqual(raw_entr, entropy)

            seed = bip39.seed_from_mnemonic(mnemonic, "TREZOR").hex()
            self.assertEqual(seed, test_vector[2])

            # test_vector[3], i.e. the bip32 master private key from seed,
            # has been tested in bip32, as it does not belong here

    def test_zeroleadingbit(self):
        # it should not throw an error
        bip39.mnemonic_from_entropy(secrets.randbits(127), 'en')


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
