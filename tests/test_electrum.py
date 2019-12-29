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

from btclib import bip32
from btclib import electrum


class TestMnemonicDictionaries(unittest.TestCase):
    def test_mnemonic(self):
        lang = "en"

        entropy = 0x110aaaa03974d093eda670121023cd0772
        eversion = 'standard'
        # FIXME: is the following mnemonic obtained in Electrum from the above entropy?
        mnemonic = "ability awful fetch liberty company spatial panda hat then canal ball crouch bunker"
        mnemonic2 = electrum.mnemonic_from_entropy(entropy, lang, eversion)
        self.assertEqual(mnemonic, mnemonic2)

        entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
        self.assertLess(entr-entropy, 0xfff)

        # mnemonic version not in electrum allowed mnemonic versions
        eversion = 'std'
        self.assertRaises(ValueError, electrum.mnemonic_from_entropy,
                          entropy, lang, eversion)
        #electrum.mnemonic_from_entropy(entropy, lang, eversion)

        # unknown electrum mnemonic version (00c)
        unknown_version = "ability awful fetch liberty company spatial panda hat then canal ball cross video"
        self.assertRaises(ValueError, electrum.entropy_from_mnemonic,
                          unknown_version, lang)
        #electrum.entropy_from_mnemonic(unknown_version, lang)

        passphrase = ''

        # unknown electrum mnemonic version (00c)
        self.assertRaises(ValueError, electrum.masterxprv_from_mnemonic,
                          unknown_version, passphrase)
        #electrum.masterxprv_from_mnemonic(mnemonic, passphrase)

        xprv = "xprv9s21ZrQH143K2tn5j4pmrLXkS6dkbuX6mFhJfCxAwN6ofRo5ddCrLRWogKEs1AptPmLgrthKxU2csfBgkoKECWtj1XMRicRsoWawukaRQft"
        xprv2 = electrum.masterxprv_from_mnemonic(mnemonic, passphrase)
        self.assertEqual(xprv2.decode(), xprv)

        eversion = '2fa'
        mnemonic = electrum.mnemonic_from_entropy(entropy, lang, eversion)
        # 2fa mnemonic version is not managed yet
        self.assertRaises(ValueError, electrum.masterxprv_from_mnemonic,
                          mnemonic, passphrase)
        #electrum.masterxprv_from_mnemonic(mnemonic, passphrase)

        eversion = '2fa_segwit'
        mnemonic = electrum.mnemonic_from_entropy(entropy, lang, eversion)
        # 2fa_segwit mnemonic version is not managed yet
        self.assertRaises(ValueError, electrum.masterxprv_from_mnemonic,
                          mnemonic, passphrase)
        #electrum.masterxprv_from_mnemonic(mnemonic, passphrase)

    def test_vectors(self):
        filename = "electrum_test_vectors.json"
        path_to_filename = os.path.join(os.path.dirname(__file__),
                                        "./data/",
                                        filename)
        with open(path_to_filename, 'r') as f:
            test_vectors = json.load(f)
        f.closed

        for test_vector in test_vectors:
            version = test_vector[0]
            mnemonic = test_vector[1]
            passphrase = test_vector[2]
            mxprv = test_vector[3]
            mxpub = test_vector[4]
            address = test_vector[5]  # "./0/0"

            mxprv2 = electrum.masterxprv_from_mnemonic(mnemonic, passphrase)
            self.assertEqual(mxprv2.decode(), mxprv)
            mxpub2 = bip32.xpub_from_xprv(mxprv2)
            self.assertEqual(mxpub2.decode(), mxpub)
            xpub = bip32.derive(mxpub2, "./0/0")

            if version == "standard":
                address2 = bip32.p2pkh_address_from_xpub(xpub)
                self.assertEqual(address2.decode(), address)

            if version == "segwit":
                pass  # FIXME: check bech32 addresses

            lang = "en"
            entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
            mnem = electrum.mnemonic_from_entropy(entr, lang, version)
            self.assertEqual(mnem, mnemonic)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
