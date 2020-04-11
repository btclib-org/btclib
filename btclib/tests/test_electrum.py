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

from btclib import bip32, slip32
from btclib import electrum


class TestMnemonicDictionaries(unittest.TestCase):
    def test_mnemonic(self):
        lang = "en"

        entropy = 0x110aaaa03974d093eda670121023cd0772
        eversion = 'standard'
        # FIXME: is the following mnemonic obtained in Electrum from the above entropy?
        mnemonic = "ability awful fetch liberty company spatial panda hat then canal ball crouch bunker"
        mnemonic2 = electrum.mnemonic_from_entropy(eversion, entropy, lang)
        self.assertEqual(mnemonic, mnemonic2)

        entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
        self.assertLess(entr-entropy, 0xfff)

        # mnemonic version not in electrum allowed mnemonic versions
        eversion = 'std'
        self.assertRaises(ValueError, electrum.mnemonic_from_entropy,
                          eversion, entropy, lang)
        #electrum.mnemonic_from_entropy(eversion, entropy, lang)

        # unknown electrum mnemonic version (00c)
        unknown_version = "ability awful fetch liberty company spatial panda hat then canal ball cross video"
        self.assertRaises(ValueError, electrum.entropy_from_mnemonic,
                          unknown_version, lang)
        #electrum.entropy_from_mnemonic(unknown_version, lang)

        passphrase = ''

        # unknown electrum mnemonic version (00c)
        self.assertRaises(ValueError, bip32.masterxprv_from_electrummnemonic,
                          unknown_version, passphrase)
        #bip32.masterxprv_from_electrummnemonic(mnemonic, passphrase)

        xprv = "xprv9s21ZrQH143K2tn5j4pmrLXkS6dkbuX6mFhJfCxAwN6ofRo5ddCrLRWogKEs1AptPmLgrthKxU2csfBgkoKECWtj1XMRicRsoWawukaRQft"
        xprv2 = bip32.masterxprv_from_electrummnemonic(mnemonic, passphrase)
        self.assertEqual(xprv2, xprv.encode())

        eversion = '2fa'
        mnemonic = electrum.mnemonic_from_entropy(eversion, entropy, lang)
        # 2fa mnemonic version is not managed yet
        self.assertRaises(ValueError, bip32.masterxprv_from_electrummnemonic,
                          mnemonic, passphrase)
        #bip32.masterxprv_from_electrummnemonic(mnemonic, passphrase)

        eversion = '2fa_segwit'
        mnemonic = electrum.mnemonic_from_entropy(eversion, entropy, lang)
        # 2fa_segwit mnemonic version is not managed yet
        self.assertRaises(ValueError, bip32.masterxprv_from_electrummnemonic,
                          mnemonic, passphrase)
        #bip32.masterxprv_from_electrummnemonic(mnemonic, passphrase)

    def test_vectors(self):
        file = "electrum_test_vectors.json"
        filename = path.join(path.dirname(__file__), "data", file)
        with open(filename, 'r') as f:
            test_vectors = json.load(f)
        f.closed

        lang = "en"
        for test_vector in test_vectors:
            mnemonic = test_vector[0]
            passphrase = test_vector[1]
            mxprv = test_vector[2]
            mxpub = test_vector[3]
            address = test_vector[4]  # "./0/0"

            if mnemonic != "":
                mxprv2 = bip32.masterxprv_from_electrummnemonic(mnemonic, passphrase)
                self.assertEqual(mxprv2, mxprv.encode())

                eversion = electrum.version_from_mnemonic(mnemonic)
                entr = int(electrum.entropy_from_mnemonic(mnemonic, lang), 2)
                mnem = electrum.mnemonic_from_entropy(eversion, entr, lang)
                self.assertEqual(mnem, mnemonic)

            if mxprv != "":
                mxpub2 = bip32.xpub_from_xprv(mxprv)
                self.assertEqual(mxpub2, mxpub.encode())

            xpub = bip32.derive(mxpub, "./0/0")
            address2 = slip32.address_from_xpub(xpub).decode('ascii')
            self.assertEqual(address2, address)

        # version 2fa_segwit
        mnemonic = "slender flight session office noodle hand couple option office wait uniform morning"
        self.assertEqual("2fa_segwit", electrum.version_from_mnemonic(mnemonic))

        # version 2fa
        mnemonic = "history recycle company awful donor fold beef nominee hard bleak bracket six"
        self.assertEqual("2fa", electrum.version_from_mnemonic(mnemonic))

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
