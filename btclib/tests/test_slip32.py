#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import base58address, bech32address, bip32, bip39, slip32
from btclib.network import MAIN_xprv, MAIN_yprv, MAIN_zprv


class TestSLIP32(unittest.TestCase):

    def test_slip32_test_vector(self):
        """SLIP32 test vector

        https://github.com/satoshilabs/slips/blob/master/slip-0132.md
        """
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        kpath = "./0/0"
        test_vectors = [
            [MAIN_xprv,
             "m / 44h / 0h / 0h",
             b'xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb',
             b'xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj',
             b'1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA'
             ],
            [MAIN_yprv,
             "m / 49h / 0h / 0h",
             b'yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF',
             b'ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP',
             b'37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf'
             ],
            [MAIN_zprv,
             "m / 84h / 0h / 0h",
             b'zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE',
             b'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs',
             b'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'
             ],
        ]
        for v in test_vectors:
            rxprv = bip32.rootxprv_from_bip39mnemonic(mnemonic, '', v[0])
            mxprv = bip32.derive(rxprv, v[1])
            self.assertEqual(v[2], mxprv)
            mxpub = bip32.xpub_from_xprv(mxprv)
            self.assertEqual(v[3], mxpub)
            xpub = bip32.derive(mxpub, kpath)
            address = slip32.address_from_xpub(xpub)
            self.assertEqual(v[4], address)
            address = slip32.address_from_xkey(xpub)
            self.assertEqual(v[4], address)
            xprv = bip32.derive(mxprv, kpath)
            address = slip32.address_from_xkey(xprv)
            self.assertEqual(v[4], address)
            if v[0] == MAIN_xprv:
                address = base58address.p2pkh(xpub)
                self.assertEqual(v[4], address)
                address = base58address.p2pkh(xprv)
                self.assertEqual(v[4], address)
            elif v[0] == MAIN_yprv:
                address = base58address.p2wpkh_p2sh(xpub)
                self.assertEqual(v[4], address)
                address = base58address.p2wpkh_p2sh(xprv)
                self.assertEqual(v[4], address)
            elif v[0] == MAIN_zprv:
                address = bech32address.p2wpkh(xpub)
                self.assertEqual(v[4], address)
                address = bech32address.p2wpkh(xprv)
                self.assertEqual(v[4], address)

    def test_slip32(self):
        # xkey is not a public one
        xprv = b'xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS'
        self.assertRaises(ValueError, slip32.address_from_xpub, xprv)
        address = slip32.address_from_xkey(xprv)
        xpub = bip32.xpub_from_xprv(xprv)
        address2 = slip32.address_from_xpub(xpub)
        self.assertEqual(address, address2)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
