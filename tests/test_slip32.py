#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import base58address, bip32, bip39, slip32


class TestSLIP32(unittest.TestCase):

    def test_slip32(self):
        """SLIP32 test vector

        https://github.com/satoshilabs/slips/blob/master/slip-0132.md
        """

        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        passphrase = ""

        path = "m/44'/0'/0'"
        prv = b"xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb"
        pub = b"xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
        address = b"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
        rxprv = bip32.rootxprv_from_bip39mnemonic(mnemonic, passphrase, bip32.MAIN_xprv)
        mprv = bip32.derive(rxprv, path)
        self.assertEqual(mprv, prv)
        mpub = bip32.xpub_from_xprv(mprv)
        self.assertEqual(mpub, pub)
        pub = bip32.derive(mpub, "./0/0")
        addr = slip32.address_from_xpub(pub)
        self.assertEqual(address, addr)

        path = "m/49'/0'/0'"
        prv = b"yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF"
        pub = b"ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"
        address = b"37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
        rxprv = bip32.rootxprv_from_bip39mnemonic(mnemonic, passphrase, bip32.MAIN_yprv)
        mprv = bip32.derive(rxprv, path)
        self.assertEqual(mprv, prv)
        mpub = bip32.xpub_from_xprv(mprv)
        self.assertEqual(mpub, pub)
        pub = bip32.derive(mpub, "./0/0")
        addr = slip32.address_from_xpub(pub)
        self.assertEqual(address, addr)
        addr = base58address.p2wpkh_p2sh_from_xpub(pub)
        self.assertEqual(address, addr)

        path = "m/84'/0'/0'"
        prv = b"zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
        pub = b"zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
        address = b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        rxprv = bip32.rootxprv_from_bip39mnemonic(mnemonic, passphrase, bip32.MAIN_zprv)
        mprv = bip32.derive(rxprv, path)
        self.assertEqual(mprv, prv)
        mpub = bip32.xpub_from_xprv(mprv)
        self.assertEqual(mpub, pub)
        pub = bip32.derive(mpub, "./0/0")
        addr = slip32.address_from_xpub(pub)
        self.assertEqual(address, addr)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
