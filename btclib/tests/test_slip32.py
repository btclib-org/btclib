#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import base58address, bech32address, bip32, slip32
from btclib.network import NETWORKS


class TestSLIP32(unittest.TestCase):

    def test_slip32_test_vector(self):
        """SLIP32 test vector

        https://github.com/satoshilabs/slips/blob/master/slip-0132.md
        """
        mnemonic = ("abandon abandon abandon abandon abandon abandon "
                    "abandon abandon abandon abandon abandon about")
        kpath = "./0/0"
        test_vectors = [
            [
                NETWORKS["mainnet"]["bip32_prv"],
                "m / 44h / 0h / 0h",
                ("xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBn"
                 "Q6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb"),
                ("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSW"
                 "GFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"),
                "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
            ],
            [
                NETWORKS["mainnet"]["slip32_p2wsh_p2sh_prv"],
                "m / 49h / 0h / 0h",
                ("yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQe"
                 "KTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF"),
                ("ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCx"
                 "oJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"),
                "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
            ],
            [
                NETWORKS["mainnet"]["slip32_p2wpkh_prv"],
                "m / 84h / 0h / 0h",
                ("zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEv"
                 "BRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"),
                ("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3E"
                 "fH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"),
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
            ],
        ]
        for version, der_path, prv, pub, addr_str in test_vectors:
            rxprv = bip32.mxprv_from_bip39_mnemonic(mnemonic, "", version)
            mxprv = bip32.derive(rxprv, der_path)
            self.assertEqual(prv.encode(), mxprv)
            mxpub = bip32.xpub_from_xprv(mxprv)
            self.assertEqual(pub.encode(), mxpub)
            xpub = bip32.derive(mxpub, kpath)
            address = slip32.address_from_xpub(xpub)
            addr = addr_str.encode()
            self.assertEqual(addr, address)
            address = slip32.address_from_xkey(xpub)
            self.assertEqual(addr, address)
            xprv = bip32.derive(mxprv, kpath)
            address = slip32.address_from_xkey(xprv)
            self.assertEqual(addr, address)
            if version == NETWORKS["mainnet"]["bip32_prv"]:
                address = base58address.p2pkh(xpub)
                self.assertEqual(addr, address)
                address = base58address.p2pkh(xprv)
                self.assertEqual(addr, address)
            elif version == NETWORKS["mainnet"]["slip32_p2wsh_p2sh_prv"]:
                address = base58address.p2wpkh_p2sh(xpub)
                self.assertEqual(addr, address)
                address = base58address.p2wpkh_p2sh(xprv)
                self.assertEqual(addr, address)
            elif version == NETWORKS["mainnet"]["slip32_p2wpkh_prv"]:
                address = bech32address.p2wpkh(xpub)
                self.assertEqual(addr, address)
                address = bech32address.p2wpkh(xprv)
                self.assertEqual(addr, address)

    def test_slip32(self):
        # xkey is not a public one
        xprv = ("xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cx"
                "dgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS").encode()
        self.assertRaises(ValueError, slip32.address_from_xpub, xprv)
        address = slip32.address_from_xkey(xprv)
        xpub = bip32.xpub_from_xprv(xprv)
        address2 = slip32.address_from_xpub(xpub)
        self.assertEqual(address, address2)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
