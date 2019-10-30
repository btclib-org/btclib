#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import bip32, bip39, base58

class TestCustody(unittest.TestCase):

    def test_ledgersetup(self):

        testnet1mainnet0 = 1
        root = "m"  # BIP32 m / account' / change / address_index
        root += "/44'/" + str(testnet1mainnet0) + "'"  # BIP39 m / purpose' / coin_type' / account' / change / address_index
        account = "/0'"
        account_root = root + account
        print("\n", account_root)

        mnemonic = list()
        passphrase = ''
        mprv = list()
        for i in range(6):
            # 128 bits
            raw_entr = bytes.fromhex(str(i)*32)
            # 12 words
            mnemonic.append(bip39.mnemonic_from_entropy(raw_entr, 'en'))
            #print(mnemonic[i])
            mprv.append(bip39.mprv_from_mnemonic(mnemonic[i], passphrase, bip32.PRV[testnet1mainnet0]))
            #print(mprv[i])
            account_root_xprv = bip32.derive(mprv[i], account_root)
            #account_root_xpub = bip32.xpub_from_xprv(account_root_xprv)
            xprv_ext = bip32.derive(account_root_xprv, "./0")  # external
            xprv_int = bip32.derive(account_root_xprv, "./1")  # internal
            xpub_ext = bip32.xpub_from_xprv(xprv_ext)
            xpub_int = bip32.xpub_from_xprv(xprv_int)

        xpub = bip32.ckd(xpub_ext, 0)
        ecpub= base58.decode_check(xpub)[-33:]
        print()
        print(xpub)
        print(ecpub.hex())
        print(bip32.address_from_xpub(xpub))

        xpub = bip32.ckd(xpub_ext, 1)
        ecpub= base58.decode_check(xpub)[-33:]
        print()
        print(xpub)
        print(ecpub.hex())
        print(bip32.address_from_xpub(xpub))

        xpub = bip32.ckd(xpub_int, 0)
        ecpub= base58.decode_check(xpub)[-33:]
        print()
        print(xpub)
        print(ecpub.hex())
        print(bip32.address_from_xpub(xpub))

        xpub = bip32.ckd(xpub_int, 1)
        ecpub= base58.decode_check(xpub)[-33:]
        print()
        print(xpub)
        print(ecpub.hex())
        print(bip32.address_from_xpub(xpub))


if __name__ == "__main__":
    unittest.main()
