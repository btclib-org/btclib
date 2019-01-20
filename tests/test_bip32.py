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

from btclib.base58 import b58encode_check, b58decode_check
from btclib import bip32

class TestBIP32(unittest.TestCase):
    def test_vector1(self):
        """ BIP32 test vestor 1
            https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        """
        xkey_version = bip32.PRIVATE[0]

        seed = "000102030405060708090a0b0c0d0e0f"
        mprv = bip32.mprv_from_seed(seed, xkey_version)
        mprv = bip32.mprv_from_seed(seed, xkey_version.hex())
        self.assertEqual(
            mprv, b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        mpub = bip32.xpub_from_xprv(mprv)  # neutering
        self.assertEqual(
            mpub, b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        xprv = mprv
        xpub = mpub

        xprv = bip32.derive(xprv, ".")  # private relative
        self.assertEqual(
            xprv, b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        xprv = bip32.derive(mprv, "m")  # private absolute
        self.assertEqual(
            xprv, b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        xpub = bip32.derive(xpub, ".")  # public relative
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        xpub = bip32.derive(mpub, "m")  # public absolute
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")

        xprv = bip32.derive(xprv, "./0'")  # private relative
        self.assertEqual(
            xprv, b"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        xprv = bip32.derive(mprv, "m/0'")  # private absolute
        self.assertEqual(
            xprv, b"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

        xprv = bip32.derive(xprv, "./1")  # private relative
        self.assertEqual(
            xprv, b"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
        xprv = bip32.derive(mprv, "m/0'/1")  # private absolute
        self.assertEqual(
            xprv, b"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
        xpub = bip32.derive(xpub, "./1")  # public relative
        self.assertEqual(
            xpub, b"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")

        xprv = bip32.derive(xprv, "./2H")  # private relative
        self.assertEqual(
            xprv, b"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")
        xprv = bip32.derive(mprv, "m/0'/1/2'")  # private absolute
        self.assertEqual(
            xprv, b"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")

        xprv = bip32.derive(xprv, "./2")  # private relative
        self.assertEqual(
            xprv, b"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334")
        xprv = bip32.derive(mprv, "m/0'/1/2'/2")  # private absolute
        self.assertEqual(
            xprv, b"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334")
        xpub = bip32.derive(xpub, "./2")  # public relative
        self.assertEqual(
            xpub, b"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")

        xprv = bip32.derive(xprv, "./1000000000")  # private relative
        self.assertEqual(
            xprv, b"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
        xprv = bip32.derive(mprv, "m/0'/1/2'/2/1000000000")  # private absolute
        self.assertEqual(
            xprv, b"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
        xpub = bip32.derive(xpub, "./1000000000")  # public relative
        self.assertEqual(
            xpub, b"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")

    def test_vector2(self):
        """ BIP32 test vestor 2
            https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        """
        xkey_version = bip32.PRIVATE[0]

        seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        mprv = bip32.mprv_from_seed(seed, xkey_version)
        self.assertEqual(
            mprv, b"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")
        mpub = bip32.xpub_from_xprv(mprv)  # neutering
        self.assertEqual(
            mpub, b"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")
        xprv = mprv
        xpub = mpub

        xprv = bip32.derive(xprv, ".")  # private relative
        self.assertEqual(
            xprv, b"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")
        xprv = bip32.derive(mprv, "m")  # private absolute
        self.assertEqual(
            xprv, b"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")
        xpub = bip32.derive(xpub, ".")  # public relative
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")
        xpub = bip32.derive(mpub, "m")  # public absolute
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")

        xprv = bip32.derive(xprv, "./0")  # private relative
        self.assertEqual(
            xprv, b"xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")
        xprv = bip32.derive(mprv, "m/0")  # private absolute
        self.assertEqual(
            xprv, b"xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")
        xpub = bip32.derive(xpub, "./0")  # public relative
        self.assertEqual(
            xpub, b"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")
        xpub = bip32.derive(mpub, "m/0")  # public absolute
        self.assertEqual(
            xpub, b"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")

        xprv = bip32.derive(xprv, "./2147483647H")  # private relative
        self.assertEqual(
            xprv, b"xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")
        xprv = bip32.derive(mprv, "m/0/2147483647H")  # private absolute
        self.assertEqual(
            xprv, b"xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a")

        xprv = bip32.derive(xprv, "./1")  # private relative
        self.assertEqual(
            xprv, b"xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef")
        xprv = bip32.derive(mprv, "m/0/2147483647H/1")  # private absolute
        self.assertEqual(
            xprv, b"xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef")
        xpub = bip32.derive(xpub, "./1")  # public relative
        self.assertEqual(
            xpub, b"xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon")

        xprv = bip32.derive(xprv, "./2147483646H")  # private relative
        self.assertEqual(
            xprv, b"xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")
        # private absolute
        xprv = bip32.derive(mprv, "m/0/2147483647H/1/2147483646H")
        self.assertEqual(
            xprv, b"xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")

        xprv = bip32.derive(xprv, "./2")  # private relative
        self.assertEqual(
            xprv, b"xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
        # private absolute
        xprv = bip32.derive(mprv, "m/0/2147483647H/1/2147483646H/2")
        self.assertEqual(
            xprv, b"xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
        xpub = bip32.derive(xpub, "./2")  # public relative
        self.assertEqual(
            xpub, b"xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")

    def test_vector3(self):
        """ BIP32 test vestor 3
            https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        """
        xkey_version = bip32.PRIVATE[0]

        seed = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
        mprv = bip32.mprv_from_seed(seed, xkey_version)
        self.assertEqual(
            mprv, b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        mpub = bip32.xpub_from_xprv(mprv)  # neutering
        self.assertEqual(
            mpub, b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")
        xprv = mprv
        xpub = mpub

        xprv = bip32.derive(xprv, ".")  # private relative
        self.assertEqual(
            xprv, b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        xprv = bip32.derive(mprv, "m")  # private absolute
        self.assertEqual(
            xprv, b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        xpub = bip32.derive(xpub, ".")  # public relative
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")
        xpub = bip32.derive(mpub, "m")  # public absolute
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")

        xprv = bip32.derive(xprv, "./0'")  # private relative
        self.assertEqual(
            xprv, b"xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
        xprv = bip32.derive(mprv, "m/0'")  # private absolute
        self.assertEqual(
            xprv, b"xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")

    def test_bip39_vectors(self):
        """ BIP32 test vectors from BIP39
            https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
        """
        filename = "test_bip39_vectors.json"
        path_to_filename = os.path.join(os.path.dirname(__file__),
                                        "./data/",
                                        filename)
        with open(path_to_filename, 'r') as f:
            test_vectors = json.load(f)["english"]
        f.closed
        xkey_version = bip32.PRIVATE[0]
        for test_vector in test_vectors:
            seed = test_vector[2]
            mprv = bip32.mprv_from_seed(seed, xkey_version)
            self.assertEqual(mprv.decode(), test_vector[3])

    def test_mainnet(self):
        # bitcoin core derivation style
        mprv = b'xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS'

        # m/0'/0'/463'
        addr1 = b'1DyfBWxhVLmrJ7keyiHeMbt7N3UdeGU4G5'
        indexes = [0x80000000, 0x80000000, 0x80000000 + 463]
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(bip32.derive(mprv, indexes)))
        self.assertEqual(addr, addr1)
        path = "m/0'/0'/463'"
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(bip32.derive(mprv, path)))
        self.assertEqual(addr, addr1)

        # m/0'/0'/267'
        addr2 = b'11x2mn59Qy43DjisZWQGRResjyQmgthki'
        indexes = [0x80000000, 0x80000000, 0x80000000 + 267]
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(bip32.derive(mprv, indexes)))
        self.assertEqual(addr, addr2)
        path = "m/0'/0'/267'"
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(bip32.derive(mprv, path)))
        self.assertEqual(addr, addr2)

        xkey_version = bip32.PRIVATE[0]
        seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
        seed = bytes.fromhex(seed)
        xprv = bip32.mprv_from_seed(seed, xkey_version)
        xpub = b'xpub661MyMwAqRbcFMYjmw8C6dJV97a4oLss6hb3v9wTQn2X48msQB61RCaLGtNhzgPCWPaJu7SvuB9EBSFCL43kTaFJC3owdaMka85uS154cEh'
        self.assertEqual(bip32.xpub_from_xprv(xprv), xpub)

        ind = [0, 0]
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'1FcfDbWwGs1PmyhMVpCAhoTfMnmSuptH6g')

        ind = [0, 1]
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'1K5GjYkZnPFvMDTGaQHTrVnd8wjmrtfR5x')

        ind = [0, 2]
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'1PQYX2uN7NYFd7Hq22ECMzfDcKhtrHmkfi')

        ind = [1, 0]
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'1BvSYpojWoWUeaMLnzbkK55v42DbizCoyq')

        ind = [1, 1]
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'1NXB59hF4QzYpFrB7o6usLBjbk2D3ZqxAL')

        ind = [1, 2]
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'16NLYkKtvYhW1Jp86tbocku3gxWcvitY1w')

        # version/key mismatch in extended parent key
        bmprv = b58decode_check(mprv)
        bad_mprv = b58encode_check(bmprv[0:45] + b'\x01' + bmprv[46:])
        self.assertRaises(ValueError, bip32.ckd, bad_mprv, 1)
        #bip32.ckd(bad_mprv, 1)

        # version/key mismatch in extended parent key
        mpub = bip32.xpub_from_xprv(mprv)
        bmpub = b58decode_check(mpub)
        bad_mpub = b58encode_check(bmpub[0:45] + b'\x00' + bmpub[46:])
        self.assertRaises(ValueError, bip32.ckd, bad_mpub, 1)
        #bip32.ckd(bad_mpub, 1)

        # no private/hardened derivation from pubkey
        self.assertRaises(ValueError, bip32.ckd, mpub, 0x80000000)
        #bip32.ckd(mpub, 0x80000000)



    def test_testnet(self):
        # bitcoin core derivation style
        mprv = b'tprv8ZgxMBicQKsPe3g3HwF9xxTLiyc5tNyEtjhBBAk29YA3MTQUqULrmg7aj9qTKNfieuu2HryQ6tGVHse9x7ANFGs3f4HgypMc5nSSoxwf7TK'

        # m/0'/0'/51'
        addr1 = b'mfXYCCsvWPgeCv8ZYGqcubpNLYy5nYHbbj'
        indexes = [0x80000000, 0x80000000, 0x80000000 + 51]
        addr = bip32.address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(mprv, indexes)))
        self.assertEqual(addr, addr1)
        path = "m/0'/0'/51'"
        addr = bip32.address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(mprv, path)))
        self.assertEqual(addr, addr1)

        # m/0'/1'/150'
        addr2 = b'mfaUnRFxVvf55uD1P3zWXpprN1EJcKcGrb'
        indexes = [0x80000000, 0x80000000 + 1, 0x80000000 + 150]
        addr = bip32.address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(mprv, indexes)))
        self.assertEqual(addr, addr2)
        path = "m/0'/1'/150'"
        addr = bip32.address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(mprv, path)))
        self.assertEqual(addr, addr2)

    def test_altnet(self):
        # non-bitcoin address version
        addr_version = 0x46.to_bytes(1, 'big')

        mprv = b'xprv9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L'

        # m/0'/0'/5'
        receive = b'VUqyLGVdUADWEqDqL2DeUBAcbPQwZfWDDY'
        indexes = [0x80000000, 0x80000000, 0x80000005]
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(
            bip32.derive(mprv, indexes)), addr_version)
        self.assertEqual(addr, receive)
        path = "m/0'/0'/5'"
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(
            bip32.derive(mprv, path)), addr_version)
        self.assertEqual(addr, receive)

        # m/0'/1'/1'
        change = b'VMg6DpX7SQUsoECdpXJ8Bv6R7p11PfwHwy'
        indexes = [0x80000000, 0x80000001, 0x80000001]
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(
            bip32.derive(mprv, indexes)), addr_version)
        self.assertEqual(addr, change)
        path = "m/0'/1'/1'"
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(
            bip32.derive(mprv, path)), addr_version)
        self.assertEqual(addr, change)

        xkey_version = bip32.PRIVATE[0]
        seed = "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570"
        seed = bytes.fromhex(seed)
        mprv = bip32.mprv_from_seed(seed, xkey_version)
        self.assertEqual(mprv, b'xprv9s21ZrQH143K3t4UZrNgeA3w861fwjYLaGwmPtQyPMmzshV2owVpfBSd2Q7YsHZ9j6i6ddYjb5PLtUdMZn8LhvuCVhGcQntq5rn7JVMqnie')

        indexes = [0x80000000, 0, 0]  # receive
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(
            bip32.derive(mprv, indexes)), addr_version)
        self.assertEqual(addr, b'VTpEhLjvGYE16pLcNrMY53gQB9bbhn581W')

        indexes = [0x80000000, 1, 0]  # change
        addr = bip32.address_from_xpub(bip32.xpub_from_xprv(
            bip32.derive(mprv, indexes)), addr_version)
        self.assertEqual(addr, b'VRtaZvAe4s29aB3vuXyq7GYEpahsQet2B1')

    def test_exceptions(self):
        mprv = b'xppp9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L'

        self.assertRaises(ValueError, bip32.ckd, mprv, 'invalid index')
        self.assertRaises(ValueError, bip32.ckd, mprv, 0x80000000)
        self.assertRaises(ValueError, bip32.ckd, mprv, "800000")
        self.assertRaises(ValueError, bip32.derive, mprv, '/1')
        self.assertRaises(TypeError, bip32.derive, mprv, 1)
        mprv = b'xprv9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L'
        self.assertRaises(ValueError, bip32.child_index, mprv)

        xkey = b'\x04\x88\xAD\xE5'  # invalid version
        xkey += b'\x00'*74
        xkey = b58encode_check(xkey)
        self.assertRaises(ValueError, bip32.ckd, xkey, 0x80000000)

    def test_crack(self):
        parent_xpub = b'xpub6BabMgRo8rKHfpAb8waRM5vj2AneD4kDMsJhm7jpBDHSJvrFAjHJHU5hM43YgsuJVUVHWacAcTsgnyRptfMdMP8b28LYfqGocGdKCFjhQMV'
        child_xprv = b'xprv9xkG88dGyiurKbVbPH1kjdYrA8poBBBXa53RKuRGJXyruuoJUDd8e4m6poiz7rV8Z4NoM5AJNcPHN6aj8wRFt5CWvF8VPfQCrDUcLU5tcTm'
        parent_xprv = bip32.crack(parent_xpub, child_xprv)
        self.assertEqual(bip32.xpub_from_xprv(parent_xprv), parent_xpub)
        index = bip32.child_index(child_xprv)
        self.assertEqual(bip32.ckd(parent_xprv, index), child_xprv)
        path = [index]
        self.assertEqual(bip32.derive(parent_xprv, path), child_xprv)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
