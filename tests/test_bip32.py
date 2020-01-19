#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import json
import unittest
from os import path

from btclib import base58, bip32, bip39
from btclib.curvemult import mult
from btclib.curves import secp256k1 as ec
from btclib.utils import int_from_octets
from btclib.wif import p2pkh_address_from_wif


class TestBIP32(unittest.TestCase):
    def test_utils(self):
        # root key, zero depth
        xkey = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        v, d, f, i, c, k, P = bip32.xkey_parse(xkey)
        self.assertEqual(P, mult(int_from_octets(k), ec.G, ec))

        decoded_key = base58.decode(xkey, 78)
        self.assertEqual(v, decoded_key[:4])
        self.assertEqual(d, decoded_key[4])
        self.assertEqual(f, decoded_key[5:9])
        self.assertEqual(i, decoded_key[9:13])
        self.assertEqual(c, decoded_key[13:45])
        self.assertEqual(k, decoded_key[45:])

        # zero depth with non-zero parent_fingerprint
        f2 = b'\x01\x01\x01\x01'
        invalid_key = base58.encode(
            v + d.to_bytes(1, 'big') + f2 + i + c + k)
        self.assertRaises(ValueError, bip32.xkey_parse, invalid_key)
        # bip32.xkey_parse(invalid_key)

        # zero depth with non-zero child_index
        i2 = b'\x01\x01\x01\x01'
        invalid_key = base58.encode(
            v + d.to_bytes(1, 'big') + f + i2 + c + k)
        self.assertRaises(ValueError, bip32.xkey_parse, invalid_key)
        # bip32.xkey_parse(invalid_key)

        # non-zero depth (255) with zero parent_fingerprint
        d2 = 255
        invalid_key = base58.encode(
            v + d2.to_bytes(1, 'big') + f + i + c + k)
        self.assertRaises(ValueError, bip32.xkey_parse, invalid_key)
        # bip32.xkey_parse(invalid_key)

        # master key provided
        self.assertRaises(ValueError, bip32.parent_fingerprint, xkey)
        # bip32.parent_fingerprint(xkey)

        f = bip32.fingerprint(xkey)
        child_key = bip32.ckd(xkey, 0)
        f2 = bip32.parent_fingerprint(child_key)
        self.assertEqual(f, f2)

        # Derivation path final depth 256>255
        self.assertRaises(ValueError, bip32.derive, child_key, "." + 255*"/0")
        #bip32.derive(child_key, "."+255*"/0")

        # Empty derivation path
        self.assertRaises(ValueError, bip32.derive, child_key, "")
        #bip32.derive(child_key, "")

        # Invalid derivation path root: ";"
        self.assertRaises(ValueError, bip32.derive, child_key, ";/0")
        #bip32.derive(child_key, ";/0")

        # Derivation path depth 256>255
        self.assertRaises(ValueError, bip32.derive, child_key, "." + 256*"/0")
        #bip32.derive(child_key, "." + 256*"/0")

        # xkey is not a public one
        self.assertRaises(ValueError, bip32.p2pkh_address_from_xpub, xkey)
        # bip32.p2pkh_address_from_xpub(xkey)

    def test_vector1(self):
        """BIP32 test vector 1

        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        """
        xkey_version = bip32._PRV_VERSIONS[0]

        seed = "000102030405060708090a0b0c0d0e0f"
        rootxprv = bip32.rootxprv_from_seed(seed, xkey_version)
        self.assertEqual(rootxprv,
                         b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        rootxprv = bip32.rootxprv_from_seed(seed, xkey_version.hex())
        self.assertEqual(rootxprv,
                         b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        rootxpub = bip32.xpub_from_xprv(rootxprv)  # neutering
        self.assertEqual(rootxpub,
                         b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")

        xprv = rootxprv
        xpub = rootxpub

        xprv = bip32.derive(xprv, ".")  # private relative
        self.assertEqual(xprv,
                         b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        xprv = bip32.derive(rootxprv, "m")  # private absolute
        self.assertEqual(xprv,
                         b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        xpub = bip32.derive(xpub, ".")  # public relative
        self.assertEqual(xpub,
                         b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        xpub = bip32.derive(rootxpub, "m")  # public absolute
        self.assertEqual(xpub,
                         b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(xpub,
                         b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")

        xprv = bip32.derive(xprv, "./0'")  # private relative
        self.assertEqual(xprv,
                         b"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        xprv = bip32.derive(rootxprv, "m/0'")  # private absolute
        self.assertEqual(xprv,
                         b"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(xpub,
                         b"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

        xprv = bip32.derive(xprv, "./1")  # private relative
        self.assertEqual(xprv,
                         b"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
        xprv = bip32.derive(rootxprv, "m/0'/1")  # private absolute
        self.assertEqual(xprv,
                         b"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
        xpub = bip32.derive(xpub, "./1")  # public relative
        self.assertEqual(xpub,
                         b"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(xpub,
                         b"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")

        xprv = bip32.derive(xprv, "./2H")  # private relative
        self.assertEqual(xprv,
                         b"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")
        xprv = bip32.derive(rootxprv, "m/0'/1/2'")  # private absolute
        self.assertEqual(xprv,
                         b"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(xpub,
                         b"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")

        xprv = bip32.derive(xprv, "./2")  # private relative
        self.assertEqual(xprv,
                         b"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334")
        xprv = bip32.derive(rootxprv, "m/0'/1/2'/2")  # private absolute
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
        # private absolute
        xprv = bip32.derive(rootxprv, "m/0'/1/2'/2/1000000000")
        self.assertEqual(
            xprv, b"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
        xpub = bip32.derive(xpub, "./1000000000")  # public relative
        self.assertEqual(
            xpub, b"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")

    def test_vector2(self):
        """BIP32 test vector 2

        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        """
        xkey_version = bip32._PRV_VERSIONS[0]

        seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        rootxprv = bip32.rootxprv_from_seed(seed, xkey_version)
        self.assertEqual(
            rootxprv, b"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")
        rootxpub = bip32.xpub_from_xprv(rootxprv)  # neutering
        self.assertEqual(
            rootxpub, b"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")
        xprv = rootxprv
        xpub = rootxpub

        xprv = bip32.derive(xprv, ".")  # private relative
        self.assertEqual(
            xprv, b"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")
        xprv = bip32.derive(rootxprv, "m")  # private absolute
        self.assertEqual(
            xprv, b"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")
        xpub = bip32.derive(xpub, ".")  # public relative
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")
        xpub = bip32.derive(rootxpub, "m")  # public absolute
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")

        xprv = bip32.derive(xprv, "./0")  # private relative
        self.assertEqual(
            xprv, b"xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")
        xprv = bip32.derive(rootxprv, "m/0")  # private absolute
        self.assertEqual(
            xprv, b"xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")
        xpub = bip32.derive(xpub, "./0")  # public relative
        self.assertEqual(
            xpub, b"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")
        xpub = bip32.derive(rootxpub, "m/0")  # public absolute
        self.assertEqual(
            xpub, b"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")

        xprv = bip32.derive(xprv, "./2147483647H")  # private relative
        self.assertEqual(
            xprv, b"xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")
        xprv = bip32.derive(rootxprv, "m/0/2147483647H")  # private absolute
        self.assertEqual(
            xprv, b"xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a")

        xprv = bip32.derive(xprv, "./1")  # private relative
        self.assertEqual(
            xprv, b"xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef")
        xprv = bip32.derive(rootxprv, "m/0/2147483647H/1")  # private absolute
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
        xprv = bip32.derive(rootxprv, "m/0/2147483647H/1/2147483646H")
        self.assertEqual(
            xprv, b"xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")

        xprv = bip32.derive(xprv, "./2")  # private relative
        self.assertEqual(
            xprv, b"xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
        # private absolute
        xprv = bip32.derive(rootxprv, "m/0/2147483647H/1/2147483646H/2")
        self.assertEqual(
            xprv, b"xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
        xpub = bip32.derive(xpub, "./2")  # public relative
        self.assertEqual(
            xpub, b"xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")

    def test_vector3(self):
        """BIP32 test vector 3

        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        """
        xkey_version = bip32._PRV_VERSIONS[0]

        seed = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
        rootxprv = bip32.rootxprv_from_seed(seed, xkey_version)
        self.assertEqual(
            rootxprv, b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        rootxpub = bip32.xpub_from_xprv(rootxprv)  # neutering
        self.assertEqual(
            rootxpub, b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")
        xprv = rootxprv
        xpub = rootxpub

        xprv = bip32.derive(xprv, ".")  # private relative
        self.assertEqual(
            xprv, b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        xprv = bip32.derive(rootxprv, "m")  # private absolute
        self.assertEqual(
            xprv, b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        xpub = bip32.derive(xpub, ".")  # public relative
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")
        xpub = bip32.derive(rootxpub, "m")  # public absolute
        self.assertEqual(
            xpub, b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")

        xprv = bip32.derive(xprv, "./0'")  # private relative
        self.assertEqual(
            xprv, b"xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
        xprv = bip32.derive(rootxprv, "m/0'")  # private absolute
        self.assertEqual(
            xprv, b"xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
        xpub = bip32.xpub_from_xprv(xprv)  # neutering
        self.assertEqual(
            xpub, b"xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")

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
        rxprv = bip39.rootxprv_from_mnemonic(
            mnemonic, passphrase, bip32.MAIN_xprv)
        mprv = bip32.derive(rxprv, path)
        self.assertEqual(prv, mprv)
        mpub = bip32.xpub_from_xprv(mprv)
        self.assertEqual(pub, mpub)
        pub = bip32.derive(mpub, "./0/0")
        addr = bip32.address_from_xpub(pub)
        self.assertEqual(address, addr)

        path = "m/49'/0'/0'"
        prv = b"yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF"
        pub = b"ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"
        address = b"37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
        rxprv = bip39.rootxprv_from_mnemonic(
            mnemonic, passphrase, bip32.MAIN_yprv)
        mprv = bip32.derive(rxprv, path)
        self.assertEqual(prv, mprv)
        mpub = bip32.xpub_from_xprv(mprv)
        self.assertEqual(pub, mpub)
        pub = bip32.derive(mpub, "./0/0")
        addr = bip32.address_from_xpub(pub)
        self.assertEqual(address, addr)
        addr = bip32.p2wpkh_p2sh_address_from_xpub(pub)
        self.assertEqual(address, addr)

        path = "m/84'/0'/0'"
        prv = b"zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
        pub = b"zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
        address = b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        rxprv = bip39.rootxprv_from_mnemonic(
            mnemonic, passphrase, bip32.MAIN_zprv)
        mprv = bip32.derive(rxprv, path)
        self.assertEqual(prv, mprv)
        mpub = bip32.xpub_from_xprv(mprv)
        self.assertEqual(pub, mpub)
        pub = bip32.derive(mpub, "./0/0")
        addr = bip32.address_from_xpub(pub)
        self.assertEqual(address, addr)

    def test_bip39_vectors(self):
        """BIP32 test vectors from BIP39

        https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
        """
        filename = "bip39_test_vectors.json"
        path_to_filename = path.join(path.dirname(__file__),
                                     "./data/", filename)
        with open(path_to_filename, 'r') as f:
            test_vectors = json.load(f)["english"]
        f.closed
        xkey_version = bip32._PRV_VERSIONS[0]
        for test_vector in test_vectors:
            seed = test_vector[2]
            rootxprv = bip32.rootxprv_from_seed(seed, xkey_version)
            self.assertEqual(rootxprv.decode(), test_vector[3])

    def test_mainnet(self):
        # bitcoin core derivation style
        rootxprv = b'xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS'

        # m/0'/0'/463'
        addr1 = b'1DyfBWxhVLmrJ7keyiHeMbt7N3UdeGU4G5'
        indexes = [0x80000000, 0x80000000, 0x80000000 + 463]
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(rootxprv, indexes)))
        self.assertEqual(addr, addr1)
        path = "m/0'/0'/463'"
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(rootxprv, path)))
        self.assertEqual(addr, addr1)

        # m/0'/0'/267'
        addr2 = b'11x2mn59Qy43DjisZWQGRResjyQmgthki'
        indexes = [0x80000000, 0x80000000, 0x80000000 + 267]
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(rootxprv, indexes)))
        self.assertEqual(addr, addr2)
        path = "m/0'/0'/267'"
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(rootxprv, path)))
        self.assertEqual(addr, addr2)

        xkey_version = bip32._PRV_VERSIONS[0]
        seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
        seed = bytes.fromhex(seed)
        xprv = bip32.rootxprv_from_seed(seed, xkey_version)
        xpub = b'xpub661MyMwAqRbcFMYjmw8C6dJV97a4oLss6hb3v9wTQn2X48msQB61RCaLGtNhzgPCWPaJu7SvuB9EBSFCL43kTaFJC3owdaMka85uS154cEh'
        self.assertEqual(bip32.xpub_from_xprv(xprv), xpub)

        ind = [0, 0]
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'1FcfDbWwGs1PmyhMVpCAhoTfMnmSuptH6g')

        ind = [0, 1]
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'1K5GjYkZnPFvMDTGaQHTrVnd8wjmrtfR5x')

        ind = [0, 2]
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'1PQYX2uN7NYFd7Hq22ECMzfDcKhtrHmkfi')

        ind = [1, 0]
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'1BvSYpojWoWUeaMLnzbkK55v42DbizCoyq')

        ind = [1, 1]
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'1NXB59hF4QzYpFrB7o6usLBjbk2D3ZqxAL')

        ind = [1, 2]
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(xprv, ind)))
        self.assertEqual(addr, b'16NLYkKtvYhW1Jp86tbocku3gxWcvitY1w')

        # version/key mismatch in extended parent key
        temp = base58.decode(rootxprv)
        bad_xprv = base58.encode(temp[0:45] + b'\x01' + temp[46:])
        self.assertRaises(ValueError, bip32.ckd, bad_xprv, 1)
        #bip32.ckd(bad_xprv, 1)

        # version/key mismatch in extended parent key
        xpub = bip32.xpub_from_xprv(rootxprv)
        temp = base58.decode(xpub)
        bad_xpub = base58.encode(temp[0:45] + b'\x00' + temp[46:])
        self.assertRaises(ValueError, bip32.ckd, bad_xpub, 1)
        #bip32.ckd(bad_xpub, 1)

        # no private/hardened derivation from pubkey
        self.assertRaises(ValueError, bip32.ckd, xpub, 0x80000000)
        #bip32.ckd(xpub, 0x80000000)

    def test_testnet(self):
        # bitcoin core derivation style
        rootxprv = b'tprv8ZgxMBicQKsPe3g3HwF9xxTLiyc5tNyEtjhBBAk29YA3MTQUqULrmg7aj9qTKNfieuu2HryQ6tGVHse9x7ANFGs3f4HgypMc5nSSoxwf7TK'

        # m/0'/0'/51'
        addr1 = b'mfXYCCsvWPgeCv8ZYGqcubpNLYy5nYHbbj'
        indexes = [0x80000000, 0x80000000, 0x80000000 + 51]
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(rootxprv, indexes)))
        self.assertEqual(addr, addr1)
        path = "m/0'/0'/51'"
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(rootxprv, path)))
        self.assertEqual(addr, addr1)

        # m/0'/1'/150'
        addr2 = b'mfaUnRFxVvf55uD1P3zWXpprN1EJcKcGrb'
        indexes = [0x80000000, 0x80000000 + 1, 0x80000000 + 150]
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(rootxprv, indexes)))
        self.assertEqual(addr, addr2)
        path = "m/0'/1'/150'"
        addr = bip32.p2pkh_address_from_xpub(
            bip32.xpub_from_xprv(bip32.derive(rootxprv, path)))
        self.assertEqual(addr, addr2)

    def test_exceptions(self):
        # valid xprv
        xprv = b'xprv9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L'

        # master key provided
        self.assertRaises(ValueError, bip32.child_index, xprv)
        # bip32.child_index(xprv)

        # invalid index
        self.assertRaises(ValueError, bip32.ckd, xprv, 'invalid index')
        #bip32.ckd(xprv, 'invalid index')

        # a 4 bytes int is required, not 3
        self.assertRaises(ValueError, bip32.ckd, xprv, "800000")
        #bip32.ckd(xprv, "800000")

        # Invalid derivation path root: ""
        self.assertRaises(ValueError, bip32.derive, xprv, '/1')
        #bip32.derive(xprv, '/1')

        # object of type 'int' has no len()
        self.assertRaises(TypeError, bip32.derive, xprv, 1)
        #bip32.derive(xprv, 1)

        # invalid checksum
        xprv = b'xppp9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L'
        self.assertRaises(ValueError, bip32.ckd, xprv, 0x80000000)
        #bip32.ckd(xprv, 0x80000000)

        # invalid extended key version
        version = b'\x04\x88\xAD\xE5'
        xkey = version + b'\x00'*74
        xkey = base58.encode(xkey)
        self.assertRaises(ValueError, bip32.ckd, xkey, 0x80000000)
        #bip32.ckd(xkey, 0x80000000)

        # invalid private version
        version = b'\x04\x88\xAD\xE5'
        seed = "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570"
        self.assertRaises(ValueError, bip32.rootxprv_from_seed, seed, version)
        #bip32.rootxprv_from_seed(seed, version)

        # extended key is not a private one
        xpub = b'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy'
        self.assertRaises(ValueError, bip32.xpub_from_xprv, xpub)
        # bip32.xpub_from_xprv(xpub)

        # Absolute derivation path for non-master key
        self.assertRaises(ValueError, bip32.derive, xpub, "m/44'/0'/1'/0/10")
        #bip32.derive(xpub, "m/0/1")

        # empty derivation path
        self.assertRaises(ValueError, bip32.derive, xpub, "")
        #bip32.derive(xpub, "")

        # extended key is not a public one
        self.assertRaises(ValueError, bip32.p2pkh_address_from_xpub, xprv)
        # bip32.p2pkh_address_from_xpub(xprv)

        # xkey is not a public one
        xprv = b'xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS'
        self.assertRaises(ValueError, bip32.address_from_xpub, xprv)
        # bip32.address_from_xpub(xprv)
        self.assertRaises(ValueError, bip32.p2wpkh_address_from_xpub, xprv)
        # bip32.p2wpkh_address_from_xpub(xprv)
        self.assertRaises(
            ValueError, bip32.p2wpkh_p2sh_address_from_xpub, xprv)
        # bip32.p2wpkh_p2sh_address_from_xpub(xprv)

    def test_crack(self):
        parent_xpub = b'xpub6BabMgRo8rKHfpAb8waRM5vj2AneD4kDMsJhm7jpBDHSJvrFAjHJHU5hM43YgsuJVUVHWacAcTsgnyRptfMdMP8b28LYfqGocGdKCFjhQMV'
        child_xprv = b'xprv9xkG88dGyiurKbVbPH1kjdYrA8poBBBXa53RKuRGJXyruuoJUDd8e4m6poiz7rV8Z4NoM5AJNcPHN6aj8wRFt5CWvF8VPfQCrDUcLU5tcTm'
        parent_xprv = bip32.crack(parent_xpub, child_xprv)
        self.assertEqual(bip32.xpub_from_xprv(parent_xprv), parent_xpub)
        index = bip32.child_index(child_xprv)
        self.assertEqual(bip32.ckd(parent_xprv, index), child_xprv)
        path = [index]
        self.assertEqual(bip32.derive(parent_xprv, path), child_xprv)

        # extended parent key is not a public one
        self.assertRaises(ValueError, bip32.crack, parent_xprv, child_xprv)
        #bip32.crack(parent_xprv, child_xprv)

        # extended child key is not a private one
        self.assertRaises(ValueError, bip32.crack, parent_xpub, parent_xpub)
        #bip32.crack(parent_xpub, parent_xpub)

        # wrong child/parent depth relation
        child_xpub = bip32.xpub_from_xprv(child_xprv)
        self.assertRaises(ValueError, bip32.crack, child_xpub, child_xprv)
        #bip32.crack(child_xpub, child_xprv)

        # not a child for the provided parent
        child0_xprv = bip32.ckd(parent_xprv, 0)
        grandchild_xprv = bip32.ckd(child0_xprv, 0)
        self.assertRaises(ValueError, bip32.crack, child_xpub, grandchild_xprv)
        #bip32.crack(child_xpub, grandchild_xprv)

        # hardened derivation
        hardened_child_xprv = bip32.ckd(parent_xprv, 0x80000000)
        self.assertRaises(ValueError, bip32.crack,
                          parent_xpub, hardened_child_xprv)
        #bip32.crack(parent_xpub, hardened_child_xprv)

    def test_testnet_versions(self):

        # data cross-checked with Electrum and https://jlopp.github.io/xpub-converter/

        # 128 bits
        raw_entr = bytes.fromhex('6'*32)
        # 12 words
        mnemonic = bip39.mnemonic_from_entropy(raw_entr, 'en')
        seed = bip39.seed_from_mnemonic(mnemonic, '')

        # p2pkh BIP44 m / 44' / coin_type' / account' / change / address_index
        path = "m/44h/1h/0h"
        version = bip32.TEST_tprv
        rootprv = bip32.rootxprv_from_seed(seed, version)
        xprv = bip32.derive(rootprv, path)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = b'tpubDChqWo2Xi2wNsxyJBE8ipcTJHLKWcqeeNUKBVTpUCNPZkHzHTm3qKAeHqgCou1t8PAY5ZnJ9QDa6zXSZxmjDnhiBpgZ7f6Yv88wEm5HXVbm'
        self.assertEqual(xpub, exp)
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = bip32.p2pkh_address_from_xpub(xpub_ext)
        exp_address = b'moutHSzeFWViMNEcvBxKzNCMj2kca8MvE1'
        self.assertEqual(address, exp_address)
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = bip32.p2pkh_address_from_xpub(xpub_int)
        exp_address = b'myWcXdNais9ExumnGKnNoJwoihQKfNPG9i'
        self.assertEqual(address, exp_address)

        # legacy segwit (p2wpkh-p2sh) m / 49'/ coin_type' / account' / change / address_index
        path = "m/49h/1h/0h"
        version = bip32.TEST_uprv
        rootprv = bip32.rootxprv_from_seed(seed, version)
        xprv = bip32.derive(rootprv, path)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = b'upub5Dj8j7YrwodV68mt58QmNpSzjqjso2WMXEpLGLSvskKccGuXhCh3dTedkzVLAePA617UyXAg2vdswJXTYjU4qjMJaHU79GJVVJCAiy9ezZ2'
        self.assertEqual(xpub, exp)
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = bip32.p2wpkh_p2sh_address_from_xpub(xpub_ext)
        exp_address = b'2Mw8tQ6uT6mHhybarVhjgomUhHQJTeV9A2c'
        self.assertEqual(address, exp_address)
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = bip32.p2wpkh_p2sh_address_from_xpub(xpub_int)
        exp_address = b'2N872CRJ3E1CzWjfixXr3aeC3hkF5Cz4kWb'
        self.assertEqual(address, exp_address)

        # legacy segwit (p2wsh-p2sh) m / 49'/ coin_type' / account' / change / address_index
        path = "m/49h/1h/0h"
        version = bip32.TEST_Uprv
        rootprv = bip32.rootxprv_from_seed(seed, version)
        xprv = bip32.derive(rootprv, path)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = b'Upub5QdDrMHJWmBrWhwG1nskCtnoTdn91PBwqWU1BbiUFXA2ETUSTc5KiaWZZhSoj5c4KUBTr7Anv92P4U9Dqxd1zDTyQkaWYfmVP2U3Js1W5cG'
        self.assertEqual(xpub, exp)

        # native segwit (p2wpkh) m / 84'/ coin_type' / account' / change / address_index
        path = "m/84h/1h/0h"
        version = bip32.TEST_vprv
        rootprv = bip32.rootxprv_from_seed(seed, version)
        xprv = bip32.derive(rootprv, path)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = b'vpub5ZhJmduYY7M5J2qCJgSW7hunX6zJrr5WuNg2kKt321HseZEYxqJc6Zso47aNXQw3Wf3sA8kppbfsxnLheUNXcL3xhzeBHLNp8fTVBN6DnJF'
        self.assertEqual(xpub, exp)
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = bip32.p2wpkh_address_from_xpub(xpub_ext)
        # this is regtest, not testnet!!
        exp_address = b'bcrt1qv8lcnmj09rpdqwgl025h2deygur64z4hqf7me5'
        # FIXME: self.assertEqual(address, exp_address)
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = bip32.p2wpkh_address_from_xpub(xpub_int)
        # this is regtest, not testnet!!
        exp_address = b'bcrt1qqhxvky4y6qkwpvdzqjkdafmj20vs5trmt6y8w5'
        # FIXME: self.assertEqual(address, exp_address)

        # native segwit (p2wsh) m / 84'/ coin_type' / account' / change / address_index
        path = "m/84h/1h/0h"
        version = bip32.TEST_Vprv
        rootprv = bip32.rootxprv_from_seed(seed, version)
        xprv = bip32.derive(rootprv, path)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = b'Vpub5kbPtsdz74uSibzaFLuUwnFbEu2a5Cm7DeKhfb9aPn8HGjoTjEgtBgjirpXr5r9wk87r2ikwhp4P5wxTwhXUkpAdYTkagjqp2PjMmGPBESU'
        self.assertEqual(xpub, exp)

    def test_mainnet_versions(self):

        # data cross-checked with Electrum and https://jlopp.github.io/xpub-converter/

        # 128 bits
        raw_entr = bytes.fromhex('6'*32)
        # 12 words
        mnemonic = bip39.mnemonic_from_entropy(raw_entr, 'en')
        seed = bip39.seed_from_mnemonic(mnemonic, '')

        # p2pkh BIP44 m / 44' / coin_type' / account' / change / address_index
        path = "m/44h/0h/0h"
        version = bip32.MAIN_xprv
        rootprv = bip32.rootxprv_from_seed(seed, version)
        xprv = bip32.derive(rootprv, path)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = b'xpub6C3uWu5Go5q62JzJpbjyCLYRGLYvexFeiepZTsYZ6SRexARkNfjG7GKtQVuGR3KHsyKsAwv7Hz3iNucPp6pfHiLvBczyK1j5CtBtpHB3NKx'
        self.assertEqual(xpub, exp)
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = bip32.p2pkh_address_from_xpub(xpub_ext)
        exp_address = b'1DDKKVHoFWGfctyEEJvrusqq6ipEaieGCq'
        self.assertEqual(address, exp_address)
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = bip32.p2pkh_address_from_xpub(xpub_int)
        exp_address = b'1FhKoffreKHzhtBMVW9NSsg3ZF148JPGoR'
        self.assertEqual(address, exp_address)

        # legacy segwit (p2wpkh-p2sh) m / 49'/ coin_type' / account' / change / address_index
        path = "m/49h/0h/0h"
        version = bip32.MAIN_yprv
        rootprv = bip32.rootxprv_from_seed(seed, version)
        xprv = bip32.derive(rootprv, path)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = b'ypub6YBGdYufCVeoPVmNXfdrWhaBCXsQoLKNetNmD9bPTrKmnKVmiyU8f1uJqwGdmBb8kbAZpHoYfXQTLbWpkXc4skQDAreeCUXdbX9k8vtiHsN'
        self.assertEqual(xpub, exp)
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = bip32.p2wpkh_p2sh_address_from_xpub(xpub_ext)
        exp_address = b'3FmNAiTCWe5kPMgc4dtSgEdY8VuaCiJEH8'
        self.assertEqual(address, exp_address)
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = bip32.p2wpkh_p2sh_address_from_xpub(xpub_int)
        exp_address = b'34FLgkoRYX5Q5fqiZCZDwsK5GpXxmFuLJN'
        self.assertEqual(address, exp_address)

        # legacy segwit (p2wsh-p2sh) m / 49'/ coin_type' / account' / change / address_index
        path = "m/49h/0h/0h"
        version = bip32.MAIN_Yprv
        rootprv = bip32.rootxprv_from_seed(seed, version)
        xprv = bip32.derive(rootprv, path)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = b'Ypub6j5Mkne6mTDAp4vkUL6qLmuyvKug1gzxyA2S8QrvqdABQW4gVNrQk8mEeeE7Kcp2z4EYgsofYjnxTm8b3km22EWt1Km3bszdVFRcipc6rXu'
        self.assertEqual(xpub, exp)

        # native segwit (p2wpkh) m / 84'/ coin_type' / account' / change / address_index
        path = "m/84h/0h/0h"
        version = bip32.MAIN_zprv
        rootprv = bip32.rootxprv_from_seed(seed, version)
        xprv = bip32.derive(rootprv, path)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = b'zpub6qg3Uc1BAQkQvcBUYMmZHSzbsshSon3FvJ8yvH3ZZMjFNvJkwSji8UUwghiF3wvpvSvcNWVP8kfUhc2V2RwGp6pTC3ouj6njj956f26TniN'
        self.assertEqual(xpub, exp)
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = bip32.p2wpkh_address_from_xpub(xpub_ext)
        exp_address = b'bc1q0hy024867ednvuhy9en4dggflt5w9unw4ztl5a'
        self.assertEqual(address, exp_address)
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = bip32.p2wpkh_address_from_xpub(xpub_int)
        exp_address = b'bc1qy4x03jyl88h2zeg7l287xhv2xrwk4c3ztfpjd2'
        self.assertEqual(address, exp_address)

        # native segwit (p2wsh) m / 84'/ coin_type' / account' / change / address_index
        path = "m/84h/0h/0h"
        version = bip32.MAIN_Zprv
        rootprv = bip32.rootxprv_from_seed(seed, version)
        xprv = bip32.derive(rootprv, path)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = b'Zpub72a8bqjcjNJnMBLrV2EY7XLQbfji28irEZneqYK6w8Zf16sfhr7zDbLsVQficP9j9uzbF6VW1y3ypmeFKf6Dxaw82WvK8WFjcsLyEvMNZjF'
        self.assertEqual(xpub, exp)

    def test_regtest_versions(self):
        pass
        # FIXME: how to obtain regtest addresses from btclib?

    def test_wif_address_from_xkey(self):
        seed = b"00"*32  # better be random
        rxprv = bip32.rootxprv_from_seed(seed)
        path = "m/0h/0h/12"
        xprv = bip32.derive(rxprv, path)
        wif = bip32.wif_from_xprv(xprv)
        self.assertEqual(wif, b'KyLk7s6Z1FtgYEVp3bPckPVnXvLUWNCcVL6wNt3gaT96EmzTKZwP')
        address = p2pkh_address_from_wif(wif)
        address2 = bip32.address_from_xpub(bip32.xpub_from_xprv(xprv))
        self.assertEqual(address, address2)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
