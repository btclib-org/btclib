#!/usr/bin/env python3

# Copyright (C) 2019-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.bms` module."

import json
import unittest
from hashlib import sha256 as hf
from os import path

from btclib import base58address, bech32address, bip32, bms, dsa
from btclib.base58address import p2pkh, p2wpkh_p2sh
from btclib.base58wif import wif_from_prvkey
from btclib.bech32address import p2wpkh
from btclib.curves import secp256k1 as ec
from btclib.to_prvkey import prvkeyinfo_from_prvkey
from btclib.to_pubkey import pubkeyinfo_from_prvkey


class TestMessageSign(unittest.TestCase):
    def test_exceptions(self):

        msg = "test"
        wif = "KwELaABegYxcKApCb3kJR9ymecfZZskL9BzVUkQhsqFiUKftb4tu"
        pubkey, _ = pubkeyinfo_from_prvkey(wif)
        address = base58address.p2pkh(pubkey)
        exp_sig = (
            "IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615"
            "FG3g9JEOPGVvcfDWIFWrg2exLNtoVc="
        ).encode()
        assert bms.verify(msg, address, exp_sig)

        # Invalid recovery flag: 26
        _, r, s = bms.deserialize(exp_sig)
        self.assertRaises(ValueError, bms.serialize, 26, r, s)
        # bms.serialize(26, r, s)

        # short exp_sig
        exp_sig = (
            "IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hNBi7J+TrI1615F"
            "G3g9JEOPGVvcfDWIFWrg2exLoVc="
        ).encode()
        self.assertRaises(ValueError, bms.assert_as_valid, msg, address, exp_sig)
        assert not bms.verify(msg, address, exp_sig)

        # Invalid recovery flag: 26
        exp_sig = (
            "GpNLHqEKSzwXV+KwwBfQthQ848mn5qSkmGDXpqshDuPYJELOnSuRYGQQg"
            "BR4PpI+w2tJdD4v+hxElvAaUSqv2eU="
        ).encode()
        self.assertRaises(ValueError, bms.assert_as_valid, msg, address, exp_sig)
        assert not bms.verify(msg, address, exp_sig)
        # bms.assert_as_valid(msg, address, exp_sig)

        # Invalid recovery flag: 66
        exp_sig = (
            "QpNLHqEKSzwXV+KwwBfQthQ848mn5qSkmGDXpqshDuPYJELOnSuRYGQQg"
            "BR4PpI+w2tJdD4v+hxElvAaUSqv2eU="
        ).encode()
        self.assertRaises(ValueError, bms.assert_as_valid, msg, address, exp_sig)
        assert not bms.verify(msg, address, exp_sig)
        # bms.assert_as_valid(msg, address, exp_sig)

        # Pubkey mismatch: compressed wif, uncompressed address
        wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
        address = "19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T"
        self.assertRaises(ValueError, bms.sign, msg, wif, address)
        # bms.sign(msg, wif, address)

        # Pubkey mismatch: uncompressed wif, compressed address
        wif = "5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn"
        address = "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"
        self.assertRaises(ValueError, bms.sign, msg, wif, address)
        # bms.sign(msg, wif, address)

        msg = "test"
        wif = "L4xAvhKR35zFcamyHME2ZHfhw5DEyeJvEMovQHQ7DttPTM8NLWCK"
        pubkey, _ = pubkeyinfo_from_prvkey(wif)
        p2pkh = base58address.p2pkh(pubkey)
        p2wpkh = bech32address.p2wpkh(pubkey)
        p2wpkh_p2sh = base58address.p2wpkh_p2sh(pubkey)

        wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
        # Mismatch between p2pkh address and key pair
        self.assertRaises(ValueError, bms.sign, msg, wif, p2pkh)
        # bms.sign(msg, wif, p2pkh)

        # Mismatch between p2wpkh address and key pair
        self.assertRaises(ValueError, bms.sign, msg, wif, p2wpkh)
        # bms.sign(msg, wif, p2wpkh)

        # Mismatch between p2wpkh_p2sh address and key pair
        self.assertRaises(ValueError, bms.sign, msg, wif, p2wpkh_p2sh)
        # bms.sign(msg, wif, p2wpkh_p2sh)

        # Invalid recovery flag (39) for base58 address
        exp_sig = (
            "IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615"
            "FG3g9JEOPGVvcfDWIFWrg2exLNtoVc="
        ).encode()
        _, r, s = bms.deserialize(exp_sig)
        sig = bms.serialize(39, r, s)
        self.assertRaises(ValueError, bms.assert_as_valid, msg, p2pkh, sig)
        # bms.assert_as_valid(msg, p2pkh, sig)

        # Invalid recovery flag (35) for bech32 address
        exp_sig = (
            "IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IO"
            "I0dpo3uGAEpCz9eepXLrA5kF35MXuU="
        ).encode()
        _, r, s = bms.deserialize(exp_sig)
        sig = bms.serialize(35, r, s)
        self.assertRaises(ValueError, bms.assert_as_valid, msg, p2wpkh, sig)
        # bms.assert_as_valid(msg, p2wpkh, sig)

    def test_one_prvkey_multiple_addresses(self):

        msg = "Paolo is afraid of ephemeral random numbers"

        # Compressed WIF
        wif = b"Kx45GeUBSMPReYQwgXiKhG9FzNXrnCeutJp4yjTd5kKxCitadm3C"
        pubkey, network = pubkeyinfo_from_prvkey(wif)
        address1 = p2pkh(pubkey, network)
        address2 = p2wpkh_p2sh(pubkey, network)
        address3 = p2wpkh(pubkey, network)

        # sign with no address (or compressed P2PKH)
        sig1 = bms.sign(msg, wif)
        # True for Bitcoin Core
        assert bms.verify(msg, address1, sig1)
        # True for Electrum p2wpkh_p2sh
        assert bms.verify(msg, address2, sig1)
        # True for Electrum p2wpkh
        assert bms.verify(msg, address3, sig1)

        # sign with p2wpkh_p2sh address (BIP137)
        sig2 = bms.sign(msg, wif, address2)
        # False for Bitcoin Core
        assert not bms.verify(msg, address1, sig2)
        # True for BIP137 p2wpkh_p2sh
        assert bms.verify(msg, address2, sig2)
        # False for BIP137 p2wpkh
        assert not bms.verify(msg, address3, sig2)

        # sign with p2wpkh address (BIP137)
        sig3 = bms.sign(msg, wif, address3)
        # False for Bitcoin Core
        assert not bms.verify(msg, address1, sig3)
        # False for BIP137 p2wpkh_p2sh
        assert not bms.verify(msg, address2, sig3)
        # True for BIP137 p2wpkh
        assert bms.verify(msg, address3, sig3)

        # uncompressed WIF / P2PKH address
        q, network, _ = prvkeyinfo_from_prvkey(wif)
        wif2 = wif_from_prvkey(q, network, False)
        pubkey, network = pubkeyinfo_from_prvkey(wif2)
        address4 = p2pkh(pubkey, network)

        # sign with uncompressed P2PKH
        sig4 = bms.sign(msg, wif2, address4)
        # False for Bitcoin Core compressed p2pkh
        assert not bms.verify(msg, address1, sig4)
        # False for BIP137 p2wpkh_p2sh
        assert not bms.verify(msg, address2, sig4)
        # False for BIP137 p2wpkh
        assert not bms.verify(msg, address3, sig4)
        # True for Bitcoin Core uncompressed p2pkh
        assert bms.verify(msg, address4, sig4)

        self.assertRaises(ValueError, bms.sign, msg, wif2, address1)
        self.assertRaises(ValueError, bms.sign, msg, wif, address4)


def test_signature():
    msg = "test message"
    wif, addr = bms.gen_keys()
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, addr, sig)

    # sig taken from (Electrum and) Bitcoin Core
    wif, addr = bms.gen_keys(b"5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw")
    exp_sig = "G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4=".encode()
    sig = bms.sign(msg, wif)
    assert exp_sig == bms.serialize(*sig)
    assert sig == bms.deserialize(sig)
    assert bms.verify(msg, addr, sig)


def test_msgsign_p2pkh():
    msg = "test message"
    # sigs are taken from (Electrum and) Bitcoin Core

    q = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"

    # uncompressed
    wif1u = wif_from_prvkey(q, "mainnet", False)
    assert wif1u == b"5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw"
    pubkey1u, _ = pubkeyinfo_from_prvkey(wif1u)
    add1u = base58address.p2pkh(pubkey1u)
    assert add1u == b"1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD"
    sig1u = bms.sign(msg, wif1u)
    assert bms.verify(msg, add1u, sig1u)
    assert sig1u[0] == 27
    exp_sig1u = "G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4=".encode()
    assert bms.serialize(*sig1u) == exp_sig1u

    # compressed
    wif1c = wif_from_prvkey(q, "mainnet", True)
    assert wif1c == b"L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk"
    pubkey1c, _ = pubkeyinfo_from_prvkey(wif1c)
    add1c = base58address.p2pkh(pubkey1c)
    assert add1c == b"14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY"
    sig1c = bms.sign(msg, wif1c)
    assert bms.verify(msg, add1c, sig1c)
    assert sig1c[0] == 31
    exp_sig1c = "H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4=".encode()
    assert bms.serialize(*sig1c) == exp_sig1c

    assert not bms.verify(msg, add1c, sig1u)
    assert not bms.verify(msg, add1u, sig1c)

    rf, r, s, = sig1c
    sig1c_malleated_rf = bms.serialize(rf + 1, r, s)
    assert not bms.verify(msg, add1c, sig1c_malleated_rf)
    sig1c_malleated_s = bms.serialize(rf, r, ec.n - s)
    assert not bms.verify(msg, add1c, sig1c_malleated_s)
    sig1c_malleated_rf_s = bms.serialize(rf + 1, r, ec.n - s)
    assert bms.verify(msg, add1c, sig1c_malleated_rf_s)


def test_msgsign_p2pkh_2():
    msg = "test message"
    # sigs are taken from (Electrum and) Bitcoin Core

    wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
    # compressed
    address = "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"
    exp_sig = "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=".encode()
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif, address)
    assert bms.verify(msg, address, sig)
    assert bms.serialize(*sig) == exp_sig
    sig = bms.sign(msg.encode(), wif)
    assert bms.verify(msg.encode(), address, sig)
    assert bms.serialize(*sig) == exp_sig

    wif = "5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn"
    # uncompressed
    address = "19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T"
    exp_sig = "HFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=".encode()
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif, address)
    assert bms.verify(msg, address, sig)
    assert bms.serialize(*sig) == exp_sig
    sig = bms.sign(msg.encode(), wif)
    assert bms.verify(msg.encode(), address, sig)
    assert bms.serialize(*sig) == exp_sig


def test_verify_p2pkh():
    msg = "Hello, world!"
    address = "1FEz167JCVgBvhJBahpzmrsTNewhiwgWVG"
    exp_sig = "G+WptuOvPCSswt/Ncm1upO4lPSCWbS2cpKariPmHvxX5eOJwgqmdEExMTKvaR0S3f1TXwggLn/m4CbI2jv0SCuM=".encode()
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/stequald/bitcoin-bms.sign-message
    msg = "test message"
    address = "14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY"
    exp_sig = "IPn9bbEdNUp6+bneZqE2YJbq9Hv5aNILq9E5eZoMSF3/fBX4zjeIN6fpXfGSGPrZyKfHQ/c/kTSP+NIwmyTzMfk=".encode()
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/stequald/bitcoin-bms.sign-message
    msg = "test message"
    address = "1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD"
    exp_sig = "G0k+Nt1u5boTTUfLyj6x1T5flg1v9rUKGlhs/jPApaTWLHf3GVdAIOIHip6sVwXEuzQGPWIlS0VT+yryXiDaavw=".encode()
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/petertodd/python-bitcoinlib/blob/master/bitcoin/tests/test_signmessage.py
    msg = address = "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
    exp_sig = "H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4=".encode()
    assert bms.verify(msg, address, exp_sig)

    # https://github.com/nanotube/supybot-bitcoin-marketmonitor/blob/master/GPG/local/bitcoinsig.py
    msg = "test message"
    address = "16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce"
    exp_sig = "HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50=".encode()
    assert bms.verify(msg, address, exp_sig)

    msg = "test message 2"
    assert not bms.verify(msg, address, exp_sig)

    msg = (
        "freenode:#bitcoin-otc:b42f7e7ea336db4109df6badc05c6b3ea8bfaa13575b51631c5178a7"
    )
    address = "1GdKjTSg2eMyeVvPV5Nivo6kR8yP2GT7wF"
    exp_sig = "GyMn9AdYeZIPWLVCiAblOOG18Qqy4fFaqjg5rjH6QT5tNiUXLS6T2o7iuWkV1gc4DbEWvyi8yJ8FvSkmEs3voWE=".encode()
    assert bms.verify(msg, address, exp_sig)

    msg = "testtest"
    address = "1Hpj6xv9AzaaXjPPisQrdAD2tu84cnPv3f"
    exp_sig = "INEJxQnSu6mwGnLs0E8eirl5g+0cAC9D5M7hALHD9sK0XQ66CH9mas06gNoIX7K1NKTLaj3MzVe8z3pt6apGJ34=".encode()
    assert bms.verify(msg, address, exp_sig)

    msg = "testtest"
    address = "18uitB5ARAhyxmkN2Sa9TbEuoGN1he83BX"
    exp_sig = "IMAtT1SjRyP6bz6vm5tKDTTTNYS6D8w2RQQyKD3VGPq2i2txGd2ar18L8/nvF1+kAMo5tNc4x0xAOGP0HRjKLjc=".encode()
    assert bms.verify(msg, address, exp_sig)

    msg = "testtest"
    address = "1LsPb3D1o1Z7CzEt1kv5QVxErfqzXxaZXv"
    exp_sig = "H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As=".encode()
    assert bms.verify(msg, address, exp_sig)

    # leading space
    exp_sig = " H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As=".encode()
    assert bms.verify(msg, address, exp_sig)

    # trailing space
    exp_sig = "H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As= ".encode()
    assert bms.verify(msg, address, exp_sig)

    # leading and trailing spaces
    exp_sig = " H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As= ".encode()
    assert bms.verify(msg, address, exp_sig)


def test_segwit():

    msg = "test"
    wif = "L4xAvhKR35zFcamyHME2ZHfhw5DEyeJvEMovQHQ7DttPTM8NLWCK"
    pubkey, _ = pubkeyinfo_from_prvkey(wif)
    p2pkh = base58address.p2pkh(pubkey)
    p2wpkh = bech32address.p2wpkh(pubkey)
    p2wpkh_p2sh = base58address.p2wpkh_p2sh(pubkey)

    # p2pkh base58 address (Core, Electrum, BIP137)
    exp_sig = "IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU=".encode()
    assert bms.verify(msg, p2pkh, exp_sig)
    sig = bms.sign(msg, wif)  # no address: p2pkh assumed
    assert bms.verify(msg, p2pkh, sig)
    assert bms.serialize(*sig) == exp_sig

    # p2wpkh-p2sh base58 address (Electrum)
    assert bms.verify(msg, p2wpkh_p2sh, sig)

    # p2wpkh bech32 address (Electrum)
    assert bms.verify(msg, p2wpkh, sig)

    # p2wpkh-p2sh base58 address (BIP137)
    # different first letter in sig because of different rf
    exp_sig = "JBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU=".encode()
    assert bms.verify(msg, p2wpkh_p2sh, exp_sig)
    sig = bms.sign(msg, wif, p2wpkh_p2sh)
    assert bms.verify(msg, p2wpkh_p2sh, sig)
    assert bms.serialize(*sig) == exp_sig

    # p2wpkh bech32 address (BIP137)
    # different first letter in sig because of different rf
    exp_sig = "KBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU=".encode()
    assert bms.verify(msg, p2wpkh, exp_sig)
    sig = bms.sign(msg, wif, p2wpkh)
    assert bms.verify(msg, p2wpkh, sig)
    assert bms.serialize(*sig) == exp_sig


def test_sign_strippable_message():

    wif = "Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ"
    address = "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"

    msg = ""
    exp_sig = "IFh0InGTy8lLCs03yoUIpJU6MUbi0La/4abhVxyKcCsoUiF3RM7lg51rCqyoOZ8Yt43h8LZrmj7nwwO3HIfesiw=".encode()
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert bms.serialize(*sig) == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = " "
    exp_sig = "IEveV6CMmOk5lFP+oDbw8cir/OkhJn4S767wt+YwhzHnEYcFOb/uC6rrVmTtG3M43mzfObA0Nn1n9CRcv5IGyak=".encode()
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert bms.serialize(*sig) == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = "  "
    exp_sig = "H/QjF1V4fVI8IHX8ko0SIypmb0yxfaZLF0o56Cif9z8CX24n4petTxolH59pYVMvbTKQkGKpznSiPiQVn83eJF0=".encode()
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert bms.serialize(*sig) == exp_sig

    msg = "test"
    exp_sig = "IJUtN/2LZjh1Vx8Ekj9opnIKA6ohKhWB95PLT/3EFgLnOu9hTuYX4+tJJ60ZyddFMd6dgAYx15oP+jLw2NzgNUo=".encode()
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert bms.serialize(*sig) == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = " test "
    exp_sig = "IA59z13/HBhvMMJtNwT6K7vJByE40lQUdqEMYhX2tnZSD+IGQIoBGE+1IYGCHCyqHvTvyGeqJTUx5ywb4StuX0s=".encode()
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert bms.serialize(*sig) == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = "test "
    exp_sig = "IPp9l2w0LVYB4FYKBahs+k1/Oa08j+NTuzriDpPWnWQmfU0+UsJNLIPI8Q/gekrWPv6sDeYsFSG9VybUKDPGMuo=".encode()
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert bms.serialize(*sig) == exp_sig

    # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
    msg = " test"
    exp_sig = "H1nGwD/kcMSmsYU6qihV2l2+Pa+7SPP9zyViZ59VER+QL9cJsIAtu1CuxfYDAVt3kgr4t3a/Es3PV82M6z0eQAo=".encode()
    assert bms.verify(msg, address, exp_sig)
    sig = bms.sign(msg, wif)
    assert bms.verify(msg, address, sig)
    assert bms.serialize(*sig) == exp_sig


def test_vector_python_bitcoinlib():
    """Test python-bitcoinlib test vectors

    https://github.com/petertodd/python-bitcoinlib/blob/master/bitcoin/tests/test_data/bms.json
    """

    fname = "bms.json"
    filename = path.join(path.dirname(__file__), "test_data", fname)
    with open(filename, "r") as f:
        test_vectors = json.load(f)

    for vector in test_vectors[:5]:
        msg = vector["address"]
        tuplesig = bms.sign(msg, vector["wif"])
        assert bms.verify(msg, vector["address"], tuplesig)
        b64sig = bms.serialize(*tuplesig)
        assert bms.verify(msg, vector["address"], b64sig)
        assert bms.verify(msg, vector["address"], vector["signature"])

        # python-bitcoinlib has a signature different from the
        # one generated by Core/Electrum/btclib (which are identical)
        assert b64sig.decode() != vector["signature"]

        # python-bitcoinlib does not use RFC6979 deterministic nonce
        # as proved by different r compared to Core/Electrum/btclib
        rf, r, s = tuplesig
        _, r0, _ = bms.deserialize(vector["signature"])
        assert r != r0

        # while Core/Electrum/btclib use "low-s" canonical signature
        assert s < ec.n - s
        # this is not true for python-bitcoinlib
        # assert s0 < ec.n - s0
        # self.assertGreater(s0, ec.n - s0)

        # just in case you wonder, here's the malleated signature
        rf += 1 if rf == 31 else -1
        tuplesig_malleated = rf, r, ec.n - s
        assert bms.verify(msg, vector["address"], tuplesig_malleated)
        b64sig_malleated = bms.serialize(*tuplesig_malleated)
        assert bms.verify(msg, vector["address"], b64sig_malleated)
        # of course,
        # it is not equal to the python-bitcoinlib one (different r)
        assert b64sig_malleated.decode() != vector["signature"]


def test_ledger():
    """Hybrid ECDSA Bitcoin message signature generated by Ledger"""

    mnemonic = (
        "barely sun snack this snack relief pipe attack disease boss enlist lawsuit"
    )

    # non-standard leading 31 in DER serialization
    derivation_path = "m/1"
    msg = b"\xfb\xa3\x1f\x8cd\x85\xe29#K\xb3{\xfd\xa7<?\x95oL\xee\x19\xb2'oh\xa7]\xd9A\xfeU\xd8"
    dersig = "3144022012ec0c174936c2a46dc657252340b2e6e6dd8c31dd059b6f9f33a90c21af2fba022030e6305b3ccf88009d419bf7651afcfcc0a30898b93ae9de9aa6ac03cf8ec56b"

    # pubkey derivation
    rprv = bip32.mxprv_from_bip39_mnemonic(mnemonic)
    xprv = bip32.derive(rprv, derivation_path)
    xpub = bip32.xpub_from_xprv(xprv)

    # the actual message being signed
    magic_msg = bms._magic_message(msg)

    # save key_id and patch dersig
    dersig = bytes.fromhex(dersig)
    key_id = dersig[0]
    dersig = b"\x30" + dersig[1:]

    r, s = dsa.deserialize(dersig)

    # ECDSA signature verification of the patched dersig
    dsa.assert_as_valid(magic_msg, xpub, dersig, ec, hf)
    assert dsa.verify(magic_msg, xpub, dersig)

    # compressed address
    addr = base58address.p2pkh(xpub)

    # equivalent Bitcoin Message Signature (non-serialized)
    rec_flag = 27 + 4 + (key_id & 0x01)
    btcmsgsig = (rec_flag, r, s)

    # Bitcoin Message Signature verification
    bms.assert_as_valid(msg, addr, btcmsgsig)
    assert bms.verify(msg, addr, btcmsgsig)
    assert not bms.verify(magic_msg, addr, btcmsgsig)

    bms.sign(msg, xprv)

    # standard leading 30 in DER serialization
    derivation_path = "m/0/0"
    msg = "hello world"
    dersig = (
        "3045022100967dac3262b4686e89638c8219c5761017f05cd87a855edf"
        "034f4a3ec6b59d3d0220108a4ef9682b71a45979d8c75c393382d9ccb8"
        "eb561d73b8c5fc0b87a47e7d27"
    )

    # pubkey derivation
    rprv = bip32.mxprv_from_bip39_mnemonic(mnemonic)
    xprv = bip32.derive(rprv, derivation_path)
    xpub = bip32.xpub_from_xprv(xprv)

    # the actual message being signed
    magic_msg = bms._magic_message(msg)

    # save key_id and patch dersig
    dersig = bytes.fromhex(dersig)
    key_id = dersig[0]
    dersig = b"\x30" + dersig[1:]

    r, s = dsa.deserialize(dersig)

    # ECDSA signature verification of the patched dersig
    dsa.assert_as_valid(magic_msg, xpub, dersig, ec, hf)
    assert dsa.verify(magic_msg, xpub, dersig)

    # compressed address
    addr = base58address.p2pkh(xpub)

    # equivalent Bitcoin Message Signature (non-serialized)
    rec_flag = 27 + 4 + (key_id & 0x01)
    btcmsgsig = (rec_flag, r, s)

    # Bitcoin Message Signature verification
    bms.assert_as_valid(msg, addr, btcmsgsig)
    assert bms.verify(msg, addr, btcmsgsig)
    assert not bms.verify(magic_msg, addr, btcmsgsig)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
