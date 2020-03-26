#!/usr/bin/env python3

# Copyright (C) 2019-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import json
import unittest
from os import path

from btclib import der, dsa
from btclib.address import p2pkh_address
from btclib.btcmsg import _verify, deserialize, serialize, sign, verify
from btclib.utils import bytes_from_hexstring
from btclib.wif import (p2pkh_address_from_wif, p2wpkh_address_from_wif,
                        p2wpkh_p2sh_address_from_wif, wif_from_prvkey)


class TestSignMessage(unittest.TestCase):
    def test_msgsign_p2pkh(self):
        msg = 'test message'
        # sigs are taken from (Electrum and) Bitcoin Core

        # first private key
        wif = 'L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk'
        address = '14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY'
        exp_sig = b'H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4='
        self.assertTrue(_verify(msg, address, exp_sig))
        sig = sign(msg, wif)
        self.assertTrue(_verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)
        sig = sign(msg.encode(), wif)
        self.assertTrue(_verify(msg.encode(), address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        wif = '5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw'
        address = '1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD'
        exp_sig = b'G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4='
        self.assertTrue(_verify(msg, address, exp_sig))
        sig = sign(msg, wif)
        self.assertTrue(_verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)
        sig = sign(msg.encode(), wif)
        self.assertTrue(_verify(msg.encode(), address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        # second private key
        wif = 'Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ'
        address = '1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5'
        exp_sig = b'IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA='
        self.assertTrue(_verify(msg, address, exp_sig))
        sig = sign(msg, wif, address)
        self.assertTrue(_verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)
        sig = sign(msg.encode(), wif)
        self.assertTrue(_verify(msg.encode(), address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        wif = '5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn'
        address = '19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T'
        exp_sig = b'HFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA='
        self.assertTrue(_verify(msg, address, exp_sig))
        sig = sign(msg, wif, address)
        self.assertTrue(_verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)
        sig = sign(msg.encode(), wif)
        self.assertTrue(_verify(msg.encode(), address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

    def test_verify_p2pkh(self):
        msg = 'Hello, world!'
        address = '1FEz167JCVgBvhJBahpzmrsTNewhiwgWVG'
        exp_sig = b'G+WptuOvPCSswt/Ncm1upO4lPSCWbS2cpKariPmHvxX5eOJwgqmdEExMTKvaR0S3f1TXwggLn/m4CbI2jv0SCuM='
        self.assertTrue(_verify(msg, address, exp_sig))

        # https://github.com/stequald/bitcoin-sign-message
        msg = 'test message'
        address = '14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY'
        exp_sig = b'IPn9bbEdNUp6+bneZqE2YJbq9Hv5aNILq9E5eZoMSF3/fBX4zjeIN6fpXfGSGPrZyKfHQ/c/kTSP+NIwmyTzMfk='
        self.assertTrue(_verify(msg, address, exp_sig))

        # https://github.com/stequald/bitcoin-sign-message
        msg = 'test message'
        address = '1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD'
        exp_sig = b'G0k+Nt1u5boTTUfLyj6x1T5flg1v9rUKGlhs/jPApaTWLHf3GVdAIOIHip6sVwXEuzQGPWIlS0VT+yryXiDaavw='
        self.assertTrue(_verify(msg, address, exp_sig))

        # https://github.com/petertodd/python-bitcoinlib/blob/master/bitcoin/tests/test_signmessage.py
        msg = address = '1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G'
        exp_sig = b'H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4='
        self.assertTrue(_verify(msg, address, exp_sig))

        # https://github.com/nanotube/supybot-bitcoin-marketmonitor/blob/master/GPG/local/bitcoinsig.py
        msg = 'test message'
        address = '16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce'
        exp_sig = b'HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50='
        self.assertTrue(_verify(msg, address, exp_sig))

        msg = 'test message 2'
        self.assertFalse(_verify(msg, address, exp_sig))

        msg = 'freenode:#bitcoin-otc:b42f7e7ea336db4109df6badc05c6b3ea8bfaa13575b51631c5178a7'
        address = '1GdKjTSg2eMyeVvPV5Nivo6kR8yP2GT7wF'
        exp_sig = b'GyMn9AdYeZIPWLVCiAblOOG18Qqy4fFaqjg5rjH6QT5tNiUXLS6T2o7iuWkV1gc4DbEWvyi8yJ8FvSkmEs3voWE='
        self.assertTrue(_verify(msg, address, exp_sig))

        msg = 'testtest'
        address = '1Hpj6xv9AzaaXjPPisQrdAD2tu84cnPv3f'
        exp_sig = b'INEJxQnSu6mwGnLs0E8eirl5g+0cAC9D5M7hALHD9sK0XQ66CH9mas06gNoIX7K1NKTLaj3MzVe8z3pt6apGJ34='
        self.assertTrue(_verify(msg, address, exp_sig))

        msg = 'testtest'
        address = '18uitB5ARAhyxmkN2Sa9TbEuoGN1he83BX'
        exp_sig = b'IMAtT1SjRyP6bz6vm5tKDTTTNYS6D8w2RQQyKD3VGPq2i2txGd2ar18L8/nvF1+kAMo5tNc4x0xAOGP0HRjKLjc='
        self.assertTrue(_verify(msg, address, exp_sig))

        msg = 'testtest'
        address = '1LsPb3D1o1Z7CzEt1kv5QVxErfqzXxaZXv'
        exp_sig = b'H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As='
        self.assertTrue(_verify(msg, address, exp_sig))

        # leading space
        exp_sig = b' H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As='
        self.assertTrue(_verify(msg, address, exp_sig))

        # trailing space
        exp_sig = b'H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As= '
        self.assertTrue(_verify(msg, address, exp_sig))

        # leading and trailing spaces
        exp_sig = b' H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As= '
        self.assertTrue(_verify(msg, address, exp_sig))

    def test_segwit(self):

        msg = 'test'
        wif = 'L4xAvhKR35zFcamyHME2ZHfhw5DEyeJvEMovQHQ7DttPTM8NLWCK'
        p2pkh_address = p2pkh_address_from_wif(wif)
        p2wpkh_address = p2wpkh_address_from_wif(wif)
        p2wpkh_p2sh_address = p2wpkh_p2sh_address_from_wif(wif)

        # p2pkh base58 address (Core, Electrum, BIP137)
        exp_sig = b'IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU='
        self.assertTrue(_verify(msg, p2pkh_address, exp_sig))
        sig = sign(msg, wif)  # no address: p2pkh assumed
        self.assertTrue(_verify(msg, p2pkh_address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        # p2wpkh-p2sh base58 address (Electrum)
        self.assertTrue(_verify(msg, p2wpkh_p2sh_address, sig))

        # p2wpkh bech32 address (Electrum)
        self.assertTrue(_verify(msg, p2wpkh_address, sig))

        # p2wpkh-p2sh base58 address (BIP137)
        # different first letter in sig because of different rf
        exp_sig = b'JBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU='
        self.assertTrue(_verify(msg, p2wpkh_p2sh_address, exp_sig))
        sig = sign(msg, wif, p2wpkh_p2sh_address)
        self.assertTrue(_verify(msg, p2wpkh_p2sh_address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        # p2wpkh bech32 address (BIP137)
        # different first letter in sig because of different rf
        exp_sig = b'KBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU='
        self.assertTrue(_verify(msg, p2wpkh_address, exp_sig))
        sig = sign(msg, wif, p2wpkh_address)
        self.assertTrue(_verify(msg, p2wpkh_address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

    def test_sign_strippable_message(self):

        wif = 'Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ'
        address = '1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5'

        msg = ''
        exp_sig = b'IFh0InGTy8lLCs03yoUIpJU6MUbi0La/4abhVxyKcCsoUiF3RM7lg51rCqyoOZ8Yt43h8LZrmj7nwwO3HIfesiw='
        self.assertTrue(verify(msg, address, exp_sig))
        sig = sign(msg, wif)
        self.assertTrue(verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
        msg = ' '
        exp_sig = b'IEveV6CMmOk5lFP+oDbw8cir/OkhJn4S767wt+YwhzHnEYcFOb/uC6rrVmTtG3M43mzfObA0Nn1n9CRcv5IGyak='
        self.assertTrue(verify(msg, address, exp_sig))
        sig = sign(msg, wif)
        self.assertTrue(verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
        msg = '  '
        exp_sig = b'H/QjF1V4fVI8IHX8ko0SIypmb0yxfaZLF0o56Cif9z8CX24n4petTxolH59pYVMvbTKQkGKpznSiPiQVn83eJF0='
        self.assertTrue(verify(msg, address, exp_sig))
        sig = sign(msg, wif)
        self.assertTrue(verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        msg = 'test'
        exp_sig = b'IJUtN/2LZjh1Vx8Ekj9opnIKA6ohKhWB95PLT/3EFgLnOu9hTuYX4+tJJ60ZyddFMd6dgAYx15oP+jLw2NzgNUo='
        self.assertTrue(verify(msg, address, exp_sig))
        sig = sign(msg, wif)
        self.assertTrue(verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
        msg = ' test '
        exp_sig = b'IA59z13/HBhvMMJtNwT6K7vJByE40lQUdqEMYhX2tnZSD+IGQIoBGE+1IYGCHCyqHvTvyGeqJTUx5ywb4StuX0s='
        self.assertTrue(verify(msg, address, exp_sig))
        sig = sign(msg, wif)
        self.assertTrue(verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
        msg = 'test '
        exp_sig = b'IPp9l2w0LVYB4FYKBahs+k1/Oa08j+NTuzriDpPWnWQmfU0+UsJNLIPI8Q/gekrWPv6sDeYsFSG9VybUKDPGMuo='
        self.assertTrue(verify(msg, address, exp_sig))
        sig = sign(msg, wif)
        self.assertTrue(verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

        # Bitcoin Core exp_sig (Electrum does strip leading/trailing spaces)
        msg = ' test'
        exp_sig = b'H1nGwD/kcMSmsYU6qihV2l2+Pa+7SPP9zyViZ59VER+QL9cJsIAtu1CuxfYDAVt3kgr4t3a/Es3PV82M6z0eQAo='
        self.assertTrue(verify(msg, address, exp_sig))
        sig = sign(msg, wif)
        self.assertTrue(verify(msg, address, sig))
        self.assertEqual(serialize(*sig), exp_sig)

    def test_exceptions(self):

        msg = 'test'
        wif = 'KwELaABegYxcKApCb3kJR9ymecfZZskL9BzVUkQhsqFiUKftb4tu'
        address = p2pkh_address_from_wif(wif)
        exp_sig = b'IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLNtoVc='
        self.assertTrue(_verify(msg, address, exp_sig))

        # Invalid recovery flag: 26
        rf, r, s = deserialize(exp_sig)
        self.assertRaises(ValueError, serialize, 26, r, s)
        #serialize(26, r, s)

        # short exp_sig
        exp_sig = b'IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLoVc='
        self.assertRaises(ValueError, _verify, msg, address, exp_sig)
        self.assertFalse(verify(msg, address, exp_sig))

        # Invalid recovery flag: 26
        exp_sig = b'GpNLHqEKSzwXV+KwwBfQthQ848mn5qSkmGDXpqshDuPYJELOnSuRYGQQgBR4PpI+w2tJdD4v+hxElvAaUSqv2eU='
        self.assertRaises(ValueError, _verify, msg, address, exp_sig)
        self.assertFalse(verify(msg, address, exp_sig))
        #_verify(msg, address, exp_sig)

        # Invalid recovery flag: 66
        exp_sig = b'QpNLHqEKSzwXV+KwwBfQthQ848mn5qSkmGDXpqshDuPYJELOnSuRYGQQgBR4PpI+w2tJdD4v+hxElvAaUSqv2eU='
        self.assertRaises(ValueError, _verify, msg, address, exp_sig)
        self.assertFalse(verify(msg, address, exp_sig))
        #_verify(msg, address, exp_sig)

        # Pubkey mismatch: compressed wif, uncompressed address
        wif = 'Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ'
        address = '19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T'
        self.assertRaises(ValueError, sign, msg, wif, address)
        #sign(msg, wif, address)

        # Pubkey mismatch: uncompressed wif, compressed address
        wif = '5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn'
        address = '1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5'
        self.assertRaises(ValueError, sign, msg, wif, address)
        #sign(msg, wif, address)

        msg = 'test'
        wif = 'L4xAvhKR35zFcamyHME2ZHfhw5DEyeJvEMovQHQ7DttPTM8NLWCK'
        p2pkh_address = p2pkh_address_from_wif(wif)
        p2wpkh_address = p2wpkh_address_from_wif(wif)
        p2wpkh_p2sh_address = p2wpkh_p2sh_address_from_wif(wif)
        wif = 'Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ'
        # Mismatch between p2pkh address and key pair
        self.assertRaises(ValueError, sign, msg, wif, p2pkh_address)
        # sign(msg, wif, p2pkh_address)

        # Mismatch between p2wpkh address and key pair
        self.assertRaises(ValueError, sign, msg, wif, p2wpkh_address)
        # sign(msg, wif, p2wpkh_address)

        # Mismatch between p2wpkh_p2sh address and key pair
        self.assertRaises(ValueError, sign, msg, wif, p2wpkh_p2sh_address)
        # sign(msg, wif, p2wpkh_p2sh_address)

        # Invalid recovery flag (39) for base58 address
        exp_sig = b'IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLNtoVc='
        _, r, s = deserialize(exp_sig)
        sig = serialize(39, r, s)
        self.assertRaises(ValueError, _verify, msg, p2pkh_address, sig)
        #_verify(msg, p2pkh_address, sig)

        # Invalid recovery flag (35) for bech32 address
        exp_sig = b'IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU='
        _, r, s = deserialize(exp_sig)
        sig = serialize(35, r, s)
        self.assertRaises(ValueError, _verify, msg, p2wpkh_address, sig)
        #_verify(msg, p2wpkh_address, sig)

    def test_vector(self):
        """Test python-bitcoinlib test vectors
        
        https://github.com/petertodd/python-bitcoinlib/blob/master/bitcoin/tests/data/btcmsg.json        
        """

        # FIXME
        filename = "btcmsg.json"
        path_to_filename = path.join(path.dirname(__file__),
                                     "./data/", filename)
        with open(path_to_filename, 'r') as f:
            test_vectors = json.load(f)

        #for vector in test_vectors:
        for i in range(5):
            vector = test_vectors[i]
            msg = vector['address']
            signature = sign(msg, vector['wif'])
            self.assertTrue(_verify(msg, vector['address'], signature))
            self.assertTrue(_verify(msg, vector['address'], vector['signature']))
            #self.assertEqual(signature.decode(), vector['signature'])

    def test_ledger(self):
        """Hybrid ECDSA Bicoin message signature generated by Ledger Nano S"""

        # customized Ledger DER encoding, with no sighash
        # first byte = 0x30 + key_id
        DER = "3044022044487c80833b7025739f450751c1d6624118e32e5f922b5a40a407efb48382e202200f2b6e53448f8e219ee1c2f109fa5b0a2b8bae482a4a81cf8c54f8c168260886"

        pubkey = '022374b3b6b06b65a3b831f857634ea135bf10b014d5bba0f935cb9eb26a4b6547'
        msg = "hello world".encode()
        msg = b'\x18Bitcoin Signed Message:\n' + len(msg).to_bytes(1, 'big') + msg 

        # ECDSA signature verification
        dsa._verify(msg, pubkey, DER)
        r, s, sighash = der.deserialize(DER)
        self.assertIsNone(sighash)

        # equivalent Bitcoin Message Signature verification
        rec_flag = 27 + bytes_from_hexstring(DER)[0] - 48
        msgsig = serialize(rec_flag, r, s)
        addr = p2pkh_address(pubkey)
        _verify(msg, addr, msgsig)

if __name__ == '__main__':
    # execute only if run as a script
    unittest.main()
