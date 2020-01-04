#!/usr/bin/env python3

# Copyright (C) 2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.signmessage import msgsign, verify, _verify
from btclib.wifaddress import wif_from_prvkey, p2pkh_address_from_wif


class TestSignMessage(unittest.TestCase):
    def test_msgsign_p2pkh(self):
        msg = "test message"
        # sigs are taken from (Electrum and) Bitcoin Core

        # first private key
        wif = 'L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk'
        sig = b"H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="
        address = b'14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY'
        mysig = msgsign(msg, wif)
        self.assertTrue(_verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

        wif = '5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw'
        sig = b"G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="
        address = b'1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD'
        mysig = msgsign(msg, wif)
        self.assertTrue(_verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

        # second private key
        wif = 'Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ'
        sig = b"IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA="
        address = b'1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5'
        mysig = msgsign(msg, wif, address)
        self.assertTrue(_verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

        wif = '5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn'
        sig = b"HFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA="
        address = b'19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T'
        mysig = msgsign(msg, wif, address)
        self.assertTrue(_verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

    def test_sign_strippable_message(self):

        wif = 'Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ'
        address = b'19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T'

        msg = ''
        sig = b'HFh0InGTy8lLCs03yoUIpJU6MUbi0La/4abhVxyKcCsoUiF3RM7lg51rCqyoOZ8Yt43h8LZrmj7nwwO3HIfesiw='
        mysig = msgsign(msg, wif, address)
        self.assertTrue(verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

        msg = ' '
        sig = b'HEveV6CMmOk5lFP+oDbw8cir/OkhJn4S767wt+YwhzHnEYcFOb/uC6rrVmTtG3M43mzfObA0Nn1n9CRcv5IGyak='
        mysig = msgsign(msg, wif, address)
        self.assertTrue(verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

        msg = '  '
        sig = b'G/QjF1V4fVI8IHX8ko0SIypmb0yxfaZLF0o56Cif9z8CX24n4petTxolH59pYVMvbTKQkGKpznSiPiQVn83eJF0='
        mysig = msgsign(msg, wif, address)
        self.assertTrue(verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

        msg = 'test'
        sig = b'HJUtN/2LZjh1Vx8Ekj9opnIKA6ohKhWB95PLT/3EFgLnOu9hTuYX4+tJJ60ZyddFMd6dgAYx15oP+jLw2NzgNUo='
        mysig = msgsign(msg, wif, address)
        self.assertTrue(verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

        # sig is taken from Bitcoin Core
        # (Electrum does strip leading/trailing spaces)
        msg = ' test '
        sig = b'HA59z13/HBhvMMJtNwT6K7vJByE40lQUdqEMYhX2tnZSD+IGQIoBGE+1IYGCHCyqHvTvyGeqJTUx5ywb4StuX0s='
        mysig = msgsign(msg, wif, address)
        self.assertTrue(verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

        # sig is taken from Bitcoin Core
        # (Electrum does strip leading/trailing spaces)
        msg = 'test '
        sig = b'HPp9l2w0LVYB4FYKBahs+k1/Oa08j+NTuzriDpPWnWQmfU0+UsJNLIPI8Q/gekrWPv6sDeYsFSG9VybUKDPGMuo='
        mysig = msgsign(msg, wif, address)
        self.assertTrue(verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

        # sig is taken from Bitcoin Core
        # (Electrum does strip leading/trailing spaces)
        msg = ' test'
        sig = b'G1nGwD/kcMSmsYU6qihV2l2+Pa+7SPP9zyViZ59VER+QL9cJsIAtu1CuxfYDAVt3kgr4t3a/Es3PV82M6z0eQAo='
        mysig = msgsign(msg, wif, address)
        self.assertTrue(verify(msg, address, mysig))
        self.assertEqual(mysig, sig)

    def test_verify_p2pkh(self):
        msg = 'Hello, world!'
        address = '1FEz167JCVgBvhJBahpzmrsTNewhiwgWVG'
        sig = "G+WptuOvPCSswt/Ncm1upO4lPSCWbS2cpKariPmHvxX5eOJwgqmdEExMTKvaR0S3f1TXwggLn/m4CbI2jv0SCuM="
        self.assertTrue(_verify(msg, address, sig))

        # https://github.com/stequald/bitcoin-sign-message
        msg = 'test message'
        address = '14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY'
        sig = "IPn9bbEdNUp6+bneZqE2YJbq9Hv5aNILq9E5eZoMSF3/fBX4zjeIN6fpXfGSGPrZyKfHQ/c/kTSP+NIwmyTzMfk="
        self.assertTrue(_verify(msg, address, sig))

        # https://github.com/stequald/bitcoin-sign-message
        msg = 'test message'
        address = '1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD'
        sig = "G0k+Nt1u5boTTUfLyj6x1T5flg1v9rUKGlhs/jPApaTWLHf3GVdAIOIHip6sVwXEuzQGPWIlS0VT+yryXiDaavw="
        self.assertTrue(_verify(msg, address, sig))

        # https://github.com/petertodd/python-bitcoinlib/blob/05cbb3c9560b36cfe71bac06085a231a6244e13a/bitcoin/tests/test_signmessage.py
        address = "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
        msg = address
        sig = "H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4="
        self.assertTrue(_verify(msg, address, sig))

        # https://github.com/nanotube/supybot-bitcoin-marketmonitor/blob/master/GPG/local/bitcoinsig.py
        address = '16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce'
        sig = 'HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50='
        msg = 'test message'
        self.assertTrue(_verify(msg, address, sig))

        address = '16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce'
        sig = 'HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50='
        msg = 'test message 2'
        self.assertFalse(_verify(msg, address, sig))

        address = '1GdKjTSg2eMyeVvPV5Nivo6kR8yP2GT7wF'
        sig = 'GyMn9AdYeZIPWLVCiAblOOG18Qqy4fFaqjg5rjH6QT5tNiUXLS6T2o7iuWkV1gc4DbEWvyi8yJ8FvSkmEs3voWE='
        msg = 'freenode:#bitcoin-otc:b42f7e7ea336db4109df6badc05c6b3ea8bfaa13575b51631c5178a7'
        self.assertTrue(_verify(msg, address, sig))

        address = '1Hpj6xv9AzaaXjPPisQrdAD2tu84cnPv3f'
        sig = 'INEJxQnSu6mwGnLs0E8eirl5g+0cAC9D5M7hALHD9sK0XQ66CH9mas06gNoIX7K1NKTLaj3MzVe8z3pt6apGJ34='
        msg = 'testtest'
        self.assertTrue(_verify(msg, address, sig))

        address = '18uitB5ARAhyxmkN2Sa9TbEuoGN1he83BX'
        sig = 'IMAtT1SjRyP6bz6vm5tKDTTTNYS6D8w2RQQyKD3VGPq2i2txGd2ar18L8/nvF1+kAMo5tNc4x0xAOGP0HRjKLjc='
        msg = 'testtest'
        self.assertTrue(_verify(msg, address, sig))

        address = '1LsPb3D1o1Z7CzEt1kv5QVxErfqzXxaZXv'
        sig = 'H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As='
        msg = 'testtest'
        self.assertTrue(_verify(msg, address, sig))

        # leading space
        sig = ' H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As='
        self.assertTrue(_verify(msg, address, sig))

        # trailing space
        sig = 'H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As= '
        self.assertTrue(_verify(msg, address, sig))

        # leading and trailing spaces
        sig = ' H3I37ur48/fn52ZvWQT+Mj2wXL36gyjfaN5qcgfiVRTJb1eP1li/IacCQspYnUntiRv8r6GDfJYsdiQ5VzlG3As= '
        self.assertTrue(_verify(msg, address, sig))

    def test_verify_p2wpkh(self):
        # p2wpkh bech32 address
        msg = 'test'
        wif = 'L4xAvhKR35zFcamyHME2ZHfhw5DEyeJvEMovQHQ7DttPTM8NLWCK'
        address = 'bc1qz0knqc5dhlgvalc3z77898thhvqek6v6j0j5zj'
        sig = ''
        mysig = msgsign(msg, wif, address)
        # auto-consistency check first
        self.assertTrue(_verify(msg, address, mysig))
        #self.assertEqual(mysig, sig)

    def test_verify_p2wsh(self):
        # p2wpkh-p2sh address
        msg = 'test'
        wif = 'KwELaABegYxcKApCb3kJR9ymecfZZskL9BzVUkQhsqFiUKftb4tu'
        address = '34FTAdfxN1oDQnLWMokUhHZ263ocodbyen'
        sig = ''
        mysig = msgsign(msg, wif, address)
        # auto-consistency check first
        self.assertTrue(_verify(msg, address, mysig))
        #self.assertEqual(mysig, sig)

    def test_exceptions(self):

        msg = 'test'
        wif = 'KwELaABegYxcKApCb3kJR9ymecfZZskL9BzVUkQhsqFiUKftb4tu'
        address = p2pkh_address_from_wif(wif)
        sig = 'IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLNtoVc='
        self.assertTrue(_verify(msg, address, sig))

        # short sig
        sig = 'IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLoVc='
        self.assertRaises(ValueError, _verify, msg, address, sig)
        self.assertFalse(verify(msg, address, sig))

        # invalid rf
        sig = 'GpNLHqEKSzwXV+KwwBfQthQ848mn5qSkmGDXpqshDuPYJELOnSuRYGQQgBR4PpI+w2tJdD4v+hxElvAaUSqv2eU='
        self.assertRaises(ValueError, _verify, msg, address, sig)
        self.assertFalse(verify(msg, address, sig))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
