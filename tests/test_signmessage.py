#!/usr/bin/env python3

# Copyright (C) 2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.signmessage import sign, verify, _verify
from btclib.wifaddress import prvkey_from_wif, address_from_wif


class TestSignMessage(unittest.TestCase):
    def test_signmessage(self):
        msg = "test message"
        # sigs are taken from (Electrum and) Bitcoin Core

        wif = 'L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk'
        prvkey, compressed = prvkey_from_wif(wif)
        self.assertEqual(prvkey, 0xCA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB)
        self.assertTrue(compressed)
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        address = b'14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY'
        self.assertEqual(mysig[0], address)
        sig = b"H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="
        self.assertEqual(mysig[1], sig)

        wif = '5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw'
        prvkey, compressed = prvkey_from_wif(wif)
        self.assertEqual(prvkey, 0xCA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB)
        self.assertFalse(compressed)
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        address = b'1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD'
        self.assertEqual(mysig[0], address)
        sig = b"G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="
        self.assertEqual(mysig[1], sig)

        wif = 'Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ'
        prvkey, compressed = prvkey_from_wif(wif)
        self.assertEqual(prvkey, 0x35687eed35e44235053dce4c65dc23b11327ecee9acc51c90651e7072047f886)
        self.assertTrue(compressed)
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        address = b'1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5'
        self.assertEqual(mysig[0], address)
        sig = b"IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA="
        self.assertEqual(mysig[1], sig)

        wif = '5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn'
        prvkey, compressed = prvkey_from_wif(wif)
        self.assertEqual(prvkey, 0x35687eed35e44235053dce4c65dc23b11327ecee9acc51c90651e7072047f886)
        self.assertFalse(compressed)
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        address = b'19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T'
        self.assertEqual(mysig[0], address)
        sig = b"HFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA="
        self.assertEqual(mysig[1], sig)

        msg = ''
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        self.assertEqual(mysig[0], address)
        sig = b'HFh0InGTy8lLCs03yoUIpJU6MUbi0La/4abhVxyKcCsoUiF3RM7lg51rCqyoOZ8Yt43h8LZrmj7nwwO3HIfesiw='
        self.assertEqual(mysig[1], sig)

        msg = ' '
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        self.assertEqual(mysig[0], address)
        sig = b'HEveV6CMmOk5lFP+oDbw8cir/OkhJn4S767wt+YwhzHnEYcFOb/uC6rrVmTtG3M43mzfObA0Nn1n9CRcv5IGyak='
        self.assertEqual(mysig[1], sig)

        msg = '  '
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        self.assertEqual(mysig[0], address)
        sig = b'G/QjF1V4fVI8IHX8ko0SIypmb0yxfaZLF0o56Cif9z8CX24n4petTxolH59pYVMvbTKQkGKpznSiPiQVn83eJF0='
        self.assertEqual(mysig[1], sig)

        msg = 'test'
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        self.assertEqual(mysig[0], address)
        sig = b'HJUtN/2LZjh1Vx8Ekj9opnIKA6ohKhWB95PLT/3EFgLnOu9hTuYX4+tJJ60ZyddFMd6dgAYx15oP+jLw2NzgNUo='
        self.assertEqual(mysig[1], sig)

        # sig is taken from Bitcoin Core
        # (Electrum does strip leading/trailing spaces)
        msg = ' test '
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        self.assertEqual(mysig[0], address)
        sig = b'HA59z13/HBhvMMJtNwT6K7vJByE40lQUdqEMYhX2tnZSD+IGQIoBGE+1IYGCHCyqHvTvyGeqJTUx5ywb4StuX0s='
        self.assertEqual(mysig[1], sig)

        # sig is taken from Bitcoin Core
        # (Electrum does strip leading/trailing spaces)
        msg = 'test '
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        self.assertEqual(mysig[0], address)
        sig = b'HPp9l2w0LVYB4FYKBahs+k1/Oa08j+NTuzriDpPWnWQmfU0+UsJNLIPI8Q/gekrWPv6sDeYsFSG9VybUKDPGMuo='
        self.assertEqual(mysig[1], sig)

        # sig is taken from Bitcoin Core
        # (Electrum does strip leading/trailing spaces)
        msg = ' test'
        mysig = sign(msg, prvkey, compressed)
        # auto-consistency check
        self.assertTrue(verify(msg, mysig[0], mysig[1]))
        self.assertEqual(mysig[0], address)
        sig = b'G1nGwD/kcMSmsYU6qihV2l2+Pa+7SPP9zyViZ59VER+QL9cJsIAtu1CuxfYDAVt3kgr4t3a/Es3PV82M6z0eQAo='
        self.assertEqual(mysig[1], sig)


    def test_verifymsgsig(self):
        msg = 'Hello, world!'
        address = '1FEz167JCVgBvhJBahpzmrsTNewhiwgWVG'
        sig = "G+WptuOvPCSswt/Ncm1upO4lPSCWbS2cpKariPmHvxX5eOJwgqmdEExMTKvaR0S3f1TXwggLn/m4CbI2jv0SCuM="
        _verify(msg, address, sig)
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

        # p2wpkh bech32 address
        wif = 'L4xAvhKR35zFcamyHME2ZHfhw5DEyeJvEMovQHQ7DttPTM8NLWCK'
        address = 'bc1qz0knqc5dhlgvalc3z77898thhvqek6v6j0j5zj'
        sig = 'IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU='
        msg = 'test'
        self.assertRaises(ValueError, _verify, msg, address, sig)

        # same prvkey as above, but regular p2pkh address
        address = address_from_wif(wif)
        self.assertTrue(_verify(msg, address, sig))

        # p2wpkh-p2sh address
        wif = 'KwELaABegYxcKApCb3kJR9ymecfZZskL9BzVUkQhsqFiUKftb4tu'
        address = '34FTAdfxN1oDQnLWMokUhHZ263ocodbyen'
        sig = 'IHdKsFF1bUrapA8GMoQUbgI+Ad0ZXyX1c/yAZHmJn5hSNBi7J+TrI1615FG3g9JEOPGVvcfDWIFWrg2exLNtoVc='
        msg = 'test'
        self.assertRaises(ValueError, _verify, msg, address, sig)

        # same prvkey as above, but regular p2pkh address
        address = address_from_wif(wif)
        self.assertTrue(_verify(msg, address, sig))

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
