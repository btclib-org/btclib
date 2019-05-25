#!/usr/bin/env python3

# Copyright (C) 2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.signmessage import sign, verify
from btclib.wifaddress import prvkey_from_wif


class TestSignMessage(unittest.TestCase):
    def test_signmessage(self):
        msg = "test message"

        wif = b'L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk'
        prvkey, compressed = prvkey_from_wif(wif)
        self.assertEqual(prvkey, 0xCA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB)
        self.assertTrue(compressed)
        mysig = sign(prvkey, msg, compressed)
        # auto-consistency check
        self.assertTrue(verify(mysig[0], mysig[1], msg))
        address = b'14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY'
        self.assertEqual(mysig[0], address)
        sig = "IPn9bbEdNUp6+bneZqE2YJbq9Hv5aNILq9E5eZoMSF3/fBX4zjeIN6fpXfGSGPrZyKfHQ/c/kTSP+NIwmyTzMfk="
        #self.assertEqual(mysig[1], sig)

        wif = b'5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw'
        prvkey, compressed = prvkey_from_wif(wif)
        self.assertEqual(prvkey, 0xCA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB)
        self.assertFalse(compressed)
        mysig = sign(prvkey, msg, compressed)
        # auto-consistency check
        self.assertTrue(verify(mysig[0], mysig[1], msg))
        address = b'1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD'
        self.assertEqual(mysig[0], address)
        sig = "G0k+Nt1u5boTTUfLyj6x1T5flg1v9rUKGlhs/jPApaTWLHf3GVdAIOIHip6sVwXEuzQGPWIlS0VT+yryXiDaavw="
        #self.assertEqual(mysig[1], sig)

        wif = b'Ky1XfDK2v6wHPazA6ECaD8UctEoShXdchgABjpU9GWGZDxVRDBMJ'
        prvkey, compressed = prvkey_from_wif(wif)
        self.assertEqual(prvkey, 0x35687eed35e44235053dce4c65dc23b11327ecee9acc51c90651e7072047f886)
        self.assertTrue(compressed)
        mysig = sign(prvkey, msg, compressed)
        # auto-consistency check
        self.assertTrue(verify(mysig[0], mysig[1], msg))
        address = b'1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5'
        self.assertEqual(mysig[0], address)
        sig = ""
        #self.assertEqual(mysig[1], sig)

        wif = b'5JDopdKaxz5bXVYXcAnfno6oeSL8dpipxtU1AhfKe3Z58X48srn'
        prvkey, compressed = prvkey_from_wif(wif)
        self.assertEqual(prvkey, 0x35687eed35e44235053dce4c65dc23b11327ecee9acc51c90651e7072047f886)
        self.assertFalse(compressed)
        mysig = sign(prvkey, msg, compressed)
        # auto-consistency check
        self.assertTrue(verify(mysig[0], mysig[1], msg))
        address = b'19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T'
        self.assertEqual(mysig[0], address)
        sig = ""
        #self.assertEqual(mysig[1], sig)

    def test_verifymsgsig(self):
        msg = "Hello, world!"
        address = b'1FEz167JCVgBvhJBahpzmrsTNewhiwgWVG'
        sig = "G+WptuOvPCSswt/Ncm1upO4lPSCWbS2cpKariPmHvxX5eOJwgqmdEExMTKvaR0S3f1TXwggLn/m4CbI2jv0SCuM="
        self.assertTrue(verify(address, sig, msg))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
