#!/usr/bin/env python3

import unittest
from btclib.rfc6979 import sha256, rfc6979

class Testrfc6979(unittest.TestCase):
    def test_rfc6979_1(self):
        # source: https://bitcointalk.org/index.php?topic=285142.40
        msg = sha256(b'Satoshi Nakamoto').digest()
        x = 0x1
        nonce = rfc6979(x, msg)
        expected = 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15
        self.assertEqual(nonce, expected)
    
    def test_rfc6979_2(self):
        msg = sha256(b'All those moments will be lost in time, like tears in rain. Time to die...').digest()
        x = 0x1
        nonce = rfc6979(x, msg)
        expected = 0x38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3
        self.assertEqual(nonce, expected)

    def test_rfc6979_3(self):
        msg = sha256(b'Satoshi Nakamoto').digest()
        x = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
        nonce = rfc6979(x, msg)
        expected = 0x33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90
        self.assertEqual(nonce, expected)
    
    def test_rfc6979_4(self):
        msg = sha256(b'Alan Turing').digest()
        x = 0xf8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181
        nonce = rfc6979(x, msg)
        expected = 0x525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1
        self.assertEqual(nonce, expected)
    
    def test_rfc6979_5(self):
        msg = sha256(b'There is a computer disease that anybody who works with computers knows about. It\'s a very serious disease and it interferes completely with the work. The trouble with computers is that you \'play\' with them!').digest()
        x = 0xe91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2
        nonce = rfc6979(x, msg)
        expected = 0x1F4B84C23A86A221D233F2521BE018D9318639D5B8BBD6374A8A59232D16AD3D
        self.assertEqual(nonce, expected)

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
