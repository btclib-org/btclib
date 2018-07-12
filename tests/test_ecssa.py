#!/usr/bin/env python3

import unittest
from hashlib import sha256
from btclib.ellipticcurves import bytes_from_Point, tuple_from_Point
from btclib.ecssa import ec, ecssa_sign, ecssa_verify, ecssa_pubkey_recovery


class TestEcssa(unittest.TestCase):
    def test_ecssa_1(self):
        prv = 0x1
        pub = ec.pointMultiply(prv, ec.G)
        msg = b'\x00' * 32
        expected_sig = (0x787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6,
                        0x7031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05)
        eph_prv = int.from_bytes(sha256(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")

        sig = ecssa_sign(msg, prv, eph_prv)
        self.assertTrue(ecssa_verify(msg, sig, pub))
        # malleability
        self.assertFalse(ecssa_verify(msg, (sig[0], ec.order - sig[1]), pub))
        self.assertEqual(sig, expected_sig)
        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(ec, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig), pub)

    def test_ecssa_2(self):
        prv = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
        pub = ec.pointMultiply(prv, ec.G)
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        expected_sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
                        0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        eph_prv = int.from_bytes(sha256(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")

        sig = ecssa_sign(msg, prv, eph_prv)
        self.assertTrue(ecssa_verify(msg, sig, pub))
        # malleability
        self.assertFalse(ecssa_verify(msg, (sig[0], ec.order - sig[1]), pub))
        self.assertEqual(sig, expected_sig)
        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(ec, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig), pub)

    def test_ecssa_3(self):
        prv = 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7
        pub = ec.pointMultiply(prv, ec.G)
        msg = bytes.fromhex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
        expected_sig = (0x00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE,
                        0x00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380)
        eph_prv = int.from_bytes(sha256(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")

        sig = ecssa_sign(msg, prv, eph_prv)
        self.assertTrue(ecssa_verify(msg, sig, pub))
        # malleability
        self.assertFalse(ecssa_verify(msg, (sig[0], ec.order - sig[1]), pub))
        self.assertEqual(sig, expected_sig)
        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(ec, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig), pub)

    def test_ecssa_4(self):
        pub = tuple_from_Point(ec, "03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
        msg = bytes.fromhex("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
        sig = (0x00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63,
               0x02A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D)

        self.assertTrue(ecssa_verify(msg, sig, pub))
        # malleability
        self.assertFalse(ecssa_verify(msg, (sig[0], ec.order - sig[1]), pub))
        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(ec, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig), pub)

    def test_ecssa_5(self):
        """Incorrect sig: incorrect R residuosity"""
        pub = tuple_from_Point(ec, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0xFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7)

        self.assertFalse(ecssa_verify(msg, sig, pub))

    def test_ecssa_6(self):
        """Incorrect sig: negated message hash"""
        pub = tuple_from_Point(ec, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
        sig = (0x00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE,
               0xD092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC)

        self.assertFalse(ecssa_verify(msg, sig, pub))

    def test_ecssa_7(self):
        """Incorrect sig: negated s value"""
        pub = tuple_from_Point(ec, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
        msg = b'\x00' * 32
        sig = (0x787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6,
               0x8FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C)

        self.assertFalse(ecssa_verify(msg, sig, pub))

    def test_ecssa_8(self):
        """Incorrect sig: negated public key"""
        pub = tuple_from_Point(ec, "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)

        self.assertFalse(ecssa_verify(msg, sig, pub))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
