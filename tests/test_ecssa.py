#!/usr/bin/env python3

import os
import unittest
from hashlib import sha256

from btclib.ellipticcurves import jac_from_affine, secp256k1, \
                                  bytes_from_Point, tuple_from_Point
from btclib.ecssa import rfc6979, int_from_hash, \
                         _ecssa_sign_raw, \
                         _ecssa_verify_raw, \
                         ecssa_pubkey_recovery, \
                         ecssa_batch_validation

from tests.test_ellipticcurves import lowcard

# Test vectors from
# https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki

class TestEcssa(unittest.TestCase):
    def test_ecssa_bip_tv1(self):
        prv = 0x1
        pub = secp256k1.pointMultiply(prv, secp256k1.G)
        msg = b'\x00' * 32
        expected_sig = (0x787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6,
                        0x7031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05)
        eph_prv = int.from_bytes(sha256(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")

        sig = _ecssa_sign_raw(msg, prv, eph_prv)
        self.assertTrue(_ecssa_verify_raw(msg, sig, pub))
        self.assertEqual(sig, expected_sig)
        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(secp256k1, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig, secp256k1), pub)

    def test_ecssa_bip_tv2(self):
        prv = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
        pub = secp256k1.pointMultiply(prv, secp256k1.G)
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        expected_sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
                        0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        eph_prv = int.from_bytes(sha256(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")

        sig = _ecssa_sign_raw(msg, prv, eph_prv)
        self.assertTrue(_ecssa_verify_raw(msg, sig, pub))
        self.assertEqual(sig, expected_sig)
        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(secp256k1, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig, secp256k1), pub)

    def test_ecssa_bip_tv3(self):
        prv = 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7
        pub = secp256k1.pointMultiply(prv, secp256k1.G)
        msg = bytes.fromhex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
        expected_sig = (0x00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE,
                        0x00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380)
        eph_prv = int.from_bytes(sha256(prv.to_bytes(32, byteorder="big") + msg).digest(), byteorder="big")

        sig = _ecssa_sign_raw(msg, prv, eph_prv)
        self.assertTrue(_ecssa_verify_raw(msg, sig, pub))
        self.assertEqual(sig, expected_sig)
        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(secp256k1, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig, secp256k1), pub)

    def test_ecssa_bip_tv4(self):
        pub = tuple_from_Point(secp256k1, "03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
        msg = bytes.fromhex("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
        sig = (0x00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63,
               0x02A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D)

        self.assertTrue(_ecssa_verify_raw(msg, sig, pub))
        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(secp256k1, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig, secp256k1), pub)

    def test_ecssa_bip_tv5(self):
        """test fails if jacobi symbol of x(R) instead of y(R) is used"""
        pub = tuple_from_Point(secp256k1, "031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F")
        msg = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        sig = (0x52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E35,
               0x30B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187)

        self.assertTrue(_ecssa_verify_raw(msg, sig, pub))
        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(secp256k1, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig, secp256k1), pub)

    def test_ecssa_bip_tv6(self):
        """test fails if msg is reduced"""
        pub = tuple_from_Point(secp256k1, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
        sig = (0x570DD4CA83D4E6317B8EE6BAE83467A1BF419D0767122DE409394414B05080DC,
               0xE9EE5F237CBD108EABAE1E37759AE47F8E4203DA3532EB28DB860F33D62D49BD)

        self.assertTrue(_ecssa_verify_raw(msg, sig, pub))
        e = sha256(sig[0].to_bytes(32, byteorder="big") +
                   bytes_from_Point(secp256k1, pub, True) +
                   msg).digest()
        self.assertEqual(ecssa_pubkey_recovery(e, sig, secp256k1), pub)

    def test_ecssa_bip_tv7(self):
        """public key not on the curve"""
        # cannot be really tested in this library:
        # by the moment one has the message digest,
        # he is expected to already have the public key as tuple
        self.assertRaises(ValueError, tuple_from_Point, secp256k1, "03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
        # pub = tuple_from_Point(secp256k1, "03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
        # msg = bytes.fromhex("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
        # sig = (0x00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63,
        #       0x02A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D)

    def test_ecssa_bip_tv8(self):
        """Incorrect sig: incorrect R residuosity"""
        pub = tuple_from_Point(secp256k1, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0xFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7)
        self.assertFalse(_ecssa_verify_raw(msg, sig, pub))

    def test_ecssa_bip_tv9(self):
        """Incorrect sig: negated message hash"""
        pub = tuple_from_Point(secp256k1, "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
        msg = bytes.fromhex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
        sig = (0x00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE,
               0xD092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC)
        self.assertFalse(_ecssa_verify_raw(msg, sig, pub))

    def test_ecssa_bip_tv10(self):
        """Incorrect sig: negated s value"""
        pub = tuple_from_Point(secp256k1, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
        msg = b'\x00' * 32
        sig = (0x787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6,
               0x8FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C)
        self.assertFalse(_ecssa_verify_raw(msg, sig, pub))

    def test_ecssa_bip_tv11(self):
        """Incorrect sig: negated public key"""
        pub = tuple_from_Point(secp256k1, "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        self.assertFalse(_ecssa_verify_raw(msg, sig, pub))

    def test_ecssa_bip_tv12(self):
        """sG - eP is infinite. Test fails in single verification if jacobi(y(inf)) is defined as 1 and x(inf) as 0"""
        pub = tuple_from_Point(secp256k1, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x0000000000000000000000000000000000000000000000000000000000000000,
               0x9E9D01AF988B5CEDCE47221BFA9B222721F3FA408915444A4B489021DB55775F)
        self.assertFalse(_ecssa_verify_raw(msg, sig, pub))

    def test_ecssa_bip_tv13(self):
        """sG - eP is infinite. Test fails in single verification if jacobi(y(inf)) is defined as 1 and x(inf) as 1"""
        pub = tuple_from_Point(secp256k1, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x0000000000000000000000000000000000000000000000000000000000000001,
               0xD37DDF0254351836D84B1BD6A795FD5D523048F298C4214D187FE4892947F728)
        self.assertFalse(_ecssa_verify_raw(msg, sig, pub))

    def test_ecssa_bip_tv14(self):
        """sig[0:32] is not an X coordinate on the curve"""
        pub = tuple_from_Point(secp256k1, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        self.assertFalse(_ecssa_verify_raw(msg, sig, pub))

    def test_ecssa_bip_tv15(self):
        """sig[0:32] is equal to field size"""
        pub = tuple_from_Point(secp256k1, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F,
               0x1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD)
        self.assertFalse(_ecssa_verify_raw(msg, sig, pub))

    def test_ecssa_bip_tv16(self):
        """sig[32:64] is equal to curve order"""
        pub = tuple_from_Point(secp256k1, "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig = (0x2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D,
               0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
        self.assertFalse(_ecssa_verify_raw(msg, sig, pub))

    def test_low_cardinality(self):
        """test all msg/key pairs of low cardinality elliptic curves"""

        # ec.n has to be prime to sign
        prime = [
              3,   5,   7,  11,  13,  17,  19,  23,  29,  31,
             37,  41,  43,  47,  53,  59,  61,  67,  71,  73#,
            # 79,  83,  89,  97, 101, 103, 107, 109, 113, 127,
            #131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            #181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
            #239, 241, 251, 257, 263, 269, 271, 277, 281, 283
            ]

        # all possible hashed messages
        hlen = 32
        H = [i.to_bytes(hlen, 'big') for i in range(0, max(prime))]

        for ec in lowcard: # only low card curves or it would take forever
            if ec.n in prime: # only few curves or it would take too long
                # Schnorr-bip only applies to curve whose prime p = 3 %4
                if not ec.pIsThreeModFour:
                    self.assertRaises(ValueError, _ecssa_sign_raw, H[0], 1, None, ec)
                    continue
                # all possible private keys (invalid 0 included)
                for q in range(0, ec.n):
                    if q == 0:
                        self.assertRaises(ValueError, _ecssa_sign_raw, H[0], q, None, ec)
                        continue
                    G = jac_from_affine(ec.G) # Generator in jacobian coordinates
                    Q = ec.pointMultiplyJacobian(q, G) # public key
                    for m in range(0, ec.n): # all possible hashed messages

                        k = rfc6979(q, H[m], sha256) % ec.n # ephemeral key
                        K = ec.pointMultiplyJacobian(k, G)
                        if K == None:
                            self.assertRaises(ValueError, _ecssa_sign_raw, H[m], q, k, ec)
                            continue
                        if ec.jacobi(K[1]) != 1:
                            k = ec.n - k

                        ebytes  = K[0].to_bytes(ec.bytesize, byteorder="big")
                        ebytes += bytes_from_Point(ec, Q, True)
                        ebytes += H[m]
                        ebytes = sha256(ebytes).digest()
                        e = int_from_hash(ebytes, ec.n, sha256().digest_size)
                        s = (k + e * q) % ec.n

                        # valid signature
                        sig = _ecssa_sign_raw(H[m], q, k, ec)
                        self.assertEqual((K[0], s), sig)
                        # valid signature must validate
                        self.assertTrue(_ecssa_verify_raw(H[m], sig, Q, ec))

    def test_batch_validation(self):
        Q = []
        m = []
        sig = []
        a = []
        G = jac_from_affine(secp256k1.G)
        for i in range(0, 50):
            q = int.from_bytes(os.urandom(secp256k1.bytesize), 'big')
            m.append(os.urandom(secp256k1.bytesize))
            sig.append(_ecssa_sign_raw(m[i], q))
            Q.append(secp256k1.pointMultiplyJacobian(q, G))
            a.append(int.from_bytes(os.urandom(secp256k1.bytesize), 'big'))
        self.assertTrue(ecssa_batch_validation(m, sig, Q, a, secp256k1))

        m.append(m[0])
        sig.append(sig[1]) # invalid
        Q.append(Q[0])
        a.append(a[0])
        self.assertFalse(ecssa_batch_validation(m, sig, Q, a, secp256k1))

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
