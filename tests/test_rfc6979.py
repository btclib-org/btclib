#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from hashlib import sha1, sha224, sha256, sha384, sha512

from btclib.curves import secp256k1, \
                           nistp192, nistp224, nistp256, nistp384, nistp521
from btclib.rfc6979 import rfc6979

from btclib.ec import mult
from btclib import dsa
from btclib.utils import int_from_bits, octets_from_int, _int_from_bits

class Testrfc6979(unittest.TestCase):
    def test_rfc6979(self):
        # source: https://bitcointalk.org/index.php?topic=285142.40
        ec = secp256k1
        hf = sha256
        msg = hf(b'Satoshi Nakamoto').digest()
        x = 0x1
        k = rfc6979(ec, hf, msg, x)
        expected = 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15
        self.assertEqual(k, expected)

        # mismatch between hf digest size and hashed message size
        self.assertRaises(ValueError, rfc6979, ec, hf, msg[:-1], x)
        #rfc6979(ec, hf, msg[:-1], x)

    def test_rfc6979_example(self):

        class _helper:
            def __init__(self, n: int) -> None:
                self.n = n
                self.nlen = n.bit_length()
                self.nsize = (self.nlen + 7) // 8

        # source: https://tools.ietf.org/html/rfc6979 section A.1

        ec = _helper(0x4000000000000000000020108A2E0CC0D99F8A5EF)
        x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
        hf = sha256; msg = b'sample'; m = hf(msg).digest()
        k = 0x23AF4074C90A02B3FE61D286D5C87F425E6BDD81B
        self.assertEqual(k, rfc6979(ec, hf, m, x))

    def test_rfc6979_tv(self):

        # source: https://tools.ietf.org/html/rfc6979 section A.2.3
        ec = nistp192
        x  = 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4
        Ux = 0xAC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56
        Uy = 0x3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43
        U = mult(ec, x, ec.G)
        self.assertEqual((Ux, Uy), U)

        ec = nistp192; hf = sha1; msg = b"sample"; m = hf(msg).digest()
        k = 0x37D7CA00D2C7B0E5E412AC03BD44BA837FDD5B28CD3B0021
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x98C6BD12B23EAF5E2A2045132086BE3EB8EBD62ABF6698FF
        s = 0x57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp192; hf = sha224; msg = b"sample"; m = hf(msg).digest()
        k = 0x4381526B3FC1E7128F202E194505592F01D5FF4C5AF015D8
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xA1F00DAD97AEEC91C95585F36200C65F3C01812AA60378F5
        s = 0xE07EC1304C7C6C9DEBBE980B9692668F81D4DE7922A0F97A
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp192; hf = sha256; msg = b"sample"; m = hf(msg).digest()
        k = 0x32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55
        s = 0xCCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp192; hf = sha384; msg = b"sample"; m = hf(msg).digest()
        k = 0x4730005C4FCB01834C063A7B6760096DBE284B8252EF4311
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xDA63BF0B9ABCF948FBB1E9167F136145F7A20426DCC287D5
        s = 0xC3AA2C960972BD7A2003A57E1C4C77F0578F8AE95E31EC5E
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp192; hf = sha512; msg = b"sample"; m = hf(msg).digest()
        k = 0xA2AC7AB055E4F20692D49209544C203A7D1F2C0BFBC75DB1
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x4D60C5AB1996BD848343B31C00850205E2EA6922DAC2E4B8
        s = 0x3F6E837448F027A1BF4B34E796E32A811CBB4050908D8F67
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp192; hf = sha1; msg = b"test"; m = hf(msg).digest()
        k = 0xD9CF9C3D3297D3260773A1DA7418DB5537AB8DD93DE7FA25
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x0F2141A0EBBC44D2E1AF90A50EBCFCE5E197B3B7D4DE036D
        s = 0xEB18BC9E1F3D7387500CB99CF5F7C157070A8961E38700B7
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp192; hf = sha224; msg = b"test"; m = hf(msg).digest()
        k = 0xF5DC805F76EF851800700CCE82E7B98D8911B7D510059FBE
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x6945A1C1D1B2206B8145548F633BB61CEF04891BAF26ED34
        s = 0xB7FB7FDFC339C0B9BD61A9F5A8EAF9BE58FC5CBA2CB15293
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp192; hf = sha256; msg = b"test"; m = hf(msg).digest()
        k = 0x5C4CE89CF56D9E7C77C8585339B006B97B5F0680B4306C6C
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x3A718BD8B4926C3B52EE6BBE67EF79B18CB6EB62B1AD97AE
        s = 0x5662E6848A4A19B1F1AE2F72ACD4B8BBE50F1EAC65D9124F
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp192; hf = sha384; msg = b"test"; m = hf(msg).digest()
        k = 0x5AFEFB5D3393261B828DB6C91FBC68C230727B030C975693
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xB234B60B4DB75A733E19280A7A6034BD6B1EE88AF5332367
        s = 0x7994090B2D59BB782BE57E74A44C9A1C700413F8ABEFE77A
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp192; hf = sha512; msg = b"test"; m = hf(msg).digest()
        k = 0x0758753A5254759C7CFBAD2E2D9B0792EEE44136C9480527
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xFE4F4AE86A58B6507946715934FE2D8FF9D95B6B098FE739
        s = 0x74CF5605C98FBA0E1EF34D4B5A1577A7DCF59457CAE52290
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        # source: https://tools.ietf.org/html/rfc6979 section A.2.4
        ec = nistp224
        x  = 0xF220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1
        Ux = 0x00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C
        Uy = 0xEEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A
        U = mult(ec, x, ec.G)
        self.assertEqual((Ux, Uy), U)

        ec = nistp224; hf = sha1; msg = b"sample"; m = hf(msg).digest()
        k = 0x7EEFADD91110D8DE6C2C470831387C50D3357F7F4D477054B8B426BC
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x22226F9D40A96E19C4A301CE5B74B115303C0F3A4FD30FC257FB57AC
        s = 0x66D1CDD83E3AF75605DD6E2FEFF196D30AA7ED7A2EDF7AF475403D69
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp224; hf = sha224; msg = b"sample"; m = hf(msg).digest()
        k = 0xC1D1F2F10881088301880506805FEB4825FE09ACB6816C36991AA06D
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x1CDFE6662DDE1E4A1EC4CDEDF6A1F5A2FB7FBD9145C12113E6ABFD3E
        s = 0xA6694FD7718A21053F225D3F46197CA699D45006C06F871808F43EBC
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp224; hf = sha256; msg = b"sample"; m = hf(msg).digest()
        k = 0xAD3029E0278F80643DE33917CE6908C70A8FF50A411F06E41DEDFCDC
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x61AA3DA010E8E8406C656BC477A7A7189895E7E840CDFE8FF42307BA
        s = 0xBC814050DAB5D23770879494F9E0A680DC1AF7161991BDE692B10101
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp224; hf = sha384; msg = b"sample"; m = hf(msg).digest()
        k = 0x52B40F5A9D3D13040F494E83D3906C6079F29981035C7BD51E5CAC40
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x0B115E5E36F0F9EC81F1325A5952878D745E19D7BB3EABFABA77E953
        s = 0x830F34CCDFE826CCFDC81EB4129772E20E122348A2BBD889A1B1AF1D
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp224; hf = sha512; msg = b"sample"; m = hf(msg).digest()
        k = 0x9DB103FFEDEDF9CFDBA05184F925400C1653B8501BAB89CEA0FBEC14
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x074BD1D979D5F32BF958DDC61E4FB4872ADCAFEB2256497CDAC30397
        s = 0xA4CECA196C3D5A1FF31027B33185DC8EE43F288B21AB342E5D8EB084
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp224; hf = sha1; msg = b"test"; m = hf(msg).digest()
        k = 0x2519178F82C3F0E4F87ED5883A4E114E5B7A6E374043D8EFD329C253
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xDEAA646EC2AF2EA8AD53ED66B2E2DDAA49A12EFD8356561451F3E21C
        s = 0x95987796F6CF2062AB8135271DE56AE55366C045F6D9593F53787BD2
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp224; hf = sha224; msg = b"test"; m = hf(msg).digest()
        k = 0xDF8B38D40DCA3E077D0AC520BF56B6D565134D9B5F2EAE0D34900524
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xC441CE8E261DED634E4CF84910E4C5D1D22C5CF3B732BB204DBEF019
        s = 0x902F42847A63BDC5F6046ADA114953120F99442D76510150F372A3F4
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp224; hf = sha256; msg = b"test"; m = hf(msg).digest()
        k = 0xFF86F57924DA248D6E44E8154EB69F0AE2AEBAEE9931D0B5A969F904
        r = 0xAD04DDE87B84747A243A631EA47A1BA6D1FAA059149AD2440DE6FBA6
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        s = 0x178D49B1AE90E3D8B629BE3DB5683915F4E8C99FDF6E666CF37ADCFD
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp224; hf = sha384; msg = b"test"; m = hf(msg).digest()
        k = 0x7046742B839478C1B5BD31DB2E862AD868E1A45C863585B5F22BDC2D
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x389B92682E399B26518A95506B52C03BC9379A9DADF3391A21FB0EA4
        s = 0x414A718ED3249FF6DBC5B50C27F71F01F070944DA22AB1F78F559AAB
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp224; hf = sha512; msg = b"test"; m = hf(msg).digest()
        k = 0xE39C2AA4EA6BE2306C72126D40ED77BF9739BB4D6EF2BBB1DCB6169D
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x049F050477C5ADD858CAC56208394B5A55BAEBBE887FDF765047C17C
        s = 0x077EB13E7005929CEFA3CD0403C7CDCC077ADF4E44F3C41B2F60ECFF
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        # source: https://tools.ietf.org/html/rfc6979 section A.2.5
        ec = nistp256
        x  = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        Ux = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
        Uy = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
        U = mult(ec, x, ec.G)
        self.assertEqual((Ux, Uy), U)

        ec = nistp256; hf = sha1; msg = b"sample"; m = hf(msg).digest()
        k = 0x882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32
        s = 0x6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp256; hf = sha224; msg = b"sample"; m = hf(msg).digest()
        k = 0x103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F
        s = 0xB9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp256; hf = sha256; msg = b"sample"; m = hf(msg).digest()
        k = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
        s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp256; hf = sha384; msg = b"sample"; m = hf(msg).digest()
        k = 0x09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719
        s = 0x4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp256; hf = sha512; msg = b"sample"; m = hf(msg).digest()
        k = 0x5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00
        s = 0x2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp256; hf = sha1; msg = b"test"; m = hf(msg).digest()
        k = 0x8C9520267C55D6B980DF741E56B4ADEE114D84FBFA2E62137954164028632A2E
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89
        s = 0x01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp256; hf = sha224; msg = b"test"; m = hf(msg).digest()
        k = 0x669F4426F2688B8BE0DB3A6BD1989BDAEFFF84B649EEB84F3DD26080F667FAA7
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xC37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692
        s = 0xC820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp256; hf = sha256; msg = b"test"; m = hf(msg).digest()
        k = 0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367
        s = 0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp256; hf = sha384; msg = b"test"; m = hf(msg).digest()
        k = 0x16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6
        s = 0x8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp256; hf = sha512; msg = b"test"; m = hf(msg).digest()
        k = 0x6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04
        s = 0x39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        # source: https://tools.ietf.org/html/rfc6979 section A.2.6
        ec = nistp384
        x  = 0x6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5
        Ux = 0xEC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13
        Uy = 0x8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720
        U = mult(ec, x, ec.G)
        self.assertEqual((Ux, Uy), U)

        ec = nistp384; hf = sha1; msg = b"sample"; m = hf(msg).digest()
        k = 0x4471EF7518BB2C7C20F62EAE1C387AD0C5E8E470995DB4ACF694466E6AB096630F29E5938D25106C3C340045A2DB01A7
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xEC748D839243D6FBEF4FC5C4859A7DFFD7F3ABDDF72014540C16D73309834FA37B9BA002899F6FDA3A4A9386790D4EB2
        s = 0xA3BCFA947BEEF4732BF247AC17F71676CB31A847B9FF0CBC9C9ED4C1A5B3FACF26F49CA031D4857570CCB5CA4424A443
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp384; hf = sha224; msg = b"sample"; m = hf(msg).digest()
        k = 0xA4E4D2F0E729EB786B31FC20AD5D849E304450E0AE8E3E341134A5C1AFA03CAB8083EE4E3C45B06A5899EA56C51B5879
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x42356E76B55A6D9B4631C865445DBE54E056D3B3431766D0509244793C3F9366450F76EE3DE43F5A125333A6BE060122
        s = 0x9DA0C81787064021E78DF658F2FBB0B042BF304665DB721F077A4298B095E4834C082C03D83028EFBF93A3C23940CA8D
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp384; hf = sha256; msg = b"sample"; m = hf(msg).digest()
        k = 0x180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404B490650A8ACC414E375572342863C899F9F2EDF9747A9B60
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD
        s = 0xF3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp384; hf = sha384; msg = b"sample"; m = hf(msg).digest()
        k = 0x94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA2907E3E83BA95368623B8C4686915CF9
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46
        s = 0x99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp384; hf = sha512; msg = b"sample"; m = hf(msg).digest()
        k = 0x92FC3C7183A883E24216D1141F1A8976C5B0DD797DFA597E3D7B32198BD35331A4E966532593A52980D0E3AAA5E10EC3
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799CFE30F35CC900056D7C99CD7882433709
        s = 0x512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp384; hf = sha1; msg = b"test"; m = hf(msg).digest()
        k = 0x66CC2C8F4D303FC962E5FF6A27BD79F84EC812DDAE58CF5243B64A4AD8094D47EC3727F3A3C186C15054492E30698497
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x4BC35D3A50EF4E30576F58CD96CE6BF638025EE624004A1F7789A8B8E43D0678ACD9D29876DAF46638645F7F404B11C7
        s = 0xD5A6326C494ED3FF614703878961C0FDE7B2C278F9A65FD8C4B7186201A2991695BA1C84541327E966FA7B50F7382282
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp384; hf = sha224; msg = b"test"; m = hf(msg).digest()
        k = 0x18FA39DB95AA5F561F30FA3591DC59C0FA3653A80DAFFA0B48D1A4C6DFCBFF6E3D33BE4DC5EB8886A8ECD093F2935726
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xE8C9D0B6EA72A0E7837FEA1D14A1A9557F29FAA45D3E7EE888FC5BF954B5E62464A9A817C47FF78B8C11066B24080E72
        s = 0x07041D4A7A0379AC7232FF72E6F77B6DDB8F09B16CCE0EC3286B2BD43FA8C6141C53EA5ABEF0D8231077A04540A96B66
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp384; hf = sha256; msg = b"test"; m = hf(msg).digest()
        k = 0x0CFAC37587532347DC3389FDC98286BBA8C73807285B184C83E62E26C401C0FAA48DD070BA79921A3457ABFF2D630AD7
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B
        s = 0x2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp384; hf = sha384; msg = b"test"; m = hf(msg).digest()
        k = 0x015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092ADA71F4A459BC0DA98ADB95837DB8312EA
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB
        s = 0xDDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp384; hf = sha512; msg = b"test"; m = hf(msg).digest()
        k = 0x3780C4F67CB15518B6ACAE34C9F83568D2E12E47DEAB6C50A4E4EE5319D1E8CE0E2CC8A136036DC4B9C00E6888F66B6C
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0xA0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D06FB6495CD21B4B6E340FC236584FB277
        s = 0x976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B224634A2092CD3792E0159AD9CEE37659C736
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        # source: https://tools.ietf.org/html/rfc6979 section A.2.7
        ec = nistp521
        x  = 0x0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538
        Ux = 0x1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4
        Uy = 0x0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5
        U = mult(ec, x, ec.G)
        self.assertEqual((Ux, Uy), U)

        ec = nistp521; hf = sha1; msg = b"sample"; m = hf(msg).digest()
        k = 0x089C071B419E1C2820962321787258469511958E80582E95D8378E0C2CCDB3CB42BEDE42F50E3FA3C71F5A76724281D31D9C89F0F91FC1BE4918DB1C03A5838D0F9
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x0343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D75D
        s = 0x0E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5D16
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp521; hf = sha224; msg = b"sample"; m = hf(msg).digest()
        k = 0x121415EC2CD7726330A61F7F3FA5DE14BE9436019C4DB8CB4041F3B54CF31BE0493EE3F427FB906393D895A19C9523F3A1D54BB8702BD4AA9C99DAB2597B92113F3
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x1776331CFCDF927D666E032E00CF776187BC9FDD8E69D0DABB4109FFE1B5E2A30715F4CC923A4A5E94D2503E9ACFED92857B7F31D7152E0F8C00C15FF3D87E2ED2E
        s = 0x050CB5265417FE2320BBB5A122B8E1A32BD699089851128E360E620A30C7E17BA41A666AF126CE100E5799B153B60528D5300D08489CA9178FB610A2006C254B41F
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp521; hf = sha256; msg = b"sample"; m = hf(msg).digest()
        k = 0x0EDF38AFCAAECAB4383358B34D67C9F2216C8382AAEA44A3DAD5FDC9C32575761793FEF24EB0FC276DFC4F6E3EC476752F043CF01415387470BCBD8678ED2C7E1A0
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7
        s = 0x04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp521; hf = sha384; msg = b"sample"; m = hf(msg).digest()
        k = 0x1546A108BC23A15D6F21872F7DED661FA8431DDBD922D0DCDB77CC878C8553FFAD064C95A920A750AC9137E527390D2D92F153E66196966EA554D9ADFCB109C4211
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x1EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67451
        s = 0x1F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65D61
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp521; hf = sha512; msg = b"sample"; m = hf(msg).digest()
        k = 0x1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA
        s = 0x0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp521; hf = sha1; msg = b"test"; m = hf(msg).digest()
        k = 0x0BB9F2BF4FE1038CCF4DABD7139A56F6FD8BB1386561BD3C6A4FC818B20DF5DDBA80795A947107A1AB9D12DAA615B1ADE4F7A9DC05E8E6311150F47F5C57CE8B222
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x13BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B0693F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0367
        s = 0x1E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90F717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC916797FF
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp521; hf = sha224; msg = b"test"; m = hf(msg).digest()
        k = 0x040D09FCF3C8A5F62CF4FB223CBBB2B9937F6B0577C27020A99602C25A01136987E452988781484EDBBCF1C47E554E7FC901BC3085E5206D9F619CFF07E73D6F706
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x1C7ED902E123E6815546065A2C4AF977B22AA8EADDB68B2C1110E7EA44D42086BFE4A34B67DDC0E17E96536E358219B23A706C6A6E16BA77B65E1C595D43CAE17FB
        s = 0x177336676304FCB343CE028B38E7B4FBA76C1C1B277DA18CAD2A8478B2A9A9F5BEC0F3BA04F35DB3E4263569EC6AADE8C92746E4C82F8299AE1B8F1739F8FD519A4
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp521; hf = sha256; msg = b"test"; m = hf(msg).digest()
        k = 0x01DE74955EFAABC4C4F17F8E84D881D1310B5392D7700275F82F145C61E843841AF09035BF7A6210F5A431A6A9E81C9323354A9E69135D44EBD2FCAA7731B909258
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8
        s = 0x0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp521; hf = sha384; msg = b"test"; m = hf(msg).digest()
        k = 0x1F1FC4A349A7DA9A9E116BFDD055DC08E78252FF8E23AC276AC88B1770AE0B5DCEB1ED14A4916B769A523CE1E90BA22846AF11DF8B300C38818F713DADD85DE0C88
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x14BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF6075578C
        s = 0x133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0ED94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B979
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))

        ec = nistp521; hf = sha512; msg = b"test"; m = hf(msg).digest()
        k = 0x16200813020EC986863BEDFC1B121F605C1215645018AEA1A7B215A564DE9EB1B38A67AA1128B80CE391C4FB71187654AAA3431027BFC7F395766CA988C964DC56D
        self.assertEqual(k, rfc6979(ec, hf, m, x))
        r = 0x13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D
        s = 0x1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3
        sig = dsa.sign(ec, hf, msg, x, k)
        self.assertEqual(r, sig[0])
        self.assertIn(s, (sig[1], ec.n - sig[1]))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
