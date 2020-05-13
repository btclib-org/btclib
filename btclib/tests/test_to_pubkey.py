#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import copy
import unittest

from btclib import bip32
from btclib.alias import INF
from btclib.base58 import b58encode
from btclib.base58wif import wif_from_prvkey
from btclib.curvemult import mult
from btclib.curves import CURVES
from btclib.network import NETWORKS
from btclib.secpoint import bytes_from_point
from btclib.to_prvkey import _prvkeyinfo_from_xprv
from btclib.to_pubkey import (
    _pubkeyinfo_from_xpub,
    fingerprint,
    point_from_key,
    point_from_pubkey,
    pubkeyinfo_from_key,
    pubkeyinfo_from_pubkey,
)

secp256r1 = CURVES["secp256r1"]


class TestToPubKey(unittest.TestCase):
    def test_point_from_key(self):

        # prvkeys
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        xprv_str = xprv.decode("ascii")
        xprv_dict = bip32.deserialize(xprv)
        q, network, _ = _prvkeyinfo_from_xprv(xprv)
        ec = NETWORKS[network]["curve"]
        q_bytes = q.to_bytes(ec.nsize, "big")
        wif1 = wif_from_prvkey(q, network, True)
        wif2 = wif_from_prvkey(q, network, False)

        # pubkeys
        Q = mult(q, ec.G, ec)
        xpub = bip32.xpub_from_xprv(xprv)
        xpub_str = xpub.decode("ascii")
        xpub_dict = bip32.deserialize(xpub)
        Q_compr = xpub_dict["key"]
        Q_compr_hexstr = Q_compr.hex()
        Q_uncompr = bytes_from_point(Q, ec, False)
        Q_uncompr_hexstr = Q_uncompr.hex()

        # int prvkey
        self.assertEqual(point_from_key(q, ec), Q)
        self.assertEqual(point_from_key(q_bytes, ec), Q)

        # wif prvkey
        self.assertEqual(point_from_key(wif1, ec), Q)
        self.assertEqual(point_from_key(wif2, ec), Q)

        # BIP32 prvkey
        self.assertEqual(point_from_key(xprv, ec), Q)
        self.assertEqual(point_from_key(xprv_str, ec), Q)
        self.assertEqual(point_from_key(" " + xprv_str + " ", ec), Q)
        self.assertEqual(point_from_key(xprv_dict, ec), Q)

        # BIP32 pubkey
        self.assertEqual(point_from_key(xpub, ec), Q)
        self.assertEqual(point_from_key(xpub_str, ec), Q)
        self.assertEqual(point_from_key(" " + xpub_str + " ", ec), Q)
        self.assertEqual(point_from_key(xpub_dict, ec), Q)

        # compressed SEC Octets (bytes or hex-string, with 02 or 03 prefix)
        self.assertEqual(point_from_key(Q_compr, ec), Q)
        self.assertRaises(ValueError, point_from_key, b"\x00" + Q_compr, ec)
        self.assertEqual(point_from_key(Q_compr_hexstr, ec), Q)
        self.assertEqual(point_from_key(" " + Q_compr_hexstr + " ", ec), Q)
        self.assertRaises(ValueError, point_from_key, Q_compr_hexstr + "00", ec)

        # uncompressed SEC Octets (bytes or hex-string, with 04 prefix)
        self.assertEqual(point_from_key(Q_uncompr, ec), Q)
        self.assertRaises(ValueError, point_from_key, b"\x00" + Q_uncompr, ec)
        self.assertEqual(point_from_key(Q_uncompr_hexstr, ec), Q)
        self.assertEqual(point_from_key(" " + Q_uncompr_hexstr + " ", ec), Q)
        self.assertRaises(ValueError, point_from_key, Q_uncompr_hexstr + "00", ec)

        # native tuple
        self.assertEqual(point_from_key(Q, ec), Q)

        # Invalid point: 7 is not a field element
        Q = INF
        self.assertRaises(ValueError, point_from_key, Q, ec)
        Q_compr = b"\x02" + Q[0].to_bytes(ec.psize, "big")
        self.assertRaises(ValueError, point_from_key, Q_compr, ec)
        Q_uncompr = (
            b"\x04" + Q[0].to_bytes(ec.psize, "big") + Q[1].to_bytes(ec.psize, "big")
        )
        self.assertRaises(ValueError, point_from_key, Q_uncompr, ec)
        Q_compr_hexstr = Q_compr.hex()
        self.assertRaises(ValueError, point_from_key, Q_compr_hexstr, ec)
        Q_uncompr_hexstr = Q_uncompr.hex()
        self.assertRaises(ValueError, point_from_key, Q_uncompr_hexstr, ec)
        t = xpub_dict["version"]
        t += xpub_dict["depth"].to_bytes(1, "big")
        t += xpub_dict["parent_fingerprint"]
        t += xpub_dict["index"]
        t += xpub_dict["chain_code"]
        t += Q_compr
        xpub = b58encode(t, 78)
        self.assertRaises(ValueError, point_from_key, xpub, ec)
        xpub_str = xpub.decode("ascii")
        self.assertRaises(ValueError, point_from_key, xpub_str, ec)

        # pubkey input
        self.assertRaises(ValueError, point_from_pubkey, xprv, ec)
        self.assertRaises(ValueError, point_from_pubkey, xprv_str, ec)
        self.assertRaises(ValueError, point_from_pubkey, xprv_dict, ec)
        self.assertRaises(ValueError, point_from_pubkey, q, ec)
        self.assertRaises(ValueError, point_from_pubkey, wif1, ec)
        self.assertRaises(ValueError, point_from_pubkey, wif2, ec)

    def test_pubkeyinfo_from_key(self):

        # prvkeys
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        xprv_str = xprv.decode("ascii")
        xprv_dict = bip32.deserialize(xprv)
        q, network, _ = _prvkeyinfo_from_xprv(xprv)
        ec = NETWORKS[network]["curve"]
        q_bytes = q.to_bytes(ec.nsize, "big")
        wif1 = wif_from_prvkey(q, network, True)
        wif2 = wif_from_prvkey(q, network, False)

        # pubkeys
        Q = mult(q, ec.G, ec)
        xpub = bip32.xpub_from_xprv(xprv)
        xpub_str = xpub.decode("ascii")
        xpub_dict = bip32.deserialize(xpub)
        Q_compr = xpub_dict["key"]
        Q_compr_hexstr = Q_compr.hex()
        Q_uncompr = bytes_from_point(Q, ec, False)
        Q_uncompr_hexstr = Q_uncompr.hex()

        # int prvkey, compressed result
        self.assertEqual(pubkeyinfo_from_key(q)[0], Q_compr)
        self.assertEqual(pubkeyinfo_from_key(q_bytes)[0], Q_compr)

        # int prvkey, uncompressed result
        self.assertEqual(pubkeyinfo_from_key(q, compressed=False)[0], Q_uncompr)
        self.assertEqual(pubkeyinfo_from_key(q_bytes, compressed=False)[0], Q_uncompr)

        # compressed wif prvkey, both results
        self.assertEqual(pubkeyinfo_from_key(wif1)[0], Q_compr)
        self.assertRaises(ValueError, pubkeyinfo_from_key, wif1, compressed=False)

        # uncompressed wif prvkey, both results
        self.assertRaises(ValueError, pubkeyinfo_from_key, wif2, compressed=True)
        self.assertEqual(pubkeyinfo_from_key(wif2)[0], Q_uncompr)

        # (compressed) BIP32 prvkey, compressed results
        self.assertEqual(pubkeyinfo_from_key(xprv)[0], Q_compr)
        self.assertEqual(pubkeyinfo_from_key(xprv_str)[0], Q_compr)
        self.assertEqual(pubkeyinfo_from_key(" " + xprv_str + " ")[0], Q_compr)
        self.assertEqual(pubkeyinfo_from_key(xprv_dict)[0], Q_compr)

        # (compressed) BIP32 prvkey, uncompressed result
        self.assertRaises(ValueError, pubkeyinfo_from_key, xprv, compressed=False)
        self.assertRaises(ValueError, pubkeyinfo_from_key, xprv_str, compressed=False)
        self.assertRaises(
            ValueError, pubkeyinfo_from_key, " " + xprv_str + " ", compressed=False
        )
        self.assertRaises(ValueError, pubkeyinfo_from_key, xprv_dict, compressed=False)

        # (compressed) BIP32 pubkey, compressed results
        self.assertEqual(pubkeyinfo_from_key(xpub)[0], Q_compr)
        self.assertEqual(pubkeyinfo_from_key(xpub_str)[0], Q_compr)
        self.assertEqual(pubkeyinfo_from_key(" " + xpub_str + " ")[0], Q_compr)
        self.assertEqual(pubkeyinfo_from_key(xpub_dict)[0], Q_compr)

        # (compressed) BIP32 pubkey, uncompressed result
        self.assertRaises(ValueError, pubkeyinfo_from_key, xpub, compressed=False)
        self.assertRaises(ValueError, pubkeyinfo_from_key, xpub_str, compressed=False)
        self.assertRaises(
            ValueError, pubkeyinfo_from_key, " " + xpub_str + " ", compressed=False
        )
        self.assertRaises(ValueError, pubkeyinfo_from_key, xpub_dict, compressed=False)

        # compressed SEC Octets (pubkey), compressed results
        self.assertEqual(pubkeyinfo_from_key(Q_compr)[0], Q_compr)
        self.assertEqual(pubkeyinfo_from_key(Q_compr_hexstr)[0], Q_compr)
        self.assertEqual(pubkeyinfo_from_key(" " + Q_compr_hexstr + " ")[0], Q_compr)

        # compressed SEC Octets (pubkey), uncompressed results
        self.assertRaises(ValueError, pubkeyinfo_from_key, Q_compr, compressed=False)
        self.assertRaises(
            ValueError, pubkeyinfo_from_key, Q_compr_hexstr, compressed=False
        )
        self.assertRaises(
            ValueError,
            pubkeyinfo_from_key,
            " " + Q_compr_hexstr + " ",
            compressed=False,
        )
        self.assertRaises(ValueError, pubkeyinfo_from_key, b"\x00" + Q_compr)
        self.assertRaises(ValueError, pubkeyinfo_from_key, Q_compr_hexstr + "00")

        # uncompressed SEC Octets (pubkey), uncompressed results
        self.assertEqual(pubkeyinfo_from_key(Q_uncompr)[0], Q_uncompr)
        self.assertEqual(pubkeyinfo_from_key(Q_uncompr_hexstr)[0], Q_uncompr)
        self.assertEqual(
            pubkeyinfo_from_key(" " + Q_uncompr_hexstr + " ")[0], Q_uncompr
        )

        # uncompressed SEC Octets (pubkey), compressed results
        self.assertRaises(ValueError, pubkeyinfo_from_key, Q_uncompr, compressed=True)
        self.assertRaises(
            ValueError, pubkeyinfo_from_key, Q_uncompr_hexstr, compressed=True
        )
        self.assertRaises(
            ValueError,
            pubkeyinfo_from_key,
            " " + Q_uncompr_hexstr + " ",
            compressed=True,
        )
        self.assertRaises(ValueError, pubkeyinfo_from_key, b"\x00" + Q_uncompr)
        self.assertRaises(ValueError, pubkeyinfo_from_key, Q_uncompr_hexstr + "00")

        # native tuple input, both results
        self.assertEqual(pubkeyinfo_from_key(Q)[0], Q_compr)
        self.assertEqual(pubkeyinfo_from_key(Q, compressed=False)[0], Q_uncompr)

        # pubkeyinfo_from_pubkey does not accept prvkey inputs
        self.assertRaises(ValueError, pubkeyinfo_from_pubkey, q)
        self.assertRaises(ValueError, pubkeyinfo_from_pubkey, q_bytes)
        self.assertRaises(ValueError, pubkeyinfo_from_pubkey, xprv)
        self.assertRaises(ValueError, pubkeyinfo_from_pubkey, xprv_str)
        self.assertRaises(ValueError, pubkeyinfo_from_pubkey, xprv_dict)
        self.assertRaises(ValueError, pubkeyinfo_from_pubkey, wif1)
        self.assertRaises(ValueError, pubkeyinfo_from_pubkey, wif2)

        # Not a public key:
        xpub_dict_bad = copy.copy(xpub_dict)
        xpub_dict_bad["key"] = b"\x00" + xpub_dict["key"][1:]
        self.assertRaises(ValueError, _pubkeyinfo_from_xpub, xpub_dict_bad)
        # _pubkeyinfo_from_xpub(xpub_dict_bad)

        # Invalid point: 7 is not a field element
        Q = INF
        self.assertRaises(ValueError, pubkeyinfo_from_key, Q)
        Q_compr = b"\x02" + Q[0].to_bytes(ec.psize, "big")
        self.assertRaises(ValueError, pubkeyinfo_from_key, Q_compr)
        Q_uncompr = (
            b"\x04" + Q[0].to_bytes(ec.psize, "big") + Q[1].to_bytes(ec.psize, "big")
        )
        self.assertRaises(ValueError, pubkeyinfo_from_key, Q_uncompr)
        Q_compr_hexstr = Q_compr.hex()
        self.assertRaises(ValueError, pubkeyinfo_from_key, Q_compr_hexstr)
        Q_uncompr_hexstr = Q_uncompr.hex()
        self.assertRaises(ValueError, pubkeyinfo_from_key, Q_uncompr_hexstr)
        t = xpub_dict["version"]
        t += xpub_dict["depth"].to_bytes(1, "big")
        t += xpub_dict["parent_fingerprint"]
        t += xpub_dict["index"]
        t += xpub_dict["chain_code"]
        t += Q_compr
        xpub = b58encode(t, 78)
        self.assertRaises(ValueError, pubkeyinfo_from_key, xpub)
        xpub_str = xpub.decode("ascii")
        self.assertRaises(ValueError, pubkeyinfo_from_key, xpub_str)

    def test_fingerprint(self):
        xpub = b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        pf = fingerprint(xpub)
        # bytes are used to increase code coverage
        # dict is used to increase code coverage
        xpubd = bip32.deserialize(xpub)
        child_key = bip32.derive(xpubd, b"\x00" * 4)
        pf2 = bip32.deserialize(child_key)["parent_fingerprint"]
        self.assertEqual(pf, pf2)

    def test_exceptions(self):

        # Not a testnet key
        xpub = b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        xpubd = bip32.deserialize(xpub)
        self.assertRaises(ValueError, _pubkeyinfo_from_xpub, xpubd, "testnet", None)
        # _pubkeyinfo_from_xpub(xpubd, 'testnet', None)

        self.assertRaises(ValueError, _pubkeyinfo_from_xpub, xpubd, None, False)
        # _pubkeyinfo_from_xpub(xpubd, compressed=False)

        xpub = b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        self.assertRaises(ValueError, point_from_key, xpub, secp256r1)

        wif = b"KzyziFNa2m2WC84NDBG2ix3rQXYcKHndvCjTkmJQWuoadpQxmdmu"
        self.assertRaises(ValueError, point_from_key, wif, secp256r1)
        # point_from_key(wif, secp256r1)

        point_from_key(1, secp256r1)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
