#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import pytest

from btclib import bip32
from btclib.base58 import b58encode
from btclib.base58wif import wif_from_prvkey
from btclib.curves import secp256k1 as ec
from btclib.secpoint import bytes_from_point
from btclib.to_prvkey import int_from_prvkey, prvkeyinfo_from_prvkey

xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
xprv_dict = bip32.deserialize(xprv)
q = xprv_dict["q"]

# prv key with no network / compression information
prv_keys = [
    xprv_dict["key"][1:],  # bytes
    xprv_dict["key"][1:].hex(),  # hex-string
    " " + xprv_dict["key"][1:].hex() + " ",  # hex-string
    q,
]

compressed_prv_keys = [
    xprv,  # bytes
    xprv.decode("ascii"),  # str
    " " + xprv.decode("ascii") + " ",  # str
    xprv_dict,  # dict
    wif_from_prvkey(q),  # compressed wif bytes
    wif_from_prvkey(q).decode("ascii"),  # compressed wif str
    " " + wif_from_prvkey(q).decode("ascii") + " ",
]

uncompressed_prv_keys = [
    wif_from_prvkey(q, compressed=False),  # uncompressed wif bytes
    wif_from_prvkey(q, compressed=False).decode("ascii"),  # uncompressed wif str
    " " + wif_from_prvkey(q, compressed=False).decode("ascii") + " ",
]

xpub = b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
xpub_dict = bip32.deserialize(xpub)
Q = xpub_dict["Q"]

compressed_pub_keys = [
    xpub,  # bytes
    xpub.decode("ascii"),  # str
    " " + xpub.decode("ascii") + " ",  # str
    xpub_dict,  # dict
    xpub_dict["key"],  # bytes
    xpub_dict["key"].hex(),  # hex-string
    " " + xpub_dict["key"].hex() + " ",  # hex-string
]

uncompressed_pub_keys = [
    bytes_from_point(Q, compressed=False),
    bytes_from_point(Q, compressed=False).hex(),
    " " + bytes_from_point(Q, compressed=False).hex() + " ",
]

not_a_prv_keys = [Q] + compressed_pub_keys + uncompressed_pub_keys
not_a_prv_keys += [
    xprv + b"\x00",
    xprv.decode("ascii") + "00",
    xprv_dict["key"][1:] + b"\x00",
    xprv_dict["key"][1:].hex() + "00",
    wif_from_prvkey(q) + b"\x00",
    wif_from_prvkey(q).decode("ascii") + "00",
    wif_from_prvkey(q, compressed=False) + b"\x00",
    wif_from_prvkey(q, compressed=False).decode("ascii") + "00",
    xprv_dict["key"],
    xprv_dict["key"].hex(),
    b"\x02" + xprv_dict["key"][1:],
    "02" + xprv_dict["key"][1:].hex(),
    "notakey",
]

invalid_prv_keys = []
for inv_q in (0, ec.n):
    invalid_prv_keys.append(inv_q)
    inv_q_bytes = inv_q.to_bytes(32, "big")
    t = b"\x80" + inv_q_bytes + b"\x01"
    wif = b58encode(t)
    invalid_prv_keys.append(wif)
    invalid_prv_keys.append(wif.decode("ascii"))
    t = xprv_dict["version"]
    t += xprv_dict["depth"].to_bytes(1, "big")
    t += xprv_dict["parent_fingerprint"]
    t += xprv_dict["index"]
    t += xprv_dict["chain_code"]
    t += b"\x00" + inv_q_bytes
    xprv = b58encode(t, 78)
    invalid_prv_keys.append(xprv)
    invalid_prv_keys.append(xprv.decode("ascii"))

# FIXME: fix error messages


def test_from_prvkey():

    t = (q, "mainnet", True)
    for prv_key in prv_keys + compressed_prv_keys:
        assert q == int_from_prvkey(prv_key)
        assert t == prvkeyinfo_from_prvkey(prv_key)
        assert t == prvkeyinfo_from_prvkey(prv_key, "mainnet")
        assert t == prvkeyinfo_from_prvkey(prv_key, "mainnet", compressed=True)
        assert t == prvkeyinfo_from_prvkey(prv_key, compressed=True)

    t = (q, "mainnet", False)
    for prv_key in uncompressed_prv_keys:
        assert q == int_from_prvkey(prv_key)
        assert t == prvkeyinfo_from_prvkey(prv_key, "mainnet", compressed=False)
        assert t == prvkeyinfo_from_prvkey(prv_key, compressed=False)

    for prv_key in uncompressed_prv_keys:
        with pytest.raises(ValueError):
            prvkeyinfo_from_prvkey(prv_key)
            prvkeyinfo_from_prvkey(prv_key, "mainnet", compressed=True)
            prvkeyinfo_from_prvkey(prv_key, compressed=True)

    for prv_key in compressed_prv_keys:
        with pytest.raises(ValueError):
            prvkeyinfo_from_prvkey(prv_key, "mainnet", compressed=False)
            prvkeyinfo_from_prvkey(prv_key, compressed=False)

    for not_a_prv_key in not_a_prv_keys:
        with pytest.raises(ValueError):
            int_from_prvkey(not_a_prv_key)
            prvkeyinfo_from_prvkey(not_a_prv_key)

    for invalid_prv_key in invalid_prv_keys:
        with pytest.raises(ValueError):
            int_from_prvkey(invalid_prv_key)
            prvkeyinfo_from_prvkey(invalid_prv_key)

    for prv_key in compressed_prv_keys + uncompressed_prv_keys:
        with pytest.raises(ValueError):
            prvkeyinfo_from_prvkey(prv_key, "testnet")
            prvkeyinfo_from_prvkey(prv_key, "testnet", compressed=True)
