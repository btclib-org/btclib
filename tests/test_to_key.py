#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Test vectors of valid and invalid keys.

Used by `btclib.tests.to_pub_key` and `btclib.tests.to_pub_key` modules.
Test vectors do include str only: no int, point tuble, or BIP32KeyData.
"""

import copy
from typing import List, Union

from btclib.alias import INF
from btclib.base58 import b58encode
from btclib.bip32.bip32 import BIP32KeyData
from btclib.ecc.curve import mult, secp256k1

ec = secp256k1

q = 12
q_bytes = q.to_bytes(32, byteorder="big", signed=False)
q_hexstring = q_bytes.hex()
q_hexstring2 = " " + q_hexstring + " "

# prv_keys with no network / compression information
plain_prv_keys: List[Union[bytes, str]] = [
    q_hexstring,
    q_hexstring2,
]

wif_compressed = b58encode(b"\x80" + q_bytes + b"\x01")
wif_compressed_string = wif_compressed.decode("ascii")
wif_compressed_string2 = " " + wif_compressed_string + " "
wif_uncompressed = b58encode(b"\x80" + q_bytes)
wif_uncompressed_string = wif_uncompressed.decode("ascii")
wif_uncompressed_string2 = " " + wif_uncompressed_string + " "

xprv_data = BIP32KeyData(
    version=bytes.fromhex("04 88 ad e4"),
    depth=0,
    parent_fingerprint=bytes.fromhex("00000000"),
    index=0,
    chain_code=32 * b"\x00",
    key=b"\x00" + q_bytes,
)
xprv_string = xprv_data.b58encode(False)
xprv_string2 = " " + xprv_string + " "

net_aware_compressed_prv_keys: List[Union[bytes, str]] = [
    wif_compressed_string,
    wif_compressed_string2,
    xprv_string,
    xprv_string2,
]
net_aware_uncompressed_prv_keys: List[Union[bytes, str]] = [
    wif_uncompressed_string,
    wif_uncompressed_string2,
]
net_unaware_compressed_prv_keys: List[Union[bytes, str]] = []
net_unaware_uncompressed_prv_keys: List[Union[bytes, str]] = []

compressed_prv_keys = net_aware_compressed_prv_keys + net_unaware_compressed_prv_keys
uncompressed_prv_keys = (
    net_aware_uncompressed_prv_keys + net_unaware_uncompressed_prv_keys
)

net_aware_prv_keys = net_aware_compressed_prv_keys + net_aware_uncompressed_prv_keys
net_unaware_prv_keys = (
    plain_prv_keys + net_unaware_compressed_prv_keys + net_unaware_uncompressed_prv_keys
)

Q = mult(q)

# pub_keys with no network / compression information
# but curve aware
plain_pub_keys: List[Union[bytes, str]] = []

x_Q_bytes = Q[0].to_bytes(32, byteorder="big", signed=False)
Q_compressed = (b"\x03" if (Q[1] & 1) else b"\x02") + x_Q_bytes
Q_compressed_hexstring = Q_compressed.hex()
Q_compressed_hexstring2 = " " + Q_compressed_hexstring + " "
Q_compressed_hexstring3 = ("03" if (Q[1] & 1) else "02") + " " + x_Q_bytes.hex()
Q_uncompressed = b"\x04" + x_Q_bytes + Q[1].to_bytes(32, byteorder="big", signed=False)
Q_uncompressed_hexstring = Q_uncompressed.hex()
Q_uncompressed_hexstring2 = " " + Q_uncompressed_hexstring + " "
Q_uncompressed_hexstring3 = (
    "04 "
    + x_Q_bytes.hex()
    + " "
    + Q[1].to_bytes(32, byteorder="big", signed=False).hex()
)

xpub_data = BIP32KeyData(
    version=bytes.fromhex("04 88 b2 1e"),
    depth=xprv_data.depth,
    parent_fingerprint=xprv_data.parent_fingerprint,
    index=xprv_data.index,
    chain_code=xprv_data.chain_code,
    key=Q_compressed,
)
xpub_string = xpub_data.b58encode(False)

xpub_string2 = " " + xpub_string + " "

net_aware_compressed_pub_keys: List[Union[bytes, str]] = [
    xpub_string,
    xpub_string2,
]
net_aware_uncompressed_pub_keys: List[Union[bytes, str]] = []
net_unaware_compressed_pub_keys: List[Union[bytes, str]] = [
    Q_compressed_hexstring,
    Q_compressed_hexstring2,
    Q_compressed_hexstring3,
]
net_unaware_uncompressed_pub_keys: List[Union[bytes, str]] = [
    Q_uncompressed_hexstring,
    Q_uncompressed_hexstring2,
    Q_uncompressed_hexstring3,
]

compressed_pub_keys = net_aware_compressed_pub_keys + net_unaware_compressed_pub_keys
uncompressed_pub_keys = (
    net_aware_uncompressed_pub_keys + net_unaware_uncompressed_pub_keys
)

net_aware_pub_keys = net_aware_compressed_pub_keys + net_aware_uncompressed_pub_keys
net_unaware_pub_keys = (
    net_unaware_compressed_pub_keys + net_unaware_uncompressed_pub_keys
)

# all bad BIP32 keys
bad_bip32_keys: List[Union[bytes, str]] = []
# version / key mismatch
xprv_data_bad = copy.copy(xprv_data)
xpub_data_bad = copy.copy(xpub_data)
xprv_data_bad.version = bytes.fromhex("04 88 b2 1e")
xpub_data_bad.version = bytes.fromhex("04 88 ad e4")
bad_bip32_keys += [
    xprv_data_bad.b58encode(False),
    xpub_data_bad.b58encode(False),
]
# key starts with 04
xprv_data_bad.key = b"\x04" + xprv_data_bad.key[1:]
xpub_data_bad.key = b"\x04" + xprv_data_bad.key[1:]
bad_bip32_keys += [
    xprv_data_bad.b58encode(False),
    xpub_data_bad.b58encode(False),
]
# key starts with 01
xprv_data_bad.key = b"\x01" + xprv_data_bad.key[1:]
xpub_data_bad.key = b"\x01" + xprv_data_bad.key[1:]
bad_bip32_keys += [
    xprv_data_bad.b58encode(False),
    xpub_data_bad.b58encode(False),
]
# depth_pfp_index mismatch
xprv_data_bad = copy.copy(xprv_data)
xpub_data_bad = copy.copy(xpub_data)
xprv_data_bad.parent_fingerprint = b"\x01\x01\x01\x01"
xpub_data_bad.parent_fingerprint = b"\x01\x01\x01\x01"
bad_bip32_keys += [
    xprv_data_bad.b58encode(False),
    xpub_data_bad.b58encode(False),
]
# depth_pfp_index mismatch
xprv_data_bad = copy.copy(xprv_data)
xpub_data_bad = copy.copy(xpub_data)
xprv_data_bad.index = xpub_data_bad.index = 101
bad_bip32_keys += [
    xprv_data_bad.b58encode(False),
    xpub_data_bad.b58encode(False),
]
# unknown version
xprv_data_bad = copy.copy(xprv_data)
xpub_data_bad = copy.copy(xpub_data)
xprv_data_bad.version = b"\x01\x01\x01\x01"
xpub_data_bad.version = b"\x01\x01\x01\x01"
bad_bip32_keys += [
    xprv_data_bad.b58encode(False),
    xpub_data_bad.b58encode(False),
]


q0 = 0
q0_bytes = q0.to_bytes(32, byteorder="big", signed=False)
q0_hexstring = q0_bytes.hex()
q0_hexstring2 = " " + q0_hexstring + " "

qn = ec.n
qn_bytes = qn.to_bytes(32, byteorder="big", signed=False)
qn_hexstring = qn_bytes.hex()
qn_hexstring2 = " " + qn_hexstring + " "

plain_inf_prv_keys: List[Union[bytes, str]] = [
    q0_hexstring,
    q0_hexstring2,
    qn_hexstring,
    qn_hexstring2,
]

wif_0_compressed = b58encode(b"\x80" + q0_bytes + b"\x01")
wif_0_compressed_string = wif_0_compressed.decode("ascii")
wif_0_compressed_string2 = " " + wif_0_compressed_string + " "
wif_0_uncompressed = b58encode(b"\x80" + q0_bytes)
wif_0_uncompressed_string = wif_0_uncompressed.decode("ascii")
wif_0_uncompressed_string2 = " " + wif_0_uncompressed_string + " "

wif_n_compressed = b58encode(b"\x80" + qn_bytes + b"\x01")
wif_n_compressed_string = wif_n_compressed.decode("ascii")
wif_n_compressed_string2 = " " + wif_n_compressed_string + " "
wif_n_uncompressed = b58encode(b"\x80" + qn_bytes)
wif_n_uncompressed_string = wif_n_uncompressed.decode("ascii")
wif_n_uncompressed_string2 = " " + wif_n_uncompressed_string + " "

xprv0_data = BIP32KeyData(
    version=bytes.fromhex("04 88 ad e4"),
    depth=0,
    parent_fingerprint=bytes.fromhex("00000000"),
    index=0,
    chain_code=32 * b"\x00",
    key=b"\x00" + q0_bytes,
    check_validity=False,
)
xprv0_string = xprv0_data.b58encode(False)
xprv0_string2 = " " + xprv0_string + " "

xprvn_data = BIP32KeyData(
    version=bytes.fromhex("04 88 ad e4"),
    depth=0,
    parent_fingerprint=bytes.fromhex("00000000"),
    index=0,
    chain_code=32 * b"\x00",
    key=b"\x00" + qn_bytes,
    check_validity=False,
)
xprvn_string = xprvn_data.b58encode(False)
xprvn_string2 = " " + xprvn_string + " "

bad_bip32_keys += [xprv0_string, xprvn_string]

net_aware_compressed_inf_prv_keys: List[Union[bytes, str]] = [
    wif_0_compressed_string,
    wif_0_compressed_string2,
    wif_n_compressed_string,
    wif_n_compressed_string2,
    xprv0_string,
    xprv0_string2,
    xprvn_string,
    xprvn_string2,
]
net_aware_uncompressed_inf_prv_keys: List[Union[bytes, str]] = [
    wif_0_uncompressed_string,
    wif_0_uncompressed_string2,
    wif_n_uncompressed_string,
    wif_n_uncompressed_string2,
]
net_unaware_compressed_inf_prv_keys: List[Union[bytes, str]] = []
net_unaware_uncompressed_inf_prv_keys: List[Union[bytes, str]] = []

# compressed_inf_prv_keys = (
#    net_aware_compressed_inf_prv_keys + net_unaware_compressed_inf_prv_keys
# )
# uncompressed_inf_prv_keys = (
#    net_aware_uncompressed_inf_prv_keys + net_unaware_uncompressed_inf_prv_keys
# )

net_aware_inf_prv_keys: List[Union[bytes, str]] = (
    net_aware_compressed_inf_prv_keys + net_aware_uncompressed_inf_prv_keys
)
net_unaware_inf_prv_keys: List[Union[bytes, str]] = (
    plain_inf_prv_keys
    + net_unaware_compressed_inf_prv_keys
    + net_unaware_uncompressed_inf_prv_keys
)

inf_prv_keys: List[Union[bytes, str]] = (
    net_aware_inf_prv_keys + net_unaware_inf_prv_keys
)


Q_compressed = (b"\x03" if (Q[1] & 1) else b"\x02") + x_Q_bytes
Q_compressed_hexstring = Q_compressed.hex()
Q_compressed_hexstring2 = " " + Q_compressed_hexstring + " "
Q_compressed_hexstring3 = ("03" if (Q[1] & 1) else "02") + " " + x_Q_bytes.hex()
Q_uncompressed = b"\x04" + x_Q_bytes + Q[1].to_bytes(32, byteorder="big", signed=False)
Q_uncompressed_hexstring = Q_uncompressed.hex()
Q_uncompressed_hexstring2 = " " + Q_uncompressed_hexstring + " "
Q_uncompressed_hexstring3 = (
    "04 "
    + x_Q_bytes.hex()
    + " "
    + Q[1].to_bytes(32, byteorder="big", signed=False).hex()
)

INF_x_bytes = INF[0].to_bytes(32, byteorder="big", signed=False)
INF_compressed = (b"\x03" if (INF[1] & 1) else b"\x02") + INF_x_bytes
INF_compressed_hexstring = INF_compressed.hex()
INF_compressed_hexstring2 = " " + INF_compressed_hexstring + " "
INF_compressed_hexstring3 = ("03" if (INF[1] & 1) else "02") + " " + INF_x_bytes.hex()
INF_uncompressed = (
    b"\x04"
    + INF[0].to_bytes(32, byteorder="big", signed=False)
    + INF[1].to_bytes(32, byteorder="big", signed=False)
)
INF_uncompressed_hexstring = INF_uncompressed.hex()
INF_uncompressed_hexstring2 = " " + INF_uncompressed_hexstring + " "
INF_uncompressed_hexstring3 = (
    "04 "
    + INF_x_bytes.hex()
    + " "
    + INF[1].to_bytes(32, byteorder="big", signed=False).hex()
)

INF_xpub_data = BIP32KeyData(
    version=bytes.fromhex("04 88 b2 1e"),
    depth=xprv_data.depth,
    parent_fingerprint=xprv_data.parent_fingerprint,
    index=xprv_data.index,
    chain_code=xprv_data.chain_code,
    key=INF_compressed,
    check_validity=False,
)
INF_xpub_string = INF_xpub_data.b58encode(False)
INF_xpub_string2 = " " + INF_xpub_string + " "

bad_bip32_keys += [INF_xpub_string]

inf_pub_keys: List[Union[bytes, str]] = [
    INF_compressed_hexstring,
    INF_compressed_hexstring2,
    INF_compressed_hexstring3,
    INF_uncompressed_hexstring,
    INF_uncompressed_hexstring2,
    INF_uncompressed_hexstring3,
    INF_xpub_string,
    INF_xpub_string2,
]


invalid_prv_keys: List[Union[bytes, str]] = (
    bad_bip32_keys
    + inf_prv_keys
    + [
        wif_compressed_string + "01",
        wif_uncompressed_string + "01",
        xprv_string + "00",
        xprv_data.key[1:] + b"\x00",
        xprv_data.key[1:].hex() + "00",
        xprv_data.key,
        xprv_data.key.hex(),
        "invalidprv_key",
        b"invalidprv_key",
    ]
)

invalid_pub_keys = bad_bip32_keys + inf_pub_keys + ["invalidpub_key", b"invalidpub_key"]

not_a_prv_keys = invalid_prv_keys + invalid_pub_keys

not_a_pub_keys = invalid_prv_keys + invalid_pub_keys
