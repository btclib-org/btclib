#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import copy

from btclib.alias import BIP32KeyDict, INF
from btclib.base58 import b58encode
from btclib.curvemult import mult
from btclib.curves import secp256k1 as ec
from btclib.secpoint import bytes_from_point


def _serialize(d: BIP32KeyDict) -> bytes:
    t = d["version"]
    t += d["depth"].to_bytes(1, "big")
    t += d["parent_fingerprint"]
    t += d["index"]
    t += d["chain_code"]
    t += d["key"]
    return b58encode(t, 78)


q = 12
q_bytes = q.to_bytes(32, byteorder="big")
q_bytes_hexstring = q_bytes.hex()
q_bytes_hexstring2 = " " + q_bytes_hexstring + " "

# prv key with no network / compression information
plain_prv_keys = [
    q,
    q_bytes,
    q_bytes_hexstring,
    q_bytes_hexstring2,
]

wifcompressed = b58encode(b"\x80" + q_bytes + b"\x01")
wifcompressed_string = wifcompressed.decode("ascii")
wifcompressed_string2 = " " + wifcompressed_string + " "
wifuncompressed = b58encode(b"\x80" + q_bytes)
wifuncompressed_string = wifuncompressed.decode("ascii")
wifuncompressed_string2 = " " + wifuncompressed_string + " "

xprv_dict: BIP32KeyDict = {
    "version": b"\x04\x88\xAD\xE4",
    "depth": 0,
    "parent_fingerprint": b"\x00\x00\x00\x00",
    "index": b"\x00\x00\x00\x00",
    "chain_code": 32 * b"\x00",
    "key": b"\x00" + q_bytes,
}
xprv = _serialize(xprv_dict)
xprv_string = xprv.decode("ascii")
xprv_string2 = " " + xprv_string + " "


net_aware_compressed_prv_keys = [
    wifcompressed,
    wifcompressed_string,
    wifcompressed_string2,
    xprv,
    xprv_string,
    xprv_string2,
    xprv_dict,
]
net_aware_uncompressed_prv_keys = [
    wifuncompressed,
    wifuncompressed_string,
    wifuncompressed_string2,
]
net_unaware_compressed_prv_keys = []
net_unaware_uncompressed_prv_keys = []

compressed_prv_keys = net_aware_compressed_prv_keys + net_unaware_compressed_prv_keys
uncompressed_prv_keys = (
    net_aware_uncompressed_prv_keys + net_unaware_uncompressed_prv_keys
)

net_aware_prv_keys = net_aware_compressed_prv_keys + net_aware_uncompressed_prv_keys
net_unaware_prv_keys = (
    net_unaware_compressed_prv_keys + net_unaware_uncompressed_prv_keys
)

Q = mult(q)

plain_pub_keys = [Q]

Q_compressed = bytes_from_point(Q, compressed=True)
Q_compressed_hexstring = Q_compressed.hex()
Q_compressed_hexstring2 = " " + Q_compressed_hexstring + " "
Q_uncompressed = bytes_from_point(Q, compressed=False)
Q_uncompressed_hexstring = Q_uncompressed.hex()
Q_uncompressed_hexstring2 = " " + Q_uncompressed_hexstring + " "

xpub_dict: BIP32KeyDict = {
    "version": b"\x04\x88\xB2\x1E",
    "depth": xprv_dict["depth"],
    "parent_fingerprint": xprv_dict["parent_fingerprint"],
    "index": xprv_dict["index"],
    "chain_code": xprv_dict["chain_code"],
    "key": Q_compressed,
}
xpub = _serialize(xpub_dict)
xpub_string = xpub.decode("ascii")
xpub_string2 = " " + xpub_string + " "

net_aware_compressed_pub_keys = [
    xpub_dict,
    xpub,
    xpub_string,
    xpub_string2,
]
net_aware_uncompressed_pub_keys = []
net_unaware_compressed_pub_keys = [
    Q_compressed,
    Q_compressed_hexstring,
    Q_compressed_hexstring2,
]
net_unaware_uncompressed_pub_keys = [
    Q_uncompressed,
    Q_uncompressed_hexstring,
    Q_uncompressed_hexstring2,
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
# version / key mismatch
xprv_dict_bad = copy.copy(xpub_dict)
xprv_dict_bad["version"] = b"\x04\x88\xB2\x1E"
xpub_dict_bad = copy.copy(xprv_dict)
xpub_dict_bad["version"] = b"\x04\x88\xAD\xE4"
bad_bip32_keys = [_serialize(xprv_dict_bad), _serialize(xpub_dict_bad)]
# depth_pfp_index mismatch
# key stats with 04
# unknown version

q_0 = 0
q_0_bytes = q_0.to_bytes(32, byteorder="big")
q_0_bytes_hexstring = q_0_bytes.hex()
q_0_bytes_hexstring2 = " " + q_0_bytes_hexstring + " "

q_n = ec.n
q_n_bytes = q_n.to_bytes(32, byteorder="big")
q_n_bytes_hexstring = q_n_bytes.hex()
q_n_bytes_hexstring2 = " " + q_n_bytes_hexstring + " "

plain_inf_prv_keys = [
    q_0,
    q_0_bytes,
    q_0_bytes_hexstring,
    q_0_bytes_hexstring2,
    q_n,
    q_n_bytes,
    q_n_bytes_hexstring,
    q_n_bytes_hexstring2,
]

wif_0_compressed = b58encode(b"\x80" + q_0_bytes + b"\x01")
wif_0_compressed_string = wif_0_compressed.decode("ascii")
wif_0_compressed_string2 = " " + wif_0_compressed_string + " "
wif_0_uncompressed = b58encode(b"\x80" + q_0_bytes)
wif_0_uncompressed_string = wif_0_uncompressed.decode("ascii")
wif_0_uncompressed_string2 = " " + wif_0_uncompressed_string + " "

wif_n_compressed = b58encode(b"\x80" + q_n_bytes + b"\x01")
wif_n_compressed_string = wif_n_compressed.decode("ascii")
wif_n_compressed_string2 = " " + wif_n_compressed_string + " "
wif_n_uncompressed = b58encode(b"\x80" + q_n_bytes)
wif_n_uncompressed_string = wif_n_uncompressed.decode("ascii")
wif_n_uncompressed_string2 = " " + wif_n_uncompressed_string + " "

xprv_0_dict: BIP32KeyDict = {
    "version": b"\x04\x88\xAD\xE4",
    "depth": 0,
    "parent_fingerprint": b"\x00\x00\x00\x00",
    "index": b"\x00\x00\x00\x00",
    "chain_code": 32 * b"\x00",
    "key": b"\x00" + q_0_bytes,
}
xprv_0 = _serialize(xprv_0_dict)
xprv_0_string = xprv_0.decode("ascii")
xprv_0_string2 = " " + xprv_0_string + " "

xprv_n_dict: BIP32KeyDict = {
    "version": b"\x04\x88\xAD\xE4",
    "depth": 0,
    "parent_fingerprint": b"\x00\x00\x00\x00",
    "index": b"\x00\x00\x00\x00",
    "chain_code": 32 * b"\x00",
    "key": b"\x00" + q_n_bytes,
}
xprv_n = _serialize(xprv_n_dict)
xprv_n_string = xprv_n.decode("ascii")
xprv_n_string2 = " " + xprv_n_string + " "

net_aware_compressed_inf_prv_keys = [
    wif_0_compressed,
    wif_0_compressed_string,
    wif_0_compressed_string2,
    wif_n_compressed,
    wif_n_compressed_string,
    wif_n_compressed_string2,
    xprv_0,
    xprv_0_string,
    xprv_0_string2,
    xprv_0_dict,
    xprv_n,
    xprv_n_string,
    xprv_n_string2,
    xprv_n_dict,
]
net_aware_uncompressed_inf_prv_keys = [
    wif_0_uncompressed,
    wif_0_uncompressed_string,
    wif_0_uncompressed_string2,
    wif_n_uncompressed,
    wif_n_uncompressed_string,
    wif_n_uncompressed_string2,
]
net_unaware_compressed_inf_prv_keys = []
net_unaware_uncompressed_inf_prv_keys = []

compressed_inf_prv_keys = (
    net_aware_compressed_inf_prv_keys + net_unaware_compressed_inf_prv_keys
)
uncompressed_inf_prv_keys = (
    net_aware_uncompressed_inf_prv_keys + net_unaware_uncompressed_inf_prv_keys
)

net_aware_inf_prv_keys = (
    net_aware_compressed_inf_prv_keys + net_aware_uncompressed_inf_prv_keys
)
net_unaware_inf_prv_keys = (
    net_unaware_compressed_inf_prv_keys + net_unaware_uncompressed_inf_prv_keys
)

inf_prv_keys = (
    plain_inf_prv_keys + net_aware_inf_prv_keys + net_unaware_compressed_inf_prv_keys
)

inf_pub_keys = [
    INF,
    b"\x02" + INF[0].to_bytes(32, "big"),
    b"\x04" + INF[0].to_bytes(32, "big") + INF[1].to_bytes(32, "big"),
    # INF as WIF
    # INF as xpub
    # INF as hex-string
]

invalid_prv_keys = inf_prv_keys + [
    wifcompressed + b"\x01",
    wifcompressed_string + "01",
    wifuncompressed + b"\x01",
    wifuncompressed_string + "01",
    xprv + b"\x00",
    xprv_string + "00",
    xprv_dict["key"][1:] + b"\x00",
    xprv_dict["key"][1:].hex() + "00",
    xprv_dict["key"],
    xprv_dict["key"].hex(),
    "invalidprvkey",
]

invalid_pub_keys = inf_pub_keys + [
    "invalidpubkey",
]

not_a_prv_keys = plain_pub_keys + compressed_pub_keys + uncompressed_pub_keys
not_a_prv_keys += invalid_prv_keys + invalid_pub_keys

not_a_pub_keys = invalid_prv_keys + invalid_pub_keys

# test wrong curve and wrong network
# q in (0, ec.n)

for inv_q in (0, ec.n):
    invalid_prv_keys.append(inv_q)
    inv_q_bytes = inv_q.to_bytes(32, "big")
    t = b"\x80" + inv_q_bytes + b"\x01"
    wif = b58encode(t)
    invalid_prv_keys.append(wif)
    invalid_prv_keys.append(wif.decode("ascii"))
    t = b"\x80" + inv_q_bytes
    wif = b58encode(t)
    invalid_prv_keys.append(wif)
    invalid_prv_keys.append(wif.decode("ascii"))
    t = b"\x04\x88\xAD\xE4"
    t += b"\x00"
    t += b"\x00\x00\x00\x00"
    t += b"\x00\x00\x00\x00"
    t += 32 * b"\x00"
    t += b"\x00" + inv_q_bytes
    xprv_temp = b58encode(t, 78)
    invalid_prv_keys.append(xprv_temp)
    invalid_prv_keys.append(xprv_temp.decode("ascii"))
