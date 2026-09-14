# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The spellings of one key pair, built once and shared.

`tests/ecc/dsa_test.py` and `tests/hashes_test.py` read them. Both ask
the same kind of question of a public API -- which spellings it takes and
which it refuses -- so the scalar, its hex, the point and the two SEC
forms are built here rather than twice.

The WIF and the xprv are here for the refusals alone: `ecc` takes a
scalar and a point, and a spelling that carries a network is read where
its format is defined -- a WIF by `b58`, an xprv by `bip32` (issue
#1188).
"""

from __future__ import annotations

from btclib.base58 import encode as b58encode
from btclib.bip32 import BIP32KeyData
from btclib.curves import mult

q = 12
q_bytes = q.to_bytes(32, byteorder="big", signed=False)
q_hexstring = q_bytes.hex()
q_hexstring2 = " " + q_hexstring + " "

# the private-key spellings a curve reads: the scalar's octets and their
# hex, naming neither a network nor a compression
plain_prv_keys: list[bytes | str] = [
    q_hexstring,
    q_hexstring2,
]

wif_compressed = b58encode(b"\x80" + q_bytes + b"\x01")
wif_compressed_string = wif_compressed.decode("ascii")
wif_uncompressed = b58encode(b"\x80" + q_bytes)
wif_uncompressed_string = wif_uncompressed.decode("ascii")

xprv_data = BIP32KeyData(
    version=bytes.fromhex("04 88 ad e4"),
    depth=0,
    parent_fingerprint=bytes.fromhex("00000000"),
    index=0,
    chain_code=32 * b"\x00",
    key=b"\x00" + q_bytes,
)
xprv_string = xprv_data.b58encode(check_validity=False)

Q = mult(q)

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

# an xpub is the only public spelling that names a network, and it is
# `bip32.pub_keyinfo_from_xpub`'s to read (issue #1188), so every family
# here is network-unaware
net_unaware_compressed_pub_keys: list[bytes | str] = [
    Q_compressed_hexstring,
    Q_compressed_hexstring2,
    Q_compressed_hexstring3,
]
net_unaware_uncompressed_pub_keys: list[bytes | str] = [
    Q_uncompressed_hexstring,
    Q_uncompressed_hexstring2,
    Q_uncompressed_hexstring3,
]
