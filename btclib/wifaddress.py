#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

'''wifs and addresses

Implementation of Base58 encoding of private keys (wifs)
and public keys (addresses)
'''

from hashlib import sha256, new as hnew
from typing import Tuple

from btclib import base58
from btclib.curve import Point, mult
from btclib.curves import secp256k1 as ec
from btclib.utils import octets, int_from_octets, octets_from_int, octets_from_point


def wif_from_prvkey(prvkey: int, compressed: bool) -> bytes:
    """private key to Wallet Import Format"""

    if not 0 < prvkey < ec.n:
        raise ValueError(f"private key {hex(prvkey)} not in (0, n)")

    payload = b'\x80' + octets_from_int(prvkey, ec.psize)
    if compressed:
        payload += b'\x01'
    return base58.encode_check(payload)


def prvkey_from_wif(wif: octets) -> Tuple[int, bool]:
    """Wallet Import Format to (bytes) private key"""

    payload = base58.decode_check(wif)
    if payload[0] != 0x80:
        raise ValueError("Not a private key WIF: missing leading 0x80")

    if len(payload) == ec.psize + 2:       # compressed WIF
        compressed = True
        if payload[ec.psize + 1] != 0x01:  # must have a trailing 0x01
            raise ValueError("Not a compressed WIF: missing trailing 0x01")
        prvkey = int_from_octets(payload[1:-1])
    elif len(payload) == ec.psize + 1:     # uncompressed WIF
        compressed = False
        prvkey = int_from_octets(payload[1:])
    else:
        raise ValueError(f"Not a WIF: wrong size ({len(payload)})")
    
    if not 0 < prvkey < ec.n:
        raise ValueError(f"Not a WIF: private key {hex(prvkey)} not in (0, n)")

    return prvkey, compressed


def _h160(pubkey: bytes) -> bytes:
    t = sha256(pubkey).digest()
    return hnew('ripemd160', t).digest()


def address_from_pubkey(Q: Point, compressed: bool, version: bytes = b'\x00') -> bytes:
    """Public key to (bytes) address"""

    # also check that the Point is on curve
    pubkey = octets_from_point(ec, Q, compressed)

    # FIXME: this is mainnet only
    vh160 = version + _h160(pubkey)
    return base58.encode_check(vh160)


def _h160_from_address(addr: octets) -> bytes:
    payload = base58.decode_check(addr, 21)
    # FIXME: this is mainnet only
    if payload[0] != 0x00:
        raise ValueError("not a mainnet address")
    return payload[1:]


def address_from_wif(wif: octets) -> bytes:
    prv, compressed = prvkey_from_wif(wif)
    pub = mult(ec, prv, ec.G)
    return address_from_pubkey(pub, compressed)
