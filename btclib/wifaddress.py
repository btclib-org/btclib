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

from btclib.base58 import b58encode_check, b58decode_check
from btclib.ec import octets, octets2int, int2octets, point2octets, Tuple, \
    secp256k1 as ec, Point, pointMult


def wif_from_prvkey(prvkey: int, compressed: bool) -> bytes:
    """private key to Wallet Import Format"""

    payload = b'\x80' + int2octets(ec, prvkey)
    if compressed:
        payload += b'\x01'
    return b58encode_check(payload)


def prvkey_from_wif(wif: octets) -> Tuple[int, bool]:
    """Wallet Import Format to (bytes) private key"""

    payload = b58decode_check(wif)
    assert payload[0] == 0x80, "not a WIF"

    if len(payload) == ec.bytesize + 2:   # compressed WIF
        # must have a trailing 0x01
        assert payload[ec.bytesize + 1] == 0x01, "not a WIF"
        return octets2int(payload[1:-1]), True
    elif len(payload) == ec.bytesize + 1:  # uncompressed WIF
        return octets2int(payload[1:]), False

    raise ValueError("not a WIF")

def h160(pubkey: bytes) -> bytes:
    t = sha256(pubkey).digest()
    return hnew('ripemd160', t).digest()


def address_from_pubkey(Q: Point, compressed: bool, version: bytes = b'\x00') -> bytes:
    """Public key to (bytes) address"""
    pubkey = point2octets(ec, Q, compressed)
    # FIXME: this is mainnet only
    vh160 = version + h160(pubkey)
    return b58encode_check(vh160)


def hash160_from_address(addr: octets) -> bytes:
    payload = b58decode_check(addr, 21)
    # FIXME: this is mainnet only
    assert payload[0] == 0x00, "not an address"
    return payload[1:]

def address_from_wif(wif: octets) -> bytes:
    prv, compressed = prvkey_from_wif(wif)
    pub = pointMult(ec, prv, ec.G)
    return address_from_pubkey(pub, compressed)
