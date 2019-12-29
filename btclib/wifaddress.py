#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Wallet Import Format (WIF) and Address functions.

Implementation of Base58 encoding of private keys (WIFs)
and public keys (addresses).
"""

from typing import Tuple

from . import base58
from .curve import Point, mult
from .curves import secp256k1 as ec
from .utils import Octets, int_from_octets, octets_from_int, \
    octets_from_point, h160


def wif_from_prvkey(prvkey: int,
                    compressed: bool = True,
                    testnet: bool = False) -> bytes:
    """Return the Wallet Import Format from a private key."""

    if not 0 < prvkey < ec.n:
        raise ValueError(f"private key {hex(prvkey)} not in (0, n)")

    payload = b'\xEF' if testnet else b'\x80'
    payload += octets_from_int(prvkey, ec.nsize)
    if compressed:
        payload += b'\x01'
    return base58.encode_check(payload)


def prvkey_from_wif(wif: Octets) -> Tuple[int, bool, bool]:
    """Return the (private key, compressed, testnet) tuple from a WIF."""

    payload = base58.decode_check(wif)

    if payload[0] == 0x80:
        testnet = False
    elif payload[0] == 0xEF:
        testnet = True
    else:
        msg = "Not a testnet/mainnet private key WIF"
        raise ValueError(msg)

    if len(payload) == ec.nsize + 2:       # compressed WIF
        compressed = True
        if payload[-1] != 0x01:            # must have a trailing 0x01
            raise ValueError("Not a compressed WIF: missing trailing 0x01")
        prvkey = int_from_octets(payload[1:-1])
    elif len(payload) == ec.nsize + 1:     # uncompressed WIF
        compressed = False
        prvkey = int_from_octets(payload[1:])
    else:
        raise ValueError(f"Not a WIF: wrong size ({len(payload)})")
    
    if not 0 < prvkey < ec.n:
        msg = f"Not a WIF: private key {hex(prvkey)} not in [1, n-1]"
        raise ValueError(msg)

    return prvkey, compressed, testnet


def h160_from_pubkey(Q: Point, compressed: bool = True) -> bytes:
    """Return the H160(Q)=RIPEMD160(SHA256(Q)) of a public key Q."""

    # also check that the Point is on curve
    pubkey = octets_from_point(ec, Q, compressed)
    return h160(pubkey)


def p2pkh_address(Q: Point,
                  compressed: bool = True,
                  testnet: bool = False) -> bytes:
    """Return the p2pkh address corresponding to a public key."""

    # results in the leading char being 'm' or 'n' if testnet else '1'
    version = b'\x6F' if testnet else b'\x00'
    vh160 = version + h160_from_pubkey(Q, compressed)
    return base58.encode_check(vh160)


def _h160_from_p2pkh_address(addr: Octets) -> bytes:
    payload = base58.decode_check(addr, 21)
    if payload[0] not in {0x6F, 0x00}:
        raise ValueError("not a testnet/mainnet address")
    return payload[1:]


def p2pkh_address_from_wif(wif: Octets) -> bytes:
    """Return the address corresponding to a WIF."""

    prv, compressed, testnet = prvkey_from_wif(wif)
    pub = mult(ec, prv)
    return p2pkh_address(pub, compressed, testnet)
