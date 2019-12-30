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
from . import segwitaddr
from .curve import Point, mult
from .curves import secp256k1 as ec
from .utils import Octets, int_from_octets, octets_from_int, \
    octets_from_point, h160

_NETWORKS = ['mainnet', 'testnet', 'regtest']
_WIF_PREFIXES = [
    b'\x80',  # WIF starts with {K,L} (if compressed) or 5 (if uncompressed)
    b'\xef',  # WIF starts with c (if compressed) or 9 (if uncompressed)
    b'\xef',  # WIF starts with c (if compressed) or 9 (if uncompressed)
]
_P2PKH_PREFIXES = [
    b'\x00',  # address starts with 1
    b'\x6f',  # address starts with {m, n}
    b'\x6f'   # address starts with {m, n}
]
_P2SH_PREFIXES = [
    b'\x05',  # address starts with 3
    b'\xc4',  # address starts with 2
    b'\xc4',  # address starts with 2
]
_P2WPKH_PREFIXES = [
    'bc',  # address starts with 3
    'tb',  # address starts with 2
    'bcrt',  # address starts with 2
]

def wif_from_prvkey(prvkey: int,
                    compressed: bool = True,
                    network: str = 'mainnet') -> bytes:
    """Return the Wallet Import Format from a private key."""

    if not 0 < prvkey < ec.n:
        raise ValueError(f"private key {hex(prvkey)} not in (0, n)")

    payload = _WIF_PREFIXES[_NETWORKS.index(network)]
    payload += octets_from_int(prvkey, ec.nsize)
    if compressed:
        payload += b'\x01'
    return base58.encode(payload)


def prvkey_from_wif(wif: Octets) -> Tuple[int, bool, str]:
    """Return the (private key, compressed, network) tuple from a WIF."""

    payload = base58.decode(wif)
    network = _NETWORKS[_WIF_PREFIXES.index(payload[0:1])]

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

    return prvkey, compressed, network


def h160_from_pubkey(Q: Point, compressed: bool = True) -> bytes:
    """Return the H160(Q)=RIPEMD160(SHA256(Q)) of a public key Q."""

    # also check that the Point is on curve
    pubkey = octets_from_point(ec, Q, compressed)
    return h160(pubkey)


def p2pkh_address(Q: Point,
                  compressed: bool = True,
                  network: str = 'mainnet') -> bytes:
    """Return the p2pkh address corresponding to a public key."""

    payload = _P2PKH_PREFIXES[_NETWORKS.index(network)]
    payload += h160_from_pubkey(Q, compressed)
    return base58.encode(payload)


def _h160_from_p2pkh_address(addr: Octets) -> bytes:
    payload = base58.decode(addr, 21)
    _ = _NETWORKS[_P2PKH_PREFIXES.index(payload[0:1])]
    return payload[1:]


def p2pkh_address_from_wif(wif: Octets) -> bytes:
    """Return the address corresponding to a WIF."""

    prv, compressed, network = prvkey_from_wif(wif)
    Pub = mult(ec, prv)
    return p2pkh_address(Pub, compressed, network)


def p2sh_address(script_pubkey: bytes,
                 network: str = 'mainnet') -> bytes:
    """Return p2sh address."""

    payload = _P2SH_PREFIXES[_NETWORKS.index(network)]
    payload += h160(script_pubkey)
    return base58.encode(payload)


def p2wpkh_p2sh_address(Q: Point,
                        network: str = 'mainnet') -> bytes:
    """Return SegWit p2wpkh nested in p2sh address."""

    witness_version = 0
    compressed = True
    witness_program = h160_from_pubkey(Q, compressed)
    script_pubkey = segwitaddr.scriptpubkey(witness_version, witness_program)
    return p2sh_address(script_pubkey, network)

def p2wpkh_address(Q: Point,
                   network: str = 'mainnet') -> str:
    """Return native SegWit Bech32 p2wpkh address."""

    hrp = _P2WPKH_PREFIXES[_NETWORKS.index(network)]
    witness_version = 0
    compressed = True
    witness_program = h160_from_pubkey(Q, compressed)
    return segwitaddr.encode(hrp, witness_version, witness_program)
