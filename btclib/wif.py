#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Tuple, Union

from .address import p2pkh_address
from .base58 import b58decode, b58encode
from .curvemult import mult
from .curves import secp256k1
from .segwitaddress import p2wpkh_address, p2wpkh_p2sh_address
from .utils import (Octets, bytes_from_hexstring, int_from_octets,
                    octets_from_int, octets_from_point)

_NETWORKS = ['mainnet', 'testnet', 'regtest']
_CURVES = [secp256k1, secp256k1, secp256k1]
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

# Private key base58 encoding, as bytes or string.
# Note that WIF is more than just the private key,
# as it carries the information about which public key
# (compressed/uncompressed) is to be used in address derivation
WIF = Union[bytes, str]

def wif_from_prvkey(prv: Union[int, Octets],
                    compressed: bool = True,
                    network: str = 'mainnet') -> bytes:
    """Return the Wallet Import Format from a private key."""

    network_index = _NETWORKS.index(network)
    payload = _WIF_PREFIXES[network_index]

    ec = _CURVES[network_index]
    prv = bytes_from_hexstring(prv)

    if isinstance(prv, bytes):
        if len(prv) != 32:  # TODO: parametrize on ec
            raise ValueError(f"not a 32-bytes private key: {prv.hex()}")
        prv = int.from_bytes(prv, byteorder='big')
    if not 0 < prv < ec.n:
        raise ValueError(f"private key {hex(prv)} not in (0, ec.n)")

    payload += octets_from_int(prv, ec.nsize)
    payload += b'\x01' if compressed else b''
    return b58encode(payload)


def prvkey_from_wif(wif: Union[bytes, str]) -> Tuple[int, bool, str]:
    """Return the (private key, compressed, network) tuple from a WIF."""

    if isinstance(wif, str):
        wif = wif.strip()

    payload = b58decode(wif)
    wif_index = _WIF_PREFIXES.index(payload[0:1])
    ec = _CURVES[wif_index]

    if len(payload) == ec.nsize + 2:       # compressed WIF
        compressed = True
        if payload[-1] != 0x01:            # must have a trailing 0x01
            raise ValueError("Not a compressed WIF: missing trailing 0x01")
        prvkey = payload[1:-1]
        prv = int_from_octets(prvkey)
    elif len(payload) == ec.nsize + 1:     # uncompressed WIF
        compressed = False
        prvkey = payload[1:]
        prv = int_from_octets(prvkey)
    else:
        raise ValueError(f"Not a WIF: wrong size ({len(payload)})")

    if not 0 < prv < ec.n:
        msg = f"Not a WIF: private key {hex(prv)} not in [1, n-1]"
        raise ValueError(msg)

    network = _NETWORKS[wif_index]
    return prv, compressed, network


def _pubkey_from_wif(wif: Union[bytes, str]) -> Tuple[bytes, str]:

    prv, compressed, network = prvkey_from_wif(wif)
    network_index = _NETWORKS.index(network)
    ec = _CURVES[network_index]
    Pub = mult(prv, ec.G, ec)
    o = octets_from_point(Pub, compressed, ec)
    return o, network


def p2pkh_address_from_wif(wif: Union[bytes, str]) -> bytes:
    """Return the address corresponding to a WIF.

    WIF encodes the information about the pubkey to be used for the
    address computation being the compressed or uncompressed one.
    """

    prv, compressed, network = prvkey_from_wif(wif)
    network_index = _NETWORKS.index(network)
    ec = _CURVES[network_index]
    Pub = mult(prv, ec.G, ec)
    o = octets_from_point(Pub, compressed, ec)
    return p2pkh_address(o, network)


def p2wpkh_address_from_wif(wif: Union[bytes, str]) -> bytes:
    o, network = _pubkey_from_wif(wif)
    return p2wpkh_address(o, network)


def p2wpkh_p2sh_address_from_wif(wif: Union[bytes, str]) -> bytes:
    o, network = _pubkey_from_wif(wif)
    return p2wpkh_p2sh_address(o, network)
