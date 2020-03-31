#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Tuple, Union, Optional

from .base58 import b58decode, b58encode
from . import bip32
from .curvemult import mult
from .curves import secp256k1
from .curve import Curve
from .utils import (Octets, String, bytes_from_hexstring, octets_from_int,
                    octets_from_point)

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

def wif_from_prvkey(prv: Union[int, Octets],
                    compressed: bool = True,
                    network: str = 'mainnet') -> bytes:
    """Return the WIF encoding of a private key."""

    network_index = _NETWORKS.index(network)
    ec = _CURVES[network_index]

    payload = _WIF_PREFIXES[network_index]
    if not isinstance(prv, int):
        t = bytes_from_hexstring(prv, ec.psize)
        payload += t
        prv = int.from_bytes(t, byteorder='big')
    else:
        payload += octets_from_int(prv, ec.nsize)

    if not 0 < prv < ec.n:
        raise ValueError(f"private key {hex(prv)} not in (0, ec.n)")

    payload += b'\x01' if compressed else b''
    return b58encode(payload)


def prvkey_from_wif(wif: String) -> Tuple[int, bool, str]:
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
    elif len(payload) == ec.nsize + 1:     # uncompressed WIF
        compressed = False
        prvkey = payload[1:]
    else:
        raise ValueError(f"Wrong WIF size ({len(payload)})")

    prv = int.from_bytes(prvkey, byteorder='big')
    if not 0 < prv < ec.n:
        raise ValueError(f"Invalid private key {hex(prv)} not in [1, n-1]")

    network = _NETWORKS[wif_index]
    return prv, compressed, network


def wif_from_xprv(d: Union[bip32.XkeyDict, String]) -> bytes:
    """Return the WIF encoding of a BIP32 extended private key.

    The WIF is always of the compressed kind,
    as this is the default public key representation in BIP32.
    """

    if not isinstance(d, dict):
        d = bip32.deserialize(d)

    if d['key'][0] != 0:
        raise ValueError("xkey is not a private one")

    network = d['network']
    network_index = _NETWORKS.index(network)
    payload = _WIF_PREFIXES[network_index] + d['key'][1:] + b'\x01'
    return b58encode(payload)


def prvkey_from_xprv(d: Union[bip32.XkeyDict, String]) -> Tuple[int, bool, str]:
    """Return the (private key, compressed, network) tuple from a BIP32 xprv."""

    if not isinstance(d, dict):
        d = bip32.deserialize(d)

    if d['key'][0] != 0:
        raise ValueError("xkey is not a private one")

    network = d['network']

    return d['prvkey'], True, network


def to_prv_int(q: Union[int, bip32.XkeyDict, bytes, str],
               network: str = 'mainnet') -> Tuple[int, Optional[bool], Optional[str]]:
    """Return a private key int from any possible key representation.

    Support:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - WIF keys (bytes or string)
    - Octets (bytes or hex-string)
    - native int
    """

    network_index = _NETWORKS.index(network)
    ec = _CURVES[network_index]
    if isinstance(q, int):
        q2 = q
    else:
        try:
            prv, compressed, network = prvkey_from_xprv(q)
        except Exception:
            pass
        else:
            return prv, compressed, network

        # useless if, just to make mypy happy
        if not isinstance(q, dict):
            try:
                prv, compressed, network = prvkey_from_wif(q)
            except Exception:
                pass
            else:
                return prv, compressed, network

        try:
            q = bytes_from_hexstring(q, ec.nsize)
            q2 = int.from_bytes(q, 'big')
        except Exception:
            raise ValueError("not a private key")

    if not 0 < q2 < ec.n:
        raise ValueError(f"private key {hex(q2)} not in [1, n-1]")

    return q2, None, None

# helper function

def _pubkey_from_wif(wif: String) -> Tuple[bytes, str]:

    prv, compressed, network = prvkey_from_wif(wif)
    network_index = _NETWORKS.index(network)
    ec = _CURVES[network_index]
    Pub = mult(prv, ec.G, ec)
    o = octets_from_point(Pub, compressed, ec)
    return o, network
