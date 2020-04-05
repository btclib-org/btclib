#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Optional, Tuple, TypedDict, Union

from . import bip32
from .alias import Octets, String, XkeyDict
from .base58 import b58decode, b58encode
from .curve import Curve
from .curvemult import mult
from .curves import secp256k1
from .network import (_CURVES, _NETWORKS, _P2PKH_PREFIXES, _P2SH_PREFIXES,
                      _WIF_PREFIXES)
from .utils import bytes_from_octets, bytes_from_point


def wif_from_xprv(xkey: Union[XkeyDict, String]) -> bytes:
    """Return the WIF encoding of a BIP32 extended private key.

    The WIF is always of the compressed kind,
    as this is the default public key representation in BIP32.
    """

    # the next few lines of code could be replaced by prvkeytuple_from_xprv
    # but the last few lines of code need intermediate results
    if not isinstance(xkey, dict):
        xkey = bip32.deserialize(xkey)

    if xkey['key'][0] != 0:
        raise ValueError("xkey is not a private one")

    network = xkey['network']
    network_index = _NETWORKS.index(network)
    payload = _WIF_PREFIXES[network_index] + xkey['key'][1:] + b'\x01'
    return b58encode(payload)


def wif_from_prvkey(prvkey: Union[int, Octets],
                    compressed: bool = True,
                    network: str = 'mainnet') -> bytes:
    """Return the WIF encoding of a private key."""

    network_index = _NETWORKS.index(network)
    ec = _CURVES[network_index]

    payload = _WIF_PREFIXES[network_index]
    if not isinstance(prvkey, int):
        prvkey = bytes_from_octets(prvkey, ec.nsize)
        payload += prvkey
        q = int.from_bytes(prvkey, byteorder='big')
    else:
        payload += prvkey.to_bytes(ec.nsize, 'big')
        q = prvkey

    if not 0 < q < ec.n:
        raise ValueError(f"private key {hex(q)} not in (0, ec.n)")

    payload += b'\x01' if compressed else b''
    return b58encode(payload)


def prvkeytuple_from_xprvwif(xkeywif: Union[XkeyDict, String],
                             network: str = 'mainnet') -> Tuple[int, Optional[bool], Optional[str]]:
    """Return a verified-as-valid private key tuple (prvkey, compressed, network).

    Support WIF or BIP32 xkey.
    """

    if not isinstance(xkeywif, dict):
        try:
            return prvkeytuple_from_wif(xkeywif)
        except Exception:
            pass

    return prvkeytuple_from_xprv(xkeywif)


def prvkeytuple_from_wif(wif: String) -> Tuple[int, bool, str]:
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

    q = int.from_bytes(prvkey, byteorder='big')
    if not 0 < q < ec.n:
        raise ValueError(f"Private key {hex(q)} not in [1, n-1]")

    network = _NETWORKS[wif_index]
    return q, compressed, network


def prvkeytuple_from_xprv(xkey: Union[XkeyDict, String]) -> Tuple[int, bool, str]:
    """Return the (private key, compressed, network) tuple from a BIP32 xprv."""

    if not isinstance(xkey, dict):
        xkey = bip32.deserialize(xkey)

    if xkey['key'][0] != 0:
        raise ValueError("xkey is not a private one")

    network = xkey['network']

    return xkey['q'], True, network


# helper function


def _pubkeytuple_from_wif(wif: String) -> Tuple[bytes, bool, str]:

    prvkey, compressed, network = prvkeytuple_from_wif(wif)
    network_index = _NETWORKS.index(network)
    ec = _CURVES[network_index]
    Pub = mult(prvkey, ec.G, ec)
    pubkey = bytes_from_point(Pub, compressed, ec)
    return pubkey, compressed, network
