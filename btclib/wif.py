#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Tuple, Union

from . import base58
from . import bech32

from .curve import mult
from .curves import secp256k1
from .utils import Octets, int_from_octets, octets_from_int, \
    octets_from_point, h160

from .segwitaddress import p2wpkh_address, p2wpkh_p2sh_address
from .wifaddress import prvkey_from_wif

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

def pubkey_from_wif(wif: Union[str, bytes]) -> Tuple[bytes, str]:

    if isinstance(wif, str):
        wif = wif.strip()

    prv, compressed, network = prvkey_from_wif(wif)
    network_index = _NETWORKS.index(network)
    ec = _CURVES[network_index]
    Pub = mult(ec, prv)
    o = octets_from_point(ec, Pub, compressed)
    return o, network

def p2wpkh_address_from_wif(wif: Union[str, bytes]) -> bytes:
    o, network = pubkey_from_wif(wif)
    return p2wpkh_address(o, network)

def p2wpkh_p2sh_address_from_wif(wif: Union[str, bytes]) -> bytes:
    o, network = pubkey_from_wif(wif)
    return p2wpkh_p2sh_address(o, network)
