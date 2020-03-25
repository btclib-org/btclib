#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Base58 address functions.

Base58 encoding of public keys and scripts as addresses.
"""

from typing import List, Tuple, Union

from .base58 import b58decode, b58encode
from .script import Script, Token
from .utils import (Octets, bytes_from_hexstring, hash160, int_from_octets,
                    octets_from_point)

_NETWORKS = ['mainnet', 'testnet', 'regtest']
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


def _p2pkh_address(h160: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2pkh address corresponding to a public key."""

    h160 = bytes_from_hexstring(h160)
    payload = _P2PKH_PREFIXES[_NETWORKS.index(network)]
    payload += h160
    return b58encode(payload)


def p2pkh_address(pubkey: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2pkh address corresponding to a public key."""

    pubkey = bytes_from_hexstring(pubkey)
    if len(pubkey) not in (33, 65):
        raise ValueError(f"Invalid SEC pubkey length: {len(pubkey)}-bytes")
    h160 = hash160(pubkey)
    return _p2pkh_address(h160, network)


def _p2sh_address(h160: Octets, network: str = 'mainnet') -> bytes:
    """Return p2sh address."""

    h160 = bytes_from_hexstring(h160)
    payload = _P2SH_PREFIXES[_NETWORKS.index(network)]
    payload += h160
    return b58encode(payload)

def p2sh_address(script: Octets, network: str = 'mainnet') -> bytes:
    """Return p2sh address."""

    h160 = hash160(script)
    return _p2sh_address(h160, network)


def h160_from_base58_address(address: Union[str, bytes]) -> Tuple[str, bool, bytes]:

    if isinstance(address, str):
        address = address.strip()
    payload = b58decode(address, 21)
    prefix = payload[0:1]
    if prefix in _P2PKH_PREFIXES:
        i = _P2PKH_PREFIXES.index(prefix)
        is_script_hash = False
    elif prefix in _P2SH_PREFIXES:
        i = _P2SH_PREFIXES.index(prefix)
        is_script_hash = True
    else:
        raise ValueError(f"Invalid base58 address prefix {prefix!r}")

    return _NETWORKS[i], is_script_hash, payload[1:]
