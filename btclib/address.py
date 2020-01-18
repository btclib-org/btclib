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

from typing import Tuple, Union

from . import base58
from .utils import Octets, int_from_octets, octets_from_int, \
    octets_from_point, h160

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


def p2pkh_address(pubkey: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2pkh address corresponding to a public key."""

    payload = _P2PKH_PREFIXES[_NETWORKS.index(network)]
    payload += h160(pubkey)
    return base58.encode(payload)


def p2sh_address(redeem_script: Octets, network: str = 'mainnet') -> bytes:
    """Return p2sh address."""

    payload = _P2SH_PREFIXES[_NETWORKS.index(network)]
    payload += h160(redeem_script)
    return base58.encode(payload)


def h160_from_base58_address(address: Union[str, bytes]) -> Tuple[str, bool, bytes]:
    if isinstance(address, str):
        address = address.strip()

    payload = base58.decode(address, 21)
    prefix = payload[0:1]
    if prefix in _P2PKH_PREFIXES:
        i = _P2PKH_PREFIXES.index(prefix)
        is_p2sh = False
    elif prefix in _P2SH_PREFIXES:
        i = _P2SH_PREFIXES.index(prefix)
        is_p2sh = True
    else:
        raise ValueError(f"Invalid base58 address prefix {prefix}")

    return _NETWORKS[i], is_p2sh, payload[1:]
