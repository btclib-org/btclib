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


def _h160_from_address(address: Union[str, bytes]) -> Tuple[bytes, bytes]:
    if isinstance(address, str):
        address = address.strip()

    payload = base58.decode(address, 21)
    if payload[0:1] not in _P2PKH_PREFIXES + _P2SH_PREFIXES:
        raise ValueError("Invalid base58 address prefix")
    return payload[0:1], payload[1:]


def h160_from_p2pkh_address(address: Union[str, bytes],
                            network: str = 'mainnet') -> bytes:
    prefix, hash160 = _h160_from_address(address)

    # check that it is a p2pkh address
    i = _P2PKH_PREFIXES.index(prefix)
    # check that it is a p2pkh address for the given network
    if _NETWORKS[i] != network:
        msg = f"{address} is a p2pkh address for '{_NETWORKS[i]}', "
        msg += f"not '{network}'"
        raise ValueError(msg)
    return hash160


def h160_from_p2sh_address(address: Union[str, bytes],
                           network: str = 'mainnet') -> bytes:

    prefix, hash160 = _h160_from_address(address)

    # check that it is a p2sh address
    i = _P2SH_PREFIXES.index(prefix)
    # check that it is a p2sh address for the given network
    if _NETWORKS[i] != network:
        msg = f"{address} is a p2sh address for '{_NETWORKS[i]}', "
        msg += f"not '{network}'"
        raise ValueError(msg)
    return hash160
