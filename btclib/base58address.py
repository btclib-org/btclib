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
from .utils import (Octets, bytes_from_hexstring, h160_from_pubkey, hash160,
                    sha256)

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


def b58address_from_h160(prefix_list: List[bytes], h160: Octets, network: str = 'mainnet') -> bytes:

    payload = prefix_list[_NETWORKS.index(network)]
    payload += bytes_from_hexstring(h160, 20)
    return b58encode(payload)


def h160_from_b58address(b58addr: Union[bytes, str]) -> Tuple[bytes, bytes, str, bool]:

    if isinstance(b58addr, str):
        b58addr = b58addr.strip()
    payload = b58decode(b58addr, 21)
    prefix = payload[0:1]
    if prefix in _P2PKH_PREFIXES:
        i = _P2PKH_PREFIXES.index(prefix)
        is_script_hash = False
    elif prefix in _P2SH_PREFIXES:
        i = _P2SH_PREFIXES.index(prefix)
        is_script_hash = True
    else:
        raise ValueError(f"Invalid base58 address prefix {prefix!r}")

    return prefix, payload[1:], _NETWORKS[i], is_script_hash


def p2pkh_address(pubkey: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2pkh address corresponding to a public key."""

    compressed_only = False
    h160 = h160_from_pubkey(pubkey, compressed_only)
    return b58address_from_h160(_P2PKH_PREFIXES, h160, network)


def p2sh_address(script: Octets, network: str = 'mainnet') -> bytes:
    """Return p2sh address."""

    h160 = hash160(script)
    return b58address_from_h160(_P2SH_PREFIXES, h160, network)


# (p2sh-wrapped) base58 legacy SegWit addresses


def b58address_from_witness(wp: Octets, network: str = 'mainnet') -> bytes:
    """Encode a base58 legacy (p2sh-wrapped) SegWit address."""

    wp = bytes_from_hexstring(wp)
    length = len(wp)
    if length in (20, 32):
        # [wv,          wp]
        # [ 0,    key_hash] : 0x0014{20-byte key-hash}
        # [ 0, script_hash] : 0x0020{32-byte key-script_hash}
        script_pubkey = b'\x00' + length.to_bytes(1, 'big') + wp
        return p2sh_address(script_pubkey, network)

    m = f"Invalid witness program length ({len(wp)})"
    raise ValueError(m)


def witness_from_b58address(b58addr: Union[bytes, str]) -> Tuple[int, bytes, str, bool]:
    """Decode a base58 legacy (p2sh-wrapped) SegWit address."""

    _, wp, network, is_script_hash = h160_from_b58address(b58addr)

    return 0, wp, network, is_script_hash


def p2wpkh_p2sh_address(pubkey: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2wpkh-p2sh (base58 legacy) Segwit address."""
    h160 = h160_from_pubkey(pubkey)
    return b58address_from_witness(h160, network)


def p2wsh_p2sh_address(wscript: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2wsh-p2sh (base58 legacy) SegWit address."""
    h256 = sha256(wscript)
    return b58address_from_witness(h256, network)
