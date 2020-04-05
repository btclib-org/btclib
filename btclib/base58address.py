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

from .alias import Octets, PubKey, String, XkeyDict
from .base58 import b58decode, b58encode
from .base58wif import _pubkeytuple_from_wif
from .bip32 import deserialize
from .network import _CURVES, _NETWORKS, _P2PKH_PREFIXES, _P2SH_PREFIXES
from .to_pubkey import to_pub_bytes
from .utils import bytes_from_octets, hash160, sha256


def b58address_from_h160(prefix: bytes, h160: Octets) -> bytes:

    if prefix not in _P2PKH_PREFIXES + _P2SH_PREFIXES:
        raise ValueError(f"Invalid base58 address prefix {prefix!r}")
    payload = prefix + bytes_from_octets(h160, 20)
    return b58encode(payload)


def h160_from_b58address(b58addr: String) -> Tuple[bytes, bytes, str, bool]:

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


def p2pkh(pubkey: PubKey, compressed: bool, network: str = 'mainnet') -> bytes:
    """Return the p2pkh address corresponding to a public key."""

    network_index = _NETWORKS.index(network)
    prefix = _P2PKH_PREFIXES[_NETWORKS.index(network)]

    ec = _CURVES[network_index]
    pubkey = to_pub_bytes(pubkey, compressed, ec)
    h160 = hash160(pubkey)

    return b58address_from_h160(prefix, h160)


def p2pkh_from_wif(wif: String) -> bytes:
    """Return the p2pkh address corresponding to a WIF.

    WIF encodes the information about which pubkey
    (compressed/uncompressed) to use for the address.
    """

    pubkey, compressed, network = _pubkeytuple_from_wif(wif)
    return p2pkh(pubkey, compressed, network)


def p2pkh_from_xpub(d: Union[XkeyDict, String]) -> bytes:
    """Return the p2pkh address."""
    if not isinstance(d, dict):
        d = deserialize(d)

    if d['key'][0] not in (2, 3):
        # if pubkey would be derived from prvkey,
        # then this safety check might be removed
        raise ValueError("xkey is not a public one")
    return p2pkh(d['key'], True, d['network'])


def p2sh(script: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2sh address corresponding to a script."""

    network_index = _NETWORKS.index(network)
    prefix = _P2SH_PREFIXES[_NETWORKS.index(network)]

    h160 = hash160(script)

    return b58address_from_h160(prefix, h160)


# (p2sh-wrapped) base58 legacy SegWit addresses


def _b58segwitaddress(wp: Octets, network: str) -> bytes:

    wp = bytes_from_octets(wp)
    length = len(wp)
    if length in (20, 32):
        # [wv,          wp]
        # [ 0,    key_hash] : 0x0014{20-byte key-hash}
        # [ 0, script_hash] : 0x0020{32-byte key-script_hash}
        script_pubkey = b'\x00' + length.to_bytes(1, 'big') + wp
        return p2sh(script_pubkey, network)

    m = f"Invalid witness program length ({len(wp)})"
    raise ValueError(m)


def p2wpkh_p2sh(pubkey: PubKey, network: str = 'mainnet') -> bytes:
    """Return the p2wpkh-p2sh (base58 legacy) Segwit address."""
    network_index = _NETWORKS.index(network)
    ec = _CURVES[network_index]
    pubkey = to_pub_bytes(pubkey, True, ec)
    h160 = hash160(pubkey)
    return _b58segwitaddress(h160, network)


def p2wpkh_p2sh_from_wif(wif: String) -> bytes:
    """Return the p2wpkh-p2sh (base58 legacy) Segwit address."""
    pubkey, compressed, network = _pubkeytuple_from_wif(wif)
    if not compressed:
        raise ValueError ("No p2wpkh-p2sh from compressed wif")
    return p2wpkh_p2sh(pubkey, network)


def p2wpkh_p2sh_from_xpub(d: Union[XkeyDict, String]) -> bytes:
    """Return the p2wpkh-p2sh (base58 legacy) Segwit address."""
    if not isinstance(d, dict):
        d = deserialize(d)

    if d['key'][0] not in (2, 3):
        # if pubkey would be derived from prvkey,
        # then this safety check might be removed
        raise ValueError("xkey is not a public one")
    return p2wpkh_p2sh(d['key'], d['network'])


def p2wsh_p2sh(wscript: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2wsh-p2sh (base58 legacy) SegWit address."""
    h256 = sha256(wscript)
    return _b58segwitaddress(h256, network)
