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

from typing import List, Optional, Tuple

from .alias import Octets, PubKey, Script, String
from .base58 import b58decode, b58encode
from .network import (_P2PKH_PREFIXES, _P2SH_PREFIXES,
                      network_from_p2pkh_prefix, network_from_p2sh_prefix,
                      p2pkh_prefix_from_network, p2sh_prefix_from_network)
from .script import encode
from .to_pubkey import bytes_from_pubkey
from .utils import bytes_from_octets, hash160, sha256

# 1. Hash/WitnessProgram from pubkey/script

def h160_from_pubkey(pubkey: PubKey, compressed: Optional[bool] = None,
                     network: Optional[str] = None) -> Tuple[bytes, str]:
    pubkey, network = bytes_from_pubkey(pubkey, compressed, network)
    h160 = hash160(pubkey)
    return h160, network


def h160_from_script(script: Script) -> bytes:
    if isinstance(script, list):
        script = encode(script)
    h160 = hash160(script)
    return h160


def h256_from_script(script: Script) -> bytes:
    if isinstance(script, list):
        script = encode(script)
    h256 = sha256(script)
    return h256

# 2. base58 address from HASH and vice versa

# TODO accept Octets prefix
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
        network = network_from_p2pkh_prefix(prefix)
        is_script_hash = False
    elif prefix in _P2SH_PREFIXES:
        network = network_from_p2sh_prefix(prefix)
        is_script_hash = True
    else:
        raise ValueError(f"Invalid base58 address prefix {prefix!r}")

    return prefix, payload[1:], network, is_script_hash

# 1.+2. = 3. base58 address from pubkey/script

def p2pkh(pubkey: PubKey, compressed: Optional[bool] = None,
          network: Optional[str] = None) -> bytes:
    "Return the p2pkh address corresponding to a public key."
    h160, network = h160_from_pubkey(pubkey, compressed, network)
    prefix = p2pkh_prefix_from_network(network)
    return b58address_from_h160(prefix, h160)


def p2sh(script: Script, network: str = 'mainnet') -> bytes:
    "Return the p2sh address corresponding to a script."
    h160 = h160_from_script(script)
    prefix = p2sh_prefix_from_network(network)
    return b58address_from_h160(prefix, h160)

# 2b. base58 address from WitnessProgram and vice versa (TODO)

def b58address_from_witness(witprog: Octets, network: str) -> bytes:
    witver = b'\x00'
    witprog = bytes_from_octets(witprog)
    length = len(witprog)
    if length in (20, 32):
        # [wv,     witprog]
        # [ 0,    key_hash] : 0x0014{20-byte key-hash}
        # [ 0, script_hash] : 0x0020{32-byte key-script_hash}
        script_pubkey = witver + length.to_bytes(1, 'big') + witprog
        return p2sh(script_pubkey, network)

    m = f"Invalid witness program length ({len(witprog)})"
    raise ValueError(m)

# 1.+2b. = 3b. base58 (p2sh-wrapped) SegWit addresses from pubkey/script

def p2wpkh_p2sh(pubkey: PubKey, network: Optional[str] = None) -> bytes:
    "Return the p2wpkh-p2sh (base58 legacy) Segwit address."
    witprog, network = h160_from_pubkey(pubkey, True, network)
    return b58address_from_witness(witprog, network)


def p2wsh_p2sh(wscript: Script, network: str = 'mainnet') -> bytes:
    "Return the p2wsh-p2sh (base58 legacy) SegWit address."
    witprog = h256_from_script(wscript)
    return b58address_from_witness(witprog, network)
