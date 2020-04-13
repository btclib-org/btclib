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

from typing import Optional, Tuple

from .alias import Octets, PubKey, Script, String
from .base58 import b58decode, b58encode
from .bech32address import _check_witness, witness_from_b32address, b32address_from_witness
from .hashes import h160_from_pubkey, h160_from_script, h256_from_script
from .network import (_P2PKH_PREFIXES, _P2SH_PREFIXES, has_segwit_prefix,
                      network_from_p2pkh_prefix, network_from_p2sh_prefix,
                      p2pkh_prefix_from_network, p2sh_prefix_from_network)
from .script import encode
from .scriptpubkey import scriptPubKey_from_payload, payload_from_scriptPubKey
from .utils import bytes_from_octets

# 1. Hash/WitnessProgram from pubkey/script
# imported from the hashes module

# 2. base58 address from HASH and vice versa

# TODO accept Octets prefix
def b58address_from_h160(prefix: bytes, h160: Octets) -> bytes:
    "Encode a base58 address from the payload."

    if prefix not in _P2PKH_PREFIXES + _P2SH_PREFIXES:
        raise ValueError(f"Invalid base58 address prefix {prefix!r}")
    payload = prefix + bytes_from_octets(h160, 20)
    return b58encode(payload)


def h160_from_b58address(b58addr: String) -> Tuple[bytes, bytes, str, bool]:
    "Return the payload from a base58 address."

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
    "Return the p2pkh base58 address corresponding to a public key."
    h160, network = h160_from_pubkey(pubkey, compressed, network)
    prefix = p2pkh_prefix_from_network(network)
    return b58address_from_h160(prefix, h160)


def p2sh(script: Script, network: str = 'mainnet') -> bytes:
    "Return the p2sh base58 address corresponding to a script."
    h160 = h160_from_script(script)
    prefix = p2sh_prefix_from_network(network)
    return b58address_from_h160(prefix, h160)

# 2b. base58 address from WitnessProgram and vice versa

def b58address_from_witness(wp: Script, network: str = 'mainnet') -> bytes:
    "Encode a legacy base58 p2sh-wrapped SegWit address."

    if isinstance(wp, list):
        wp = encode(wp)

    length = len(wp)
    if length == 20:
        redeem_script = scriptPubKey_from_payload('p2wpkh', wp)
    elif length == 32:
        redeem_script = scriptPubKey_from_payload('p2wsh', wp)
    else:
        m = f"Invalid witness program length ({len(wp)})"
        raise ValueError(m)

    return p2sh(redeem_script, network)


def witness_from_b58address(b58addr: String) -> Tuple[bytes, str, bool]:
    "Decode a legacy base58 p2sh-wrapped SegWit address."

    _, payload, network, is_script_hash = h160_from_b58address(b58addr)
    if not is_script_hash:
        raise ValueError("Not a p2sh address")

    is_script_hash = False
    length = len(payload)
    if length == 32:
        is_script_hash = True

    return payload, network, is_script_hash

# 1.+2b. = 3b. base58 (p2sh-wrapped) SegWit addresses from pubkey/script

def p2wpkh_p2sh(pubkey: PubKey, network: Optional[str] = None) -> bytes:
    "Return the p2wpkh-p2sh base58 address corresponding to a pubkey."
    witprog, network = h160_from_pubkey(pubkey, True, network)
    return b58address_from_witness(witprog, network)


def p2wsh_p2sh(wscript: Script, network: str = 'mainnet') -> bytes:
    "Return the p2wsh-p2sh base58 address corresponding to a script."
    witprog = h256_from_script(wscript)
    return b58address_from_witness(witprog, network)


##########################


def scriptPubKey_from_address(addr: String) -> Tuple[bytes, str]:
    "Return (scriptPubKey, network) from the input bech32/base58 address"

    if has_segwit_prefix(addr):
        # also check witness validity
        witvers, witprog, network, is_script_hash = witness_from_b32address(addr)
        if is_script_hash:
            return scriptPubKey_from_payload('p2wsh', witprog), network
        else:
            return scriptPubKey_from_payload('p2wpkh', witprog), network
    else:
        _, h160, network, is_p2sh = h160_from_b58address(addr)
        if is_p2sh:
            return scriptPubKey_from_payload('p2sh', h160), network
        else:
            return scriptPubKey_from_payload('p2pkh', h160), network


def address_from_scriptPubKey(s: Script, network: str = "mainnet") -> bytes:
    "Return the bech32/base58 address from the input scriptPubKey."

    script_type, payload, _ = payload_from_scriptPubKey(s)
    if script_type == 'p2pk':
        raise ValueError("No address for p2pk script")
    if script_type == 'p2ms':
        raise ValueError("No address for p2ms script")
    if script_type == 'nulldata':
        raise ValueError("No address for null data script")

    if script_type == 'p2pkh':
        prefix = p2pkh_prefix_from_network(network)
        return b58address_from_h160(prefix, payload)
    if script_type == 'p2sh':
        prefix = p2sh_prefix_from_network(network)
        return b58address_from_h160(prefix, payload)

    # 'p2wsh' or 'p2wpkh'
    return b32address_from_witness(0, payload, network)
