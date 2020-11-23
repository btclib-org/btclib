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

from .alias import Octets, Script, String
from .base58 import b58decode, b58encode
from .exceptions import BTClibValueError
from .hashes import hash160_from_key, hash160_from_script, hash256_from_script
from .network import (
    _P2PKH_PREFIXES,
    _P2SH_PREFIXES,
    NETWORKS,
    network_from_key_value,
)
from .scriptpubkey import script_pubkey_from_payload
from .to_pubkey import Key
from .utils import bytes_from_octets

# 1. Hash/WitnessProgram from pubkey/script_pubkey
# imported from the hashes module

# 2. base58 address from HASH and vice versa


def b58address_from_h160(prefix: Octets, h160: Octets, network: str) -> bytes:
    "Encode a base58 address from the payload."

    prefix = bytes_from_octets(prefix)
    prefixes = NETWORKS[network].p2pkh, NETWORKS[network].p2sh
    if prefix not in prefixes:
        raise BTClibValueError(f"invalid {network} base58 address prefix: {prefix!r}")
    payload = prefix + bytes_from_octets(h160, 20)
    return b58encode(payload)


def h160_from_b58address(b58addr: String) -> Tuple[bytes, bytes, str, bool]:
    "Return the payload from a base58 address."

    if isinstance(b58addr, str):
        b58addr = b58addr.strip()

    payload = b58decode(b58addr, 21)
    prefix = payload[0:1]
    if prefix in _P2PKH_PREFIXES:
        network = network_from_key_value("p2pkh", prefix)
        is_script_hash = False
    elif prefix in _P2SH_PREFIXES:
        network = network_from_key_value("p2sh", prefix)
        is_script_hash = True
    else:
        raise BTClibValueError(f"invalid base58 address prefix: 0x{prefix.hex()}")

    return prefix, payload[1:], network, is_script_hash


# 1.+2. = 3. base58 address from pubkey/script_pubkey


def p2pkh(
    key: Key, network: Optional[str] = None, compressed: Optional[bool] = None
) -> bytes:
    "Return the p2pkh base58 address corresponding to a public key."
    h160, network = hash160_from_key(key, network, compressed)
    prefix = NETWORKS[network].p2pkh
    return b58address_from_h160(prefix, h160, network)


def p2sh(script_pubkey: Script, network: str = "mainnet") -> bytes:
    "Return the p2sh base58 address corresponding to a script_pubkey."
    h160 = hash160_from_script(script_pubkey)
    prefix = NETWORKS[network].p2sh
    return b58address_from_h160(prefix, h160, network)


# 2b. base58 address from WitnessProgram
# it cannot be inverted because of the hash performed by p2sh


def b58address_from_witness(witness_program: Octets, network: str = "mainnet") -> bytes:
    "Encode a legacy base58 p2sh-wrapped SegWit address."

    length = len(witness_program)
    if length == 20:
        redeem_script = script_pubkey_from_payload("p2wpkh", witness_program)
    elif length == 32:
        redeem_script = script_pubkey_from_payload("p2wsh", witness_program)
    else:
        err_msg = "invalid witness program length for witness version zero: "
        err_msg += f"{length} instead of 20 or 32"
        raise BTClibValueError(err_msg)

    return p2sh(redeem_script, network)


# 1.+2b. = 3b. base58 (p2sh-wrapped) SegWit addresses from pubkey/script_pubkey


def p2wpkh_p2sh(key: Key, network: Optional[str] = None) -> bytes:
    "Return the p2wpkh-p2sh base58 address corresponding to a pubkey."
    compressed = True  # needed to force check on pubkey
    witprog, network = hash160_from_key(key, network, compressed)
    return b58address_from_witness(witprog, network)


def p2wsh_p2sh(reedem_script: Script, network: str = "mainnet") -> bytes:
    "Return the p2wsh-p2sh base58 address corresponding to a reedem script."
    witprog = hash256_from_script(reedem_script)
    return b58address_from_witness(witprog, network)
