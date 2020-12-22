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

from btclib.alias import Octets, String
from btclib.base58 import b58decode, b58encode
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160_from_key
from btclib.network import NETWORKS, network_from_key_value
from btclib.script_pub_key import script_pub_key_from_payload
from btclib.to_pub_key import Key
from btclib.utils import bytes_from_octets, hash160, sha256

# 1. Hash/WitnessProgram from pub_key/script_pub_key
# imported from the hashes module

# 2. base58 address from HASH and vice versa


def address_from_h160(prefix: Octets, h160: Octets, network: str = "mainnet") -> str:
    "Encode a base58 address from the payload."

    prefix = bytes_from_octets(prefix)
    prefixes = NETWORKS[network].p2pkh, NETWORKS[network].p2sh
    if prefix not in prefixes:
        raise BTClibValueError(f"invalid {network} base58 address prefix: {prefix!r}")
    payload = prefix + bytes_from_octets(h160, 20)
    return b58encode(payload).decode("ascii")


def h160_from_address(b58addr: String) -> Tuple[bytes, bytes, str, bool]:
    "Return the payload from a base58 address."

    if isinstance(b58addr, str):
        b58addr = b58addr.strip()
    payload = b58decode(b58addr, 21)
    prefix = payload[:1]

    for script_type, is_script_hash in zip(("p2pkh", "p2sh"), (False, True)):
        # with pytohn>=3.8 use walrus operator
        # if network := network_from_key_value(script_type, prefix):
        network = network_from_key_value(script_type, prefix)
        if network:
            return prefix, payload[1:], network, is_script_hash

    err_msg = f"invalid base58 address prefix: 0x{prefix.hex()}"
    raise BTClibValueError(err_msg)


# 1.+2. = 3. base58 address from pub_key/script_pub_key


def p2pkh(
    key: Key, network: Optional[str] = None, compressed: Optional[bool] = None
) -> str:
    "Return the p2pkh base58 address corresponding to a public key."
    h160, network = hash160_from_key(key, network, compressed)
    prefix = NETWORKS[network].p2pkh
    return address_from_h160(prefix, h160, network)


def p2sh(script_pub_key: Octets, network: str = "mainnet") -> str:
    "Return the p2sh base58 address corresponding to a script_pub_key."
    h160 = hash160(script_pub_key)
    prefix = NETWORKS[network].p2sh
    return address_from_h160(prefix, h160, network)


# 2b. base58 address from WitnessProgram
# it cannot be inverted because of the hash performed by p2sh


def address_from_witness(witness: Octets, network: str = "mainnet") -> str:
    "Encode a legacy base58 p2sh-wrapped SegWit address."

    length = len(witness)
    if length == 20:
        redeem_script = script_pub_key_from_payload("p2wpkh", witness)
    elif length == 32:
        redeem_script = script_pub_key_from_payload("p2wsh", witness)
    else:
        err_msg = "invalid witness program length for witness v0: "
        err_msg += f"{length} instead of 20 or 32"
        raise BTClibValueError(err_msg)

    return p2sh(redeem_script, network)


# 1.+2b. = 3b. base58 (p2sh-wrapped) SegWit addresses from pub_key/script_pub_key


def p2wpkh_p2sh(key: Key, network: Optional[str] = None) -> str:
    "Return the p2wpkh-p2sh base58 address corresponding to a pub_key."
    compressed = True  # needed to force check on pub_key
    witness, network = hash160_from_key(key, network, compressed)
    return address_from_witness(witness, network)


def p2wsh_p2sh(redeem_script: Octets, network: str = "mainnet") -> str:
    "Return the p2wsh-p2sh base58 address corresponding to a reedem script."
    witness = sha256(redeem_script)
    return address_from_witness(witness, network)
