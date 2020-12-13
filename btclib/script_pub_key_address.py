#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Tuple

from .alias import Octets, String
from .base58_address import base58_address_from_h160, h160_from_base58_address
from .bech32_address import (
    bech32_address_from_witness,
    witness_from_bech32_address,
)
from .exceptions import BTClibValueError
from .network import NETWORKS
from .script_pub_key import (
    payload_from_script_pub_key,
    script_pub_key_from_payload,
)


def has_segwit_prefix(addr: String) -> bool:

    str_addr = addr.strip().lower() if isinstance(addr, str) else addr.decode("ascii")
    return any(str_addr.startswith(NETWORKS[net].p2w + "1") for net in NETWORKS)


def script_pub_key_from_address(addr: String) -> Tuple[bytes, str]:
    "Return (script_pub_key, network) from the input bech32/base58 address"

    if has_segwit_prefix(addr):
        # also check witness validity
        wit_ver, wit_prg, network, is_script_hash = witness_from_bech32_address(addr)
        if wit_ver != 0:
            raise BTClibValueError(f"unmanaged witness version: {wit_ver}")
        if is_script_hash:
            return script_pub_key_from_payload("p2wsh", wit_prg), network
        return script_pub_key_from_payload("p2wpkh", wit_prg), network

    _, h160, network, is_p2sh = h160_from_base58_address(addr)
    if is_p2sh:
        return script_pub_key_from_payload("p2sh", h160), network
    return script_pub_key_from_payload("p2pkh", h160), network


def address_from_script_pub_key(
    script_pub_key: Octets, network: str = "mainnet"
) -> str:
    "Return the bech32/base58 address from a script_pub_key."

    if script_pub_key:
        script_type, payload = payload_from_script_pub_key(script_pub_key)
        if script_type == "p2pkh":
            prefix = NETWORKS[network].p2pkh
            return base58_address_from_h160(prefix, payload, network)
        if script_type == "p2sh":
            prefix = NETWORKS[network].p2sh
            return base58_address_from_h160(prefix, payload, network)
        if script_type in ("p2wsh", "p2wpkh"):
            return bech32_address_from_witness(0, payload, network)

    # not script_pub_key
    # or
    # script_type in ("p2pk", "p2ms", "nulldata", "unknown")
    return ""
