#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Tuple

from .alias import Script, String
from .base58address import b58address_from_h160, h160_from_b58address
from .bech32address import b32address_from_witness, witness_from_b32address
from .network import NETWORKS
from .script import decode
from .scriptpubkey import payload_from_scriptPubKey, scriptPubKey_from_payload
from .tx_out import TxOut


def has_segwit_prefix(addr: String) -> bool:

    str_addr = addr.strip().lower() if isinstance(addr, str) else addr.decode("ascii")
    return any(str_addr.startswith(NETWORKS[net]["p2w"] + "1") for net in NETWORKS)


def scriptPubKey_from_address(addr: String) -> Tuple[bytes, str]:
    "Return (scriptPubKey, network) from the input bech32/base58 address"

    if has_segwit_prefix(addr):
        # also check witness validity
        wv, wp, network, is_script_hash = witness_from_b32address(addr)
        if wv != 0:
            raise ValueError(f"unmanaged witness version: {wv}")
        if is_script_hash:
            return scriptPubKey_from_payload("p2wsh", wp), network
        else:
            return scriptPubKey_from_payload("p2wpkh", wp), network
    else:
        _, h160, network, is_p2sh = h160_from_b58address(addr)
        if is_p2sh:
            return scriptPubKey_from_payload("p2sh", h160), network
        else:
            return scriptPubKey_from_payload("p2pkh", h160), network


def address_from_scriptPubKey(scriptPubKey: Script, network: str = "mainnet") -> bytes:
    "Return the bech32/base58 address from a scriptPubKey."

    script_type, payload, m = payload_from_scriptPubKey(scriptPubKey)
    if script_type == "p2pk":
        raise ValueError("no address for p2pk scriptPubKey")
    if script_type == "p2ms" or isinstance(payload, list) or m != 0:
        raise ValueError("no address for p2ms scriptPubKey")
    if script_type == "nulldata":
        raise ValueError("no address for null data script")

    if script_type == "p2pkh":
        prefix = NETWORKS[network]["p2pkh"]
        return b58address_from_h160(prefix, payload, network)
    if script_type == "p2sh":
        prefix = NETWORKS[network]["p2sh"]
        return b58address_from_h160(prefix, payload, network)

    # 'p2wsh' or 'p2wpkh'
    return b32address_from_witness(0, payload, network)


def tx_out_from_address(address: str, value: int) -> TxOut:
    scriptPubKey = scriptPubKey_from_address(address)[0]
    return TxOut(value, decode(scriptPubKey))


def address_from_tx_out(tx_out: TxOut) -> str:
    scriptPubKey = tx_out.scriptPubKey
    address = address_from_scriptPubKey(scriptPubKey)
    return address.decode("ascii")
