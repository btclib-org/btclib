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
from .exceptions import BTClibValueError
from .network import NETWORKS
from .scriptpubkey import payload_from_script_pubkey, script_pubkey_from_payload
from .tx_out import TxOut


def has_segwit_prefix(addr: String) -> bool:

    str_addr = addr.strip().lower() if isinstance(addr, str) else addr.decode("ascii")
    return any(str_addr.startswith(NETWORKS[net].p2w + "1") for net in NETWORKS)


def script_pubkey_from_address(addr: String) -> Tuple[bytes, str]:
    "Return (script_pubkey, network) from the input bech32/base58 address"

    if has_segwit_prefix(addr):
        # also check witness validity
        wv, wp, network, is_script_hash = witness_from_b32address(addr)
        if wv != 0:
            raise BTClibValueError(f"unmanaged witness version: {wv}")
        if is_script_hash:
            return script_pubkey_from_payload("p2wsh", wp), network
        return script_pubkey_from_payload("p2wpkh", wp), network

    _, h160, network, is_p2sh = h160_from_b58address(addr)
    if is_p2sh:
        return script_pubkey_from_payload("p2sh", h160), network
    return script_pubkey_from_payload("p2pkh", h160), network


def address_from_script_pubkey(
    script_pubkey: Script, network: str = "mainnet"
) -> bytes:
    "Return the bech32/base58 address from a script_pubkey."

    script_type, payload, m = payload_from_script_pubkey(script_pubkey)
    if script_type == "p2pk":
        raise BTClibValueError("no address for p2pk script_pubkey")
    if script_type == "p2ms" or isinstance(payload, list) or m != 0:
        raise BTClibValueError("no address for p2ms script_pubkey")
    if script_type == "nulldata":
        raise BTClibValueError("no address for null data script")

    if script_type == "p2pkh":
        prefix = NETWORKS[network].p2pkh
        return b58address_from_h160(prefix, payload, network)
    if script_type == "p2sh":
        prefix = NETWORKS[network].p2sh
        return b58address_from_h160(prefix, payload, network)

    # 'p2wsh' or 'p2wpkh'
    return b32address_from_witness(0, payload, network)


def tx_out_from_address(address: str, value: int) -> TxOut:
    script_pubkey = script_pubkey_from_address(address)[0]
    return TxOut(value, script_pubkey)


def address_from_tx_out(tx_out: TxOut) -> str:
    script_pubkey = tx_out.script_pubkey
    address = address_from_script_pubkey(script_pubkey)
    return address.decode("ascii")
