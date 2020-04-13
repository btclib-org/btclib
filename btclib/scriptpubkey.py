#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""ScriptPubKey functions.

"""

from typing import Dict, Iterable, List, Optional, Tuple, Union

from .alias import Octets, PubKey, Script, String, Token
from .base58address import (b58address_from_h160, h160_from_b58address,
                            h160_from_pubkey, h160_from_script,
                            h256_from_script)
from .bech32address import (b32address_from_witness, has_segwit_prefix,
                            witness_from_b32address)
from .curves import secp256k1
from .network import p2pkh_prefix_from_network, p2sh_prefix_from_network
from .script import encode
from .to_pubkey import bytes_from_pubkey
from .utils import bytes_from_octets, hash160, sha256

# 1. Hash/WitnessProgram from pubkey/script

# h160_from_pubkey, h160_from_script, and h256_from_script
# are imported from base58address

# FIXME: do P2PK and P2MS work also with compressed key?
# def payload_from_pubkeys(pubkeys: Iterable[PubKey], compressed: Optional[bool] = None) -> bytes:
def payload_from_pubkeys(pubkeys: Iterable[PubKey],
                         lexicographic_sort: bool = True) -> bytes:

    compressed = False
    pk = [bytes_from_pubkey(p, compressed)[0] for p in pubkeys]
    if lexicographic_sort:
        pk.sort()
    payload = b''
    for p in pk:
        payload += p
    return payload

# 2. scriptPubKey from Hash/WitnessProgram and vice versa

# TODO sort in the script_type, payload, m order
def scriptPubKey_from_payload(payload: Octets, script_type: str, m: int = 0) -> bytes:
    "Return the requested scriptPubKey for the provided payload."

    script_type = script_type.lower()

    if (script_type == "p2ms") ^ (m != 0):
        errmsg = f"Invalid m ({m}) for {script_type} script"
        raise ValueError(errmsg)

    n = 0
    m_keys_n : List[Token] = []
    if script_type == 'nulldata':
        payload = bytes_from_octets(payload)
        if len(payload) > 80:
            msg = f"Invalid data lenght ({len(payload)} bytes) "
            msg += "for nulldata scriptPubKey"
            raise ValueError(msg)
    elif script_type == 'p2ms':
        payload = bytes_from_octets(payload)
        length = len(payload)
        n, r = divmod(length, 65)
        if r != 0:
            msg = f"Invalid payload lenght ({length} bytes) "
            msg += "for p2ms scriptPubKey"
            raise ValueError(msg)
        if m>n:
            raise ValueError(f"Impossible {m}-of-{n} multisignature")
        if m<1 or m>16:
            raise ValueError(f"Invalid m ({m}) in {m}-of-{n} multisignature")
        if n<1 or n>16:
            raise ValueError(f"Invalid n ({n}) in {m}-of-{n} multisignature")
        m_keys_n.append(m)
        for i in range(n):
            start = i*65
            m_keys_n.append(payload[start:start+65])
        m_keys_n.append(n)
    elif script_type == 'p2pk':
        payload = bytes_from_octets(payload, 65)
    elif script_type == 'p2wsh':
        payload = bytes_from_octets(payload, 32)
    else:
        payload = bytes_from_octets(payload, 20)

    script_templates: Dict[str, List[Token]] = {
        'nulldata' : ['OP_RETURN', payload],
        'p2pkh'    : ['OP_DUP', 'OP_HASH160', payload, 'OP_EQUALVERIFY', 'OP_CHECKSIG'],
        'p2sh'     : ['OP_HASH160', payload, 'OP_EQUAL'],
        'p2wpkh'   : [0, payload],
        'p2wsh'    : [0, payload],
        'p2pk'     : [payload, 'OP_CHECKSIG'],
        'p2ms'     : m_keys_n + ['OP_CHECKMULTISIG'],
    }
    script = script_templates[script_type]
    return encode(script)


def payload_from_scriptPubKey(script: Script) -> Tuple[bytes, str, int]:
    "Return (payload, scriptPubKey type) from the input script."

    if isinstance(script, list):
        s = encode(script)
    else:
        s = bytes_from_octets(script)

    length = len(s)
    # p2wpkh [0, pubkey_hash]
    # 0x0014{20-byte pubkey_hash}
    if length == 22 and s[:2] == b'\x00\x14':
        return s[2:], 'p2wpkh', 0
    # p2sh [OP_HASH160, script_hash, OP_EQUAL]
    # 0xA914{20-byte script_hash}87
    elif length == 23 and s[:2] == b'\xa9\x14' and s[-1:] == b'\x87':
        return s[2:length-1], 'p2sh', 0
    # p2pkh [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
    # 0x76A914{20-byte pubkey_hash}88AC
    elif length == 25 and s[:3] == b'\x76\xa9\x14' and s[-2:] == b'\x88\xac':
        return s[3:length-2], 'p2pkh', 0
    # p2wsh [0, script_hash]
    # 0x0020{32-byte script_hash}
    elif length == 34 and s[:2] == b'\x00\x20':
        return s[2:], 'p2wsh', 0
    # p2pk [pubkey, OP_CHECKSIG]
    # 0x43{65-byte pubkey}87
    elif length == 67 and s[-1:] == b'\x87':
        return s[:-1], 'p2pk', 0
    # nulldata [OP_RETURN, data]
    # 0x6A{1-byte data-length}{data (max 80 bytes)}
    elif length < 83 and s[0] == 106 and s[1] == length-2:
        return s[2:], 'nulldata', 0
    # p2ms [m, pubkeys, n, OP_CHECKMULTISIG]
    # 0x{1-byte m}{n * (65-byte pubkey)}{1-byte n}AE
    elif (length-3) % 65 == 0 and s[-1] == 174:
        return s[1:-2], 'p2ms', s[0]
    else:
        raise ValueError(f"Unknown script {s.decode()}")

# 1.+2. = 3. scriptPubKey from pubkey/script

def p2pkh(pubkey: PubKey, compressed: Optional[bool] = None) -> bytes:
    "Return the p2pkh scriptPubKey of the provided pubkey."

    pubkey_h160, _ = h160_from_pubkey(pubkey, compressed)
    return scriptPubKey_from_payload(pubkey_h160, 'p2pkh')


def p2sh(script: Script) -> bytes:
    "Return the p2sh scriptPubKey of the provided script."

    script_h160 = h160_from_script(script)
    return scriptPubKey_from_payload(script_h160, 'p2sh')


def p2wpkh(pubkey: PubKey) -> bytes:
    "Return the p2wpkh scriptPubKey of the provided pubkey."

    compressed = True
    pubkey_h160, _ = h160_from_pubkey(pubkey, compressed)
    return scriptPubKey_from_payload(pubkey_h160, 'p2wpkh')


def p2wsh(wscript: Script) -> bytes:
    "Return the p2wsh scriptPubKey of the provided script."

    script_h256 = h256_from_script(wscript)
    return scriptPubKey_from_payload(script_h256, 'p2wsh')


def nulldata(data: String) -> bytes:
    "Return the nulldata scriptPubKey of the provided data."

    if isinstance(data, str):
        data = data.encode()
    return scriptPubKey_from_payload(data, 'nulldata')


def p2pk(pubkey: PubKey) -> bytes:
    "Return the p2pk scriptPubKey of the provided pubkey."

    payload = payload_from_pubkeys([pubkey])
    return scriptPubKey_from_payload(payload, 'p2pk')


def p2ms(m: int, pubkeys: Iterable[PubKey],
         lexicographic_sort: bool = True) -> bytes:
    "Return the m-of-n multi-sig scriptPubKey of the provided pubkeys."

    payload = payload_from_pubkeys(pubkeys, lexicographic_sort)
    return scriptPubKey_from_payload(payload, 'p2ms', m)

# extra scriptPubKey from address and vice versa

def scriptPubKey_from_address(addr: String) -> Tuple[bytes, str]:
    "Return (scriptPubKey, network) from the input bech32/base58 address"

    if has_segwit_prefix(addr):
        # also check witness validity
        witvers, witprog, network, is_script_hash = witness_from_b32address(addr)
        if witvers != 0:
            raise ValueError(f"Unhandled witness version ({witvers})")
        len_wprog = len(witprog)
        assert len_wprog in (20, 32), f"Witness program length: {len_wprog}"
        if len_wprog == 32 and is_script_hash:
            return scriptPubKey_from_payload(witprog, 'p2wsh'), network
        else:
            return scriptPubKey_from_payload(witprog, 'p2wpkh'), network
    else:
        _, h160, network, is_p2sh = h160_from_b58address(addr)
        if is_p2sh:
            return scriptPubKey_from_payload(h160, 'p2sh'), network
        else:
            return scriptPubKey_from_payload(h160, 'p2pkh'), network


def address_from_scriptPubKey(s: Script, network: str = "mainnet") -> bytes:
    "Return the bech32/base58 address from the input scriptPubKey."

    payload, script_type, _ = payload_from_scriptPubKey(s)
    if script_type is 'nulldata':
        raise ValueError("No address for null data script")
    elif script_type == 'p2pk':
        raise ValueError("No address for p2pk script")
    elif script_type == 'p2ms':
        raise ValueError("No address for p2ms script")
    elif script_type == 'p2wsh' or script_type == 'p2wpkh':
        return b32address_from_witness(0, payload, network)
    elif script_type == 'p2sh':
        prefix = p2sh_prefix_from_network(network)
    elif script_type == 'p2pkh':
        prefix = p2pkh_prefix_from_network(network)

    return b58address_from_h160(prefix, payload)
