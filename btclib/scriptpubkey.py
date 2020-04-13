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

from typing import Dict, Sequence, List, Optional, Tuple, Union

from .alias import Octets, PubKey, Script, String, Token
from .base58address import (b58address_from_h160, h160_from_b58address,
                            h160_from_pubkey, h160_from_script,
                            h256_from_script)
from .bech32address import (b32address_from_witness, has_segwit_prefix,
                            witness_from_b32address)
from .curves import secp256k1
from .network import p2pkh_prefix_from_network, p2sh_prefix_from_network
from .script import encode, decode
from .to_pubkey import bytes_from_pubkey
from .utils import bytes_from_octets, hash160, sha256

# 1. Hash/WitnessProgram from pubkey/script

# h160_from_pubkey, h160_from_script, and h256_from_script
# are imported from base58address

# FIXME: do P2PK and P2MS work also with compressed key?
# TODO: accept Sequence instead of List
# def payload_from_pubkeys(pubkeys: List[PubKey], compressed: Optional[bool] = None) -> bytes:
def payload_from_pubkeys(pubkeys: Union[List[PubKey], PubKey],
                         lexicographic_sort: bool = True) -> bytes:

    compressed = False
    if not isinstance(pubkeys, List):
        payload, _ = bytes_from_pubkey(pubkeys, compressed)
    else:
        pk = [bytes_from_pubkey(p, compressed)[0] for p in pubkeys]
        if lexicographic_sort:
            pk.sort()
        payload = b''.join(pk)

    return payload

# 2. scriptPubKey from Hash/WitnessProgram and vice versa

# TODO sort in the script_type, payload, m order
def scriptPubKey_from_payload(script_type: str, payload: Octets, m: int = 0) -> bytes:
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
    elif script_type == 'p2pk':
        payload = bytes_from_octets(payload, 65)
    elif script_type == 'p2ms':
        payload = bytes_from_octets(payload)
        length = len(payload)
        n, r = divmod(length, 65)
        if r != 0:
            msg = f"Invalid payload lenght ({length} bytes) "
            msg += "for p2ms scriptPubKey"
            raise ValueError(msg)
        if m>n:
            raise ValueError(f"Impossible m>n {m}-of-{n} multisignature")
        if m<1 or m>16:
            raise ValueError(f"Invalid m ({m}) in {m}-of-{n} multisignature")
        if n<1 or n>16:
            raise ValueError(f"Invalid n ({n}) in {m}-of-{n} multisignature")
        m_keys_n.append(m)
        for i in range(n):
            start = i*65
            m_keys_n.append(payload[start:start+65])
        m_keys_n.append(n)
    elif script_type == 'p2wsh':
        payload = bytes_from_octets(payload, 32)
    else:
        payload = bytes_from_octets(payload, 20)

    script_templates: Dict[str, List[Token]] = {
        'p2pk'     : [payload, 'OP_CHECKSIG'],
        'p2ms'     : m_keys_n + ['OP_CHECKMULTISIG'],
        'nulldata' : ['OP_RETURN', payload],
        'p2pkh'    : ['OP_DUP', 'OP_HASH160', payload, 'OP_EQUALVERIFY', 'OP_CHECKSIG'],
        'p2sh'     : ['OP_HASH160', payload, 'OP_EQUAL'],
        'p2wpkh'   : [0, payload],
        'p2wsh'    : [0, payload],
    }
    script = script_templates[script_type]
    return encode(script)


def payload_from_scriptPubKey(script: Script) -> Tuple[str, bytes, int]:
    "Return (payload, scriptPubKey type) from the input script."

    if isinstance(script, list):
        s = encode(script)
    else:
        s = bytes_from_octets(script)

    l = len(s)
    n, r = divmod(l - 3, 66)  # n in m-of-n
    if   l==67 and s[:1] ==b'\x41'         and s[-1:]==b'\xAC':      # pk
        # p2pk [pubkey, OP_CHECKSIG]
        # 0x41{65-byte pubkey}AC
        return 'p2pk', s[1:-1], 0
    elif r== 0 and s[-1:]==b'\xAE':                                  # ms
        # p2ms [m, pubkeys, n, OP_CHECKMULTISIG]
        # 0x{1-byte m}41{65-byte pubkey1}...41{65-byte pubkeyn}{1-byte n}AE
        if n<1 or n>16:
            raise ValueError(f"Invalid n ({n}) in m-of-n multisignature")
        assert n == s[-2]-80, f"Invalid n ({n}) in m-of-n multisignature"
        m = s[0]-80
        if m>n:
            raise ValueError(f"Impossible m>n {m}-of-{n} multisignature")
        if m<1 or m>16:
            raise ValueError(f"Invalid m ({m}) in {m}-of-{n} multisignature")
        payload = b''
        for i in range(n):
            if s[i*66+1] != 0x41:
                errmsg = f"{i}-th byte "
                errmsg += f"in {m}-of-{n} multisignature payload "
                errmsg += f"is {hex(s[i*65+1])}, it should have been 0x41"
                raise ValueError(errmsg)
            payload += s[i*66+2:i*66+67] 
        return 'p2ms', payload, m
    # fix l-2 condition for e.g. l = 14
    elif l<=82 and s[:1] ==b'\x6A'         and s[1]  ==l-2:          # nulldata
        # nulldata [OP_RETURN, data]
        # 0x6A{1-byte data-length}{data (max 80 bytes)}
        return 'nulldata', s[2:], 0
    elif l==25 and s[:3] ==b'\x76\xa9\x14' and s[-2:]==b'\x88\xac':  # pkh
        # p2pkh [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
        # 0x76A914{20-byte pubkey_hash}88AC
        return 'p2pkh', s[3:l-2], 0
    elif l==23 and s[:2] ==b'\xa9\x14'     and s[-1:]==b'\x87':      # sh
        # p2sh [OP_HASH160, script_hash, OP_EQUAL]
        # 0xA914{20-byte script_hash}87
        return 'p2sh', s[2:l-1], 0
    elif l==22 and s[:2] ==b'\x00\x14':                              # wkh
        # p2wpkh [0, pubkey_hash]
        # 0x0014{20-byte pubkey_hash}
        return 'p2wpkh', s[2:], 0
    elif l==34 and s[:2] ==b'\x00\x20':                              # wsh
        # p2wsh [0, script_hash]
        # 0x0020{32-byte script_hash}
        return 'p2wsh', s[2:], 0
    else:
        errmsg = f"Unknown {len(s)}-bytes script"
        errmsg += f", starts with {s[:3].hex()}"
        errmsg += f", ends with {s[-2:].hex()}"
        errmsg += f": {decode(s)}"
        raise ValueError(errmsg)

# 1.+2. = 3. scriptPubKey from pubkey/script

def p2pk(pubkey: PubKey) -> bytes:
    "Return the p2pk scriptPubKey of the provided pubkey."

    payload = payload_from_pubkeys([pubkey])
    return scriptPubKey_from_payload('p2pk', payload, )


def p2ms(m: int, pubkeys: List[PubKey], lexi_sort: bool = True) -> bytes:
    "Return the m-of-n multi-sig scriptPubKey of the provided pubkeys."

    payload = payload_from_pubkeys(pubkeys, lexi_sort)
    return scriptPubKey_from_payload('p2ms', payload, m)


def nulldata(data: String) -> bytes:
    "Return the nulldata scriptPubKey of the provided data."

    if isinstance(data, str):
        data = data.encode()
    return scriptPubKey_from_payload('nulldata', data)


def p2pkh(pubkey: PubKey, compressed: Optional[bool] = None) -> bytes:
    "Return the p2pkh scriptPubKey of the provided pubkey."

    pubkey_h160, _ = h160_from_pubkey(pubkey, compressed)
    return scriptPubKey_from_payload('p2pkh', pubkey_h160)


def p2sh(script: Script) -> bytes:
    "Return the p2sh scriptPubKey of the provided script."

    script_h160 = h160_from_script(script)
    return scriptPubKey_from_payload('p2sh', script_h160)


def p2wpkh(pubkey: PubKey) -> bytes:
    "Return the p2wpkh scriptPubKey of the provided pubkey."

    compressed = True
    pubkey_h160, _ = h160_from_pubkey(pubkey, compressed)
    return scriptPubKey_from_payload('p2wpkh', pubkey_h160)


def p2wsh(wscript: Script) -> bytes:
    "Return the p2wsh scriptPubKey of the provided script."

    script_h256 = h256_from_script(wscript)
    return scriptPubKey_from_payload('p2wsh', script_h256)


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

