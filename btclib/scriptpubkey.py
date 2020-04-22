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

from typing import Dict, List, Optional, Sequence, Tuple, Union

from .alias import Octets, PubKey, Script, String, Token
from .hashes import (hash160_from_pubkey, hash160_from_script,
                     hash256_from_script)
from .network import p2pkh_prefix_from_network, p2sh_prefix_from_network
from .script import decode, encode
from .to_pubkey import bytes_from_pubkey
from .utils import bytes_from_octets

# 1. Hash/WitnessProgram from pubkey/script

# hash160_from_pubkey, hash160_from_script, and hash256_from_script
# are imported from base58address

# FIXME: do P2PK and P2MS work also with compressed key?
# TODO: accept Sequence instead of List
def payload_from_pubkeys(pubkeys: Union[List[PubKey], PubKey],
                         lexicographic_sort: bool = True) -> bytes:

    if not isinstance(pubkeys, List):
        payload, _ = bytes_from_pubkey(pubkeys, compressed=False)
    else:
        pk = [bytes_from_pubkey(p, compressed=False)[0] for p in pubkeys]
        if lexicographic_sort:
            pk.sort()
        payload = b''.join(pk)

    return payload

# 2. scriptPubKey from Hash/WitnessProgram and vice versa

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
        if m<1 or m>16:
            raise ValueError(f"Invalid m ({m}) in {m}-of-{n} multisignature")
        if n<1 or n>16:
            raise ValueError(f"Invalid n ({n}) in {m}-of-{n} multisignature")
        if m>n:
            raise ValueError(f"Impossible m>n {m}-of-{n} multisignature")
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
    nkeys, r = divmod(l - 3, 66)  # n. of keys in m-of-n
    if   l==67 and s[0] == 0x41           and s[-1] == 0xAC:        # pk
        # p2pk [pubkey, OP_CHECKSIG]
        # 0x41{65-byte pubkey}AC
        return 'p2pk', s[1:-1], 0
    elif r== 0                            and s[-1] == 0xAE:        # ms
        # p2ms [m, pubkeys, n, OP_CHECKMULTISIG]
        # 0x{1-byte m}41{65-byte pubkey1}...41{65-byte pubkeyn}{1-byte n}AE
        m = s[0]-80 if s[0] else 0
        if nkeys < 1 or nkeys > 16:
            errmsg = f"Invalid number of keys ({nkeys}) in m-of-n "
            errmsg += f"multisignature: {decode(s)}"
            raise ValueError(errmsg)
        if m < 1 or m > 16:
            errmsg = f"Invalid m ({m}) in {m}-of-{nkeys} multisignature"
            errmsg += f": {decode(s)}"
            raise ValueError(errmsg)
        n = s[-2]-80 if s[-2] else 0
        if n != nkeys:
            errmsg = f"Keys ({nkeys}) / n ({n}) mismatch "
            errmsg += "in m-of-n multisignature"
            raise ValueError(errmsg)
        if m>n:
            errmsg = f"Impossible {m}-of-{n} multisignature"
            errmsg += f": {decode(s)}"
            raise ValueError(errmsg)
        payload = b''
        for i in range(n):
            if s[i*66+1] != 0x41:
                errmsg = f"{i*66+1}-th byte "
                errmsg += f"in {m}-of-{n} multisignature payload "
                errmsg += f"is {hex(s[i*66+1])}, it should have been 0x41"
                errmsg += f": {decode(s)}"
                raise ValueError(errmsg)
            payload += s[i*66+2:i*66+67] 
        return 'p2ms', payload, m
    elif l<=83 and s[0] == 0x6A:                                    # nulldata
        # nulldata [OP_RETURN, data]
        zeroone = int(l>77)
        if s[1+zeroone] != l - 2 - zeroone:
            errmsg = f"Wrong data lenght ({s[1+zeroone]}) in {l}-bytes "
            errmsg += f"nulldata script: it should have been {l-2-zeroone}"
            errmsg += f": {decode(s)}"
            raise ValueError(errmsg)
        if l < 77:
            # OP_RETURN, data length, data up to 74 bytes max
            # 0x6A{1 byte data-length}{data (0-74 bytes)}
            return 'nulldata', s[2:], 0
        if l > 77:
            # OP_RETURN, OP_PUSHDATA1, data length, data min 75 bytes up to 80
            # 0x6A4C{1-byte data-length}{data (75-80 bytes)}
            if s[1] != 0x4c:
                errmsg = f"Missing OP_PUSHDATA1 (0x4c) in {l}-bytes nulldata script"
                errmsg += f", got {hex(s[1])} instead"
                errmsg += f": {decode(s)}"
                raise ValueError(errmsg)
            return 'nulldata', s[3:], 0
        raise ValueError(f"Invalid 77 bytes OP_RETURN script length")
    elif l==25 and s[:3]==b'\x76\xa9\x14' and s[-2:]==b'\x88\xac':  # pkh
        # p2pkh [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
        # 0x76A914{20-byte pubkey_hash}88AC
        return 'p2pkh', s[3:l-2], 0
    elif l==23 and s[:2]==b'\xa9\x14'     and s[-1] == 0x87:        # sh
        # p2sh [OP_HASH160, script_hash, OP_EQUAL]
        # 0xA914{20-byte script_hash}87
        return 'p2sh', s[2:l-1], 0
    elif l==22 and s[:2]==b'\x00\x14':                              # wkh
        # p2wpkh [0, pubkey_hash]
        # 0x0014{20-byte pubkey_hash}
        return 'p2wpkh', s[2:], 0
    elif l==34 and s[:2]==b'\x00\x20':                              # wsh
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

    pubkey_h160, _ = hash160_from_pubkey(pubkey, compressed=compressed)
    return scriptPubKey_from_payload('p2pkh', pubkey_h160)


def p2sh(script: Script) -> bytes:
    "Return the p2sh scriptPubKey of the provided script."

    script_h160 = hash160_from_script(script)
    return scriptPubKey_from_payload('p2sh', script_h160)


def p2wpkh(pubkey: PubKey) -> bytes:
    "Return the p2wpkh scriptPubKey of the provided pubkey."
    compressed = True  # needed to force check on pubkey
    pubkey_h160, _ = hash160_from_pubkey(pubkey, compressed=compressed)
    return scriptPubKey_from_payload('p2wpkh', pubkey_h160)


def p2wsh(wscript: Script) -> bytes:
    "Return the p2wsh scriptPubKey of the provided script."

    script_h256 = hash256_from_script(wscript)
    return scriptPubKey_from_payload('p2wsh', script_h256)
