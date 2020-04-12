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

from typing import Iterable, List, Tuple, Union

from .alias import Octets, PubKey, String, Token
from .base58address import b58address_from_h160, h160_from_b58address
from .bech32address import (b32address_from_witness, has_segwit_prefix,
                            witness_from_b32address)
from .curves import secp256k1
from .network import p2pkh_prefix_from_network, p2sh_prefix_from_network
from .script import encode
from .to_pubkey import bytes_from_pubkey
from .utils import bytes_from_octets, hash160, sha256


def nulldata(data: Octets) -> bytes:
    "Return the nulldata scriptPubKey with the provided data."

    data = bytes_from_octets(data)
    if len(data) > 80:
        msg = f"Invalid data lenght ({len(data)} bytes) "
        msg += "for nulldata scriptPubKey"
        raise ValueError(msg)
    script: List[Token] = ['OP_RETURN', data]
    return encode(script)


def p2pk(pubkey: PubKey) -> bytes:
    "Return the p2pk scriptPubKey of the provided pubkey."

    # FIXME: does P2PK work also with compressed key?
    compressed = False
    pubkey, _ = bytes_from_pubkey(pubkey, compressed)
    script: List[Token] = [pubkey, 'OP_CHECKSIG']
    return encode(script)


def p2ms(m: int, pubkeys: Iterable[PubKey]) -> bytes:
    "Return the m-of-n multi-sig scriptPubKey of the provided pubkeys."

    if m<1 or m>16:
        raise ValueError(f"Invalid m ({m}) in m-of-n multisignature")
        # raise ValueError("Impossible m-of-n ({m}-of-{n})")

    script : List[Token] = [m]
    # FIXME: does P2MS work also with compressed key?
    compressed = False
    for pubkey in pubkeys:
        pubkey, _ = bytes_from_pubkey(pubkey, compressed)
        script.append(pubkey)

    # FIXME: handle script max length
    # FIXME: enable lexicographic key sorting
    n = len(script)-1
    if n<1 or n>16:
        raise ValueError(f"Invalid n ({n}) in {m}-of-{n} multisignature")
    if m>n:
        raise ValueError(f"Impossible {m}-of-{n} multisignature")
    script.append(n)
    script.append('OP_CHECKMULTISIG')
    return encode(script)


def p2pkh(pubkey_h160: Octets) -> bytes:
    "Return the p2pkh scriptPubKey of the provided HASH160 pubkey."

    pubkey_h160 = bytes_from_octets(pubkey_h160, 20)
    script: List[Token] = [
        'OP_DUP', 'OP_HASH160', pubkey_h160,
        'OP_EQUALVERIFY', 'OP_CHECKSIG'
    ]
    return encode(script)


def p2sh(script: Union[Octets, List[Token]]) -> bytes:
    """Return the p2sh scriptPubKey of the script (hashed or not).
    
    Warning: the input must be the HASH160 20-byte script-hash or
    the List[Token] script; byte encoded script is not supported,
    as it cannot be reliably differentiated from the HASH160(script).
    """

    if isinstance(script, list):
        scriptPubKey = encode(script)
        script_h160 = hash160(scriptPubKey)
    else:
        script_h160 = bytes_from_octets(script, 20)
    script = ['OP_HASH160', script_h160, 'OP_EQUAL']
    return encode(script)


def p2wpkh(pubkey_h160: Octets) -> bytes:
    """Return the p2wpkh scriptPubKey of the provided HASH160 pubkey.

    For P2WPKH, the witness program must be the HASH160 20-byte pubkey-hash;
    the scriptPubkey is the witness version 0 followed by the canonical push
    of the witness program (program lenght + program),
    that is 0x0014{20-byte key-hash}
    """

    pubkey_h160 = bytes_from_octets(pubkey_h160, 20)
    script: List[Token] = [0, pubkey_h160]
    return encode(script)


def p2wsh(script: Union[Octets, List[Token]]) -> bytes:
    """Return the p2wsh scriptPubKey of the script (hashed or not).
    
    Warning: the input must be the SHA256 32-byte script-hash or
    the List[Token] script; byte encoded script is not supported,
    as it cannot be reliably differentiated from the SHA256(script).

    The scriptPubkey is the witness version 0 followed by the
    canonical push of the witness program (program lenght + program),
    that is 0x0020{32-byte script-hash}
    """

    if isinstance(script, list):
        scriptPubKey = encode(script)
        script_h256 = sha256(scriptPubKey)
    else:
        script_h256 = bytes_from_octets(script, 32)

    script = [0, script_h256]
    return encode(script)


def address_from_scriptPubKey(s: Union[Iterable[Token], bytes],
                              network: str = "mainnet") -> bytes:
    "Return the bech32/base58 address from the input scriptPubKey."

    if not isinstance(s, bytes):
        s = encode(s)
    length = len(s)
    # [0, script_hash] : 0x0020{32-byte key-script_hash}
    if length == 34 and s[:2] == b'\x00\x20':
        return b32address_from_witness(0, s[2:], network)
    # [0, key_hash]    : 0x0014{20-byte key-hash}
    elif length == 22 and s[:2] == b'\x00\x14':
        return b32address_from_witness(0, s[2:], network)
    elif length == 23 and s[:2] == b'\xa9\x14' and s[-1:] == b'\x87':
        prefix = p2sh_prefix_from_network(network)
        return b58address_from_h160(prefix, s[2:length-1])
    elif length == 25 and s[:3] == b'\x76\xa9\x14' and s[-2:] == b'\x88\xac':
        prefix = p2pkh_prefix_from_network(network)
        return b58address_from_h160(prefix, s[3:length-2])
    else:
        raise ValueError(f"No address for script {s.decode()}")


def scriptPubKey_from_address(addr: String) -> Tuple[bytes, str]:
    "Return (scriptPubKey, network) from the input bech32/base58 address"

    if has_segwit_prefix(addr):
        # also check witness validity
        witvers, witprog, network, _ = witness_from_b32address(addr)
        if witvers != 0:
            raise ValueError(f"Unhandled witness version ({witvers})")
        len_wprog = len(witprog)
        assert len_wprog in (20, 32), f"Witness program length: {len_wprog}"
        if len_wprog == 32:
            return p2wsh(witprog), network
        else:
            return p2wpkh(witprog), network
    else:
        _, h160, network, is_p2sh = h160_from_b58address(addr)
        if is_p2sh:
            return p2sh(h160), network
        else:
            return p2pkh(h160), network
