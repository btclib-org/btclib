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

from .base58address import (_P2PKH_PREFIXES, _P2SH_PREFIXES,
                            b58address_from_h160, h160_from_b58address)
from .bech32address import (b32address_from_witness, has_segwit_prefix,
                            witness_from_b32address)
from .script import Token, encode
from .utils import Octets, bytes_from_hexstring


def nulldata_scriptPubKey(data: Octets) -> List[Token]:
    """Return the nulldata scriptPubKey with the provided data."""

    data = bytes_from_hexstring(data)
    if len(data) > 40:
        msg = f"Invalid data lenght ({len(data)} bytes) "
        msg += "for nulldata scriptPubKey"
        raise ValueError(msg)
    return ['OP_RETURN', data.hex()]


def p2pk_scriptPubKey(pubkey: Octets) -> List[Token]:
    """Return the p2pk scriptPubKey of the provided pubkey."""

    pubkey = bytes_from_hexstring(pubkey)
    if len(pubkey) not in (33, 65):
        msg = f"Invalid pubkey lenght ({len(pubkey)} bytes) "
        msg += "for p2pk scriptPubKey"
        raise ValueError(msg)
    return [pubkey.hex(), 'OP_CHECKSIG']


def multisig_scriptPubKey(m: int, pubkeys: Iterable[Octets]) -> List[Token]:
    """Return the m-of-n multi-sig scriptPubKey of the provided pubkeys."""

    if m<1 or m>16:
        raise ValueError(f"Invalid m ({m})")
        # raise ValueError("Impossible m-of-n ({m}-of-{n})")

    scriptPubKey : List[Token] = [m]
    for pubkey in pubkeys:
        pubkey = bytes_from_hexstring(pubkey)
        if len(pubkey) not in (33, 65):
            msg = f"Invalid pubkey lenght ({len(pubkey)} bytes) "
            msg += "for m-of-n multi-sig scriptPubKey"
            raise ValueError(msg)
        scriptPubKey.append(pubkey.hex())

    # FIXME: handle script max length
    # FIXME: enable lexicographic key sorting
    n = len(scriptPubKey)-1
    if n<1 or n>16:
        raise ValueError(f"Invalid n ({n})")
    if m>n:
        raise ValueError(f"Impossible m-of-n ({m}-of-{n})")
    scriptPubKey.append(n)
    scriptPubKey.append('OP_CHECKMULTISIGVERIFY')
    return scriptPubKey


def p2pkh_scriptPubKey(pubkey_h160: Octets) -> List[Token]:
    """Return the p2pkh scriptPubKey of the provided HASH160 pubkey-hash."""

    pubkey_h160 = bytes_from_hexstring(pubkey_h160)
    if len(pubkey_h160) != 20:
        msg = f"Invalid pubkey-hash lenght ({len(pubkey_h160)} bytes) "
        msg += "for p2pkh scriptPubKey"
        raise ValueError(msg)
    return ['OP_DUP', 'OP_HASH160', pubkey_h160.hex(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']


def p2sh_scriptPubKey(script_h160: Octets) -> List[Token]:
    """Return the p2sh scriptPubKey of the provided HASH160 script-hash."""

    script_h160 = bytes_from_hexstring(script_h160)
    if len(script_h160) != 20:
        msg = f"Invalid script-hash lenght ({len(script_h160)} bytes) "
        msg += "for p2sh scriptPubKey"
        raise ValueError(msg)
    return ['OP_HASH160', script_h160.hex(), 'OP_EQUAL']


def p2wpkh_scriptPubKey(pubkey_h160: Octets) -> List[Token]:
    """Return the p2wpkh scriptPubKey of the provided HASH160 pubkey-hash.

    For P2WPKH, the witness program must be the HASH160 20-byte pubkey-hash;
    the scriptPubkey is the witness version 0 followed by the canonical push
    of the witness program (program lenght + program),
    that is 0x0014{20-byte key-hash}
    """

    pubkey_h160 = bytes_from_hexstring(pubkey_h160)
    if len(pubkey_h160) != 20:
        msg = f"Invalid witness program lenght ({len(pubkey_h160)} bytes) "
        msg += "for p2wpkh scriptPubKey"
        raise ValueError(msg)
    return [0, pubkey_h160.hex()]


def p2wsh_scriptPubKey(script_h160: Octets) -> List[Token]:
    """Return the p2wsh scriptPubKey of the provided SHA256 script-hash.

    For P2WSH, the witness program must be the SHA256 32-byte script-hash;
    the scriptPubkey is the witness version 0 followed by the canonical push
    of the witness program (program lenght + program),
    that is 0x0020{32-byte script-hash}
    """

    script_h160 = bytes_from_hexstring(script_h160)
    if len(script_h160) != 32:
        msg = f"Invalid witness program lenght ({len(script_h160)} bytes) "
        msg += "for p2wsh scriptPubKey"
        raise ValueError(msg)
    return [0, script_h160.hex()]


def address_from_scriptPubKey(scriptPubKey: Iterable[Token],
                              network: str = "mainnet") -> bytes:
    """Return the bech32/base58 address from the input scriptPubKey."""

    s = encode(scriptPubKey)
    len_s = len(s)
    # [0, script_hash] : 0x0020{32-byte key-script_hash}
    if len_s == 34 and s[:2] == b'\x00\x20':
        return b32address_from_witness(0, s[2:], network)
    # [0, key_hash]    : 0x0014{20-byte key-hash}
    elif len_s == 22 and s[:2] == b'\x00\x14':
        return b32address_from_witness(0, s[2:], network)
    elif len_s == 23 and s[:2] == b'\xa9\x14' and s[-1:] == b'\x87':
        return b58address_from_h160(_P2SH_PREFIXES, s[2:len_s-1], network)
    elif len_s == 25 and s[:3] == b'\x76\xa9\x14' and s[-2:] == b'\x88\xac':
        return b58address_from_h160(_P2PKH_PREFIXES, s[3:len_s-2], network)
    else:
        raise ValueError("Unknown script")


def scriptPubKey_from_address(addr: Union[bytes, str]) -> Tuple[List[Token], str]:
    """Return (scriptPubKey, network) from the input bech32/base58 address"""

    if has_segwit_prefix(addr):
        # also check witness validity
        witvers, witprog, network, _ = witness_from_b32address(addr)
        if witvers == 0:
            len_wprog = len(witprog)
            if len_wprog == 32:
                return p2wsh_scriptPubKey(witprog), network
            else:  # must be len_wprog == 20
                return p2wpkh_scriptPubKey(witprog), network
        else:
            raise ValueError(f"Unhandled witness version ({witvers})")
    else:
        _, h160, network, is_p2sh = h160_from_b58address(addr)
        if is_p2sh:
            return p2sh_scriptPubKey(h160), network
        else:
            return p2pkh_scriptPubKey(h160), network
