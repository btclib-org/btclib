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

from .alias import Octets, PubKey, String
from .base58address import b58address_from_h160, h160_from_b58address
from .bech32address import (b32address_from_witness, has_segwit_prefix,
                            witness_from_b32address)
from .curves import secp256k1
from .network import _NETWORKS, _P2PKH_PREFIXES, _P2SH_PREFIXES
from .script import Token, encode
from .to_pubkey import to_pubkey_bytes
from .utils import bytes_from_octets


def nulldata_scriptPubKey(data: Octets) -> List[Token]:
    """Return the nulldata scriptPubKey with the provided data."""

    data = bytes_from_octets(data)
    if len(data) > 80:
        msg = f"Invalid data lenght ({len(data)} bytes) "
        msg += "for nulldata scriptPubKey"
        raise ValueError(msg)
    return ['OP_RETURN', data.hex()]


def p2pk_scriptPubKey(pubkey: PubKey) -> List[Token]:
    """Return the p2pk scriptPubKey of the provided pubkey."""

    # FIXME: does P2PK work also with compressed key?
    # TODO: remove hardcoded secp256k1
    compressed = False
    pubkey = to_pubkey_bytes(pubkey, compressed, secp256k1)
    return [pubkey.hex(), 'OP_CHECKSIG']


def p2ms_scriptPubKey(m: int, pubkeys: Iterable[PubKey]) -> List[Token]:
    """Return the m-of-n multi-sig scriptPubKey of the provided pubkeys."""

    if m<1 or m>16:
        raise ValueError(f"Invalid m ({m}) in m-of-n multisignature")
        # raise ValueError("Impossible m-of-n ({m}-of-{n})")

    scriptPubKey : List[Token] = [m]
    # FIXME: does P2MS work also with compressed key?
    # TODO: remove hardcoded secp256k1
    compressed = False
    for pubkey in pubkeys:
        pubkey = to_pubkey_bytes(pubkey, compressed, secp256k1)
        scriptPubKey.append(pubkey.hex())

    # FIXME: handle script max length
    # FIXME: enable lexicographic key sorting
    n = len(scriptPubKey)-1
    if n<1 or n>16:
        raise ValueError(f"Invalid n ({n}) in {m}-of-{n} multisignature")
    if m>n:
        raise ValueError(f"Impossible {m}-of-{n} multisignature")
    scriptPubKey.append(n)
    scriptPubKey.append('OP_CHECKMULTISIG')
    return scriptPubKey


def p2pkh_scriptPubKey(pubkey_h160: Octets) -> List[Token]:
    """Return the p2pkh scriptPubKey of the provided HASH160 pubkey-hash."""

    pubkey_h160 = bytes_from_octets(pubkey_h160, 20)
    return ['OP_DUP', 'OP_HASH160', pubkey_h160.hex(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']


def p2sh_scriptPubKey(script_h160: Octets) -> List[Token]:
    """Return the p2sh scriptPubKey of the provided HASH160 script-hash."""

    script_h160 = bytes_from_octets(script_h160, 20)
    return ['OP_HASH160', script_h160.hex(), 'OP_EQUAL']


def p2wpkh_scriptPubKey(pubkey_h160: Octets) -> List[Token]:
    """Return the p2wpkh scriptPubKey of the provided HASH160 pubkey-hash.

    For P2WPKH, the witness program must be the HASH160 20-byte pubkey-hash;
    the scriptPubkey is the witness version 0 followed by the canonical push
    of the witness program (program lenght + program),
    that is 0x0014{20-byte key-hash}
    """

    pubkey_h160 = bytes_from_octets(pubkey_h160, 20)
    return [0, pubkey_h160.hex()]


def p2wsh_scriptPubKey(script_h256: Octets) -> List[Token]:
    """Return the p2wsh scriptPubKey of the provided SHA256 script-hash.

    For P2WSH, the witness program must be the SHA256 32-byte script-hash;
    the scriptPubkey is the witness version 0 followed by the canonical push
    of the witness program (program lenght + program),
    that is 0x0020{32-byte script-hash}
    """

    script_h256 = bytes_from_octets(script_h256, 32)
    return [0, script_h256.hex()]


def address_from_scriptPubKey(s: Union[Iterable[Token], bytes],
                              network: str = "mainnet") -> bytes:
    """Return the bech32/base58 address from the input scriptPubKey."""

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
        prefix = _P2SH_PREFIXES[_NETWORKS.index(network)]
        return b58address_from_h160(prefix, s[2:length-1])
    elif length == 25 and s[:3] == b'\x76\xa9\x14' and s[-2:] == b'\x88\xac':
        prefix = _P2PKH_PREFIXES[_NETWORKS.index(network)]
        return b58address_from_h160(prefix, s[3:length-2])
    else:
        raise ValueError(f"No address for script {s.decode()}")


def scriptPubKey_from_address(addr: String) -> Tuple[List[Token], str]:
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
