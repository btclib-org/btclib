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

from typing import List, Optional, Tuple, Union

from .alias import Key, Octets, Script, String, Token
from .hashes import hash160_from_key, hash160_from_script, hash256_from_script
from .script import decode, encode
from .to_pubkey import pubkeyinfo_from_key
from .utils import bytes_from_octets

# 1. Hash/WitnessProgram from pubkey/scriptPubKey

# hash160_from_key, hash160_from_script, and hash256_from_script
# are imported from hashes.py


# 2. scriptPubKey from Hash/WitnessProgram and vice versa


def scriptPubKey_from_payload(
    s_type: str,
    payloads: Union[Octets, List[Octets]],
    m: int = 0,
    lexicographic_sort: bool = True,
) -> bytes:
    """Return the requested scriptPubKey for the provided payload.

    Multi-signature payloads can be lexicographically sorted.
    BIP67 endorses key sorting according to compressed key
    representation: this implementation is BIP67 compliant.

    Note that sorting uncompressed keys (leading 0x04 byte) results
    in a different order than sorting the same keys in compressed
    (leading 0x02 or 0x03 bytes) representation.
    This implementation sorts uncompressed key according to their
    uncompressed representation, i.e. 04 leading byte being equal
    according to the point x-coordinate

    https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
    """

    script_type = s_type.lower()

    if (script_type == "p2ms") ^ (m != 0):
        errmsg = f"invalid m for {script_type} scriptPubKey: {m}"
        raise ValueError(errmsg)

    if isinstance(payloads, list):
        if script_type == "p2ms":
            if m < 1 or m > 16:
                raise ValueError(f"invalid m in m-of-n multisignature: {m}")
            if lexicographic_sort:
                # BIP67 compliant
                payloads = sorted(payloads)
            n = len(payloads)
            if n < m:
                raise ValueError(
                    f"number-of-pubkeys < m in {m}-of-n multisignature: {n}"
                )
            if n > 16:
                raise ValueError(f"too many pubkeys in m-of-n multisignature: {n}")
            scriptPubKey: List[Token] = [m]
            for key in payloads:
                key = bytes_from_octets(key, (33, 65))
                scriptPubKey.append(key)
            scriptPubKey.append(n)
            scriptPubKey.append("OP_CHECKMULTISIG")
        else:
            errmsg = f"invalid list of Octets for {script_type} scriptPubKey"
            raise ValueError(errmsg)
    else:
        if script_type == "nulldata":
            payload = bytes_from_octets(payloads)
            if len(payload) > 80:
                err_msg = f"invalid nulldata script lenght: {len(payload)} bytes "
                raise ValueError(err_msg)
            scriptPubKey = ["OP_RETURN", payload]
        elif script_type == "p2pk":
            payload = bytes_from_octets(payloads, (33, 65))
            scriptPubKey = [payload, "OP_CHECKSIG"]
        elif script_type == "p2wsh":
            payload = bytes_from_octets(payloads, 32)
            scriptPubKey = [0, payload]
        elif script_type == "p2pkh":
            payload = bytes_from_octets(payloads, 20)
            scriptPubKey = [
                "OP_DUP",
                "OP_HASH160",
                payload,
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        elif script_type == "p2sh":
            payload = bytes_from_octets(payloads, 20)
            scriptPubKey = ["OP_HASH160", payload, "OP_EQUAL"]
        elif script_type == "p2wpkh":
            payload = bytes_from_octets(payloads, 20)
            scriptPubKey = [0, payload]
        else:
            raise ValueError(f"unknown scriptPubKey type: {script_type}")

    return encode(scriptPubKey)


Payloads = Union[bytes, List[bytes]]


def payload_from_nulldata_scriptPubKey(
    scriptPubKey: Script,
) -> Tuple[str, Payloads, int]:
    scriptPubKey = (
        encode(scriptPubKey)
        if isinstance(scriptPubKey, list)
        else bytes_from_octets(scriptPubKey)
    )
    length = len(scriptPubKey)

    # nulldata [OP_RETURN, data]
    zero_or_one = int(length > 78)
    if scriptPubKey[1 + zero_or_one] != length - 2 - zero_or_one:
        raise ValueError(
            f"wrong data lenght: {scriptPubKey[1+zero_or_one]} "
            f"in {length}-bytes nulldata script; it should "
            f"have been {length-2-zero_or_one}: {decode(scriptPubKey)}"
        )
    if length < 78:
        # OP_RETURN, data length, data up to 75 bytes max
        # 0x6A{1 byte data-length}{data (0-75 bytes)}
        return "nulldata", scriptPubKey[2:], 0
    if length > 78:
        # OP_RETURN, OP_PUSHDATA1, data length, data min 76 bytes up to 80
        # 0x6A4C{1-byte data-length}{data (76-80 bytes)}
        if scriptPubKey[1] != 0x4C:
            raise ValueError(
                f"missing OP_PUSHDATA1 (0x4c) in {length}-bytes nulldata script, "
                f"got {hex(scriptPubKey[1])} instead: {decode(scriptPubKey)}"
            )
        return "nulldata", scriptPubKey[3:], 0
    raise ValueError("invalid 78 bytes nulldata script length")


def payload_from_pms_scriptPubKey(scriptPubKey: Script) -> Tuple[str, Payloads, int]:
    scriptPubKey = (
        encode(scriptPubKey)
        if isinstance(scriptPubKey, list)
        else bytes_from_octets(scriptPubKey)
    )
    # p2ms [m, pubkeys, n, OP_CHECKMULTISIG]
    scriptPubKey = decode(scriptPubKey)
    m = int(scriptPubKey[0])
    if m < 1 or m > 16:
        raise ValueError(f"invalid m in m-of-n multisignature: {m}")
    n = len(scriptPubKey) - 3
    if n < m or n > 16:
        raise ValueError(f"invalid number of pubkeys in {m}-of-n multisignature: {n}")
    if n != int(scriptPubKey[-2]):
        err_msg = "wrong number of pubkeys "
        err_msg += f"in {m}-of-{int(scriptPubKey[-2])} multisignature: {n}"
        raise ValueError(err_msg)
    keys: List[bytes] = []
    for pk in scriptPubKey[1:-2]:
        if isinstance(pk, int):
            raise ValueError("invalid key in p2ms")
        key = bytes_from_octets(pk, (33, 65))
        keys.append(key)
    return "p2ms", keys, m


def payload_from_scriptPubKey(scriptPubKey: Script) -> Tuple[str, Payloads, int]:
    "Return (scriptPubKey type, payload, m) from the input scriptPubKey."

    scriptPubKey = (
        encode(scriptPubKey)
        if isinstance(scriptPubKey, list)
        else bytes_from_octets(scriptPubKey)
    )
    length = len(scriptPubKey)

    # p2pk [pubkey, OP_CHECKSIG]
    # 0x41{65-byte pubkey}AC or 0x21{33-byte pubkey}AC
    if (
        length == scriptPubKey[0] + 2
        and scriptPubKey[0] in (0x41, 0x21)
        and scriptPubKey[-1] == 0xAC
    ):
        return "p2pk", scriptPubKey[1:-1], 0
    # p2ms [m, pubkeys, n, OP_CHECKMULTISIG]
    elif scriptPubKey[-1] == 0xAE:
        return payload_from_pms_scriptPubKey(scriptPubKey)
    # nulldata [OP_RETURN, data]
    elif length <= 83 and scriptPubKey[0] == 0x6A:
        return payload_from_nulldata_scriptPubKey(scriptPubKey)
    # p2pkh [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
    # 0x76A914{20-byte pubkey_hash}88AC
    elif (
        length == 25
        and scriptPubKey[:3] == b"\x76\xa9\x14"
        and scriptPubKey[-2:] == b"\x88\xac"
    ):
        return "p2pkh", scriptPubKey[3 : length - 2], 0
    # p2sh [OP_HASH160, script_hash, OP_EQUAL]
    # 0xA914{20-byte script_hash}87
    elif length == 23 and scriptPubKey[:2] == b"\xa9\x14" and scriptPubKey[-1] == 0x87:
        return "p2sh", scriptPubKey[2 : length - 1], 0
    # p2wpkh [0, pubkey_hash]
    # 0x0014{20-byte pubkey_hash}
    elif length == 22 and scriptPubKey[:2] == b"\x00\x14":
        return "p2wpkh", scriptPubKey[2:], 0
    # p2wsh [0, script_hash]
    # 0x0020{32-byte script_hash}
    elif length == 34 and scriptPubKey[:2] == b"\x00\x20":
        return "p2wsh", scriptPubKey[2:], 0
    # Unknow scriptPubKey
    else:
        raise ValueError(
            f"unknown scriptPubKey: {len(scriptPubKey)}-bytes length"
            f"; starts with {scriptPubKey[:3].hex()}"
            f", ends with {scriptPubKey[-2:].hex()}: {decode(scriptPubKey)}"
        )


# 1.+2. = 3. scriptPubKey from pubkey/script


def p2pk(key: Key) -> bytes:
    "Return the p2pk scriptPubKey of the provided pubkey."

    payload, _ = pubkeyinfo_from_key(key)
    return scriptPubKey_from_payload("p2pk", payload)


def p2ms(
    keys: List[Key],
    m: int,
    lexicographic_sort: bool = True,
    compressed: Optional[bool] = None,
) -> bytes:
    "Return the m-of-n multi-sig scriptPubKey of the provided keys."

    pk: List[Octets] = [pubkeyinfo_from_key(p, compressed=compressed)[0] for p in keys]
    return scriptPubKey_from_payload("p2ms", pk, m, lexicographic_sort)


def nulldata(data: String) -> bytes:
    "Return the nulldata scriptPubKey of the provided data."

    if isinstance(data, str):
        data = data.encode()
    return scriptPubKey_from_payload("nulldata", data)


def p2pkh(key: Key, compressed: Optional[bool] = None) -> bytes:
    "Return the p2pkh scriptPubKey of the provided key."

    pubkey_h160, _ = hash160_from_key(key, compressed=compressed)
    return scriptPubKey_from_payload("p2pkh", pubkey_h160)


def p2sh(redeem_script: Script) -> bytes:
    "Return the p2sh scriptPubKey of the provided redeem script."

    script_h160 = hash160_from_script(redeem_script)
    return scriptPubKey_from_payload("p2sh", script_h160)


def p2wpkh(key: Key) -> bytes:
    """Return the p2wpkh scriptPubKey of the provided key.

    If the provided key is a public one, it must be compressed.
    """

    pubkey_h160, _ = hash160_from_key(key, compressed=True)
    return scriptPubKey_from_payload("p2wpkh", pubkey_h160)


def p2wsh(redeem_script: Script) -> bytes:
    "Return the p2wsh scriptPubKey of the provided redeem script."

    script_h256 = hash256_from_script(redeem_script)
    return scriptPubKey_from_payload("p2wsh", script_h256)
