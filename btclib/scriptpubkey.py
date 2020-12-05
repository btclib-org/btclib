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

from .alias import Octets, Script, ScriptToken, String
from .exceptions import BTClibValueError
from .hashes import hash160_from_key, hash160_from_script, hash256_from_script
from .script import deserialize, serialize
from .to_pubkey import Key, pubkeyinfo_from_key
from .utils import bytes_from_octets

# 1. Hash/WitnessProgram from pubkey/script_pubkey

# hash160_from_key, hash160_from_script, and hash256_from_script
# are imported from hashes.py


# 2. script_pubkey from Hash/WitnessProgram and vice versa


def script_pubkey_from_payload(
    s_type: str,
    payloads: Union[Octets, List[Octets]],
    m: int = 0,
    lexicographic_sort: bool = True,
) -> bytes:
    """Return the requested script_pubkey for the provided payload.

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
        errmsg = f"invalid m for {script_type} script_pubkey: {m}"
        raise BTClibValueError(errmsg)

    if isinstance(payloads, list):
        if script_type == "p2ms":
            if m < 1 or m > 16:
                raise BTClibValueError(f"invalid m in m-of-n multisignature: {m}")
            if lexicographic_sort:
                # BIP67 compliant
                payloads = sorted(payloads)
            n = len(payloads)
            if n < m:
                raise BTClibValueError(
                    f"number-of-pubkeys < m in {m}-of-n multisignature: {n}"
                )
            if n > 16:
                raise BTClibValueError(
                    f"too many pubkeys in m-of-n multisignature: {n}"
                )
            script_pubkey: List[ScriptToken] = [m]
            for key in payloads:
                key = bytes_from_octets(key, (33, 65))
                script_pubkey.append(key)
            script_pubkey.append(n)
            script_pubkey.append("OP_CHECKMULTISIG")
            return serialize(script_pubkey)
        errmsg = f"invalid list of Octets for {script_type} script_pubkey"
        raise BTClibValueError(errmsg)

    if script_type == "nulldata":
        payload = bytes_from_octets(payloads)
        if len(payload) > 80:
            err_msg = f"invalid nulldata script length: {len(payload)} bytes "
            raise BTClibValueError(err_msg)
        return serialize(["OP_RETURN", payload])

    if script_type == "p2pk":
        payload = bytes_from_octets(payloads, (33, 65))
        return serialize([payload, "OP_CHECKSIG"])

    if script_type == "p2wsh":
        payload = bytes_from_octets(payloads, 32)
        return serialize([0, payload])

    if script_type == "p2pkh":
        payload = bytes_from_octets(payloads, 20)
        return serialize(
            [
                "OP_DUP",
                "OP_HASH160",
                payload,
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        )

    if script_type == "p2sh":
        payload = bytes_from_octets(payloads, 20)
        return serialize(["OP_HASH160", payload, "OP_EQUAL"])

    if script_type == "p2wpkh":
        payload = bytes_from_octets(payloads, 20)
        return serialize([0, payload])

    raise BTClibValueError(f"unknown script_pubkey type: {script_type}")


Payloads = Union[bytes, List[bytes]]


def _payload_from_nulldata_script_pubkey(
    script_pubkey: Script,
) -> Tuple[str, Payloads, int]:
    script_pubkey = (
        serialize(script_pubkey)
        if isinstance(script_pubkey, list)
        else bytes_from_octets(script_pubkey)
    )

    if len(script_pubkey) < 78:
        # OP_RETURN, data length, data up to 75 bytes max
        # 0x6A{1 byte data-length}{data (0-75 bytes)}
        return "nulldata", script_pubkey[2:], 0

    # OP_RETURN, OP_PUSHDATA1, data length, data min 76 bytes up to 80
    # 0x6A4C{1-byte data-length}{data (76-80 bytes)}
    return "nulldata", script_pubkey[3:], 0


def _payload_from_pms_script_pubkey(script_pubkey: Script) -> Tuple[str, Payloads, int]:
    script_pubkey = (
        serialize(script_pubkey)
        if isinstance(script_pubkey, list)
        else bytes_from_octets(script_pubkey)
    )
    # p2ms [m, pubkeys, n, OP_CHECKMULTISIG]
    script_pubkey = deserialize(script_pubkey)
    m = int(script_pubkey[0])
    if m < 1 or m > 16:
        raise BTClibValueError(f"invalid m in m-of-n multisignature: {m}")
    n = len(script_pubkey) - 3
    if n < m or n > 16:
        raise BTClibValueError(
            f"invalid number of pubkeys in {m}-of-n multisignature: {n}"
        )
    if n != int(script_pubkey[-2]):
        err_msg = "wrong number of pubkeys "
        err_msg += f"in {m}-of-{int(script_pubkey[-2])} multisignature: {n}"
        raise BTClibValueError(err_msg)
    keys: List[bytes] = []
    for pk in script_pubkey[1:-2]:
        if isinstance(pk, int):
            raise BTClibValueError("invalid key in p2ms")
        key = bytes_from_octets(pk, (33, 65))
        keys.append(key)
    return "p2ms", keys, m


def is_p2pk(script_pubkey: bytes) -> bool:
    # p2pk [pubkey, OP_CHECKSIG]
    # 0x41{65-byte pubkey}AC or 0x21{33-byte pubkey}AC
    length = len(script_pubkey)
    return (
        length > 34
        and length == script_pubkey[0] + 2
        and script_pubkey[0] in (0x41, 0x21)
        and script_pubkey[-1] == 0xAC
    )


def is_p2pkh(script_pubkey: bytes) -> bool:
    # p2pkh [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
    # 0x76A914{20-byte pubkey_hash}88AC
    return (
        len(script_pubkey) == 25
        and script_pubkey[:3] == b"\x76\xa9\x14"
        and script_pubkey[-2:] == b"\x88\xac"
    )


def is_p2sh(script_pubkey: bytes) -> bool:
    # p2sh [OP_HASH160, script_hash, OP_EQUAL]
    # 0xA914{20-byte script_hash}87
    return (
        len(script_pubkey) == 23
        and script_pubkey[:2] == b"\xa9\x14"
        and script_pubkey[-1] == 0x87
    )


def is_p2ms(script_pubkey: bytes) -> bool:
    # p2ms [m, pubkeys, n, OP_CHECKMULTISIG]
    length = len(script_pubkey)
    return length > 0 and script_pubkey[-1] == 0xAE


def is_nulldata(script_pubkey: bytes) -> bool:
    # nulldata [OP_RETURN, data]
    length = len(script_pubkey)
    if length < 78:
        # OP_RETURN, data length, data up to 75 bytes max
        # 0x6A{1 byte data-length}{data (0-75 bytes)}
        return (
            length > 1 and script_pubkey[0] == 0x6A and script_pubkey[1] == length - 2
        )
    return (
        # OP_RETURN, OP_PUSHDATA1, data length, data min 76 bytes up to 80
        # 0x6A4C{1-byte data-length}{data (76-80 bytes)}
        78 < length < 84
        and script_pubkey[0] == 0x6A
        and script_pubkey[1] == 0x4C
        and script_pubkey[2] == length - 3
    )


def is_p2wpkh(script_pubkey: bytes) -> bool:
    # p2wpkh [0, pubkey_hash]
    # 0x0014{20-byte pubkey_hash}
    length = len(script_pubkey)
    return length == 22 and script_pubkey[:2] == b"\x00\x14"


def is_p2wsh(script_pubkey: bytes) -> bool:
    # p2wsh [0, script_hash]
    # 0x0020{32-byte script_hash}
    length = len(script_pubkey)
    return length == 34 and script_pubkey[:2] == b"\x00\x20"


def payload_from_script_pubkey(script_pubkey: Script) -> Tuple[str, Payloads, int]:
    "Return (script_pubkey type, payload, m) from the input script_pubkey."

    script_pubkey = (
        serialize(script_pubkey)
        if isinstance(script_pubkey, list)
        else bytes_from_octets(script_pubkey)
    )

    if is_p2wpkh(script_pubkey):
        return "p2wpkh", script_pubkey[2:], 0

    if is_p2wsh(script_pubkey):
        return "p2wsh", script_pubkey[2:], 0

    if is_p2pk(script_pubkey):
        return "p2pk", script_pubkey[1:-1], 0

    if is_p2ms(script_pubkey):
        return _payload_from_pms_script_pubkey(script_pubkey)

    if is_nulldata(script_pubkey):
        return _payload_from_nulldata_script_pubkey(script_pubkey)

    if is_p2pkh(script_pubkey):
        length = len(script_pubkey)
        return "p2pkh", script_pubkey[3 : length - 2], 0

    if is_p2sh(script_pubkey):
        length = len(script_pubkey)
        return "p2sh", script_pubkey[2 : length - 1], 0

    return "unknown", script_pubkey, 0


# 1.+2. = 3. script_pubkey from pubkey/script


def p2pk(key: Key) -> bytes:
    "Return the p2pk script_pubkey of the provided pubkey."

    payload, _ = pubkeyinfo_from_key(key)
    return script_pubkey_from_payload("p2pk", payload)


def p2ms(
    keys: List[Key],
    m: int,
    lexicographic_sort: bool = True,
    compressed: Optional[bool] = None,
) -> bytes:
    "Return the m-of-n multi-sig script_pubkey of the provided keys."

    pk: List[Octets] = [pubkeyinfo_from_key(p, compressed=compressed)[0] for p in keys]
    return script_pubkey_from_payload("p2ms", pk, m, lexicographic_sort)


def nulldata(data: String) -> bytes:
    "Return the nulldata script_pubkey of the provided data."

    if isinstance(data, str):
        data = data.encode()
    return script_pubkey_from_payload("nulldata", data)


def p2pkh(key: Key, compressed: Optional[bool] = None) -> bytes:
    "Return the p2pkh script_pubkey of the provided key."

    pubkey_h160, _ = hash160_from_key(key, compressed=compressed)
    return script_pubkey_from_payload("p2pkh", pubkey_h160)


def p2sh(redeem_script: Script) -> bytes:
    "Return the p2sh script_pubkey of the provided redeem script."

    script_h160 = hash160_from_script(redeem_script)
    return script_pubkey_from_payload("p2sh", script_h160)


def p2wpkh(key: Key) -> bytes:
    """Return the p2wpkh script_pubkey of the provided key.

    If the provided key is a public one, it must be compressed.
    """

    pubkey_h160, _ = hash160_from_key(key, compressed=True)
    return script_pubkey_from_payload("p2wpkh", pubkey_h160)


def p2wsh(redeem_script: Script) -> bytes:
    "Return the p2wsh script_pubkey of the provided redeem script."

    script_h256 = hash256_from_script(redeem_script)
    return script_pubkey_from_payload("p2wsh", script_h256)
