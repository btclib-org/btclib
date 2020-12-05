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

from typing import List, Optional, Tuple

from . import varbytes
from .alias import Octets, Script, String
from .exceptions import BTClibValueError
from .hashes import hash160_from_key, hash160_from_script, hash256_from_script
from .script import serialize
from .to_pubkey import Key, pubkeyinfo_from_key
from .utils import bytes_from_octets, bytesio_from_binarydata

# 1. Hash/WitnessProgram from pubkey/script_pubkey

# hash160_from_key, hash160_from_script, and hash256_from_script
# are imported from hashes.py


# 2. script_pubkey from Hash/WitnessProgram and vice versa


def script_pubkey_from_payload(script_type: str, payload: Octets) -> bytes:
    "Return the script_pubkey for the provided script_type and payload."

    script_type = script_type.lower()

    if script_type == "p2ms":
        script_pubkey = bytes_from_octets(payload) + b"\xae"
        if not is_p2ms(script_pubkey):
            raise BTClibValueError("invalid p2ms payload")
        return script_pubkey

    if script_type == "nulldata":
        payload = bytes_from_octets(payload)
        if len(payload) > 80:
            err_msg = f"invalid nulldata script length: {len(payload)} bytes "
            raise BTClibValueError(err_msg)
        return serialize(["OP_RETURN", payload])

    if script_type == "p2pk":
        payload = bytes_from_octets(payload, (33, 65))
        # TODO: check it is a valid pub_key
        return serialize([payload, "OP_CHECKSIG"])

    if script_type == "p2wsh":
        payload = bytes_from_octets(payload, 32)
        return serialize([0, payload])

    if script_type == "p2pkh":
        payload = bytes_from_octets(payload, 20)
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
        payload = bytes_from_octets(payload, 20)
        return serialize(["OP_HASH160", payload, "OP_EQUAL"])

    if script_type == "p2wpkh":
        payload = bytes_from_octets(payload, 20)
        return serialize([0, payload])

    raise BTClibValueError(f"unknown script_pubkey type: {script_type}")


def is_p2pk(script_pubkey: Octets) -> bool:
    script_pubkey = bytes_from_octets(script_pubkey)
    # p2pk [pubkey, OP_CHECKSIG]
    # 0x41{65-byte pubkey}AC or 0x21{33-byte pubkey}AC
    length = len(script_pubkey)
    return (
        length > 34
        and length == script_pubkey[0] + 2
        and script_pubkey[0] in (0x41, 0x21)
        and script_pubkey[-1] == 0xAC
    )


def is_p2pkh(script_pubkey: Octets) -> bool:
    script_pubkey = bytes_from_octets(script_pubkey)
    # p2pkh [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
    # 0x76A914{20-byte pubkey_hash}88AC
    return (
        len(script_pubkey) == 25
        and script_pubkey[:3] == b"\x76\xa9\x14"
        and script_pubkey[-2:] == b"\x88\xac"
    )


def is_p2sh(script_pubkey: Octets) -> bool:
    script_pubkey = bytes_from_octets(script_pubkey)
    # p2sh [OP_HASH160, script_hash, OP_EQUAL]
    # 0xA914{20-byte script_hash}87
    return (
        len(script_pubkey) == 23
        and script_pubkey[:2] == b"\xa9\x14"
        and script_pubkey[-1] == 0x87
    )


def is_p2ms(script_pubkey: Octets) -> bool:
    script_pubkey = bytes_from_octets(script_pubkey)
    # p2ms [m, pubkeys, n, OP_CHECKMULTISIG]
    length = len(script_pubkey)
    if length < 37 or script_pubkey[-1] != 0xAE:
        return False
    m = script_pubkey[0] - 80
    n = script_pubkey[-2] - 80
    if not 0 < m < 17 or not m <= n < 17:
        return False
    stream = bytesio_from_binarydata(script_pubkey[1:-2])
    pub_keys = [varbytes.deserialize(stream) for _ in range(n)]
    if any(len(pub_key) not in (33, 65) for pub_key in pub_keys):
        return False
    # TODO: check all pub_keys are valid
    return not stream.read(1)


def is_nulldata(script_pubkey: Octets) -> bool:
    script_pubkey = bytes_from_octets(script_pubkey)
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


def is_p2wpkh(script_pubkey: Octets) -> bool:
    script_pubkey = bytes_from_octets(script_pubkey)
    # p2wpkh [0, pubkey_hash]
    # 0x0014{20-byte pubkey_hash}
    length = len(script_pubkey)
    return length == 22 and script_pubkey[:2] == b"\x00\x14"


def is_p2wsh(script_pubkey: Octets) -> bool:
    script_pubkey = bytes_from_octets(script_pubkey)
    length = len(script_pubkey)
    return length == 34 and script_pubkey[:2] == b"\x00\x20"


def payload_from_script_pubkey(script_pubkey: Script) -> Tuple[str, bytes]:
    "Return (script_pubkey type, payload) from the input script_pubkey."

    script_pubkey = (
        serialize(script_pubkey)
        if isinstance(script_pubkey, list)
        else bytes_from_octets(script_pubkey)
    )

    if is_p2wpkh(script_pubkey):
        # p2wpkh [0, pubkey_hash]
        # 0x0014{20-byte pubkey_hash}
        return "p2wpkh", script_pubkey[2:]

    if is_p2wsh(script_pubkey):
        # p2wsh [0, script_hash]
        # 0x0020{32-byte script_hash}
        return "p2wsh", script_pubkey[2:]

    if is_p2pk(script_pubkey):
        # p2pk [pubkey, OP_CHECKSIG]
        # 0x41{65-byte pubkey}AC or 0x21{33-byte pubkey}AC
        return "p2pk", script_pubkey[1:-1]

    if is_p2ms(script_pubkey):
        # p2ms [m, pubkeys, n, OP_CHECKMULTISIG]
        return "p2ms", script_pubkey[:-1]

    if is_nulldata(script_pubkey):
        # nulldata [OP_RETURN, data]
        if len(script_pubkey) < 78:
            # OP_RETURN, data length, data up to 75 bytes max
            # 0x6A{1 byte data-length}{data (0-75 bytes)}
            return "nulldata", script_pubkey[2:]

        # OP_RETURN, OP_PUSHDATA1, data length, data min 76 bytes up to 80
        # 0x6A4C{1-byte data-length}{data (76-80 bytes)}
        return "nulldata", script_pubkey[3:]

    if is_p2pkh(script_pubkey):
        # p2pkh [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
        # 0x76A914{20-byte pubkey_hash}88AC
        length = len(script_pubkey)
        return "p2pkh", script_pubkey[3 : length - 2]

    if is_p2sh(script_pubkey):
        # p2sh [OP_HASH160, script_hash, OP_EQUAL]
        # 0xA914{20-byte script_hash}87
        length = len(script_pubkey)
        return "p2sh", script_pubkey[2 : length - 1]

    return "unknown", script_pubkey


# 1.+2. = 3. script_pubkey from key(s)/script


def p2pk(key: Key) -> bytes:
    "Return the p2pk script_pubkey of the provided key."

    payload, _ = pubkeyinfo_from_key(key)
    return script_pubkey_from_payload("p2pk", payload)


def p2ms(
    m: int, keys: List[Key], lexi_sort: bool = True, compressed: Optional[bool] = None
) -> bytes:
    """Return the m-of-n multi-sig script_pubkey of the provided keys.

    BIP67 endorses lexicographica key sorting
    according to compressed key representation.

    Note that sorting uncompressed keys (leading 0x04 byte) results
    in a different order than sorting the same keys in compressed
    (leading 0x02 or 0x03 bytes) representation.

    https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
    """
    m += 80
    payload = m.to_bytes(1, byteorder="big")
    pub_keys = [pubkeyinfo_from_key(k, compressed=compressed)[0] for k in keys]
    if lexi_sort:
        pub_keys = sorted(pub_keys)
    payload += b"".join([varbytes.serialize(k) for k in pub_keys])
    n = len(keys) + 80
    payload += n.to_bytes(1, byteorder="big")
    return script_pubkey_from_payload("p2ms", payload)


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
