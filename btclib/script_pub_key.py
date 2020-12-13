#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"ScriptPubKey functions."

from typing import Callable, List, Optional, Tuple

from btclib.sec_point import point_from_octets

from . import var_bytes
from .alias import Octets, String
from .exceptions import BTClibValueError
from .hashes import hash160_from_key
from .script import serialize
from .to_pub_key import Key, pub_keyinfo_from_key
from .utils import bytes_from_octets, bytesio_from_binarydata, hash160, sha256

# 1. Hash/WitnessProgram from pub_key/script_pub_key

# hash160_from_key, hash160, and sha256
# are imported from hashes.py and utils.py


# 2. script_pub_key from Hash/WitnessProgram and vice versa


def _is_funct(assert_funct: Callable[[Octets], None], script_pub_key: Octets) -> bool:

    try:
        # if the assert function detects a problem, it must rise an Exception
        assert_funct(script_pub_key)
    # must always return a bool: all Exceptions are catched
    except Exception:  # pylint: disable=broad-except
        return False
    return True


def assert_p2pk(script_pub_key: Octets) -> None:
    script_pub_key = bytes_from_octets(script_pub_key, (35, 67))
    # p2pk [pub_key, OP_CHECKSIG]
    # 0x41{65-byte pub_key}AC
    # or
    # 0x21{33-byte pub_key}AC
    if script_pub_key[-1] != 0xAC:
        raise BTClibValueError("missing final OP_CHECKSIG")

    len_marker = script_pub_key[0]
    length = len(script_pub_key)
    if length == 35:
        if len_marker != 0x21:
            err_msg = f"invalid pub_key length marker: {len_marker}"
            err_msg += f" instead of {0x21}"
            raise BTClibValueError(err_msg)
    elif length == 67:
        if len_marker != 0x41:
            err_msg = f"invalid pub_key length marker: {len_marker}"
            err_msg += f" instead of {0x41}"
            raise BTClibValueError(err_msg)

    pub_key = script_pub_key[1:-1]
    point_from_octets(pub_key)


def is_p2pk(script_pub_key: Octets) -> bool:
    return _is_funct(assert_p2pk, script_pub_key)


def assert_p2pkh(script_pub_key: Octets) -> None:
    script_pub_key = bytes_from_octets(script_pub_key, 25)
    # p2pkh [OP_DUP, OP_HASH160, pub_key hash, OP_EQUALVERIFY, OP_CHECKSIG]
    # 0x76A914{20-byte pub_key_hash}88AC
    if script_pub_key[-2:] != b"\x88\xac":
        raise BTClibValueError("missing final OP_EQUALVERIFY, OP_CHECKSIG")
    if script_pub_key[:2] != b"\x76\xa9":
        raise BTClibValueError("missing leading OP_DUP, OP_HASH160")
    if script_pub_key[2] != 0x14:
        err_msg = f"invalid pub_key hash length marker: {script_pub_key[2]}"
        err_msg += f" instead of {0x14}"
        raise BTClibValueError(err_msg)


def is_p2pkh(script_pub_key: Octets) -> bool:
    return _is_funct(assert_p2pkh, script_pub_key)


def assert_p2sh(script_pub_key: Octets) -> None:
    script_pub_key = bytes_from_octets(script_pub_key, 23)
    # p2sh [OP_HASH160, redeem_script hash, OP_EQUAL]
    # 0xA914{20-byte redeem_script hash}87
    if script_pub_key[-1] != 0x87:
        raise BTClibValueError("missing final OP_EQUAL")
    if script_pub_key[0] != 0xA9:
        raise BTClibValueError("missing leading OP_HASH160")
    if script_pub_key[1] != 0x14:
        err_msg = f"invalid redeem script hash length marker: {script_pub_key[1]}"
        err_msg += f" instead of {0x14}"
        raise BTClibValueError(err_msg)


def is_p2sh(script_pub_key: Octets) -> bool:
    return _is_funct(assert_p2sh, script_pub_key)


def assert_p2ms(script_pub_key: Octets) -> None:
    script_pub_key = bytes_from_octets(script_pub_key)
    # p2ms [m, pub_keys, n, OP_CHECKMULTISIG]
    length = len(script_pub_key)
    if length < 37:
        raise BTClibValueError(f"invalid length {length}")
    if script_pub_key[-1] != 0xAE:
        raise BTClibValueError("missing final OP_CHECKMULTISIG")
    m = script_pub_key[0] - 80
    if not 0 < m < 17:
        raise BTClibValueError(f"invalid m in m-of-n: {m}")
    n = script_pub_key[-2] - 80
    if not m <= n < 17:
        raise BTClibValueError(f"invalid m-of-n: {m}-of-{n}")

    stream = bytesio_from_binarydata(script_pub_key[1:-2])
    for _ in range(n):
        pub_key = var_bytes.deserialize(stream)
        point_from_octets(pub_key)

    if stream.read(1):
        raise BTClibValueError("invalid extra data")


def is_p2ms(script_pub_key: Octets) -> bool:
    return _is_funct(assert_p2ms, script_pub_key)


def assert_nulldata(script_pub_key: Octets) -> None:
    script_pub_key = bytes_from_octets(script_pub_key)
    # nulldata [OP_RETURN, data]
    length = len(script_pub_key)
    if length == 0:
        raise BTClibValueError("null length")
    if script_pub_key[0] != 0x6A:
        raise BTClibValueError("missing leading OP_RETURN")

    if length == 78 or length >= 84:
        raise BTClibValueError(f"invalid length {length}")

    # OP_RETURN, data length, data up to 75 bytes max
    # 0x6A{1 byte data-length}{data (0-75 bytes)}
    if length < 78:
        if script_pub_key[1] != length - 2:
            raise BTClibValueError(f"invalid data length marker {script_pub_key[1]}")
    # OP_RETURN, OP_PUSHDATA1, data length, data min 76 bytes up to 80
    # 0x6A4C{1-byte data-length}{data (76-80 bytes)}
    elif script_pub_key[1] != 0x4C or script_pub_key[2] != length - 3:
        err_msg = f"invalid data length marker {script_pub_key[1:2].hex()}"
        raise BTClibValueError(err_msg)


def is_nulldata(script_pub_key: Octets) -> bool:
    return _is_funct(assert_nulldata, script_pub_key)


def assert_p2wpkh(script_pub_key: Octets) -> None:
    script_pub_key = bytes_from_octets(script_pub_key, 22)
    # p2wpkh [0, pub_key hash]
    # 0x0014{20-byte pub_key hash}
    if script_pub_key[0] != 0:
        err_msg = f"invalid witness version: {script_pub_key[0]}"
        err_msg += f" instead of {0}"
        raise BTClibValueError(err_msg)
    if script_pub_key[1] != 0x14:
        err_msg = f"invalid pub_key hash length marker: {script_pub_key[1]}"
        err_msg += f" instead of {0x14}"
        raise BTClibValueError(err_msg)


def is_p2wpkh(script_pub_key: Octets) -> bool:
    return _is_funct(assert_p2wpkh, script_pub_key)


def assert_p2wsh(script_pub_key: Octets) -> None:
    script_pub_key = bytes_from_octets(script_pub_key, 34)
    # p2wsh [0, redeem_script hash]
    # 0x0020{32-byte redeem_script hash}
    if script_pub_key[0] != 0:
        err_msg = f"invalid witness version: {script_pub_key[0]}"
        err_msg += f" instead of {0}"
        raise BTClibValueError(err_msg)
    if script_pub_key[1] != 0x20:
        err_msg = f"invalid redeem script hash length marker: {script_pub_key[1]}"
        err_msg += f" instead of {0x20}"
        raise BTClibValueError(err_msg)


def is_p2wsh(script_pub_key: Octets) -> bool:
    return _is_funct(assert_p2wsh, script_pub_key)


def script_pub_key_from_payload(script_type: str, payload: Octets) -> bytes:
    "Return the script_pub_key for the provided script_type and payload."

    script_type = script_type.lower()

    if script_type == "p2ms":
        script_pub_key = bytes_from_octets(payload) + b"\xae"
        if not is_p2ms(script_pub_key):
            raise BTClibValueError("invalid p2ms payload")
        return script_pub_key

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

    raise BTClibValueError(f"unknown script_pub_key type: {script_type}")


def payload_from_script_pub_key(script_pub_key: Octets) -> Tuple[str, bytes]:
    "Return (script_pub_key type, payload) from the input script_pub_key."

    script_pub_key = bytes_from_octets(script_pub_key)

    if is_p2wpkh(script_pub_key):
        # p2wpkh [0, pub_key_hash]
        # 0x0014{20-byte pub_key_hash}
        return "p2wpkh", script_pub_key[2:]

    if is_p2wsh(script_pub_key):
        # p2wsh [0, script_hash]
        # 0x0020{32-byte script_hash}
        return "p2wsh", script_pub_key[2:]

    if is_p2pk(script_pub_key):
        # p2pk [pub_key, OP_CHECKSIG]
        # 0x41{65-byte pub_key}AC or 0x21{33-byte pub_key}AC
        return "p2pk", script_pub_key[1:-1]

    if is_p2ms(script_pub_key):
        # p2ms [m, pub_keys, n, OP_CHECKMULTISIG]
        return "p2ms", script_pub_key[:-1]

    if is_nulldata(script_pub_key):
        # nulldata [OP_RETURN, data]
        if len(script_pub_key) < 78:
            # OP_RETURN, data length, data up to 75 bytes max
            # 0x6A{1 byte data-length}{data (0-75 bytes)}
            return "nulldata", script_pub_key[2:]

        # OP_RETURN, OP_PUSHDATA1, data length, data min 76 bytes up to 80
        # 0x6A4C{1-byte data-length}{data (76-80 bytes)}
        return "nulldata", script_pub_key[3:]

    if is_p2pkh(script_pub_key):
        # p2pkh [OP_DUP, OP_HASH160, pub_key_hash, OP_EQUALVERIFY, OP_CHECKSIG]
        # 0x76A914{20-byte pub_key_hash}88AC
        length = len(script_pub_key)
        return "p2pkh", script_pub_key[3 : length - 2]

    if is_p2sh(script_pub_key):
        # p2sh [OP_HASH160, script_hash, OP_EQUAL]
        # 0xA914{20-byte script_hash}87
        length = len(script_pub_key)
        return "p2sh", script_pub_key[2 : length - 1]

    return "unknown", script_pub_key


# 1.+2. = 3. script_pub_key from key(s)/script


def p2pk(key: Key) -> bytes:
    "Return the p2pk script_pub_key of the provided key."

    payload, _ = pub_keyinfo_from_key(key)
    return script_pub_key_from_payload("p2pk", payload)


def p2ms(
    m: int, keys: List[Key], lexi_sort: bool = True, compressed: Optional[bool] = None
) -> bytes:
    """Return the m-of-n multi-sig script_pub_key of the provided keys.

    BIP67 endorses lexicographica key sorting
    according to compressed key representation.

    Note that sorting uncompressed keys (leading 0x04 byte) results
    in a different order than sorting the same keys in compressed
    (leading 0x02 or 0x03 bytes) representation.

    https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
    """
    m += 80
    payload = m.to_bytes(1, byteorder="big", signed=False)
    pub_keys = [pub_keyinfo_from_key(k, compressed=compressed)[0] for k in keys]
    if lexi_sort:
        pub_keys = sorted(pub_keys)
    payload += b"".join([var_bytes.serialize(k) for k in pub_keys])
    n = len(keys) + 80
    payload += n.to_bytes(1, byteorder="big", signed=False)
    return script_pub_key_from_payload("p2ms", payload)


def nulldata(data: String) -> bytes:
    "Return the nulldata script_pub_key of the provided data."

    if isinstance(data, str):
        # do not strip spaces
        data = data.encode()

    return script_pub_key_from_payload("nulldata", data)


def p2pkh(key: Key, compressed: Optional[bool] = None) -> bytes:
    "Return the p2pkh script_pub_key of the provided key."

    pub_key_h160, _ = hash160_from_key(key, compressed=compressed)
    return script_pub_key_from_payload("p2pkh", pub_key_h160)


def p2sh(redeem_script: Octets) -> bytes:
    "Return the p2sh script_pub_key of the provided redeem script."

    script_h160 = hash160(redeem_script)
    return script_pub_key_from_payload("p2sh", script_h160)


def p2wpkh(key: Key) -> bytes:
    """Return the p2wpkh script_pub_key of the provided key.

    If the provided key is a public one, it must be compressed.
    """

    pub_key_h160, _ = hash160_from_key(key, compressed=True)
    return script_pub_key_from_payload("p2wpkh", pub_key_h160)


def p2wsh(redeem_script: Octets) -> bytes:
    "Return the p2wsh script_pub_key of the provided redeem script."

    script_h256 = sha256(redeem_script)
    return script_pub_key_from_payload("p2wsh", script_h256)
