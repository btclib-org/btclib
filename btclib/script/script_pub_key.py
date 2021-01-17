#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"ScriptPubKey class and functions."

from typing import Callable, List, Optional, Sequence, Tuple, Type, TypeVar

from btclib import var_bytes
from btclib.alias import Octets, String
from btclib.b32 import address_from_witness, witness_from_address
from btclib.b58 import address_from_h160, h160_from_address
from btclib.ecc.sec_point import point_from_octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160_from_key
from btclib.network import NETWORKS
from btclib.script.script import Command, Script, serialize
from btclib.to_pub_key import Key, pub_keyinfo_from_key
from btclib.utils import bytes_from_octets, bytesio_from_binarydata, hash160, sha256


def has_segwit_prefix(addr: String) -> bool:

    str_addr = addr.strip().lower() if isinstance(addr, str) else addr.decode("ascii")
    return any(str_addr.startswith(NETWORKS[net].hrp + "1") for net in NETWORKS)


def address(script_pub_key: Octets, network: str = "mainnet") -> str:
    "Return the bech32/base58 address from a script_pub_key."

    if script_pub_key:
        script_type, payload = type_and_payload(script_pub_key)
        if script_type == "p2pkh":
            prefix = NETWORKS[network].p2pkh
            return address_from_h160(prefix, payload, network)
        if script_type == "p2sh":
            prefix = NETWORKS[network].p2sh
            return address_from_h160(prefix, payload, network)
        if script_type in ("p2wsh", "p2wpkh"):
            return address_from_witness(0, payload, network)

    # not script_pub_key
    # or
    # script_type in ("p2pk", "p2ms", "nulldata", "unknown")
    return ""


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
        pub_key = var_bytes.parse(stream)
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


def type_and_payload(script_pub_key: Octets) -> Tuple[str, bytes]:
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


_ScriptPubKey = TypeVar("_ScriptPubKey", bound="ScriptPubKey")


class ScriptPubKey(Script):
    network: str

    @property
    def type(self) -> str:
        "Return (script_pub_key type, payload)."

        return type_and_payload(self.script)[0]

    @property
    def type_and_payload(self) -> Tuple[str, bytes]:
        "Return (script_pub_key type, payload)."

        return type_and_payload(self.script)

    @property
    def address(self) -> str:
        "Return the bech32/base58 address."

        return address(self.script, self.network)

    @property
    def addresses(self) -> List[str]:
        "Return the addresses, if any."
        return [self.address]

    def __init__(
        self,
        script: Octets,
        network: str = "mainnet",
        check_validity: bool = True,
    ) -> None:
        self.network = network
        super().__init__(script, check_validity=False)
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        super().assert_valid()
        if self.network not in NETWORKS:
            raise BTClibValueError(f"unknown network: {self.network}")

    @classmethod
    def from_type_and_payload(
        cls: Type[_ScriptPubKey],
        script_type: str,
        payload: Octets,
        network: str = "mainnet",
        check_validity: bool = True,
    ) -> _ScriptPubKey:
        "Return the ScriptPubKey of the provided script_type and payload."
        # sourcery skip: switch

        script_type = script_type.lower()

        if script_type == "p2ms":
            script = bytes_from_octets(payload) + b"\xae"
            if not is_p2ms(script):
                raise BTClibValueError("invalid p2ms payload")
            return cls(script, network, check_validity)

        cmds: List[Command] = []

        if script_type == "nulldata":
            payload = bytes_from_octets(payload)
            if len(payload) > 80:
                err_msg = f"invalid nulldata payload length: {len(payload)} bytes "
                raise BTClibValueError(err_msg)
            cmds = ["OP_RETURN", payload]

        if script_type == "p2pk":
            payload = bytes_from_octets(payload, (33, 65))
            # TODO: check it is a valid pub_key
            cmds = [payload, "OP_CHECKSIG"]

        if script_type == "p2pkh":
            payload = bytes_from_octets(payload, 20)
            cmds = ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]

        if script_type == "p2sh":
            payload = bytes_from_octets(payload, 20)
            cmds = ["OP_HASH160", payload, "OP_EQUAL"]

        wit_ver = 0
        if script_type == "p2wsh":
            wit_prg = bytes_from_octets(payload, 32)
            cmds = [wit_ver, wit_prg]

        if script_type == "p2wpkh":
            wit_prg = bytes_from_octets(payload, 20)
            cmds = [wit_ver, wit_prg]

        if cmds:
            return cls(serialize(cmds), network, check_validity)
        raise BTClibValueError(f"unknown ScriptPubKey type: {script_type}")

    @classmethod
    def from_address(
        cls: Type[_ScriptPubKey], addr: String, check_validity: bool = True
    ) -> _ScriptPubKey:
        "Return the ScriptPubKey of the input bech32/base58 address."

        if has_segwit_prefix(addr):
            # also check witness validity
            wit_ver, wit_prg, network, is_script_hash = witness_from_address(addr)
            if wit_ver != 0:
                raise BTClibValueError(f"unmanaged witness version: {wit_ver}")
            return cls(serialize([wit_ver, wit_prg]), network, check_validity)

        _, h160, network, is_script_hash = h160_from_address(addr)
        if is_script_hash:
            return cls(
                serialize(["OP_HASH160", h160, "OP_EQUAL"]), network, check_validity
            )
        commands: List[Command] = [
            "OP_DUP",
            "OP_HASH160",
            h160,
            "OP_EQUALVERIFY",
            "OP_CHECKSIG",
        ]
        return cls(serialize(commands), network, check_validity)

    @classmethod
    def p2pk(
        cls: Type[_ScriptPubKey],
        key: Key,
        network: Optional[str] = None,
        check_validity: bool = True,
    ) -> _ScriptPubKey:
        "Return the p2pk ScriptPubKey of the provided Key."
        payload, network = pub_keyinfo_from_key(key, network)
        return cls.from_type_and_payload("p2pk", payload, network, check_validity)

    @classmethod
    def p2ms(
        cls: Type[_ScriptPubKey],
        m: int,
        keys: Sequence[Key],
        network: Optional[str] = None,
        compressed: Optional[bool] = None,
        lexi_sort: bool = True,
        check_validity: bool = True,
    ) -> _ScriptPubKey:
        """Return the m-of-n multi-sig ScriptPubKey of the provided keys.

        BIP67 endorses lexicographica key sorting
        according to compressed key representation.

        Note that sorting uncompressed keys (leading 0x04 byte) results
        in a different order than sorting the same keys in compressed
        (leading 0x02 or 0x03 bytes) representation.

        https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
        """
        n = len(keys)
        if not 0 < n < 17:
            raise BTClibValueError(f"invalid n in m-of-n: {n}")
        if not 0 < m <= n:
            raise BTClibValueError(f"invalid m in m-of-n: {m}-of-{n}")

        m += 80
        payload = m.to_bytes(1, byteorder="big", signed=False)
        pub_key, network = pub_keyinfo_from_key(keys[0], network, compressed)
        pub_keys = [pub_key] + [
            pub_keyinfo_from_key(k, network, compressed)[0] for k in keys[1:]
        ]
        if lexi_sort:
            pub_keys = sorted(pub_keys)
        payload += b"".join([var_bytes.serialize(k) for k in pub_keys])
        n += 80
        payload += n.to_bytes(1, byteorder="big", signed=False)
        return cls.from_type_and_payload("p2ms", payload, network, check_validity)

    @classmethod
    def nulldata(
        cls: Type[_ScriptPubKey],
        data: String,
        network: str = "mainnet",
        check_validity: bool = True,
    ) -> _ScriptPubKey:
        "Return the nulldata ScriptPubKey of the provided data."

        if isinstance(data, str):
            # do not strip spaces
            data = data.encode()

        return cls.from_type_and_payload("nulldata", data, network, check_validity)

    @classmethod
    def p2pkh(
        cls: Type[_ScriptPubKey],
        key: Key,
        compressed: Optional[bool] = None,
        network: Optional[str] = None,
        check_validity: bool = True,
    ) -> _ScriptPubKey:
        "Return the p2pkh ScriptPubKey of the provided key."

        pub_key_h160, network = hash160_from_key(key, network, compressed=compressed)
        return cls.from_type_and_payload("p2pkh", pub_key_h160, network, check_validity)

    @classmethod
    def p2sh(
        cls: Type[_ScriptPubKey],
        redeem_script: Octets,
        network: str = "mainnet",
        check_validity: bool = True,
    ) -> _ScriptPubKey:
        "Return the p2sh ScriptPubKey of the provided redeem script."

        script_h160 = hash160(redeem_script)
        return cls.from_type_and_payload("p2sh", script_h160, network, check_validity)

    @classmethod
    def p2wpkh(
        cls: Type[_ScriptPubKey],
        key: Key,
        check_validity: bool = True,
    ) -> _ScriptPubKey:
        """Return the p2wpkh ScriptPubKey of the provided key.

        If the provided key is a public one, it must be compressed.
        """

        pub_key_h160, network = hash160_from_key(key, compressed=True)
        return cls.from_type_and_payload(
            "p2wpkh", pub_key_h160, network, check_validity
        )

    @classmethod
    def p2wsh(
        cls: Type[_ScriptPubKey],
        redeem_script: Octets,
        network: str = "mainnet",
        check_validity: bool = True,
    ) -> _ScriptPubKey:
        "Return the p2wsh ScriptPubKey of the provided redeem script."

        script_h256 = sha256(redeem_script)
        return cls.from_type_and_payload("p2wsh", script_h256, network, check_validity)
