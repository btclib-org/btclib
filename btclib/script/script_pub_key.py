#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"ScriptPubKey class and functions."

from typing import Callable, List, Optional, Sequence, Tuple, Type

from btclib import b32, b58, var_bytes
from btclib.alias import Octets, String
from btclib.ecc.sec_point import point_from_octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.network import NETWORKS
from btclib.script.script import Command, Script, op_int, serialize
from btclib.script.taproot import TaprootScriptTree, output_pubkey
from btclib.to_pub_key import Key, pub_keyinfo_from_key
from btclib.utils import bytes_from_octets, bytesio_from_binarydata


def address(script_pub_key: Octets, network: str = "mainnet") -> str:
    "Return the bech32/base58 address from a script_pub_key."

    if script_pub_key:
        script_type, payload = type_and_payload(script_pub_key)
        if script_type in ("p2pkh", "p2sh"):
            return b58.address_from_h160(script_type, payload, network)
        if script_type in ("p2wsh", "p2wpkh"):
            return b32.address_from_witness(0, payload, network)
        if script_type == "p2tr":
            return b32.address_from_witness(1, payload, network)

    # not script_pub_key
    # or
    # script_type in ("p2pk", "p2ms", "nulldata", "unknown")
    return ""


def addresses(script_pub_key: Octets, network: str = "mainnet") -> List[str]:
    "Return the p2pkh addresses of the pub_keys used in a p2ms script_pub_key."

    script_pub_key = bytes_from_octets(script_pub_key)
    # p2ms [m, pub_keys, n, OP_CHECKMULTISIG]
    length = len(script_pub_key)
    if length < 37:
        raise BTClibValueError(f"invalid p2ms length {length}")
    if script_pub_key[-1] != 0xAE:
        raise BTClibValueError("missing final OP_CHECKMULTISIG")
    m = script_pub_key[0] - 80
    if not 0 < m < 17:
        raise BTClibValueError(f"invalid m in m-of-n: {m}")
    n = script_pub_key[-2] - 80
    if not m <= n < 17:
        raise BTClibValueError(f"invalid m-of-n: {m}-of-{n}")

    stream = bytesio_from_binarydata(script_pub_key[1:-2])
    pub_keys = [var_bytes.parse(stream) for _ in range(n)]

    if stream.read(1):
        raise BTClibValueError("invalid p2ms script_pub_key size")

    return [b58.p2pkh(pub_key, network) for pub_key in pub_keys]


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
    addresses(script_pub_key)


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
    # p2wpkh [OP_0, pub_key hash]
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
    # p2wsh [OP_0, redeem_script hash]
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


def assert_p2tr(script_pub_key: Octets) -> None:
    script_pub_key = bytes_from_octets(script_pub_key, 34)
    # p2wtr [OP_1, redeem_script hash]
    # 0x0120{32-byte redeem_script hash}
    if script_pub_key[0] != 0x51:  # OP_1 = b"\x51",
        err_msg = f"invalid witness version: {script_pub_key[0]}"
        err_msg += f" instead of {0}"
        raise BTClibValueError(err_msg)
    if script_pub_key[1] != 0x20:
        err_msg = f"invalid redeem script hash length marker: {script_pub_key[1]}"
        err_msg += f" instead of {0x20}"
        raise BTClibValueError(err_msg)


def is_p2tr(script_pub_key: Octets) -> bool:
    return _is_funct(assert_p2tr, script_pub_key)


def type_and_payload(script_pub_key: Octets) -> Tuple[str, bytes]:
    "Return (script_pub_key type, payload) from the input script_pub_key."

    script_pub_key = bytes_from_octets(script_pub_key)

    if is_p2pk(script_pub_key):
        # p2pk [pub_key, OP_CHECKSIG]
        # 0x41{65-byte pub_key}AC or 0x21{33-byte pub_key}AC
        return "p2pk", script_pub_key[1:-1]

    if is_p2ms(script_pub_key):
        # p2ms [m, pub_keys, n, OP_CHECKMULTISIG]
        return "p2ms", script_pub_key[:-1]

    if is_p2pkh(script_pub_key):
        # p2pkh [OP_DUP, OP_HASH160, pub_key_hash, OP_EQUALVERIFY, OP_CHECKSIG]
        # 0x76A914{20-byte pub_key_hash}88AC
        return "p2pkh", script_pub_key[3:-2]

    if is_p2sh(script_pub_key):
        # p2sh [OP_HASH160, script_hash, OP_EQUAL]
        # 0xA914{20-byte script_hash}87
        return "p2sh", script_pub_key[2:-1]

    if is_p2wpkh(script_pub_key):
        # p2wpkh [OP_0, pub_key_hash]
        # 0x0014{20-byte pub_key_hash}
        return "p2wpkh", script_pub_key[2:]

    if is_p2wsh(script_pub_key):
        # p2wsh [OP_0, script_hash]
        # 0x0020{32-byte script_hash}
        return "p2wsh", script_pub_key[2:]

    if is_p2tr(script_pub_key):
        # p2wtr [OP_1, script_hash]
        # 0x0120{32-byte script_hash}
        return "p2tr", script_pub_key[2:]

    if is_nulldata(script_pub_key):
        # nulldata [OP_RETURN, data]
        if len(script_pub_key) < 78:
            # OP_RETURN, data length, data up to 75 bytes max
            # 0x6A{1 byte data-length}{data (0-75 bytes)}
            return "nulldata", script_pub_key[2:]

        # OP_RETURN, OP_PUSHDATA1, data length, data min 76 bytes up to 80
        # 0x6A4C{1-byte data-length}{data (76-80 bytes)}
        return "nulldata", script_pub_key[3:]

    return "unknown", script_pub_key


class ScriptPubKey(Script):
    network: str

    @property
    def type(self) -> str:
        return type_and_payload(self.script)[0]

    @property
    def address(self) -> str:
        """Return the bech32/base58 address.

        An address is a shortened notation for a particular script.
        As a transaction output contains exactly one script,
        it has at most one address (it is possible that the script
        does not correspond to a particular address, though).
        """

        return address(self.script, self.network)

    @property
    def addresses(self) -> List[str]:
        """Return the address, if any, or the p2pkh addresses for p2ms.

        Historically, a p2pkh address has been used to refer to a key.
        For a p2ms multisig script, the keys it pays to are returned,
        expressed in p2pkh-address notation.

        https://bitcoin.stackexchange.com/questions/30442/multiple-addresses-in-one-utxo
        """
        try:
            return addresses(self.script, self.network)
        except BTClibValueError:
            return [self.address]

    def __eq__(self, other: object) -> bool:

        if not isinstance(other, ScriptPubKey):
            return NotImplemented

        if self.network != other.network:
            return False
        return super().__eq__(other)

    def __init__(
        self,
        script: Octets,
        network: str = "mainnet",
        check_validity: bool = True,
    ) -> None:
        self.network = network
        super().__init__(script, check_validity=check_validity)
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        super().assert_valid()
        if self.network not in NETWORKS:
            raise BTClibValueError(f"unknown network: {self.network}")

    @classmethod
    def from_address(
        cls: Type["ScriptPubKey"], addr: String, check_validity: bool = True
    ) -> "ScriptPubKey":
        "Return the ScriptPubKey of the input bech32/base58 address."

        if b32.has_segwit_prefix(addr):
            wit_ver, wit_prg, network = b32.witness_from_address(addr)
            return cls(serialize([op_int(wit_ver), wit_prg]), network, check_validity)

        script_type, h160, network = b58.h160_from_address(addr)
        if script_type == "p2sh":
            commands: List[Command] = ["OP_HASH160", h160, "OP_EQUAL"]
        else:  # it must be "p2pkh"
            commands = [
                "OP_DUP",
                "OP_HASH160",
                h160,
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        return cls(serialize(commands), network, check_validity)

    @classmethod
    def p2pk(
        cls: Type["ScriptPubKey"],
        key: Key,
        network: Optional[str] = None,
        check_validity: bool = True,
    ) -> "ScriptPubKey":
        "Return the p2pk ScriptPubKey of the provided Key."
        payload, network = pub_keyinfo_from_key(key, network)
        script = serialize([payload, "OP_CHECKSIG"])
        return cls(script, network, check_validity)

    @classmethod
    def p2ms(
        cls: Type["ScriptPubKey"],
        m: int,
        keys: Sequence[Key],
        network: Optional[str] = None,
        compressed: Optional[bool] = None,
        lexi_sort: bool = True,
        check_validity: bool = True,
    ) -> "ScriptPubKey":
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

        # if network is None, then first key sets the network
        pub_key, network = pub_keyinfo_from_key(keys[0], network, compressed)
        pub_keys = [pub_key] + [
            pub_keyinfo_from_key(k, network, compressed)[0] for k in keys[1:]
        ]
        if lexi_sort:
            pub_keys = sorted(pub_keys)

        script = serialize([op_int(m), *pub_keys, op_int(n), "OP_CHECKMULTISIG"])
        return cls(script, network, check_validity)

    @classmethod
    def nulldata(
        cls: Type["ScriptPubKey"],
        data: String,
        check_validity: bool = True,
    ) -> "ScriptPubKey":
        "Return the nulldata ScriptPubKey of the provided data."

        if isinstance(data, str):
            # do not strip spaces
            data = data.encode()

        if len(data) > 80:
            err_msg = f"invalid nulldata payload length: {len(data)} bytes "
            raise BTClibValueError(err_msg)

        script = serialize(["OP_RETURN", data])
        return cls(script, check_validity=check_validity)

    @classmethod
    def p2pkh(
        cls: Type["ScriptPubKey"],
        key: Key,
        compressed: Optional[bool] = None,
        network: Optional[str] = None,
        check_validity: bool = True,
    ) -> "ScriptPubKey":
        "Return the p2pkh ScriptPubKey of the provided key."

        pub_key, network = pub_keyinfo_from_key(key, network, compressed=compressed)
        script = serialize(
            ["OP_DUP", "OP_HASH160", hash160(pub_key), "OP_EQUALVERIFY", "OP_CHECKSIG"]
        )
        return cls(script, network, check_validity)

    @classmethod
    def p2sh(
        cls: Type["ScriptPubKey"],
        redeem_script: Octets,
        network: str = "mainnet",
        check_validity: bool = True,
    ) -> "ScriptPubKey":
        "Return the p2sh ScriptPubKey of the provided redeem script."

        script_h160 = hash160(redeem_script)
        script = serialize(["OP_HASH160", script_h160, "OP_EQUAL"])
        return cls(script, network, check_validity)

    @classmethod
    def p2wpkh(
        cls: Type["ScriptPubKey"],
        key: Key,
        check_validity: bool = True,
    ) -> "ScriptPubKey":
        """Return the p2wpkh ScriptPubKey of the provided key.

        If the provided key is a public one, it must be compressed.
        """

        pub_key, network = pub_keyinfo_from_key(key, compressed=True)
        script = serialize(["OP_0", hash160(pub_key)])
        return cls(script, network, check_validity)

    @classmethod
    def p2wsh(
        cls: Type["ScriptPubKey"],
        redeem_script: Octets,
        network: str = "mainnet",
        check_validity: bool = True,
    ) -> "ScriptPubKey":
        "Return the p2wsh ScriptPubKey of the provided redeem script."

        script_h256 = sha256(redeem_script)
        script = serialize(["OP_0", script_h256])
        return cls(script, network, check_validity)

    @classmethod
    def p2tr(
        cls: Type["ScriptPubKey"],
        internal_key: Optional[Key] = None,
        script_path: Optional[TaprootScriptTree] = None,
        network: str = "mainnet",
        check_validity: bool = True,
    ) -> "ScriptPubKey":
        "Return the p2tr ScriptPubKey of the provided script tree."

        pub_key = output_pubkey(internal_key, script_path)[0]
        script = serialize(["OP_1", pub_key])
        return cls(script, network, check_validity)
