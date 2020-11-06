#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""BIP32 Hierarchical Deterministic Wallet functions.

A deterministic wallet is a hash-chain of private/public key pairs that
derives from a single root, which is the only element requiring backup.
Moreover, there are schemes where public keys can be calculated without
accessing private keys.

A hierarchical deterministic wallet is a tree of multiple hash-chains,
derived from a single root, allowing for selective sharing of keypair
chains.

Here, the HD wallet is implemented according to BIP32 bitcoin standard
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki.

A BIP32 extended key is 78 bytes:

- [  : 4] version
- [ 4: 5] depth in the derivation path
- [ 5: 9] parent fingerprint
- [ 9:13] index
- [13:45] chain code
- [45:78] compressed pubkey or [0x00][prvkey]
"""

import copy
import hmac
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Type, TypeVar, Union

from dataclasses_json import DataClassJsonMixin, config

from . import bip39, electrum
from .alias import INF, Octets, Point, String
from .base58 import b58decode, b58encode
from .curve import mult, secp256k1
from .mnemonic import Mnemonic
from .network import (
    _NETWORKS,
    _P2WPKH_PRV_PREFIXES,
    _XPRV_PREFIXES,
    _XPRV_VERSIONS_ALL,
    _XPUB_VERSIONS_ALL,
    NETWORKS,
)
from .secpoint import bytes_from_point, point_from_octets
from .utils import bytes_from_octets, hash160, hex_string

ec = secp256k1


_BIP32KeyData = TypeVar("_BIP32KeyData", bound="BIP32KeyData")


@dataclass
class BIP32KeyData(DataClassJsonMixin):
    version: bytes = field(
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    depth: int
    parent_fingerprint: bytes = field(
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    # index is an int, not bytes, to avoid any byteorder ambiguity
    index: int
    chain_code: bytes = field(
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    key: bytes = field(
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )

    def assert_valid(self) -> None:

        if not isinstance(self.version, bytes):
            raise ValueError("version is not an instance of bytes")
        if len(self.version) != 4:
            m = "invalid version length: "
            m += f"{len(self.version)} bytes"
            m += " instead of 4"
            raise ValueError(m)

        if not isinstance(self.depth, int):
            raise ValueError("depth is not an instance of int")
        if self.depth < 0 or self.depth > 255:
            raise ValueError(f"invalid depth: {self.depth}")

        if not isinstance(self.parent_fingerprint, bytes):
            raise ValueError("parent fingerprint is not an instance of bytes")
        if len(self.parent_fingerprint) != 4:
            m = "invalid parent fingerprint length: "
            m += f"{len(self.parent_fingerprint)} bytes"
            m += " instead of 4"
            raise ValueError(m)

        if not isinstance(self.index, int):
            raise ValueError("index is not an instance of bytes")
        if self.index < 0:
            raise ValueError(f"negative index: {self.index}")
        if self.index > 0xFFFFFFFF:
            raise ValueError(f"index too high: {self.index}")

        if not isinstance(self.chain_code, bytes):
            raise ValueError("chain code is not an instance of bytes")
        if len(self.chain_code) != 32:
            m = "invalid chain code length: "
            m += f"{len(self.chain_code)} bytes"
            m += " instead of 32"
            raise ValueError(m)

        if not isinstance(self.key, bytes):
            raise ValueError("key is not an instance of bytes")
        if len(self.key) != 33:
            m = "invalid key length: "
            m += f"{len(self.key)} bytes"
            m += " instead of 33"
            raise ValueError(m)

        if self.version in _XPRV_VERSIONS_ALL:
            if self.key[0] != 0:
                raise ValueError(f"invalid private key prefix: 0x{self.key[0:1].hex()}")
            q = int.from_bytes(self.key[1:], byteorder="big")
            if not 0 < q < ec.n:
                raise ValueError(f"private key not in 1..n-1: {hex(q)}")
        elif self.version in _XPUB_VERSIONS_ALL:
            if self.key[0] not in (2, 3):
                raise ValueError(f"invalid public key prefix: 0x{self.key[0:1].hex()}")
            try:
                ec.y(int.from_bytes(self.key[1:], byteorder="big"))
            except Exception:
                raise ValueError(f"invalid public key 0x{self.key.hex()}")
        else:
            raise ValueError(f"unknown extended key version 0x{self.version.hex()}")

        if self.depth == 0:
            if self.parent_fingerprint != bytes.fromhex("00000000"):
                m = f"zero depth with non-zero parent fingerprint 0x{self.parent_fingerprint.hex()}"
                raise ValueError(m)
            if self.index != 0:
                raise ValueError(f"zero depth with non-zero index: {self.index}")
        else:
            if self.parent_fingerprint == bytes.fromhex("00000000"):
                m = f"zero parent fingerprint with non-zero depth {self.depth}"
                raise ValueError(m)

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        t = self.version
        t += self.depth.to_bytes(1, "big")
        t += self.parent_fingerprint
        t += self.index.to_bytes(4, "big")
        t += self.chain_code
        t += self.key
        return b58encode(t, 78)

    @classmethod
    def deserialize(
        cls: Type[_BIP32KeyData], xkey: String, assert_valid: bool = True
    ) -> _BIP32KeyData:

        if isinstance(xkey, str):
            xkey = xkey.strip()
        xkey = b58decode(xkey, 78)

        key_data = cls(
            version=xkey[:4],
            depth=xkey[4],
            parent_fingerprint=xkey[5:9],
            index=int.from_bytes(xkey[9:13], "big"),
            chain_code=xkey[13:45],
            key=xkey[45:],
        )
        if assert_valid:
            key_data.assert_valid()

        return key_data


def rootxprv_from_seed(
    seed: Octets, version: Octets = NETWORKS["mainnet"]["bip32_prv"]
) -> bytes:
    """Return BIP32 root master extended private key from seed."""

    seed = bytes_from_octets(seed)
    bitlenght = len(seed) * 8
    if bitlenght < 128:
        raise ValueError(f"too few bits for seed: {bitlenght} in '{hex_string(seed)}'")
    if bitlenght > 512:
        raise ValueError(f"too many bits for seed: {bitlenght} in '{hex_string(seed)}'")
    hd = hmac.digest(b"Bitcoin seed", seed, "sha512")
    k = b"\x00" + hd[:32]
    v = bytes_from_octets(version, 4)
    if v not in _XPRV_VERSIONS_ALL:
        raise ValueError(f"unknown private key version: {v.hex()}")

    key_data = BIP32KeyData(
        version=v,
        depth=0,
        parent_fingerprint=bytes.fromhex("00000000"),
        index=0,
        chain_code=hd[32:],
        key=k,
    )
    return key_data.serialize()


def mxprv_from_bip39_mnemonic(
    mnemonic: Mnemonic, passphrase: str = "", network: str = "mainnet"
) -> bytes:
    """Return BIP32 root master extended private key from BIP39 mnemonic."""

    seed = bip39.seed_from_mnemonic(mnemonic, passphrase)
    version = NETWORKS[network]["bip32_prv"]
    return rootxprv_from_seed(seed, version)


def mxprv_from_electrum_mnemonic(
    mnemonic: Mnemonic, passphrase: str = "", network: str = "mainnet"
) -> bytes:
    """Return BIP32 master extended private key from Electrum mnemonic.

    Note that for a "standard" mnemonic the derivation path is "m",
    for a "segwit" mnemonic it is "m/0h" instead.
    """

    version, seed = electrum._seed_from_mnemonic(mnemonic, passphrase)
    network_index = _NETWORKS.index(network)

    if version == "standard":
        xversion = _XPRV_PREFIXES[network_index]
        return rootxprv_from_seed(seed, xversion)
    elif version == "segwit":
        xversion = _P2WPKH_PRV_PREFIXES[network_index]
        rootxprv = rootxprv_from_seed(seed, xversion)
        return derive(rootxprv, 0x80000000)  # "m/0h"
    else:
        raise ValueError(f"unmanaged electrum mnemonic version: {version}")


BIP32Key = Union[BIP32KeyData, String]


def xpub_from_xprv(xprv: BIP32Key) -> bytes:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions).
    """

    xkey_data = (
        copy.copy(xprv)
        if isinstance(xprv, BIP32KeyData)
        else BIP32KeyData.deserialize(xprv)
    )
    if xkey_data.key[0] != 0:
        raise ValueError(f"not a private key: {xkey_data.serialize().decode('ascii')}")

    i = _XPRV_VERSIONS_ALL.index(xkey_data.version)
    xkey_data.version = _XPUB_VERSIONS_ALL[i]

    q = int.from_bytes(xkey_data.key[1:], byteorder="big")
    Q = mult(q)
    xkey_data.key = bytes_from_point(Q)

    return xkey_data.serialize()


def _indexes_from_bip32_path_str(der_path: str) -> List[int]:

    steps = [x.strip() for x in der_path.split("/")]
    if steps[0] not in ("m", "M"):
        raise ValueError(f"invalid root: {steps[0]}")

    indexes: List[int] = list()
    for step in steps[1:]:
        if step == "":  # extra slash
            continue

        hardened = False
        if step[-1] in ("'", "H", "h"):
            step = step[:-1]
            hardened = True

        index = int(step)
        if index < 0:
            raise ValueError(f"negative index: {index}")
        if index >= 0x80000000:
            raise ValueError(f"index too high: {index}")
        index += 0x80000000 if hardened else 0

        indexes.append(index)

    if len(indexes) > 255:
        err_msg = f"depth greater than 255: {len(indexes)}"
        raise ValueError(err_msg)
    return indexes


# BIP 32 derivation path
# "m/44h/0'/1H/0/10" string
# sequence of integer indexes (even a single int)
# bytes (multiples of 4-bytes index)
BIP32Path = Union[str, Iterable[int], int, bytes]


def str_from_bip32_path(der_path: BIP32Path, byteorder: str = "big") -> str:
    indexes = indexes_from_bip32_path(der_path, byteorder)
    result = "m"
    for i in indexes:
        result += "/"
        result += str(i) if i < 0x80000000 else (str(i - 0x80000000) + "h")
    return result


def bytes_from_bip32_path(der_path: BIP32Path, byteorder: str = "big") -> bytes:
    indexes = indexes_from_bip32_path(der_path, byteorder)
    result = [i.to_bytes(4, byteorder) for i in indexes]
    return b"".join(result)


def indexes_from_bip32_path(der_path: BIP32Path, byteorder: str = "big") -> List[int]:

    if isinstance(der_path, str):
        return _indexes_from_bip32_path_str(der_path)

    if isinstance(der_path, int):
        return [der_path]

    if isinstance(der_path, bytes):
        if len(der_path) % 4 != 0:
            m = f"index is not a multiple of 4-bytes: {len(der_path)}"
            raise ValueError(m)
        return [
            int.from_bytes(der_path[4 * n : 4 * (n + 1)], byteorder)
            for n in range(len(der_path) // 4)
        ]

    # Iterable[int]
    return [int(i) for i in der_path]


@dataclass
class _ExtendedBIP32KeyData(BIP32KeyData):
    # extensions used to cache intemediate results
    # in multi-level derivation: do not rely on them elsewhere
    q: int = 0  # non-zero for private key only
    Q: Point = INF  # non-Infinity for public key only


def __ckd(key_data: _ExtendedBIP32KeyData, index: int) -> None:

    # FIXME the following check should be enforced
    # if key_data.depth == 0 and index[0] < 0x80:
    #    raise UserWarning("public derivation at depth one level")

    # key_data is a prvkey
    if key_data.key[0] == 0:
        key_data.depth += 1
        Pbytes = bytes_from_point(mult(key_data.q))
        key_data.parent_fingerprint = hash160(Pbytes)[:4]
        key_data.index = index
        if index >= 0x80000000:  # hardened derivation
            h = hmac.digest(
                key_data.chain_code, key_data.key + index.to_bytes(4, "big"), "sha512"
            )
        else:  # normal derivation
            h = hmac.digest(
                key_data.chain_code, Pbytes + index.to_bytes(4, "big"), "sha512"
            )
        key_data.chain_code = h[32:]
        offset = int.from_bytes(h[:32], byteorder="big")
        key_data.q = (key_data.q + offset) % ec.n
        key_data.key = b"\x00" + key_data.q.to_bytes(32, "big")
        key_data.Q = INF
    # key_data is a pubkey
    else:
        if index >= 0x80000000:
            raise ValueError("hardened derivation from public key")
        key_data.depth += 1
        key_data.parent_fingerprint = hash160(key_data.key)[:4]
        key_data.index = index
        h = hmac.digest(
            key_data.chain_code, key_data.key + index.to_bytes(4, "big"), "sha512"
        )
        key_data.chain_code = h[32:]
        offset = int.from_bytes(h[:32], byteorder="big")
        Offset = mult(offset)
        key_data.Q = ec.add(key_data.Q, Offset)
        key_data.key = bytes_from_point(key_data.Q)
        key_data.q = 0


def _derive(
    xkey_data: BIP32KeyData,
    der_path: BIP32Path,
    forced_version: Optional[Octets] = None,
) -> BIP32KeyData:

    indexes = indexes_from_bip32_path(der_path)

    final_depth = xkey_data.depth + len(indexes)
    if final_depth > 255:
        err_msg = f"final depth greater than 255: {final_depth}"
        raise ValueError(err_msg)

    if forced_version is not None:
        version = xkey_data.version
        fversion = bytes_from_octets(forced_version, 4)
        if version in _XPRV_VERSIONS_ALL and fversion not in _XPRV_VERSIONS_ALL:
            err_msg = "invalid non-private version forced on a private key: "
            err_msg += f"{hex_string(fversion)}"
            raise ValueError(err_msg)
        if version in _XPUB_VERSIONS_ALL and fversion not in _XPUB_VERSIONS_ALL:
            err_msg = "invalid non-public version forced on a public key: "
            err_msg += f"{hex_string(fversion)}"
            raise ValueError(err_msg)

    is_prv = xkey_data.key[0] == 0
    q = int.from_bytes(xkey_data.key[1:], byteorder="big") if is_prv else 0
    Q = INF if is_prv else point_from_octets(xkey_data.key, ec)
    key_data = _ExtendedBIP32KeyData(
        version=xkey_data.version,
        depth=xkey_data.depth,
        parent_fingerprint=xkey_data.parent_fingerprint,
        index=xkey_data.index,
        chain_code=xkey_data.chain_code,
        key=xkey_data.key,
        q=q,
        Q=Q,
    )
    for index in indexes:
        __ckd(key_data, index)
    if forced_version is not None:
        key_data.version = fversion

    return key_data


def derive(
    xkey: BIP32Key, der_path: BIP32Path, forced_version: Optional[Octets] = None
) -> bytes:
    """Derive a BIP32 key across a path spanning multiple depth levels.

    Valid BIP32Path examples:

    - string like "m/44h/0'/1H/0/10"
    - iterable integer indexes
    - one single integer index
    - bytes in multiples of the 4-bytes index

    BIP32Path is case/blank/extra-slash insensitive
    (e.g. "M /44h / 0' /1H // 0/ 10 / ").
    """
    key_data = (
        copy.copy(xkey)
        if isinstance(xkey, BIP32KeyData)
        else BIP32KeyData.deserialize(xkey)
    )
    key_data = _derive(key_data, der_path, forced_version)
    return key_data.serialize()


def _derive_from_account(
    key_data: BIP32KeyData,
    branch: int,
    address_index: int,
    more_than_two_branches: bool = False,
) -> BIP32KeyData:

    if more_than_two_branches and branch >= 0x80000000:
        raise ValueError("invalid private derivation at branch level")
    elif branch not in (0, 1):
        raise ValueError(f"invalid branch: {branch} not in (0, 1)")

    if address_index >= 0x80000000:
        raise ValueError("invalid private derivation at address index level")

    if key_data.index < 0x80000000:
        raise UserWarning("public derivation at account level")

    return _derive(key_data, f"m/{branch}/{address_index}")


def derive_from_account(
    account_xkey: BIP32Key,
    branch: int,
    address_index: int,
    more_than_two_branches: bool = False,
) -> bytes:

    key_data = (
        copy.copy(account_xkey)
        if isinstance(account_xkey, BIP32KeyData)
        else BIP32KeyData.deserialize(account_xkey)
    )
    key_data = _derive_from_account(
        key_data, branch, address_index, more_than_two_branches
    )
    return key_data.serialize()


def crack_prvkey(parent_xpub: BIP32Key, child_xprv: BIP32Key) -> bytes:

    if isinstance(parent_xpub, BIP32KeyData):
        p = copy.copy(parent_xpub)
    else:
        p = BIP32KeyData.deserialize(parent_xpub)

    if p.key[0] not in (2, 3):
        m = "extended parent key is not a public key: "
        m += f"{p.serialize().decode('ascii')}"
        raise ValueError(m)

    c = (
        child_xprv
        if isinstance(child_xprv, BIP32KeyData)
        else BIP32KeyData.deserialize(child_xprv)
    )
    if c.key[0] != 0:
        m = f"extended child key is not a private key: {c.serialize().decode('ascii')}"
        raise ValueError(m)

    # check depth
    if c.depth != p.depth + 1:
        raise ValueError("not a parent's child: wrong depths")

    # check fingerprint
    if c.parent_fingerprint != hash160(p.key)[:4]:
        raise ValueError("not a parent's child: wrong parent fingerprint")

    # check normal derivation
    if c.index >= 0x80000000:
        raise ValueError("hardened child derivation")

    p.version = c.version

    h = hmac.digest(p.chain_code, p.key + c.index.to_bytes(4, "big"), "sha512")
    child_q = int.from_bytes(c.key[1:], byteorder="big")
    offset = int.from_bytes(h[:32], byteorder="big")
    parent_q = (child_q - offset) % ec.n
    p.key = b"\x00" + parent_q.to_bytes(32, byteorder="big")

    return p.serialize()
