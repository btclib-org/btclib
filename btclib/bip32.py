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
from .exceptions import BTClibValueError
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


def _index_int_from_str(s: str) -> int:

    s.strip().lower()
    hardened = False
    if s[-1] in ("'", "h"):
        s = s[:-1]
        hardened = True

    index = int(s)
    if not 0 <= index < 0x80000000:
        raise BTClibValueError(f"invalid index: {index}")
    return index + (0x80000000 if hardened else 0)


def _str_from_index_int(i: int, hardening: str = "'") -> str:

    if hardening not in ("'", "h", "H"):
        raise BTClibValueError(f"invalid hardening symbol: {hardening}")
    if not 0 <= i <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid index: {i}")
    if i < 0x80000000:
        return str(i)
    return str(i - 0x80000000) + hardening


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
    index: int = field(
        metadata=config(encoder=_str_from_index_int, decoder=_index_int_from_str)
    )
    chain_code: bytes = field(
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    key: bytes = field(
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )

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

    def assert_valid(self) -> None:

        if not isinstance(self.version, bytes):
            raise BTClibValueError("version is not an instance of bytes")
        if len(self.version) != 4:
            err_msg = "invalid version length: "
            err_msg += f"{len(self.version)} bytes"
            err_msg += " instead of 4"
            raise BTClibValueError(err_msg)

        if not isinstance(self.depth, int):
            raise BTClibValueError("depth is not an instance of int")
        if self.depth < 0 or self.depth > 255:
            raise BTClibValueError(f"invalid depth: {self.depth}")

        if not isinstance(self.parent_fingerprint, bytes):
            raise BTClibValueError("parent fingerprint is not an instance of bytes")
        if len(self.parent_fingerprint) != 4:
            err_msg = "invalid parent fingerprint length: "
            err_msg += f"{len(self.parent_fingerprint)} bytes"
            err_msg += " instead of 4"
            raise BTClibValueError(err_msg)

        if not isinstance(self.index, int):
            raise BTClibValueError("index is not an instance of bytes")
        if not 0 <= self.index <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid index: {self.index}")

        if not isinstance(self.chain_code, bytes):
            raise BTClibValueError("chain code is not an instance of bytes")
        if len(self.chain_code) != 32:
            err_msg = "invalid chain code length: "
            err_msg += f"{len(self.chain_code)} bytes"
            err_msg += " instead of 32"
            raise BTClibValueError(err_msg)

        if not isinstance(self.key, bytes):
            raise BTClibValueError("key is not an instance of bytes")
        if len(self.key) != 33:
            err_msg = "invalid key length: "
            err_msg += f"{len(self.key)} bytes"
            err_msg += " instead of 33"
            raise BTClibValueError(err_msg)

        if self.version in _XPRV_VERSIONS_ALL:
            if self.key[0] != 0:
                raise BTClibValueError(
                    f"invalid private key prefix: 0x{self.key[0:1].hex()}"
                )
            q = int.from_bytes(self.key[1:], byteorder="big")
            if not 0 < q < ec.n:
                raise BTClibValueError(f"invalid private key not in 1..n-1: {hex(q)}")
        elif self.version in _XPUB_VERSIONS_ALL:
            if self.key[0] not in (2, 3):
                err_msg = f"invalid public key prefix not in (0x02, 0x03): 0x{self.key[0:1].hex()}"
                raise BTClibValueError(err_msg)
            try:
                ec.y(int.from_bytes(self.key[1:], byteorder="big"))
            except BTClibValueError as e:
                err_msg = f"invalid public key: 0x{self.key.hex()}"
                raise BTClibValueError(err_msg) from e
        else:
            raise BTClibValueError(
                f"unknown extended key version: 0x{self.version.hex()}"
            )

        if self.depth == 0:
            if self.parent_fingerprint != bytes.fromhex("00000000"):
                err_msg = f"zero depth with non-zero parent fingerprint: 0x{self.parent_fingerprint.hex()}"
                raise BTClibValueError(err_msg)
            if self.index != 0:
                raise BTClibValueError(f"zero depth with non-zero index: {self.index}")

    @property
    def is_hardened(self) -> bool:
        self.assert_valid()
        return self.index >= 0x80000000


def rootxprv_from_seed(
    seed: Octets, version: Octets = NETWORKS["mainnet"].bip32_prv
) -> bytes:
    """Return BIP32 root master extended private key from seed."""

    seed = bytes_from_octets(seed)
    bitlenght = len(seed) * 8
    if bitlenght < 128:
        raise BTClibValueError(
            f"too few bits for seed: {bitlenght} in '{hex_string(seed)}'"
        )
    if bitlenght > 512:
        raise BTClibValueError(
            f"too many bits for seed: {bitlenght} in '{hex_string(seed)}'"
        )
    hd = hmac.new(b"Bitcoin seed", seed, "sha512").digest()
    k = b"\x00" + hd[:32]
    v = bytes_from_octets(version, 4)
    if v not in _XPRV_VERSIONS_ALL:
        raise BTClibValueError(f"unknown private key version: {v.hex()}")

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
    version = NETWORKS[network].bip32_prv
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
    if version == "segwit":
        xversion = _P2WPKH_PRV_PREFIXES[network_index]
        rootxprv = rootxprv_from_seed(seed, xversion)
        return derive(rootxprv, 0x80000000)  # "m/0h"
    raise BTClibValueError(f"unmanaged electrum mnemonic version: {version}")


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
        raise BTClibValueError(
            f"not a private key: {xkey_data.serialize().decode('ascii')}"
        )

    i = _XPRV_VERSIONS_ALL.index(xkey_data.version)
    xkey_data.version = _XPUB_VERSIONS_ALL[i]

    q = int.from_bytes(xkey_data.key[1:], byteorder="big")
    Q = mult(q)
    xkey_data.key = bytes_from_point(Q)

    return xkey_data.serialize()


def _indexes_from_bip32_path_str(der_path: str) -> List[int]:

    steps = [x.strip().lower() for x in der_path.split("/")]
    if steps[0] == "m":
        steps = steps[1:]

    indexes = [_index_int_from_str(s) for s in steps if s != ""]

    if len(indexes) > 255:
        err_msg = f"depth greater than 255: {len(indexes)}"
        raise BTClibValueError(err_msg)
    return indexes


# BIP 32 derivation path
# "m/44h/0'/1H/0/10" string
# sequence of integer indexes (even a single int)
# bytes (multiples of 4-bytes index)
BIP32Path = Union[str, Iterable[int], int, bytes]


def str_from_bip32_path(
    der_path: BIP32Path, byteorder: str = "big", hardening_symbol: str = "'"
) -> str:
    indexes = indexes_from_bip32_path(der_path, byteorder)
    result = "/".join([_str_from_index_int(i, hardening_symbol) for i in indexes])
    return "m/" + result if indexes else "m"


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
            err_msg = f"index is not a multiple of 4-bytes: {len(der_path)}"
            raise BTClibValueError(err_msg)
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

    # key_data is a prvkey
    if key_data.key[0] == 0:
        key_data.depth += 1
        Pbytes = bytes_from_point(mult(key_data.q))
        key_data.parent_fingerprint = hash160(Pbytes)[:4]
        key_data.index = index
        if key_data.is_hardened:
            h = hmac.new(
                key_data.chain_code, key_data.key + index.to_bytes(4, "big"), "sha512"
            ).digest()
        else:  # normal derivation
            h = hmac.new(
                key_data.chain_code, Pbytes + index.to_bytes(4, "big"), "sha512"
            ).digest()
        key_data.chain_code = h[32:]
        offset = int.from_bytes(h[:32], byteorder="big")
        key_data.q = (key_data.q + offset) % ec.n
        key_data.key = b"\x00" + key_data.q.to_bytes(32, "big")
        key_data.Q = INF
    # key_data is a pubkey
    else:
        key_data.depth += 1
        key_data.parent_fingerprint = hash160(key_data.key)[:4]
        key_data.index = index
        if key_data.is_hardened:
            raise BTClibValueError("invalid hardened derivation from public key")
        h = hmac.new(
            key_data.chain_code, key_data.key + index.to_bytes(4, "big"), "sha512"
        ).digest()
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
        raise BTClibValueError(err_msg)

    if forced_version is not None:
        version = xkey_data.version
        fversion = bytes_from_octets(forced_version, 4)
        if version in _XPRV_VERSIONS_ALL and fversion not in _XPRV_VERSIONS_ALL:
            err_msg = "invalid non-private version forced on a private key: "
            err_msg += f"{hex_string(fversion)}"
            raise BTClibValueError(err_msg)
        if version in _XPUB_VERSIONS_ALL and fversion not in _XPUB_VERSIONS_ALL:
            err_msg = "invalid non-public version forced on a public key: "
            err_msg += f"{hex_string(fversion)}"
            raise BTClibValueError(err_msg)

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
        raise BTClibValueError("invalid private derivation at branch level")
    if branch not in (0, 1):
        raise BTClibValueError(f"invalid branch: {branch} not in (0, 1)")
    if address_index >= 0x80000000:
        raise BTClibValueError("invalid private derivation at address index level")
    if not key_data.is_hardened:
        raise UserWarning("invalid public derivation at account level")

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
        err_msg = "extended parent key is not a public key: "
        err_msg += f"{p.serialize().decode('ascii')}"
        raise BTClibValueError(err_msg)

    c = (
        child_xprv
        if isinstance(child_xprv, BIP32KeyData)
        else BIP32KeyData.deserialize(child_xprv)
    )
    if c.key[0] != 0:
        err_msg = (
            f"extended child key is not a private key: {c.serialize().decode('ascii')}"
        )
        raise BTClibValueError(err_msg)

    # check depth
    if c.depth != p.depth + 1:
        raise BTClibValueError("not a parent's child: wrong depths")

    # check fingerprint
    if c.parent_fingerprint != hash160(p.key)[:4]:
        raise BTClibValueError("not a parent's child: wrong parent fingerprint")

    if c.is_hardened:
        raise BTClibValueError("hardened child derivation")

    p.version = c.version

    h = hmac.new(p.chain_code, p.key + c.index.to_bytes(4, "big"), "sha512").digest()
    child_q = int.from_bytes(c.key[1:], byteorder="big")
    offset = int.from_bytes(h[:32], byteorder="big")
    parent_q = (child_q - offset) % ec.n
    p.key = b"\x00" + parent_q.to_bytes(32, byteorder="big")

    return p.serialize()
