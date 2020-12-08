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
- [45:78] compressed pub_key or [0x00][prv_key]
"""

import copy
import hmac
from dataclasses import InitVar, dataclass, field
from typing import Optional, Type, TypeVar, Union

from dataclasses_json import DataClassJsonMixin, config

from . import base58, bip39, electrum
from .alias import INF, BinaryData, Octets, Point, String
from .bip32_path import (
    BIP32Path,
    _int_from_index_str,
    _str_from_index_int,
    indexes_from_bip32_path,
)
from .curve import mult, secp256k1
from .exceptions import BTClibTypeError, BTClibValueError
from .mnemonic import Mnemonic
from .network import (
    _NETWORKS,
    _P2WPKH_PRV_PREFIXES,
    _XPRV_PREFIXES,
    _XPRV_VERSIONS_ALL,
    _XPUB_VERSIONS_ALL,
    NETWORKS,
)
from .sec_point import bytes_from_point, point_from_octets
from .utils import (
    bytes_from_octets,
    bytesio_from_binarydata,
    hash160,
    hex_string,
)

ec = secp256k1


_BIP32KeyData = TypeVar("_BIP32KeyData", bound="BIP32KeyData")
_EXPECTED_DECODED_LENGHT = 78


@dataclass
class BIP32KeyData(DataClassJsonMixin):
    version: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    depth: int = -1
    parent_fingerprint: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    # index is an int, not bytes, to avoid any byteorder ambiguity
    index: int = field(
        default=-1,
        metadata=config(encoder=_str_from_index_int, decoder=_int_from_index_str),
    )
    chain_code: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    key: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def is_hardened(self) -> bool:
        return self.index >= 0x80000000

    def assert_valid(self) -> None:

        if not isinstance(self.version, bytes):
            raise BTClibTypeError("version is not an instance of bytes")
        if len(self.version) != 4:
            err_msg = "invalid version length: "
            err_msg += f"{len(self.version)} bytes"
            err_msg += " instead of 4"
            raise BTClibValueError(err_msg)

        if not isinstance(self.depth, int):
            raise BTClibTypeError("depth is not an instance of int")
        if self.depth < 0 or self.depth > 255:
            raise BTClibValueError(f"invalid depth: {self.depth}")

        if not isinstance(self.parent_fingerprint, bytes):
            raise BTClibTypeError("parent fingerprint is not an instance of bytes")
        if len(self.parent_fingerprint) != 4:
            err_msg = "invalid parent fingerprint length: "
            err_msg += f"{len(self.parent_fingerprint)} bytes"
            err_msg += " instead of 4"
            raise BTClibValueError(err_msg)

        if not isinstance(self.index, int):
            raise BTClibTypeError("index is not an instance of bytes")
        if not 0 <= self.index <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid index: {self.index}")

        if not isinstance(self.chain_code, bytes):
            raise BTClibTypeError("chain code is not an instance of bytes")
        if len(self.chain_code) != 32:
            err_msg = "invalid chain code length: "
            err_msg += f"{len(self.chain_code)} bytes"
            err_msg += " instead of 32"
            raise BTClibValueError(err_msg)

        if not isinstance(self.key, bytes):
            raise BTClibTypeError("key is not an instance of bytes")
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

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        xkey_bin = self.version
        xkey_bin += self.depth.to_bytes(1, "big")
        xkey_bin += self.parent_fingerprint
        xkey_bin += self.index.to_bytes(4, "big")
        xkey_bin += self.chain_code
        xkey_bin += self.key
        return xkey_bin

    @classmethod
    def deserialize(
        cls: Type[_BIP32KeyData], xkey_bin: BinaryData, assert_valid: bool = True
    ) -> _BIP32KeyData:
        "Return a BIP32KeyData by parsing 73 bytes from binary data."

        stream = bytesio_from_binarydata(xkey_bin)
        xkey = cls(check_validity=False)

        xkey.version = stream.read(4)
        xkey.depth = int.from_bytes(stream.read(1), byteorder="big")
        xkey.parent_fingerprint = stream.read(4)
        xkey.index = int.from_bytes(stream.read(4), byteorder="big")
        xkey.chain_code = stream.read(32)
        xkey.key = stream.read(33)

        if assert_valid:
            xkey.assert_valid()
        return xkey

    def b58encode(self, assert_valid: bool = True) -> bytes:
        data_binary = self.serialize(assert_valid)
        return base58.b58encode(data_binary)

    @classmethod
    def b58decode(
        cls: Type[_BIP32KeyData], data_str: String, assert_valid: bool = True
    ) -> _BIP32KeyData:
        if isinstance(data_str, str):
            data_str = data_str.strip()
        data_decoded = base58.b58decode(data_str)
        if assert_valid and len(data_decoded) != _EXPECTED_DECODED_LENGHT:
            err_msg = f"invalid decoded length: {len(data_decoded)}"
            err_msg += f" instead of {_EXPECTED_DECODED_LENGHT}"
            raise BTClibValueError(err_msg)
        return cls.deserialize(data_decoded, assert_valid)


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
    hmac_ = hmac.new(b"Bitcoin seed", seed, "sha512").digest()
    k = b"\x00" + hmac_[:32]
    v = bytes_from_octets(version, 4)
    if v not in _XPRV_VERSIONS_ALL:
        raise BTClibValueError(f"unknown private key version: {v.hex()}")

    key_data = BIP32KeyData(
        version=v,
        depth=0,
        parent_fingerprint=bytes.fromhex("00000000"),
        index=0,
        chain_code=hmac_[32:],
        key=k,
    )
    return key_data.b58encode()


def mxprv_from_bip39_mnemonic(  # nosec
    mnemonic: Mnemonic, passphrase: str = "", network: str = "mainnet"
) -> bytes:
    """Return BIP32 root master extended private key from BIP39 mnemonic."""

    seed = bip39.seed_from_mnemonic(mnemonic, passphrase)
    version = NETWORKS[network].bip32_prv
    return rootxprv_from_seed(seed, version)


def mxprv_from_electrum_mnemonic(  # nosec
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
        else BIP32KeyData.b58decode(xprv)
    )
    if xkey_data.key[0] != 0:
        raise BTClibValueError(
            f"not a private key: {xkey_data.b58encode().decode('ascii')}"
        )

    i = _XPRV_VERSIONS_ALL.index(xkey_data.version)
    xkey_data.version = _XPUB_VERSIONS_ALL[i]

    q = int.from_bytes(xkey_data.key[1:], byteorder="big")
    Q = mult(q)
    xkey_data.key = bytes_from_point(Q)

    return xkey_data.b58encode()


@dataclass
class _ExtendedBIP32KeyData(BIP32KeyData):
    # extensions used to cache intermediate results
    # in multi-level derivation: do not rely on them elsewhere
    q: int = 0  # non-zero for private key only
    Q: Point = INF  # non-Infinity for public key only


def __ckd(key_data: _ExtendedBIP32KeyData, index: int) -> None:

    key_data.depth += 1
    key_data.index = index
    if key_data.key[0] == 0:  # private key
        Q_bytes = bytes_from_point(mult(key_data.q))
        key_data.parent_fingerprint = hash160(Q_bytes)[:4]
        if key_data.is_hardened():  # hardened derivation
            hmac_ = hmac.new(
                key_data.chain_code, key_data.key + index.to_bytes(4, "big"), "sha512"
            ).digest()
        else:  # normal derivation
            hmac_ = hmac.new(
                key_data.chain_code, Q_bytes + index.to_bytes(4, "big"), "sha512"
            ).digest()
        key_data.chain_code = hmac_[32:]
        offset = int.from_bytes(hmac_[:32], byteorder="big")
        key_data.q = (key_data.q + offset) % ec.n
        key_data.key = b"\x00" + key_data.q.to_bytes(32, "big")
        key_data.Q = INF
    else:  # public key
        key_data.parent_fingerprint = hash160(key_data.key)[:4]
        if key_data.is_hardened():
            raise BTClibValueError("invalid hardened derivation from public key")
        hmac_ = hmac.new(
            key_data.chain_code, key_data.key + index.to_bytes(4, "big"), "sha512"
        ).digest()
        key_data.chain_code = hmac_[32:]
        offset = int.from_bytes(hmac_[:32], byteorder="big")
        key_data.Q = ec.add(key_data.Q, mult(offset))
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
        else BIP32KeyData.b58decode(xkey)
    )
    key_data = _derive(key_data, der_path, forced_version)
    return key_data.b58encode()


def _derive_from_account(
    key_data: BIP32KeyData,
    branch: int,
    address_index: int,
    more_than_two_branches: bool = False,
) -> BIP32KeyData:

    if not key_data.is_hardened():
        raise UserWarning("invalid public derivation at account level")
    if branch >= 0x80000000:
        raise BTClibValueError("invalid private derivation at branch level")
    if branch not in (0, 1) or more_than_two_branches:
        raise BTClibValueError(f"invalid branch: {branch} not in (0, 1)")
    if address_index >= 0x80000000:
        raise BTClibValueError("invalid private derivation at address index level")

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
        else BIP32KeyData.b58decode(account_xkey)
    )
    key_data = _derive_from_account(
        key_data, branch, address_index, more_than_two_branches
    )
    return key_data.b58encode()


def crack_prv_key(parent_xpub: BIP32Key, child_xprv: BIP32Key) -> bytes:

    if isinstance(parent_xpub, BIP32KeyData):
        p = copy.copy(parent_xpub)
    else:
        p = BIP32KeyData.b58decode(parent_xpub)

    if p.key[0] not in (2, 3):
        err_msg = "extended parent key is not a public key: "
        err_msg += f"{p.b58encode().decode('ascii')}"
        raise BTClibValueError(err_msg)

    c = (
        child_xprv
        if isinstance(child_xprv, BIP32KeyData)
        else BIP32KeyData.b58decode(child_xprv)
    )
    if c.key[0] != 0:
        err_msg = (
            f"extended child key is not a private key: {c.b58encode().decode('ascii')}"
        )
        raise BTClibValueError(err_msg)

    # check depth
    if c.depth != p.depth + 1:
        raise BTClibValueError("not a parent's child: wrong depths")

    # check fingerprint
    if c.parent_fingerprint != hash160(p.key)[:4]:
        raise BTClibValueError("not a parent's child: wrong parent fingerprint")

    if c.is_hardened():
        raise BTClibValueError("hardened child derivation")

    p.version = c.version

    hmac_ = hmac.new(
        p.chain_code, p.key + c.index.to_bytes(4, "big"), "sha512"
    ).digest()
    child_q = int.from_bytes(c.key[1:], byteorder="big")
    offset = int.from_bytes(hmac_[:32], byteorder="big")
    parent_q = (child_q - offset) % ec.n
    p.key = b"\x00" + parent_q.to_bytes(32, byteorder="big")

    return p.b58encode()
