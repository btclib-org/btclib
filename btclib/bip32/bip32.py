#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
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
from dataclasses import dataclass
from typing import List, Optional, Tuple, Type, Union

from btclib import base58
from btclib.alias import INF, BinaryData, Octets, Point, String
from btclib.bip32.der_path import BIP32DerPath, indexes_from_bip32_path
from btclib.ecc.curve import mult, secp256k1
from btclib.ecc.sec_point import bytes_from_point, point_from_octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160
from btclib.network import NETWORKS, XPRV_VERSIONS_ALL, XPUB_VERSIONS_ALL
from btclib.utils import bytes_from_octets, bytesio_from_binarydata, hex_string

ec = secp256k1


_KEY_SIZE: List[Tuple[str, int]] = [
    ("version", 4),
    ("parent_fingerprint", 4),
    ("chain_code", 32),
    ("key", 33),
]
_REQUIRED_LENGHT = 78


@dataclass
class BIP32KeyData:
    version: bytes
    depth: int
    parent_fingerprint: bytes
    # index is an int, not bytes, to avoid any byteorder ambiguity
    index: int
    chain_code: bytes
    key: bytes

    @property
    def is_private(self) -> bool:
        return self.key[0] == 0

    @property
    def is_hardened(self) -> bool:
        return self.index >= 0x80000000

    @property
    def is_root(self) -> bool:
        return (
            self.depth == 0
            and self.index == 0
            and self.parent_fingerprint == b"\x00" * 4
        )

    def __init__(
        self,
        version: Octets,
        depth: int,
        parent_fingerprint: Octets,
        index: int,
        chain_code: Octets,
        key: Octets,
        check_validity: bool = True,
    ) -> None:

        self.version = bytes_from_octets(version)
        self.depth = depth
        self.parent_fingerprint = bytes_from_octets(parent_fingerprint)
        self.index = index
        self.chain_code = bytes_from_octets(chain_code)
        self.key = bytes_from_octets(key)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:

        for key, size in _KEY_SIZE:
            value = bytes(getattr(self, key))
            setattr(self, key, value)
            if len(value) != size:
                err_msg = f"invalid {key} length: "
                err_msg += f"{len(value)} bytes"
                err_msg += f" instead of {size}"
                raise BTClibValueError(err_msg)

        self.index = int(self.index)
        if not 0 <= self.index <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid index: {self.index}")

        self.depth = int(self.depth)
        if not 0 <= self.depth <= 255:
            raise BTClibValueError(f"invalid depth: {self.depth}")

        if self.depth == 0:
            if self.parent_fingerprint != b"\x00" * 4:
                err_msg = f"zero depth with non-zero parent fingerprint: 0x{self.parent_fingerprint.hex()}"
                raise BTClibValueError(err_msg)
            if self.index != 0:
                raise BTClibValueError(f"zero depth with non-zero index: {self.index}")

        if self.version in XPRV_VERSIONS_ALL:
            if self.key[0] != 0:
                raise BTClibValueError(
                    f"invalid private key prefix: 0x{self.key[:1].hex()}"
                )
            q = int.from_bytes(self.key[1:], byteorder="big", signed=False)
            if not 0 < q < ec.n:
                raise BTClibValueError(f"invalid private key not in 1..n-1: {hex(q)}")
        elif self.version in XPUB_VERSIONS_ALL:
            if self.key[0] not in (2, 3):
                err_msg = f"invalid public key prefix not in (0x02, 0x03): 0x{self.key[:1].hex()}"
                raise BTClibValueError(err_msg)
            try:
                ec.y(int.from_bytes(self.key[1:], byteorder="big", signed=False))
            except BTClibValueError as e:
                err_msg = f"invalid public key: 0x{self.key.hex()}"
                raise BTClibValueError(err_msg) from e
        else:
            raise BTClibValueError(
                f"unknown extended key version: 0x{self.version.hex()}"
            )

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        return b"".join(
            [
                self.version,
                self.depth.to_bytes(1, byteorder="big", signed=False),
                self.parent_fingerprint,
                self.index.to_bytes(4, byteorder="big", signed=False),
                self.chain_code,
                self.key,
            ]
        )

    def b58encode(self, check_validity: bool = True) -> str:
        data_binary = self.serialize(check_validity)
        return base58.b58encode(data_binary).decode("ascii")

    @classmethod
    def parse(
        cls: Type["BIP32KeyData"], xkey_bin: BinaryData, check_validity: bool = True
    ) -> "BIP32KeyData":
        "Return a BIP32KeyData by parsing 73 bytes from binary data."

        stream = bytesio_from_binarydata(xkey_bin)
        xkey_bin = stream.read(_REQUIRED_LENGHT)

        if check_validity and len(xkey_bin) != _REQUIRED_LENGHT:
            err_msg = f"invalid decoded length: {len(xkey_bin)}"
            err_msg += f" instead of {_REQUIRED_LENGHT}"
            raise BTClibValueError(err_msg)

        return cls(
            version=xkey_bin[0:4],
            depth=xkey_bin[4],
            parent_fingerprint=xkey_bin[5:9],
            index=int.from_bytes(xkey_bin[9:13], byteorder="big", signed=False),
            chain_code=xkey_bin[13:45],
            key=xkey_bin[45:78],
            check_validity=check_validity,
        )

    @classmethod
    def b58decode(
        cls: Type["BIP32KeyData"], address: String, check_validity: bool = True
    ) -> "BIP32KeyData":

        if isinstance(address, str):
            address = address.strip()

        xkey_bin = base58.b58decode(address)
        # pylance cannot grok the following line
        return cls.parse(xkey_bin, check_validity)  # type: ignore


def _rootxprv_from_seed(
    seed: Octets, version: Octets = NETWORKS["mainnet"].bip32_prv
) -> BIP32KeyData:
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

    return BIP32KeyData(
        version=v,
        depth=0,
        parent_fingerprint=b"\x00" * 4,
        index=0,
        chain_code=hmac_[32:],
        key=k,
    )


def rootxprv_from_seed(
    seed: Octets, version: Octets = NETWORKS["mainnet"].bip32_prv
) -> str:
    """Return BIP32 root master extended private key from seed."""
    xkey = _rootxprv_from_seed(seed, version)
    return xkey.b58encode()


BIP32Key = Union[BIP32KeyData, String]


def _xpub_from_xprv(xprv: BIP32Key) -> BIP32KeyData:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions).
    """

    if isinstance(xprv, BIP32KeyData):
        xkey = copy.copy(xprv)
    else:
        xkey = BIP32KeyData.b58decode(xprv)

    if xkey.key[0] != 0:
        err_msg = f"not a private key: {xkey.b58encode()}"
        raise BTClibValueError(err_msg)

    i = XPRV_VERSIONS_ALL.index(xkey.version)
    xkey.version = XPUB_VERSIONS_ALL[i]

    q = int.from_bytes(xkey.key[1:], byteorder="big", signed=False)
    Q = mult(q)
    xkey.key = bytes_from_point(Q)

    return xkey


def xpub_from_xprv(xprv: BIP32Key) -> str:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions).
    """
    xkey = _xpub_from_xprv(xprv)
    return xkey.b58encode()


@dataclass
class _ExtendedBIP32KeyData(BIP32KeyData):
    # extensions used to cache intermediate results
    # in multi-level derivation: do not rely on them elsewhere
    prv_key_int: int  # non-zero for private key only
    pub_key_point: Point  # non-Infinity for public key only

    def __init__(
        self,
        version: Octets,
        depth: int,
        parent_fingerprint: Octets,
        index: int,
        chain_code: Octets,
        key: Octets,
        check_validity: bool = True,
    ) -> None:

        super().__init__(
            version, depth, parent_fingerprint, index, chain_code, key, False
        )

        if self.is_private:
            self.prv_key_int = int.from_bytes(self.key[1:], "big", signed=False)
            self.pub_key_point = INF
        else:
            self.prv_key_int = 0
            self.pub_key_point = point_from_octets(self.key, ec)

        if check_validity:
            self.assert_valid()


def __ckd(xkey: _ExtendedBIP32KeyData, index: int) -> None:

    xkey.depth += 1
    xkey.index = index
    if xkey.is_private:
        Q_bytes = bytes_from_point(mult(xkey.prv_key_int))
        xkey.parent_fingerprint = hash160(Q_bytes)[:4]
        if xkey.is_hardened:  # hardened derivation
            hmac_ = hmac.new(
                xkey.chain_code,
                xkey.key + index.to_bytes(4, byteorder="big", signed=False),
                "sha512",
            ).digest()
        else:  # normal derivation
            hmac_ = hmac.new(
                xkey.chain_code,
                Q_bytes + index.to_bytes(4, byteorder="big", signed=False),
                "sha512",
            ).digest()
        xkey.chain_code = hmac_[32:]
        offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)
        xkey.prv_key_int = (xkey.prv_key_int + offset) % ec.n
        xkey.key = b"\x00" + xkey.prv_key_int.to_bytes(
            32, byteorder="big", signed=False
        )
        xkey.pub_key_point = INF
    else:  # public key
        xkey.parent_fingerprint = hash160(xkey.key)[:4]
        if xkey.is_hardened:
            raise BTClibValueError("invalid hardened derivation from public key")
        hmac_ = hmac.new(
            xkey.chain_code,
            xkey.key + index.to_bytes(4, byteorder="big", signed=False),
            "sha512",
        ).digest()
        xkey.chain_code = hmac_[32:]
        offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)
        xkey.pub_key_point = ec.add(xkey.pub_key_point, mult(offset))
        xkey.key = bytes_from_point(xkey.pub_key_point)
        xkey.prv_key_int = 0


def _derive(
    xkey: BIP32Key, der_path: BIP32DerPath, forced_version: Optional[Octets] = None
) -> BIP32KeyData:

    if not isinstance(xkey, BIP32KeyData):
        xkey = BIP32KeyData.b58decode(xkey)

    indexes = indexes_from_bip32_path(der_path)

    final_depth = xkey.depth + len(indexes)
    if final_depth > 255:
        err_msg = f"final depth greater than 255: {final_depth}"
        raise BTClibValueError(err_msg)

    xkey = _ExtendedBIP32KeyData(
        version=xkey.version,
        depth=xkey.depth,
        parent_fingerprint=xkey.parent_fingerprint,
        index=xkey.index,
        chain_code=xkey.chain_code,
        key=xkey.key,
    )
    for index in indexes:
        __ckd(xkey, index)

    if forced_version:
        if xkey.version in XPRV_VERSIONS_ALL:
            allowed_versions = XPRV_VERSIONS_ALL
        else:
            allowed_versions = XPUB_VERSIONS_ALL
        fversion = bytes_from_octets(forced_version, 4)
        if fversion not in allowed_versions:
            err_msg = "invalid version forced on the extended key"
            err_msg += f"{hex_string(fversion)}"
            raise BTClibValueError(err_msg)
        xkey.version = fversion

    return xkey


def derive(
    xkey: BIP32Key, der_path: BIP32DerPath, forced_version: Optional[Octets] = None
) -> str:
    """Derive a BIP32 key across a path spanning multiple depth levels.

    Valid BIP32DerPath examples:

    - string like "m/44h/0'/1H/0/10"
    - iterable integer indexes
    - one single integer index
    - bytes in multiples of the 4-bytes index

    BIP32DerPath is case/blank/extra-slash insensitive
    (e.g. "M /44h / 0' /1H // 0/ 10 / ").
    """
    xkey = _derive(xkey, der_path, forced_version)
    return xkey.b58encode()


def _derive_from_account(
    mxkey: BIP32Key,
    branch: int,
    address_index: int,
    branches_0_1_only: bool = True,
    max_index: int = 0xFFFF,
) -> BIP32KeyData:

    if not isinstance(mxkey, BIP32KeyData):
        mxkey = BIP32KeyData.b58decode(mxkey)

    if not mxkey.is_hardened:
        raise BTClibValueError("unhardened account/master key")

    if branch >= 0x80000000:
        raise BTClibValueError("invalid private derivation at branch level")
    if branch > max_index:
        raise BTClibValueError(f"too high branch: {branch}")
    if branches_0_1_only and branch not in (0, 1):
        raise BTClibValueError(f"invalid branch: {branch} not in (0, 1)")

    if address_index >= 0x80000000:
        raise BTClibValueError("invalid private derivation at address index level")
    if address_index > max_index:
        raise BTClibValueError(f"too high address index: {branch}")

    return _derive(mxkey, f"m/{branch}/{address_index}")


def derive_from_account(
    mxkey: BIP32Key,
    branch: int,
    address_index: int,
    branches_0_1_only: bool = True,
    max_index: int = 0xFFFF,
) -> str:
    """Derive a key with public derivation at the given branch and index.

    It also ensures that the master key is hardened,
    that the branch is a standard receive or change,
    and that the index is not arbitrarily high.
    """

    return _derive_from_account(
        mxkey, branch, address_index, branches_0_1_only, max_index
    ).b58encode()


def crack_prv_key(parent_xpub: BIP32Key, child_xprv: BIP32Key) -> str:

    if isinstance(parent_xpub, BIP32KeyData):
        p = copy.copy(parent_xpub)
    else:
        p = BIP32KeyData.b58decode(parent_xpub)

    if p.key[0] not in (2, 3):
        err_msg = "extended parent key is not a public key: "
        err_msg += f"{p.b58encode()}"
        raise BTClibValueError(err_msg)

    if isinstance(child_xprv, BIP32KeyData):
        c = child_xprv
    else:
        c = BIP32KeyData.b58decode(child_xprv)

    if c.key[0] != 0:
        err_msg = "extended child key is not a private key: "
        err_msg += f"{c.b58encode()}"
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

    hmac_ = hmac.new(
        p.chain_code,
        p.key + c.index.to_bytes(4, byteorder="big", signed=False),
        "sha512",
    ).digest()
    child_q = int.from_bytes(c.key[1:], byteorder="big", signed=False)
    offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)
    parent_q = (child_q - offset) % ec.n
    p.key = b"\x00" + parent_q.to_bytes(32, byteorder="big", signed=False)

    return p.b58encode()
