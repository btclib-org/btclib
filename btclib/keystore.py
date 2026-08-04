#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Keystore: the addresses handed out, and the key that signs for each.

`btclib.ecc.bms` says it in its own docstring -- "at signing time, a
wallet infrastructure is required to access the private key corresponding
to a given address" -- and then has none to reach for. This module is
that infrastructure, and no more of it than the sentence asks for: a
`KeyStore` holds a key source, hands out addresses, remembers the
derivation path of each, and answers which private key signs for one.
`sign(address, msg)` is what the three together buy, a message signature
addressed by *address*, which `bms.sign` cannot offer because it has no
way to find the key.

Two key sources, one class each. `BIP32KeyStore` takes an extended key
and the BIP44 account path it sits on, and derives addresses down the two
unhardened levels below it; `KeyStore` takes individual keys, one address
each, and is also the base the derivation is added to. Either one is
watch-only when it holds no private key -- an xpub, or public keys -- and
that is a first-class state rather than a broken one: watching is most of
what a keystore does, and `sign` on one raises rather than returning
something a caller might mistake for a signature.

**What this module is not.** No utxo tracking, no balances, no
transaction building, no persistence to disk, no encryption at rest. Each
of those is a decision this module cannot take on its own: the first three
need a view of the chain, which btclib does not have and does not fetch,
and the last two need a file format and a key-derivation function that
would outlive any release choosing them. Without them a keystore is a
pure function of its key source -- the same source gives the same
addresses in the same order, every time -- which is what makes it
testable and what keeps its whole state in memory, where the caller can
see it. A spender is the larger reading of "wallet" and belongs above
this, not inside it.

Which encoding an account path means is `bip44`'s question and is
answered there, not here: this module imports that mapping and those four
encoders rather than keeping a second copy, so a purpose added to
`bip44`'s data file is a purpose a keystore hands out. What it does not
borrow is `bip44.address_from_der_path`, which walks the whole five-level
path from the extended key it is given; a keystore has already derived
down to the account at construction, and `bip32.derive_from_account` --
which imposes the branch and index bounds -- is the two levels left.

https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from dataclasses import dataclass

from btclib import b32, b58
from btclib.alias import BIP44ScriptType, Octets, String
from btclib.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    derive,
    derive_from_account,
)
from btclib.bip32.der_path import (
    _HARDENED_OFFSET,
    DerPath,
    indexes_from_der_path,
    str_from_der_path,
)
from btclib.bip44 import _ADDRESS_FROM_SCRIPT_TYPE, _script_type_from_purpose
from btclib.ecc import bms
from btclib.exceptions import BTClibValueError
from btclib.network import NETWORKS, network_from_xkeyversion
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.to_pub_key import Key, pub_keyinfo_from_key, pub_keyinfo_from_pub_key

# purpose, coin type, account: the three hardened levels of a BIP44 path
# above the two a keystore walks itself
_ACCOUNT_LEVELS = 3

# native segwit, which is what a wallet created today uses and what
# `slip132.p2wpkh_xkey` already defaults to
_DEFAULT_ACCOUNT = "m/84h/0h/0h"
_DEFAULT_SCRIPT_TYPE: BIP44ScriptType = "p2wpkh"


def _checked_script_type(script_type: str) -> BIP44ScriptType:
    """Return a script type this module can turn into an address.

    The lookup and not an isinstance, for `bip44`'s reason: the table is
    the list of encodings that exist, so missing from it and unknown are
    one thing, and a Literal is a mypy fact rather than a runtime one.
    What this adds to the caller's `BIP44ScriptType` annotation is the
    check for a caller who runs no type checker.
    """
    if script_type not in _ADDRESS_FROM_SCRIPT_TYPE:
        known = ", ".join(sorted(_ADDRESS_FROM_SCRIPT_TYPE))
        err_msg = f"unknown script type: {script_type} not in ({known})"
        raise BTClibValueError(err_msg)
    # no cast: the table is keyed by BIP44ScriptType, so the membership
    # test above narrows the str to it and mypy calls a cast redundant
    return script_type


def _address_str(address: String) -> str:
    """Return an address spelled the way a keystore records it.

    Bech32 is case insensitive and BIP173 blesses the upper case spelling
    for QR codes, so an address read off one has to find the lower case
    one the keystore handed out. Base58 is not case insensitive -- `1Lq`
    and `1lq` are different payloads -- so it is left exactly as it came.
    """
    addr = address.decode("ascii") if isinstance(address, bytes) else address
    addr = addr.strip()
    return addr.lower() if b32.has_segwit_prefix(addr) else addr


def _wif_if_private(key: Key, network: str) -> str:
    """Return the WIF of a private key, or "" for a public one.

    Two of the five spellings `to_pub_key.Key` admits say which they are
    by their type, and are taken first because the ambiguous test below
    cannot be asked of them: an int is a scalar, so it is a private key,
    and a point is a pair of coordinates, so it is a public one.

    The rest -- octets, a WIF or an extended key -- are told apart in the
    order `to_pub_key.pub_keyinfo_from_key` tells them apart, public
    first: a public key is a complete answer here, the keystore watching
    that address and unable to sign for it, while anything that is not
    one has to be a private key, and the error raised for a malformed one
    is the diagnosis the caller needs rather than a silent demotion to
    watch-only.
    """
    if isinstance(key, int):
        return b58.wif_from_prv_key(key, network)
    if isinstance(key, tuple):
        return ""

    with contextlib.suppress(BTClibValueError):
        pub_keyinfo_from_pub_key(key, network)
        return ""

    q, net, compressed = prv_keyinfo_from_prv_key(key, network)
    return b58.wif_from_prv_key(q, net, compressed)


@dataclass(frozen=True)
class AddressInfo:
    """What a keystore remembers about one address it has handed out.

    No key material, deliberately: this is the record a caller prints,
    logs and compares, and the private key is one call away behind
    `KeyStore.prv_key`, which reads as the request it is. Frozen for the
    same reason `addresses` hands back a tuple -- what comes out of a
    keystore is a copy of what it knows, not a handle on it.

    `der_path` is the whole path from the master key, so that it can be
    handed to `bip32.derive` or written into a PSBT key origin as it
    stands; it is empty for a key that came into the keystore on its own,
    which has no path.
    """

    address: str
    script_type: BIP44ScriptType
    der_path: str


class KeyStore:
    """Individual keys, the address of each, and who signs for it.

    The addresses are handed out by `add`, one per key, all of them in
    the script type the keystore was built with; `BIP32KeyStore` below is
    the same thing with an extended key underneath and derivation on top.

    A public key is as welcome as a private one and makes that address
    watch-only. `sign` then raises, naming the address: the alternative
    would be a keystore that answers a signing request with something
    falsy, and every caller that forgets to check has published an
    unsigned message.
    """

    def __init__(
        self,
        keys: Iterable[Key] = (),
        script_type: BIP44ScriptType = _DEFAULT_SCRIPT_TYPE,
        network: str = "mainnet",
    ) -> None:
        if network not in NETWORKS:
            raise BTClibValueError(f"unknown network: {network}")
        self.network = network
        self.script_type = _checked_script_type(script_type)

        # insertion ordered, which is the order the addresses were handed
        # out in: `addresses` is that order and nothing else records it
        self._handed_out: dict[str, AddressInfo] = {}
        # address -> WIF, and only for the keys that came in on their own.
        # A BIP32KeyStore re-derives instead of caching, so what is held
        # here is exactly the key material the caller handed over
        self._prv_keys: dict[str, str] = {}

        for key in keys:
            self.add(key)

    def __len__(self) -> int:
        return len(self._handed_out)

    def __contains__(self, address: String) -> bool:
        """Whether the keystore has handed this address out.

        The question `address_info` raises on, asked without the
        exception: a caller deciding what to do about an unknown address
        is not handling an error, and should not have to write one.
        """
        return _address_str(address) in self._handed_out

    @property
    def addresses(self) -> tuple[str, ...]:
        """Every address handed out, in the order it was handed out."""
        return tuple(self._handed_out)

    @property
    def is_watch_only(self) -> bool:
        """Whether the keystore holds no private key at all."""
        return not self._prv_keys

    def add(self, key: Key, script_type: BIP44ScriptType | None = None) -> str:
        """Take one key into the keystore, and return its address."""
        script_type = (
            self.script_type
            if script_type is None
            else _checked_script_type(script_type)
        )
        pub_key, _ = pub_keyinfo_from_key(key, self.network)
        # segwit has no uncompressed form, so the three segwit encodings
        # would silently answer an uncompressed key with the address of
        # its compressed twin -- an address bms cannot then sign for,
        # because the recovery flag it would need says compressed
        if script_type != "p2pkh" and len(pub_key) != 33:
            err_msg = f"uncompressed key cannot be {script_type}:"
            err_msg += " segwit has no uncompressed form"
            raise BTClibValueError(err_msg)

        address = _ADDRESS_FROM_SCRIPT_TYPE[script_type](key, self.network)
        if wif := _wif_if_private(key, self.network):
            self._prv_keys[address] = wif
        self._handed_out[address] = AddressInfo(address, script_type, "")
        return address

    def address_info(self, address: String) -> AddressInfo:
        """Return what the keystore remembers about an address.

        A miss raises rather than answering None. A keystore that has not
        handed an address out has no opinion about it -- not "no key",
        which is what a watch-only address has -- and the two are worth
        different answers; and every other lookup in btclib raises, so a
        None here would be the one place a caller has to remember not to
        use the result. `address in keystore` is the question that wants
        a boolean.

        A miss is also not evidence that the keystore cannot reach the
        address: a `BIP32KeyStore` derives on demand, so an address of
        its own chain that it has not been asked for yet is a miss.
        `address(branch, index)` is what puts one in.
        """
        addr = _address_str(address)
        if addr not in self._handed_out:
            err_msg = f"address not in the keystore: {addr}"
            raise BTClibValueError(err_msg)
        return self._handed_out[addr]

    def prv_key(self, address: String) -> str:
        """Return the WIF of the private key signing for an address."""
        addr = self.address_info(address).address
        if addr not in self._prv_keys:
            raise BTClibValueError(f"watch-only address, no private key: {addr}")
        return self._prv_keys[addr]

    def sign(self, address: String, msg: Octets) -> bms.Sig:
        """Return the BMS signature of a message, by address.

        The address is the argument `bms.sign` has no way to resolve on
        its own; everything after the lookup is `bms.sign`'s, this method
        signing nothing itself. The resolved address is passed on to it
        as well as the key, which is what makes the recovery flag name
        the right address type -- BIP137's 35..38 for the wrapped segwit
        spelling and 39..42 for the native one -- rather than the
        compressed p2pkh flag that a key alone would produce.
        """
        info = self.address_info(address)
        # p2tr is the one script type this module hands out and cannot
        # sign for. BMS recovers an ECDSA public key and matches it
        # against a hash160; a taproot output key is an x-only BIP340 key
        # tweaked by BIP341, which none of the sixteen recovery flags
        # names, so bms would refuse it as a "mismatch between private
        # key and address" -- true of every wrong key and misleading
        # here, where the key is right and the scheme is the problem.
        # BIP322 is the signature a taproot address wants, and btclib has
        # no implementation of it yet
        if info.script_type == "p2tr":
            err_msg = f"BMS cannot sign for a p2tr address: {info.address};"
            err_msg += " message signing for taproot is BIP322"
            raise BTClibValueError(err_msg)
        return bms.sign(msg, self.prv_key(info.address), info.address)


class BIP32KeyStore(KeyStore):
    """An extended key at a BIP44 account, and the addresses below it.

    `xkey` is the master key, the account key, or any key between the
    two; `der_path` is always the whole account path from the master,
    `m/purpose'/coin_type'/account'`, because the purpose lives at the
    top of it and is what says whether the addresses are p2pkh, p2wpkh-
    p2sh, p2wpkh or p2tr. What is left of the path below the key is
    derived once, at construction.

    Addresses come from the two unhardened levels BIP44 puts under an
    account, `branch/index` with branch 0 receiving and 1 change, which
    is also what public derivation can walk -- so an account *xpub* is a
    complete watch-only keystore.
    """

    def __init__(
        self,
        xkey: BIP32Key,
        der_path: DerPath = _DEFAULT_ACCOUNT,
        script_type: BIP44ScriptType | None = None,
    ) -> None:
        if not isinstance(xkey, BIP32KeyData):
            xkey = BIP32KeyData.b58decode(xkey)

        indexes = indexes_from_der_path(der_path)
        if len(indexes) != _ACCOUNT_LEVELS:
            err_msg = f"invalid account path: {len(indexes)} levels"
            err_msg += f" instead of {_ACCOUNT_LEVELS}"
            raise BTClibValueError(err_msg)
        # the hardening is checked and not merely documented because the
        # purpose is read off the first index: m/84/0h/0h derives an
        # account no BIP84 wallet has, and reading 84 out of it would
        # answer that account with p2wpkh addresses as if they were the
        # ones a BIP84 wallet watches
        if any(index < _HARDENED_OFFSET for index in indexes):
            err_msg = "invalid account path: all three levels must be hardened"
            raise BTClibValueError(err_msg)

        super().__init__(
            script_type=(
                _script_type_from_purpose(indexes[0] - _HARDENED_OFFSET)
                if script_type is None
                else script_type
            ),
            network=network_from_xkeyversion(xkey.version),
        )

        self.der_path = str_from_der_path(indexes)
        self._xkey = self._account_xkey(xkey, indexes)
        # branch -> the index `next_address` will hand out next, which is
        # one past the highest handed out so far and not a count of them:
        # `address(0, 7)` on a fresh keystore leaves the next at 8, so
        # that a keystore restored by replaying the paths it issued does
        # not reissue one
        self._next_index: dict[int, int] = {}

    @staticmethod
    def _account_xkey(xkey: BIP32KeyData, indexes: list[int]) -> BIP32KeyData:
        """Return the account key, deriving whatever is left of the path.

        The key may be anywhere on the account path, its depth saying how
        much of the path is already behind it; what it can be checked
        against is its own index, which is the path element at that
        depth. That catches the account xpub paired with the path of
        another account. It cannot catch a key from another purpose or
        another coin, an extended key recording nothing about where it
        came from, so the caller's word is taken for the levels above.
        """
        if xkey.depth > _ACCOUNT_LEVELS:
            err_msg = f"invalid key depth: {xkey.depth} is past the"
            err_msg += f" {_ACCOUNT_LEVELS} levels of an account path"
            raise BTClibValueError(err_msg)
        if xkey.depth and xkey.index != indexes[xkey.depth - 1]:
            err_msg = f"key index {xkey.index} at depth {xkey.depth}"
            err_msg += f" is not the account path's {indexes[xkey.depth - 1]}"
            raise BTClibValueError(err_msg)

        # the public `derive` rather than bip32's private `_derive`: what
        # it costs is one b58 round trip, once, at construction
        return BIP32KeyData.b58decode(derive(xkey, indexes[xkey.depth :]))

    @property
    def is_watch_only(self) -> bool:
        """Whether the keystore holds no private key at all.

        An xpub account is the watch-only case; a private key handed to
        `add` alongside it is not derived from the account and does not
        make the account signable, but it does make the keystore hold key
        material, which is what this answers.
        """
        return not self._xkey.is_private and super().is_watch_only

    def address(self, branch: int, index: int) -> str:
        """Hand out the address at branch/index, and remember the path.

        Idempotent: asking twice derives twice and records once, the
        keystore being a function of its key source rather than a
        generator with a position. `bip32.derive_from_account` is what
        imposes the bounds -- branch 0 or 1, index at most 65535 -- and
        the message on a violation is its own.
        """
        key = derive_from_account(self._xkey, branch, index)
        address = _ADDRESS_FROM_SCRIPT_TYPE[self.script_type](key, self.network)
        der_path = f"{self.der_path}/{branch}/{index}"
        self._handed_out[address] = AddressInfo(address, self.script_type, der_path)
        self._next_index[branch] = max(self._next_index.get(branch, 0), index + 1)
        return address

    def next_address(self, branch: int = 0) -> str:
        """Hand out the next unused address of a branch."""
        return self.address(branch, self._next_index.get(branch, 0))

    def prv_key(self, address: String) -> str:
        """Return the WIF of the private key signing for an address."""
        info = self.address_info(address)
        # a key added on its own, which the base class holds and this
        # keystore cannot derive: it has no path, and the account key is
        # not its parent
        if info.address in self._prv_keys:
            return self._prv_keys[info.address]

        if not self._xkey.is_private:
            err_msg = "watch-only keystore, no private key for"
            err_msg += f" {info.address} at {info.der_path}"
            raise BTClibValueError(err_msg)

        # re-derived rather than cached: the path is the record, and one
        # source of truth cannot disagree with itself. It also keeps the
        # keystore holding one private key, the account one, however many
        # addresses it has handed out
        branch, index = indexes_from_der_path(info.der_path)[-2:]
        return b58.wif_from_prv_key(derive_from_account(self._xkey, branch, index))
