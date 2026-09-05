# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The wallets whose output is the hash of one key, and who signs for it.

`btclib.ecc.bms` says it in its own docstring -- "at signing time, a
wallet infrastructure is required to access the private key corresponding
to a given address" -- and then has none to reach for. This module is
that infrastructure, and no more of it than the sentence asks for: a
wallet holds a key source, hands out addresses, remembers what each was
derived from, and answers which private key signs for one.
`sign(address, msg)` is what the three together buy, a message signature
addressed by *address*, which `bms.sign` cannot offer because it has no
way to find the key.

Two key sources, one class each. `BIP32KeyWallet` takes an extended key
and the BIP44 account path it sits on, and derives the addresses of the
two unhardened levels below it; `KeyWallet` takes individual keys, one
address each, and is also the base the derivation is added to. Either one
is watch-only when it holds no private key -- an xpub, or public keys --
and `sign` on one raises rather than returning something a caller might
mistake for a signature.

Both are the one-key half of `btclib.wallet`: the address is a hash of a
single public key, which is what makes a private key for it a single
thing to look up. `BIP44ScriptType` is therefore the whole of what they
encode -- a p2wsh address is the hash of a *script*, and `ScriptWallet`
is where a script goes.

Which encoding an account path means is `bip44`'s question and is
answered there, not here: this module imports that mapping and those four
encoders rather than keeping a second copy, so a purpose added to
`bip44`'s data file is a purpose a wallet hands out. What it does not
borrow is `bip44.address_from_der_path`, which walks the whole five-level
path from the extended key it is given; a wallet has already derived down
to the account at construction, and `bip32.derive_from_account` -- which
imposes the branch and index bounds -- is the two levels left.

https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
"""

from __future__ import annotations

from collections.abc import Iterable

from typing_extensions import override

from btclib import b58
from btclib.alias import BIP44ScriptType, Octets, String
from btclib.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    _key_data_from_bip32_key,
    derive_,
    derive_from_account_,
    prv_keyinfo_from_xprv,
    pub_keyinfo_from_xkey,
)
from btclib.bip32.der_path import (
    _HARDENED_OFFSET,
    DerPath,
    indexes_from_der_path,
    str_from_der_path,
)
from btclib.bip44 import _ADDRESS_FROM_SCRIPT_TYPE, _script_type_from_purpose
from btclib.curves import PreparedPoint
from btclib.ecc import bms
from btclib.exceptions import BTClibValueError, NotAPrvKeyError
from btclib.key import PrvKeyData, PubKeyData
from btclib.network import network_from_xkeyversion
from btclib.script.script_pub_key import ScriptPubKey
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.to_pub_key import Key, pub_keyinfo_from_pub_key
from btclib.wallet.wallet import AddressInfo, RangedWallet, Wallet

__all__ = [
    "BIP32KeyWallet",
    "KeyWallet",
]

# purpose, coin type, account: the three hardened levels of a BIP44 path
# above the two a wallet walks itself
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


def _key_data(key: Key, network: str) -> PrvKeyData | PubKeyData:
    """Return the canonical form of a key, and which half it is.

    The spellings `to_pub_key.Key` admits stop here: what leaves is one
    of the two `btclib.key` types, parsed once, and which of them it is
    is the answer to "can this wallet sign", which `add` therefore reads
    off a type instead of walking the spellings for it.

    Two of them say which half they are by their type, and are taken
    first because the ambiguous test below cannot be asked of them: an
    int is a scalar, so it is a private key, and a point is a pair of
    coordinates, so it is a public one -- a `PreparedPoint` with it, that
    being a point and a caller's word about how often it will be
    multiplied, which says nothing about who can sign.

    The rest -- octets or a WIF -- are told apart public first: a public
    key is a complete answer here, the wallet watching that address and
    unable to sign for it, while anything that is not one has to be a
    private key, and the error raised for a malformed one is the
    diagnosis the caller needs rather than a silent demotion to
    watch-only. Only the converter's refusal is caught, and not
    `PubKeyData`'s own: what the type refused would otherwise fall
    through to the private branch and come back as "not a private key",
    its own diagnosis lost. Nothing reaches that today, and the narrow
    `try` is so that nothing can rather than that nothing does.

    A WIF is tried ahead of `to_prv_key.prv_keyinfo_from_prv_key`, which
    cannot resolve one itself: `b58` is where a WIF is read, and this
    module already imports it for the direction `add` below writes. It is
    tried unguarded, the two branches above having left `Octets` as the
    whole of what reaches it -- an extended key is not a `Key` at all,
    `bip32` being where one is read (issue #1188).

    Both types re-check what the converter that fed them has already
    guaranteed, which looks redundant and is not: `to_prv_key` admits a
    `bool` and `PrvKeyData` refuses one, so without this second check
    `add(True)` is the scalar 1 and an address handed back for it.
    """
    if isinstance(key, int):
        return PrvKeyData(*prv_keyinfo_from_prv_key(key, network))
    if isinstance(key, (tuple, PreparedPoint)):
        return PubKeyData(*pub_keyinfo_from_pub_key(key, network))

    try:
        pub_key_info = pub_keyinfo_from_pub_key(key, network)
    except BTClibValueError:
        pass
    else:
        return PubKeyData(*pub_key_info)

    try:
        return b58.prv_key_data_from_wif(key, network)
    except NotAPrvKeyError:
        pass
    return PrvKeyData(*prv_keyinfo_from_prv_key(key, network))


class KeyWallet(Wallet):
    """Individual keys, the address of each, and who signs for it.

    The addresses are handed out by `add`, one per key, all of them in
    the script type the wallet was built with; `BIP32KeyWallet` below is
    the same thing with an extended key underneath and derivation on top.

    A public key is as welcome as a private one and makes that address
    watch-only. `sign` then raises, naming the address: the alternative
    would be a wallet that answers a signing request with something
    falsy, and every caller that forgets to check has published an
    unsigned message.

    Not a `RangedWallet`: a key handed over is one address and there is
    no position it came from, so `address(branch, index)` would have
    nothing to compute. `BIP32KeyWallet` is where the positions are.
    """

    def __init__(
        self,
        keys: Iterable[Key] = (),
        script_type: BIP44ScriptType = _DEFAULT_SCRIPT_TYPE,
        network: str = "mainnet",
    ) -> None:
        super().__init__(network)
        self.script_type = _checked_script_type(script_type)

        # address -> WIF, and only for the keys that came in on their own.
        # A BIP32KeyWallet re-derives instead of caching, so what is held
        # here is exactly the key material the caller handed over
        self._prv_keys: dict[str, str] = {}

        for key in keys:
            self.add(key)

    @property
    @override
    def is_watch_only(self) -> bool:
        """Whether the wallet holds no private key at all."""
        return not self._prv_keys

    def add(self, key: Key, script_type: BIP44ScriptType | None = None) -> str:
        """Take one key into the wallet, and return its address."""
        # one call for both paths, and it is what narrows the str
        # `Wallet.script_type` carries back to the Literal the table below
        # is keyed by: what every wallet answers is a script type, and
        # which four of them exist is this module's own vocabulary
        checked = _checked_script_type(
            self.script_type if script_type is None else script_type
        )
        # parsed once, and the type of what comes back is what says
        # whether this wallet can sign: `data.pub` derives at most once
        # and memoizes, so the address builder below is handed those
        # octets rather than a key it would derive them from again
        # (issue #1188)
        data = _key_data(key, self.network)
        pub = data.pub if isinstance(data, PrvKeyData) else data
        # segwit has no uncompressed form, so the three segwit encodings
        # would silently answer an uncompressed key with the address of
        # its compressed twin -- an address bms cannot then sign for,
        # because the recovery flag it would need says compressed
        if checked != "p2pkh" and not pub.is_compressed:
            err_msg = f"uncompressed key cannot be {checked}:"
            err_msg += " segwit has no uncompressed form"
            raise BTClibValueError(err_msg)

        address = _ADDRESS_FROM_SCRIPT_TYPE[checked](pub.sec, self.network)
        if isinstance(data, PrvKeyData):
            wif = b58.wif_from_prv_key(data.q, data.network, data.compressed)
            self._prv_keys[address] = wif
        return self._record(AddressInfo(address, checked, ""))

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

        BMS and no other scheme, which is what leaves p2tr out: a caller
        wanting BIP322 for one of these addresses passes `prv_key` and
        the address to `btclib.bip322.sign`, which signs for all four
        script types this module hands out.
        """
        info = self.address_info(address)
        # p2tr is the one script type this module hands out and cannot
        # sign for. BMS recovers an ECDSA public key and matches it
        # against a hash160; a taproot output key is an x-only BIP340 key
        # tweaked by BIP341, which none of the sixteen recovery flags
        # names, so bms would refuse it as a "mismatch between private
        # key and address" -- true of every wrong key and misleading
        # here, where the key is right and the scheme is the problem
        if info.script_type == "p2tr":
            err_msg = f"BMS cannot sign for a p2tr address: {info.address};"
            err_msg += " message signing for taproot is btclib.bip322"
            raise BTClibValueError(err_msg)
        prv_key = b58.prv_key_data_from_wif(self.prv_key(info.address))
        return bms.sign(msg, prv_key, info.address)


class BIP32KeyWallet(KeyWallet, RangedWallet):
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
    complete watch-only wallet.

    Both bases carry their weight: `RangedWallet` is the positions, and
    `KeyWallet` the signing and the loose keys, which an extended key
    does not stop a caller from adding.
    """

    def __init__(
        self,
        xkey: BIP32Key,
        der_path: DerPath = _DEFAULT_ACCOUNT,
        script_type: BIP44ScriptType | None = None,
    ) -> None:
        xkey = _key_data_from_bip32_key(xkey)

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

        # `derive_` rather than bip32's private `_derive`: the public
        # spelling, and the one that answers the key -- where `derive`
        # answers its Base58Check text, which this line would decode
        # straight back, paying a b58 round trip for nothing
        return derive_(xkey, indexes[xkey.depth :])

    @property
    @override
    def branches(self) -> tuple[int, ...]:
        """The receiving and change chains, which is what BIP44 defines.

        The two `bip32.derive_from_account` walks and the only two: a
        third would be a chain no BIP44 wallet looks at, so an address of
        it is an address nobody else recovers.
        """
        return (0, 1)

    @property
    @override
    def is_watch_only(self) -> bool:
        """Whether the wallet holds no private key at all.

        An xpub account is the watch-only case; a private key handed to
        `add` alongside it is not derived from the account and does not
        make the account signable, but it does make the wallet hold key
        material, which is what this answers.
        """
        return not self._xkey.is_private and super().is_watch_only

    def _derived_xkey(self, branch: int, index: int) -> BIP32KeyData:
        """Return the extended key of a position, bounds imposed.

        `bip32.derive_from_account_` is what imposes them -- branch 0 or 1,
        index at most 65535 -- and the message on a violation is its own.

        The key and not its xprv/xpub text: every caller resolves it with
        a `bip32` call, and answering text instead would make each of
        them build it and read it back inside one line (issue 886).
        Which call it is, is what the caller wants of the key: the
        address builders and `ScriptPubKey.p2wpkh` take a public key, so
        `_derived_sec` below is what feeds them, and
        `b58.wif_from_prv_key` wants the scalar an xprv resolves to
        (issue #1188).
        """
        return derive_from_account_(self._xkey, branch, index)

    def _derived_sec(self, branch: int, index: int) -> bytes:
        """Return the SEC public key of a position, whichever half derives it.

        An account xprv and its xpub derive to the same public key, so
        this is what an address is built from either way, and the wallet
        being watch-only is a question about signing rather than about
        the address.
        """
        return pub_keyinfo_from_xkey(self._derived_xkey(branch, index))[0]

    @override
    def _address(self, branch: int, index: int) -> str:
        # checked again for the narrowing and not for the check, which the
        # constructor already made: see `add` above
        return _ADDRESS_FROM_SCRIPT_TYPE[_checked_script_type(self.script_type)](
            self._derived_sec(branch, index), self.network
        )

    @override
    def _script_pub_key(self, branch: int, index: int) -> ScriptPubKey:
        """Return the output of a position, read back from its address.

        The address and not a second table: `bip44`'s is the library's one
        mapping from a key and a network to an address, `p2wpkh-p2sh` is
        a nesting rather than an output script type, and
        `ScriptPubKey.from_address` reads any of the four back into the
        very script that pays it. What it costs is one base58 or bech32
        round trip on a string this wallet has just written.
        """
        return ScriptPubKey.from_address(self._address(branch, index))

    @override
    def _der_path(self, branch: int, index: int) -> str:
        return f"{self.der_path}/{branch}/{index}"

    @override
    def redeem_script(self, branch: int = 0, index: int = 0) -> bytes:
        """Return the p2wpkh script a `p2wpkh-p2sh` output commits to.

        The one script type here that has one: the other three pay to a
        key hash or to a key, so what a spend of them pushes is the key
        itself and there is no pre-image for a psbt to carry -- which is
        the base class's answer, and is deferred to rather than repeated.
        """
        if self.script_type != "p2wpkh-p2sh":
            return super().redeem_script(branch, index)
        self._assert_position(branch, index)
        return ScriptPubKey.p2wpkh(self._derived_sec(branch, index)).script

    @override
    def prv_key(self, address: String) -> str:
        """Return the WIF of the private key signing for an address."""
        info = self.address_info(address)
        # a key added on its own, which the base class holds and this
        # wallet cannot derive: it has no path, and the account key is
        # not its parent
        if info.address in self._prv_keys:
            return self._prv_keys[info.address]

        if not self._xkey.is_private:
            err_msg = "watch-only wallet, no private key for"
            err_msg += f" {info.address} at {info.der_path}"
            raise BTClibValueError(err_msg)

        # re-derived rather than cached: the path is the record, and one
        # source of truth cannot disagree with itself. It also keeps the
        # wallet holding one private key, the account one, however many
        # addresses it has handed out
        branch, index = indexes_from_der_path(info.der_path)[-2:]
        xkey = self._derived_xkey(branch, index)
        q, network, compressed = prv_keyinfo_from_xprv(xkey)
        return b58.wif_from_prv_key(q, network, compressed)
