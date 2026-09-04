# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP44 address: an extended key and m/purpose/coin/account/change/index.

https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

The composition every wallet performs and no single call here did:
`bip32.derive` walks the path, `b58` and `b32` encode the address, and
the purpose level -- BIP43's, the first of the five -- says which of the
four encodings the path means. Nothing in this module derives or encodes
anything itself; what it adds is the mapping that makes a path
unambiguous, and the two checks that keep it honest.

The module sits above `script`, and taproot is the reason: a p2tr
address encodes the *tweaked* output key of BIP341, which
`script.taproot.output_pubkey` computes, and `bip32` is below `script`
and may not import it. `slip132` sits beside it at the top level for a
narrower version of the same shape: it needs `b58` and `b32`, which
import `bip32`, so it cannot live inside the package whose keys it
derives addresses from either.

What imports this module is what the mapping and the checks are for, and
in one direction only: `wallet` takes the encoders and the purpose
lookup rather than keeping a second copy of either, and `descriptors`
takes the path checks and the same lookup for the account descriptor pair
it builds. Neither is imported back -- a descriptor is what a wallet
exports, and this is what a path means.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from btclib import b32, b58
from btclib.alias import BIP44ScriptType, NetworkType
from btclib.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    _derive,
    _key_data_from_bip32_key,
    pub_keyinfo_from_xkey,
)
from btclib.bip32.der_path import (
    _HARDENED_OFFSET,
    DerPath,
    indexes_from_der_path,
    str_from_index_int,
)
from btclib.exceptions import BTClibValueError
from btclib.network import network_from_xkeyversion, network_type_from_xkeyversion
from btclib.script.taproot import output_pubkey
from btclib.to_pub_key import Key

__all__ = [
    "SCRIPT_TYPE_FROM_PURPOSE",
    "address_from_der_path",
]

# purpose, coin type, account, change, address index: BIP44 fixes the
# meaning of each level, so a path of any other length is not one
_LEVELS = 5
# the first three of them, which are the hardened ones and as much of the
# path as an account xpub stands for: what a wallet exports, and what a
# descriptor's key origin names
_ACCOUNT_LEVELS = 3

# the mapping is data and lives with the network data, not in this file:
# it is the canonical row of the wallet-format table electrum ships as
# bip39_wallet_formats.json (sourced from walletsrecovery.org) and uses
# to scan a seed for the derivations wallets actually use. What a
# recovery helper wants next -- per-wallet rows, with the xpub version
# each writes -- is more of this file and no more of this module, and
# that list tracks the wallet ecosystem rather than the library
_PURPOSES_FILE = Path(__file__).parent / "_data" / "bip44_purposes.json"
with _PURPOSES_FILE.open(encoding="ascii") as _purposes:
    # json object keys are strings; a purpose is an int, as it is in a
    # derivation path. The values are annotated and not validated here:
    # BIP44ScriptType is a mypy fact and json.load answers Any, so what
    # refuses a script type the file should not have named is the same
    # table lookup that refuses one a caller passes
    SCRIPT_TYPE_FROM_PURPOSE: dict[int, BIP44ScriptType] = {
        int(purpose): script_type
        for purpose, script_type in json.load(_purposes).items()
    }

# BIP44's registered coin types, and the only two it registers: 0 is
# Bitcoin and 1 is "Bitcoin Testnet", which SLIP44 widens to the test
# chain of every coin. That is why what they are checked against is the
# network *type* of the extended key and not its name: btclib's test
# networks share one set of version bytes, so an xkey cannot say which of
# them it is, and coin type 1 does not distinguish them either
_NETWORK_TYPE_FROM_COIN_TYPE: dict[int, NetworkType] = {0: "main", 1: "test"}


def _p2tr(key: Key, network: str) -> str:
    """Return the p2tr address of a key, tweaked as BIP86 prescribes.

    BIP86 is BIP44 for taproot and the tweak is the whole of it: the
    output key commits to the internal key and to no script path, so what
    the address encodes is not the derived key but `output_pubkey` of it
    with an empty merkle root. The other three encoders take the derived
    key as it comes, which is why this one is a function here and
    `b32.p2tr` -- which expects the output key already tweaked -- is not
    in the table below.
    """
    return b32.p2tr(output_pubkey(key)[0], network)


# a key and the network in, the address out: four encodings that already
# exist, named by the script type the purpose resolves to. Keyed by
# BIP44ScriptType, so the alias and this table are checked against each
# other -- a fifth encoding is a key mypy does not know.
#
# The key is a Key and not the SEC octets every caller passes, because
# all four encoders take one and narrowing it here would make the table
# this module's rather than the library's, for no check gained
_ADDRESS_FROM_SCRIPT_TYPE: dict[BIP44ScriptType, Callable[[Key, str], str]] = {
    "p2pkh": b58.p2pkh,
    "p2wpkh-p2sh": b58.p2wpkh_p2sh,
    "p2wpkh": b32.p2wpkh,
    "p2tr": _p2tr,
}


def _assert_valid_path(indexes: list[int]) -> None:
    """Raise unless the indexes are the five levels BIP44 defines.

    The hardening is checked and not merely documented because the
    purpose is read off the first index: `m/84/0h/0h/0/0` derives a key
    no BIP84 wallet has, and reading 84 out of it would answer that key
    with a p2wpkh address as if it were the right one.
    """
    if len(indexes) != _LEVELS:
        err_msg = f"invalid BIP44 path: {len(indexes)} levels instead of {_LEVELS}"
        raise BTClibValueError(err_msg)

    if any(index < _HARDENED_OFFSET for index in indexes[:_ACCOUNT_LEVELS]):
        err_msg = "invalid BIP44 path: purpose, coin type and account must be hardened"
        raise BTClibValueError(err_msg)

    if any(index >= _HARDENED_OFFSET for index in indexes[_ACCOUNT_LEVELS:]):
        err_msg = "invalid BIP44 path: change and address index must not be hardened"
        raise BTClibValueError(err_msg)


def _assert_valid_account_path(indexes: list[int]) -> None:
    """Raise unless the indexes are the three hardened levels of an account.

    m/purpose'/coin_type'/account', which is what a wallet exports and what
    a descriptor names in its key origin: the two levels below it are the
    unhardened ones public derivation can walk, so an account path is
    exactly as much as an xpub is useful for.

    The hardening is checked for the reason the five-level check gives, and
    one more: the whole point of stopping here is that nothing below needs
    a private key, and an unhardened account level would make the level
    above it -- not this path -- the last one that did.
    """
    if len(indexes) != _ACCOUNT_LEVELS:
        err_msg = f"invalid BIP44 account path: {len(indexes)} levels"
        err_msg += f" instead of {_ACCOUNT_LEVELS}"
        raise BTClibValueError(err_msg)

    if any(index < _HARDENED_OFFSET for index in indexes):
        err_msg = "invalid BIP44 account path: purpose, coin type and account"
        err_msg += " must be hardened"
        raise BTClibValueError(err_msg)


def _script_type_from_purpose(purpose: int) -> BIP44ScriptType:
    """Return the script type of a purpose, refusing the ones unknown.

    Refusing is the answer because the alternative is to guess: a purpose
    the mapping does not name says the path was written for a scheme this
    module has never been told about, and answering it with p2pkh --
    BIP44's own encoding, the tempting default -- would be an address the
    wallet that wrote the path does not watch. The caller who knows what
    the scheme is says so with the script_type argument, which is the
    override, and gets no guess either way.
    """
    script_type = SCRIPT_TYPE_FROM_PURPOSE.get(purpose)
    if script_type is None:
        known = ", ".join(str(known) for known in sorted(SCRIPT_TYPE_FROM_PURPOSE))
        err_msg = f"unknown BIP44 purpose: {purpose} not in ({known});"
        err_msg += " pass script_type to say what it means"
        raise BTClibValueError(err_msg)
    return script_type


def _assert_valid_coin_type(coin_type: int, xkey: BIP32KeyData) -> None:
    """Raise unless the coin type agrees with the key's own network.

    The address is minted on the network of the key, never on the one the
    path claims: the version bytes are what an xprv, a tpub or a zprv
    *is*, while the coin type is a claim about where the key was meant to
    live. When the two disagree, one of them is a mistake and nothing
    here can tell which, so neither is silently preferred -- taking the
    key's network alone would answer `m/44h/1h/0h/0/0` under a mainnet
    xprv with a real-money address, from a path that says testnet.

    An unregistered coin type is refused for the same reason and not as
    an extra rule: coin type 2 is Litecoin, and the address this module
    would hand back is a bitcoin one, computed from a key the path says
    belongs to another chain.

    There is no override, where an unknown purpose has one, because an
    override here would mean "encode another chain's key as a bitcoin
    address" -- the very mistake this level of the path exists to
    prevent. A caller who wants exactly that is one b58 or b32 call away.
    """
    network_type = _NETWORK_TYPE_FROM_COIN_TYPE.get(coin_type)
    if network_type is None:
        registered = ", ".join(str(coin) for coin in _NETWORK_TYPE_FROM_COIN_TYPE)
        err_msg = f"unregistered BIP44 coin type: {coin_type} not in ({registered})"
        raise BTClibValueError(err_msg)

    key_network_type = network_type_from_xkeyversion(xkey.version)
    if network_type != key_network_type:
        err_msg = f"coin type {coin_type} is {network_type},"
        err_msg += f" the extended key is {key_network_type}"
        raise BTClibValueError(err_msg)


def _indexes_left_to_derive(xkey: BIP32KeyData, indexes: list[int]) -> list[int]:
    """Return the tail of the path the key has not walked yet.

    The path is always the whole of it, from the master key down, because
    that is where the purpose is; the key may be anywhere along it. An
    account xpub is the case that matters -- it is what a wallet exports,
    and the two levels left below it are the unhardened ones public
    derivation can walk -- and its depth says which levels are already
    behind it.

    What the key can be checked against is its own index, which is the
    path element at its depth. That catches the account xpub paired with
    the path of another account; it cannot catch a key from another
    purpose or another coin, nothing in an extended key recording where
    it came from, so the caller's word is taken for the levels above.

    The bound is the path's own length rather than BIP44's five, because
    an account path is three of them: a key deeper than the path it is
    handed has walked past its end, whichever of the two paths it is.
    """
    if xkey.depth > len(indexes):
        err_msg = f"invalid key depth: {xkey.depth} is past the {len(indexes)}"
        err_msg += " levels of the path"
        raise BTClibValueError(err_msg)

    if xkey.depth and xkey.index != indexes[xkey.depth - 1]:
        err_msg = f"key index {str_from_index_int(xkey.index)} at depth {xkey.depth}"
        err_msg += f" is not the path's {str_from_index_int(indexes[xkey.depth - 1])}"
        raise BTClibValueError(err_msg)

    return indexes[xkey.depth :]


def address_from_der_path(
    xkey: BIP32Key, der_path: DerPath, script_type: BIP44ScriptType | None = None
) -> str:
    """Return the address of a BIP44 derivation path.

    der_path is the whole five-level path,
    m/purpose'/coin_type'/account'/change/address_index, in any spelling
    `bip32.derive` accepts; xkey is the extended key it starts from,
    which may be the master key or any key already partway down it -- an
    account xpub, typically, the depth saying how much of the path is
    behind it.

    The purpose selects the encoding: 44 is p2pkh, 49 p2wpkh-p2sh, 84
    p2wpkh, 86 p2tr. A purpose outside that mapping raises, unless
    script_type names one of those four encodings, which then overrides
    the mapping for known purposes too.

    The network is the extended key's own; the coin type has to agree
    with it, 0 for mainnet and 1 for any test network, or the path and
    the key are describing different chains and neither wins.
    """
    xkey = _key_data_from_bip32_key(xkey)

    indexes = indexes_from_der_path(der_path)
    _assert_valid_path(indexes)

    if script_type is None:
        script_type = _script_type_from_purpose(indexes[0] - _HARDENED_OFFSET)
    # the lookup and not an isinstance: the table is the list of encodings
    # this module has, so missing from it and unknown are one thing. The
    # check survives BIP44ScriptType typing the argument because a Literal
    # is a mypy fact and not a runtime one -- it is what refuses a fifth
    # script type from the json above, and from a caller who runs no type
    # checker
    address_funct = _ADDRESS_FROM_SCRIPT_TYPE.get(script_type)
    if address_funct is None:
        known = ", ".join(sorted(_ADDRESS_FROM_SCRIPT_TYPE))
        err_msg = f"unknown script type: {script_type} not in ({known})"
        raise BTClibValueError(err_msg)

    _assert_valid_coin_type(indexes[1] - _HARDENED_OFFSET, xkey)

    # the derived key stays decoded: an extended key is not a `Key`
    # (issue #1188), so what the encoder is handed is its public key, and
    # the public `derive` would serialize this one here for
    # `pub_keyinfo_from_xkey` to decode straight back
    key = _derive(xkey, _indexes_left_to_derive(xkey, indexes), None)
    network = network_from_xkeyversion(xkey.version)
    return address_funct(pub_keyinfo_from_xkey(key, network)[0], network)
