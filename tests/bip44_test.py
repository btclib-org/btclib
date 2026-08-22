# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bip44` module.

`descriptors.account_descriptors` is read here as well, against the same
vectors: it answers with the receive and change descriptors of an account
and reads the purpose off the same table, so the addresses it describes
have to be the addresses this module derives. What is tested there is the
function; what is tested here is that the two agree on published values.
"""

from __future__ import annotations

from typing import get_args

import pytest

from btclib import b32
from btclib.alias import BIP44ScriptType
from btclib.bip32 import bip32, fingerprint
from btclib.bip44 import (
    _ADDRESS_FROM_SCRIPT_TYPE,
    SCRIPT_TYPE_FROM_PURPOSE,
    address_from_der_path,
)
from btclib.descriptors import account_descriptors
from btclib.exceptions import BTClibValueError

# the "abandon abandon ... about" seed of BIP39, which BIP84 and BIP86
# publish as a root key: the same key, spelled with two versions
_XPRV_ROOT = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
_ZPRV_ROOT = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5"
# BIP49's own root, the same seed on testnet
_UPRV_ROOT = "uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd"

# (master key, account xpub, path, address), every field published.
#
# BIP44 has no address vector of its own -- it leans on BIP32's, which
# stop at the extended keys -- so the two mainnet rows for purposes 44
# and 49 are SLIP132's, which walks m/44h/0h/0h and m/49h/0h/0h from this
# very seed. Purpose 49 on testnet is BIP49's own vector, and the three
# rows each of purposes 84 and 86 are BIP84's and BIP86's.
#
# The account xpub of a row is the key the wallet exports, and the two
# entry points must agree: SLIP132 writes the purpose into the version
# byte, so the 49 mainnet row starts from a master xprv and an account
# ypub, which derive keys of different versions and the same address.
#
# https://github.com/satoshilabs/slips/blob/master/slip-0132.md
# https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
# https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
# https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
_VECTORS = [
    (
        _XPRV_ROOT,
        "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
        "m/44h/0h/0h/0/0",
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    ),
    (
        _XPRV_ROOT,
        "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP",
        "m/49h/0h/0h/0/0",
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
    ),
    (
        _UPRV_ROOT,
        "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY",
        "m/49h/1h/0h/0/0",
        "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
    ),
    (
        _ZPRV_ROOT,
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        "m/84h/0h/0h/0/0",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    ),
    (
        _ZPRV_ROOT,
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        "m/84h/0h/0h/0/1",
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    ),
    (
        _ZPRV_ROOT,
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        "m/84h/0h/0h/1/0",
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
    ),
    (
        _XPRV_ROOT,
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
        "m/86h/0h/0h/0/0",
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    ),
    (
        _XPRV_ROOT,
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
        "m/86h/0h/0h/0/1",
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
    ),
    (
        _XPRV_ROOT,
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
        "m/86h/0h/0h/1/0",
        "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
    ),
]


@pytest.mark.parametrize("mxkey, xpub, der_path, address", _VECTORS)
def test_bip44_vectors(mxkey: str, xpub: str, der_path: str, address: str) -> None:
    """Reproduce SLIP132, BIP49, BIP84 and BIP86 addresses, any level."""
    # from the master key, walking the whole path
    assert address_from_der_path(mxkey, der_path) == address
    # from the account xpub, walking the two public levels left
    assert address_from_der_path(xpub, der_path) == address
    # and from the address key itself, with nothing left to walk
    xkey = bip32.derive(mxkey, der_path)
    assert address_from_der_path(xkey, der_path) == address
    # a BIP32KeyData is a BIP32Key too
    assert (
        address_from_der_path(bip32.BIP32KeyData.b58decode(xkey), der_path) == address
    )


@pytest.mark.parametrize("mxkey, xpub, der_path, address", _VECTORS)
def test_the_account_descriptors_reach_the_same_addresses(
    mxkey: str, xpub: str, der_path: str, address: str
) -> None:
    """`descriptors.account_descriptors` and this module are one mapping.

    The purpose says which encoding a path means and both read it from the
    same table, so the pair a wallet exports has to describe the addresses
    this module answers for the same path: the change chain of the pair at
    an index is the `/1/index` address, and the receive chain the `/0/`
    one. The vectors above are published addresses, so this is the
    descriptor half of them.

    The account level is where the two split: `address_from_der_path`
    walks all five levels, while a descriptor names the first three in its
    key origin and derives the last two -- which is why the descriptors
    are built from the account path alone.
    """
    account, chain, index = der_path.rsplit("/", 2)
    pair = account_descriptors(mxkey, account)
    assert pair[int(chain)].address(int(index)) == address

    # and from the account xpub, which cannot say which master key it came
    # from, so the fingerprint the origin needs is handed in
    master_fingerprint = fingerprint(mxkey)
    from_account = account_descriptors(xpub, account, master_fingerprint)
    assert str(from_account[int(chain)]) == str(pair[int(chain)])


def test_purpose_mapping() -> None:
    """The mapping is the one BIP44, BIP49, BIP84 and BIP86 define."""
    assert SCRIPT_TYPE_FROM_PURPOSE == {
        44: "p2pkh",
        49: "p2wpkh-p2sh",
        84: "p2wpkh",
        86: "p2tr",
    }


def test_unknown_purpose() -> None:
    """Refuse purpose 48 bare, and let the script type override win."""
    # 48 is BIP48, multi-signature: a real purpose, and one whose script
    # type an account key does not determine
    err_msg = "unknown BIP44 purpose: 48 not in "
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(_XPRV_ROOT, "m/48h/0h/0h/0/0")

    # the override says what the mapping cannot, and the composition it
    # names is the one it performs
    der_path = "m/48h/0h/0h/0/0"
    address = address_from_der_path(_XPRV_ROOT, der_path, "p2wpkh")
    assert address == b32.p2wpkh(bip32.derive(_XPRV_ROOT, der_path))

    # it overrides a known purpose too, and the p2wpkh of BIP84's path is
    # BIP84's address whichever way it is asked for
    assert (
        address_from_der_path(_ZPRV_ROOT, "m/84h/0h/0h/0/0", "p2wpkh")
        == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    )


def test_unknown_script_type() -> None:
    """Refuse p2wsh, and verify the alias and the table agree."""
    # the alias and the table say the same four encodings, which is what
    # lets one of them type the other
    assert get_args(BIP44ScriptType) == tuple(_ADDRESS_FROM_SCRIPT_TYPE)
    assert set(SCRIPT_TYPE_FROM_PURPOSE.values()) == set(get_args(BIP44ScriptType))

    # p2wsh is an encoding btclib has; it is not one a single derived key
    # determines, so it is not in the table. mypy rejects the call, the
    # Literal being the static half of this check; the runtime half is for
    # the caller who does not run mypy
    with pytest.raises(BTClibValueError, match="unknown script type: p2wsh not in "):
        address_from_der_path(_XPRV_ROOT, "m/84h/0h/0h/0/0", "p2wsh")  # type: ignore[arg-type]


def test_coin_type() -> None:
    """Refuse a coin type off the key's network, and Litecoin's."""
    # a mainnet key with the testnet coin type, and the other way round
    err_msg = "coin type 1 is test, the extended key is main"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(_XPRV_ROOT, "m/44h/1h/0h/0/0")
    err_msg = "coin type 0 is main, the extended key is test"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(_UPRV_ROOT, "m/49h/0h/0h/0/0")

    # 2 is Litecoin: another chain, and no bitcoin address to give it
    with pytest.raises(
        BTClibValueError, match="unregistered BIP44 coin type: 2 not in"
    ):
        address_from_der_path(_XPRV_ROOT, "m/44h/2h/0h/0/0")


@pytest.mark.parametrize(
    "der_path, err_msg",
    [
        ("m/84h/0h/0h/0", "invalid BIP44 path: 4 levels instead of 5"),
        ("m/84h/0h/0h/0/0/0", "invalid BIP44 path: 6 levels instead of 5"),
        ("m/84/0h/0h/0/0", "purpose, coin type and account must be hardened"),
        ("m/84h/0/0h/0/0", "purpose, coin type and account must be hardened"),
        ("m/84h/0h/0/0/0", "purpose, coin type and account must be hardened"),
        ("m/84h/0h/0h/0h/0", "change and address index must not be hardened"),
        ("m/84h/0h/0h/0/0h", "change and address index must not be hardened"),
    ],
)
def test_invalid_path(der_path: str, err_msg: str) -> None:
    """Refuse a BIP44 path of wrong depth or wrong hardening."""
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(_ZPRV_ROOT, der_path)


def test_key_depth() -> None:
    """Refuse a key whose depth or index disagrees with the path."""
    der_path = "m/84h/0h/0h/0/0"

    # the account xpub of another account: the depth says which index of
    # the path the key must be, and it is not that one
    xpub = bip32.xpub_from_xprv(bip32.derive(_ZPRV_ROOT, "m/84h/0h/1h"))
    err_msg = "key index 1h at depth 3 is not the path's 0h"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(xpub, der_path)

    # a key deeper than the path itself has no tail left to walk, and the
    # bound is the path's own length: an account path is three levels
    xkey = bip32.derive(_ZPRV_ROOT, "m/84h/0h/0h/0/0/0")
    err_msg = "invalid key depth: 6 is past the 5 levels of the path"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(xkey, der_path)


def test_root_xpub() -> None:
    """A root xpub cannot walk a BIP44 path, and bip32 says so."""
    xpub = bip32.xpub_from_xprv(_ZPRV_ROOT)
    err_msg = "invalid hardened derivation from public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(xpub, "m/84h/0h/0h/0/0")
