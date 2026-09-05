# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.wallet.key_wallet` module."""

from __future__ import annotations

from typing import Any

import pytest

from btclib import b58
from btclib.alias import BIP44ScriptType
from btclib.bip32 import bip32
from btclib.curves import curve, sec_point
from btclib.ecc import bms
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.wallet import AddressInfo, BIP32KeyWallet, KeyWallet
from tests import needs_bindings, replace_unchecked

# the "abandon abandon ... about" seed, whose master key BIP84 and BIP86
# both publish as their rootpriv and whose addresses SLIP132, BIP49,
# BIP84 and BIP86 publish between them
_ROOT = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
# the same seed on testnet, which is BIP49's own masterseed
_TROOT = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd"

# SLIP132's account keys for purpose 44 and 84, the second spelled with
# the zprv version bytes that SLIP132 exists to define
_ACCOUNT_44_XPRV = "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb"
_ACCOUNT_44_XPUB = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
_ACCOUNT_84_ZPRV = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
# and the same key with the plain xprv version, which is what
# `bip32.derive` down m/84h/0h/0h from the master gives
_ACCOUNT_84_XPRV = "xprv9ybY78BftS5UGANki6oSifuQEjkpyAC8ZmBvBNTshQnCBcxnefjHS7buPMkkqhcRzmoGZ5bokx7GuyDAiktd5HemohAU4wV1ZPMDRmLpBMm"

_MSG = b"Hello, wallet"

# the classic uncompressed WIF of the private key 0x01...01 is not
# wanted here: this is a random key, compressed and uncompressed
_WIF_COMPRESSED = "L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk"
_WIF_UNCOMPRESSED = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
_PUB_KEY = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"


@pytest.mark.parametrize(
    "purpose, script_type, addresses",
    [
        pytest.param(
            44,
            "p2pkh",
            (
                "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
                "1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP",
                "1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH",
            ),
            id="44-p2pkh",
        ),
        pytest.param(
            49,
            "p2wpkh-p2sh",
            (
                "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
                "3LtMnn87fqUeHBUG414p9CWwnoV6E2pNKS",
                "34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7",
            ),
            id="49-p2wpkh-p2sh",
        ),
        pytest.param(
            84,
            "p2wpkh",
            (
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
                "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
            ),
            id="84-p2wpkh",
        ),
        pytest.param(
            86,
            "p2tr",
            (
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
                "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
            ),
            id="86-p2tr",
        ),
    ],
)
def test_published_vectors(
    purpose: int, script_type: str, addresses: tuple[str, str, str]
) -> None:
    """The addresses BIP49, BIP84, BIP86 and SLIP132 publish.

    Three per purpose: the first two of the receiving branch and the
    first of the change branch, which is the whole of what BIP84 and
    BIP86 print. Asserted from the master key and again from the account
    xpub, the two ends a wallet can be built from.
    """
    der_path = f"m/{purpose}h/0h/0h"
    wallet = BIP32KeyWallet(_ROOT, der_path)
    assert wallet.script_type == script_type
    assert wallet.network == "mainnet"
    assert wallet.der_path == der_path
    assert not wallet.is_watch_only

    assert wallet.next_address() == addresses[0]
    assert wallet.next_address() == addresses[1]
    assert wallet.next_address(1) == addresses[2]
    assert wallet.addresses == addresses
    assert len(wallet) == 3

    account_xpub = bip32.xpub_from_xprv(bip32.derive(_ROOT, der_path))
    watching = BIP32KeyWallet(account_xpub, der_path)
    assert watching.is_watch_only
    assert [watching.address(0, 0), watching.address(0, 1), watching.address(1, 0)] == [
        *addresses
    ]


def test_bip49_testnet_vector() -> None:
    """BIP49's own vector, which is the only testnet one published."""
    wallet = BIP32KeyWallet(_TROOT, "m/49h/1h/0h")
    assert wallet.network == "testnet"
    assert wallet.script_type == "p2wpkh-p2sh"
    assert wallet.next_address() == "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"


def test_the_path_says_the_script_type_and_the_version_bytes_do_not() -> None:
    """A zprv and an xprv holding one key hand out one set of addresses.

    The alternative -- reading the script type off the SLIP132 version
    bytes, as `slip132.address_from_xpub` does -- would make the
    same account answer one path with two different addresses depending
    on how the key was spelled, and only one of them would be watched.
    """
    from_zprv = BIP32KeyWallet(_ACCOUNT_84_ZPRV, "m/84h/0h/0h")
    from_xprv = BIP32KeyWallet(_ACCOUNT_84_XPRV, "m/84h/0h/0h")
    assert from_zprv.address(0, 0) == from_xprv.address(0, 0)
    assert from_zprv.address(0, 0) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def test_a_key_anywhere_on_the_account_path() -> None:
    """Master, an intermediate level, and the account key itself."""
    address = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
    for xkey in (
        _ROOT,
        bip32.derive(_ROOT, "m/44h"),
        bip32.derive(_ROOT, "m/44h/0h"),
        _ACCOUNT_44_XPRV,
        _ACCOUNT_44_XPUB,
    ):
        assert BIP32KeyWallet(xkey, "m/44h/0h/0h").next_address() == address


def test_a_bip32keydata_is_taken_as_it_is() -> None:
    """Verify a decoded BIP32KeyData works as the account key."""
    xkey = bip32.BIP32KeyData.b58decode(_ACCOUNT_44_XPRV)
    wallet = BIP32KeyWallet(xkey, "m/44h/0h/0h")
    assert wallet.next_address() == "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"


def test_a_bip32keydata_is_validated_even_when_already_one() -> None:
    """The rule of #684: an object is validated as a string is.

    A string went through `BIP32KeyData.b58decode`, which validates by
    default; an already-built `BIP32KeyData` was trusted as it stood,
    unlike the four `to_prv_key`/`to_pub_key`/`bip32` functions the same
    census names as compliant.
    """
    bad = replace_unchecked(bip32.BIP32KeyData.b58decode(_ACCOUNT_44_XPUB), index=-1)
    err_msg = "invalid index: -1"
    with pytest.raises(BTClibValueError, match=err_msg):
        bad.assert_valid()
    with pytest.raises(BTClibValueError, match=err_msg):
        BIP32KeyWallet(bad, "m/44h/0h/0h")


def test_the_key_index_must_be_the_path_element_at_its_depth() -> None:
    """Refuse a key at the wrong index, or past the account depth."""
    # the account 0 xpub against the path of account 1, and the message
    # names the index the path has at that depth -- which is what says
    # the comparison read the element the key's own depth points at,
    # rather than some other element of the same path
    err_msg = "key index 2147483648 at depth 3 is not the account path's 2147483649"
    with pytest.raises(BTClibValueError, match=err_msg):
        BIP32KeyWallet(_ACCOUNT_44_XPUB, "m/44h/0h/1h")
    # a key already below the account level
    too_deep = bip32.derive(_ACCOUNT_44_XPUB, "m/0/0")
    with pytest.raises(BTClibValueError, match="invalid key depth: 5 is past the"):
        BIP32KeyWallet(too_deep, "m/44h/0h/0h")


@pytest.mark.parametrize(
    "der_path, err_msg",
    [
        ("m/84h/0h", "invalid account path: 2 levels instead of 3"),
        ("m/84h/0h/0h/0", "invalid account path: 4 levels instead of 3"),
        ("m/84/0h/0h", "all three levels must be hardened"),
        ("m/84h/0/0h", "all three levels must be hardened"),
        ("m/84h/0h/0", "all three levels must be hardened"),
    ],
)
def test_invalid_account_path(der_path: str, err_msg: str) -> None:
    """Refuse an account path of wrong depth or missing hardening."""
    with pytest.raises(BTClibValueError, match=err_msg):
        BIP32KeyWallet(_ROOT, der_path)


def test_an_unknown_purpose_is_refused_and_script_type_is_the_override() -> None:
    """Refuse purpose 45 bare, and let the script type override win."""
    with pytest.raises(BTClibValueError, match="unknown BIP44 purpose: 45"):
        BIP32KeyWallet(_ROOT, "m/45h/0h/0h")
    wallet = BIP32KeyWallet(_ROOT, "m/45h/0h/0h", "p2wpkh")
    assert wallet.script_type == "p2wpkh"
    assert wallet.next_address().startswith("bc1q")
    # and the override wins over a purpose the table does name
    assert BIP32KeyWallet(_ROOT, "m/84h/0h/0h", "p2pkh").next_address().startswith("1")


def test_an_unknown_script_type_is_refused() -> None:
    """Refuse p2wsh at every entry point that takes a script type."""
    with pytest.raises(BTClibValueError, match="unknown script type: p2wsh"):
        BIP32KeyWallet(_ROOT, "m/84h/0h/0h", "p2wsh")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="unknown script type: p2wsh"):
        KeyWallet(script_type="p2wsh")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="unknown script type: p2wsh"):
        KeyWallet().add(_PUB_KEY, "p2wsh")  # type: ignore[arg-type]


def test_a_network_name_is_taken_as_the_rest_of_the_library_takes_one() -> None:
    """`Wallet` normalizes the name it is given, and refuses the rest.

    `__init__` puts the name through `network._validated_network_name`,
    so the spellings issue #216 decided to keep reach a wallet, and
    `Wallet.network` is the name `network_from_name` answers to.
    """
    assert KeyWallet(network=" RegTest ").network == "regtest"
    with pytest.raises(BTClibValueError, match="unknown network: 'regtest2'"):
        KeyWallet(network="regtest2")
    # a name that is not a string is the type rule, which RELEASE_NOTES.md
    # tells a caller to act on
    with pytest.raises(BTClibTypeError, match="not a network name"):
        KeyWallet(network=[])  # type: ignore[arg-type]


@pytest.mark.parametrize("purpose", [44, 49, 84])
def test_sign_by_address_verifies_with_bms(purpose: int) -> None:
    """The whole point: a signature asked for by address, not by key.

    `bms.verify` is the authority -- it is the code a counterparty runs
    -- and the address it is given is the one the wallet handed out.
    """
    wallet = BIP32KeyWallet(_ROOT, f"m/{purpose}h/0h/0h")
    address = wallet.next_address()
    sig = wallet.sign(address, _MSG)
    assert bms.verify(_MSG, address, sig)
    # and the signature is bms's own, reachable the long way round: the
    # WIF `prv_key` answers is `b58`'s object, not `bms.sign`'s (issue
    # #1188)
    prv_key = b58.prv_key_data_from_wif(wallet.prv_key(address))
    assert sig == bms.sign(_MSG, prv_key, address)


def test_the_recovery_flag_names_the_address_type() -> None:
    """The address reaches `bms.sign`, not only the key.

    A key alone would produce the compressed p2pkh flag 31..34 for all
    three; passing the address on is what makes the flag say which
    address type was signed for, which is BIP137's spelling.
    """
    flags = {}
    for purpose in (44, 49, 84):
        wallet = BIP32KeyWallet(_ROOT, f"m/{purpose}h/0h/0h")
        address = wallet.next_address()
        flags[purpose] = wallet.sign(address, _MSG).rf
    assert 30 < flags[44] < 35
    assert 34 < flags[49] < 39
    assert flags[84] > 38


def test_bms_cannot_sign_for_a_taproot_address() -> None:
    """The one script type the wallet hands out and cannot sign for."""
    wallet = BIP32KeyWallet(_ROOT, "m/86h/0h/0h")
    address = wallet.next_address()
    with pytest.raises(BTClibValueError, match="BMS cannot sign for a p2tr address"):
        wallet.sign(address, _MSG)
    # the key is there all the same: it is the scheme that is missing
    assert wallet.prv_key(address)


def test_a_watch_only_wallet_fails_to_sign_and_says_why() -> None:
    """Refuse to sign without a private key, naming the reason."""
    wallet = BIP32KeyWallet(_ACCOUNT_44_XPUB, "m/44h/0h/0h")
    assert wallet.is_watch_only
    address = wallet.next_address()
    err_msg = "watch-only wallet, no private key for"
    with pytest.raises(BTClibValueError, match=err_msg):
        wallet.prv_key(address)
    with pytest.raises(BTClibValueError, match=err_msg):
        wallet.sign(address, _MSG)


def test_a_lookup_miss_raises() -> None:
    """Refuse an address the wallet never handed out."""
    wallet = BIP32KeyWallet(_ROOT, "m/84h/0h/0h")
    # an address of its own chain, not handed out yet: a miss all the
    # same, the map being what the wallet has issued rather than what
    # it could issue
    unissued = BIP32KeyWallet(_ROOT, "m/84h/0h/0h").address(0, 7)
    for address in (unissued, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"):
        assert address not in wallet
        with pytest.raises(BTClibValueError, match="address not in the wallet"):
            wallet.address_info(address)
        with pytest.raises(BTClibValueError, match="address not in the wallet"):
            wallet.sign(address, _MSG)
    assert wallet.next_address() in wallet


def test_the_record_is_the_path_and_no_key_material() -> None:
    """Verify AddressInfo is frozen and no repr leaks key material."""
    wallet = BIP32KeyWallet(_ROOT, "m/84h/0h/0h")
    address = wallet.address(1, 5)
    info = wallet.address_info(address)
    assert info == AddressInfo(address, "p2wpkh", "m/84h/0h/0h/1/5", 1, 5)
    assert address not in repr(wallet)
    assert wallet.prv_key(address) not in repr(info)
    # frozen: what comes out of a wallet is a copy of what it knows
    with pytest.raises(AttributeError):
        info.address = "whatever"  # type: ignore[misc]


def test_handing_out_is_idempotent_and_ordered() -> None:
    """Verify an address is issued once, next_address one past the top."""
    wallet = BIP32KeyWallet(_ROOT, "m/84h/0h/0h")
    first = wallet.address(0, 0)
    assert wallet.address(0, 0) == first
    assert len(wallet) == 1
    # next_address is one past the highest handed out, not a count
    wallet.address(0, 7)
    assert wallet.next_address() == wallet.address(0, 8)
    assert len(wallet) == 3
    # the branches count separately
    assert wallet.next_address(1) == wallet.address(1, 0)
    assert wallet.addresses[0] == first


def test_the_derivation_bounds_are_bip32s_own() -> None:
    """Refuse a branch outside (0, 1) and an address index out of range."""
    wallet = BIP32KeyWallet(_ROOT, "m/84h/0h/0h")
    with pytest.raises(BTClibValueError, match="not in \\(0, 1\\)"):
        wallet.address(2, 0)
    with pytest.raises(BTClibValueError, match="invalid address index"):
        wallet.address(0, 0x10000)


@pytest.mark.parametrize(
    "script_type, address",
    [
        ("p2pkh", "14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY"),
        ("p2wpkh-p2sh", "3G6hxdgC91ETUpsGCrVywYRDZBp8LHarPF"),
        ("p2wpkh", "bc1qylqhfq22y39xtt8t6vxhf75dwgmes3efag3kry"),
    ],
)
def test_individual_keys(script_type: BIP44ScriptType, address: str) -> None:
    """Verify one WIF gives one address per script type, and it signs."""
    wallet = KeyWallet([_WIF_COMPRESSED], script_type)
    assert wallet.addresses == (address,)
    assert not wallet.is_watch_only
    assert wallet.prv_key(address) == _WIF_COMPRESSED
    assert wallet.address_info(address) == AddressInfo(address, script_type, "")
    assert bms.verify(_MSG, address, wallet.sign(address, _MSG))


def test_a_key_that_says_what_it_is_by_its_type() -> None:
    """An int is a scalar, a point is a pair: neither needs the guess."""
    q = 0xCA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB
    address = "14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY"
    wallet = KeyWallet([q], "p2pkh")
    assert wallet.addresses == (address,)
    assert wallet.prv_key(address) == _WIF_COMPRESSED

    point = (
        0x30D54FD0DD420A6E5F8D3624F5F3482CAE350F79D5F0753BF5BEEF9C2D91AF3C,
        0x04717159CE0828A7F686C2C7510B7AA7D4C685EBC2051642CCBEBC7099E2F679,
    )
    watching = KeyWallet([point], "p2wpkh")
    assert watching.is_watch_only
    assert watching.addresses == ("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",)


def test_a_public_key_makes_a_watch_only_entry() -> None:
    """Verify an entry built from a public key alone cannot sign."""
    wallet = KeyWallet([_PUB_KEY])
    address = wallet.addresses[0]
    assert wallet.is_watch_only
    assert address == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    with pytest.raises(BTClibValueError, match="watch-only address, no private key"):
        wallet.prv_key(address)
    with pytest.raises(BTClibValueError, match="watch-only address, no private key"):
        wallet.sign(address, _MSG)


def test_an_uncompressed_key_can_only_be_p2pkh() -> None:
    """Segwit has no uncompressed form, so the address would be a lie."""
    address = KeyWallet([_WIF_UNCOMPRESSED], "p2pkh").addresses[0]
    assert address == "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S"
    for script_type in ("p2wpkh-p2sh", "p2wpkh", "p2tr"):
        with pytest.raises(BTClibValueError, match="uncompressed key cannot be"):
            KeyWallet([_WIF_UNCOMPRESSED], script_type)


def test_add_takes_a_script_type_of_its_own() -> None:
    """Verify each added key can carry its own script type."""
    wallet = KeyWallet(script_type="p2pkh")
    assert not wallet.addresses
    assert wallet.is_watch_only
    p2pkh = wallet.add(_WIF_COMPRESSED)
    p2wpkh = wallet.add(_WIF_COMPRESSED, "p2wpkh")
    assert wallet.addresses == (p2pkh, p2wpkh)
    assert wallet.address_info(p2wpkh).script_type == "p2wpkh"
    assert not wallet.is_watch_only


def test_add_refuses_an_extended_key() -> None:
    """An extended key is `bip32`'s object and no `Key` at all.

    Both spellings of one: the text, which is base58 and no scalar's
    octets, and the decoded `BIP32KeyData`, whose type the union does not
    declare. A caller holding either resolves it with `bip32` and adds
    what comes back (issue #1188).
    """
    wallet = KeyWallet()
    with pytest.raises(BTClibValueError, match="not a private key"):
        wallet.add(_ACCOUNT_44_XPRV)
    xkey = bip32.BIP32KeyData.b58decode(_ACCOUNT_44_XPRV)
    with pytest.raises(BTClibTypeError, match="not a public key"):
        wallet.add(xkey)  # type: ignore[arg-type]


def test_a_key_added_to_a_bip32_wallet_is_not_derived() -> None:
    """Verify an added key signs while the derived ones stay watch-only."""
    wallet = BIP32KeyWallet(_ACCOUNT_44_XPUB, "m/44h/0h/0h")
    derived = wallet.next_address()
    added = wallet.add(_WIF_COMPRESSED, "p2pkh")
    # the account is still watch-only, but the wallet now holds a key
    assert not wallet.is_watch_only
    assert wallet.prv_key(added) == _WIF_COMPRESSED
    assert bms.verify(_MSG, added, wallet.sign(added, _MSG))
    with pytest.raises(BTClibValueError, match="watch-only wallet"):
        wallet.prv_key(derived)
    assert not wallet.address_info(added).der_path


def test_an_address_is_found_however_it_is_spelled() -> None:
    """Verify bech32 lookups ignore case and spaces; base58 must not."""
    wallet = BIP32KeyWallet(_ROOT, "m/84h/0h/0h")
    address = wallet.next_address()
    for spelling in (address.upper(), f"  {address}  ", address.encode("ascii")):
        assert spelling in wallet
        assert wallet.address_info(spelling).address == address
    # base58 is not case insensitive and is left exactly as it came
    b58_wallet = BIP32KeyWallet(_ROOT, "m/44h/0h/0h")
    b58_address = b58_wallet.next_address()
    assert b58_address.upper() not in b58_wallet


def test_the_wrapped_segwit_spelling_is_the_one_with_a_pre_image() -> None:
    """`p2wpkh-p2sh` has a redeem script; the other three have neither.

    Which is what a psbt needs from the wallet: the p2wpkh program is the
    pre-image of the hash in the p2sh output, and a wallet paying to a key
    hash directly has no script to carry -- `b""`, and not an error, being
    what "there is no such script" answers.
    """
    wrapped = BIP32KeyWallet(_ROOT, "m/49h/0h/0h")
    address = wrapped.address(0, 0)
    redeem_script = wrapped.redeem_script(0, 0)
    assert b58.p2sh(redeem_script) == address
    assert not wrapped.witness_script(0, 0)

    for purpose in (44, 84, 86):
        wallet = BIP32KeyWallet(_ROOT, f"m/{purpose}h/0h/0h")
        assert not wallet.redeem_script(0, 0)
        assert not wallet.witness_script(0, 0)


def test_the_output_is_the_script_the_address_pays() -> None:
    """`script_pub_key` reads the address back into the script it encodes.

    Which is what `position_of` compares, and what makes the four
    encodings one answer: the address is the library's own mapping from a
    key, and the script is that address decoded rather than a second
    table.
    """
    for purpose in (44, 49, 84, 86):
        wallet = BIP32KeyWallet(_ROOT, f"m/{purpose}h/0h/0h")
        script_pub_key = wallet.script_pub_key(1, 3)
        assert script_pub_key.address == wallet.address(1, 3)
        assert script_pub_key.network == "mainnet"
        assert wallet.position_of(script_pub_key, 4) == (1, 3)


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_add_derives_the_public_key_once(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A private key handed to a wallet is multiplied once, not twice.

    `add` computes the public key through `PrvKeyData.pub`, which
    memoizes, and builds the address out of the SEC octets that answered
    rather than out of the key that would derive them again -- one scalar
    multiplication on the secret where there were two (issue #1188).

    What makes that a gate rather than a claim is *where* this counts.
    Every caller of `bytes_from_prv_key_int` binds it with a from-import,
    so patching one caller's name leaves the others multiplying
    uncounted -- which is exactly what the address builder does, through
    `to_pub_key`'s own binding. Counted here instead are the two calls
    that name is a wrapper around, in the module that defines it, so
    every derivation reaching that function is counted whichever caller
    spelled it -- and both of the ones at issue here do reach it.

    One of those two calls answers per install, which is why both arms
    run: the bindings for the one that has them, `mult` for the one that
    does not.
    """
    if not bindings:
        monkeypatch.setattr(curve, "_libsecp256k1_available", False)

    calls = 0
    for name in ("libsecp256k1_pubkey_from_prvkey", "mult"):
        original = getattr(sec_point, name)

        def counting(*args: object, _original: Any = original, **kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            return _original(*args, **kwargs)

        monkeypatch.setattr(sec_point, name, counting)

    wallet = KeyWallet()
    wallet.add(_WIF_COMPRESSED)

    assert calls == 1
    assert not wallet.is_watch_only
