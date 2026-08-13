# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bip85` module.

The vectors are BIP85's own, transcribed from the mediawiki into
`tests/_data/bip85_test_vectors.json`; `tests/_data/README.md` pins the
revision they were read from.

Two of the BIP's fields are not what their name suggests, and the
assertions below read them as the BIP prints them rather than as the
name reads:

- for application 32' the DERIVED ENTROPY is the *second* half of the 64
  bytes, the private key of the xprv, and not the whole entropy nor the
  chain code that is its first half;
- for application 39' it is the entropy already truncated to what the
  sentence encodes, so 16, 24 and 32 bytes rather than 64.

The applications btclib does not implement are the reason four of the
BIP's vector groups are not in that file: BIP85-DRNG, the two password
encodings, and the dice rolls, which the module docstring accounts for.
"""

from __future__ import annotations

from typing import Any

import pytest

from btclib.bip32 import BIP32KeyData, derive, rootxprv_from_seed, xpub_from_xprv
from btclib.bip85 import (
    _LANGUAGE_INDEXES,
    bytes_entropy_from_root_key,
    entropy_from_der_path,
    mnemonic_from_root_key,
    wif_from_root_key,
    xprv_from_root_key,
)
from btclib.exceptions import BTClibValueError
from btclib.mnemonic.bip39 import entropy_from_mnemonic
from btclib.network import NETWORKS
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from tests import load, vector_id

_VECTORS = load("_data", "bip85_test_vectors.json")
_ROOT = _VECTORS["master_bip32_root_key"]


def _ids(group: str) -> dict[str, Any]:
    """Parametrize a vector group, each case named by its path."""
    cases = _VECTORS[group]
    return {
        "argvalues": cases,
        "ids": [vector_id(i, case["path"]) for i, case in enumerate(cases)],
    }


@pytest.mark.parametrize("vector", **_ids("entropy"))
def test_entropy_of_a_path(vector: dict[str, Any]) -> None:
    """The two vectors of the specification's own section.

    The DERIVED KEY is the child private key the path reaches, which is
    plain BIP32 and is asserted through `bip32.derive`: it is the message
    of the HMAC, so a wrong key would give a wrong entropy with nothing
    to say which of the two steps was at fault.
    """
    child = BIP32KeyData.b58decode(derive(_ROOT, vector["path"]))
    assert child.key[1:].hex() == vector["derived_key"]
    assert (
        entropy_from_der_path(_ROOT, vector["path"]).hex()
        == (vector["derived_entropy"])
    )


@pytest.mark.parametrize("vector", **_ids("bip39"))
def test_bip39_application(vector: dict[str, Any]) -> None:
    """Application 39': the mnemonic, and the entropy behind it."""
    words = vector["words"]
    entropy = entropy_from_der_path(_ROOT, vector["path"])
    truncated = entropy[: len(bytes.fromhex(vector["derived_entropy"]))]
    assert truncated.hex() == vector["derived_entropy"]

    mnemonic = mnemonic_from_root_key(_ROOT, words)
    assert mnemonic == vector["derived_bip39_mnemonic"]
    assert len(mnemonic.split()) == words


@pytest.mark.parametrize("vector", **_ids("hd_seed_wif"))
def test_hd_seed_wif_application(vector: dict[str, Any]) -> None:
    """Application 2': the leading 256 bits as a compressed WIF."""
    entropy = entropy_from_der_path(_ROOT, vector["path"])
    assert entropy[:32].hex() == vector["derived_entropy"]

    wif = wif_from_root_key(_ROOT)
    assert wif == vector["derived_wif"]
    _, network, compressed = prv_keyinfo_from_prv_key(wif)
    assert (network, compressed) == ("mainnet", True)


@pytest.mark.parametrize("vector", **_ids("xprv"))
def test_xprv_application(vector: dict[str, Any]) -> None:
    """Application 32': the halves in the order BIP32 reverses.

    The first 32 bytes are the chain code and the second 32 the private
    key, which is the warning the BIP carries; the vector's DERIVED
    ENTROPY is that second half.
    """
    entropy = entropy_from_der_path(_ROOT, vector["path"])
    assert entropy[32:].hex() == vector["derived_entropy"]

    xprv = xprv_from_root_key(_ROOT)
    assert xprv == vector["derived_xprv"]
    derived = BIP32KeyData.b58decode(xprv)
    assert derived.is_root
    assert derived.chain_code == entropy[:32]
    assert derived.key[1:] == entropy[32:]


@pytest.mark.parametrize("vector", **_ids("hex"))
def test_hex_application(vector: dict[str, Any]) -> None:
    """Application 128169': the entropy truncated to num_bytes."""
    num_bytes = vector["num_bytes"]
    entropy = bytes_entropy_from_root_key(_ROOT, num_bytes)
    assert entropy.hex() == vector["derived_entropy"]
    assert entropy == entropy_from_der_path(_ROOT, vector["path"])[:num_bytes]


@pytest.mark.parametrize("num_bytes", [16, 32, 64])
def test_the_hex_application_bounds_are_inclusive(num_bytes: int) -> None:
    """16 and 64 are values BIP85 allows, and 32 is the default."""
    assert len(bytes_entropy_from_root_key(_ROOT, num_bytes)) == num_bytes


@pytest.mark.parametrize("words", [12, 15, 18, 21, 24])
def test_every_sentence_length_of_the_words_table(words: int) -> None:
    """BIP85 numbers five, where its own vectors publish three.

    The two without a vector are checked against BIP39 instead: the
    sentence has to hold that many words and its checksum has to verify,
    which is what `entropy_from_mnemonic` does.
    """
    mnemonic = mnemonic_from_root_key(_ROOT, words)
    assert len(mnemonic.split()) == words
    # the binary string BIP39 encodes: 32 bits to every three words
    assert len(entropy_from_mnemonic(mnemonic)) == words * 32 // 3


@pytest.mark.parametrize("lang", sorted(_LANGUAGE_INDEXES))
def test_every_language_of_the_language_table(lang: str) -> None:
    """Ten languages, ten paths, ten valid sentences."""
    mnemonic = mnemonic_from_root_key(_ROOT, 12, lang)
    assert len(entropy_from_mnemonic(mnemonic, lang)) == 128


def test_the_language_index_is_a_path_level() -> None:
    """A language is a different derivation, not a re-spelling.

    BIP39's own entropy round trip writes one entropy in another
    language; here the language is the third level of the path, so the
    entropy itself differs and so does every word of the sentence.
    """
    sentences = {
        lang: mnemonic_from_root_key(_ROOT, 12, lang) for lang in _LANGUAGE_INDEXES
    }
    entropies = {entropy_from_mnemonic(m, lang) for lang, m in sentences.items()}
    assert len(entropies) == len(_LANGUAGE_INDEXES)


def test_the_index_selects_another_output() -> None:
    """The last level of each application path numbers its outputs."""
    assert wif_from_root_key(_ROOT) != wif_from_root_key(_ROOT, 1)
    assert xprv_from_root_key(_ROOT) != xprv_from_root_key(_ROOT, 1)
    assert mnemonic_from_root_key(_ROOT) != mnemonic_from_root_key(_ROOT, index=1)
    assert bytes_entropy_from_root_key(_ROOT) != bytes_entropy_from_root_key(
        _ROOT, index=1
    )


def test_a_testnet_root_emits_testnet_keys() -> None:
    """What BIP85 says of application 32', and the WIF needs too.

    "Applications may support Testnet by emitting TPRV keys if and only
    if the input root key is a Testnet key": the network is read off the
    root key's version, and the WIF prefix answers to the same fact.
    """
    seed = "000102030405060708090a0b0c0d0e0f"
    tprv = rootxprv_from_seed(seed, NETWORKS["testnet"].bip32_prv)
    assert xprv_from_root_key(tprv).startswith("tprv")
    _, network, _ = prv_keyinfo_from_prv_key(wif_from_root_key(tprv))
    assert network == "testnet"


def test_a_slip132_root_still_emits_an_xprv() -> None:
    """A yprv roots a tree of one script type; the derived key roots none.

    So the version of the answer is the network's own, and the two roots
    that differ only in their version bytes derive the same key material.
    """
    seed = "000102030405060708090a0b0c0d0e0f"
    xprv = rootxprv_from_seed(seed)
    yprv = rootxprv_from_seed(seed, NETWORKS["mainnet"].slip132_p2wpkh_p2sh_prv)
    assert xprv_from_root_key(yprv).startswith("xprv")
    assert xprv_from_root_key(yprv) == xprv_from_root_key(xprv)


def test_a_public_root_key_is_refused() -> None:
    """Every level is hardened, so there is nothing to derive publicly."""
    xpub = xpub_from_xprv(_ROOT)
    with pytest.raises(BTClibValueError, match="invalid hardened derivation"):
        entropy_from_der_path(xpub, "m/83696968h/0h/0h")


@pytest.mark.parametrize(
    "der_path, err_msg",
    [
        ("m/83696968h/0h", "too few bip85 path levels: 2"),
        ("m", "too few bip85 path levels: 0"),
        ("m/44h/0h/0h", "not a bip85 derivation path: "),
        ("m/83696968h/0h/0", "unhardened bip85 derivation path"),
        ("m/83696968/0h/0h", "not a bip85 derivation path: "),
    ],
)
def test_a_path_bip85_defines_no_entropy_for(der_path: str, err_msg: str) -> None:
    """The purpose level, the length, and the hardening of every level."""
    with pytest.raises(BTClibValueError, match=err_msg):
        entropy_from_der_path(_ROOT, der_path)


def test_an_application_parameter_outside_its_table() -> None:
    """Each application refuses what its own section bounds."""
    with pytest.raises(BTClibValueError, match="invalid number of words: 13"):
        mnemonic_from_root_key(_ROOT, 13)

    with pytest.raises(BTClibValueError, match="unnumbered bip85 language: 'ru'"):
        mnemonic_from_root_key(_ROOT, 12, "ru")

    with pytest.raises(BTClibValueError, match="invalid number of bytes: 15"):
        bytes_entropy_from_root_key(_ROOT, 15)

    with pytest.raises(BTClibValueError, match="invalid number of bytes: 65"):
        bytes_entropy_from_root_key(_ROOT, 65)


def test_an_index_no_path_level_can_hold() -> None:
    """A level is 31 bits before it is hardened, and cannot be negative."""
    with pytest.raises(BTClibValueError, match="invalid index: 2147483648"):
        wif_from_root_key(_ROOT, 0x80000000)

    with pytest.raises(BTClibValueError, match="invalid index: -1"):
        xprv_from_root_key(_ROOT, -1)
