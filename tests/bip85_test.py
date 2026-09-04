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

Every vector the BIP publishes is in that file and asserted here. The
one application with none is RSA, which is the one btclib does not
generate a key for: what `rsa_drng_from_root_key` hands back is the
stream the BIP says to feed a key generator, and the assertions below
reach no further than the path it is seeded from.
"""

from __future__ import annotations

import hmac
from typing import Any

import pytest

from btclib import b58
from btclib.bip32 import BIP32KeyData, derive, rootxprv_from_seed, xpub_from_xprv
from btclib.bip85 import (
    _HMAC_KEY,
    _LANGUAGE_INDEXES,
    BIP85DRNG,
    base64_password_from_root_key,
    base85_password_from_root_key,
    bytes_entropy_from_root_key,
    drng_from_der_path,
    entropy_from_der_path,
    mnemonic_from_root_key,
    nsec_from_root_key,
    rolls_from_root_key,
    rsa_drng_from_root_key,
    wif_from_root_key,
    xprv_from_root_key,
)
from btclib.curves import secp256k1 as ec
from btclib.exceptions import BTClibValueError
from btclib.mnemonic.bip39 import entropy_from_mnemonic
from btclib.network import NETWORKS
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
    data = b58.prv_key_data_from_wif(wif)
    assert (data.network, data.compressed) == ("mainnet", True)


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
    assert b58.prv_key_data_from_wif(wif_from_root_key(tprv)).network == "testnet"


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


@pytest.mark.parametrize("vector", **_ids("drng"))
def test_the_drng_stream(vector: dict[str, Any]) -> None:
    """BIP85-DRNG-SHAKE256, at the path of the entropy vectors."""
    drng = drng_from_der_path(_ROOT, vector["path"])
    assert drng.read(vector["num_bytes"]).hex() == vector["drng"]


@pytest.mark.parametrize("vector", **_ids("drng"))
def test_the_stream_does_not_depend_on_how_it_is_read(
    vector: dict[str, Any],
) -> None:
    """A read is a squeeze of a prefix, so the pieces are the whole.

    Which is what the dice application relies on: it reads one roll at a
    time, and the rolls have to be the stream a single read of the same
    length would have given.
    """
    whole = bytes.fromhex(vector["drng"])
    drng = drng_from_der_path(_ROOT, vector["path"])
    pieces = b"".join(drng.read(n) for n in (1, 0, 31, 48))
    assert pieces == whole
    assert len(pieces) == vector["num_bytes"]


@pytest.mark.parametrize("vector", **_ids("pwd_base64"))
def test_base64_password_application(vector: dict[str, Any]) -> None:
    """Application 707764': all 64 bytes encoded, then sliced."""
    entropy = entropy_from_der_path(_ROOT, vector["path"])
    assert entropy.hex() == vector["derived_entropy"]

    pwd = base64_password_from_root_key(_ROOT, vector["pwd_len"])
    assert pwd == vector["derived_pwd"]
    assert len(pwd) == vector["pwd_len"]


@pytest.mark.parametrize("vector", **_ids("pwd_base85"))
def test_base85_password_application(vector: dict[str, Any]) -> None:
    """Application 707785', in the alphabet the BIP's vector is in."""
    entropy = entropy_from_der_path(_ROOT, vector["path"])
    assert entropy.hex() == vector["derived_entropy"]

    pwd = base85_password_from_root_key(_ROOT, vector["pwd_len"])
    assert pwd == vector["derived_pwd"]
    assert len(pwd) == vector["pwd_len"]


def test_a_password_is_a_prefix_of_the_longest_one() -> None:
    """Only where the length is the same: it is a path level too.

    The slice is of an encoding of the entropy of a path that spells the
    length, so two lengths are two derivations and not one password cut
    in two places -- which is what keeps a longer password from
    disclosing a shorter one.
    """
    assert (
        base64_password_from_root_key(_ROOT, 20)
        != (base64_password_from_root_key(_ROOT, 86)[:20])
    )
    assert (
        base85_password_from_root_key(_ROOT, 10)
        != (base85_password_from_root_key(_ROOT, 80)[:10])
    )


@pytest.mark.parametrize("pwd_len", [20, 86])
def test_the_base64_bounds_are_inclusive(pwd_len: int) -> None:
    """86 is where the padding of those 64 bytes would start."""
    pwd = base64_password_from_root_key(_ROOT, pwd_len)
    assert len(pwd) == pwd_len
    assert "=" not in pwd


@pytest.mark.parametrize("pwd_len", [10, 80])
def test_the_base85_bounds_are_inclusive(pwd_len: int) -> None:
    """10 and 80 are the two ends BIP85 states."""
    assert len(base85_password_from_root_key(_ROOT, pwd_len)) == pwd_len


@pytest.mark.parametrize("vector", **_ids("dice"))
def test_dice_application(vector: dict[str, Any]) -> None:
    """Application 89101': ten rolls of a six-sided die.

    The vector is what makes the rejection branch load-bearing: a byte
    whose top three bits are 6 or 7 is no face of a six-sided die, and
    the ten rolls below are what the stream gives once those are
    dropped.
    """
    rolls = rolls_from_root_key(_ROOT, vector["rolls"], vector["sides"])
    assert ",".join(str(roll) for roll in rolls) == vector["derived_rolls"]
    assert all(0 <= roll < vector["sides"] for roll in rolls)


@pytest.mark.parametrize("sides", [2, 6, 8, 20, 62, 256, 257])
def test_a_roll_is_a_face_of_the_die(sides: int) -> None:
    """Whatever the die, including the powers of two either side of 8.

    `ceil(log2(sides))` is where a float logarithm would put a roll one
    bit too wide, and a roll too wide is one the rejection above drops
    far too often rather than a wrong answer -- so the width is asserted
    through the rolls it produces.
    """
    rolls = rolls_from_root_key(_ROOT, 32, sides)
    assert len(rolls) == 32
    assert all(0 <= roll < sides for roll in rolls)


@pytest.mark.parametrize("vector", **_ids("nostr"))
def test_nostr_application(vector: dict[str, Any]) -> None:
    """Application 128002': the leading 256 bits, bech32-encoded as an nsec.

    The BIP prints DERIVED ENTROPY for this application as the whole 64
    bytes, unlike the HD-Seed WIF section it otherwise mirrors, so the
    assertion is against the whole of it and not a 32-byte slice.
    """
    entropy = entropy_from_der_path(_ROOT, vector["path"])
    assert entropy.hex() == vector["derived_entropy"]

    nsec = nsec_from_root_key(_ROOT, vector["identity"], vector["account_index"])
    assert nsec == vector["derived_nsec"]
    assert nsec.startswith("nsec1")


def test_nostr_identity_and_account_index_are_reserved_at_zero() -> None:
    """0' of either level is the BIP's reserved key-management slot."""
    with pytest.raises(BTClibValueError, match="invalid nostr identity: 0"):
        nsec_from_root_key(_ROOT, 0, 1)
    with pytest.raises(BTClibValueError, match="invalid nostr account index: 0"):
        nsec_from_root_key(_ROOT, 1, 0)


class _ForcedHmac:
    """An hmac whose digest is chosen rather than computed."""

    def __init__(self, digest: bytes) -> None:
        self._digest = digest

    def digest(self) -> bytes:
        return self._digest


def _force_bip85_entropy(monkeypatch: pytest.MonkeyPatch, leading_32: bytes) -> None:
    """Make bip85's own entropy hmac -- and only that one -- see leading_32.

    `_entropy_from_der_path` derives the path first, through bip32's own
    hardened-derivation hmacs, and only computes its own hmac afterwards,
    keyed with `_HMAC_KEY`: patching `hmac.new` indiscriminately, as
    `bip32_test.py`'s own `_force_hmac` does for bip32 itself, would also
    dictate those path-derivation hmacs and trip BIP32's own "not a valid
    scalar" rejection before bip85's is ever reached. So only the call
    keyed with `_HMAC_KEY` is answered with the chosen digest; every
    other key reaches the real `hmac.new`, which is what lets the path
    derivation above it complete undisturbed.

    Zero and the curve order are each about 2**-127 odds, which is why
    the branch refusing them as a Nostr secret key can only be tested
    this way. The trailing 32 bytes play no part in `nsec_from_root_key`,
    so they are left zero.
    """
    real_new = hmac.new
    digest = leading_32 + bytes(32)

    def _new(key: bytes, msg: bytes, digestmod: str) -> hmac.HMAC | _ForcedHmac:
        if key == _HMAC_KEY:
            return _ForcedHmac(digest)
        return real_new(key, msg, digestmod)

    monkeypatch.setattr(hmac, "new", _new)


@pytest.mark.parametrize("leading", [0, ec.n])
def test_a_nostr_key_outside_the_curve_order_is_refused(
    leading: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The curve-order footnote WIF documents, which Nostr cross-references.

    `wif_from_root_key` already refuses the same two scalars through
    `wif_from_prv_key`; this is the same hard failure on the application
    that bech32-encodes the key instead of formatting it as a WIF.
    """
    _force_bip85_entropy(monkeypatch, leading.to_bytes(32, byteorder="big"))
    with pytest.raises(BTClibValueError, match="private key not in 1..n-1"):
        nsec_from_root_key(_ROOT, 1, 1)


def test_the_rsa_drng_is_the_stream_of_its_path() -> None:
    """The path BIP85 allocates, sub-key level included.

    btclib generates no RSA key and the BIP publishes no vector for one,
    so what is asserted is the derivation: the reader is the one the
    path seeds, and the four GPG sub-keys are four different streams.
    """
    key_bits, key_index = 1024, 0
    path = f"m/83696968h/828365h/{key_bits}h/{key_index}h"
    assert rsa_drng_from_root_key(_ROOT, key_bits).read(32) == (
        drng_from_der_path(_ROOT, path).read(32)
    )

    streams = {
        rsa_drng_from_root_key(_ROOT, key_bits, key_index, sub_key).read(32)
        for sub_key in (0, 1, 2)
    }
    assert len(streams) == 3
    assert rsa_drng_from_root_key(_ROOT, key_bits, key_index, 0).read(32) == (
        drng_from_der_path(_ROOT, f"{path}/0h").read(32)
    )


def test_the_drng_seed_is_exactly_64_bytes() -> None:
    """What BIP85 requires of the input, and what read refuses."""
    with pytest.raises(BTClibValueError, match="invalid size: 32 bytes"):
        BIP85DRNG(bytes(32))

    with pytest.raises(BTClibValueError, match="invalid number of bytes: -1"):
        BIP85DRNG(bytes(64)).read(-1)


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
        ("m/44h/0h/0h", "not a bip85 derivation path: 44h"),
        ("m/83696968h/0h/0", "unhardened bip85 derivation path"),
        ("m/83696968/0h/0h", "not a bip85 derivation path: 83696968"),
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

    with pytest.raises(BTClibValueError, match="invalid password length: 19"):
        base64_password_from_root_key(_ROOT, 19)

    with pytest.raises(BTClibValueError, match="invalid password length: 87"):
        base64_password_from_root_key(_ROOT, 87)

    with pytest.raises(BTClibValueError, match="invalid password length: 9"):
        base85_password_from_root_key(_ROOT, 9)

    with pytest.raises(BTClibValueError, match="invalid password length: 81"):
        base85_password_from_root_key(_ROOT, 81)

    with pytest.raises(BTClibValueError, match="invalid number of rolls: 0"):
        rolls_from_root_key(_ROOT, 0)

    with pytest.raises(BTClibValueError, match="invalid number of sides: 1"):
        rolls_from_root_key(_ROOT, 10, 1)


def test_an_index_no_path_level_can_hold() -> None:
    """A level is 31 bits before it is hardened, and cannot be negative."""
    with pytest.raises(BTClibValueError, match="invalid index: 2147483648"):
        wif_from_root_key(_ROOT, 0x80000000)

    with pytest.raises(BTClibValueError, match="invalid index: -1"):
        xprv_from_root_key(_ROOT, -1)
