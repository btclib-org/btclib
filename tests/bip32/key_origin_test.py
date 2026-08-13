# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bip32.key_origin` module."""

import dataclasses
from typing import cast

import pytest

from btclib.alias import Octets
from btclib.bip32 import (
    BIP32KeyOrigin,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)
from btclib.bip32.der_path import _HARDENING
from btclib.exceptions import BTClibValueError
from tests.conftest import JsonGolden


def test_bip32_key_origin() -> None:
    """Parse descriptions in every hardening spelling; refuse bad ones."""
    with pytest.raises(BTClibValueError, match="invalid master fingerprint length: "):
        BIP32KeyOrigin("badbad", [0])
    # one octet too many, not too few: `!= 4` weakened to `< 4` would
    # still catch the short one above and miss this one
    with pytest.raises(BTClibValueError, match="invalid master fingerprint length: "):
        BIP32KeyOrigin("deadbeef00", [0])

    with pytest.raises(BTClibValueError, match="invalid der_path size: "):
        BIP32KeyOrigin("deadbeef", [0] * 256)
    # the boundary itself, not only one past it: `> 255` weakened to
    # `>= 255` or to `> 254` would refuse the 255 every other vector
    # already carries a shorter version of
    assert len(BIP32KeyOrigin("deadbeef", [0] * 255)) == 255

    # the path reader refuses these before the constructor stores them,
    # so this is its message and not assert_valid's
    with pytest.raises(BTClibValueError, match="invalid index: "):
        BIP32KeyOrigin("deadbeef", [0xFFFFFFFF + 1])
    with pytest.raises(BTClibValueError, match="invalid index: "):
        BIP32KeyOrigin("deadbeef", [-1])
    # the upper boundary itself: `<= 0xffffffff` weakened to `<
    # 0xffffffff` or to `<= 0xfffffffe` would refuse it
    assert BIP32KeyOrigin("deadbeef", [0xFFFFFFFF]).der_path == [0xFFFFFFFF]

    # and assert_valid still asks. The field is annotated Sequence[int]
    # and holds the list `indexes_from_der_path` built, so the dataclass
    # being frozen stops a rebinding and not an append: the constructor
    # is not the only way an out-of-range index reaches the field
    key_origin = BIP32KeyOrigin("deadbeef", [0])
    cast("list[int]", key_origin.der_path).append(0xFFFFFFFF + 1)
    with pytest.raises(BTClibValueError, match="invalid der_path element"):
        key_origin.assert_valid()

    description = master_fingerprint = "deadbeef"
    key_origin = BIP32KeyOrigin.from_description(description)
    assert len(key_origin) == 0
    key_origin2 = BIP32KeyOrigin.from_description(f"{description}/")
    assert len(key_origin) == 0
    assert key_origin == key_origin2
    assert key_origin.description == description
    assert key_origin.master_fingerprint == bytes.fromhex(master_fingerprint)
    assert not key_origin.der_path
    assert BIP32KeyOrigin.parse(key_origin.serialize()) == key_origin
    assert BIP32KeyOrigin.from_dict(key_origin.to_dict()) == key_origin

    description = (  # use the hardening convention of the normalized der_path
        master_fingerprint
        + "/44"
        + _HARDENING
        + "/0"
        + _HARDENING
        + "/1"
        + _HARDENING
        + "/0/10"
    )
    key_origin = BIP32KeyOrigin.from_description(description)
    key_origin2 = BIP32KeyOrigin.from_description("deadbeef//44h/0'/1H/0/10/")
    assert key_origin == key_origin2
    assert key_origin.description == description
    assert key_origin.master_fingerprint == bytes.fromhex(master_fingerprint)
    assert key_origin.der_path == [
        44 + 0x80000000,
        0 + 0x80000000,
        1 + 0x80000000,
        0,
        10,
    ]
    assert BIP32KeyOrigin.parse(key_origin.serialize()) == key_origin
    assert BIP32KeyOrigin.from_dict(key_origin.to_dict()) == key_origin
    assert len(key_origin) == 5


def test_key_origin_is_frozen() -> None:
    """`@dataclass(frozen=True)`, refusing an assignment nothing else tries."""
    key_origin = BIP32KeyOrigin("deadbeef", [0])
    with pytest.raises(dataclasses.FrozenInstanceError):
        key_origin.master_fingerprint = b"\x00" * 4  # type: ignore[misc]


def test_check_validity_defaults_to_true_on_to_dict_from_dict_and_serialize() -> None:
    """An over-long fingerprint tells the three defaults apart from `False`.

    `to_dict` and `serialize` read the field back as it is stored, no
    boundary of their own in the way; an invalid `BIP32KeyOrigin` (built
    with `check_validity=False`) must still be refused at the default,
    and `from_dict` must refuse the same dict right back.
    """
    key_origin = BIP32KeyOrigin("deadbeef00", [0], check_validity=False)
    err_msg = "invalid master fingerprint length: "

    with pytest.raises(BTClibValueError, match=err_msg):
        key_origin.to_dict()
    as_dict = key_origin.to_dict(check_validity=False)

    with pytest.raises(BTClibValueError, match=err_msg):
        BIP32KeyOrigin.from_dict(as_dict)
    assert BIP32KeyOrigin.from_dict(as_dict, check_validity=False) == key_origin

    with pytest.raises(BTClibValueError, match=err_msg):
        key_origin.serialize()
    assert key_origin.serialize(check_validity=False)


def test_check_validity_defaults_to_true_on_parse() -> None:
    """`parse` always reads exactly four fingerprint octets, valid or not.

    What check_validity still guards there is everything past them:
    `assert_valid`'s own `len(self) > 255`, unreachable through a string
    path (`_pairs_from_der_path_str` refuses the same count first) but
    not through the raw indexes a serialized path decodes to.
    """
    key_origin = BIP32KeyOrigin("deadbeef", [0] * 256, check_validity=False)
    as_bytes = key_origin.serialize(check_validity=False)

    with pytest.raises(BTClibValueError, match="invalid der_path size: "):
        BIP32KeyOrigin.parse(as_bytes)
    assert BIP32KeyOrigin.parse(as_bytes, check_validity=False) == key_origin


def test_check_validity_defaults_to_true_on_from_description() -> None:
    """A description too short for its 8-hex-octet fingerprint slice.

    `data[:8]` takes whatever there is of a shorter string, so a bare
    four-hex-character fingerprint with no path at all is what reaches
    `assert_valid`'s length check rather than being caught by the slice.
    """
    with pytest.raises(BTClibValueError, match="invalid master fingerprint length: "):
        BIP32KeyOrigin.from_description("dead")
    parsed = BIP32KeyOrigin.from_description("dead", check_validity=False)
    assert parsed.master_fingerprint == bytes.fromhex("dead")


def test_decode_hd_key_paths_reads_the_map_it_is_given() -> None:
    """A populated map decodes to itself; `None` and `{}` to an empty one.

    `{...} if map_ else {}` negated builds the comprehension only when
    `map_` is falsy -- `None`, crashing on `.items()`, or empty, staying
    empty -- and returns `{}` for the one case, a populated map, that
    should not.
    """
    key_origin = BIP32KeyOrigin("deadbeef", [0])
    pub_key = bytes(33)
    populated: dict[Octets, BIP32KeyOrigin] = {pub_key: key_origin}

    assert decode_hd_key_paths(populated) == populated
    assert decode_hd_key_paths(None) == {}
    assert decode_hd_key_paths({}) == {}


def test_assert_valid_hd_key_paths_checks_the_pub_key_length() -> None:
    """78, 65 or 33 octets: an xpub, an uncompressed or a compressed key.

    Each boundary is checked on both sides, `not in {78, 33, 65}`
    surviving being narrowed to any one of the six neighbors a single
    `NumberReplacer` reaches.
    """
    key_origin = BIP32KeyOrigin("deadbeef", [0])
    for length in (78, 65, 33):
        hd_key_paths = {bytes(length): key_origin}
        assert_valid_hd_key_paths(hd_key_paths)
    for length in (77, 79, 64, 66, 32, 34):
        hd_key_paths = {bytes(length): key_origin}
        with pytest.raises(BTClibValueError, match="invalid public key length: "):
            assert_valid_hd_key_paths(hd_key_paths)


def test_assert_valid_hd_key_paths_checks_every_entry() -> None:
    """A second, invalid entry is refused, not just the first one checked.

    The per-entry loop survives being replaced with one over an empty
    list unless an entry past the first is what is wrong with the map:
    every existing vector either has one entry or is invalid in its
    first one.
    """
    good = BIP32KeyOrigin("deadbeef", [0])
    good2 = BIP32KeyOrigin("deadbeef", [1])  # a different origin: no duplicate
    bad_pub_key = bytes(32)  # neither 78, 65 nor 33 octets
    hd_key_paths = {bytes(33): good, bad_pub_key: good2}
    with pytest.raises(BTClibValueError, match="invalid public key length: "):
        assert_valid_hd_key_paths(hd_key_paths)


def test_dataclasses_json_dict_key_origin(json_golden: JsonGolden) -> None:
    """Round-trip a BIP32KeyOrigin through dict, against the golden json."""
    key_origin = BIP32KeyOrigin.from_description("deadbeef//44h/0'/1H/0/10/")

    # BIP32KeyOrigin dataclass
    assert isinstance(key_origin, BIP32KeyOrigin)
    key_origin.assert_valid()

    # BIP32KeyOrigin dataclass to dict
    key_origin_dict = key_origin.to_dict()
    assert isinstance(key_origin_dict, dict)
    assert key_origin_dict["master_fingerprint"]
    assert key_origin_dict["path"]

    # against the json committed beside this module, not written to it
    json_golden("key_origin.json", key_origin_dict)

    # BIP32KeyOrigin dataclass from dict
    key_origin2 = BIP32KeyOrigin.from_dict(key_origin_dict)
    assert isinstance(key_origin2, BIP32KeyOrigin)
    key_origin2.assert_valid()

    assert key_origin == key_origin2


def test_bip32_derivs() -> None:
    """Round-trip bip32_derivs dicts; refuse duplicated key origins."""
    # the basic type dict representation
    bip32_derivs = [
        {
            "pub_key": "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f",
            "master_fingerprint": "d90c6a4f",
            "path": f"m/0{_HARDENING}/0/0",
        },
        {
            "pub_key": "02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7",
            "master_fingerprint": "d90c6a4f",
            "path": f"m/0{_HARDENING}/0/1",
        },
    ]
    hd_key_paths = decode_from_bip32_derivs(bip32_derivs)
    assert bip32_derivs == encode_to_bip32_derivs(hd_key_paths)

    assert_valid_hd_key_paths(hd_key_paths)

    bip32_derivs = [
        {
            "pub_key": "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f",
            "master_fingerprint": "d90c6a4f",
            "path": f"m/0{_HARDENING}/0/0",
        },
        {
            "pub_key": "02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7",
            "master_fingerprint": "d90c6a4f",
            "path": f"m/0{_HARDENING}/0/0",
        },
    ]
    hd_key_paths = decode_from_bip32_derivs(bip32_derivs)
    with pytest.raises(
        BTClibValueError, match="Duplicated key origin values in hd_key_paths"
    ):
        assert_valid_hd_key_paths(hd_key_paths)


def test_bip32_derivs_check_validity() -> None:
    """Check check_validity=False defers the fingerprint check (issue 264)."""
    # issue 264: check_validity=False lets a malformed master_fingerprint
    # through decode_from_bip32_derivs, the way every other check_validity
    # does -- deferred to assert_valid_hd_key_paths rather than refused here
    bip32_derivs = [
        {
            "pub_key": "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f",
            "master_fingerprint": "d90c6a",
            "path": f"m/0{_HARDENING}/0/0",
        },
    ]
    with pytest.raises(BTClibValueError, match="invalid size: "):
        decode_from_bip32_derivs(bip32_derivs)

    hd_key_paths = decode_from_bip32_derivs(bip32_derivs, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid master fingerprint length: "):
        assert_valid_hd_key_paths(hd_key_paths)


def test_an_unchecked_origin_cannot_enter_a_psbt_or_its_json() -> None:
    """The two public entries of this module (issue 693, rule of #684).

    `decode_hd_key_paths` runs `bytes_from_octets` over the mapping's keys
    and copied the `BIP32KeyOrigin` values across untouched, so it was a
    public entry through which an unchecked origin entered a psbt's
    `hd_key_paths`; `encode_to_bip32_derivs` then wrote
    `master_fingerprint.hex()` of whatever it held into the json.
    `assert_valid_hd_key_paths`, the validating counterpart, sits beside
    both.
    """
    bad = BIP32KeyOrigin(b"\x01\x02\x03", [0], check_validity=False)
    pub_key = b"\x02" * 33
    err_msg = "invalid master fingerprint length: 3"

    with pytest.raises(BTClibValueError, match=err_msg):
        decode_hd_key_paths({pub_key: bad})
    with pytest.raises(BTClibValueError, match=err_msg):
        encode_to_bip32_derivs({pub_key: bad})
