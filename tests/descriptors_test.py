#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.descriptors` module.

The derivation vectors are Bitcoin Core's own, transcribed from the
`descriptor_test` case of `src/test/descriptor_tests.cpp` at commit
8ecbe270f0dee68b7eec6cea1714f453c5e215ad (2026-07-29): each `Check(prv,
pub, ...)` there gives a descriptor in its private and its public
spelling and the scriptPubKey each expands to, at index 0, 1 and 2 where
the descriptor is ranged. Both spellings are exercised, so a WIF and an
xprv are checked to reach the script the public key and the xpub beside
them reach. Not vendored as a file: the values are extracted from C++
source rather than copied from a data file, so the citation is the
commit and the case, and `tests/_data/README.md` covers what is vendored.

Four of those descriptors have no public spelling to check, and Core's
own flags say why: HARDENED and DERIVE_HARDENED mark a derivation that
needs the private key, so Core expands the private form alone and this
module expects the public one to be refused.

The descriptors of Core's `doc/descriptors.md` are already vendored, as
`tests/_data/descriptor_checksums.json`, and are read here a second
time: what the checksum test asks of them is the eight characters, what
the parser test asks is that each one expands and that every address it
produces is the address of that very script.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib.descriptors import (
    AddrDescriptor,
    ComboDescriptor,
    Descriptor,
    KeyExpression,
    MultiDescriptor,
    PkDescriptor,
    RawDescriptor,
    ShDescriptor,
    TrDescriptor,
    WshDescriptor,
    __descsum_expand,
    add_checksum,
    descriptor_checksum,
    descriptor_from_address,
    multipath_descriptors,
    parse,
    strip_checksum,
)
from btclib.exceptions import BTClibValueError
from btclib.script.script_pub_key import ScriptPubKey
from tests import load, vector_id

DOC_DESCRIPTORS = [
    descriptor_data["desc"]
    for descriptor_data in load("_data", "descriptor_checksums.json", encoding="utf-8")
]

CHECKSUM_VECTORS = [
    pytest.param(
        descriptor_data["desc"],
        descriptor_data["checksum"],
        id=vector_id(index, descriptor_data["desc"]),
    )
    for index, descriptor_data in enumerate(
        load("_data", "descriptor_checksums.json", encoding="utf-8")
    )
]


# descriptors taken from https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
# checksum calculated using https://docs.rs/bdk/latest/bdk/descriptor/checksum/fn.get_checksum.html
@pytest.mark.parametrize(("descriptor", "checksum"), CHECKSUM_VECTORS)
def test_checksum(descriptor: str, checksum: str) -> None:
    assert descriptor_checksum(descriptor) == checksum


def test_invalid_charset() -> None:
    with pytest.raises(BTClibValueError):
        __descsum_expand("è")


def test_addr() -> None:
    address = "bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0"
    descriptor = "addr(bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0)#s2y3vepm"
    assert descriptor_from_address(address) == descriptor


def test_add_and_strip_checksum() -> None:
    descriptor = "addr(bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0)"
    checksummed = f"{descriptor}#s2y3vepm"
    assert add_checksum(descriptor) == checksummed
    # adding one to a descriptor that has one verifies it and changes
    # nothing, which is what makes add_checksum safe to call on input
    assert add_checksum(checksummed) == checksummed
    assert strip_checksum(checksummed) == descriptor
    assert strip_checksum(descriptor) == descriptor


def test_invalid_checksum() -> None:
    descriptor = "addr(bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0)"
    with pytest.raises(BTClibValueError, match="invalid descriptor checksum"):
        strip_checksum(f"{descriptor}#00000000")
    with pytest.raises(BTClibValueError, match="more than one"):
        strip_checksum(f"{descriptor}#s2y3vepm#s2y3vepm")


# what a descriptor is made of: the checksum alphabet is defined over
# these, and a character outside it is a different error
DESCRIPTOR_CHARS = (
    "0123456789()[],'/*abcdefgh@:$%{}"
    "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    'ijklmnopqrstuvwxyzABCDEFGH`#"\\ '
)
DESCRIPTOR = st.text(alphabet=DESCRIPTOR_CHARS, min_size=1, max_size=60)


@given(descriptor=DESCRIPTOR)
def test_checksum_is_eight_characters(descriptor: str) -> None:
    assert len(descriptor_checksum(descriptor)) == 8


@given(
    descriptor=DESCRIPTOR,
    position=st.integers(min_value=0),
    replacement=st.sampled_from(DESCRIPTOR_CHARS),
)
def test_a_changed_character_changes_the_checksum(
    descriptor: str, position: int, replacement: str
) -> None:
    """A single substitution is what the BIP-380 checksum must catch.

    It is designed to catch any error of up to four characters, so one
    is the case it must never miss -- and the case a wallet meets, a
    descriptor being something a person retypes.
    """
    i = position % len(descriptor)
    mutated = descriptor[:i] + replacement + descriptor[i + 1 :]
    if mutated == descriptor:
        return
    assert descriptor_checksum(mutated) != descriptor_checksum(descriptor)


# Bitcoin Core's descriptor_test: the private spelling, the public one
# (None where Core's flags say the public key cannot derive the scripts),
# and the scriptPubKey set at each index
CORE_VECTORS: list[tuple[str, str | None, list[list[str]]]] = [
    (
        "combo(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
        "combo(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        [
            [
                "2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac",
                "76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac",
                "00149a1c78a507689f6f54b847ad1cef1e614ee23f1e",
                "a91484ab21b1b2fd065d4504ff693d832434b6108d7b87",
            ]
        ],
    ),
    (
        "pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
        "pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        [["2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac"]],
    ),
    (
        "pkh([deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
        "pkh([deadbeef/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        [["76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac"]],
    ),
    (
        "wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
        "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        [["00149a1c78a507689f6f54b847ad1cef1e614ee23f1e"]],
    ),
    (
        "sh(wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))",
        "sh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        [["a91484ab21b1b2fd065d4504ff693d832434b6108d7b87"]],
    ),
    (
        "tr(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
        "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        [["512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11"]],
    ),
    (
        "combo(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)",
        "combo(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
        [
            [
                "4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac",
                "76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac",
            ]
        ],
    ),
    (
        "pk(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)",
        "pk(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
        [
            [
                "4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac"
            ]
        ],
    ),
    (
        "pkh(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)",
        "pkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
        [["76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac"]],
    ),
    (
        "sh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))",
        "sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        [["a9141857af51a5e516552b3086430fd8ce55f7c1a52487"]],
    ),
    (
        "sh(pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))",
        "sh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        [["a9141a31ad23bf49c247dd531a623c2ef57da3c400c587"]],
    ),
    (
        "wsh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))",
        "wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        [["00202e271faa2325c199d25d22e1ead982e45b64eeb4f31e73dbdf41bd4b5fec23fa"]],
    ),
    (
        "wsh(pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))",
        "wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        [["0020338e023079b91c58571b20e602d7805fb808c22473cbc391a41b1bd3a192e75b"]],
    ),
    (
        "sh(wsh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)))",
        "sh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        [["a91472d0c5a3bfad8c3e7bd5303a72b94240e80b6f1787"]],
    ),
    (
        "sh(wsh(pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)))",
        "sh(wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        [["a914b61b92e2ca21bac1e72a3ab859a742982bea960a87"]],
    ),
    (
        "tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5,{pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5),{pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5)}})",
        "tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5,{pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5),{pk(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5)}})",
        [["51201497ae16f30dacb88523ed9301bff17773b609e8a90518a3f96ea328a47d1500"]],
    ),
    (
        "combo([01234567]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)",
        "combo([01234567]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)",
        [
            [
                "2102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0ac",
                "76a91431a507b815593dfc51ffc7245ae7e5aee304246e88ac",
                "001431a507b815593dfc51ffc7245ae7e5aee304246e",
                "a9142aafb926eb247cb18240a7f4c07983ad1f37922687",
            ]
        ],
    ),
    (
        "pk(xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0)",
        "pk(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)",
        [["210379e45b3cf75f9c5f9befd8e9506fb962f6a9d185ac87001ec44a8d3df8d4a9e3ac"]],
    ),
    (
        "pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0)",
        None,
        [["76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac"]],
    ),
    (
        "wpkh([ffffffff/13']xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*)",
        "wpkh([ffffffff/13']xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)",
        [
            ["0014326b2249e3a25d5dc60935f044ee835d090ba859"],
            ["0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7"],
            ["00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27"],
        ],
    ),
    (
        "sh(wpkh(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))",
        None,
        [
            ["a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87"],
            ["a914bed59fc0024fae941d6e20a3b44a109ae740129287"],
            ["a9148483aa1116eb9c05c482a72bada4b1db24af654387"],
        ],
    ),
    (
        "combo(xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/*)",
        "combo(xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/*)",
        [
            [
                "2102df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e076ac",
                "76a914f90e3178ca25f2c808dc76624032d352fdbdfaf288ac",
                "0014f90e3178ca25f2c808dc76624032d352fdbdfaf2",
                "a91408f3ea8c68d4a7585bf9e8bda226723f70e445f087",
            ],
            [
                "21032869a233c9adff9a994e4966e5b821fd5bac066da6c3112488dc52383b4a98ecac",
                "76a914a8409d1b6dfb1ed2a3e8aa5e0ef2ff26b15b75b788ac",
                "0014a8409d1b6dfb1ed2a3e8aa5e0ef2ff26b15b75b7",
                "a91473e39884cb71ae4e5ac9739e9225026c99763e6687",
            ],
        ],
    ),
    (
        "tr(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/0/*,pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/1/*))",
        "tr(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*,pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*))",
        [
            ["512078bc707124daa551b65af74de2ec128b7525e10f374dc67b64e00ce0ab8b3e12"],
            ["512001f0a02a17808c20134b78faab80ef93ffba82261ccef0a2314f5d62b6438f11"],
            ["512021024954fcec88237a9386fce80ef2ced5f1e91b422b26c59ccfc174c8d1ad25"],
        ],
    ),
    (
        "wsh(multi(1,xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/0,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))",
        "wsh(multi(1,xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/0,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        [["0020cb155486048b23a6da976d4c6fe071a2dbc8a7b57aaf225b8955f2e2a27b5f00"]],
    ),
    (
        "multi(1,xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/*,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
        "multi(1,xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/*,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        [
            [
                "512102df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e0762103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd52ae"
            ],
            [
                "5121032869a233c9adff9a994e4966e5b821fd5bac066da6c3112488dc52383b4a98ec2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd52ae"
            ],
            [
                "5121035d30b6c66dc1e036c45369da8287518cf7e0d6ed1e2b905171c605708f14ca032103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd52ae"
            ],
        ],
    ),
    (
        "pkh([01234567/10/20]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0)",
        None,
        [["76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac"]],
    ),
    (
        "multi(1,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)",
        "multi(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
        [
            [
                "512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae"
            ]
        ],
    ),
    (
        "multi(2,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy,KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr,KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X)",
        "multi(2,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8)",
        [
            [
                "522103669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0210260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600210362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e853ae"
            ]
        ],
    ),
    (
        "sortedmulti(1,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)",
        "sortedmulti(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
        [
            [
                "512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae"
            ]
        ],
    ),
    (
        "sortedmulti(1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
        "sortedmulti(1,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        [
            [
                "512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae"
            ]
        ],
    ),
    (
        "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))",
        "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))",
        [["a91445a9a622a8b0a1269944be477640eedc447bbd8487"]],
    ),
    (
        "sortedmulti(2,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/*,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0/0/*)",
        "sortedmulti(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/*)",
        [
            [
                "5221025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b62102fbd47cc8034098f0e6a94c6aeee8528abf0a2153a5d8e46d325b7284c046784652ae"
            ],
            [
                "52210264fd4d1f5dea8ded94c61e9641309349b62f27fbffe807291f664e286bfbe6472103f4ece6dfccfa37b211eb3d0af4d0c61dba9ef698622dc17eecdf764beeb005a652ae"
            ],
            [
                "5221022ccabda84c30bad578b13c89eb3b9544ce149787e5b538175b1d1ba259cbb83321024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c52ae"
            ],
        ],
    ),
    (
        "wsh(multi(2,xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))",
        None,
        [
            ["0020b92623201f3bb7c3771d45b2ad1d0351ea8fbf8cfe0a0e570264e1075fa1948f"],
            ["002036a08bbe4923af41cf4316817c93b8d37e2f635dd25cfff06bd50df6ae7ea203"],
            ["0020a96e7ab4607ca6b261bfe3245ffda9c746b28d3f59e83d34820ec0e2b36c139c"],
        ],
    ),
    (
        "tr(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,pk(KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy))",
        "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))",
        [["512017cf18db381d836d8923b1bdb246cfcd818da1a9f0e6e7907f187f0b2f937754"]],
    ),
]

# the public spelling of the four descriptors that derive hardened: Core
# flags them HARDENED or DERIVE_HARDENED and expands the private one only
HARDENED_PUBLIC = [
    "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)",
    "sh(wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))",
    "pkh([01234567/10/20]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)",
    "wsh(multi(2,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))",
]

DERIVATION_VECTORS = [
    pytest.param(private, public, scripts, id=vector_id(index, public or private))
    for index, (private, public, scripts) in enumerate(CORE_VECTORS)
]


@pytest.mark.parametrize(("private", "public", "scripts"), DERIVATION_VECTORS)
def test_core_derivation_vector(
    private: str, public: str | None, scripts: list[list[str]]
) -> None:
    for descriptor in (private, public):
        if descriptor is None:
            continue
        parsed = parse(descriptor)
        assert parsed.is_ranged == (len(scripts) > 1)
        for index, expected in enumerate(scripts):
            derived = parsed.script_pub_keys(index)
            assert [spk.script.hex() for spk in derived] == expected
            assert parsed.addresses(index) == [spk.address for spk in derived]


@pytest.mark.parametrize(
    "descriptor",
    [
        pytest.param(descriptor, id=vector_id(index, descriptor))
        for index, descriptor in enumerate(HARDENED_PUBLIC)
    ],
)
def test_hardened_derivation_needs_the_private_key(descriptor: str) -> None:
    """An xpub cannot answer a hardened step, so the descriptor cannot.

    Bitcoin Core says the same by expanding only the private spelling of
    these four, and BIP 380 states it as a rule of the language.
    """
    parsed = parse(descriptor)
    with pytest.raises(BTClibValueError, match="hardened derivation"):
        parsed.script_pub_keys()


@pytest.mark.parametrize(
    "descriptor",
    [
        pytest.param(descriptor, id=vector_id(index, descriptor))
        for index, descriptor in enumerate(DOC_DESCRIPTORS)
    ],
)
def test_doc_descriptor(descriptor: str) -> None:
    """Every documented descriptor expands, and its addresses round-trip.

    The scripts have no external oracle here -- Core's document lists no
    script -- so what is checked is btclib against itself: an address is
    a notation for a script, and `ScriptPubKey.from_address` has to give
    back the very script the descriptor derived.
    """
    if "sortedmulti_a(" in descriptor:
        with pytest.raises(NotImplementedError, match="sortedmulti_a"):
            parse(descriptor)
        return
    script_pub_keys = parse(descriptor).script_pub_keys()
    assert script_pub_keys
    for script_pub_key in script_pub_keys:
        address = script_pub_key.address
        # p2pk and bare multisig have no address, which is not a failure
        if address:
            assert ScriptPubKey.from_address(address) == script_pub_key


def test_doc_descriptors_are_read_but_for_one() -> None:
    """Seventeen of Core's eighteen documented descriptors expand here.

    The eighteenth is a `sortedmulti_a()`, BIP 387, refused rather than
    guessed at. Counted rather than assumed, so that refreshing the
    vendored file cannot move a descriptor from one group to the other
    unnoticed.
    """
    unimplemented = [d for d in DOC_DESCRIPTORS if "sortedmulti_a(" in d]
    assert len(DOC_DESCRIPTORS) == 18
    assert len(unimplemented) == 1


def test_sortedmulti_sorts_what_multi_leaves_alone() -> None:
    """Core's document gives the same 2-of-2 twice, sorted and in order.

    The keys of the sortedmulti() are written in the other order, so the
    two describe one script only if the sorting happens.
    """
    ordered = "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))"
    sorted_ = "sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))"
    assert parse(ordered).script_pub_key() == parse(sorted_).script_pub_key()
    # and the ordering is not vacuous: written the other way round,
    # multi() gives another script where sortedmulti() gives this one
    reversed_ = "sh(multi(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))"
    assert parse(reversed_).script_pub_key() != parse(ordered).script_pub_key()


# Bitcoin Core's CheckMultipath vector at line 705 of the same file: one
# BIP 389 descriptor, the two it expands to, and the scripts of each
MULTIPATH = "wpkh([ffffffff/13h]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/<1;3>/2/*)"
MULTIPATH_EXPANSIONS = [
    "wpkh([ffffffff/13h]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)",
    "wpkh([ffffffff/13h]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/3/2/*)",
]
MULTIPATH_SCRIPTS = [
    [
        "0014326b2249e3a25d5dc60935f044ee835d090ba859",
        "0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7",
        "00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27",
    ],
    [
        "001426183882ef9c76b9a44386e9b387f33cee7c3a2d",
        "001447c1b9dc215c3f8b47e572981eb97528768cde4e",
        "00146e92cbaa397f9caeccf9a049460258af6ccd67e2",
    ],
]


def test_multipath() -> None:
    expanded = multipath_descriptors(MULTIPATH)
    assert [strip_checksum(d) for d in expanded] == MULTIPATH_EXPANSIONS
    for descriptor, scripts in zip(expanded, MULTIPATH_SCRIPTS, strict=True):
        parsed = parse(descriptor)
        derived = [parsed.script_pub_key(i).script.hex() for i in range(3)]
        assert derived == scripts


def test_multipath_of_a_single_path_descriptor() -> None:
    """A descriptor with no multipath step is one descriptor, checksummed."""
    descriptor = (
        "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
    )
    assert multipath_descriptors(descriptor) == [add_checksum(descriptor)]


def test_multipath_in_two_key_expressions() -> None:
    """Every step takes its i-th element, which is what BIP 389 says.

    Bitcoin Core's CheckMultipath vector at line 755 of the same file.
    """
    descriptor = "multi(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<1;2>/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/<3;4>/0/*)"
    expansions = [
        "multi(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/3/0/*)",
        "multi(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/2/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/4/0/*)",
    ]
    expanded = multipath_descriptors(descriptor)
    assert [strip_checksum(d) for d in expanded] == expansions


def test_invalid_multipath() -> None:
    xpub = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
    with pytest.raises(BTClibValueError, match="different length"):
        multipath_descriptors(f"multi(1,{xpub}/<0;1>/*,{xpub}/<0;1;2>/*)")
    with pytest.raises(BTClibValueError, match="at least two elements"):
        multipath_descriptors(f"pk({xpub}/<0>)")
    # and parse() does not read one, rather than reading it wrong
    with pytest.raises(BTClibValueError, match="multipath_descriptors"):
        parse(f"pk({xpub}/<0;1>)")


# Bitcoin Core's own, from the multipath example of doc/descriptors.md
TESTNET_XPUB = "tpubDDjsCRDQ9YzyaAq9rspCfq8RZFrWoBpYnLxK6sS2hS2yukqSczgcYiur8Scx4Hd5AZatxTuzMtJQJhchufv1FRFanLqUP7JHwusSSpfcEp2"


def test_network() -> None:
    """The chain is a parameter, and a key disagreeing with it is an error."""
    descriptor = f"wpkh([6f53d49c/44h/1h/0h]{TESTNET_XPUB}/0/0)"
    script_pub_key = parse(descriptor, "testnet").script_pub_key()
    assert script_pub_key.network == "testnet"
    assert script_pub_key.address.startswith("tb1")
    assert ScriptPubKey.from_address(script_pub_key.address) == script_pub_key
    with pytest.raises(BTClibValueError, match="key for mainnet"):
        parse(descriptor).script_pub_key()


def test_addr_takes_the_network_of_its_address() -> None:
    """An address states its own chain, so no parameter can contradict it."""
    address = "tb1qjwxuan3npm4489vlt0gcyqxwvaghkux009tfyd"
    parsed = parse(f"addr({address})")
    assert isinstance(parsed, AddrDescriptor)
    assert parsed.network == "testnet"
    assert parsed.address() == address
    assert not parsed.is_ranged
    assert parsed.key_expressions == ()


def test_raw() -> None:
    script = "76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac"
    parsed = parse(f"raw({script})")
    assert isinstance(parsed, RawDescriptor)
    assert parsed.script_pub_key().script.hex() == script
    assert not parsed.is_ranged
    assert parsed.key_expressions == ()


def test_combo_is_a_set_of_scripts() -> None:
    """`combo()` answers with four scripts, so it answers with no address.

    `script_pub_key` is the one-script question, and asking it of a
    combo() is a question with no answer rather than one of the four.
    """
    key = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
    parsed = parse(f"combo({key})")
    assert isinstance(parsed, ComboDescriptor)
    assert len(parsed.script_pub_keys()) == 4
    with pytest.raises(BTClibValueError, match="use script_pub_keys instead"):
        parsed.script_pub_key()
    with pytest.raises(BTClibValueError, match="use script_pub_keys instead"):
        parsed.address()
    # the p2pk of the four has no address, and says so with an empty one
    assert parsed.addresses()[0] == ""


def test_redeem_script() -> None:
    """What sh() hashes is the script of the descriptor it embeds."""
    key = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
    parsed = parse(f"sh(wpkh({key}))")
    assert isinstance(parsed, ShDescriptor)
    assert parsed.inner.redeem_script() == ScriptPubKey.p2wpkh(key).script
    assert parsed.script_pub_key() == ScriptPubKey.p2sh(parsed.inner.redeem_script())


def test_index_out_of_range() -> None:
    ranged = "wpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)"
    parsed = parse(ranged)
    assert parsed.is_ranged
    with pytest.raises(BTClibValueError, match="invalid derivation index"):
        parsed.script_pub_keys(-1)
    with pytest.raises(BTClibValueError, match="invalid derivation index"):
        parsed.script_pub_keys(0x80000000)
    key = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
    fixed = parse(f"wpkh({key})")
    assert not fixed.is_ranged
    with pytest.raises(BTClibValueError, match="not a ranged descriptor"):
        fixed.script_pub_keys(1)


def test_key_origin_is_kept() -> None:
    """The origin does not change the script, and is not thrown away."""
    key = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
    origin = parse(f"pkh([deadbeef/1/2h/3/4h]{key})").key_expressions[0].origin
    assert origin is not None
    assert origin.description == "deadbeef/1/2h/3/4h"
    # the same descriptor with the other hardening marker is the same
    # descriptor: BIP 380 gives h and ' the same meaning
    apostrophes = parse(f"pkh([deadbeef/1/2'/3/4']{key})")
    assert apostrophes.key_expressions[0].origin == origin


def test_key_expression_fields() -> None:
    xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
    (key,) = parse(f"wpkh({xpub}/1/2/*)").key_expressions
    assert key == KeyExpression(xkey=xpub, der_path=(1, 2), wildcard=0)
    assert key.is_ranged
    assert key.is_compressed
    (hardened,) = parse(f"pkh({xpub}/1/2/*h)").key_expressions
    assert hardened.wildcard == 0x80000000
    uncompressed = "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235"
    (plain,) = parse(f"pk({uncompressed})").key_expressions
    assert not plain.is_ranged
    assert not plain.is_compressed
    assert plain.sec() == bytes.fromhex(uncompressed)
    # the index is the wildcard's, so a key without one ignores it
    assert plain.sec(5) == plain.sec(0)


def test_tr_tree_keys() -> None:
    internal = "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
    leaf = "669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0"
    parsed = parse(f"tr({internal},{{pk({leaf}),pk({internal})}})")
    assert isinstance(parsed, TrDescriptor)
    # the internal key and both leaves, in that order
    assert len(parsed.key_expressions) == 3
    assert parsed.key_expressions[0].x_only
    key_path_only = parse(f"tr({internal})")
    assert isinstance(key_path_only, TrDescriptor)
    assert key_path_only.tree is None
    assert len(key_path_only.key_expressions) == 1


def test_parsed_types() -> None:
    key = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
    assert isinstance(parse(f"pk({key})"), PkDescriptor)
    assert isinstance(parse(f"wsh(pk({key}))"), WshDescriptor)
    multi = parse(f"multi(1,{key})")
    assert isinstance(multi, MultiDescriptor)
    assert multi.threshold == 1
    assert not multi.sort
    sorted_multi = parse(f"sortedmulti(1,{key})")
    assert isinstance(sorted_multi, MultiDescriptor)
    assert sorted_multi.sort


def test_too_many_keys_for_a_multisig() -> None:
    """OP_CHECKMULTISIG counts with one op code, so n stops at 16.

    Bitcoin Core reads a `multi()` of twenty keys inside `wsh()`, where
    the count is pushed rather than encoded as OP_1 to OP_16; this
    library's p2ms builder does not, and refuses it here rather than
    building a script that says something else.
    """
    key = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
    keys = ",".join([key] * 17)
    with pytest.raises(BTClibValueError, match="invalid n in m-of-n"):
        parse(f"wsh(multi(1,{keys}))").script_pub_key()


def test_descriptor_is_abstract() -> None:
    """The base class is the interface, and derives no script of its own."""
    with pytest.raises(TypeError, match="abstract"):
        Descriptor()  # type: ignore[abstract]


KEY = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
UNCOMPRESSED = "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235"
XPUB = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
XONLY = "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
OFF_CURVE = "020000000000000000000000000000000000000000000000000000000000000005"

# what a descriptor cannot be, and the message that says so. The first
# group is Bitcoin Core's own CheckUnparsable cases, from the same
# descriptor_test; the rest are the position rules of BIP 381 to BIP 386
# and the shapes a recursive parser has to refuse
UNPARSABLE = [
    # Core: an invalid public key, here 64 hex characters where an x-only
    # key is not allowed
    (f"sh(wpkh({KEY[:64]}))", "x-only"),
    # Core: a key origin without its opening bracket
    (f"pkh(deadbeef/1/2h]{KEY})", "without the "),
    # Core: two closing brackets for one key
    (f"pkh([deadbeef][01234567]{KEY})", "more than one"),
    # Core: no uncompressed key in a witness program
    (f"wpkh({UNCOMPRESSED})", "uncompressed"),
    (f"wsh(pk({UNCOMPRESSED}))", "uncompressed"),
    (f"sh(wpkh({UNCOMPRESSED}))", "uncompressed"),
    # Core: the hybrid encoding, which nothing in bitcoin produces
    (f"combo(07{UNCOMPRESSED[2:]})", "public key prefix"),
    (f"pk(06{UNCOMPRESSED[2:]})", "public key prefix"),
    # Core: a fingerprint that is not four bytes
    (f"combo([012345678]{XPUB})", "fingerprint"),
    # Core: a derivation index that is no BIP 32 index
    (f"pkh({XPUB}/2147483648)", "invalid index"),
    (f"pkh({XPUB}/1aa)", "invalid derivation index"),
    (f"pkh({XPUB}/+1)", "invalid derivation index"),
    # Core: an address that is not one, and a script that is not hex
    ("addr(asdf)", "base58"),
    ("raw(asdf)", "hex script"),
    # the position rules
    (f"wsh(sh(pk({KEY})))", "not allowed inside"),
    (f"sh(combo({KEY}))", "not allowed inside"),
    (f"wsh(wpkh({KEY}))", "not allowed inside"),
    (f"sh(tr({XONLY}))", "not allowed inside"),
    ("sh(addr(1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH))", "not allowed inside"),
    ("sh(raw(00))", "not allowed inside"),
    # a key expression written for another position, or not at all
    (f"pk({XONLY})", "x-only"),
    (f"pk({KEY}/0)", "cannot derive"),
    (f"pk({KEY[:-4]})", "public key length"),
    (f"pk({OFF_CURVE})", "not a public key"),
    ("pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY2)", "key expression"),
    ("pk(nope(03))", "not a key expression"),
    (f"pkh([deadbeef{KEY})", "missing "),
    # the shape of an expression
    ("pk", "not a descriptor expression"),
    ("(pk)", "not a descriptor expression"),
    (f"nope({KEY})", "unknown descriptor function"),
    (f"pk({KEY},{KEY})", "takes one argument"),
    (f"multi(x,{KEY})", "threshold"),
    ("multi(1)", "at least one key"),
    (f"pk({KEY}))", "unbalanced"),
    (f"pk(({KEY})", "unbalanced"),
    (f"tr({XONLY},pk({XONLY}),pk({XONLY}))", "at most one tree"),
    (f"tr({XONLY},{{pk({XONLY})}})", "two subtrees"),
    (f"tr({XONLY},{{pk({XONLY}),pk({XONLY})}}x)", "unbalanced braces"),
    # a character the language has no symbol for, which is the checksum's
    # charset speaking about a descriptor that carries no checksum: every
    # printable ASCII character is in INPUT_CHARSET, so it takes a
    # non-ASCII one to be outside it
    (f"pk(è{KEY[1:]})", "invalid descriptor character"),
]


@pytest.mark.parametrize(
    ("descriptor", "message"),
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(UNPARSABLE)
    ],
)
def test_unparsable(descriptor: str, message: str) -> None:
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


# what is a descriptor, is not implemented, and is refused by name rather
# than read wrong
UNIMPLEMENTED = [
    (
        f"wsh(and_v(v:ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e),pk({KEY})))",
        "187",
    ),
    (f"wsh(thresh(1,pk({KEY})))", "187"),
    (f"wsh(s:pk({KEY}))", "187"),
    (f"tr({XONLY},multi_a(1,{XONLY}))", "BIP 387"),
    (f"tr({XONLY},sortedmulti_a(1,{XONLY}))", "BIP 387"),
    (f"tr({XONLY},pkh({KEY}))", "inside tr"),
    (f"rawtr({XONLY})", "BIP 386"),
    (f"tr(musig({KEY},{KEY}))", "BIP 390"),
]


@pytest.mark.parametrize(
    ("descriptor", "message"),
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(UNIMPLEMENTED)
    ],
)
def test_unimplemented(descriptor: str, message: str) -> None:
    with pytest.raises(NotImplementedError, match=message):
        parse(descriptor)
