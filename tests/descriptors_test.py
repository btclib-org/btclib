# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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

from btclib.alias import Octets
from btclib.bip32 import BIP32KeyOrigin
from btclib.bip32.bip32 import xpub_from_xprv
from btclib.bip32.der_path import _HARDENING
from btclib.descriptors import (
    AddrDescriptor,
    ComboDescriptor,
    Descriptor,
    KeyExpression,
    MultiA,
    MultiDescriptor,
    PkDescriptor,
    RawDescriptor,
    ShDescriptor,
    TrDescriptor,
    WshDescriptor,
    __descsum_expand,
    add_checksum,
    checksum,
    from_address,
    multipath_descriptors,
    parse,
    strip_checksum,
)
from btclib.ecc import dsa, ssa
from btclib.exceptions import BTClibValueError
from btclib.psbt.psbt import (
    Psbt,
    _finalized_input,
    finalize,
    taproot_sig_hash,
)
from btclib.psbt.psbt_in import PsbtIn
from btclib.script import sig_hash, taproot
from btclib.script.engine import verify_transaction
from btclib.script.script import serialize
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.witness import Witness
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.to_pub_key import pub_keyinfo_from_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut
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
@pytest.mark.parametrize("descriptor, expected_checksum", CHECKSUM_VECTORS)
def test_checksum(descriptor: str, expected_checksum: str) -> None:
    """Reproduce the checksum of each descriptor of Core's descriptors.md."""
    assert checksum(descriptor) == expected_checksum


def test_invalid_charset() -> None:
    """Refuse a character outside the BIP380 checksum charset."""
    with pytest.raises(BTClibValueError):
        __descsum_expand("è")


def test_addr() -> None:
    """Build a checksummed addr() descriptor from an address."""
    address = "bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0"
    descriptor = "addr(bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0)#s2y3vepm"
    assert from_address(address) == descriptor


def test_add_and_strip_checksum() -> None:
    """Round-trip the checksum, idempotently in both directions."""
    descriptor = "addr(bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0)"
    checksummed = f"{descriptor}#s2y3vepm"
    assert add_checksum(descriptor) == checksummed
    # adding one to a descriptor that has one verifies it and changes
    # nothing, which is what makes add_checksum safe to call on input
    assert add_checksum(checksummed) == checksummed
    assert strip_checksum(checksummed) == descriptor
    assert strip_checksum(descriptor) == descriptor


def test_invalid_checksum() -> None:
    """Refuse a wrong checksum and a descriptor carrying two."""
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
    """Verify the checksum is eight characters whatever the input."""
    assert len(checksum(descriptor)) == 8


@given(
    descriptor=DESCRIPTOR,
    position=st.integers(min_value=0),
    replacement=st.sampled_from(DESCRIPTOR_CHARS),
)
def test_a_changed_character_changes_the_checksum(
    descriptor: str, position: int, replacement: str
) -> None:
    """A single substitution is what the BIP380 checksum must catch.

    It is designed to catch any error of up to four characters, so one
    is the case it must never miss -- and the case a wallet meets, a
    descriptor being something a person retypes.
    """
    i = position % len(descriptor)
    mutated = descriptor[:i] + replacement + descriptor[i + 1 :]
    if mutated == descriptor:
        return
    assert checksum(mutated) != checksum(descriptor)


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


@pytest.mark.parametrize("private, public, scripts", DERIVATION_VECTORS)
def test_core_derivation_vector(
    private: str, public: str | None, scripts: list[list[str]]
) -> None:
    """Reproduce Bitcoin Core's descriptor derivation vectors.

    Both spellings derive the same scripts at every index, and the
    addresses are the addresses of those very scripts.

    The private material `parse` hands back goes into every expansion,
    which four of these vectors need and the rest do not: a hardened step
    under an xprv is the one thing an xpub cannot take, and the four
    public spellings of those are `HARDENED_PUBLIC` below.
    """
    for descriptor in (private, public):
        if descriptor is None:
            continue
        prv_keys: dict[str, str] = {}
        parsed = parse(descriptor, prv_keys=prv_keys)
        assert prv_keys == {} or descriptor is private
        assert parsed.is_ranged == (len(scripts) > 1)
        for index, expected in enumerate(scripts):
            derived = parsed.script_pub_keys(index, prv_keys)
            assert [spk.script.hex() for spk in derived] == expected
            assert parsed.addresses(index, prv_keys) == [spk.address for spk in derived]


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
    these four, and BIP380 states it as a rule of the language.
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
    script_pub_keys = parse(descriptor).script_pub_keys()
    assert script_pub_keys
    for script_pub_key in script_pub_keys:
        address = script_pub_key.address
        # p2pk and bare multisig have no address, which is not a failure
        if address:
            assert ScriptPubKey.from_address(address) == script_pub_key


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
# BIP389 descriptor, the two it expands to, and the scripts of each
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
    """Reproduce Bitcoin Core's CheckMultipath vector, scripts included."""
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
    """Every step takes its i-th element, which is what BIP389 says.

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
    """Refuse mismatched multipath lengths and a single-element step."""
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
    """Verify raw() answers the very script it wraps, unranged."""
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
    """Refuse an out-of-range index, and any index on a fixed descriptor."""
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


def test_no_private_key_survives_the_parse() -> None:
    """Nothing reachable from a parsed descriptor is a key that signs.

    The whole object graph is searched and not `xkey` alone: what the
    property has to be is that a descriptor cannot leak a secret, and a
    field added later must not be the place it does.
    """
    xprv = (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
        "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    )
    wif = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"
    descriptor = f"wsh(multi(1,{xprv}/10/20,{wif}))"

    prv_keys: dict[str, str] = {}
    parsed = parse(descriptor, prv_keys=prv_keys)

    # the mapping is keyed by the public spelling, and holds the private
    # one: the xprv left the descriptor rather than being dropped
    xpub = xpub_from_xprv(xprv)
    assert prv_keys == {xpub: xprv}
    assert parsed.key_expressions[0].xkey == xpub

    for secret in (xprv, wif, str(prv_keyinfo_from_prv_key(wif)[0])):
        assert secret not in repr(parsed)
        assert secret not in str(vars(parsed))

    # and asking for nothing gets a descriptor with nothing in it
    assert parse(descriptor).key_expressions[0].xkey == xpub

    # the WIF was already public before this: no derivation is made from
    # it and nothing here signs, so it is reduced and not filed
    assert wif not in prv_keys.values()
    assert parsed.key_expressions[1].pub_key == pub_keyinfo_from_key(wif)[0]


def test_a_hardened_step_takes_the_keys_back() -> None:
    """The parsed descriptor derives what an xpub can, and no more."""
    xprv = (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
        "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    )
    prv_keys: dict[str, str] = {}
    hardened = parse(f"wpkh({xprv}/10h/*)", prv_keys=prv_keys)

    with pytest.raises(BTClibValueError, match="hardened derivation"):
        hardened.script_pub_keys(0)
    assert hardened.script_pub_keys(0, prv_keys)

    # every expansion method takes them, and answers the same either way
    # where the path has no hardened step to take
    unhardened = parse(f"wpkh({xprv}/10/*)", prv_keys=prv_keys)
    for index in (0, 7):
        assert unhardened.script_pub_keys(index) == unhardened.script_pub_keys(
            index, prv_keys
        )
        assert unhardened.address(index) == unhardened.address(index, prv_keys)

    # a mapping that does not name this key leaves it as it is, so the
    # hardened step is refused the way it is with no mapping at all
    with pytest.raises(BTClibValueError, match="hardened derivation"):
        hardened.script_pub_keys(0, {"xpub-of-somebody-else": xprv})


def test_the_hardening_symbol_that_was_read_is_the_one_kept() -> None:
    """A key expression remembers which of the two spellings it was written in.

    BIP380 gives ``h`` and ``'`` one meaning, and the two are different
    strings with different checksums, so which one was read is what
    writing the descriptor back again takes.
    """
    key = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"

    for symbol in ("h", "'"):
        parsed = parse(f"pkh([deadbeef/1/2{symbol}/3]{key})")
        assert parsed.key_expressions[0].hardening == symbol

    # BIP380's own valid vector with mixed indicators: one symbol for the
    # expression, and it is the last hardened step's, which is Bitcoin
    # Core's single m_apostrophe by construction
    mixed = parse(f"pk([deadbeef/0'/0h/0']{key})")
    assert mixed.key_expressions[0].hardening == "'"
    assert parse(f"pk([deadbeef/0'/0h/0h]{key})").key_expressions[0].hardening == "h"

    # the key's own path is written after the origin's, and the wildcard
    # after both, so each in turn has the last word
    assert parse(f"wpkh([deadbeef/0']{XPUB}/1h/2)").key_expressions[0].hardening == "h"
    assert parse(f"wpkh([deadbeef/0h]{XPUB}/1'/2)").key_expressions[0].hardening == "'"
    assert parse(f"wpkh([deadbeef/0h]{XPUB}/1/*')").key_expressions[0].hardening == "'"
    assert parse(f"wpkh([deadbeef/0']{XPUB}/1/*h)").key_expressions[0].hardening == "h"

    # a path that hardens nothing, and a key that has no path at all,
    # keep the default rather than an answer they were never given
    assert parse(f"wpkh({XPUB}/1/2)").key_expressions[0].hardening == _HARDENING
    assert parse(f"pk({key})").key_expressions[0].hardening == _HARDENING


def test_the_origin_is_the_same_whichever_symbol_spelled_it() -> None:
    """The spelling is the key expression's, and never the origin's.

    `BIP32KeyOrigin` is a fingerprint and a path: two that differ in
    nothing else are equal, serialize to the same bytes and hash the
    same, whichever way the descriptor wrote the path. Which is why the
    symbol is a field of the KeyExpression around it.
    """
    key = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
    apostrophes = parse(f"pkh([deadbeef/1/2'/3]{key})").key_expressions[0]
    aitches = parse(f"pkh([deadbeef/1/2h/3]{key})").key_expressions[0]

    assert apostrophes.origin == aitches.origin
    assert hash(apostrophes.origin) == hash(aitches.origin)
    assert apostrophes.hardening != aitches.hardening
    # and so the two key expressions are not the same key expression
    assert apostrophes != aitches


def test_key_origin_is_kept() -> None:
    """The origin does not change the script, and is not thrown away."""
    key = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
    origin = parse(f"pkh([deadbeef/1/2h/3/4h]{key})").key_expressions[0].origin
    assert origin is not None
    assert origin.description == "deadbeef/1/2h/3/4h"
    # the same descriptor with the other hardening marker is the same
    # descriptor: BIP380 gives h and ' the same meaning
    apostrophes = parse(f"pkh([deadbeef/1/2'/3/4']{key})")
    assert apostrophes.key_expressions[0].origin == origin


def test_key_expression_fields() -> None:
    """Check the parsed fields of ranged, hardened and plain keys."""
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
    """Verify a tr() lists the internal key and every leaf key."""
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
    """Verify parse returns the descriptor type each function names."""
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
# the same two keys as WIFs, which is how BIP387 writes them
WIF = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"
UNCOMPRESSED_WIF = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss"
XPUB = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
XONLY = "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
OFF_CURVE = "020000000000000000000000000000000000000000000000000000000000000005"

# what a descriptor cannot be, and the message that says so. The first
# group is Bitcoin Core's own CheckUnparsable cases, from the same
# descriptor_test; the rest are the position rules of BIP381 to BIP386
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
    # Core: a derivation index that is no BIP32 index
    (f"pkh({XPUB}/2147483648)", "invalid index"),
    (f"pkh({XPUB}/1aa)", "invalid derivation index"),
    (f"pkh({XPUB}/+1)", "invalid derivation index"),
    # BIP380's own invalid hardened indicators: the uppercase H that
    # BIP32 writes its vectors with is not one a descriptor may hold
    (f"pk([deadbeef/0H/0H/0H]{KEY})", "invalid derivation index"),
    (f"pk([deadbeef/0f/0f/0f]{KEY})", "invalid derivation index"),
    (f"pk([deadbeef/-0/-0/-0]{KEY})", "invalid derivation index"),
    (f"pkh({XPUB}/3H/4h/5h)", "invalid derivation index"),
    # what the lenient BIP32 reading takes and BIP380's grammar does not
    (f"pkh({XPUB}/m/0)", "invalid derivation index"),
    (f"pkh({XPUB}/0//1)", "invalid derivation index"),
    (f"pkh({XPUB}/ 0 h)", "invalid derivation index"),
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
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(UNPARSABLE)
    ],
)
def test_unparsable(descriptor: str, message: str) -> None:
    """Refuse each unparsable descriptor with the message naming why."""
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
    (f"tr({XONLY},pkh({KEY}))", "inside tr"),
    (f"rawtr({XONLY})", "BIP386"),
    (f"tr(musig({KEY},{KEY}))", "BIP390"),
]


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(UNIMPLEMENTED)
    ],
)
def test_unimplemented(descriptor: str, message: str) -> None:
    """Refuse each unimplemented descriptor, naming the BIP or issue."""
    with pytest.raises(NotImplementedError, match=message):
        parse(descriptor)


# BIP387's own test vectors, transcribed from `bip-0387.mediawiki`: a
# valid descriptor and the scriptPubKey it produces, three of them where
# the keys derive. The third and the fourth are the same two keys, ordered
# and sorted, so the pair says both that the sorting happens and which
# script each spelling means
BIP387_VECTORS: list[tuple[str, list[str]]] = [
    (
        "tr(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,multi_a(1,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy))",
        ["5120eb5bd3894327d75093891cc3a62506df7d58ec137fcd104cdd285d67816074f3"],
    ),
    (
        "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,multi_a(1,669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))",
        ["5120eb5bd3894327d75093891cc3a62506df7d58ec137fcd104cdd285d67816074f3"],
    ),
    (
        "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,multi_a(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))",
        ["51202eea93581594a43c0c8423b70dc112e5651df63984d108d4fc8ccd3b63b4eafa"],
    ),
    (
        "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))",
        ["512016fa6a6ba7e98c54b5bf43b3144912b78a61b60b02f6a74172b8dcb35b12bc30"],
    ),
    (
        "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/*))",
        [
            "5120abd47468515223f58a1a18edfde709a7a2aab2b696d59ecf8c34f0ba274ef772",
            "5120fe62e7ed20705bd1d3678e072bc999acb014f07795fa02cb8f25a7aa787e8cbd",
            "51201311093750f459039adaa2a5ed23b0f7a8ae2c2ffb07c5390ea37e2fb1050b41",
        ],
    ),
    (
        "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,multi_a(2,xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))",
        [
            "5120e4c8f2b0a7d3a688ac131cb03248c0d4b0a59bbd4f37211c848cfbd22a981192",
            "5120827faedaa21e52fca2ac83b53afd1ab7d4d1e6ce67ff42b19f2723d48b5a19ab",
            "5120647495ed09de61a3a324704f9203c130d655bf3141f9b748df8f7be7e9af55a4",
        ],
    ),
]


@pytest.mark.parametrize(
    "descriptor, scripts",
    [
        pytest.param(descriptor, scripts, id=vector_id(index, descriptor))
        for index, (descriptor, scripts) in enumerate(BIP387_VECTORS)
    ],
)
def test_bip387_vector(descriptor: str, scripts: list[str]) -> None:
    """Reproduce BIP387's own vectors: the script at each index it lists.

    One of them takes a hardened step under an xprv, which is what the
    private material `parse` hands back is for.
    """
    prv_keys: dict[str, str] = {}
    parsed = parse(descriptor, prv_keys=prv_keys)
    assert parsed.is_ranged == (len(scripts) > 1)
    for index, expected in enumerate(scripts):
        assert parsed.script_pub_key(index, prv_keys).script.hex() == expected


# BIP387's invalid descriptors, and what each is refused with. The
# threshold bounds are checked where the script is built, as `multi()`'s
# are in `ScriptPubKey.p2ms`, so for those the refusal comes from
# `script_pub_key` and for the rest from `parse`
BIP387_INVALID = [
    (f"multi_a(1,{KEY})", "not allowed inside top level"),
    (f"sh(multi_a(1,{KEY}))", "not allowed inside sh"),
    (f"wsh(multi_a(1,{KEY}))", "not allowed inside wsh"),
    (f"tr({XONLY},multi_a(a,{KEY}))", "invalid multi_a\\(\\) threshold"),
    (f"tr({XONLY},multi_a(0,{KEY}))", "invalid k in k-of-n multi_a"),
    (f"tr({XONLY},multi_a(1,{UNCOMPRESSED}))", "uncompressed"),
    # BIP387's own "threshold larger than keys" case names two
    # uncompressed WIFs, and an uncompressed key is refused before any
    # threshold is read: it is the case below that reaches the bound
    (f"tr({XONLY},multi_a(3,{WIF},{UNCOMPRESSED_WIF}))", "uncompressed"),
    (f"tr({XONLY},multi_a(3,{KEY},{KEY}))", "invalid k in k-of-n multi_a"),
    # and what BIP387 does not list: a threshold with no key after it
    (f"tr({XONLY},multi_a(1))", "at least one key"),
]


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(BIP387_INVALID)
    ],
)
def test_bip387_invalid(descriptor: str, message: str) -> None:
    """Refuse each of BIP387's invalid descriptors, with the reason named."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor).script_pub_key()


def leaf_script_of(descriptor: str) -> bytes:
    """Return the one leaf script of a tr() whose tree is a single leaf."""
    parsed = parse(descriptor)
    assert isinstance(parsed, TrDescriptor)
    ((script, _),) = parsed.taproot_leaf_scripts().values()
    return script


def test_multi_a_is_a_tree_leaf_and_not_a_descriptor() -> None:
    """What a `multi_a()` parses to is a `MultiA` leaf, its keys and all."""
    descriptor = parse(f"tr({XONLY},multi_a(2,{KEY},{XONLY}))")
    assert isinstance(descriptor, TrDescriptor)
    leaf = descriptor.tree
    assert isinstance(leaf, MultiA)
    assert leaf.threshold == 2
    assert not leaf.sort
    # the internal key and both of the leaf's keys, in that order
    assert len(descriptor.key_expressions) == 3
    assert descriptor.key_expressions[1:] == leaf.keys
    sorted_ = parse(f"tr({XONLY},sortedmulti_a(2,{KEY},{XONLY}))")
    assert isinstance(sorted_, TrDescriptor)
    assert isinstance(sorted_.tree, MultiA)
    assert sorted_.tree.sort


def test_sortedmulti_a_sorts_on_the_x_only_keys() -> None:
    """BIP387 sorts the 32 bytes the script holds, not the 33 SEC bytes.

    The two spellings of a key differ by the prefix that says the parity
    of y, so sorting the SEC form would order the keys by that parity
    first. These two are chosen for it: the odd-y key is the smaller of
    the two x-only and the larger of the two SEC, so one sort puts it
    first and the other last.
    """
    odd_y = "032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f"
    even_y = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert odd_y[2:] < even_y[2:]
    assert odd_y > even_y
    assert leaf_script_of(
        f"tr({XONLY},sortedmulti_a(1,{even_y},{odd_y}))"
    ) == serialize(
        [
            bytes.fromhex(odd_y[2:]),
            "OP_CHECKSIG",
            bytes.fromhex(even_y[2:]),
            "OP_CHECKSIGADD",
            "OP_1",
            "OP_NUMEQUAL",
        ]
    )


def test_a_multi_a_threshold_above_sixteen_is_pushed_as_a_number() -> None:
    """OP_1 to OP_16 are the thresholds an op code means, and 17 has none.

    Which is what BIP387 says about the script, and the only thing the
    seventeenth key changes beyond the length: sixteen ends in the single
    byte `60`, seventeen in the two-byte push `0111`, and `9c` is
    OP_NUMEQUAL either way.
    """
    keys = ",".join([KEY] * 17)
    assert leaf_script_of(f"tr({XONLY},multi_a(16,{keys}))").endswith(
        bytes.fromhex("609c")
    )
    assert leaf_script_of(f"tr({XONLY},multi_a(17,{keys}))").endswith(
        bytes.fromhex("01119c")
    )


def test_too_many_keys_for_a_multi_a() -> None:
    """BIP387 stops at 999 keys, a satisfaction being one element per key.

    Built rather than parsed: a thousand key expressions is a descriptor
    nobody writes, and the bound is on what the leaf holds.
    """
    (key,) = parse(f"tr({XONLY})").key_expressions
    with pytest.raises(BTClibValueError, match="invalid n in k-of-n multi_a"):
        TrDescriptor(key, MultiA(1, (key,) * 1000)).script_pub_key()
    # and the last count BIP387 allows is a script this builds
    allowed = TrDescriptor(key, MultiA(1, (key,) * 999))
    assert allowed.script_pub_key().script


# three keys and a signature made with each. Real DER signatures rather
# than placeholder bytes because the psbt finalizer that satisfaction is
# checked against parses every partial signature it is handed, so a
# placeholder would not reach the comparison
PRV_KEYS = (1, 2, 3)
SEC_KEYS = [pub_keyinfo_from_key(prv_key)[0].hex() for prv_key in PRV_KEYS]
SIGNATURES = {
    sec: (dsa.sign(bytes([i]) * 32, prv_key).serialize() + b"\x01").hex()
    for i, (sec, prv_key) in enumerate(zip(SEC_KEYS, PRV_KEYS, strict=True))
}
KEY_A, KEY_B, KEY_C = SEC_KEYS
# the x-only spelling of the same three, which is what a tr() holds
XONLY_A, XONLY_B, XONLY_C = (sec[2:] for sec in SEC_KEYS)
SCHNORR = ssa.sign(bytes(32), 1).serialize().hex()
# the same message signed by the other two keys: a stack holding several
# signatures says which key's is where only if they differ
SCHNORR_B = ssa.sign(bytes(32), 2).serialize().hex()
SCHNORR_C = ssa.sign(bytes(32), 3).serialize().hex()

MULTI = f"multi(2,{KEY_A},{KEY_B},{KEY_C})"
SORTED_MULTI = f"sortedmulti(2,{KEY_A},{KEY_B},{KEY_C})"
# the threshold the two constructions used to disagree about: one
# signature is a full satisfaction and OP_CHECKMULTISIG pops the dummy
# all the same, which the psbt finalizer decided by counting (issue #305)
MULTI_1 = f"multi(1,{KEY_A},{KEY_B},{KEY_C})"


def signatures_of(*keys: str) -> dict[Octets, Octets]:
    """Return the signature of each key, in the shape satisfy takes."""
    return {key: SIGNATURES[key] for key in keys}


# a descriptor, the keys that sign, and the descriptors of the redeem
# script and of the witness script a psbt would have to be told about --
# the two fields the finalizer dispatches on, and the ones an Updater
# built from a descriptor would fill in
FINALIZER_VECTORS = [
    pytest.param(f"pk({KEY_A})", [KEY_A], "", "", id="pk"),
    pytest.param(f"pkh({KEY_A})", [KEY_A], "", "", id="pkh"),
    pytest.param(f"wpkh({KEY_A})", [KEY_A], "", "", id="wpkh"),
    pytest.param(f"sh(wpkh({KEY_A}))", [KEY_A], f"wpkh({KEY_A})", "", id="sh-wpkh"),
    pytest.param(MULTI, [KEY_A, KEY_C], "", "", id="multi"),
    pytest.param(f"sh({MULTI})", [KEY_A, KEY_C], MULTI, "", id="sh-multi"),
    pytest.param(f"wsh({MULTI})", [KEY_A, KEY_C], "", MULTI, id="wsh-multi"),
    pytest.param(
        f"sh(wsh({MULTI}))",
        [KEY_A, KEY_C],
        f"wsh({MULTI})",
        MULTI,
        id="sh-wsh-multi",
    ),
    pytest.param(
        f"wsh({SORTED_MULTI})", [KEY_A, KEY_C], "", SORTED_MULTI, id="wsh-sortedmulti"
    ),
    pytest.param(MULTI_1, [KEY_A], "", "", id="multi-1"),
    pytest.param(f"sh({MULTI_1})", [KEY_A], MULTI_1, "", id="sh-multi-1"),
    pytest.param(f"wsh({MULTI_1})", [KEY_A], "", MULTI_1, id="wsh-multi-1"),
    pytest.param(
        f"sh(wsh({MULTI_1}))",
        [KEY_A],
        f"wsh({MULTI_1})",
        MULTI_1,
        id="sh-wsh-multi-1",
    ),
]


@pytest.mark.parametrize("descriptor, signing_keys, redeem, witness", FINALIZER_VECTORS)
def test_satisfy_matches_the_psbt_finalizer(
    descriptor: str, signing_keys: list[str], redeem: str, witness: str
) -> None:
    """The two ways btclib builds a spend agree, byte for byte.

    `finalize` assembles the same script_sig and witness from a
    psbt input carrying the same signatures, and it is the older and the
    independently tested of the two: BIP174 describes what it does, and
    what a descriptor adds is knowing the scripts and the key order
    without being told them. So the psbt is told them here -- the redeem
    script, the witness script and the output being spent -- and the two
    constructions are compared.
    """
    parsed = parse(descriptor)
    psbt_in = PsbtIn(
        witness_utxo=TxOut(1000, parsed.script_pub_key()),
        partial_sigs={
            bytes.fromhex(key): bytes.fromhex(SIGNATURES[key]) for key in signing_keys
        },
        redeem_script=parse(redeem).redeem_script() if redeem else b"",
        witness_script=parse(witness).redeem_script() if witness else b"",
    )
    assert parsed.satisfy(signatures_of(*signing_keys)) == _finalized_input(psbt_in)


def test_signatures_go_in_the_order_the_script_holds_the_keys() -> None:
    """OP_CHECKMULTISIG never goes back, so the order is not the caller's.

    The descriptor names the keys C, B, A and the mapping offers them in
    yet another order: what decides is neither, but the script -- which
    for `multi()` is the order written and for `sortedmulti()` the
    sorted one, the two being opposite here on purpose.
    """
    keys = f"{KEY_C},{KEY_B},{KEY_A}"
    signatures = signatures_of(KEY_C, KEY_A)
    ordered = parse(f"wsh(multi(2,{keys}))").satisfy(signatures)[1]
    sorted_ = parse(f"wsh(sortedmulti(2,{keys}))").satisfy(signatures)[1]
    assert ordered.stack[1:3] == (
        bytes.fromhex(SIGNATURES[KEY_C]),
        bytes.fromhex(SIGNATURES[KEY_A]),
    )
    assert sorted_.stack[1:3] == (
        bytes.fromhex(SIGNATURES[KEY_A]),
        bytes.fromhex(SIGNATURES[KEY_C]),
    )
    # the empty push BIP147 requires, both times
    assert ordered.stack[0] == sorted_.stack[0] == b""


def test_more_signatures_than_the_threshold_pops() -> None:
    """The extra ones are the other keys of the descriptor having signed."""
    witness = parse(f"wsh({MULTI})").satisfy(signatures_of(*SEC_KEYS))[1]
    # the witness script last, two signatures and the dummy before it
    assert len(witness) == 4
    assert witness.stack[1] == bytes.fromhex(SIGNATURES[KEY_A])
    assert witness.stack[2] == bytes.fromhex(SIGNATURES[KEY_B])


def test_satisfy_a_ranged_descriptor() -> None:
    """The index derives the key that has to have signed."""
    descriptor = parse(f"wpkh({XPUB}/0/*)")
    key = descriptor.key_expressions[0]
    for index in (0, 1, 2):
        signature = SIGNATURES[KEY_A]
        witness = descriptor.satisfy({key.sec(index): signature}, index)[1]
        assert witness.stack == (bytes.fromhex(signature), key.sec(index))
    # the signature of index 0 is no signature of the key at index 1
    with pytest.raises(BTClibValueError, match="no signature for public key"):
        descriptor.satisfy({key.sec(0): SIGNATURES[KEY_A]}, 1)


def test_satisfy_index_out_of_range() -> None:
    """Refuse satisfy with a negative index, or any on a fixed key."""
    with pytest.raises(BTClibValueError, match="invalid derivation index"):
        parse(f"wpkh({XPUB}/0/*)").satisfy({}, -1)
    with pytest.raises(BTClibValueError, match="not a ranged descriptor"):
        parse(f"wpkh({KEY_A})").satisfy({}, 1)


def test_satisfy_taproot_key_path() -> None:
    """One element, and the internal key is what it is filed under."""
    descriptor = parse(f"tr({XONLY_A})")
    expected = (b"", Witness([SCHNORR]))
    assert descriptor.satisfy({XONLY_A: SCHNORR}) == expected
    # the same key spelled as the 33-byte even-y SEC form answers too
    assert descriptor.satisfy({KEY_A: SCHNORR}) == expected


def test_satisfy_taproot_script_path() -> None:
    """Every leaf of an asymmetric tree, and its control block checked.

    `check_output_pubkey` is the verifier's own side of BIP341: it
    takes the output key, the leaf script and the control block, and
    walks the merkle path back to the tweak. That it answers True is
    what says the parity bit and the path are the ones this leaf needs,
    and the tree is asymmetric so that a path of one hash and a path of
    two are both exercised.
    """
    descriptor = parse(
        f"tr({XONLY_A},{{pk({XONLY_B}),{{pk({XONLY_C}),pk({XONLY_A})}}}})"
    )
    output_key = descriptor.script_pub_key().script[2:]
    for leaf_key in (XONLY_B, XONLY_C):
        script_sig, witness = descriptor.satisfy({leaf_key: SCHNORR})
        assert script_sig == b""
        signature, script, control_block = witness.stack
        assert signature == bytes.fromhex(SCHNORR)
        assert script == serialize([bytes.fromhex(leaf_key), "OP_CHECKSIG"])
        assert taproot.check_output_pubkey(output_key, script, control_block)


def test_the_taproot_key_path_is_preferred() -> None:
    """As Bitcoin Core's finalizer prefers it: the cheaper spend.

    The internal key is a leaf of this tree as well, so both paths are
    open and the answer says which was taken by its length.
    """
    descriptor = parse(f"tr({XONLY_A},pk({XONLY_A}))")
    assert descriptor.satisfy({XONLY_A: SCHNORR}) == (b"", Witness([SCHNORR]))


# a 2-of-3 `multi_a()` of the three keys above, under an internal key
# nothing here can sign with: the key path is preferred wherever it is
# open, so an internal key with no signature is what leaves the script
# path to be exercised
MULTI_A = f"tr({XONLY},multi_a(2,{XONLY_A},{XONLY_B},{XONLY_C}))"


def test_satisfy_a_multi_a_leaf() -> None:
    """One element per key, in the reverse of the order the script holds.

    OP_CHECKSIG pops the first key's signature first, so that signature is
    the last element of the witness and the top of the stack -- the
    opposite of `multi()`, where the signatures go in key order. The key
    that has not signed is the empty push, which `multi()` has nothing
    standing for at all.
    """
    script_sig, witness = parse(MULTI_A).satisfy({XONLY_A: SCHNORR, XONLY_C: SCHNORR_C})
    assert script_sig == b""
    signatures = witness.stack[:3]
    assert signatures == (bytes.fromhex(SCHNORR_C), b"", bytes.fromhex(SCHNORR))
    assert witness.stack[3] == leaf_script_of(MULTI_A)


def test_a_multi_a_signature_beyond_the_threshold_is_not_spare() -> None:
    """The third signature of a 2-of-3 becomes the empty push, not a fourth.

    Which is the other difference from `multi()`: OP_CHECKSIGADD counts
    every signature that verifies and OP_NUMEQUAL compares that count with
    the threshold, where OP_CHECKMULTISIG pops the signatures the script
    was built for and leaves the rest alone.
    """
    witness = parse(MULTI_A).satisfy(
        {XONLY_A: SCHNORR, XONLY_B: SCHNORR_B, XONLY_C: SCHNORR_C}
    )[1]
    # the three keys in reverse order, the third one's signature dropped
    assert witness.stack[:3] == (
        b"",
        bytes.fromhex(SCHNORR_B),
        bytes.fromhex(SCHNORR),
    )


def test_a_leaf_the_signatures_do_not_open_is_the_next_leaf_s_turn() -> None:
    """A tree is several spending paths, and a leaf short of one is not one.

    The 2-of-2 comes first in the tree and only one of its keys has
    signed, so what satisfies the descriptor is the `pk()` beside it. No
    error either, which is what a leaf answering "not with these
    signatures" rather than raising is for.
    """
    descriptor = parse(f"tr({XONLY},{{multi_a(2,{XONLY_A},{XONLY_B}),pk({XONLY_C})}})")
    script_sig, witness = descriptor.satisfy({XONLY_A: SCHNORR, XONLY_C: SCHNORR_C})
    assert script_sig == b""
    signature, script, _ = witness.stack
    assert signature == bytes.fromhex(SCHNORR_C)
    assert script == serialize([bytes.fromhex(XONLY_C), "OP_CHECKSIG"])


def test_a_multi_a_leaf_spends_under_the_engine() -> None:
    """The satisfaction is checked by running it, and not by its shape.

    A stack in the wrong order is a witness that looks well formed and
    that OP_CHECKSIGADD counts to something else, so the oracle here is
    btclib's own script engine: the sig_hash, the tapleaf hash, the
    control block, the two signatures and their places all have to agree
    for it to accept the spend.
    """
    descriptor = parse(MULTI_A)
    assert isinstance(descriptor, TrDescriptor)
    script_pub_key = descriptor.script_pub_key()
    prevouts = [TxOut(100_000, script_pub_key)]
    ((control_block, (script, _)),) = descriptor.taproot_leaf_scripts().items()

    vin = TxIn(OutPoint(b"\x11" * 32, 0))
    # the sig_hash of a script path spend commits to the tapleaf hash, and
    # sig_hash reads that off the witness: the leaf script and the control
    # block are the whole of the stack it looks at, so a placeholder
    # carrying them is enough to sign against
    vin.script_witness = Witness([b"", b"", b"", script, control_block])
    tx = Tx(vin=[vin], vout=[TxOut(90_000, script_pub_key)])
    msg_hash = sig_hash.from_tx(prevouts, tx, 0, sig_hash.DEFAULT)

    signatures: dict[Octets, Octets] = {
        x_only: ssa.sign_(msg_hash, prv_key).serialize()
        for x_only, prv_key in ((XONLY_A, 1), (XONLY_C, 3))
    }
    script_sig, witness = descriptor.satisfy(signatures)
    assert script_sig == b""
    tx.vin[0].script_witness = witness
    verify_transaction(prevouts, tx)


# what cannot be satisfied, and what says so. Each refusal is a
# BTClibValueError rather than the NotImplementedError the parser raises
# for miniscript: nothing a later release adds makes any of these
# spendable from the descriptor alone
UNSATISFIABLE: list[tuple[str, dict[Octets, Octets], str]] = [
    (f"pk({KEY_A})", {}, "no signature for public key"),
    (f"pkh({KEY_A})", {}, "no signature for public key"),
    (f"wpkh({KEY_A})", {}, "no signature for public key"),
    (f"sh(wpkh({KEY_A}))", {}, "no signature for public key"),
    (f"wsh({MULTI})", {KEY_A: SIGNATURES[KEY_A]}, "1 signatures of 2, missing "),
    (f"combo({KEY_A})", {KEY_A: SIGNATURES[KEY_A]}, "combo\\(\\) is four scripts"),
    ("addr(1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)", {}, "addr\\(\\) cannot be satisfied"),
    ("raw(76a914000000000000000000000000000000000000000088ac)", {}, "raw\\(\\) cannot"),
    (f"tr({XONLY_A})", {}, "no signature for the tr\\(\\) internal key"),
    (f"tr({XONLY_A},pk({XONLY_B}))", {}, "or for any of its leaves"),
    (
        f"tr({XONLY_A},multi_a(2,{XONLY_B},{XONLY_C}))",
        {XONLY_B: SCHNORR},
        "or for any of its leaves",
    ),
]


@pytest.mark.parametrize(
    "descriptor, signatures, message",
    [
        pytest.param(descriptor, signatures, message, id=vector_id(index, descriptor))
        for index, (descriptor, signatures, message) in enumerate(UNSATISFIABLE)
    ],
)
def test_unsatisfiable(
    descriptor: str, signatures: dict[Octets, Octets], message: str
) -> None:
    """Refuse each unsatisfiable descriptor with the reason named."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor).satisfy(signatures)


def test_the_missing_keys_are_named() -> None:
    """Which key has not signed is the whole content of the refusal."""
    with pytest.raises(BTClibValueError, match=f"missing {KEY_B}, {KEY_C}"):
        parse(f"wsh({MULTI})").satisfy({KEY_A: SIGNATURES[KEY_A]})


def test_only_a_script_is_embeddable() -> None:
    """The wrappers have no stack of their own to be embedded with.

    The grammar refuses `wsh(tr())` and `sh(addr())` and every other
    such pair, so this is reachable only by building the descriptor
    rather than parsing one -- which the dataclasses are public enough
    to allow.
    """
    inner = parse(f"tr({XONLY_A})")
    with pytest.raises(BTClibValueError, match="TrDescriptor is not a script"):
        WshDescriptor(inner).satisfy({XONLY_A: SCHNORR})


def psbt_spending(descriptor: Descriptor, index: int = 0) -> Psbt:
    """Return a one-input psbt spending what the descriptor describes.

    The whole previous transaction as the utxo, rather than the spent
    output alone: a witness_utxo beside a legacy input is what
    `Psbt.assert_signable` refuses as "script type not in ('p2wpkh',
    'p2wsh')", and these vectors are of every kind.
    """
    script_pub_key = descriptor.script_pub_key(index)
    prev_tx = Tx(
        vin=[TxIn(OutPoint(b"\x02" * 32, 0))], vout=[TxOut(1000, script_pub_key)]
    )
    psbt = Psbt.from_tx(
        Tx(vin=[TxIn(OutPoint(prev_tx.id, 0))], vout=[TxOut(900, script_pub_key)])
    )
    psbt.inputs[0].non_witness_utxo = prev_tx
    return psbt


@pytest.mark.parametrize("descriptor, signing_keys, redeem, witness", FINALIZER_VECTORS)
def test_the_updater_fills_what_the_finalizer_dispatches_on(
    descriptor: str, signing_keys: list[str], redeem: str, witness: str
) -> None:
    """The vectors above, with the two scripts written by the descriptor.

    Which is the whole of issue 306 for a legacy input: the test beside
    this one hands the psbt the redeem and witness scripts by parsing a
    second descriptor of each, and here nothing is handed to it. That the
    same signatures then finalize to the same spend says the fields are
    the ones the Finalizer needs, and `assert_signable` says each script
    is the one the output being spent commits to.
    """
    parsed = parse(descriptor)
    psbt = parsed.update_psbt(psbt_spending(parsed), 0)
    psbt.assert_signable()

    psbt_in = psbt.inputs[0]
    assert psbt_in.redeem_script == (parse(redeem).redeem_script() if redeem else b"")
    assert psbt_in.witness_script == (
        parse(witness).redeem_script() if witness else b""
    )
    psbt_in.partial_sigs = {
        bytes.fromhex(key): bytes.fromhex(SIGNATURES[key]) for key in signing_keys
    }
    assert parsed.satisfy(signatures_of(*signing_keys)) == _finalized_input(psbt_in)


def test_the_updater_carries_the_key_origin_of_the_derived_key() -> None:
    """The path down to the key itself, and not down to the xpub above it.

    What BIP174 carries is what a signer derives with, so the origin of
    a ranged descriptor's key is the origin written in it, the steps the
    descriptor derives, and the index -- three pieces the psbt sees as
    one path.
    """
    descriptor = parse(f"wpkh([d34db33f/84h/0h/0h]{XPUB}/0/*)")
    key = descriptor.key_expressions[0]
    for index in (0, 7):
        psbt = descriptor.update_psbt(psbt_spending(descriptor, index), 0, index)
        hd_key_paths = psbt.inputs[0].hd_key_paths
        assert list(hd_key_paths) == [key.sec(index)]
        assert (
            hd_key_paths[key.sec(index)].description == f"d34db33f/84h/0h/0h/0/{index}"
        )


def test_a_key_without_an_origin_is_skipped_rather_than_refused() -> None:
    """A descriptor may name one key as hex and the next with an origin.

    The field is keyed by public key, so what a key with nothing to say
    about where it came from costs is its own entry and not the field.
    """
    descriptor = parse(f"wsh(multi(2,[d34db33f/0h]{XPUB}/0,{KEY_B},{KEY_C}))")
    psbt = descriptor.update_psbt(psbt_spending(descriptor), 0)
    hd_key_paths = psbt.inputs[0].hd_key_paths
    assert list(hd_key_paths) == [descriptor.key_expressions[0].sec()]
    assert hd_key_paths[descriptor.key_expressions[0].sec()].description == (
        "d34db33f/0h/0"
    )


def test_the_updater_adds_to_what_the_psbt_already_carries() -> None:
    """An Updater is a role a psbt passes through, and not the first one.

    Another signer's key origin is left where it is, and the entry for a
    key this descriptor names too is this one: what the descriptor knows
    is knowledge about its own keys.
    """
    descriptor = parse(f"wsh(multi(2,[d34db33f/0h]{XPUB}/0,{KEY_B},{KEY_C}))")
    key = descriptor.key_expressions[0].sec()
    psbt = psbt_spending(descriptor)
    psbt.inputs[0].hd_key_paths = {
        bytes.fromhex(KEY_A): BIP32KeyOrigin("ffffffff", "m/1"),
        key: BIP32KeyOrigin("ffffffff", "m/2"),
    }
    hd_key_paths = descriptor.update_psbt(psbt, 0).inputs[0].hd_key_paths
    assert hd_key_paths[bytes.fromhex(KEY_A)].description == "ffffffff/1"
    assert hd_key_paths[key].description == "d34db33f/0h/0"


def test_the_updater_leaves_the_psbt_it_was_given_alone() -> None:
    """A copy, as `finalize` returns one."""
    descriptor = parse(f"sh({MULTI})")
    psbt = psbt_spending(descriptor)
    assert descriptor.update_psbt(psbt, 0).inputs[0].redeem_script
    assert not psbt.inputs[0].redeem_script


def test_the_updater_refuses_an_index_that_names_no_input() -> None:
    """An IndexError out of a public method is not an answer.

    A negative one least of all: it is the input at the other end of the
    psbt, updated with the fields of an output it does not spend.
    """
    descriptor = parse(f"wpkh({KEY_A})")
    psbt = psbt_spending(descriptor)
    for vin_i in (-1, 1):
        with pytest.raises(BTClibValueError, match="invalid input index"):
            descriptor.update_psbt(psbt, vin_i)
    with pytest.raises(BTClibValueError, match="not a ranged descriptor"):
        descriptor.update_psbt(psbt, 0, 1)


def taproot_leaf_of(psbt_in: PsbtIn, x_only: str) -> tuple[bytes, bytes]:
    """Return the leaf script a key is the whole of, and its control block."""
    return next(
        (script, control_block)
        for control_block, (script, _) in psbt_in.taproot_leaf_scripts.items()
        if script[1:-1] == bytes.fromhex(x_only)
    )


def test_the_updater_fills_the_taproot_fields() -> None:
    """The internal key, the merkle root, and every leaf of the tree.

    A control block is the field an Updater is needed for rather than
    convenient: it holds the merkle path from its leaf to the root, which
    is the whole tree seen from that leaf, so a psbt handed one leaf
    cannot work out another. `check_output_pubkey` is the verifier's own
    side of BIP341 and says each of them is the path and the parity bit
    that leaf needs.
    """
    descriptor = parse(f"tr({XONLY_A},{{pk({XONLY_B}),pk({XONLY_C})}})")
    assert isinstance(descriptor, TrDescriptor)
    psbt_in = descriptor.update_psbt(psbt_spending(descriptor), 0).inputs[0]

    assert psbt_in.taproot_internal_key == bytes.fromhex(XONLY_A)
    assert psbt_in.taproot_merkle_root == descriptor.taproot_merkle_root()
    output_key = descriptor.script_pub_key().script[2:]
    for leaf_key in (XONLY_B, XONLY_C):
        script, control_block = taproot_leaf_of(psbt_in, leaf_key)
        assert script == serialize([bytes.fromhex(leaf_key), "OP_CHECKSIG"])
        assert taproot.check_output_pubkey(output_key, script, control_block)
    # 0xc0 is the leaf version of every BIP386 tree, and what the
    # control block's first byte carries beside the parity bit
    assert {version for _, version in psbt_in.taproot_leaf_scripts.values()} == {0xC0}


def test_a_taproot_key_path_descriptor_has_no_root_and_no_leaf() -> None:
    """Which is not the same as a tree that is empty.

    `tr(KEY)` tweaks its internal key with no tree at all, and BIP371
    says so by leaving PSBT_IN_TAP_MERKLE_ROOT out.
    """
    descriptor = parse(f"tr({XONLY_A})")
    assert isinstance(descriptor, TrDescriptor)
    assert descriptor.taproot_merkle_root() == b""
    assert descriptor.taproot_leaf_scripts() == {}

    psbt_in = descriptor.update_psbt(psbt_spending(descriptor), 0).inputs[0]
    assert psbt_in.taproot_internal_key == bytes.fromhex(XONLY_A)
    assert not psbt_in.taproot_merkle_root
    assert not psbt_in.taproot_leaf_scripts


def test_a_taproot_key_origin_names_the_leaves_it_is_in() -> None:
    """BIP371 keys the field by x-only key and carries the tapleaf hashes.

    None for the internal key, which no leaf commits to, and one per leaf
    for a key in the tree. `hd_key_paths` stays empty: the same key in
    its 33-byte spelling there would be a second entry for a signer that
    signs with neither.
    """
    internal = f"[d34db33f/86h]{XPUB}/0"
    left, right = f"[aabbccdd/1]{XPUB}/1", f"[11223344/2]{XPUB}/2"
    # the left key is in two leaves, at two depths, so its two control
    # blocks are two entries of `taproot_leaf_scripts` -- and one leaf
    # hash here, the two leaves being the same script
    descriptor = parse(f"tr({internal},{{pk({left}),{{pk({right}),pk({left})}}}})")
    psbt_in = descriptor.update_psbt(psbt_spending(descriptor), 0).inputs[0]

    assert not psbt_in.hd_key_paths
    # the left key twice among the key expressions, and once here
    keys = list(dict.fromkeys(key.sec()[1:] for key in descriptor.key_expressions))
    assert len(descriptor.key_expressions) == len(keys) + 1
    assert list(psbt_in.taproot_hd_key_paths) == keys
    assert len(psbt_in.taproot_leaf_scripts) == 3
    leaf_hashes, origin = psbt_in.taproot_hd_key_paths[keys[0]]
    assert leaf_hashes == []
    assert origin.description == "d34db33f/86h/0"
    for key, description in zip(
        keys[1:], ("aabbccdd/1/1", "11223344/2/2"), strict=True
    ):
        leaf_hashes, origin = psbt_in.taproot_hd_key_paths[key]
        script = taproot_leaf_of(psbt_in, key.hex())[0]
        assert leaf_hashes == [taproot.leaf_hash(0xC0, script)]
        assert origin.description == description


def test_the_updater_names_the_leaf_a_multi_a_key_is_in() -> None:
    """A leaf commits to as many keys as it names, and BIP371 to each.

    The tapleaf hash is of the whole script, so both keys of one
    `multi_a()` name one hash and the same one: what a signer reads there
    is which scripts it has to sign for, and this is a script both of them
    have to sign. The internal key carries no origin here, so what the
    field holds is the leaf's two keys and nothing else.
    """
    left, right = f"[aabbccdd/1]{XPUB}/1", f"[11223344/2]{XPUB}/2"
    descriptor = parse(f"tr({XONLY},multi_a(2,{left},{right}))")
    assert isinstance(descriptor, TrDescriptor)
    psbt_in = descriptor.update_psbt(psbt_spending(descriptor), 0).inputs[0]

    assert psbt_in.taproot_leaf_scripts == descriptor.taproot_leaf_scripts()
    ((script, version),) = psbt_in.taproot_leaf_scripts.values()
    assert version == 0xC0
    keys = [key.sec()[1:] for key in descriptor.key_expressions[1:]]
    assert list(psbt_in.taproot_hd_key_paths) == keys
    for key, description in zip(keys, ("aabbccdd/1/1", "11223344/2/2"), strict=True):
        leaf_hashes, origin = psbt_in.taproot_hd_key_paths[key]
        assert leaf_hashes == [taproot.leaf_hash(0xC0, script)]
        assert origin.description == description


def test_a_taproot_script_path_is_finalizable_only_after_the_updater() -> None:
    """The gap issue 306 names: a psbt cannot invent a leaf script.

    The Finalizer builds the witness of a script path spend out of the
    leaf script and the control block the input carries, and until now
    nothing wrote them there from a descriptor. With them, the psbt
    finalizes to the very bytes `satisfy` builds from the same signature.
    """
    descriptor = parse(f"tr({XONLY_A},{{pk({XONLY_B}),pk({XONLY_C})}})")
    psbt = descriptor.update_psbt(psbt_spending(descriptor), 0)
    script, control_block = taproot_leaf_of(psbt.inputs[0], XONLY_B)

    # sign_ and not sign: what BIP341 signs is the hash BIP342 makes of
    # the transaction, and the Finalizer checks it with verify_
    leaf_hash = taproot.leaf_hash(0xC0, script)
    msg_hash = taproot_sig_hash(psbt, 0, leaf_hash=leaf_hash)
    signature = ssa.sign_(msg_hash, 2).serialize()
    key_data = bytes.fromhex(XONLY_B) + leaf_hash
    psbt.inputs[0].taproot_script_spend_signatures = {key_data: signature}

    witness = Witness([signature, script, control_block])
    assert finalize(psbt).inputs[0].final_script_witness == witness
    assert descriptor.satisfy({XONLY_B: signature}) == (b"", witness)

    # the same signature in a psbt the descriptor never updated: the
    # leaf it names is one that input says nothing about
    not_updated = psbt_spending(descriptor)
    not_updated.inputs[0].taproot_script_spend_signatures = {key_data: signature}
    with pytest.raises(BTClibValueError, match="no leaf script for tapleaf hash"):
        finalize(not_updated)


# what cannot update a psbt, and what says so. The three `satisfy`
# refuses as well, for reasons of their own: an Updater has nothing to
# choose between, and these have nothing to write
UNUPDATABLE = [
    (f"combo({KEY_A})", "combo\\(\\) is four scripts"),
    ("addr(1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)", "addr\\(\\) cannot update a psbt"),
    ("raw(76a914000000000000000000000000000000000000000088ac)", "raw\\(\\) cannot"),
]


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(UNUPDATABLE)
    ],
)
def test_what_cannot_update_a_psbt(descriptor: str, message: str) -> None:
    """Refuse update_psbt on combo(), addr() and raw()."""
    parsed = parse(descriptor)
    # combo() is four scripts and script_pub_key refuses to pick one, so
    # the psbt is built around the p2pkh of the same key: what is being
    # tested is the refusal, and it comes before anything reads the utxo
    psbt = psbt_spending(parse(f"pkh({KEY_A})"))
    with pytest.raises(BTClibValueError, match=message):
        parsed.update_psbt(psbt, 0)
