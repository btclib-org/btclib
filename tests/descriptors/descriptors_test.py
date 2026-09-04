# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.descriptors` module.

The derivation vectors are Bitcoin Core's own, transcribed from the
`descriptor_test` case of `src/test/descriptor_tests.cpp`: each
`Check(prv, pub, ...)` there gives a descriptor in its private and its
public spelling and the scriptPubKey each expands to, at index 0, 1 and 2
where the descriptor is ranged. Both spellings are exercised, so a WIF
and an xprv are checked to reach the script the public key and the xpub
beside them reach. The two ``rawtr()`` vectors are read there too, no BIP
having any.

Not vendored as files, those and BIP387's and BIP390's alike: the values
are read out of C++ source and mediawiki prose rather than copied from a
data file, so what this module cites is the path and the case, and
`tests/_data/README.md` carries the revision each is pinned to -- which
is also what the weekly upstream re-check reads.

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

from dataclasses import fields, is_dataclass
from typing import get_args

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib import b58
from btclib.alias import BIP44ScriptType, Octets
from btclib.bip32 import BIP32KeyOrigin, fingerprint
from btclib.bip32.bip32 import BIP32KeyData, derive, xpub_from_xprv
from btclib.bip32.der_path import _HARDENING
from btclib.bip44 import SCRIPT_TYPE_FROM_PURPOSE
from btclib.descriptors import (
    AddrDescriptor,
    ComboDescriptor,
    Descriptor,
    KeyExpression,
    MultiA,
    MultiDescriptor,
    PkDescriptor,
    RawDescriptor,
    RawTrDescriptor,
    ShDescriptor,
    TrDescriptor,
    WpkhDescriptor,
    WshDescriptor,
    account_descriptors,
    add_checksum,
    at_index,
    checksum,
    from_address,
    multipath_descriptors,
    normalized,
    parse,
    strip_checksum,
    wallet_policy,
    wallet_policy_address,
    wallet_policy_descriptor,
)
from btclib.descriptors.descriptors import __descsum_expand
from btclib.descriptors.miniscript import _ARITY, Miniscript
from btclib.ecc import dsa, ssa
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160, tagged_hash
from btclib.psbt.musig2 import nonce_gen, partial_sign, partial_sigs_agg
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
from tests import load, replace_unchecked, vector_id

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
    (
        "rawtr(xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/86'/1'/0'/1/*)",
        None,
        [
            ["51205172af752f057d543ce8e4a6f8dcf15548ec6be44041bfa93b72e191cfc8c1ee"],
            ["51201b66f20b86f700c945ecb9ad9b0ad1662b73084e2bfea48bee02126350b8a5b1"],
            ["512063e70f66d815218abcc2306aa930aaca07c5cde73b75127eb27b5e8c16b58a25"],
        ],
    ),
    (
        "rawtr(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
        "rawtr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        [["5120a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"]],
    ),
]

# the public spelling of the five descriptors that derive hardened: Core
# flags them HARDENED or DERIVE_HARDENED and expands the private one only
HARDENED_PUBLIC = [
    "rawtr(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/86'/1'/0'/1/*)",
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


# BIP388's own Test Vectors section (bitcoin/bips, bip-0388.mediawiki,
# commit cfff9719405fa35113cab637958809824873750f): every valid policy,
# its template, its key-information vector as descriptor text -- read the
# way `wallet_policy` hands one back, by parsing a lone `pk()` of it -- and
# the multipath descriptor the two compile to. That descriptor is what
# each vector is checked against, branch by branch, rather than restated
# as an address of its own: `multipath_descriptors` and `parse` already
# answer for what one branch is.
BIP388_VECTORS = (
    pytest.param(
        "pkh(@0/**)",
        (
            "[6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb",
        ),
        "pkh([6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb/<0;1>/*)",
        id="bip44-first-account",
    ),
    pytest.param(
        "sh(wpkh(@0/**))",
        (
            "[6738736c/49'/0'/1']xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9",
        ),
        "sh(wpkh([6738736c/49'/0'/1']xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9/<0;1>/*))",
        id="bip49-second-account",
    ),
    pytest.param(
        "wpkh(@0/**)",
        (
            "[6738736c/84'/0'/2']xpub6CRQzb8u9dmMcq5XAwwRn9gcoYCjndJkhKgD11WKzbVGd932UmrExWFxCAvRnDN3ez6ZujLmMvmLBaSWdfWVn75L83Qxu1qSX4fJNrJg2Gt",
        ),
        "wpkh([6738736c/84'/0'/2']xpub6CRQzb8u9dmMcq5XAwwRn9gcoYCjndJkhKgD11WKzbVGd932UmrExWFxCAvRnDN3ez6ZujLmMvmLBaSWdfWVn75L83Qxu1qSX4fJNrJg2Gt/<0;1>/*)",
        id="bip84-third-account",
    ),
    pytest.param(
        "tr(@0/**)",
        (
            "[6738736c/86'/0'/0']xpub6CryUDWPS28eR2cDyojB8G354izmx294BdjeSvH469Ty3o2E6Tq5VjBJCn8rWBgesvTJnyXNAJ3QpLFGuNwqFXNt3gn612raffLWfdHNkYL",
        ),
        "tr([6738736c/86'/0'/0']xpub6CryUDWPS28eR2cDyojB8G354izmx294BdjeSvH469Ty3o2E6Tq5VjBJCn8rWBgesvTJnyXNAJ3QpLFGuNwqFXNt3gn612raffLWfdHNkYL/<0;1>/*)",
        id="bip86-first-account",
    ),
    pytest.param(
        "wsh(sortedmulti(2,@0/**,@1/**))",
        (
            "[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw",
            "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7",
        ),
        "wsh(sortedmulti(2,[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw/<0;1>/*,[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7/<0;1>/*))",
        id="bip48-p2wsh-multisig",
    ),
    pytest.param(
        "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
        (
            "[6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa",
            "[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js",
            "[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2",
        ),
        "wsh(thresh(3,pk([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa/<0;1>/*),s:pk([b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js/<0;1>/*),s:pk([a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2/<0;1>/*),sln:older(12960)))",
        id="miniscript-3-of-3-degrading",
    ),
    pytest.param(
        "wsh(or_d(pk(@0/**),and_v(v:multi(2,@1/**,@2/**,@3/**),older(65535))))",
        (
            "[6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa",
            "[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js",
            "[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2",
            "[bb641298/44'/0'/0'/100']xpub6Dz8PHFmXkYkykQ83ySkruky567XtJb9N69uXScJZqweYiQn6FyieajdiyjCvWzRZ2GoLHMRE1cwDfuJZ6461YvNRGVBJNnLA35cZrQKSRJ",
        ),
        "wsh(or_d(pk([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa/<0;1>/*),and_v(v:multi(2,[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js/<0;1>/*,[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2/<0;1>/*,[bb641298/44'/0'/0'/100']xpub6Dz8PHFmXkYkykQ83ySkruky567XtJb9N69uXScJZqweYiQn6FyieajdiyjCvWzRZ2GoLHMRE1cwDfuJZ6461YvNRGVBJNnLA35cZrQKSRJ/<0;1>/*),older(65535))))",
        id="miniscript-singlesig-inheritance",
    ),
    pytest.param(
        "tr(@0/**,{sortedmulti_a(1,@0/<2;3>/*,@1/**),or_b(pk(@2/**),s:pk(@3/**))})",
        (
            "[6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa",
            "xpub6Fc2TRaCWNgfT49nRGG2G78d1dPnjhW66gEXi7oYZML7qEFN8e21b2DLDipTZZnfV6V7ivrMkvh4VbnHY2ChHTS9qM3XVLJiAgcfagYQk6K",
            "xpub6GxHB9kRdFfTqYka8tgtX9Gh3Td3A9XS8uakUGVcJ9NGZ1uLrGZrRVr67DjpMNCHprZmVmceFTY4X4wWfksy8nVwPiNvzJ5pjLxzPtpnfEM",
            "xpub6GjFUVVYewLj5no5uoNKCWuyWhQ1rKGvV8DgXBG9Uc6DvAKxt2dhrj1EZFrTNB5qxAoBkVW3wF8uCS3q1ri9fueAa6y7heFTcf27Q4gyeh6",
        ),
        "tr([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa/<0;1>/*,{sortedmulti_a(1,[6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa/<2;3>/*,xpub6Fc2TRaCWNgfT49nRGG2G78d1dPnjhW66gEXi7oYZML7qEFN8e21b2DLDipTZZnfV6V7ivrMkvh4VbnHY2ChHTS9qM3XVLJiAgcfagYQk6K/<0;1>/*),or_b(pk(xpub6GxHB9kRdFfTqYka8tgtX9Gh3Td3A9XS8uakUGVcJ9NGZ1uLrGZrRVr67DjpMNCHprZmVmceFTY4X4wWfksy8nVwPiNvzJ5pjLxzPtpnfEM/<0;1>/*),s:pk(xpub6GjFUVVYewLj5no5uoNKCWuyWhQ1rKGvV8DgXBG9Uc6DvAKxt2dhrj1EZFrTNB5qxAoBkVW3wF8uCS3q1ri9fueAa6y7heFTcf27Q4gyeh6/<0;1>/*))})",
        id="taproot-sortedmulti-a-and-miniscript-leaf",
    ),
    pytest.param(
        "tr(musig(@0,@1,@2)/**,{and_v(v:pk(musig(@0,@1)/**),older(12960)),{and_v(v:pk(musig(@0,@2)/**),older(12960)),and_v(v:pk(musig(@1,@2)/**),older(12960))}})",
        (
            "[6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa",
            "[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js",
            "[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2",
        ),
        "tr(musig([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa,[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js,[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2)/<0;1>/*,{and_v(v:pk(musig([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa,[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js)/<0;1>/*),older(12960)),{and_v(v:pk(musig([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa,[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2)/<0;1>/*),older(12960)),and_v(v:pk(musig([b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js,[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2)/<0;1>/*),older(12960))}})",
        id="taproot-musig2-with-recovery-paths",
    ),
)


@pytest.mark.parametrize("template, keys, descriptor", BIP388_VECTORS)
def test_bip388_vectors(template: str, keys: tuple[str, ...], descriptor: str) -> None:
    """Reproduce every valid policy of BIP388's Test Vectors section.

    Each key-information string is a lone KEY expression, read the way
    `wallet_policy` hands one back: `pk()` is the trivial wrapper that
    parses one without a SCRIPT function of its own. Both multipath
    branches are checked, index 9 standing for "any index": what matters
    is that the descriptor and the address agree with the branch the BIP
    itself publishes, not a property special to one index.
    """
    key_info = tuple(parse(f"pk({key})").key_expressions[0] for key in keys)
    for multipath_index, branch in enumerate(multipath_descriptors(descriptor)):
        expected = parse(branch)
        resolved = wallet_policy_descriptor(template, key_info, multipath_index)
        assert str(resolved) == str(expected)
        assert resolved.script_pub_key(9) == expected.script_pub_key(9)
        address = wallet_policy_address(template, key_info, 9, multipath_index)
        assert address == expected.address(9)


def test_bip388_invalid_templates() -> None:
    """Refuse the templates BIP388's Invalid policies section lists.

    Four of the nine: a placeholder with no path following it, one with
    an explicit path in front of the wildcard, a multipath cardinality
    above two, and derivation on a ``musig()`` participant. The other
    five are not checked here -- `tests/_data/README.md` says which and
    why -- except for the one refused anyway, by `parse`'s own
    "multipath_descriptors first" rather than by anything this checks.
    """
    key = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    key_info = (parse(f"pk({key})").key_expressions[0],)
    with pytest.raises(BTClibValueError, match="not a BIP388 wallet-policy template"):
        wallet_policy_descriptor("pkh(@0)", key_info)
    with pytest.raises(BTClibValueError, match="not a BIP388 wallet-policy template"):
        wallet_policy_descriptor("pkh(@0/0/**)", key_info)
    with pytest.raises(BTClibValueError, match="not a BIP388 wallet-policy template"):
        wallet_policy_descriptor("pkh(@0/<0;1;2>/*)", key_info)
    with pytest.raises(BTClibValueError, match="musig[(][)] placeholder"):
        wallet_policy_descriptor("tr(musig(@0/**,@1/**))", (key_info[0], key_info[0]))
    # a non-KP key present: parse()'s own multipath refusal catches it,
    # the raw `<0;1>` text reaching it unconsumed rather than substituted
    non_kp = f"sh(multi(1,@0/**,{key}/<0;1>/*))"
    with pytest.raises(BTClibValueError, match="multipath_descriptors"):
        wallet_policy_descriptor(non_kp, key_info)


@pytest.mark.parametrize("template, keys, descriptor", BIP388_VECTORS)
def test_wallet_policy_reconstructs_bip388s_own_vectors(
    template: str, keys: tuple[str, ...], descriptor: str
) -> None:
    """Reconstruct every valid policy of BIP388's vectors, from a descriptor.

    BIP388's vectors read as an input to `wallet_policy` and not only as
    an output of `wallet_policy_descriptor`.

    `multipath_descriptors` splits the vector's own descriptor into the
    receive and change branches BIP389's `<0;1>` (or, for the
    sortedmulti_a() vector, `<2;3>`) always describes, and `wallet_policy`
    given both reassembles the very template and key-information vector
    the BIP publishes beside it -- byte for byte, key for key.
    """
    branch0, branch1 = multipath_descriptors(descriptor)
    recv, chg = parse(branch0), parse(branch1)
    built_template, built_key_info = wallet_policy(recv, chg)
    assert built_template == template
    expected_key_info = tuple(parse(f"pk({key})").key_expressions[0] for key in keys)
    assert built_key_info == expected_key_info


def test_wallet_policy_of_an_account_level_descriptor_agrees_with_it() -> None:
    """A policy built from a `Descriptor` derives what the descriptor does.

    Which is the property that makes a wallet policy worth having: an
    account-level descriptor -- no chain step of its own, `wallet_policy`
    refusing the more common two-chain shape (`test_wallet_policy_refuses`
    says why) -- and the policy built from it must describe the very same
    scripts, at every index, whichever multipath branch is asked for.
    """
    xpub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    other = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
    descriptor = parse(f"wsh(sortedmulti(2,[6738736c/48h/0h/0h]{xpub}/*,{other}/*))")
    template, key_info = wallet_policy(descriptor)
    assert template == "wsh(sortedmulti(2,@0/*,@1/*))"
    for index in (0, 1, 9):
        for multipath_index in (0, 1):
            resolved = wallet_policy_descriptor(template, key_info, multipath_index)
            assert resolved.script_pub_key(index) == descriptor.script_pub_key(index)
            address = wallet_policy_address(template, key_info, index, multipath_index)
            assert address == descriptor.address(index)


def test_wallet_policy_of_a_musig_descriptor_agrees_with_it() -> None:
    """A ``musig()`` aggregate numbers its participants and none for itself.

    The same agreement as the plain-key case above, over the one shape a
    plain key does not reach: the wildcard sits on the aggregate, and
    `@0`, `@1` are the participants rather than the group.
    """
    xpub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    other = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
    descriptor = parse(f"tr(musig({xpub},{other})/*)")
    template, key_info = wallet_policy(descriptor)
    assert template == "tr(musig(@0,@1)/*)"
    for index, multipath_index in ((0, 0), (0, 1), (5, 0)):
        resolved = wallet_policy_descriptor(template, key_info, multipath_index)
        assert resolved.script_pub_key(index) == descriptor.script_pub_key(index)
        address = wallet_policy_address(template, key_info, index, multipath_index)
        assert address == descriptor.address(index)


def test_wallet_policy_of_a_receive_change_pair_agrees_with_both() -> None:
    """`account_descriptors`' own pair produces BIP388's own `/**` shorthand.

    That pair -- a BIP44 account's receive and change descriptors,
    `.../0/*` and `.../1/*` -- is the shape most callers actually hold,
    and the one shape `wallet_policy(descriptor)` alone refuses
    (`test_wallet_policy_refuses_what_cannot_become_one` measures that).
    Given both, the policy answers the very scripts the two descriptors
    it was built from answer, at every index and on both branches.
    """
    xpub = "xpub6C7Mz3RXdDAhrx7ECcAg29du1qTQeFHwk1WEUz3JHCNUhZQNeGAdkUb19AZZheLWLqWL71ZEL5G93Uxpj7BXE5TxU3P9mnEaj8itk5V5n7Z"
    recv, chg = account_descriptors(xpub, "84h/0h/0h", master_fingerprint="6738736c")
    template, key_info = wallet_policy(recv, chg)
    assert template == "wpkh(@0/**)"
    for index in (0, 1, 9):
        for multipath_index, expected in ((0, recv), (1, chg)):
            resolved = wallet_policy_descriptor(template, key_info, multipath_index)
            assert resolved.script_pub_key(index) == expected.script_pub_key(index)
            address = wallet_policy_address(template, key_info, index, multipath_index)
            assert address == expected.address(index)


def test_wallet_policy_pair_refuses_what_cannot_pair() -> None:
    """Refuse a receive/change pair that is not one, and say why."""
    xpub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    other = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
    third = "xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa"
    # a different function entirely: `_skeleton` catches it before any key
    # is even looked at
    with pytest.raises(BTClibValueError, match="do not share the same structure"):
        wallet_policy(parse(f"wpkh({xpub}/0/*)"), parse(f"pkh({xpub}/1/*)"))
    # the same chain digit on both sides: no pair to pick between at all
    with pytest.raises(BTClibValueError, match="use the same chain step"):
        wallet_policy(parse(f"wpkh({xpub}/0/*)"), parse(f"wpkh({xpub}/0/*)"))
    # the same shape, a different key: not a receive and a change of one
    # account, whatever `_skeleton` cannot see about it
    with pytest.raises(BTClibValueError, match="disagree on a key"):
        wallet_policy(parse(f"wpkh({xpub}/0/*)"), parse(f"wpkh({other}/1/*)"))
    # a musig() participant that differs between the two sides
    with pytest.raises(
        BTClibValueError, match="disagree on a musig[(][)] participant:"
    ):
        wallet_policy(
            parse(f"tr(musig({xpub},{other})/0/*)"),
            parse(f"tr(musig({xpub},{third})/1/*)"),
        )
    # derivation before aggregation, on the paired side of the same check
    # `test_wallet_policy_refuses_what_cannot_become_one` makes alone
    with pytest.raises(BTClibValueError, match="derivation before aggregation"):
        wallet_policy(
            parse(f"tr(musig({xpub}/0/*,{other}/0/*))"),
            parse(f"tr(musig({xpub}/1/*,{other}/1/*))"),
        )
    # the same key at the same pair, twice: BIP388's own invalid shape,
    # `sh(multi(1,@0/**,@0/**))`, over one chain pair rather than the
    # single suffix the unpaired path is limited to -- the identical
    # pair is the one case that always shares both digits with itself
    with pytest.raises(
        BTClibValueError, match="chain digits are not disjoint from an earlier use"
    ):
        wallet_policy(
            parse(f"multi(1,{xpub}/0/*,{xpub}/0/*)"),
            parse(f"multi(1,{xpub}/1/*,{xpub}/1/*)"),
        )
    # the same key at two pairs that share one digit rather than the
    # whole pair: BIP388's own invalid-list entry 6,
    # `sh(multi(1,@0/<0;1>/*,@0/<1;2>/*))`, sharing digit 1
    with pytest.raises(
        BTClibValueError, match="chain digits are not disjoint from an earlier use"
    ):
        wallet_policy(
            parse(f"sh(multi(1,{xpub}/0/*,{xpub}/1/*))"),
            parse(f"sh(multi(1,{xpub}/1/*,{xpub}/2/*))"),
        )
    # the same participant twice inside one musig() group, on the paired
    # side of the check `test_wallet_policy_refuses_what_cannot_become_one`
    # makes alone
    with pytest.raises(BTClibValueError, match="musig\\(\\) repeats a participant"):
        wallet_policy(
            parse(f"tr(musig({xpub},{xpub})/0/*)"),
            parse(f"tr(musig({xpub},{xpub})/1/*)"),
        )
    # a receive side that is not one explicit chain step before the
    # wildcard -- the same origin and extended key stay no defense once
    # the two sides no longer agree on the shape of the step in front
    with pytest.raises(BTClibValueError, match="not a receive/change chain step"):
        wallet_policy(parse(f"wpkh({xpub}/0/0/*)"), parse(f"wpkh({xpub}/1/*)"))
    # a hardened step on either side: BIP388's `/<M;N>/*` grammar spells
    # `NUM` as "representing unhardened derivations"
    with pytest.raises(BTClibValueError, match="not a receive/change chain step"):
        wallet_policy(parse(f"wpkh({xpub}/0/*)"), parse(f"wpkh({xpub}/1h/*)"))
    with pytest.raises(BTClibValueError, match="not a receive/change chain step"):
        wallet_policy(parse(f"wpkh({xpub}/0h/*)"), parse(f"wpkh({xpub}/1h/*)"))
    # the same musig() group at the same pair, twice: the paired form of
    # the plain-key case above, over the participant set rather than one
    # key
    with pytest.raises(
        BTClibValueError, match="chain digits are not disjoint from an earlier use"
    ):
        wallet_policy(
            parse(f"tr(musig({xpub},{other})/0/*,pk(musig({xpub},{other})/0/*))"),
            parse(f"tr(musig({xpub},{other})/1/*,pk(musig({xpub},{other})/1/*))"),
        )
    # the same musig() group at two pairs sharing one digit, the musig
    # form of the sharing-one-digit case above
    with pytest.raises(
        BTClibValueError, match="chain digits are not disjoint from an earlier use"
    ):
        wallet_policy(
            parse(f"tr(musig({xpub},{other})/0/*,pk(musig({xpub},{other})/1/*))"),
            parse(f"tr(musig({xpub},{other})/1/*,pk(musig({xpub},{other})/2/*))"),
        )
    # the control: the same key at two genuinely disjoint pairs, still
    # allowed -- the sortedmulti_a() vector's own shape
    template, _ = wallet_policy(
        parse(f"wsh(multi(1,{xpub}/0/*,{xpub}/2/*))"),
        parse(f"wsh(multi(1,{xpub}/1/*,{xpub}/3/*))"),
    )
    assert template == "wsh(multi(1,@0/**,@0/<2;3>/*))"


def test_wallet_policy_refuses_what_cannot_become_one() -> None:
    """Refuse a `Descriptor` no wallet-policy template can hold, and say why."""
    xpub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    # the standard receive-or-change account descriptor: an explicit
    # chain step in front of the wildcard, which is `pkh(@0/0/**)`'s own
    # invalid shape and not the `/**` a `Descriptor` cannot spell anyway
    with pytest.raises(BTClibValueError, match="explicit derivation step"):
        wallet_policy(parse(f"wpkh({xpub}/0/*)"))
    # a fixed public key: never ranged, so it fails the wildcard check the
    # same way a hardened or absent one does, `_parse_key` giving a fixed
    # key no `wildcard` to be zero
    with pytest.raises(BTClibValueError, match="not an unhardened wildcard"):
        wallet_policy(parse(f"wpkh({KEY})"))
    # a hardened wildcard: the one step an account xpub cannot compute
    with pytest.raises(BTClibValueError, match="not an unhardened wildcard"):
        wallet_policy(parse(f"wpkh({xpub}/*h)"))
    # not ranged at all
    with pytest.raises(BTClibValueError, match="not an unhardened wildcard"):
        wallet_policy(parse(f"wpkh({xpub})"))
    # the same key twice: with no change descriptor the only suffix
    # this writes is the single `/*`, so any repeat is BIP388's own
    # invalid shape, `sh(multi(1,@0/**,@0/**))`, over that one suffix
    with pytest.raises(BTClibValueError, match="used more than once"):
        wallet_policy(parse(f"multi(1,{xpub}/*,{xpub}/*)"))
    # derivation before aggregation: BIP390 allows it, BIP388 does not
    with pytest.raises(BTClibValueError, match="derivation before aggregation"):
        wallet_policy(parse(f"tr(musig({xpub}/*,{MUSIG_XPUB_B}/*))"))
    # the same musig() group twice: the aggregate's own trailing wildcard
    # is the same collision as a plain key's, over the participant set
    # rather than over one key
    with pytest.raises(BTClibValueError, match="musig\\(\\) placeholder"):
        wallet_policy(
            parse(
                f"tr(musig({xpub},{MUSIG_XPUB_B})/*,pk(musig({xpub},{MUSIG_XPUB_B})/*))"
            )
        )
    # the same participant twice inside one musig() group: BIP388's
    # *Additional rules* forbid it whether or not the whole group repeats
    with pytest.raises(BTClibValueError, match="musig\\(\\) repeats a participant"):
        wallet_policy(parse(f"tr(musig({xpub},{xpub})/*)"))
    # a function BIP388's SCRIPT grammar does not list
    with pytest.raises(BTClibValueError, match="not a BIP388 SCRIPT expression"):
        wallet_policy(parse(f"combo({xpub}/*)"))
    with pytest.raises(BTClibValueError, match="not a BIP388 SCRIPT expression"):
        wallet_policy(parse(f"pk({xpub}/*)"))


def test_wallet_policy_descriptor_validates_its_own_input() -> None:
    """Refuse a multipath index BIP388 has no branch for, and a torn-up pair."""
    key = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    key_info = (parse(f"pk({key})").key_expressions[0],)
    with pytest.raises(BTClibValueError, match="invalid multipath index"):
        wallet_policy_descriptor("wpkh(@0/**)", key_info, multipath_index=2)
    with pytest.raises(BTClibValueError, match="key placeholder out of range"):
        wallet_policy_descriptor("wpkh(@1/**)", key_info)
    # a key-information entry that still carries its own path: not what
    # `wallet_policy` ever hands back, but a caller building one by hand
    # can still get this wrong
    ranged = parse(f"pk({key}/*)").key_expressions[0]
    with pytest.raises(BTClibValueError, match="not a bare key-information entry"):
        wallet_policy_descriptor("wpkh(@0/**)", (ranged,))
    # a leading zero: BIP388's `KI` grammar spells the index as a decimal
    # integer with none, so `@00` is not a placeholder at all and is left
    # unconsumed, the same refusal a template with no placeholder gets
    with pytest.raises(BTClibValueError, match="not a BIP388 wallet-policy template"):
        wallet_policy_descriptor("wpkh(@00/**)", key_info)
    # one placeholder resolved and one left over: `count` alone would let
    # this through, `text` still holding an unconsumed `@` is what refuses
    # it -- `test_bip388_invalid_templates`'s `pkh(@0)` exercises
    # `count == 0` without ever making `text` hold one
    pair = (key_info[0], key_info[0])
    with pytest.raises(BTClibValueError, match="not a BIP388 wallet-policy template"):
        wallet_policy_descriptor("sh(multi(1,@0/**,@1))", pair)


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
    assert not parsed.addresses()[0]


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

    for secret in (xprv, wif, str(b58.prv_key_data_from_wif(wif).q)):
        assert secret not in repr(parsed)
        assert secret not in str(vars(parsed))

    # and asking for nothing gets a descriptor with nothing in it
    assert parse(descriptor).key_expressions[0].xkey == xpub

    # the WIF was already public before this: no derivation is made from
    # it and nothing here signs, so it is reduced and not filed
    assert wif not in prv_keys.values()
    assert parsed.key_expressions[1].pub_key == b58.prv_key_data_from_wif(wif).pub.sec


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
# a second xpub, for the case where an origin agrees and a script does not
XPUB_OTHER = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
OFF_CURVE = "020000000000000000000000000000000000000000000000000000000000000005"

# BIP390's own participants: three fixed keys, the first of them also
# written as the WIF its vectors use, and two xpubs. MUSIG_A[2:] is the
# x-only spelling of the first, which two of those vectors write as a
# plain taproot key beside the musig() rather than inside it
MUSIG_A = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
MUSIG_B = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
MUSIG_C = "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66"
MUSIG_A_WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S"
MUSIG_XPUB_A = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
MUSIG_XPUB_B = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"

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
    # Core: rawtr() is top level only, and a SCRIPT function where a tree
    # leaf is expected is that same rule and not an unimplemented one
    (f"sh(rawtr({XONLY}))", "not allowed inside"),
    (f"wsh(rawtr({XONLY}))", "not allowed inside"),
    (f"tr({XONLY},rawtr({XONLY}))", "not allowed inside"),
    (f"tr({XONLY},pkh({KEY}))", "not allowed inside"),
    # inside tr() a function that is no BIP386 leaf is read as a
    # miniscript, so what answers is the language and not the table
    (f"tr({XONLY},nope({KEY}))", "unknown miniscript fragment"),
    # Core refuses a second key too, as rawtr(): only one key expected
    (f"rawtr({XONLY},{XONLY})", "takes one argument"),
    (f"rawtr({UNCOMPRESSED})", "uncompressed"),
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


def _nested_tree(depth: int) -> str:
    """Return a tr() whose only leaf sits under `depth` braces."""
    leaf = f"pk({XONLY})"
    return f"tr({XONLY}," + "{" * depth + leaf + f",{leaf}}}" * depth + ")"


def test_tr_tree_depth_is_bounded() -> None:
    """A tr() deeper than the control block can prove is refused (issue 571).

    The parser recurses once per brace, so without a bound a deep enough
    expression exhausts the interpreter stack and leaves through
    `RecursionError` -- which `btclib.exceptions` does not declare and no
    caller of `parse` catches. 1000 braces did exactly that at the
    default recursion limit.

    128 is the bound because it is `taproot.MAX_TREE_DEPTH`, i.e. Core's
    TAPROOT_CONTROL_MAX_NODE_COUNT: a leaf below it is proved by a merkle
    path the control block has no room for, so what the expression
    describes is not a spendable output. Both sides of the boundary are
    pinned here, and both were checked against Core v31.1.0's
    `getdescriptorinfo`, which takes 128, refuses 129, and phrases the
    refusal in the words this one repeats.
    """
    assert taproot.MAX_TREE_DEPTH == 128

    # the deepest tree a control block can prove, and one deeper
    parse(_nested_tree(taproot.MAX_TREE_DEPTH))
    err_msg = "tr\\(\\) supports at most 128 nesting levels"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(_nested_tree(taproot.MAX_TREE_DEPTH + 1))

    # what used to be a RecursionError, well past the interpreter's limit
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(_nested_tree(5000))


# what is a descriptor, is not implemented, and is refused by name rather
# than read wrong
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


# BIP390's own test vectors: a valid descriptor and the scriptPubKey it
# produces, three of them where the keys derive. The first two are the same
# three participants under rawtr() and tr(), so the pair says which key is
# the output key and which is tweaked into it; the last aggregates one key
# with itself, participants being allowed to repeat
BIP390_VECTORS: list[tuple[str, list[str]]] = [
    (
        f"rawtr(musig({MUSIG_A_WIF},{MUSIG_B},{MUSIG_C}))",
        ["5120789d937bade6673538f3e28d8368dda4d0512f94da44cf477a505716d26a1575"],
    ),
    (
        f"tr(musig({MUSIG_A},{MUSIG_B},{MUSIG_C}))",
        ["512079e6c3e628c9bfbce91de6b7fb28e2aec7713d377cf260ab599dcbc40e542312"],
    ),
    (
        f"rawtr(musig({MUSIG_XPUB_A},{MUSIG_XPUB_B})/0/*)",
        [
            "51209508c08832f3bb9d5e8baf8cb5cfa3669902e2f2da19acea63ff47b93faa9bfc",
            "51205ca1102663025a83dd9b5dbc214762c5a6309af00d48167d2d6483808525a298",
            "51207dbed1b89c338df6a1ae137f133a19cae6e03d481196ee6f1a5c7d1aeb56b166",
        ],
    ),
    (
        f"tr(musig({MUSIG_XPUB_A},{MUSIG_XPUB_B})/0/*,pk({MUSIG_A[2:]}))",
        [
            "51201d377b637b5c73f670f5c8a96a2c0bb0d1a682a1fca6aba91fe673501a189782",
            "51208950c83b117a6c208d5205ffefcf75b187b32512eb7f0d8577db8d9102833036",
            "5120a49a477c61df73691b77fcd563a80a15ea67bb9c75470310ce5c0f25918db60d",
        ],
    ),
    (
        f"tr({MUSIG_A[2:]},pk(musig({MUSIG_XPUB_A},{MUSIG_XPUB_B})/0/*))",
        [
            "512068983d461174afc90c26f3b2821d8a9ced9534586a756763b68371a404635cc8",
            "5120368e2d864115181bdc8bb5dc8684be8d0760d5c33315570d71a21afce4afd43e",
            "512097a1e6270b33ad85744677418bae5f59ea9136027223bc6e282c47c167b471d5",
        ],
    ),
    (
        f"tr(musig({MUSIG_XPUB_A}/1,{MUSIG_XPUB_A}/1)/2)",
        ["5120a17ceacd6422bd5ffd9f165807b254b7d68ad39f179cc4f11545a6835227e97c"],
    ),
]


@pytest.mark.parametrize(
    "descriptor, scripts",
    [
        pytest.param(descriptor, scripts, id=vector_id(index, descriptor))
        for index, (descriptor, scripts) in enumerate(BIP390_VECTORS)
    ],
)
def test_bip390_vector(descriptor: str, scripts: list[str]) -> None:
    """Reproduce BIP390's own vectors: the script at each index it lists.

    Nothing here needs the private material `parse` hands back: a
    ``musig()`` derives from xpubs and from the aggregate of them, neither
    of which can take a hardened step.
    """
    parsed = parse(descriptor)
    assert parsed.is_ranged == (len(scripts) > 1)
    for index, expected in enumerate(scripts):
        assert parsed.script_pub_key(index).script.hex() == expected


# BIP390's invalid descriptors, and what each is refused with. The first
# eight are one rule -- a musig() is a key expression of tr() and rawtr()
# and of nothing else -- and the rest are the conditions derivation from
# the aggregate key comes with
BIP390_INVALID = [
    (f"pk(musig({MUSIG_A},{MUSIG_B},{MUSIG_C}))", "only allowed in tr"),
    (f"pkh(musig({MUSIG_A},{MUSIG_B},{MUSIG_C}))", "only allowed in tr"),
    (f"wpkh(musig({MUSIG_A},{MUSIG_B},{MUSIG_C}))", "only allowed in tr"),
    (f"combo(musig({MUSIG_A},{MUSIG_B},{MUSIG_C}))", "only allowed in tr"),
    (f"sh(wpkh(musig({MUSIG_A},{MUSIG_B},{MUSIG_C})))", "only allowed in tr"),
    (f"sh(wsh(pk(musig({MUSIG_A},{MUSIG_B},{MUSIG_C}))))", "only allowed in tr"),
    (f"wsh(musig({MUSIG_A},{MUSIG_B},{MUSIG_C}))", "only allowed in tr"),
    (f"sh(musig({MUSIG_A},{MUSIG_B},{MUSIG_C}))", "only allowed in tr"),
    (
        f"tr(musig({MUSIG_A},{MUSIG_B},{MUSIG_C})/0/0)",
        "requires every participant to be extended",
    ),
    (
        f"tr(musig({MUSIG_XPUB_A}/*,{MUSIG_XPUB_B})/0/*)",
        "ranged participant and derivation",
    ),
    # BIP390 refuses a multipath musig() holding multipath participants;
    # btclib refuses the whole shape earlier and for the general reason,
    # `parse` taking one path per key and `multipath_descriptors` being
    # what expands the <a;b> steps textually, as BIP389 defines them
    (
        f"tr(musig({MUSIG_XPUB_A}/<0;1>,{MUSIG_XPUB_B})/<2;3>)",
        "multipath key expression",
    ),
    (f"tr(musig({MUSIG_XPUB_A},{MUSIG_XPUB_B})/0h/*)", "hardened derivation steps"),
    (f"tr(musig({MUSIG_XPUB_A},{MUSIG_XPUB_B})/0/*h)", "hardened wildcard"),
    (
        f"tr(musig({MUSIG_XPUB_A}/*,{MUSIG_XPUB_B}/*)/1/2)",
        "ranged participant and derivation",
    ),
    # and what BIP390 states in prose rather than listing: no nesting, no
    # origin in front of one, and at least one participant. A musig() as a
    # tree leaf is refused too: what a leaf holds is a script
    (f"tr(musig(musig({MUSIG_A},{MUSIG_B}),{MUSIG_XPUB_A}))", "only allowed in tr"),
    (f"tr([deadbeef/0]musig({MUSIG_A},{MUSIG_B}))", "nested inside a key origin"),
    ("tr(musig())", "at least one key"),
    (f"tr({XONLY},musig({MUSIG_A},{MUSIG_B}))", "pk\\(musig\\(...\\)\\) is the leaf"),
    # a participant is aggregated as a point, so an x-only one is short of
    # the byte that says which point it is
    (f"tr(musig({XONLY},{MUSIG_B}))", "musig\\(\\): x-only"),
    # and characters after the closing bracket that are no path at all
    (f"tr(musig({MUSIG_A},{MUSIG_B})x)", "not a musig\\(\\) derivation path"),
]


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(BIP390_INVALID)
    ],
)
def test_bip390_invalid(descriptor: str, message: str) -> None:
    """Refuse each of BIP390's invalid descriptors, with the reason named."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


def test_the_order_participants_are_written_in_is_not_the_key() -> None:
    """BIP390 sorts before aggregating, and that is the whole rationale.

    MuSig2 is about a set of keys, so a descriptor written in another order
    describes the same output -- which is also what makes a descriptor
    recoverable without the order having been backed up. What is *not*
    normalized is the text: the participants are written back in the order
    they were read, as Bitcoin Core writes them.
    """
    written = f"tr(musig({MUSIG_A},{MUSIG_B},{MUSIG_C}))"
    reordered = f"tr(musig({MUSIG_C},{MUSIG_A},{MUSIG_B}))"
    assert parse(written).script_pub_key() == parse(reordered).script_pub_key()
    assert str(parse(reordered)) == reordered

    # and the aggregation order is the sorted one, which is the list BIP373
    # stores in a psbt
    keys = parse(written).key_expressions[0].participant_keys()
    assert keys == sorted(keys)
    assert [key.hex() for key in keys] == sorted((MUSIG_A, MUSIG_B, MUSIG_C))


def test_a_musig_descriptor_builds_a_psbt_its_group_can_sign() -> None:
    """The whole point of naming an aggregate key: BIP373's rounds can run.

    What the Updater has to write for that is three things, and all three
    come from the descriptor: the internal key, which is the aggregate key
    derived at this index; the participants, under the *undervied*
    aggregate key, which is what BIP373 keys its field by; and the BIP328
    path from that key to this one, under the fingerprint of the synthetic
    xpub, which is how `psbt.musig2` recognizes the derivation.

    Then the two signers play BIP373's two rounds and the Finalizer adds
    their partial signatures up. `finalize` is the oracle: it verifies the
    aggregate signature against the output key it reads out of the script,
    so it accepts only if every tweak on the way agreed.
    """
    prv_keys: dict[str, str] = {}
    descriptor = parse(f"tr(musig({XPRV_ROOT},{XPRV_SECOND})/0/*)", prv_keys=prv_keys)
    key = descriptor.key_expressions[0]
    psbt = descriptor.update_psbt_input(psbt_spending(descriptor, 1), 0, 1)
    psbt.assert_signable()

    aggregate = key.aggregate(1)
    psbt_in = psbt.inputs[0]
    assert psbt_in.taproot_internal_key == key.sec(1)[1:]
    assert psbt_in.musig2_participant_pub_keys == {aggregate: key.participant_keys(1)}
    ((leaf_hashes, origin),) = psbt_in.taproot_hd_key_paths.values()
    assert leaf_hashes == []
    assert origin.master_fingerprint == hash160(aggregate)[:4]
    assert origin.description.endswith("/0/1")

    signers = [prv_keyinfo_from_prv_key(xprv)[0] for xprv in (XPRV_ROOT, XPRV_SECOND)]
    sec_nonces = [nonce_gen(psbt, 0, signer, aggregate) for signer in signers]
    for signer, sec_nonce in zip(signers, sec_nonces, strict=True):
        partial_sign(psbt, 0, sec_nonce, signer, aggregate)
    signature = partial_sigs_agg(psbt, 0, aggregate)

    witness = finalize(psbt).inputs[0].final_script_witness
    assert witness == Witness([signature.serialize()])


def test_the_updater_writes_a_musig_group_that_derives_nothing() -> None:
    """An aggregate key that *is* the internal key has no path to report.

    Which is the first of BIP373's four ways for an aggregate key to reach
    what is spent, and the field that would say how to get from one to the
    other is left out rather than filled with an empty path. What is still
    written is the participants, and the origin of each participant that
    carries one -- the entry a signer looks itself up in.
    """
    participant = f"[d34db33f/0h]{MUSIG_XPUB_A}"
    descriptor = parse(f"tr(musig({participant},{MUSIG_XPUB_B}))")
    key = descriptor.key_expressions[0]
    psbt_in = descriptor.update_psbt_input(psbt_spending(descriptor), 0).inputs[0]

    aggregate = key.aggregate()
    assert psbt_in.taproot_internal_key == aggregate[1:]
    assert psbt_in.musig2_participant_pub_keys == {aggregate: key.participant_keys()}
    # the aggregate key is the internal key, so no derivation of it, and
    # the one entry there is is the participant that named an origin
    x_only = key.participants[0].sec()[1:]
    ((leaf_hashes, origin),) = psbt_in.taproot_hd_key_paths.values()
    assert list(psbt_in.taproot_hd_key_paths) == [x_only]
    assert leaf_hashes == []
    assert origin.description == "d34db33f/0h"


def test_the_normalized_form_of_a_musig_is_its_participants() -> None:
    """Its own path cannot harden, so there is nothing else to re-root.

    A participant with a hardened step is re-rooted as any other key is,
    and the result computes every script with no private key at all --
    which is what an export to a watch-only wallet needs, aggregate key or
    not.
    """
    prv_keys: dict[str, str] = {}
    descriptor = parse(
        f"tr(musig({XPRV_ROOT}/44h/0h/0h/0,{MUSIG_XPUB_B})/0/*)", prv_keys=prv_keys
    )
    canonical = normalized(descriptor, prv_keys)

    assert f"[{fingerprint(XPRV_ROOT).hex()}/44h/0h/0h]" in str(canonical)
    for index in (0, 5):
        assert canonical.script_pub_keys(index) == descriptor.script_pub_keys(
            index, prv_keys
        )


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
    (f"rawtr({XONLY_A})", {}, "no signature for the rawtr\\(\\) output key"),
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
    psbt = parsed.update_psbt_input(psbt_spending(parsed), 0)
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
        psbt = descriptor.update_psbt_input(psbt_spending(descriptor, index), 0, index)
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
    psbt = descriptor.update_psbt_input(psbt_spending(descriptor), 0)
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
    hd_key_paths = descriptor.update_psbt_input(psbt, 0).inputs[0].hd_key_paths
    assert hd_key_paths[bytes.fromhex(KEY_A)].description == "ffffffff/1"
    assert hd_key_paths[key].description == "d34db33f/0h/0"


def test_the_updater_leaves_the_psbt_it_was_given_alone() -> None:
    """A copy, as `finalize` returns one."""
    descriptor = parse(f"sh({MULTI})")
    psbt = psbt_spending(descriptor)
    assert descriptor.update_psbt_input(psbt, 0).inputs[0].redeem_script
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
            descriptor.update_psbt_input(psbt, vin_i)
    with pytest.raises(BTClibValueError, match="not a ranged descriptor"):
        descriptor.update_psbt_input(psbt, 0, 1)


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
    psbt_in = descriptor.update_psbt_input(psbt_spending(descriptor), 0).inputs[0]

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

    psbt_in = descriptor.update_psbt_input(psbt_spending(descriptor), 0).inputs[0]
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
    psbt_in = descriptor.update_psbt_input(psbt_spending(descriptor), 0).inputs[0]

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
    psbt_in = descriptor.update_psbt_input(psbt_spending(descriptor), 0).inputs[0]

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
    leaf script and the control block the input carries, and a
    descriptor writes them there only through the Updater. With them,
    the psbt finalizes to the very bytes `satisfy` builds from the same
    signature.
    """
    descriptor = parse(f"tr({XONLY_A},{{pk({XONLY_B}),pk({XONLY_C})}})")
    psbt = descriptor.update_psbt_input(psbt_spending(descriptor), 0)
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
    """Refuse update_psbt_input on combo(), addr() and raw()."""
    parsed = parse(descriptor)
    # combo() is four scripts and script_pub_key refuses to pick one, so
    # the psbt is built around the p2pkh of the same key: what is being
    # tested is the refusal, and it comes before anything reads the utxo
    psbt = psbt_spending(parse(f"pkh({KEY_A})"))
    with pytest.raises(BTClibValueError, match=message):
        parsed.update_psbt_input(psbt, 0)


def psbt_paying(script_pub_key: ScriptPubKey) -> Psbt:
    """Return a psbt paying somebody else at output 0 and this at output 1.

    Which is the shape change detection is about: one output is the
    payment being made and the other comes back to the wallet, and nothing
    but the script says which is which.
    """
    elsewhere = parse(f"wpkh({KEY_B})").script_pub_key()
    tx = Tx(
        vin=[TxIn(OutPoint(b"\x03" * 32, 0))],
        vout=[TxOut(500, elsewhere), TxOut(400, script_pub_key)],
    )
    return Psbt.from_tx(tx)


@pytest.mark.parametrize("descriptor, signing_keys, redeem, witness", FINALIZER_VECTORS)
def test_the_output_updater_fills_the_scripts_and_the_origins(
    descriptor: str, signing_keys: list[str], redeem: str, witness: str
) -> None:
    """The same fields as the input half, on the map an output has.

    A redeem script, a witness script and a key origin say what they say
    whether the psbt is spending the script or paying to it, so the two
    updaters share the writer -- and these are the vectors the input half
    is checked with.
    """
    parsed = parse(descriptor)
    psbt = parsed.update_psbt_output(psbt_paying(parsed.script_pub_key()), 1)
    psbt_out = psbt.outputs[1]

    assert psbt_out.redeem_script == (parse(redeem).redeem_script() if redeem else b"")
    assert psbt_out.witness_script == (
        parse(witness).redeem_script() if witness else b""
    )
    assert list(psbt_out.hd_key_paths) == list(
        parsed.update_psbt_input(psbt_spending(parsed), 0).inputs[0].hd_key_paths
    )
    # and the output the psbt pays to somebody else is left alone
    assert psbt.outputs[0] == Psbt.from_tx(psbt.tx).outputs[0]


def test_the_output_updater_refuses_an_output_it_does_not_describe() -> None:
    """The claim is "this output is mine", and the evidence is the script.

    Never the key origin: four bytes of a hash160 collide, and a psbt is
    written by whoever sends it, so an output marked as change on a
    fingerprint is one a wallet may hand to somebody else believing it
    keeps it. The refusal names the script that was paid.
    """
    descriptor = parse(f"wpkh([d34db33f/84h/0h/0h]{XPUB}/1/*)")
    psbt = psbt_paying(descriptor.script_pub_key(3))

    assert descriptor.update_psbt_output(psbt, 1, 3).outputs[1].hd_key_paths
    # output 0 pays elsewhere, and index 4 is another script of this very
    # descriptor: both are the same refusal
    with pytest.raises(BTClibValueError, match="which is not the script"):
        descriptor.update_psbt_output(psbt, 0, 3)
    with pytest.raises(BTClibValueError, match="which is not the script"):
        descriptor.update_psbt_output(psbt, 1, 4)

    # the same origin, another key: everything a fingerprint check would
    # look at agrees, and the scripts do not
    other = parse(f"wpkh([d34db33f/84h/0h/0h]{XPUB_OTHER}/1/*)")
    with pytest.raises(BTClibValueError, match="which is not the script"):
        other.update_psbt_output(psbt, 1, 3)


def test_the_output_updater_refuses_an_index_that_names_no_output() -> None:
    """An IndexError out of a public method is not an answer."""
    descriptor = parse(f"wpkh({KEY_A})")
    psbt = psbt_paying(descriptor.script_pub_key())
    for vout_i in (-1, 2):
        with pytest.raises(BTClibValueError, match="invalid output index"):
            descriptor.update_psbt_output(psbt, vout_i)
    with pytest.raises(BTClibValueError, match="not a ranged descriptor"):
        descriptor.update_psbt_output(psbt, 1, 1)


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(UNUPDATABLE)
    ],
)
def test_what_cannot_update_an_output(descriptor: str, message: str) -> None:
    """combo(), addr() and raw() have nothing to write into an output either.

    The refusal comes from the same method the input half calls, which is
    the point of there being one: what a fragment knows does not depend on
    which side of the transaction is asking.
    """
    parsed = parse(descriptor)
    # the psbt pays to a script of this very descriptor, so what refuses
    # is the fragment and not the script check before it: combo() is the
    # one with four, and any of the four is the same index
    psbt = psbt_paying(parsed.script_pub_keys()[0])
    with pytest.raises(BTClibValueError, match=message):
        parsed.update_psbt_output(psbt, 1)


def test_index_of_answers_with_the_whole_script() -> None:
    """Which index of the descriptor pays here, None where none does.

    The search is bounded by the caller, because how far ahead of its own
    gap limit a wallet looks is a policy this module has no view on.
    """
    descriptor = parse(f"wpkh([d34db33f/84h/0h/0h]{XPUB}/1/*)")
    for index in (0, 5, 999):
        assert descriptor.index_of(descriptor.script_pub_key(index).script) == index
    assert descriptor.index_of(descriptor.script_pub_key(7).script, 6) is None
    assert descriptor.index_of(parse(f"wpkh({KEY_B})").script_pub_key().script) is None

    # an unranged descriptor has one script and answers 0 or None, the
    # bound being about a range it does not have
    fixed = parse(f"wpkh({KEY_A})")
    assert fixed.index_of(fixed.script_pub_key().script, 0) == 0
    assert fixed.index_of(parse(f"wpkh({KEY_B})").script_pub_key().script) is None

    # combo() is four scripts at one index, and any of them is that index
    combo = parse(f"combo({KEY_A})")
    for script_pub_key in combo.script_pub_keys():
        assert combo.index_of(script_pub_key.script) == 0


def test_index_of_takes_the_output_however_the_caller_holds_it() -> None:
    """The ScriptPubKey, its bytes, its hex and its address, all one index.

    The object `script_pub_key` returns is the natural thing to hand back
    to the method beside it, and the address is the question a human
    actually has.
    """
    descriptor = parse(f"wpkh([d34db33f/84h/0h/0h]{XPUB}/1/*)")
    script_pub_key = descriptor.script_pub_key(7)
    assert descriptor.index_of(script_pub_key) == 7
    assert descriptor.index_of(script_pub_key.script) == 7
    assert descriptor.index_of(script_pub_key.script.hex()) == 7
    assert descriptor.index_of(script_pub_key.address) == 7

    # somebody else's address is somebody else's, which is what None says
    other = parse(f"wpkh({KEY_B})")
    assert descriptor.index_of(other.address()) is None
    assert descriptor.index_of(other.script_pub_key()) is None

    # a script with no address is named by its bytes and by nothing else:
    # the "" that `address` answers for one names no output, and reading
    # it as the empty script would deny the wallet its own p2pk
    p2pk = parse(f"pk({KEY_A})")
    assert p2pk.index_of(p2pk.script_pub_key()) == 0
    assert p2pk.address() == ""
    with pytest.raises(BTClibValueError, match="empty script_pub_key: "):
        p2pk.index_of(p2pk.address())
    # empty bytes are the empty script, which no descriptor derives
    assert p2pk.index_of(b"") is None


def test_index_of_refuses_what_it_could_only_answer_none_for() -> None:
    """None means "not this wallet's", so a wrong type may not say it.

    A value that is neither a script nor an address compares False
    against every candidate, and the caller reads the None that falls out
    of the loop as an answer about the output.
    """
    descriptor = parse(f"wpkh([d34db33f/84h/0h/0h]{XPUB}/1/*)")
    for wrong in (7, None, [descriptor.script_pub_key().script]):
        with pytest.raises(BTClibTypeError, match="invalid script_pub_key type: "):
            descriptor.index_of(wrong)  # type: ignore[arg-type]
    # a string is the hex of a script or an address, and this one is
    # neither, so the complaint is btclib's rather than bytes.fromhex's
    with pytest.raises(BTClibValueError, match="neither a script nor an address: "):
        descriptor.index_of("not an address")


def taproot_merkle_root_of(tree: list[tuple[int, int, bytes]]) -> bytes:
    """Return the merkle root a PSBT_OUT_TAP_TREE field folds up to.

    What a reader does with the field, and the reason the field is the
    tree rather than the root: the leaves arrive depth-first, each with
    its depth, so two of the same depth in a row are siblings and fold
    into their parent. BIP341's TapBranch hash sorts the two, which is
    what makes the fold independent of the order they arrived in.
    """
    stack: list[tuple[int, bytes]] = []
    for depth, leaf_version, script in tree:
        stack.append((depth, taproot.leaf_hash(leaf_version, script)))
        while len(stack) > 1 and stack[-1][0] == stack[-2][0]:
            (depth_, right), (_, left) = stack.pop(), stack.pop()
            branch = min(left, right) + max(left, right)
            stack.append((depth_ - 1, tagged_hash(b"TapBranch", branch)))
    ((depth, root),) = stack
    assert depth == 0
    return root


def test_the_output_updater_publishes_the_whole_taproot_tree() -> None:
    """PSBT_OUT_TAP_TREE, where an input carries the one leaf it spends.

    An output has no leaf being spent, so what it publishes is every leaf
    with the depth it sits at -- and that is enough to rebuild the tree,
    which is what makes the field worth more than the merkle root an input
    carries. The check is the rebuild: fold the leaves back up, tweak the
    internal key with the root, and land on the output key the psbt pays.
    """
    descriptor = parse(
        f"tr({XONLY_A},{{pk({XONLY_B}),{{pk({XONLY_C}),multi_a(1,{XONLY_A})}}}})"
    )
    assert isinstance(descriptor, TrDescriptor)
    psbt_out = descriptor.update_psbt_output(
        psbt_paying(descriptor.script_pub_key()), 1
    ).outputs[1]

    assert psbt_out.taproot_internal_key == bytes.fromhex(XONLY_A)
    assert [depth for depth, _, _ in psbt_out.taproot_tree] == [1, 2, 2]
    assert {version for _, version, _ in psbt_out.taproot_tree} == {0xC0}
    assert [script for _, _, script in psbt_out.taproot_tree] == [
        serialize([bytes.fromhex(XONLY_B), "OP_CHECKSIG"]),
        serialize([bytes.fromhex(XONLY_C), "OP_CHECKSIG"]),
        serialize([bytes.fromhex(XONLY_A), "OP_CHECKSIG", "OP_1", "OP_NUMEQUAL"]),
    ]

    root = taproot_merkle_root_of(psbt_out.taproot_tree)
    assert root == descriptor.taproot_merkle_root()
    output_key = taproot.output_pubkey_from_merkle_root(
        psbt_out.taproot_internal_key, root
    )[0]
    assert output_key == descriptor.script_pub_key().script[2:]

    # what an output does not carry: the merkle root is the fold of the
    # tree and would be the same fact twice, and there is no leaf being
    # spent, so no control block either
    assert not hasattr(psbt_out, "taproot_merkle_root")
    assert not hasattr(psbt_out, "taproot_leaf_scripts")


def test_a_taproot_output_with_no_tree_publishes_none() -> None:
    """`tr(KEY)` commits to no script, and BIP371 leaves the field out."""
    descriptor = parse(f"tr({XONLY_A})")
    assert isinstance(descriptor, TrDescriptor)
    assert descriptor.taproot_tree() == []

    psbt_out = descriptor.update_psbt_output(
        psbt_paying(descriptor.script_pub_key()), 1
    ).outputs[1]
    assert psbt_out.taproot_internal_key == bytes.fromhex(XONLY_A)
    assert not psbt_out.taproot_tree


def test_the_output_updater_names_a_musig_group() -> None:
    """BIP373 asks for the participants on an output too, for change.

    A wallet reading a psbt it did not build finds out that an output
    comes back to a group it is in, which is the same question the input
    field answers on the way out.
    """
    descriptor = parse(f"tr(musig({MUSIG_XPUB_A},{MUSIG_XPUB_B})/0/*)")
    key = descriptor.key_expressions[0]
    psbt_out = descriptor.update_psbt_output(
        psbt_paying(descriptor.script_pub_key(2)), 1, 2
    ).outputs[1]

    aggregate = key.aggregate(2)
    assert psbt_out.musig2_participant_pub_keys == {aggregate: key.participant_keys(2)}
    assert psbt_out.taproot_internal_key == key.sec(2)[1:]
    ((leaf_hashes, origin),) = psbt_out.taproot_hd_key_paths.values()
    assert leaf_hashes == []
    assert origin.master_fingerprint == hash160(aggregate)[:4]


ROUND_TRIP = [
    *(d for private, public, _ in CORE_VECTORS for d in (private, public) if d),
    *(descriptor for descriptor, _ in BIP387_VECTORS),
    *(descriptor for descriptor, _ in BIP390_VECTORS),
    *DOC_DESCRIPTORS,
    *HARDENED_PUBLIC,
]


@pytest.mark.parametrize(
    "descriptor",
    [
        pytest.param(descriptor, id=vector_id(index, descriptor))
        for index, descriptor in enumerate(ROUND_TRIP)
    ],
)
def test_a_descriptor_writes_itself_back(descriptor: str) -> None:
    """Every descriptor the suite reads is written back and read again.

    Writing is idempotent, and what it writes parses to the same scripts:
    the text may differ from the input, `parse` keeping the meaning and
    not the characters, but it cannot differ from itself.
    """
    prv_keys: dict[str, str] = {}
    parsed = parse(descriptor, prv_keys=prv_keys)
    text = str(parsed)

    assert "#" not in text
    assert str(parse(text)) == text
    assert add_checksum(text) == add_checksum(str(parse(add_checksum(text))))

    reparsed = parse(text)
    assert reparsed.is_ranged == parsed.is_ranged
    # HARDENED_PUBLIC is the corpus that derives nothing, by construction
    if descriptor not in HARDENED_PUBLIC:
        assert reparsed.script_pub_keys(0, prv_keys) == parsed.script_pub_keys(
            0, prv_keys
        )


def test_what_writing_a_descriptor_normalizes() -> None:
    """Two spellings are not echoed back, and one that could be is.

    A WIF and an xprv are gone by the time there is anything to write:
    the first was reduced to its public key on the way in and the second
    neutered. Bitcoin Core writes the same, `ToString` holding the public
    key alone. The hardening symbol is the one that *is* echoed, being
    the one whose two spellings are two checksums.
    """
    wif = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"
    pub_key = b58.prv_key_data_from_wif(wif).pub.sec.hex()
    assert str(parse(f"pkh({wif})")) == f"pkh({pub_key})"
    assert str(parse(f"pkh({pub_key.upper()})")) == f"pkh({pub_key})"

    xprv = (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
        "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    )
    xpub = xpub_from_xprv(xprv)
    assert str(parse(f"wpkh({xprv}/0/*)")) == f"wpkh({xpub}/0/*)"

    aitches = f"wpkh([deadbeef/84h]{xpub}/1h/*h)"
    apostrophes = f"wpkh([deadbeef/84']{xpub}/1'/*')"
    assert str(parse(aitches)) == aitches
    assert str(parse(apostrophes)) == apostrophes
    # which matters because the two spellings are two descriptors: one
    # meaning, two strings, two checksums
    assert checksum(aitches) != checksum(apostrophes)


def test_every_fragment_writes_its_own_function() -> None:
    """One case per grammar function, the nested ones included."""
    xonly = XONLY
    written = [
        f"pk({KEY})",
        f"pkh({KEY})",
        f"wpkh({KEY})",
        f"combo({KEY})",
        f"sh(wpkh({KEY}))",
        f"wsh(pk({KEY}))",
        f"sh(wsh(pk({KEY})))",
        f"multi(1,{KEY})",
        f"sortedmulti(2,{KEY},{KEY_B})",
        f"tr({xonly})",
        f"tr({xonly},pk({xonly}))",
        f"tr({xonly},{{pk({xonly}),pk({KEY_B})}})",
        f"tr({xonly},multi_a(1,{xonly}))",
        f"tr({xonly},{{sortedmulti_a(2,{xonly},{KEY_B}),pk({KEY_C})}})",
        f"rawtr({xonly})",
        "addr(1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)",
        "raw(76a914f8c62e9b7c0e7e1e6e3f0e2c1e6e6a0e6e6e6e6e88ac)",
    ]
    for descriptor in written:
        assert str(parse(descriptor)) == descriptor


def test_a_wif_in_a_taproot_position_is_written_x_only() -> None:
    """A private key has no spelling of its own, so the position decides.

    Bitcoin Core writes the same and says so with one bool per key: a hex
    key carries whether it was written in 32 bytes, a WIF carries whether
    it sits where only 32 are written. Its own ``tr()`` and ``rawtr()``
    vectors are what pin it -- the WIF below is the one they use, and it
    comes back in 32 bytes there and in 33 everywhere else.
    """
    assert str(parse(f"tr({WIF})")) == f"tr({XONLY})"
    assert str(parse(f"rawtr({WIF})")) == f"rawtr({XONLY})"
    assert str(parse(f"tr({XONLY},pk({WIF}))")) == f"tr({XONLY},pk({XONLY}))"
    assert str(parse(f"tr({XONLY},multi_a(1,{WIF}))")) == (
        f"tr({XONLY},multi_a(1,{XONLY}))"
    )
    assert str(parse(f"wpkh({WIF})")) == f"wpkh({KEY})"


XPRV_ROOT = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
    "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)
# a second one, so that a MuSig2 group of two has two keys to hold
XPRV_SECOND = (
    "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWP"
    "rS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
)


def test_the_normalized_form_derives_from_an_xpub_alone() -> None:
    """The point of it: a hardened descriptor a watch-only wallet can use.

    The extended key becomes the xpub at the last hardened step and the
    hardened prefix moves into the origin, so every script the descriptor
    describes is computable with no private key at all -- which is what
    `getdescriptorinfo` answers with and what an export wants.
    """
    for descriptor in (
        f"wpkh({XPRV_ROOT}/44h/0h/0h/0/*)",
        f"wpkh([deadbeef/84h]{XPRV_ROOT}/0h/1/*)",
        f"sh(wsh(multi(1,{XPRV_ROOT}/1h/2,{XPRV_ROOT}/3/4)))",
        f"tr({XPRV_ROOT}/86h/0h/0h/0/*)",
        f"tr({XPRV_ROOT}/1h/0,multi_a(1,{XPRV_ROOT}/2h/0))",
    ):
        prv_keys: dict[str, str] = {}
        parsed = parse(descriptor, prv_keys=prv_keys)
        canonical = normalized(parsed, prv_keys)

        for index in (0, 5):
            if index and not parsed.is_ranged:
                continue
            # no prv_keys at all on the normalized side: that is the claim
            assert canonical.script_pub_keys(index) == parsed.script_pub_keys(
                index, prv_keys
            )
        # and it is a descriptor, so it writes itself back and parses again
        assert str(parse(str(canonical))) == str(canonical)


def test_what_the_normalized_form_leaves_alone() -> None:
    """Three keys have no hardened step to re-root at, and one cannot."""
    xpub = xpub_from_xprv(XPRV_ROOT)

    # a path that hardens nothing, and a key that is not extended
    for descriptor in (f"wpkh({xpub}/0/1/*)", f"pk({KEY})"):
        assert str(normalized(parse(descriptor))) == descriptor

    # a hardened wildcard: the step that needs the private key is the one
    # taken at every index, so there is no point to re-root to. Bitcoin
    # Core's first branch, and for the same reason
    hardened_range = f"wpkh({xpub}/0/*h)"
    assert str(normalized(parse(hardened_range))) == hardened_range

    # the symbol is h throughout, whichever was read: a normalized
    # descriptor is a canonical spelling and not the one that came in
    assert str(normalized(parse(f"wpkh({xpub}/0/*')"))) == f"wpkh({xpub}/0/*h)"
    prv_keys: dict[str, str] = {}
    apostrophes = parse(f"wpkh([deadbeef/84']{XPRV_ROOT}/0'/1/*)", prv_keys=prv_keys)
    assert "'" not in str(normalized(apostrophes, prv_keys))


def test_normalizing_without_the_key_says_so() -> None:
    """A hardened step and no private key is refused, not quietly kept."""
    xpub = xpub_from_xprv(XPRV_ROOT)
    err_msg = "no private key to normalize the hardened derivation"
    with pytest.raises(BTClibValueError, match=err_msg):
        normalized(parse(f"wpkh({xpub}/0h/1/*)"))

    # and the mapping has to name this key, not merely be non-empty
    with pytest.raises(BTClibValueError, match=err_msg):
        normalized(parse(f"wpkh({xpub}/0h/1/*)"), {"somebody-else": XPRV_ROOT})


def test_the_three_spellings_of_core_s_rawtr_vector() -> None:
    """Core gives that vector in three forms, and each is a different answer.

    The private one is what is read, the public one is `ToString` -- the
    xprv neutered and the apostrophes echoed -- and the third is
    `ToNormalizedString`, the xpub at the last hardened step with the
    hardened prefix moved into the key origin. The scripts are checked by
    `test_core_derivation_vector`, which reads the same vector; what is
    checked here is the text, `rawtr()` being a function whose only oracle
    is Core.
    """
    private = "rawtr(xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/86'/1'/0'/1/*)"
    public = "rawtr(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/86'/1'/0'/1/*)"
    canonical = "rawtr([5a61ff8e/86h/1h/0h]xpub6DtZpc9PRL2B6pwoNGysmHAaBofDmWv5S6KQEKKGPKhf5fV62ywDtSziSApYVK3JnYY5KUSgiCwiXW5wtd8z7LNBxT9Mu5sEro8itdGfTeA/1/*)"
    # Core's own checksums, which is the whole descriptor being compared
    assert add_checksum(private) == f"{private}#a5gn3t7k"
    assert add_checksum(public) == f"{public}#4ur3xhft"
    assert add_checksum(canonical) == f"{canonical}#vwgx7hj9"

    prv_keys: dict[str, str] = {}
    parsed = parse(private, prv_keys=prv_keys)
    assert str(parsed) == public
    assert str(normalized(parsed, prv_keys)) == canonical


def test_a_rawtr_key_is_the_output_key_and_a_tr_key_is_not() -> None:
    """The whole difference between the two functions, in one comparison.

    ``rawtr(KEY)`` writes the key into ``OP_1 <32 bytes>`` as it is, where
    ``tr(KEY)`` tweaks it with an empty merkle root: same key, two
    scripts, two addresses. Which is also why a `RawTrDescriptor` is not
    a `TrDescriptor` carrying no tree.
    """
    raw_tr = parse(f"rawtr({XONLY_A})")
    assert isinstance(raw_tr, RawTrDescriptor)
    assert raw_tr.script_pub_key().script == serialize(["OP_1", bytes.fromhex(XONLY_A)])
    assert raw_tr.script_pub_key().script[2:] == bytes.fromhex(XONLY_A)

    # the even-y SEC form of the same key, which is what a KeyExpression
    # holds an x-only one as and what the tweak is computed from
    sec = bytes.fromhex(f"02{XONLY_A}")
    tweaked = parse(f"tr({XONLY_A})")
    assert tweaked.script_pub_key().script[2:] == taproot.output_pubkey(sec)[0]
    assert raw_tr.script_pub_key() != tweaked.script_pub_key()


def test_a_rawtr_spend_is_the_untweaked_key_path() -> None:
    """A signature by the key as written, which the engine is the oracle for.

    The signer must not tweak what it holds -- the opposite of a ``tr()``
    key path spend, where the signature the output key verifies is made by
    a signer that tweaked the internal key. `psbt.finalize` verifies
    against the output key it reads out of the script, so the same
    signature finalizes the psbt to the same witness `satisfy` builds.
    """
    descriptor = parse(f"rawtr({XONLY_A})")
    script_pub_key = descriptor.script_pub_key()
    prevouts = [TxOut(100_000, script_pub_key)]
    tx = Tx(
        vin=[TxIn(OutPoint(b"\x11" * 32, 0))],
        vout=[TxOut(90_000, script_pub_key)],
    )
    # a key path witness is one element and the hash does not commit to
    # it, so a placeholder of the right shape is what there is to sign
    # against: sig_hash reads the stack to tell the two paths apart
    tx.vin[0].script_witness = Witness([b"\x00" * 64])
    msg_hash = sig_hash.from_tx(prevouts, tx, 0, sig_hash.DEFAULT)
    # key 1 is XONLY_A itself, signing with no tweak at all
    signature = ssa.sign_(msg_hash, 1).serialize()

    script_sig, witness = descriptor.satisfy({XONLY_A: signature})
    assert script_sig == b""
    assert witness == Witness([signature])
    tx.vin[0].script_witness = witness
    verify_transaction(prevouts, tx)

    psbt = descriptor.update_psbt_input(psbt_spending(descriptor), 0)
    psbt.assert_signable()
    psbt.inputs[0].taproot_key_spend_signature = ssa.sign_(
        taproot_sig_hash(psbt, 0), 1
    ).serialize()
    assert finalize(psbt).inputs[0].final_script_witness == Witness(
        [psbt.inputs[0].taproot_key_spend_signature]
    )


def test_the_updater_writes_one_taproot_field_for_a_rawtr() -> None:
    """The derivation, and none of the other three.

    PSBT_IN_TAP_INTERNAL_KEY names the key a verifier tweaks and a
    ``rawtr()`` has none, so it has no merkle root and no leaf script
    either; what it does have is a key with an origin, keyed by the 32
    bytes the script holds. `hd_key_paths` stays empty for the reason it
    does under a ``tr()``: the same key in its 33-byte spelling would be a
    second entry for a signer that signs with neither.
    """
    descriptor = parse(f"rawtr([d34db33f/86h/0h/0h]{XPUB}/0/*)")
    key = descriptor.key_expressions[0]
    psbt_in = descriptor.update_psbt_input(psbt_spending(descriptor, 3), 0, 3).inputs[0]

    assert not psbt_in.hd_key_paths
    assert not psbt_in.taproot_internal_key
    assert not psbt_in.taproot_merkle_root
    assert not psbt_in.taproot_leaf_scripts
    leaf_hashes, origin = psbt_in.taproot_hd_key_paths[key.sec(3)[1:]]
    assert leaf_hashes == []
    assert origin.description == "d34db33f/86h/0h/0h/0/3"


def test_a_rawtr_without_an_origin_writes_nothing_at_all() -> None:
    """There is no other field of it to fill, so the input is left as it is.

    Which is not a refusal: the script an input spends is its
    script_pub_key and the psbt has that from the utxo, so a ``rawtr()``
    naming a key with no origin has told the psbt everything it knows by
    saying nothing.
    """
    descriptor = parse(f"rawtr({XONLY_A})")
    psbt = descriptor.update_psbt_input(psbt_spending(descriptor), 0)
    assert psbt.inputs[0] == psbt_spending(descriptor).inputs[0]


def test_a_descriptor_at_one_index_names_one_script() -> None:
    """The wildcard written out, which is what a reader of one script needs.

    `.../0/*` at index 5 is `.../0/5`: the same script the ranged
    descriptor describes at that index, said as a descriptor of its own —
    which is what an external signer displaying an address has to be given,
    and what Bitcoin Core's `deriveaddresses` answers the address of.
    """
    descriptor = parse(f"wpkh([d34db33f/84h/0h/0h]{XPUB}/0/*)")
    for index in (0, 5):
        fixed = at_index(descriptor, index)
        assert not fixed.is_ranged
        assert str(fixed).endswith(f"/0/{index})")
        assert fixed.script_pub_key() == descriptor.script_pub_key(index)
        assert fixed.key_expressions[0].origin == descriptor.key_expressions[0].origin
        # and it is a descriptor like any other: written back and read again
        assert parse(str(fixed)).script_pub_key() == fixed.script_pub_key()

    # a descriptor with no wildcard has one index, and comes back as it was
    unranged = parse(f"wpkh({KEY_A})")
    assert str(at_index(unranged)) == str(unranged)
    with pytest.raises(BTClibValueError, match="not a ranged descriptor"):
        at_index(unranged, 1)
    with pytest.raises(BTClibValueError, match="invalid derivation index"):
        at_index(descriptor, -1)


def test_the_index_of_a_musig_is_written_where_the_range_is() -> None:
    """Either side of the aggregation, and BIP390 forbids both at once.

    So the walk reaches the participants and the aggregate alike, and what
    comes back has no wildcard on either side.
    """
    aggregate = parse(f"tr(musig({MUSIG_XPUB_A},{MUSIG_XPUB_B})/0/*)")
    participants = parse(f"tr(musig({MUSIG_XPUB_A}/*,{MUSIG_XPUB_B}/*))")
    for descriptor in (aggregate, participants):
        fixed = at_index(descriptor, 3)
        assert not fixed.is_ranged
        assert "*" not in str(fixed)
        assert fixed.script_pub_key() == descriptor.script_pub_key(3)

    # a tree leaf is walked too, being where the other keys of a tr() are
    tree = parse(f"tr({XONLY_A},{{pk({XPUB}/0/*),multi_a(1,{XPUB}/1/*)}})")
    fixed = at_index(tree, 2)
    assert not fixed.is_ranged
    assert fixed.script_pub_key() == tree.script_pub_key(2)


# a key that is ranged and hardened at once, which is the one shape both
# functions have something to do to: `at_index` writes the index the
# wildcard stands for, `normalized` re-roots at the hardened step
RANGED_A = f"{XPRV_ROOT}/1h/0/*"
RANGED_B = f"{XPRV_ROOT}/1h/1/*"
RANGED_C = f"{XPRV_ROOT}/1h/2/*"
DIGEST_32 = "00" * 32
DIGEST_20 = "00" * 20

# every miniscript fragment there is, spread over the descriptors that
# can hold one: `multi()` is a p2wsh and `multi_a()` a tapscript, so it
# takes both contexts, and a `tr()` puts a key outside the miniscript as
# well as in it. What holds this list to "every" is the test below, which
# reads the parser's own table rather than a copy of it written here
MINISCRIPT_CORPUS = (
    f"wsh(and_v(vn:pk({RANGED_A}),older(5)))",
    f"wsh(or_d(pk({RANGED_A}),and_v(v:pkh({RANGED_B}),dv:after(500))))",
    (
        f"wsh(andor(pk({RANGED_A}),older(5),"
        f"j:and_v(v:pk({RANGED_B}),sha256({DIGEST_32}))))"
    ),
    f"wsh(thresh(2,pk({RANGED_A}),s:pk({RANGED_B}),s:pk({RANGED_C})))",
    f"wsh(and_v(v:multi(2,{RANGED_A},{RANGED_B}),hash256({DIGEST_32})))",
    f"wsh(or_b(pk({RANGED_A}),a:pk({RANGED_B})))",
    f"wsh(or_i(and_v(or_c(pk({RANGED_A}),v:pk({RANGED_B})),ripemd160({DIGEST_20})),0))",
    f"wsh(and_b(pk({RANGED_A}),a:and_v(v:pk({RANGED_B}),1)))",
    (
        f"tr({RANGED_A},{{multi_a(2,{RANGED_B},{RANGED_C}),"
        f"and_v(v:multi_a(2,{RANGED_B},{RANGED_C}),hash160({DIGEST_20}))}})"
    ),
)


def _fragments(value: object) -> set[str]:
    """Return the name of every miniscript fragment inside a descriptor.

    A walk of its dataclass fields, so that it finds a node wherever one
    sits -- under a `wsh()`, in a script tree, or nested in another
    fragment -- without being told where to look.
    """
    if isinstance(value, Miniscript):
        return {value.fragment, *_fragments(value.subs)}
    if isinstance(value, tuple):
        return {name for item in value for name in _fragments(item)}
    if is_dataclass(value) and not isinstance(value, type):
        return {
            name
            for field in fields(value)
            for name in _fragments(getattr(value, field.name))
        }
    return set()


def test_the_miniscript_corpus_covers_every_fragment() -> None:
    """The corpus is taken from the parser's table, not written beside it.

    `_ARITY` is what the parser reads a fragment name against -- thresh()
    excepted, which takes one subexpression or more and is therefore not
    in it -- so a fragment added to the language is a fragment this test
    demands a descriptor for, and the two walks below then cover it or go
    red. A list written here would have covered whatever it covered on
    the day it was written.
    """
    covered: set[str] = set()
    for descriptor in MINISCRIPT_CORPUS:
        covered |= _fragments(parse(descriptor))
    assert covered == {*_ARITY, "thresh"}


def test_the_index_is_written_into_every_miniscript_key() -> None:
    """Every key of a BIP379 expression, not the descriptor around it.

    The post-condition of `at_index` is that no wildcard is left, and a
    key inside a miniscript is a key like any other: the descriptor that
    comes back names one script, and it is the script the ranged one
    describes at that index.
    """
    for descriptor in MINISCRIPT_CORPUS:
        prv_keys: dict[str, str] = {}
        parsed = parse(descriptor, prv_keys=prv_keys)
        assert parsed.is_ranged

        fixed = at_index(parsed, 3)
        assert not fixed.is_ranged
        assert "*" not in str(fixed)
        assert fixed.script_pub_keys(0, prv_keys) == parsed.script_pub_keys(3, prv_keys)
        # and it is a descriptor like any other: written back and read again
        assert str(parse(str(fixed))) == str(fixed)


def test_the_normalized_form_re_roots_every_miniscript_key() -> None:
    """The same walk, and what it is worth is the same claim as elsewhere.

    Every key of the answer derives from an xpub, so the scripts are
    computable with no private key at all -- which for a miniscript is a
    claim `test_the_normalized_form_derives_from_an_xpub_alone` cannot
    make, its descriptors having no fragment in them.
    """
    for descriptor in MINISCRIPT_CORPUS:
        prv_keys: dict[str, str] = {}
        parsed = parse(descriptor, prv_keys=prv_keys)
        canonical = normalized(parsed, prv_keys)

        # no prv_keys at all on the normalized side: that is the claim
        assert canonical.script_pub_keys(3) == parsed.script_pub_keys(3, prv_keys)
        assert str(parse(str(canonical))) == str(canonical)


def test_normalizing_a_miniscript_without_the_key_says_so() -> None:
    """A key the walk does not reach is a key that cannot be refused.

    So the refusal is the evidence that it was visited: a hardened step
    inside a fragment and no private key for it raises, where before the
    descriptor came back quietly still needing one.
    """
    xpub = xpub_from_xprv(XPRV_ROOT)
    with pytest.raises(BTClibValueError, match="no private key to normalize"):
        normalized(parse(f"wsh(and_v(v:pk({xpub}/0h/1/*),older(5)))"))


def test_the_account_descriptor_pair() -> None:
    """One account, two chains, and one difference between them.

    BIP44 puts receiving addresses under `/0` and change under `/1`, and a
    wallet is both: what the pair says about the account -- the key origin,
    the account xpub, the wildcard, the script type the purpose means -- is
    the same on both sides, and the chain step is not. The addresses those
    descriptors describe are checked against `bip44.address_from_der_path`
    in `tests/bip44_test.py`, which holds the published vectors.
    """
    receive, change = account_descriptors(XPRV_ROOT, "m/84h/0h/0h")
    account_xpub = xpub_from_xprv(derive(XPRV_ROOT, "m/84h/0h/0h"))
    master_fingerprint = fingerprint(XPRV_ROOT).hex()

    for descriptor, chain in ((receive, 0), (change, 1)):
        assert isinstance(descriptor, WpkhDescriptor)
        assert descriptor.is_ranged
        assert descriptor.network == "mainnet"
        (key,) = descriptor.key_expressions
        assert key.xkey == account_xpub
        assert key.der_path == (chain,)
        assert key.wildcard == 0
        assert key.origin is not None
        assert key.origin.description == f"{master_fingerprint}/84h/0h/0h"
        assert str(descriptor) == (
            f"wpkh([{master_fingerprint}/84h/0h/0h]{account_xpub}/{chain}/*)"
        )

    assert receive.address(7) != change.address(7)
    # and each is a descriptor like any other: it writes itself back and
    # parses again to the same scripts
    for descriptor in (receive, change):
        assert parse(str(descriptor)).script_pub_keys(3) == descriptor.script_pub_keys(
            3
        )


def test_the_account_descriptors_of_each_purpose() -> None:
    """The purpose selects the fragment, as it selects the encoding.

    Four purposes, four shapes, and the table is checked against
    `bip44`'s own: a fifth script type would be a purpose this cannot
    build, which is a refusal rather than a guess.
    """
    for purpose, expected in (
        (44, "pkh("),
        (49, "sh(wpkh("),
        (84, "wpkh("),
        (86, "tr("),
    ):
        receive, change = account_descriptors(XPRV_ROOT, f"m/{purpose}h/0h/0h")
        assert str(receive).startswith(expected)
        assert str(change).startswith(expected)
    assert set(SCRIPT_TYPE_FROM_PURPOSE.values()) == set(get_args(BIP44ScriptType))

    # a purpose the mapping does not name is refused, and script_type is
    # the override -- BIP48 multisig, whose script type an account key does
    # not determine
    with pytest.raises(BTClibValueError, match="unknown BIP44 purpose: 48"):
        account_descriptors(XPRV_ROOT, "m/48h/0h/0h")
    overridden = account_descriptors(XPRV_ROOT, "m/48h/0h/0h", None, "p2wpkh")[0]
    assert str(overridden).startswith("wpkh(")
    with pytest.raises(BTClibValueError, match="unknown script type: p2wsh"):
        account_descriptors(XPRV_ROOT, "m/48h/0h/0h", None, "p2wsh")  # type: ignore[arg-type]


def test_an_account_descriptor_needs_a_fingerprint_it_cannot_compute() -> None:
    """The origin names the *master* key, and only the master key says so.

    A key at depth three carries its own fingerprint and its parent's, and
    neither is the master's, so an account xpub has to be told. Where the
    key is the master one it is computed instead — and a value handed in
    beside it has to agree, neither being more likely to be right.
    """
    account_xpub = xpub_from_xprv(derive(XPRV_ROOT, "m/84h/0h/0h"))
    with pytest.raises(BTClibValueError, match="no master fingerprint"):
        account_descriptors(account_xpub, "m/84h/0h/0h")

    master_fingerprint = fingerprint(XPRV_ROOT)
    told = account_descriptors(account_xpub, "m/84h/0h/0h", master_fingerprint)
    computed = account_descriptors(XPRV_ROOT, "m/84h/0h/0h")
    assert str(told[0]) == str(computed[0])
    # the same key with the fingerprint named too, which is what it is
    assert str(
        account_descriptors(XPRV_ROOT, "m/84h/0h/0h", master_fingerprint)[0]
    ) == (str(computed[0]))
    with pytest.raises(BTClibValueError, match="is not the key's own"):
        account_descriptors(XPRV_ROOT, "m/84h/0h/0h", "deadbeef")


def test_account_descriptors_validates_an_already_built_key_too() -> None:
    """The rule of #684: an object is validated as a string is.

    A string went through `BIP32KeyData.b58decode`, which validates by
    default; an already-built `BIP32KeyData` was trusted as it stood.
    """
    good = BIP32KeyData.b58decode(XPRV_ROOT)
    receive, _ = account_descriptors(good, "m/84h/0h/0h")
    assert str(receive) == str(account_descriptors(XPRV_ROOT, "m/84h/0h/0h")[0])

    bad = replace_unchecked(BIP32KeyData.b58decode(XPRV_ROOT), index=-1)
    err_msg = "invalid index: -1"
    with pytest.raises(BTClibValueError, match=err_msg):
        bad.assert_valid()
    with pytest.raises(BTClibValueError, match=err_msg):
        account_descriptors(bad, "m/84h/0h/0h")


def test_an_account_descriptor_holds_a_bip32_version() -> None:
    """A SLIP132 zpub says what the descriptor function already says.

    Same key, one spelling of it: the version bytes come back BIP32's, so
    the descriptor is one every implementation reads -- Bitcoin Core
    decodes those versions and no others -- and the script type is stated
    once, by `wpkh()`.
    """
    zprv = (
        "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPv"
        "G6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5"
    )
    receive = account_descriptors(zprv, "m/84h/0h/0h")[0]
    (key,) = receive.key_expressions
    assert key.xkey.startswith("xpub")
    # the same account key, spelled with BIP32's own private version and
    # then neutered: 0488ade4 is xprv and 0488b21e the xpub it becomes
    assert key.xkey == xpub_from_xprv(derive(zprv, "m/84h/0h/0h", b"\x04\x88\xad\xe4"))
    # and the scripts are the ones the SLIP132 spelling describes
    assert receive.address(0) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def test_an_account_path_is_three_hardened_levels() -> None:
    """What an account xpub stands for, and what the coin type has to say.

    The two levels below an account are the unhardened ones, so an account
    path is exactly as much as a wallet exports -- a fourth level is
    already a chain, and an unhardened account level would leave the level
    above it the last that needed a private key.
    """
    for der_path, err_msg in (
        ("m/84h/0h", "2 levels instead of 3"),
        ("m/84h/0h/0h/0", "4 levels instead of 3"),
        ("m/84h/0h/0", "must be hardened"),
        ("m/84/0h/0h", "must be hardened"),
    ):
        with pytest.raises(BTClibValueError, match=err_msg):
            account_descriptors(XPRV_ROOT, der_path)

    # the coin type is a claim about the chain and the key is the chain
    with pytest.raises(BTClibValueError, match="coin type 1 is test"):
        account_descriptors(XPRV_ROOT, "m/84h/1h/0h")
    with pytest.raises(BTClibValueError, match="unregistered BIP44 coin type: 2"):
        account_descriptors(XPRV_ROOT, "m/84h/2h/0h")

    # a key below the account level has walked past the path
    deeper = derive(XPRV_ROOT, "m/84h/0h/0h/0")
    with pytest.raises(BTClibValueError, match="past the 3 levels of the path"):
        account_descriptors(deeper, "m/84h/0h/0h")
    # and one at the account level has to be *that* account
    other = xpub_from_xprv(derive(XPRV_ROOT, "m/84h/0h/1h"))
    with pytest.raises(BTClibValueError, match="is not the path's 0h"):
        account_descriptors(other, "m/84h/0h/0h", "deadbeef")


def test_the_normalized_origin_keeps_the_fingerprint_that_was_given() -> None:
    """An origin already there is extended; one absent is the key's own."""
    prv_keys: dict[str, str] = {}
    given = parse(f"wpkh([deadbeef/84h]{XPRV_ROOT}/0h/1/*)", prv_keys=prv_keys)
    origin = normalized(given, prv_keys).key_expressions[0].origin
    assert origin is not None
    assert origin.description == "deadbeef/84h/0h"

    absent = parse(f"wpkh({XPRV_ROOT}/44h/0h/0h/0/*)", prv_keys=prv_keys)
    origin = normalized(absent, prv_keys).key_expressions[0].origin
    assert origin is not None
    assert origin.master_fingerprint == fingerprint(XPRV_ROOT)
    assert origin.description == f"{fingerprint(XPRV_ROOT).hex()}/44h/0h/0h"


def test_an_invalid_output_is_refused_and_not_answered_about() -> None:
    """A negative answer where a refusal belongs (issue 691).

    The worst shape a missing check can take, the answer being a negative
    rather than an error: `index_of` answered `None` for a `ScriptPubKey`
    its own `assert_valid` refuses, which is exactly what it answers about
    a perfectly good output belonging to somebody else, with nothing in the
    answer to say the question was malformed. `_script_from` stays the
    private twin that converts and does not validate;
    `_validated_script_from` beside it is what the public questions call.
    """
    descriptor = parse(f"wpkh({KEY_A})")
    assert descriptor.index_of(descriptor.script_pub_key()) == 0

    bad = ScriptPubKey(b"\x51", "notanetwork", check_validity=False)
    err_msg = "unknown network: notanetwork"
    with pytest.raises(BTClibValueError, match=err_msg):
        bad.assert_valid()
    with pytest.raises(BTClibValueError, match=err_msg):
        descriptor.index_of(bad)
