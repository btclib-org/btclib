#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.mnemonic.dispatch` module.

The Electrum half of the table is electrum's own, from the Test_seeds
table of `spesmilo/electrum`'s `tests/test_mnemonic.py` -- the same
sentences `electrum_test.py` measures `version_from_mnemonic` against,
here to pin that the dispatcher reports what that function reports and
does not re-decide it. The BIP39 half comes from btclib's own
`bip39_test.py` and from electrum's `Test_BIP39.test_checksum`.

Two cases are neither: the collisions. They are btclib's, found by
searching -- no upstream publishes a sentence two schemes both read --
and `electrum_test.py` says where each came from.
"""

import pytest

from btclib.mnemonic import bip39, dispatch, electrum, slip39
from tests import load

# every word in the pre-2.0 list, so electrum reads it as "old" although
# its HMAC also carries the "01" prefix of a "standard" seed. The
# precedence is the whole point of the case: "old" wins, and it wins
# inside electrum's own chain rather than by anything decided here
OLD_COLLISION = (
    "control age around curtain wall velvet limb sadness struggle orange slice yard"
)

# a valid BIP39 mnemonic that is also a "standard" electrum seed: the one
# sentence in this file that two schemes both read as valid, and so the
# one where the order between them is the answer rather than a formality
BIP39_COLLISION = (
    "park leaf system perfect top lecture rather foster best nest craft topic"
)

DISPATCH_VECTORS = [
    # the pre-2.0 scheme, which is what the dispatcher was missing
    pytest.param(
        "powerful random nobody notice nothing important anyway look away "
        "hidden message over",
        "electrum_old",
        ["electrum_old"],
        id="electrum-old",
    ),
    pytest.param(
        "cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze",
        "electrum_old",
        ["electrum_old"],
        id="electrum-old-test-seeds",
    ),
    pytest.param(
        "0123456789abcdef" * 2,
        "electrum_old",
        ["electrum_old"],
        id="electrum-old-hex",
    ),
    # the four versioned types, each also carrying the weak BIP39 answer:
    # electrum's english.txt is BIP39's, so the words are BIP39's words
    pytest.param(
        "ostrich security deer aunt climb inner alpha arm mutual marble solid task",
        "electrum_standard",
        ["electrum_standard", "bip39_wordlist"],
        id="electrum-standard",
    ),
    pytest.param(
        "frost pig brisk excite novel report camera enlist axis nation novel desert",
        "electrum_segwit",
        ["electrum_segwit", "bip39_wordlist"],
        id="electrum-segwit",
    ),
    pytest.param(
        "science dawn member doll dutch real can brick knife deny drive list",
        "electrum_2fa",
        ["electrum_2fa", "bip39_wordlist"],
        id="electrum-2fa",
    ),
    pytest.param(
        "agree install",
        "electrum_2fa_segwit",
        ["electrum_2fa_segwit", "bip39_wordlist"],
        id="electrum-2fa-segwit",
    ),
    # BIP39, checksum and all: the first is electrum's Test_BIP39 vector,
    # the second BIP39's own first vector
    pytest.param(
        "gravity machine north sort system female filter attitude volume "
        "fold club stay feature office ecology stable narrow fog",
        "bip39",
        ["bip39"],
        id="bip39-18-words",
    ),
    pytest.param(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about",
        "bip39",
        ["bip39"],
        id="bip39-12-words",
    ),
    # the same twelve words with the checksum word wrong: BIP39's list,
    # BIP39's length, and no valid reading
    pytest.param(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon",
        "bip39_wordlist",
        ["bip39_wordlist"],
        id="bip39-bad-checksum",
    ),
    # thirteen words is not a length BIP39 defines, and electrum reports
    # the same pair for it as for a failed checksum
    pytest.param(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon",
        "bip39_wordlist",
        ["bip39_wordlist"],
        id="bip39-13-words",
    ),
    pytest.param("not a seed", "", [], id="unknown"),
    pytest.param("", "", [], id="empty"),
    pytest.param("   \t\n  ", "", [], id="whitespace"),
]


@pytest.mark.parametrize(("mnemonic", "seed_type", "seed_types"), DISPATCH_VECTORS)
def test_dispatch_vectors(mnemonic: str, seed_type: str, seed_types: list[str]) -> None:
    assert dispatch.seed_type_from_mnemonic(mnemonic) == seed_type
    assert dispatch.all_seed_types_from_mnemonic(mnemonic) == seed_types


def test_old_beats_a_lucky_prefix() -> None:
    """A pre-2.0 seed wins over the version prefix it happens to carry.

    Electrum's calc_seed_type tests is_old_seed before any prefix, and
    the dispatcher inherits that by asking version_from_mnemonic rather
    than re-deciding: the sentence below hashes to "01" and would be a
    "standard" seed if the order were the other way round, deriving a
    BIP32 wallet from a seed whose keys hang off a stretched master key
    instead.
    """
    assert electrum._seed_version(OLD_COLLISION).startswith("01")
    assert dispatch.seed_type_from_mnemonic(OLD_COLLISION) == "electrum_old"
    # and it is a pre-2.0 seed that reads, not one that only looks like one
    assert electrum.hex_seed_from_old_mnemonic(OLD_COLLISION)


def test_electrum_beats_a_valid_bip39_checksum() -> None:
    """Two valid readings, and the order between them is btclib's.

    Electrum has none to copy here: its wizard asks the user which
    variant a sentence is and dispatches on the answer. Electrum first is
    the base rate -- a version prefix is a deliberate marker present by
    chance in one sentence in 256, a valid BIP39 checksum in one in
    sixteen -- and the plural function is what keeps the choice visible.
    """
    assert bip39.entropy_from_mnemonic(BIP39_COLLISION)
    assert electrum.version_from_mnemonic(BIP39_COLLISION)[0] == "standard"

    assert dispatch.seed_type_from_mnemonic(BIP39_COLLISION) == "electrum_standard"
    assert dispatch.all_seed_types_from_mnemonic(BIP39_COLLISION) == [
        "electrum_standard",
        "bip39",
    ]

    # the old collision is claimed twice as well, and by the weak BIP39
    # answer rather than a valid one: its words are BIP39 words and its
    # checksum is not a BIP39 checksum
    assert dispatch.all_seed_types_from_mnemonic(OLD_COLLISION) == [
        "electrum_old",
        "bip39_wordlist",
    ]


def test_no_normalization_of_its_own() -> None:
    """Each scheme normalizes as it defines, and the dispatcher adds nothing.

    An upper-cased sentence is an electrum seed, electrum lower-casing
    before it hashes, and is not a BIP39 mnemonic, btclib's BIP39 reader
    splitting on whitespace and nothing more. That difference belongs to
    the two schemes as they stand; what btclib should normalize, once and
    for all of them, is issue 201, and this pins the position the
    dispatcher takes until that is settled: none.
    """
    shouted = (
        "OSTRICH SECURITY DEER AUNT CLIMB INNER ALPHA ARM MUTUAL MARBLE SOLID TASK"
    )
    assert dispatch.all_seed_types_from_mnemonic(shouted) == ["electrum_standard"]

    shouted_bip39 = (
        "ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON "
        "ABANDON ABANDON ABANDON ABOUT"
    )
    assert dispatch.all_seed_types_from_mnemonic(shouted_bip39) == []

    # whitespace, on the other hand, both schemes already collapse
    spaced = "  abandon  abandon\tabandon abandon abandon abandon abandon "
    spaced += "abandon abandon abandon abandon\nabout  "
    assert dispatch.seed_type_from_mnemonic(spaced) == "bip39"


def test_italian() -> None:
    """The language reaches the BIP39 branch, and only that branch.

    Electrum's word-list is not a parameter of its version check: the
    HMAC is over the sentence, so a language btclib has and electrum does
    not still gets an electrum answer. BIP39 is where the word-list is
    consulted, and where "en" would report nothing.
    """
    mnemonic = bip39.mnemonic_from_entropy(0x0102030405060708090A0B0C0D0E0F10, "it")
    assert dispatch.seed_type_from_mnemonic(mnemonic, "it") == "bip39"
    # the same sentence against the english list: no word of it is there
    assert dispatch.all_seed_types_from_mnemonic(mnemonic, "en") == []


def test_slip39_is_not_claimed() -> None:
    """A SLIP-0039 share is reported unknown, and cannot be anything else.

    mnemonic.slip39 reads shares, and this dispatcher does not ask it:
    what a share is claimed *as* is a decision still to take, one share
    being a share of a secret rather than a sentence that derives a
    wallet by itself. What the module docstring says about the order is
    measured here -- a share carries none of the other schemes' signals,
    its words coming from SLIP-0039's own 1024-word list, so wiring it in
    at the end of the chain cannot displace an answer already given.
    """
    share = load("mnemonic", "_data", "vectors.json")[0][1][0]
    # a share slip39 does read, so that "unknown" is the dispatcher's
    # answer and not a sentence nothing at all can make sense of
    assert slip39.mnemonic_from_share(slip39.share_from_mnemonic(share)) == share
    assert dispatch.all_seed_types_from_mnemonic(share) == []
    assert dispatch.seed_type_from_mnemonic(share) == ""
