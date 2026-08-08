# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.mnemonic.dispatch` module.

The Electrum half of the table is electrum's own, from the Test_seeds
table of `spesmilo/electrum`'s `tests/test_mnemonic.py` -- the same
sentences `electrum_test.py` measures `version_from_mnemonic` against,
here to pin that the dispatcher reports what that function reports and
does not re-decide it. The BIP39 half comes from btclib's own
`bip39_test.py` and from electrum's `Test_BIP39.test_checksum`.

The SLIP-0039 half is trezor/python-shamir-mnemonic's vector file, the
same one `slip39_test.py` runs, here to pin which of its 45 cases this
dispatcher claims and which it leaves alone.

Four cases are none of the three: the collisions. They are btclib's,
found by searching -- no upstream publishes a sentence two schemes both
read -- and `electrum_test.py` says where the two Electrum/BIP39 ones
came from. The two SLIP-0039 ones were found here, one per Electrum
prefix flavour, and the comment beside them gives the rate.
"""

import pytest

from btclib.exceptions import BTClibValueError
from btclib.mnemonic import bip39, dispatch, electrum, slip39
from tests import load, vector_id

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


@pytest.mark.parametrize("mnemonic, seed_type, seed_types", DISPATCH_VECTORS)
def test_dispatch_vectors(mnemonic: str, seed_type: str, seed_types: list[str]) -> None:
    """Verify each sentence's seed type and its full candidate list."""
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


SLIP39_VECTORS = load("mnemonic", "_data", "vectors.json")

# upstream's vectors are all under this passphrase; fixture and not a
# credential, as slip39_test.py's copy of the constant also says
SLIP39_PASSPHRASE = "TREZOR"  # noqa: S105

# a share whose RS1024 checksum verifies and whose electrum HMAC also
# happens to start "01", so two schemes claim it and the order decides
# which one a caller is told. Found by search: no upstream publishes such
# a sentence, one scheme in 250 being rare enough that nobody trips over
# it and common enough that a library will. The second is the same thing
# against the "102" prefix, to pin that it is the collision and not the
# "standard" branch in particular
SLIP39_ELECTRUM_STANDARD = (
    "enemy frequent academic academic brother remember join timber "
    "detailed advocate relate together drift careful disaster elder "
    "friendly fluff fiction muscle"
)
SLIP39_ELECTRUM_2FA = (
    "move fawn academic academic champion parcel picture surprise "
    "flexible unfair fiction fantasy jacket helpful galaxy vanish "
    "listen mandate improve element"
)


@pytest.mark.parametrize(
    "share",
    [
        pytest.param(vector[1][0], id=vector_id(index, vector[0]))
        for index, vector in enumerate(SLIP39_VECTORS)
        if vector[2]
    ],
)
def test_slip39_vectors(share: str) -> None:
    """Every valid SLIP-0039 vector share is reported "slip39"."""
    assert dispatch.seed_type_from_mnemonic(share) == "slip39"


# upstream's 30 invalid vectors split in two, and the split is what
# "slip39" means. These five phrases of upstream's own descriptions name a
# fault in one sentence -- a checksum, a padding, a length, a threshold
# above its own group count; the remaining descriptions name a fault
# between sentences -- mismatching fields, duplicate indices, too few
# groups, a digest that does not check out. Classified by upstream's
# words and not by asking share_from_mnemonic, which is the function
# under test here
_PER_SHARE_FAULTS = (
    "invalid checksum",
    "invalid padding",
    "greater group threshold than group counts",
    "insufficient length",
    "invalid master secret length",
)
INVALID_SLIP39_VECTORS = [
    (index, vector, any(f in vector[0] for f in _PER_SHARE_FAULTS))
    for index, vector in enumerate(SLIP39_VECTORS)
    if not vector[2] and vector[1]
]


def test_the_invalid_vectors_split_as_described() -> None:
    """8 of the 30 are one bad sentence, 22 are a bad set of good ones.

    The counts are here so that the classification below cannot drift
    silently: a vector upstream adds, or a description it rewords, fails
    this rather than quietly joining the wrong half.
    """
    assert len(INVALID_SLIP39_VECTORS) == 30
    assert sum(per_share for _, _, per_share in INVALID_SLIP39_VECTORS) == 8


@pytest.mark.parametrize(
    "mnemonics",
    [
        pytest.param(vector[1], id=vector_id(index, vector[0]))
        for index, vector, per_share in INVALID_SLIP39_VECTORS
        if per_share
    ],
)
def test_slip39_bad_sentence_is_not_claimed(mnemonics: list[str]) -> None:
    """A fault inside one share is one this branch sees.

    share_from_mnemonic is the whole of the test -- word count, every word
    in SLIP-0039's list, RS1024 -- so a checksum, a padding or a length
    upstream calls invalid is not claimed here either. The assertion is
    over the set because these vectors carry one bad sentence among sound
    ones; what must not happen is every sentence passing.
    """
    assert not all(
        "slip39" in dispatch.all_seed_types_from_mnemonic(mnemonic)
        for mnemonic in mnemonics
    )


@pytest.mark.parametrize(
    "mnemonics",
    [
        pytest.param(vector[1], id=vector_id(index, vector[0]))
        for index, vector, per_share in INVALID_SLIP39_VECTORS
        if not per_share
    ],
)
def test_slip39_bad_set_of_good_sentences(mnemonics: list[str]) -> None:
    """Report a share as "slip39" whatever the set it belongs to.

    These 22 vectors are sets that cannot be combined -- mismatching
    fields, duplicate indices, too few groups, a digest that does not
    check out -- built from sentences that are every one of them a
    well-formed share. So each is reported "slip39" and
    master_secret_from_mnemonics is what refuses the set: a fault between
    sentences is not one a dispatcher reading a single sentence can see,
    and reporting "" for a share that is genuinely a share would be the
    wrong answer to the question actually asked.
    """
    for mnemonic in mnemonics:
        assert dispatch.seed_type_from_mnemonic(mnemonic) == "slip39"

    with pytest.raises(BTClibValueError):
        slip39.master_secret_from_mnemonics(mnemonics, SLIP39_PASSPHRASE)


@pytest.mark.parametrize(
    "share, electrum_type",
    [
        pytest.param(SLIP39_ELECTRUM_STANDARD, "electrum_standard", id="standard"),
        pytest.param(SLIP39_ELECTRUM_2FA, "electrum_2fa", id="2fa"),
    ],
)
def test_slip39_wins_over_electrum(share: str, electrum_type: str) -> None:
    """SLIP-0039 first, and this is the sentence where it matters.

    Electrum's version check is an HMAC over the sentence and consults no
    word-list, so it claims a share whenever the HMAC starts "01" or one
    of the three-nibble prefixes -- one share in 250, measured. The share
    is the rarer signal by orders of magnitude, 30 checksum bits over
    words that must every one of them be among SLIP-0039's 1024, so it is
    the answer; reporting the electrum type instead would hand back a
    wallet derived from a share of a secret.
    """
    assert slip39.mnemonic_from_share(slip39.share_from_mnemonic(share)) == share
    assert electrum.version_from_mnemonic(share)[0] == electrum_type.removeprefix(
        "electrum_"
    )
    assert dispatch.all_seed_types_from_mnemonic(share) == ["slip39", electrum_type]
    assert dispatch.seed_type_from_mnemonic(share) == "slip39"


def test_the_other_schemes_are_not_read_as_shares() -> None:
    """Going first costs the other two schemes nothing, and cannot.

    1495 of BIP39's 2048 english words are absent from SLIP-0039's list,
    so an english sentence has to be built from that list to reach the
    RS1024 checksum at all -- and 0 of 2000 electrum seeds and 0 of 2000
    BIP39 mnemonics did, measured. The two collisions above run the order
    in the direction where it bites; every sentence in the table above
    runs it in the direction where it must not, this asserting the absence
    directly rather than leaving it to the expected lists.
    """
    for param in DISPATCH_VECTORS:
        mnemonic = param.values[0]
        assert isinstance(mnemonic, str)
        assert "slip39" not in dispatch.all_seed_types_from_mnemonic(mnemonic)
