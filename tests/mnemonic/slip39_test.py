# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.mnemonic.slip39` module."""

from collections.abc import Callable

import pytest

from btclib.exceptions import BTClibValueError
from btclib.mnemonic import slip39
from btclib.mnemonic.mnemonic import WORDLISTS
from tests import load, vector_id

# the passphrase SLIP-0039 uses for every valid set of mnemonics in its
# own vectors, and the one value that makes those 15 answers
# reproducible. noqa because a passphrase a standard publishes is a
# fixture and not a credential; the name says which it is, so renaming
# it past the S105 heuristic would hide the fact rather than the finding
PASSPHRASE = "TREZOR"  # noqa: S105

_VECTORS = load("mnemonic", "_data", "vectors.json")

VECTORS = [
    pytest.param(*vector[1:], id=vector_id(index, vector[0]))
    for index, vector in enumerate(_VECTORS)
]

# the valid vectors that are a single 1-of-1 share: those are the only
# ones generation can be checked against, a share of any larger scheme
# depending on randomness the vector does not record
SINGLE_SHARE_VECTORS = [
    pytest.param(vector[1][0], vector[2], id=vector_id(index, vector[0]))
    for index, vector in enumerate(_VECTORS)
    if vector[2] and len(vector[1]) == 1
]


def fixed_identifier(identifier: int) -> Callable[[int], bytes]:
    """Return an entropy source spelling one identifier and nothing else.

    A 1-of-1 backup draws no other random byte, so this is the whole of
    what generating one needs to be deterministic.
    """
    return lambda _: identifier.to_bytes(2, byteorder="big")


class CountingSource:
    """A deterministic stand-in for os.urandom, distinct on every call.

    Not `random.Random(seed).randbytes`, which would tie the expected
    shares to the mersenne twister's stream and so to a CPython
    implementation detail; the round trip only needs bytes that differ
    between the free coefficients of one polynomial.
    """

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, n_bytes: int) -> bytes:
        """Return n_bytes bytes, distinct on every call."""
        self.calls += 1
        return bytes((self.calls * 31 + i) % 256 for i in range(n_bytes))


def test_wordlist() -> None:
    """Verify the word-list satisfies SLIP-0039's own criteria."""
    assert WORDLISTS.language_length("slip39") == 1024
    wordlist = WORDLISTS.wordlist("slip39")
    assert wordlist[0] == "academic"
    assert wordlist[1023] == "zero"
    # SLIP-0039's own criteria: 4 to 8 letters, and a unique four-letter
    # prefix, which is what lets a share be entered by its first four
    assert all(4 <= len(word) <= 8 for word in wordlist)
    assert len({word[:4] for word in wordlist}) == 1024
    # not BIP39's list, and the two must not be confused for one another
    assert set(wordlist) != set(WORDLISTS.wordlist("en"))


@pytest.mark.parametrize(("mnemonics", "master_secret", "xprv"), VECTORS)
def test_vectors(mnemonics: list[str], master_secret: str, xprv: str) -> None:
    """SLIP-0039 test vectors.

    https://github.com/trezor/python-shamir-mnemonic/blob/master/vectors.json

    The file SLIP-0039 names as its own; tests/_data/README.md pins the
    revision. An empty master secret means combining the mnemonics must
    fail, and the 30 vectors that ask for a failure are as much of the
    specification as the 15 that ask for an answer -- between them they
    cover every check the combining step is required to make.
    """
    if not master_secret:
        with pytest.raises(BTClibValueError):
            slip39.master_secret_from_mnemonics(mnemonics, PASSPHRASE)
        return

    assert slip39.master_secret_from_mnemonics(mnemonics, PASSPHRASE) == bytes.fromhex(
        master_secret
    )
    assert slip39.mxprv_from_mnemonics(mnemonics, PASSPHRASE) == xprv
    # every valid mnemonic re-encodes to itself, which is the half of
    # the format the vectors do not check on their own
    for mnemonic in mnemonics:
        share = slip39.share_from_mnemonic(mnemonic)
        assert slip39.mnemonic_from_share(share) == mnemonic


@pytest.mark.parametrize(("mnemonic", "master_secret"), SINGLE_SHARE_VECTORS)
def test_generation_vectors(mnemonic: str, master_secret: str) -> None:
    """Regenerate the 1-of-1 vectors, mnemonic for mnemonic.

    A 1-of-1 share is the encrypted master secret itself, so the answer
    is fixed by the master secret, the passphrase, the iteration
    exponent, the extendable backup flag and the identifier -- all of
    them read back out of the vector. This is generation checked against
    SLIP-0039 rather than against btclib's own recovery.
    """
    share = slip39.share_from_mnemonic(mnemonic)
    assert (share.group_index, share.group_threshold, share.group_count) == (0, 1, 1)
    assert (share.member_index, share.member_threshold) == (0, 1)

    mnemonics = slip39.mnemonics_from_master_secret(
        master_secret,
        passphrase=PASSPHRASE,
        iteration_exponent=share.iteration_exponent,
        extendable=share.extendable,
        entropy_source=fixed_identifier(share.identifier),
    )
    assert mnemonics == [[mnemonic]]


@pytest.mark.parametrize("extendable", [True, False])
def test_round_trip(extendable: bool) -> None:
    """Two groups, 2-of-3 and 3-of-5, both thresholds exercised."""
    master_secret = bytes(range(32))
    mnemonics = slip39.mnemonics_from_master_secret(
        master_secret,
        groups=[(2, 3), (3, 5)],
        group_threshold=2,
        passphrase=PASSPHRASE,
        iteration_exponent=0,
        extendable=extendable,
        entropy_source=CountingSource(),
    )
    assert [len(group) for group in mnemonics] == [3, 5]
    assert all(len(m.split()) == 33 for group in mnemonics for m in group)

    # a threshold of each group, and not the first shares of either
    shares = [mnemonics[0][0], mnemonics[0][2]]
    shares += [mnemonics[1][1], mnemonics[1][3], mnemonics[1][4]]
    assert slip39.master_secret_from_mnemonics(shares, PASSPHRASE) == master_secret

    # one group is not enough, however many of its shares are offered
    err_msg = "1 groups, group threshold is 2"
    with pytest.raises(BTClibValueError, match=err_msg):
        slip39.master_secret_from_mnemonics(mnemonics[0][:2], PASSPHRASE)


def test_wrong_passphrase() -> None:
    """A wrong passphrase is a different secret, never an error.

    SLIP-0039 has no way to tell a right passphrase from a wrong one,
    deliberately: that is what lets a decoy wallet be plausible.
    """
    mnemonics, master_secret, _ = _VECTORS[0][1:]
    assert slip39.master_secret_from_mnemonics(
        mnemonics, "not TREZOR"
    ) != bytes.fromhex(master_secret)


def test_extendable_flag_changes_the_secret() -> None:
    """The flag is in the salt, so it is in the answer.

    Two backups of the same master secret differing only in the flag
    produce different shares, and a share of one kind fails the other's
    checksum -- which is why both states have to be supported rather
    than assumed.
    """
    master_secret = bytes.fromhex("bb54aac4b89dc868ba37d9cc21b2cece")

    def backup(extendable: bool) -> list[list[str]]:
        return slip39.mnemonics_from_master_secret(
            master_secret,
            passphrase=PASSPHRASE,
            iteration_exponent=0,
            extendable=extendable,
            entropy_source=fixed_identifier(0x1234),
        )

    extended, legacy = backup(extendable=True), backup(extendable=False)
    assert extended != legacy
    assert slip39.share_from_mnemonic(extended[0][0]).extendable
    assert not slip39.share_from_mnemonic(legacy[0][0]).extendable
    for mnemonics in (extended, legacy):
        recovered = slip39.master_secret_from_mnemonics(mnemonics[0], PASSPHRASE)
        assert recovered == master_secret

    # same identifier, same everything else: only the flag differs, and
    # the share value already does
    assert (
        slip39.share_from_mnemonic(extended[0][0]).value
        != slip39.share_from_mnemonic(legacy[0][0]).value
    )


def test_unknown_word() -> None:
    """Refuse a word outside the SLIP-0039 word-list, naming it."""
    mnemonic = _VECTORS[0][1][0].replace("duckling", "abandon", 1)
    err_msg = r"not in the SLIP-0039 word-list: \['abandon'\]"
    with pytest.raises(BTClibValueError, match=err_msg):
        slip39.share_from_mnemonic(mnemonic)


def test_whitespace_is_collapsed() -> None:
    """Verify extra whitespace decodes to the same share."""
    mnemonic = _VECTORS[0][1][0]
    # not an f-string with the escapes inside the braces: a backslash in
    # a replacement field is python 3.12, and this package supports 3.10
    noisy = "  " + mnemonic.replace(" ", "  \n\t") + "  "
    assert slip39.share_from_mnemonic(noisy) == slip39.share_from_mnemonic(mnemonic)


def test_no_mnemonic() -> None:
    """Refuse an empty list of mnemonics."""
    with pytest.raises(BTClibValueError, match="no mnemonic"):
        slip39.master_secret_from_mnemonics([], PASSPHRASE)


@pytest.mark.parametrize("passphrase", ["\x1f", "\x7f", "è"])
def test_invalid_passphrase(passphrase: str) -> None:
    """Refuse a passphrase outside printable ASCII, both directions."""
    err_msg = "invalid passphrase: only printable ASCII"
    with pytest.raises(BTClibValueError, match=err_msg):
        slip39.master_secret_from_mnemonics(_VECTORS[0][1], passphrase)
    with pytest.raises(BTClibValueError, match=err_msg):
        slip39.mnemonics_from_master_secret(bytes(16), passphrase=passphrase)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("identifier", -1),
        ("identifier", 1 << 15),
        ("iteration_exponent", 16),
        ("group_index", 16),
        ("group_threshold", 0),
        ("group_count", 17),
        ("member_index", 16),
        ("member_threshold", 0),
    ],
)
def test_invalid_share_field(field: str, value: int) -> None:
    """Refuse each out-of-range Share field, one at a time."""
    fields = {
        "identifier": 1,
        "extendable": True,
        "iteration_exponent": 0,
        "group_index": 0,
        "group_threshold": 1,
        "group_count": 1,
        "member_index": 0,
        "member_threshold": 1,
        "value": bytes(16),
    }
    fields[field] = value
    with pytest.raises(BTClibValueError, match="invalid "):
        slip39.Share(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize("n_bytes", [0, 14, 17])
def test_invalid_secret_length(n_bytes: int) -> None:
    """Refuse master secrets and share values of invalid length."""
    err_msg = f"invalid master secret length: {n_bytes} bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        slip39.mnemonics_from_master_secret(bytes(n_bytes))
    err_msg = f"invalid share value length: {n_bytes} bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        slip39.Share(1, True, 0, 0, 1, 1, 0, 1, bytes(n_bytes))


def test_group_count_below_threshold() -> None:
    """Refuse a group count smaller than the group threshold."""
    err_msg = "group count 1 smaller than group threshold 2"
    with pytest.raises(BTClibValueError, match=err_msg):
        slip39.Share(1, True, 0, 0, 2, 1, 0, 1, bytes(16))


@pytest.mark.parametrize("iteration_exponent", [-1, 16])
def test_invalid_iteration_exponent(iteration_exponent: int) -> None:
    """Refuse an iteration exponent outside 0..15."""
    err_msg = f"invalid iteration exponent: {iteration_exponent}"
    with pytest.raises(BTClibValueError, match=err_msg):
        slip39.mnemonics_from_master_secret(
            bytes(16), iteration_exponent=iteration_exponent
        )


def test_one_of_many_group() -> None:
    """A 1-of-N group is N copies of one secret; SLIP-0039 forbids it."""
    err_msg = "invalid 1-of-3 group"
    with pytest.raises(BTClibValueError, match=err_msg):
        slip39.mnemonics_from_master_secret(bytes(16), groups=[(1, 3)])


@pytest.mark.parametrize(
    ("groups", "group_threshold"),
    [
        ([(2, 3)], 0),  # a threshold of no group
        ([(2, 3)], 2),  # more groups needed than there are
        ([(1, 1)] * 17, 1),  # seventeen groups, four bits of index
        ([(3, 2)], 1),  # a group needing more shares than it has
        ([(2, 17)], 1),  # seventeen members, four bits of index
    ],
)
def test_invalid_threshold(groups: list[tuple[int, int]], group_threshold: int) -> None:
    """Refuse thresholds and counts outside SLIP-0039's bounds."""
    with pytest.raises(BTClibValueError, match="invalid threshold "):
        slip39.mnemonics_from_master_secret(
            bytes(16), groups=groups, group_threshold=group_threshold
        )
