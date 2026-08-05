# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.script.engine.flags` module."""

import re
from pathlib import Path

import pytest

import btclib.script.engine
from btclib.exceptions import BTClibValueError
from btclib.script import ScriptPubKey
from btclib.script.engine import (
    ALL_FLAGS,
    NO_FLAGS,
    ScriptFlag,
    ScriptFlags,
    to_script_flags,
    verify_transaction,
)
from btclib.script.sig_hash import SIG_HASH_TYPES
from btclib.tx import OutPoint, Tx, TxIn
from btclib.tx.tx_out import TxOut

ENGINE_DIR = Path(btclib.script.engine.__file__).parent


def flags_named_in_the_engine() -> set[str]:
    """Every `ScriptFlag.X` the engine mentions, flags.py aside."""
    names: set[str] = set()
    for path in sorted(ENGINE_DIR.glob("*.py")):
        if path.name == "flags.py":
            continue  # where they are defined, not where they are checked
        names |= set(re.findall(r"ScriptFlag\.([A-Z0-9_]+)", path.read_text()))
    return names


def test_every_flag_is_checked_and_every_check_is_a_flag() -> None:
    """No member without a branch, and no branch on a name that is not one.

    The two halves of issue #145. A member the engine never looks at is a
    rule a caller can ask for and not get, and a name the engine looks at
    that is not a member is a misspelling that would otherwise read as a
    rule switched off -- it is an AttributeError, but only on the branch
    that runs, so this test is what makes it a failure on every run.

    Read out of the source and not out of the imported modules, there
    being nothing to introspect: the check is a name inside an `if`. A
    member mentioned in a comment alone would satisfy this, which is the
    one gap and a small one.
    """
    assert flags_named_in_the_engine() == set(ScriptFlag.__members__)


def test_all_flags_is_the_consensus_set() -> None:
    """What the engine enforces by default, named one by one.

    ALL_FLAGS is not every member -- the standardness ones are off -- and
    a change to it is a change to what `verify_transaction(prevouts, tx)`
    means, so it is spelled out here rather than derived.
    """
    assert ALL_FLAGS == (
        ScriptFlag.P2SH
        | ScriptFlag.DERSIG
        | ScriptFlag.NULLDUMMY
        | ScriptFlag.CHECKLOCKTIMEVERIFY
        | ScriptFlag.CHECKSEQUENCEVERIFY
        | ScriptFlag.WITNESS
        | ScriptFlag.TAPROOT
    )
    assert ScriptFlag.STRICTENC not in ALL_FLAGS


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        (None, ALL_FLAGS),
        (ALL_FLAGS, ALL_FLAGS),
        (NO_FLAGS, NO_FLAGS),
        ("", NO_FLAGS),
        ("NONE", NO_FLAGS),
        ([], NO_FLAGS),
        (["NONE"], NO_FLAGS),
        ("P2SH", ScriptFlag.P2SH),
        (["P2SH"], ScriptFlag.P2SH),
        ("P2SH,WITNESS", ScriptFlag.P2SH | ScriptFlag.WITNESS),
        (["P2SH", "WITNESS"], ScriptFlag.P2SH | ScriptFlag.WITNESS),
        (iter(["P2SH", "WITNESS"]), ScriptFlag.P2SH | ScriptFlag.WITNESS),
    ],
)
def test_to_script_flags(flags: ScriptFlags | None, expected: ScriptFlag) -> None:
    """Verify every accepted spelling of the flags converts to the enum."""
    assert to_script_flags(flags) == expected


@pytest.mark.parametrize(
    "flags", ["DERSING", "P2SH,DERSING", ["DERSING"], "p2sh", "NONE,P2SH", " P2SH"]
)
def test_unknown_flag_name_raises(flags: ScriptFlags) -> None:
    """A misspelled name is refused rather than disabling a rule.

    `"NONE,P2SH"` among them: NONE is Core's spelling of an empty field,
    the whole field, and not a name to be mixed with others.
    """
    with pytest.raises(BTClibValueError, match="unknown script flag"):
        to_script_flags(flags)


def test_default_flags_cannot_be_mutated() -> None:
    """A caller cannot widen or narrow what the next one gets.

    A mutable module-level ALL_FLAGS is one missed copy away from a
    caller's `flags.remove("P2SH")` disabling BIP16 for the rest of the
    process; likewise SIG_HASH_TYPES, whose membership test is what the
    engine accepts as a signature's hash type.
    """
    assert ALL_FLAGS & ~ScriptFlag.P2SH != ALL_FLAGS  # a new value, not a change
    assert ScriptFlag.P2SH in ALL_FLAGS

    with pytest.raises(AttributeError):
        SIG_HASH_TYPES.add(0x04)  # type: ignore[attr-defined]
    assert 0x04 not in SIG_HASH_TYPES


def test_a_misspelled_flag_does_not_verify_a_transaction() -> None:
    """The end of the road for issue #145, at the public entry point.

    The transaction is the one test_invalid_amount builds, and it never
    gets as far as a script: `verify_transaction` converts its flags
    first, and "DERSING" is not a rule it can ask for.
    """
    prevouts = [TxOut(10, ScriptPubKey(""))]
    tx = Tx(vin=[TxIn(OutPoint(b"1" * 32, 1))], vout=[TxOut(10, ScriptPubKey(""))])

    with pytest.raises(BTClibValueError, match="unknown script flag"):
        verify_transaction(prevouts, tx, ["P2SH", "DERSING"])
