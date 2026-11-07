# Copyright (c) The btclib developers
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
        source = path.read_text(encoding="utf-8")
        names |= set(re.findall(r"ScriptFlag\.([A-Z0-9_]+)", source))
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


# the position of each name in Bitcoin Core's `script_verify_flag_name`,
# src/script/interpreter.h at bitcoin/bitcoin@f0de87f040, whose
# `script_verify_flags` sets bit `1 << position`
# (src/script/verify_flags.h). Written out, not derived, so that a member
# given another bit fails
CORE_BIT = {
    "P2SH": 0,
    "STRICTENC": 1,
    "DERSIG": 2,
    "LOW_S": 3,
    "NULLDUMMY": 4,
    "SIGPUSHONLY": 5,
    "MINIMALDATA": 6,
    "DISCOURAGE_UPGRADABLE_NOPS": 7,
    "CLEANSTACK": 8,
    "CHECKLOCKTIMEVERIFY": 9,
    "CHECKSEQUENCEVERIFY": 10,
    "WITNESS": 11,
    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM": 12,
    "MINIMALIF": 13,
    "NULLFAIL": 14,
    "WITNESS_PUBKEYTYPE": 15,
    "CONST_SCRIPTCODE": 16,
    "TAPROOT": 17,
    "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION": 18,
    "DISCOURAGE_OP_SUCCESS": 19,
    "DISCOURAGE_UPGRADABLE_PUBKEYTYPE": 20,
}


def test_every_core_flag_has_core_bit() -> None:
    """A Core bitmask passed as `ScriptFlag(n)` reads the flags Core means.

    The names alone do not catch a swapped bit: Core's vectors spell
    their flags by name (issue #2770). `MINIMALIF_ALL` is not Core's, so
    it is the one member outside the table.
    """
    assert set(ScriptFlag.__members__) == set(CORE_BIT) | {"MINIMALIF_ALL"}
    for name, position in CORE_BIT.items():
        assert ScriptFlag[name].value == 1 << position, name


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
    "flags, expected",
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
    process; likewise SIG_HASH_TYPES, which the engine's STRICTENC set
    is derived from.
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
