# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Script verification flags.

A bitmask, not a list of plain strings asked `"P2SH" in flags`: that
check accepts any string at all, so a misspelled name -- `"DERSING"`,
`"MINMALIF"` -- silently *disables* a consensus rule instead of failing,
in a script verification engine (issue #145).

Both spellings are checked. A caller's name is looked up in the enum
by `to_script_flags`, which refuses what it does not know, and every test
the engine makes is `ScriptFlag.X in flags`, which a typo turns into an
AttributeError rather than into a rule that never runs. A test asserts
the two sets are the same: `tests/script_engine/flags_test.py` reads the
engine's own source, and no member may go unchecked there and no name
checked there may be missing here.

Names and bit positions are Bitcoin Core's `SCRIPT_VERIFY_*` of
src/script/interpreter.h, so a flag means here what it means there, and
Core's vectors -- `script_tests.json` and `tx_valid.json` carry theirs as
a comma-separated string -- can be passed as they are written.

One member is stricter than its name in Core, and it is named here
because the rest of the file promises it is not: CONST_SCRIPTCODE
refuses a signature check carried anywhere in the script_sig, executed
or not, where Core errors only where its FindAndDelete finds the
signature in an executed op. `engine/__init__.py` says why the class is
refused up front.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Flag

from btclib.exceptions import BTClibValueError

__all__ = [
    "ALL_FLAGS",
    "NO_FLAGS",
    "ScriptFlag",
    "ScriptFlags",
    "to_script_flags",
]


class ScriptFlag(Flag):
    """A set of script verification rules to enforce.

    One member per rule the engine implements, and none for a rule it
    does not: asking for a member is asking for a branch, never a request
    quietly ignored, which is the failure mode this enum exists to
    remove. So every `SCRIPT_VERIFY_*` Core spells is a member here, bit
    for bit and with no holes in the positions below.
    """

    # consensus: what a node must enforce to stay on the chain, and what
    # ALL_FLAGS turns on
    P2SH = 1 << 0  # BIP16
    DERSIG = 1 << 2  # BIP66
    NULLDUMMY = 1 << 4  # BIP147
    CHECKLOCKTIMEVERIFY = 1 << 9  # BIP65
    CHECKSEQUENCEVERIFY = 1 << 10  # BIP112
    WITNESS = 1 << 11  # BIP141
    TAPROOT = 1 << 17  # BIP341, BIP342

    # standardness: BIP62, which was never finalized, and the relay rules
    # that outlived it. A block breaking one of these is valid, so
    # ALL_FLAGS leaves them off and only a caller asking a policy question
    # turns them on. Where a BIP made one of them consensus for a script
    # version -- cleanstack and minimalif under segwit, minimalif under
    # tapscript -- the engine enforces that part whatever the flags say,
    # which is why these are still off by default
    STRICTENC = 1 << 1
    LOW_S = 1 << 3
    SIGPUSHONLY = 1 << 5
    MINIMALDATA = 1 << 6
    DISCOURAGE_UPGRADABLE_NOPS = 1 << 7
    CLEANSTACK = 1 << 8
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12
    MINIMALIF = 1 << 13
    NULLFAIL = 1 << 14
    WITNESS_PUBKEYTYPE = 1 << 15
    CONST_SCRIPTCODE = 1 << 16
    # the three cases BIP342 left open for a future soft fork -- unknown,
    # therefore successful -- which policy discourages relaying so that
    # the fork stays deployable. Consensus is untouched by all three, and
    # a spend refused under one of them is a spend a node still accepts
    # in a block
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 1 << 18
    DISCOURAGE_OP_SUCCESS = 1 << 19
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 1 << 20


# no rule at all, which is not the same as "the default rules": `None`
# against `NO_FLAGS` is what tells the two apart
NO_FLAGS = ScriptFlag(0)

# what the engine enforces when a caller names nothing: the consensus soft
# forks, i.e. seven of the twenty-one members and not all of them
ALL_FLAGS = (
    ScriptFlag.P2SH
    | ScriptFlag.DERSIG
    | ScriptFlag.NULLDUMMY
    | ScriptFlag.CHECKLOCKTIMEVERIFY
    | ScriptFlag.CHECKSEQUENCEVERIFY
    | ScriptFlag.WITNESS
    | ScriptFlag.TAPROOT
)

# what the entry points accept: the bitmask itself, Core's comma-separated
# spelling of it, or any iterable of names.
# Union, not "|": this is an assignment, which Python evaluates whatever
# the __future__ import above defers, and PEP 604 unions are a TypeError
# until 3.10
ScriptFlags = ScriptFlag | str | Iterable[str]


def to_script_flags(flags: ScriptFlags | None) -> ScriptFlag:
    """Return the rules to enforce, from any of the spellings accepted.

    A `ScriptFlag` is returned as it is, a string is split on commas, and
    anything else is taken as an iterable of names; an unknown name raises
    rather than being skipped, which is the whole point of the enum.

    `None` is `ALL_FLAGS`, the default set, while an empty string, an
    empty iterable and Core's `"NONE"` are `NO_FLAGS`, no rule at all.
    Those two must stay tellable apart -- the first says "whatever btclib
    enforces by default", the second "check the script and nothing else"
    -- so this does not collapse a falsy argument onto the default.
    """
    if flags is None:
        return ALL_FLAGS
    if isinstance(flags, ScriptFlag):
        return flags

    names = flags.split(",") if isinstance(flags, str) else list(flags)
    # `""` is how Core's vectors spell an empty flag field and `"NONE"` is
    # how they spell it when the field is not left empty; both are the
    # whole field, so neither is a name to be looked up among others
    if names in ([], [""], ["NONE"]):
        return NO_FLAGS

    script_flags = NO_FLAGS
    for name in names:
        if name not in ScriptFlag.__members__:
            raise BTClibValueError(f"unknown script flag: {name!r}")
        script_flags |= ScriptFlag[name]
    return script_flags
