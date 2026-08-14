# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for the bool contract, over what only a fixture can reach.

CONTRIBUTING.md's "Every public function validates its inputs" states two
rules about a function that answers a `bool`, and
`input_validation_test.py` drives them automatically -- over the
functions whose every required parameter is a library input type. That
leaves out the ones this file is about, and they are the ones the rules
were argued over: a signature verification takes a valid message, key and
signature, and a `Sig | Octets` that no vocabulary of wrong values can
build.

So the calls here are hand-written, which is issue #776's own answer to
what its walk cannot reach: "a hand-written table of name, and the
shortest call that reaches the validator". Each case names a function, a
call of it that answers True, and a wrong value for each position worth
driving. Two rules, asked one position at a time with the others left
valid:

- a **wrong type** leaves as a `BTClibTypeError`. A bool is an answer
  about a value, so a type the signature does not declare is not
  something it answers about.
- a **wrong value** of a declared type is `False`. That is what the bool
  is for, and what a caller filtering signatures off the wire relies on.

Issue #814 settled the second against issue #745's "total over everything
it is handed", and this is where the decision is held to.

## The two open lists, and which way they ratchet

Reaching new ground found new findings, which is what issue #776 said its
own floor of fifty-nine would do. `_TYPE_OPEN` and `_VALUE_OPEN` are
those, one entry per position, each naming what comes out instead. They
can only shrink: `test_what_is_open_is_still_open` fails on an entry that
has come into line, as RUF100 fails an unused `noqa`, so a fix cannot
land without deleting its line -- and a line cannot outlive the defect.

Three shapes are in them. A **sequence parameter** -- `batch_verify`'s
three, `merkle_proof.verify`'s branch -- is walked without being checked,
so a `None` is "not iterable" from underneath the library. A **signature
parameter** reaches `Sig.b64decode`, which strips before it decodes, so a
type with no `strip` is an `AttributeError`. And the **engine adapters**
take plain `bytes` and hand them to the bindings, whose own `TypeError`
says "the message hash must be bytes" -- true, and not btclib saying it.
The two `_VALUE_OPEN` shapes are one: `verify` reduces the message with
`hf` *before* the `try`, so a message that is no octets is refused where
`verify_`, handed the hash, answers False.

What no fixture here reaches, and why: `musig2.partial_sig_verify_` and
`partial_sig_verify` want a `SessionContext` and a signing round,
`psbt.musig2.partial_sig_verify` a `Psbt` carrying one, and
`dsa.anti_exfil_host_verify` a host-device exchange. Those are driven by
the tests of their own modules, against fixtures those modules build.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from btclib import b58, bip322
from btclib.block import merkle_proof
from btclib.ecc import bms, dleq, dsa, pedersen, ssa
from btclib.hashes import reduce_to_hlen
from btclib.script.engine import script as engine_script
from btclib.script.engine import tapscript as engine_tapscript
from btclib.to_pub_key import pub_keyinfo_from_prv_key

_Q = 12
_PUB = pub_keyinfo_from_prv_key(_Q)[0]
_X_ONLY = _PUB[1:]
_MSG = b"Satoshi Nakamoto"
_OTHER_MSG = b"another message"
_MSG_HASH = reduce_to_hlen(_MSG)
_ADDR = b58.p2pkh(_PUB)
_DSA_SIG = dsa.sign(_MSG, _Q)
_SSA_SIG = ssa.sign(_MSG, _Q)
_BMS_SIG = bms.sign(_MSG, _Q)
# BIP322 declares a `Sig` of its own, and it is not bms's: the two are
# distinct classes, so each case is given the one its function takes
_BIP322_SIG = bip322.sign(_MSG, _Q, _ADDR)
_TX_ID = bytes.fromhex("01" * 32)
# a DLEQ triple: A = a*G and C = a*B, so the proof holds for (A, B, C)
_DLEQ_B = pub_keyinfo_from_prv_key(2)[0]
_DLEQ_C = pub_keyinfo_from_prv_key(2 * _Q)[0]
_DLEQ_PROOF = dleq.generate_proof(_Q, _DLEQ_B)
# rG + vH for the very (r, v) its case opens it with
_COMMITMENT = pedersen.commit(1, 2)

# a value of a declared type that no valid input carries. The same split
# `input_validation_test.py` makes, spelled per position because a
# hand-written call knows which alias each of its arguments is
_WRONG_OCTETS_VALUE = "not hex at all"
_WRONG_KEY_VALUE = "not a key"
_WRONG_STRING_VALUE = "not an address"

# a value of no type any of these positions declares
_WRONG_TYPES = (None, 1.5)


@dataclass(frozen=True)
class _Case:
    """A bool function, a call that answers True, and what to drive."""

    label: str
    function: Any
    args: tuple[Any, ...]
    # position -> a wrong value of the type that position declares
    wrong_values: dict[int, Any]


_CASES = (
    _Case(
        "dsa.verify",
        dsa.verify,
        (_MSG, _PUB, _DSA_SIG),
        {0: _WRONG_OCTETS_VALUE, 1: _WRONG_KEY_VALUE, 2: _WRONG_OCTETS_VALUE},
    ),
    _Case(
        "dsa.verify_",
        dsa.verify_,
        (_MSG_HASH, _PUB, _DSA_SIG),
        {0: _WRONG_OCTETS_VALUE, 1: _WRONG_KEY_VALUE, 2: _WRONG_OCTETS_VALUE},
    ),
    _Case(
        "ssa.verify",
        ssa.verify,
        (_MSG, _X_ONLY, _SSA_SIG),
        {0: _WRONG_OCTETS_VALUE, 1: _WRONG_KEY_VALUE, 2: _WRONG_OCTETS_VALUE},
    ),
    _Case(
        "ssa.verify_",
        ssa.verify_,
        (_MSG_HASH, _X_ONLY, _SSA_SIG),
        {0: _WRONG_OCTETS_VALUE, 1: _WRONG_KEY_VALUE, 2: _WRONG_OCTETS_VALUE},
    ),
    _Case(
        "ssa.batch_verify",
        ssa.batch_verify,
        ([_MSG], [_X_ONLY], [_SSA_SIG]),
        # a sequence whose element is the wrong value, the sequence being
        # what the parameter declares
        {0: [_WRONG_OCTETS_VALUE], 1: [_WRONG_KEY_VALUE]},
    ),
    _Case(
        "bms.verify",
        bms.verify,
        (_MSG, _ADDR, _BMS_SIG),
        {0: _WRONG_OCTETS_VALUE, 1: _WRONG_STRING_VALUE, 2: _WRONG_STRING_VALUE},
    ),
    _Case(
        "bip322.verify",
        bip322.verify,
        (_MSG, _ADDR, _BIP322_SIG),
        {0: _WRONG_OCTETS_VALUE, 1: _WRONG_STRING_VALUE, 2: _WRONG_STRING_VALUE},
    ),
    _Case(
        "pedersen.verify",
        pedersen.verify,
        (1, 2, _COMMITMENT),
        # every value of an int is one, so the wrong value here is a
        # different number rather than a malformed one, and a commitment
        # those two do not open
        {0: 999, 1: 999, 2: pedersen.commit(9, 9)},
    ),
    _Case(
        "merkle_proof.verify",
        merkle_proof.verify,
        # a one-transaction tree, where the coinbase *is* the root and the
        # branch is empty: the shortest call that reaches the check
        (_TX_ID, [], 0, _TX_ID),
        # an index no branch places is the wrong value of an int, as
        # merkle_proof's own tests put it
        {0: _WRONG_OCTETS_VALUE, 2: 1, 3: _WRONG_OCTETS_VALUE},
    ),
    _Case(
        "dleq.verify_proof",
        dleq.verify_proof,
        (_PUB, _DLEQ_B, _DLEQ_C, _DLEQ_PROOF),
        {
            0: _WRONG_KEY_VALUE,
            1: _WRONG_KEY_VALUE,
            2: _WRONG_KEY_VALUE,
            3: _WRONG_OCTETS_VALUE,
        },
    ),
    _Case(
        "engine.script.dsa_verify",
        engine_script.dsa_verify,
        (_MSG_HASH, _PUB, _DSA_SIG.serialize()),
        # plain bytes, so a wrong value is bytes that are not the thing: a
        # DER signature of the right shape over another message
        {2: dsa.sign(_OTHER_MSG, _Q).serialize()},
    ),
    _Case(
        "engine.tapscript.ssa_verify",
        engine_tapscript.ssa_verify,
        (_MSG_HASH, _X_ONLY, _SSA_SIG.serialize()),
        {2: ssa.sign(_OTHER_MSG, _Q).serialize()},
    ),
)

_IDS = tuple(case.label for case in _CASES)

# each entry names the class that comes out where a BTClibTypeError
# belongs; the module docstring has the three shapes behind them
_TYPE_OPEN: dict[str, str] = {
    "bip322.verify[2]": "AttributeError",
    "bms.verify[2]": "AttributeError",
    "engine.script.dsa_verify[0]": "TypeError",
    "engine.script.dsa_verify[1]": "TypeError",
    "engine.script.dsa_verify[2]": "TypeError",
    "engine.tapscript.ssa_verify[0]": "TypeError",
    "engine.tapscript.ssa_verify[1]": "TypeError",
    "engine.tapscript.ssa_verify[2]": "TypeError",
    "merkle_proof.verify[1]": "TypeError",
    # the one that answers rather than raising, which is the shape issue
    # #776 put first because it is the only one that can cost money: a
    # commitment of no type at all is reported as one that does not open
    "pedersen.verify[2]": "answers False",
    "ssa.batch_verify[0]": "TypeError",
    "ssa.batch_verify[1]": "TypeError",
    "ssa.batch_verify[2]": "TypeError",
}

# one shape, and `verify_` beside each of these is where it is not: the
# message is reduced before the `try`, so a message that is no octets is
# refused where the hash spelling answers False
_VALUE_OPEN: dict[str, str] = {
    "dsa.verify[0]": "BTClibValueError",
    "ssa.batch_verify[0]": "BTClibValueError",
    "ssa.verify[0]": "BTClibValueError",
}


def _at(label: str, position: int) -> str:
    """Return the key both open lists are read by."""
    return f"{label}[{position}]"


def _case_of(at: str) -> tuple[_Case, int]:
    """Return the case and the position an open entry names."""
    label, _, rest = at.partition("[")
    case = next(c for c in _CASES if c.label == label)
    return case, int(rest.rstrip("]"))


def _outcome(case: _Case, position: int, wrong: Any) -> str:
    """Return what came out: the class raised, or the answer given."""
    args = list(case.args)
    args[position] = wrong
    try:
        return f"answers {case.function(*args)!r}"
    # the class of what came out is the finding, so every one of them is
    # named rather than let out of the walk
    except Exception as e:  # noqa: BLE001
        return type(e).__name__


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_the_call_answers_true(case: _Case) -> None:
    """The fixture is valid, which is what makes False an answer below.

    Without this a case whose arguments had gone stale would pass every
    test in the file by answering False to everything.
    """
    assert case.function(*case.args) is True


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_type_leaves_as_a_btclib_type_error(case: _Case) -> None:
    """The first rule, one position at a time, the others left valid."""
    for position in range(len(case.args)):
        if _at(case.label, position) in _TYPE_OPEN:
            continue
        for wrong in _WRONG_TYPES:
            assert _outcome(case, position, wrong) == "BTClibTypeError"


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_value_answers_false(case: _Case) -> None:
    """The second rule: a value of a declared type is answered, not refused."""
    for position, wrong in sorted(case.wrong_values.items()):
        if _at(case.label, position) in _VALUE_OPEN:
            continue
        assert _outcome(case, position, wrong) == "answers False"


@pytest.mark.parametrize("at", sorted(_TYPE_OPEN))
def test_what_the_type_rule_holds_open_is_still_open(at: str) -> None:
    """A fix cannot land without deleting its line from `_TYPE_OPEN`."""
    case, position = _case_of(at)
    assert _outcome(case, position, _WRONG_TYPES[0]) == _TYPE_OPEN[at], (
        f"{at} no longer answers a wrong type with {_TYPE_OPEN[at]}: delete"
        " its line, or correct it to what it answers with now"
    )


@pytest.mark.parametrize("at", sorted(_VALUE_OPEN))
def test_what_the_value_rule_holds_open_is_still_open(at: str) -> None:
    """A fix cannot land without deleting its line from `_VALUE_OPEN`."""
    case, position = _case_of(at)
    wrong = case.wrong_values[position]
    assert _outcome(case, position, wrong) == _VALUE_OPEN[at], (
        f"{at} no longer answers a wrong value with {_VALUE_OPEN[at]}:"
        " delete its line, or correct it to what it answers with now"
    )


def test_every_open_entry_names_a_driven_position() -> None:
    """Neither list may name a position no case drives.

    A renamed case, or a position dropped from `wrong_values`, would
    otherwise leave an entry excusing something nothing runs.
    """
    for at in sorted(_TYPE_OPEN):
        case, position = _case_of(at)
        assert position < len(case.args), at
    for at in sorted(_VALUE_OPEN):
        case, position = _case_of(at)
        assert position in case.wrong_values, at
