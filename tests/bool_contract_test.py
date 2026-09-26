# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for the bool contract, over what only a fixture can reach.

CONTRIBUTING.md's "Every public function validates its inputs" states
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
call of it that answers True, a wrong value for each position worth
driving, and a structurally invalid one for each position where the two
diverge. Three rules, asked one position at a time with the others left
valid:

- a **wrong type** leaves as a `BTClibTypeError`. A bool is an answer
  about a value, so a type the signature does not declare is not
  something it answers about.
- a **wrong value** of a declared type is `False`. That is what the bool
  is for, and what a caller filtering signatures off the wire relies on.
- a value of a declared type whose size or encoding makes it
  **structurally invalid** -- one no valid input could ever carry, as
  opposed to one that is merely not authentic -- is a `BTClibValueError`.
  A verification is not the question that value answers, so it is
  refused rather than read as a forged signature. What decides is
  whether the position declares a size: `dsa.verify_`'s digest does and
  `dsa.verify`'s message does not, so the same wrong octets are a
  refusal in one case and `False` in the other.

Issue #814 settled the second against issue #745's "total over everything
it is handed", and this is where the decision is held to. Issue #2170 is
where the third was carved out of the second, for the `ecc` verifications:
a signature, a key, an address or an opening whose size or encoding makes
it impossible is refused there, and issue #2181 carried the same line into
`btclib_wallet.bip322.verify`, where the encoding stands in for the size,
and where its case is. What is left
on the other side is `merkle_proof.verify` and the two script-engine
spellings, which answer a structurally invalid argument with `False`.

The verifications of the schemes btclib_ecc carries, `dsa`, `ssa`,
`dleq` and `pedersen`, are held to these rules by that package's own
copy of this file (issue #2282); `bms.verify` is btclib's, and is here.

## Both rules hold, and they did not when this file was written

Reaching ground the automatic walk cannot touch found sixteen positions
open, which is what issue #776 said a floor would do, and they were held
in two ratcheted lists until they were closed. Three shapes accounted for
them, so the fixes are where the shapes are: a sequence parameter checked
before it is walked (`ssa._assert_batch_sequences`,
`merkle_proof.assert_as_valid`), a signature coerced by `str_from_string`
before `Sig.b64decode` strips it, and the engine adapters asking
`_assert_bytes_arguments` before the bindings would. The two value-rule
entries were one shape as well: `verify` reduced the message *before* its
`try`, so a message that is no octets was refused where `verify_`, handed
the hash, answered False; both spellings wrap `assert_as_valid` now
instead of delegating past the reduction.

No list is left, and that is deliberate: a finding this file makes next is
a red test above, to be fixed or to be given a reason of its own.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from btclib import b58
from btclib.block import merkle_proof
from btclib.ecc import bms, dsa, ssa
from btclib.hashes import reduce_to_hlen
from btclib.key import PrvKeyData, PubKeyData
from btclib.script.engine import script as engine_script
from btclib.script.engine import tapscript as engine_tapscript

_Q = 12
_PUB = PrvKeyData(_Q).pub.sec
_X_ONLY = _PUB[1:]
_MSG = b"Satoshi Nakamoto"
_OTHER_MSG = b"another message"
_MSG_HASH = reduce_to_hlen(_MSG)
_ADDR = b58.p2pkh(PubKeyData(_PUB))
_DSA_SIG = dsa.sign(_MSG, _Q)
_SSA_SIG = ssa.sign(_MSG, _Q)
_BMS_SIG = bms.sign(_MSG, PrvKeyData(_Q))
_TX_ID = bytes.fromhex("01" * 32)

# a value of a declared type that no valid input carries. The same split
# `input_validation_test.py` makes, spelled per position because a
# hand-written call knows which alias each of its arguments is
_WRONG_OCTETS_VALUE = "not hex at all"
_WRONG_STRING_VALUE = "not an address"

# a value of no type any of these positions declares
_WRONG_TYPES = (None, 1.5)


@dataclass(frozen=True)
class _Case:
    """A bool function, a call that answers True, and what to drive."""

    label: str
    function: Any
    args: tuple[Any, ...]
    # position -> a wrong value of the type that position declares, one
    # a valid input could carry -- False is the answer
    wrong_values: dict[int, Any]
    # position -> a value of the declared type whose size or encoding
    # makes the question unanswerable -- a raise is the answer (issue
    # 2170). Empty for every case this issue leaves alone
    structurally_invalid_values: dict[int, Any] = field(default_factory=dict)


_CASES = (
    _Case(
        "bms.verify",
        bms.verify,
        (_MSG, _ADDR, _BMS_SIG),
        {0: _WRONG_OCTETS_VALUE},
        # the address is this scheme's public key, and the signature is
        # 65 octets or nothing
        {1: _WRONG_STRING_VALUE, 2: _WRONG_STRING_VALUE},
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
        for wrong in _WRONG_TYPES:
            assert _outcome(case, position, wrong) == "BTClibTypeError"


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_value_answers_false(case: _Case) -> None:
    """The second rule: a value of a declared type is answered, not refused."""
    for position, wrong in sorted(case.wrong_values.items()):
        assert _outcome(case, position, wrong) == "answers False"


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_structurally_invalid_value_raises(case: _Case) -> None:
    """The third rule, issue 2170's: an unanswerable question is refused.

    A signature or a public key whose size or encoding no valid input
    could carry is not a value the equation ever reaches, so it is a
    BTClibValueError rather than a False that would read as a forged
    signature.
    """
    for position, wrong in sorted(case.structurally_invalid_values.items()):
        assert _outcome(case, position, wrong) == "BTClibValueError"
