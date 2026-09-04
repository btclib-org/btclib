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
from btclib.key import PrvKeyData
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
_BMS_SIG = bms.sign(_MSG, PrvKeyData(_Q))
# BIP322 declares a `Sig` of its own, and it is not bms's: the two are
# distinct classes, so each case is given the one its function takes
_BIP322_SIG = bip322.sign(_MSG, PrvKeyData(_Q), _ADDR)
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
