# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for a function taking an object the caller already built.

CONTRIBUTING.md's "Every public function validates its inputs" is driven
automatically by `input_validation_test.py`, over the functions whose every
required parameter is a library input type, and by hand in
`bool_contract_test.py`, over the ones that answer a `bool`. Neither
reaches a function whose parameter is a `Psbt`, a `PsbtIn` or a sequence of
extended keys: no vocabulary of wrong values builds one, so a fixture has
to, and issue #856 is where that ceiling is written down.

`check_validity=False` is why this family is worth a gate of its own.
CONTRIBUTING.md's "it says *do not check now*, not *this object is exempt
from here on*" makes an invalid object something a caller can legitimately
hold, so a public name accepting one is a name that has to ask -- and the
rules are the same two everywhere else obeys:

- a **wrong type** leaves as a `BTClibTypeError`
- a **wrong value** of a declared type leaves as a `BTClibValueError`,
  these functions answering no `bool` about their argument

Both were open when this file was written, in the four shapes issue #856
predicted: a sequence walked before it is checked (`KeyGroup`'s `keys` and
`origins`, `satisfaction_sizer`'s), an argument reaching a comparison
before its type is asked (`KeyGroup`'s `threshold`,
`Psbt.assert_valid`'s three int fields), and an argument read for a field
it has not got (`assert_signatures_only`, `estimated_input_sizes`, both
sizers). The fifth was silence: `estimated_input_sizes` took a `sizer` of
no callable type for every input it answers for on its own, and `KeyGroup`
a float threshold.

Two of the annotations *accept* the mistake, which is why neither gate nor
mypy could see it: `Sequence[BIP32Key]` accepts a `str`, and
`Iterable[Octets]` accepts a `str` and a `bytes`, every character being a
key as far as the type goes. One xpub handed where the list was meant was
111 keys.

A `bool` parameter is driven in `bool_parameter_test.py` rather than here,
and the line it sorts them by is `musig2._flag`'s: a flag that decides
*what is computed* is a kind and not a truth, so `KeyGroup(verify=)`
refuses a non-bool -- it chooses the closing opcode, and a wallet built
from a configuration file reading "false" would compute every address of
the other script. A flag that decides only *whether a check runs* --
`check_validity`, and `slip132`'s `check_root_xkey` -- is read for its
truth, a wrong value there running a check or skipping one and never
changing an answer. `check_validity_test.py` owns that convention, and
`KeyGroup(verify=)` is in the kinds of that census with the rest.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from functools import partial
from typing import Any

import pytest

from btclib import slip132
from btclib.bip32.bip32 import rootxprv_from_seed, xpub_from_xprv
from btclib.descriptors.descriptors import miniscript_sizer, satisfaction_sizer
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.psbt.psbt import Psbt, assert_signatures_only
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_size import estimated_input_sizes
from btclib.tx import TxOut
from btclib.tx_builder import build_psbt
from btclib.wallet.script_wallet import KeyGroup
from tests.psbt import psbt_cases

_ROOT_XPRV = rootxprv_from_seed("00" * 32)
_XPUB = xpub_from_xprv(_ROOT_XPRV)

# the first BIP174 vector carrying signatures, which is what makes a
# request-and-answer pair out of one published psbt: the answer is the
# vector, the request is the same psbt before a Signer touched it
_SIGNED = next(
    psbt
    for psbt in (
        Psbt.b64decode(case["encoded psbt"])
        for case in psbt_cases("bip174_test_vectors.json", "valid psbts")
    )
    if any(psbt_in.partial_sigs for psbt_in in psbt.inputs)
)
_REQUEST = deepcopy(_SIGNED)
for _psbt_in in _REQUEST.inputs:
    _psbt_in.partial_sigs = {}
# an answer that changed something no answer may change, which is a psbt
# of a perfectly good type and the wrong value of it
_CHANGED = deepcopy(_SIGNED)
_CHANGED.unknown = {b"\x00": b"\x01"}

_PSBT_IN = _SIGNED.inputs[0]
_TX_IN = _SIGNED.tx.vin[0]
# a payment small enough for that input to cover it at any rate, to the
# script the vector's own first output pays
_TX_OUT = TxOut(1_000, _SIGNED.tx.vout[0].script_pub_key)
# the input's own keys, which is the caller a satisfaction sizer is for:
# it sizes the branch these will take, so the quorum has to be theirs
_SIGNER_KEYS = list(_PSBT_IN.hd_key_paths)

# a value of a declared type that no valid input carries
_WRONG_KEY_VALUE = "not a key"

# a value of no type any of these positions declares
_WRONG_TYPES = (None, 1.5)


@dataclass(frozen=True)
class _Case:
    """A function, a call of it that works, and what to drive."""

    label: str
    function: Any
    args: tuple[Any, ...]
    # position -> a wrong value of the type that position declares
    wrong_values: dict[int, Any]
    # positions whose annotation is `| None`, where None is therefore a
    # declared type and not a wrong one. A statement about the signature,
    # not an exemption from the rule: it is read off the annotation, and a
    # position missing from here is one the rule applies to in full
    optional: frozenset[int] = frozenset()


_CASES = (
    _Case(
        "slip132.address_from_xkey",
        slip132.address_from_xkey,
        (_XPUB,),
        {0: _WRONG_KEY_VALUE},
    ),
    _Case(
        "slip132.address_from_xpub",
        slip132.address_from_xpub,
        (_XPUB,),
        {0: _WRONG_KEY_VALUE},
    ),
    _Case(
        "slip132.p2pkh_xkey", slip132.p2pkh_xkey, (_ROOT_XPRV,), {0: _WRONG_KEY_VALUE}
    ),
    _Case(
        "slip132.p2wpkh_xkey",
        slip132.p2wpkh_xkey,
        (_ROOT_XPRV,),
        {0: _WRONG_KEY_VALUE},
    ),
    _Case(
        "slip132.p2wpkh_p2sh_xkey",
        slip132.p2wpkh_p2sh_xkey,
        (_ROOT_XPRV,),
        {0: _WRONG_KEY_VALUE},
    ),
    _Case(
        "KeyGroup",
        KeyGroup,
        # all four positions written out, the two with a default included:
        # `verify` and `origins` are as much a part of what a group
        # computes as the keys are, and a default is not an exemption
        (2, [_XPUB, _XPUB], False, [None, None]),
        # every value of an int is one, so a threshold no quorum of two
        # keys has is the wrong value rather than a malformed number; and
        # one origin for two keys is a list of the right type and the
        # wrong length
        {0: 0, 1: [_WRONG_KEY_VALUE, _XPUB], 3: [None]},
        optional=frozenset({3}),
    ),
    _Case(
        "psbt.assert_signatures_only",
        assert_signatures_only,
        (_REQUEST, _SIGNED),
        {0: _CHANGED, 1: _CHANGED},
    ),
    _Case(
        "psbt_size.estimated_input_sizes",
        estimated_input_sizes,
        (_PSBT_IN, _TX_IN),
        # an input carrying no utxo is a PsbtIn whose type cannot be read,
        # which is what this function raises about rather than guesses at
        {0: PsbtIn()},
    ),
    _Case(
        "tx_builder.build_psbt",
        build_psbt,
        ([_PSBT_IN], [_TX_OUT], FeeRate(sats_per_kvbyte=1000)),
        # an input carrying no utxo is worth nothing this can read, and a
        # transaction with no output at all is one Core's CheckTransaction
        # refuses: both are sequences of the declared type holding a value
        # no valid call carries. The rate has no wrong value -- every
        # FeeRate its own constructor admits is a price
        {0: [PsbtIn()], 1: []},
    ),
    # the two SolutionSizers, which take the same pair and owe a caller the
    # same check. Neither has a wrong *value*: "not mine" is what a sizer
    # answers with None, so nothing of the declared type is refused
    _Case("descriptors.miniscript_sizer", miniscript_sizer, (_PSBT_IN, _TX_IN), {}),
    _Case(
        "descriptors.satisfaction_sizer(...)",
        satisfaction_sizer(_SIGNER_KEYS),
        (_PSBT_IN, _TX_IN),
        {},
    ),
)

_IDS = tuple(case.label for case in _CASES)


def _driven(case: _Case, position: int, wrong: Any) -> Callable[[], Any]:
    """Return the call with one position replaced, the others left valid."""
    args = list(case.args)
    args[position] = wrong
    return partial(case.function, *args)


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_the_call_works(case: _Case) -> None:
    """The fixture is valid, which is what makes a refusal below a finding.

    Without this a case whose arguments had gone stale would pass every
    test in the file by refusing everything it is handed.
    """
    case.function(*case.args)


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_type_leaves_as_a_btclib_type_error(case: _Case) -> None:
    """The first rule, one position at a time, the others left valid."""
    for position in range(len(case.args)):
        for wrong in _WRONG_TYPES:
            if wrong is None and position in case.optional:
                continue
            with pytest.raises(BTClibTypeError):
                _driven(case, position, wrong)()


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_value_leaves_as_a_btclib_value_error(case: _Case) -> None:
    """The second rule: a value of a declared type is refused as a value.

    `BTClibValueError` and not `BTClibException`, which would be the
    contract read literally: a type error is one of those too, so the
    wider class would let the first rule's failures through as the
    second's answer.
    """
    for position, wrong in sorted(case.wrong_values.items()):
        with pytest.raises(BTClibValueError):
            _driven(case, position, wrong)()


def test_an_origin_that_is_no_origin_is_refused_as_a_type() -> None:
    """A sequence of the right shape whose entries are of the wrong type.

    Driven separately because the table replaces a whole argument: what a
    `Sequence[BIP32KeyOrigin | None]` declares is checked entry by entry,
    and a `str` is the case that makes the order matter -- three
    characters are three origins as far as the count is concerned, so the
    report would be about the number rather than about the type.
    """
    for wrong in ([1, 2], "ab"):
        with pytest.raises(BTClibTypeError, match="invalid origin type"):
            KeyGroup(2, [_XPUB, _XPUB], origins=wrong)  # type: ignore[arg-type]


def test_the_keys_a_satisfaction_sizer_is_built_from() -> None:
    """The factory's own argument, which the table cannot reach.

    `Iterable[Octets]` accepts a `str` and a `bytes`, each of them being an
    `Octets` and an iterable of one, so a single key handed where the list
    was meant is as many keys as it has characters -- and each of those
    would be refused as octets, which reports the wrong mistake.
    """
    assert satisfaction_sizer(_SIGNER_KEYS)(_PSBT_IN, _TX_IN) == [0, 72, 72, 71]
    for wrong in (*_WRONG_TYPES, _SIGNER_KEYS[0], _SIGNER_KEYS[0].hex()):
        with pytest.raises(BTClibTypeError, match="invalid keys type"):
            satisfaction_sizer(wrong)  # type: ignore[arg-type]


def test_the_sizer_is_asked_for_before_it_is_needed() -> None:
    """A keyword-only parameter, and the one consulted in a single branch.

    Which is why it went unchecked: an input this function answers for on
    its own never calls the sizer, so a value of no callable type was
    accepted by every call that did not need it.
    """
    assert estimated_input_sizes(_PSBT_IN, _TX_IN, sizer=None) == (35, [0, 72, 72, 71])
    for wrong in _WRONG_TYPES[1:]:
        with pytest.raises(BTClibTypeError, match="invalid sizer type"):
            estimated_input_sizes(_PSBT_IN, _TX_IN, sizer=wrong)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "field, what",
    [
        ("version", "version"),
        ("tx_modifiable", "tx modifiable"),
        ("fallback_lock_time", "fallback locktime"),
    ],
)
def test_psbt_assert_valid_asks_the_type_of_its_int_fields(
    field: str, what: str
) -> None:
    """The object *is* the input here, so the fields are what to drive.

    `check_validity=False` on the way in is what makes this reachable:
    the three are compared against a range, and a value of no integer type
    raised from underneath the library rather than being refused by it.

    Neither `None` nor a `bool` is in the list: two of the three are
    optional, so `None` is a value they declare, and a bool is refused as
    a type by the one policy `integer_policy_test.py` holds every integer
    field to.
    """
    for wrong in (1.5, "one"):
        psbt = deepcopy(_SIGNED)
        setattr(psbt, field, wrong)
        with pytest.raises(BTClibTypeError, match=f"invalid {what} type"):
            psbt.assert_valid()


def test_the_psbt_int_fields_a_refusal_must_not_take_with_it() -> None:
    """The same fields with a number, which is what the refusal is around.

    And `None` where the field declares it: the version is the one of the
    three that does not, every psbt having one.
    """
    psbt = deepcopy(_SIGNED)
    psbt.assert_valid()

    psbt.fallback_lock_time = 0
    psbt.assert_valid()
    psbt.fallback_lock_time = None
    psbt.assert_valid()

    psbt.fallback_lock_time = -1
    with pytest.raises(BTClibValueError, match="invalid fallback locktime"):
        psbt.assert_valid()

    psbt = deepcopy(_SIGNED)
    psbt.version = None  # type: ignore[assignment]
    with pytest.raises(BTClibTypeError, match="invalid version type"):
        psbt.assert_valid()
