# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for `ec`, the parameter that says which curve is meant.

`input_validation_test.py` drives every public function whose *required*
parameters are all library input types, and its docstring says why a
parameter behind a default is out of its reach: the arguments in front of
it would have to be valid, and a table of valid values per position is
what that walk is built to do without. `hf` and `network` are gated by
hand for that reason, where their own checks live. This is the table for
the third of the three, and it is the widest of them.

Issue #868 is where the count is, and `ec` had no check of its own when
this file was written: every function below answered a wrong one with
`AttributeError: 'NoneType' object has no attribute 'n'`, a field read off
whatever arrived, which is the third of the four shapes issue #856 named.
`Network.assert_valid` said so out loud, with a comment reading "no check
on self.curve" where the check now is.

## The rule, and what the second half of it has to ask here

CONTRIBUTING.md's "Every public function validates its inputs": a value
of a type the signature does not declare leaves as a `BTClibTypeError`,
and a value of a declared type that no valid input carries as a
`BTClibValueError`.

The first half is the whole of the table below. The second half has
nothing to ask here, because **every curve is a valid ec** -- that is
what the parameter is for. What can be wrong is a curve the *key* names,
and the one key spelling that names a network, and through it a curve,
is an xpub: `btclib_wallet.bip32` reads it, and the test of that
mismatch is there.

The functions of the btclib_ecc package that btclib re-exports take
an `ec` too, and that package's suite is the table for them (issue
#2282): what is here is the `ec` of btclib's own code.

## The walk is what makes the table complete

`_curve_parameters` reads every public function of the package whose
signature declares a `Curve` or a `CurveGroup`, so
`test_the_table_is_every_curve_parameter` fails on a function this file
does not drive -- a new one, or one that gains the parameter. There is no
exemption list, and that is the state to keep.

Arguments go in by keyword, which is what lets one driver replace `ec`
in every call whatever its position, and none of these signatures has a
positional-only parameter.

## Where the walk finds nothing on purpose

`parse` and `serialize` never declare `ec`, so the whole family is
absent from the table below -- not an omission, a rule:
`serialization_boundary_test.py`'s module docstring states it and why,
and `test_the_family_takes_no_ec_or_hf` is its gate (issue #1084).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from btclib.consensus import CONSENSUS_PARAMS
from btclib.curves import Curve, CurveGroup, mult, secp256k1
from btclib.ecc import ellswift
from btclib.exceptions import BTClibTypeError
from btclib.network import NETWORKS, Network

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib"

# a value of no type any `ec` declares, and both are calls mypy refuses
_WRONG_TYPES: tuple[Any, ...] = (None, 1.5)

_PRV_KEY = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
_ELL = ellswift.encode_var(mult(_PRV_KEY))
_ELL_2 = ellswift.encode_var(mult(_PRV_KEY + 1))

# a group and not a curve: it has p, a and b and neither the n nor the G a
# Curve adds, which is the wrong type a check against the group would let
# through
_GROUP = CurveGroup(13, 0, 2)

# every field of mainnet but its curve, in the hex spelling to_dict writes
# and the constructor takes
# `to_dict` writes the curve and the consensus row as the names they are
# catalogued under, so each is put back here as the object the
# constructor takes rather than as the name -- the curve by the case
# below, which is what this file varies, and the row by hand
_NETWORK_ARGS: dict[str, Any] = {
    key: value
    for key, value in NETWORKS["mainnet"].to_dict().items()
    if key not in {"curve", "consensus"}
}
_NETWORK_ARGS["consensus"] = CONSENSUS_PARAMS["mainnet"]


@dataclass(frozen=True)
class _Case:
    """A function taking an ec, and a call of it that works."""

    dotted: str
    function: Any
    # every argument but ec, by keyword
    args: dict[str, Any] = field(default_factory=dict)
    # the valid ec, which is a Curve unless the signature says CurveGroup
    ec: CurveGroup = secp256k1
    # a label of its own, where one function is driven by two cases
    label: str = ""
    # what the parameter is called: `ec` everywhere but in `Network`,
    # whose curve is a field of the network and is spelled `curve`
    parameter: str = "ec"


_CASES = (
    _Case(
        "btclib.ecc.ellswift.xdh",
        ellswift.xdh,
        {"ell_a": _ELL, "ell_b": _ELL_2, "prv_key": _PRV_KEY, "party": 0},
    ),
    # the one curve parameter that is a field rather than an argument to
    # compute with, and the one not called `ec`. `to_dict`'s keys are the
    # constructor's parameter names, so the valid call is mainnet rebuilt
    # from its own dict, with the two names `_NETWORK_ARGS` resolves back
    # into objects
    _Case(
        "btclib.network.Network.__init__",
        Network,
        _NETWORK_ARGS,
        parameter="curve",
    ),
)

_IDS = tuple(case.label or case.dotted for case in _CASES)

# the functions whose ec is a Curve, which is every one of them but the
# two group explorers: a CurveGroup is a wrong type for these and the
# right one for those
_CURVE_CASES = tuple(case for case in _CASES if isinstance(case.ec, Curve))
_CURVE_IDS = tuple(case.label or case.dotted for case in _CURVE_CASES)


def _curve_parameters() -> set[str]:
    """Return every public function of the package taking a curve.

    The **annotation** and not the name `ec`: `Network.__init__` spells
    its own `curve`, and a walk keyed on the spelling would leave the one
    curve parameter that is a field out of the table.

    `Curve` and `CurveGroup` exactly, and not a union containing one:
    `network.networks_from_key_value` takes a `str | bytes | Curve` to
    *compare* against every network's field, and its docstring says what
    a value of any other type gets there -- "no network carries this
    prefix", the answer a lookup owes a caller, where these functions
    have a curve to compute in.

    A method counts, `Network.__init__` being one, and a private function
    does not: the guard is what those call.

    The walk reads btclib's own files, so what btclib re-exports of the
    btclib_ecc package is not in it: those names are imports there,
    and that package's own suite drives its `ec` parameters.
    """
    found: set[str] = set()

    def walk(node: ast.Module | ast.ClassDef, module: str, prefix: str) -> None:
        for child in node.body:
            if isinstance(child, ast.ClassDef):
                walk(child, module, f"{prefix}{child.name}.")
            elif isinstance(child, ast.FunctionDef):
                if child.name.startswith("_") and not child.name.startswith("__"):
                    continue
                arguments = [
                    *child.args.posonlyargs,
                    *child.args.args,
                    *child.args.kwonlyargs,
                ]
                if any(
                    a.annotation is not None
                    and ast.unparse(a.annotation) in {"Curve", "CurveGroup"}
                    for a in arguments
                ):
                    found.add(f"{module}.{prefix}{child.name}")

    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        walk(ast.parse(path.read_text(encoding="utf-8")), module, "")
    return found


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_the_call_works(case: _Case) -> None:
    """The fixture is valid, which is what makes a refusal below a finding.

    Without this a case whose arguments had gone stale would pass every
    test in the file by refusing everything it is handed.
    """
    case.function(**case.args, **{case.parameter: case.ec})


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_type_leaves_as_a_btclib_type_error(case: _Case) -> None:
    """The rule, with every other argument left valid.

    `BTClibTypeError` and not `BTClibException`, which is where the class
    is the point: the two failures this is around are an `AttributeError`
    from underneath the library -- a field read off whatever arrived --
    and a `BTClibValueError`, which would be the library calling a
    caller's mistake a fact about the curve.
    """
    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid ec type"):
            case.function(**case.args, **{case.parameter: wrong})


@pytest.mark.parametrize("case", _CURVE_CASES, ids=_CURVE_IDS)
def test_a_curve_group_is_not_a_curve(case: _Case) -> None:
    """The wrong type a check against the group would let through.

    `CurveGroup` is what `Curve` derives from and it is a type mypy
    refuses here, which is the whole reason the check asks for the
    subclass: the group has p, a and b, so a check spelled against it
    would pass an ec that the very next line reads an `n` or a `G` off.
    """
    with pytest.raises(BTClibTypeError, match="invalid ec type: CurveGroup"):
        case.function(**case.args, **{case.parameter: _GROUP})


def test_the_table_is_every_curve_parameter() -> None:
    """No exemption list: a function taking a curve is one driven here.

    The walk is the inventory, so a new `ec` parameter -- or an existing
    function that gains one -- fails here rather than going ungated in
    silence.
    """
    driven = {case.dotted for case in _CASES}
    found = _curve_parameters()
    assert driven == found, f"not driven: {sorted(found - driven)}"


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes the walk must find, and the ones it must not.

    A walk that found nothing would pass the test above.
    """
    found = _curve_parameters()
    # a defaulted ec, and a constructor's spelled `curve`
    assert "btclib.ecc.ellswift.xdh" in found
    assert "btclib.network.Network.__init__" in found

    # a private function taking an ec, a re-exported one, and one with no
    # ec at all
    assert "btclib.ecc.ellswift._ell_from_octets" not in found
    assert "btclib.ecc.dsa.sign" not in found
    assert "btclib.hashes.sha256" not in found
