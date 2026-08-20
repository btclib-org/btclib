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

The first half is the whole of the table below. The second half is
answered in two places and not in the table, because **every curve is a
valid ec** -- that is what the parameter is for, and the low-cardinality
curves of `curve_test.py` are the proof that no value of the type is
refused for being unusual. What can be wrong is a curve the *key* names:
an xprv, an xpub or a WIF carries a network, and a network has a curve,
so a mismatch there is a fact about the pair and a `BTClibValueError`.
`test_the_curve_a_key_names_is_still_a_value` is that half, and it is in
this file because the guard sits in front of those comparisons: an ec of
no curve type compares unequal to every network's curve, which is the one
place where the type rule taking over is the point rather than a side
effect -- a caller's own mistake would otherwise be reported as a
statement about the key.

A `bool` answer is no exemption from the first half either:
`borromean.verify` and `pedersen.verify` answer `False` about a
commitment or a ring, not about the curve they were told to work in, and
their `except (ValueError, BTClibRuntimeError)` lets a `BTClibTypeError`
through for the same reason `dsa.verify` does.

## The walk is what makes the table complete

`_curve_parameters` reads every public function of the package whose
signature declares a `Curve` or a `CurveGroup`, so
`test_the_table_is_every_curve_parameter` fails on a function this file
does not drive -- a new one, or one that gains the parameter. There is no
exemption list, and that is the state to keep.

Arguments go in by keyword, which is what lets one driver replace `ec`
in every call whatever its position: `ec` is the last parameter of the
`curves` functions, the fifth of `dsa.sign_` and the first of the two
group explorers, and none of these signatures has a positional-only
parameter.

## Where the walk finds nothing on purpose

`parse` and `serialize` never declare `ec`, so the whole family is
absent from the table below -- not an omission, a rule:
`serialization_boundary_test.py`'s module docstring states it and why,
and `test_the_family_takes_no_ec_or_hf` is its gate (issue #1084).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from btclib.b58 import wif_from_prv_key
from btclib.bip32.bip32 import BIP32KeyData, rootxprv_from_seed, xpub_from_xprv
from btclib.curves import CurveGroup, secp256k1
from btclib.curves.curve import (
    Curve,
    PreparedPoint,
    _TweakChain,
    double_mult_var,
    mult,
    multi_mult_var,
)
from btclib.curves.curve_group_f import find_all_points, find_subgroup_points
from btclib.curves.sec_point import (
    bytes_from_point,
    bytes_from_prv_key_int,
    point_from_octets,
)
from btclib.ecc import borromean, dsa, ellswift, pedersen, ssa
from btclib.ecc.bip340_nonce import bip340_nonce_
from btclib.ecc.commit_nonce import commit_nonce_, commit_point_
from btclib.ecc.dh import diffie_hellman
from btclib.ecc.rfc6979_nonce import challenge_, rfc6979_nonce_
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import NETWORKS, Network
from btclib.to_prv_key import int_from_prv_key
from btclib.to_pub_key import point_from_key, point_from_pub_key
from tests.curves.curve_test import low_card_curves

_LIBRARY = Path(__file__).parents[1] / "btclib"

# a value of no type any `ec` declares, and both are calls mypy refuses
_WRONG_TYPES: tuple[Any, ...] = (None, 1.5)

_PRV_KEY = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
_PRV_KEY_2, _PUB_KEY_2 = dsa.gen_keys(_PRV_KEY + 1)
_PUB_KEY = mult(_PRV_KEY)
_SEC = bytes_from_point(_PUB_KEY)
_MSG = b"Satoshi Nakamoto"
_MSG_HASH = sha256(_MSG).digest()
_DSA_SIG = dsa.sign(_MSG, _PRV_KEY)
_SSA_SIG = ssa.sign(_MSG, _PRV_KEY)
_ELL = ellswift.encode_var(_PUB_KEY)
_ELL_2 = ellswift.encode_var(_PUB_KEY_2)
_COMMITMENT = pedersen.commit(1, 2)

# two rings of two keys, the smallest borromean signature there is: what
# this file asks of it is the curve, and a wider ring would only be a
# slower way of asking
_RING_KEYS = [dsa.gen_keys(_PRV_KEY + i) for i in range(2, 6)]
_PUBK_RINGS = [
    [_RING_KEYS[0][1], _RING_KEYS[1][1]],
    [_RING_KEYS[2][1], _RING_KEYS[3][1]],
]
_SIGN_KEY_IDX = [0, 1]
_SIGN_KEYS = [_RING_KEYS[0][0], _RING_KEYS[3][0]]
_E0, _S = borromean.sign(_MSG, [1, 2], _SIGN_KEY_IDX, _SIGN_KEYS, _PUBK_RINGS)

# the two group explorers walk every point, so their ec is a group small
# enough to be walked -- and a CurveGroup, which is the type they declare:
# it has p, a and b and neither the n nor the G a Curve adds
_GROUP = CurveGroup(13, 0, 2)
_GROUP_G = (1, 9)

# every field of mainnet but its curve, in the hex spelling to_dict writes
# and the constructor takes
_NETWORK_ARGS = {
    key: value for key, value in NETWORKS["mainnet"].to_dict().items() if key != "curve"
}


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
    _Case("btclib.curves.curve.mult", mult, {"m_int": _PRV_KEY, "Q": _PUB_KEY}),
    # the constructor, `point` being what it calls the argument the
    # multiplications call Q: the guard runs before the point is looked
    # at, as everywhere else here
    _Case(
        "btclib.curves.curve.PreparedPoint.__init__",
        PreparedPoint,
        {"point": _PUB_KEY},
    ),
    # the other constructor holding a point across calls, private and
    # driven here all the same: the walk finds it, its `__init__` being a
    # dunder, and a function the walk finds is one this table drives
    _Case(
        "btclib.curves.curve._TweakChain.__init__",
        _TweakChain,
        {"base": _PUB_KEY},
    ),
    _Case(
        "btclib.curves.curve.double_mult_var",
        double_mult_var,
        {"u": _PRV_KEY, "H": _PUB_KEY, "v": _PRV_KEY_2, "Q": _PUB_KEY_2},
    ),
    _Case(
        "btclib.curves.curve.multi_mult_var",
        multi_mult_var,
        {"scalars": [_PRV_KEY, _PRV_KEY_2], "points": [_PUB_KEY, _PUB_KEY_2]},
    ),
    _Case("btclib.curves.curve_group_f.find_all_points", find_all_points, ec=_GROUP),
    _Case(
        "btclib.curves.curve_group_f.find_subgroup_points",
        find_subgroup_points,
        {"G": _GROUP_G},
        ec=_GROUP,
    ),
    _Case(
        "btclib.curves.sec_point.bytes_from_point",
        bytes_from_point,
        {"Q": _PUB_KEY},
    ),
    _Case(
        "btclib.curves.sec_point.bytes_from_prv_key_int",
        bytes_from_prv_key_int,
        {"prv_key_int": _PRV_KEY},
    ),
    _Case(
        "btclib.curves.sec_point.point_from_octets",
        point_from_octets,
        {"pub_key": _SEC},
    ),
    _Case(
        "btclib.ecc.bip340_nonce.bip340_nonce_",
        bip340_nonce_,
        {"msg": _MSG, "prv_key": _PRV_KEY},
    ),
    _Case(
        "btclib.ecc.borromean.sign",
        borromean.sign,
        {
            "msg": _MSG,
            "ks": [1, 2],
            "sign_key_idx": _SIGN_KEY_IDX,
            "sign_keys": _SIGN_KEYS,
            "pubk_rings": _PUBK_RINGS,
        },
    ),
    _Case(
        "btclib.ecc.borromean.verify",
        borromean.verify,
        {"msg": _MSG, "e0": _E0, "s": _S, "pubk_rings": _PUBK_RINGS},
    ),
    _Case(
        "btclib.ecc.borromean.assert_as_valid",
        borromean.assert_as_valid,
        {"msg": _MSG, "e0": _E0, "s": _S, "pubk_rings": _PUBK_RINGS},
    ),
    _Case(
        "btclib.ecc.commit_nonce.commit_nonce_",
        commit_nonce_,
        {"commit_hash": _MSG_HASH, "nonce": _PRV_KEY, "tag": b"tag"},
    ),
    _Case(
        "btclib.ecc.commit_nonce.commit_point_",
        commit_point_,
        {"commit_hash": _MSG_HASH, "receipt": _PUB_KEY, "tag": b"tag"},
    ),
    _Case(
        "btclib.ecc.dh.diffie_hellman",
        diffie_hellman,
        {"dU": _PRV_KEY, "QV": _PUB_KEY_2, "size": 32},
    ),
    _Case(
        "btclib.ecc.dsa.Sig.__init__",
        dsa.Sig,
        {"r": _DSA_SIG.r, "s": _DSA_SIG.s},
    ),
    _Case(
        "btclib.ecc.dsa.Signer.__init__",
        dsa.Signer,
        {"prv_key": _PRV_KEY},
    ),
    _Case("btclib.ecc.dsa.gen_keys", dsa.gen_keys, {"prv_key": _PRV_KEY}),
    # the same function with the key it draws itself, which is the branch
    # that reads n off the curve rather than reaching int_from_prv_key
    _Case(
        "btclib.ecc.dsa.gen_keys",
        dsa.gen_keys,
        {"prv_key": None},
        label="btclib.ecc.dsa.gen_keys(None)",
    ),
    _Case(
        "btclib.ecc.dsa.sign_", dsa.sign_, {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY}
    ),
    _Case("btclib.ecc.dsa.sign", dsa.sign, {"msg": _MSG, "prv_key": _PRV_KEY}),
    _Case(
        "btclib.ecc.dsa.sign_recoverable_",
        dsa.sign_recoverable_,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY},
    ),
    _Case(
        "btclib.ecc.dsa.sign_recoverable",
        dsa.sign_recoverable,
        {"msg": _MSG, "prv_key": _PRV_KEY},
    ),
    _Case(
        "btclib.ecc.dsa.anti_exfil_signer_commit",
        dsa.anti_exfil_signer_commit,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY, "host_commitment": _MSG_HASH},
    ),
    _Case(
        "btclib.ecc.dsa.anti_exfil_sign",
        dsa.anti_exfil_sign,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY, "rho": _MSG_HASH},
    ),
    _Case("btclib.ecc.ellswift.create_var", ellswift.create_var, {"prv_key": _PRV_KEY}),
    _Case("btclib.ecc.ellswift.encode_var", ellswift.encode_var, {"pub_key": _PUB_KEY}),
    _Case("btclib.ecc.ellswift.decode_var", ellswift.decode_var, {"ell": _ELL}),
    _Case(
        "btclib.ecc.ellswift.xdh",
        ellswift.xdh,
        {"ell_a": _ELL, "ell_b": _ELL_2, "prv_key": _PRV_KEY, "party": 0},
    ),
    _Case("btclib.ecc.pedersen.second_generator", pedersen.second_generator),
    _Case("btclib.ecc.pedersen.commit", pedersen.commit, {"r": 1, "v": 2}),
    _Case(
        "btclib.ecc.pedersen.assert_as_valid",
        pedersen.assert_as_valid,
        {"r": 1, "v": 2, "commitment": _COMMITMENT},
    ),
    _Case(
        "btclib.ecc.pedersen.verify",
        pedersen.verify,
        {"r": 1, "v": 2, "commitment": _COMMITMENT},
    ),
    _Case("btclib.ecc.rfc6979_nonce.challenge_", challenge_, {"msg_hash": _MSG_HASH}),
    _Case(
        "btclib.ecc.rfc6979_nonce.rfc6979_nonce_",
        rfc6979_nonce_,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY},
    ),
    _Case(
        "btclib.ecc.ssa.Sig.__init__",
        ssa.Sig,
        {"r": _SSA_SIG.r, "s": _SSA_SIG.s},
    ),
    _Case(
        "btclib.ecc.ssa.Signer.__init__",
        ssa.Signer,
        {"prv_key": _PRV_KEY},
    ),
    _Case(
        "btclib.ecc.ssa.point_from_bip340pub_key",
        ssa.point_from_bip340pub_key,
        {"x_Q": _PUB_KEY[0]},
    ),
    _Case("btclib.ecc.ssa.gen_keys", ssa.gen_keys, {"prv_key": _PRV_KEY}),
    _Case(
        "btclib.ecc.ssa.gen_keys",
        ssa.gen_keys,
        {"prv_key": None},
        label="btclib.ecc.ssa.gen_keys(None)",
    ),
    # ec and hf are required here, this being the prepared-challenge
    # spelling BIP340 verification is built on
    _Case(
        "btclib.ecc.ssa.challenge_",
        ssa.challenge_,
        {"msg": _MSG, "x_Q": _PUB_KEY[0], "x_K": _SSA_SIG.r, "hf": sha256},
    ),
    _Case("btclib.ecc.ssa.sign_", ssa.sign_, {"msg": _MSG, "prv_key": _PRV_KEY}),
    _Case("btclib.ecc.ssa.sign", ssa.sign, {"msg": _MSG, "prv_key": _PRV_KEY}),
    _Case(
        "btclib.to_prv_key.int_from_prv_key",
        int_from_prv_key,
        {"prv_key": _PRV_KEY},
    ),
    _Case("btclib.to_pub_key.point_from_key", point_from_key, {"key": _SEC}),
    _Case(
        "btclib.to_pub_key.point_from_pub_key", point_from_pub_key, {"pub_key": _SEC}
    ),
    # the one curve parameter that is a field rather than an argument to
    # compute with, and the one not called `ec`. `to_dict`'s keys are the
    # constructor's parameter names, the curve excepted -- it goes out as a
    # name and comes back as the catalogued curve -- so the valid call is
    # mainnet rebuilt from its own dict
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

    A method counts, `dsa.Sig.__init__` and `ssa.Sig.__init__` being two
    of them, and a private function does not: the guard is what those call.
    An `@overload` stub is not a function to drive -- `dsa.sign_` has
    three of them in front of the one implementation, and driving a stub
    would be driving `...`.
    """
    found: set[str] = set()

    def walk(node: ast.Module | ast.ClassDef, module: str, prefix: str) -> None:
        for child in node.body:
            if isinstance(child, ast.ClassDef):
                walk(child, module, f"{prefix}{child.name}.")
            elif isinstance(child, ast.FunctionDef):
                if child.name.startswith("_") and not child.name.startswith("__"):
                    continue
                if any(ast.unparse(d) == "overload" for d in child.decorator_list):
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
    refuses here, which is the whole reason `curve._assert_valid_ec` asks
    for the subclass: the group has p, a and b, so a check spelled against
    it would pass an ec that the very next line reads an `n` or a `G` off.
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
    """The shapes the walk must find, and the three it must not.

    A walk that found nothing would pass the test above.
    """
    found = _curve_parameters()
    # a defaulted ec, a required one, and a constructor's
    assert "btclib.ecc.dsa.sign" in found
    assert "btclib.curves.curve_group_f.find_all_points" in found
    assert "btclib.ecc.dsa.Sig.__init__" in found

    # the guards themselves, which take an ec and are what the rest call
    assert "btclib.curves.curve._assert_valid_ec" not in found
    assert "btclib.curves.curve_group._assert_valid_ec" not in found
    # a function of another name, and one with no ec at all
    assert "btclib.ecc.dsa.verify" not in found
    assert "btclib.hashes.sha256" not in found


def test_the_curve_a_key_names_is_still_a_value() -> None:
    """The second rule, which is the one the guard sits in front of.

    A key that names a network names its curve, so an ec that is not that
    curve is a fact about the pair and a `BTClibValueError`. All three
    compare rather than parse, which is why the type check comes first: an
    ec of no curve type compares unequal to every network's curve, so
    without it a caller's own mistake leaves as this same mismatch -- a
    statement about the key, about which nothing was wrong.
    """
    ec = low_card_curves["ec23_31"]

    # derived rather than written out: what makes it a mainnet WIF is the
    # network, which is the whole of what this test is about
    wif = wif_from_prv_key(_PRV_KEY)
    with pytest.raises(BTClibValueError, match="ec / network"):
        int_from_prv_key(wif, ec)
    with pytest.raises(BTClibValueError, match="Curve mismatch"):
        point_from_key(wif, ec)

    # the parsed form, and not the string it b58decodes from: a spelling
    # this converter has to guess at is tried as octets after the xkey
    # branch declines it, so the mismatch is reported as "not a public
    # key" -- the pair is what is wrong, and which of the two spellings
    # says so is `point_from_pub_key`'s own business
    xpub = BIP32KeyData.b58decode(xpub_from_xprv(rootxprv_from_seed("00" * 32)))
    with pytest.raises(BTClibValueError, match="ec/xpub version"):
        point_from_pub_key(xpub, ec)
