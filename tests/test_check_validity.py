#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `check_validity` convention.

`check_validity` is keyword-only throughout the package, which is a rule
about signatures rather than about any one of them: it appears in 91 of
them and is forwarded by hand from one to the next, so the guard has to be
the rule itself. A new signature spelling it positionally is what this
module fails on.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib

import pytest

from btclib.curves import secp256k1
from btclib.ecc import dsa
from btclib.exceptions import BTClibValueError
from btclib.script.script_pub_key import ScriptPubKey
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx

PACKAGE = pathlib.Path(__file__).parent.parent / "btclib"


def _signatures() -> list[tuple[str, int, str, list[str], list[str]]]:
    out = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = node.args
            positional = [a.arg for a in args.posonlyargs + args.args]
            keyword_only = [a.arg for a in args.kwonlyargs]
            if "check_validity" in positional + keyword_only:
                out.append(
                    (
                        str(path.relative_to(PACKAGE.parent)),
                        node.lineno,
                        node.name,
                        positional,
                        keyword_only,
                    )
                )
    return out


def test_check_validity_is_keyword_only() -> None:
    signatures = _signatures()

    # not an assertion about the number, which changes: an assertion that
    # the walk found the signatures at all, a broken one passing vacuously
    assert len(signatures) > 80

    offenders = [
        f"{path}:{lineno} {name}"
        for path, lineno, name, pos, _ in signatures
        if "check_validity" in pos
    ]
    assert not offenders, "check_validity must be keyword-only: " + ", ".join(offenders)


def test_check_validity_positional_is_a_type_error() -> None:
    """The hazard the rule exists for, in the four shapes it took.

    Passing it positionally used to work, so a signature growing a
    parameter before it silently moved the flag into another slot. It is a
    TypeError now, at the call rather than wherever the wrong value landed.
    """
    with pytest.raises(TypeError, match="positional argument"):
        Tx(1, 0, [], [], False)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="positional argument"):
        OutPoint(b"\x00" * 32, 0xFFFFFFFF, False)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="positional argument"):
        ScriptPubKey("", "mainnet", False)  # type: ignore[call-arg]
    # a dataclass: the flag was an InitVar field, so the generated
    # __init__ took it positionally and no star could reach it
    with pytest.raises(TypeError, match="positional argument"):
        dsa.Sig(1, 1, secp256k1, False)  # type: ignore[call-arg]


def test_check_validity_keyword_still_works() -> None:
    """Source-compatible for a caller that already used the keyword."""
    assert Tx(1, 0, [], [], check_validity=False).version == 1
    assert OutPoint(b"\x00" * 32, 0, check_validity=False).vout == 0
    assert ScriptPubKey("", "mainnet", check_validity=False).network == "mainnet"

    # and it still switches validation off, which is the whole point of it
    with pytest.raises(BTClibValueError, match="invalid OutPoint"):
        OutPoint(b"\x00" * 32, 0)


def test_dsa_sig_is_still_a_dataclass() -> None:
    """The three Sig classes trade InitVar for a written-out __init__.

    field(kw_only=True) is python 3.10 and this package supports 3.9, so
    the InitVar and its __post_init__ are gone. What the dataclass
    generates around them must not be.
    """
    r = 0x2B698A0F0A4041059B5C617F42B2B90D68F0F27F8B8F1CBA0D7D8F0B4D4B7C1A
    s = 0x1BE0DFEF2E4DAB1F4BFAF0C36F9E1DDA1E92BCEA6D8D9AFB0BE1DAF9E5BE3C57
    sig = dsa.Sig(r, s)

    assert [f.name for f in dataclasses.fields(sig)] == ["r", "s", "ec"]
    assert sig == dsa.Sig(r, s)
    assert hash(sig) == hash(dsa.Sig(r, s))
    assert dataclasses.replace(sig, s=s) == sig
    assert "check_validity" not in repr(sig)

    # frozen, as it was: the hand-written __init__ assigns through
    # object.__setattr__, which must not leave the class writable
    with pytest.raises(dataclasses.FrozenInstanceError):
        sig.r = 1  # type: ignore[misc]


def test_strict_became_keyword_only_too() -> None:
    """dsa.Sig.parse is the one signature with a parameter after the flag.

    Starring check_validity makes `strict` keyword-only as well. The
    alternative, moving `strict` in front of the star, would have made
    `Sig.parse(data, False)` mean strict=False where it used to mean
    check_validity=False -- silently, which is the failure mode this whole
    change is against.
    """
    sig_bytes = "3006020180020180"
    assert dsa.Sig.parse(sig_bytes, check_validity=False, strict=False).r == 0x80
    with pytest.raises(TypeError, match="positional argument"):
        dsa.Sig.parse(sig_bytes, False, False)  # type: ignore[call-arg]


def test_a_parameter_before_the_flag_stays_positional() -> None:
    """Only check_validity moved behind the star: what precedes it did not.

    Tx.serialize is the case that shows it, include_witness being a
    positional parameter of a signature that carries the flag.
    """
    tx = Tx(1, 0, [], [], check_validity=False)
    assert tx.serialize(False, check_validity=False) == tx.serialize(
        include_witness=False, check_validity=False
    )
