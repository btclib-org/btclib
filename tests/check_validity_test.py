# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `check_validity` convention.

`check_validity` is keyword-only throughout the package, which is a rule
about signatures rather than about any one of them: it is the flag most of
them carry, and it is forwarded by hand from one to the next, so the guard
has to be the rule itself. A new signature spelling it positionally is
what this module fails on.

How many carry it is not written down here, because a number in prose
drifts where a walk does not: this file said 91 for as long as the tree
kept growing past it. `_signatures` is what answers instead, and
`len(_signatures())` is the count whenever one is wanted.

What the flag *does* when nobody passes it is the other half, and the same
kind of rule: every default is True, so a caller who says nothing gets the
check. Nothing held any of those defaults to it -- the mutation profile of
issue #327 reported one survivor per default and per `if check_validity:`
in `btclib/tx/` -- and the tests at the end of this module are what does,
over the wire-format classes that profile measures.

Which of the three boundaries a class can be asked about is not this
file's to decide, and the exclusion sets below are not where that rule
is written: it is in `btclib/utils.py`, beside the parse contract, and a
class missing from one of these lists is a class whose invariants its
encoding already enforces rather than one nobody got round to.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
from typing import Any

import pytest
from typing_extensions import override

from btclib.amount import _MAX_SATOSHI
from btclib.curves import secp256k1
from btclib.ecc import dsa
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import Witness
from btclib.script.script_pub_key import ScriptPubKey
from btclib.tx import TxIn, TxOut
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx

PACKAGE = pathlib.Path(__file__).parent.parent / "btclib"


def _signatures() -> list[tuple[str, int, str, list[str], list[str]]]:
    """Return every btclib signature that takes check_validity."""
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
    """Verify no signature takes check_validity positionally."""
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
    """The hazard the rule exists for, in four shapes.

    Were the flag positional, a signature growing a parameter before it
    would silently move it into another slot. As a TypeError it fails at
    the call, rather than wherever the wrong value landed.
    """
    with pytest.raises(TypeError, match="positional argument"):
        Tx(1, 0, [], [], False)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="positional argument"):
        OutPoint(b"\x00" * 32, 0xFFFFFFFF, False)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="positional argument"):
        ScriptPubKey("", "mainnet", False)  # type: ignore[call-arg]
    # a dataclass: a generated __init__ takes an InitVar positionally and
    # no star can reach it, hence the written-out constructor
    with pytest.raises(TypeError, match="positional argument"):
        dsa.Sig(1, 1, secp256k1, False)  # type: ignore[call-arg]


def test_check_validity_keyword_still_works() -> None:
    """Source-compatible for a caller that already used the keyword."""
    assert Tx(1, 0, [], [], check_validity=False).version == 1
    assert OutPoint(b"\x00" * 31, 0, check_validity=False).vout == 0
    assert ScriptPubKey("", "mainnet", check_validity=False).network == "mainnet"

    # and it still switches validation off, which is the whole point of it
    with pytest.raises(BTClibValueError, match="invalid OutPoint tx_id"):
        OutPoint(b"\x00" * 31, 0)


def test_dsa_sig_is_still_a_dataclass() -> None:
    """The three Sig classes trade InitVar for a written-out __init__.

    The InitVar and its __post_init__ are gone -- from every signature
    that takes the flag, not only these three -- so what the dataclass
    generates around them is all that is left to check, and it must not
    go too. field(kw_only=True) would express the same thing in fewer
    lines and is available now that 3.10 is the floor; it is not used,
    because using it in three of the many is the inconsistency the
    written-out constructors removed.
    """
    r = 0x2B698A0F0A4041059B5C617F42B2B90D68F0F27F8B8F1CBA0D7D8F0B4D4B7C1A
    s = 0x1BE0DFEF2E4DAB1F4BFAF0C36F9E1DDA1E92BCEA6D8D9AFB0BE1DAF9E5BE3C57
    sig = dsa.Sig(r, s)

    assert [f.name for f in dataclasses.fields(sig)] == ["r", "s", "ec"]
    assert sig == dsa.Sig(r, s)
    assert hash(sig) == hash(dsa.Sig(r, s))
    assert dataclasses.replace(sig, s=s) == sig
    assert "check_validity" not in repr(sig)

    # frozen: the hand-written __init__ assigns through
    # object.__setattr__, which must not leave the class writable
    with pytest.raises(dataclasses.FrozenInstanceError):
        sig.r = 1  # type: ignore[misc]


def test_strict_became_keyword_only_too() -> None:
    """dsa.Sig.parse is the one signature with a parameter after the flag.

    Starring check_validity makes `strict` keyword-only as well. The
    alternative, `strict` in front of the star, would silently turn a
    caller's `Sig.parse(data, False)` from check_validity=False into
    strict=False -- the failure mode this whole rule is against.
    """
    sig_bytes = "3006020180020180"
    assert dsa.Sig.parse(sig_bytes, check_validity=False, strict=False).r == 0x80
    with pytest.raises(TypeError, match="positional argument"):
        dsa.Sig.parse(sig_bytes, False, False)  # type: ignore[call-arg]


def test_a_parameter_before_the_flag_stays_positional() -> None:
    """Only check_validity sits behind the star: what precedes it does not.

    Tx.serialize is the case that shows it, include_witness being a
    positional parameter of a signature that carries the flag.
    """
    tx = Tx(1, 0, [], [], check_validity=False)
    assert tx.serialize(False, check_validity=False) == tx.serialize(
        include_witness=False, check_validity=False
    )


# an outpoint whose vout is a bool, which `is_integer` refuses: a bool is
# an int, so it passes every range check, and naming the type is the
# whole of what assert_valid has to say about it. What it stands in for
# is nothing: an `OutPoint` has no invalidity of *value* left to be
# asked about, 32 octets of tx_id and four of vout being an outpoint
# whatever they hold, and a `TxIn` has no child that has one. The rule
# that makes that a type in good order rather than a class missing a
# check is written down in `btclib/utils.py`, beside the parse contract
# it belongs to; here it is why neither class has a case of its own, and
# why the transaction below has to reach for a bool to have one
_BOOL_VOUT = OutPoint(b"\x01" * 32, True, check_validity=False)
_GOOD_OUT_POINT = OutPoint(b"\x01" * 32, 0)

# invalid objects, built with the check off, and two shapes of invalid
# rather than one because they answer different questions.
#
# `-itself` is invalid at that class's own boundary, which is what holds the
# class's own guard: a parent forwards the flag to its children, so an object
# invalid only in a child is refused by the child whatever the parent does --
# take `if check_validity:` out of `TxIn.serialize` and the
# `prev_out.serialize` below it raises in its place, a green suite about
# nothing.
#
# `-nested` is invalid in a child, which is what holds the
# `check_validity=False` a parent hands its children: turned True, that inner
# call refuses an object the outer call was told not to look at. It is also
# the only shape `parse` can be asked about, for the reason beside
# _NO_OCTETS.
#
# Every one of them is invalid in a way the conversions do not notice: a
# sequence of `True`, a transaction without inputs and an amount over
# MoneyRange all serialize, so what refuses them is the flag and not the
# arithmetic underneath
_INVALID: list[tuple[str, Any]] = [
    ("tx_in-itself", TxIn(_GOOD_OUT_POINT, b"", True, check_validity=False)),
    ("tx_out", TxOut(_MAX_SATOSHI + 1, "", check_validity=False)),
    ("tx-itself", Tx(1, 0, [], [TxOut(1, "")], check_validity=False)),
    # two nested transactions and not one, because the two boundaries
    # cannot be asked about the same child: an invalid vout survives
    # to_dict and not serialize, an invalid amount serialize and not
    # to_dict, and the exclusion lists below are where each says so
    (
        "tx-nested-in",
        Tx(
            1,
            0,
            [TxIn(_BOOL_VOUT, check_validity=False)],
            [TxOut(1, "")],
            check_validity=False,
        ),
    ),
    (
        "tx-nested-out",
        Tx(
            1,
            0,
            [TxIn(_GOOD_OUT_POINT)],
            [TxOut(_MAX_SATOSHI + 1, "", check_validity=False)],
            check_validity=False,
        ),
    ),
]

# what a `parse` cannot be asked, and why: a bool reads back as the number
# it is -- a sequence of `True` and a vout of `True` both as one, which is
# valid -- and a transaction without inputs has no octets to read back at
# all, the input count being where the segwit marker lives, so its `\x00`
# opens a witness section rather than an empty list.
#
# That takes everything holding a bool out of the octets test, and
# `tx-nested-out` is what keeps a nested case in it: an amount above
# MoneyRange survives the round trip, eight little-endian bytes carrying
# it, and `Tx.assert_valid` reaches it through `tx_out.assert_valid()`
# before the total it would also refuse
_NO_OCTETS = {"tx_in-itself", "tx-itself", "tx-nested-in"}

# and what a dict cannot be asked. TxOut's only validity question is the
# amount, and `to_dict` puts that amount through `btc_from_sats`, which is
# `valid_sats_amount` -- the conversion asks what assert_valid would ask, so
# there is no answer the flag could change. The last test below is that
# exclusion, stated as a test rather than as prose here, and
# `tx-nested-out` is excluded by it too, that conversion running on the
# output it nests whatever the transaction was told
_NO_DICT = {"tx_out", "tx-nested-out"}

_OCTETS = [case for case in _INVALID if case[0] not in _NO_OCTETS]
_DICTS = [case for case in _INVALID if case[0] not in _NO_DICT]


def _serialize(obj: Any, **flag: bool) -> bytes:
    """Return the wire octets, `include_witness` being Tx's own parameter.

    The flag is forwarded and never spelled: a default written here would
    be a copy of the one under test, and the call with nothing to forward
    is the case that matters.
    """
    if isinstance(obj, Tx):
        return obj.serialize(include_witness=True, **flag)
    octets: bytes = obj.serialize(**flag)
    return octets


@pytest.mark.parametrize("name, invalid", _INVALID, ids=[c[0] for c in _INVALID])
def test_the_default_checks_the_object_it_is_asked_about(
    name: str, invalid: Any
) -> None:
    """Serialize refuses an object its own class calls invalid.

    And writes it when the caller says so, which is the half that says the
    flag still switches the check off rather than the half that says it is
    there.
    """
    assert name  # the id of the case, so a failure names it

    assert _serialize(invalid, check_validity=False)
    with pytest.raises((BTClibValueError, BTClibTypeError)):
        _serialize(invalid)


@pytest.mark.parametrize("name, invalid", _OCTETS, ids=[c[0] for c in _OCTETS])
def test_the_default_checks_the_octets_it_reads(name: str, invalid: Any) -> None:
    """Parse refuses octets that decode to an invalid object.

    The other direction of the same boundary, and the one somebody else's
    bytes arrive through.
    """
    assert name

    octets = _serialize(invalid, check_validity=False)

    assert type(invalid).parse(octets, check_validity=False)
    with pytest.raises((BTClibValueError, BTClibTypeError)):
        type(invalid).parse(octets)


@pytest.mark.parametrize("name, invalid", _DICTS, ids=[c[0] for c in _DICTS])
def test_the_default_checks_the_dict_it_writes_and_reads(
    name: str, invalid: Any
) -> None:
    """to_dict and from_dict validate unless the caller says not to.

    The json boundary, where the default matters most: `from_dict` is what
    reads a value somebody else wrote.
    """
    assert name

    dict_ = invalid.to_dict(check_validity=False)
    with pytest.raises((BTClibValueError, BTClibTypeError)):
        invalid.to_dict()

    assert type(invalid).from_dict(dict_, check_validity=False)
    with pytest.raises((BTClibValueError, BTClibTypeError)):
        type(invalid).from_dict(dict_)


def test_a_nested_object_is_left_the_flag_it_was_given() -> None:
    """The `check_validity=False` a parent hands its children is theirs.

    Turned True, that inner call refuses an object the outer call was told
    not to look at -- and a subclass is where the invariant that shows it
    lives, `Witness`, `TxOut` and `TxIn` all being public and not final. The
    base classes cannot say so: an empty witness has nothing to reject, and
    a TxOut's only question is an amount its own conversion asks whatever
    the flag says, which is the test below.

    Held through the two constructors that build `cls` rather than a named
    class, too, since a subclass is what they are `cls` for.
    """

    class RejectingWitness(Witness):
        @override
        def assert_valid(self) -> None:
            raise BTClibValueError("invalid witness")

    class RejectingTxOut(TxOut):
        @override
        def assert_valid(self) -> None:
            raise BTClibValueError("invalid output")

    tx_in = TxIn(
        _GOOD_OUT_POINT,
        b"",
        0,
        RejectingWitness(check_validity=False),
        check_validity=False,
    )
    tx_out = RejectingTxOut(1, "", check_validity=False)
    tx = Tx(1, 0, [TxIn(_GOOD_OUT_POINT)], [tx_out], check_validity=False)

    for obj, err_msg in (
        (tx_in, "invalid witness"),
        (tx_out, "invalid output"),
        (tx, "invalid output"),
    ):
        assert obj.to_dict(check_validity=False)
        with pytest.raises(BTClibValueError, match=err_msg):
            obj.to_dict()

    dict_ = tx_out.to_dict(check_validity=False)
    assert RejectingTxOut.from_dict(dict_, check_validity=False).value == 1
    with pytest.raises(BTClibValueError, match="invalid output"):
        RejectingTxOut.from_dict(dict_)

    octets = tx_out.serialize(check_validity=False)
    assert RejectingTxOut.parse(octets, check_validity=False).value == 1
    with pytest.raises(BTClibValueError, match="invalid output"):
        RejectingTxOut.parse(octets)


def test_a_base_tx_out_dict_refuses_the_amount_either_way() -> None:
    """The exclusion above, and why it is one rather than an oversight.

    A base TxOut is valid when its amount is, and the dict form of an amount
    is BTC: `to_dict` calls `btc_from_sats` and `from_dict` calls
    `sats_from_btc`, each of which validates the amount on its own. So for
    this class the flag has nothing left to switch off, and the refusal below
    is the conversion's rather than assert_valid's -- which is what the
    subclass above answers for, an invariant of its own being the thing a
    conversion cannot ask.
    """
    invalid = TxOut(_MAX_SATOSHI + 1, "", check_validity=False)
    for check_validity in (True, False):
        with pytest.raises(BTClibValueError, match="invalid satoshi amount: "):
            invalid.to_dict(check_validity=check_validity)

    over = {"value": "21000000.00000001", "scriptPubKey": {"asm": "", "hex": ""}}
    for check_validity in (True, False):
        with pytest.raises(BTClibValueError, match="invalid BTC amount: "):
            TxOut.from_dict(over, check_validity=check_validity)

    # and what neither refusal takes with it: the octets, where the amount
    # is eight bytes and `serialize` is the only reader of the flag
    assert invalid.serialize(check_validity=False)
