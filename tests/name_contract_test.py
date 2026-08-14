# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for what a public function's name promises about its answer.

CONTRIBUTING.md's "Every public function validates its inputs" states the
vocabulary: `assert_*` refuses and returns None, `is_*` and `verify*`
answer a bool about a value of a declared type, and `check_*` answers a
bool *and* refuses what cannot be an answer -- the one prefix that warns
a caller it still needs an `except`.

This file is why the statement is worth making. `check_` had drifted to
four meanings at once -- nine refusals returning None, two verdicts, a
converter returning bytes and a query returning a pair of bools -- and a
prefix that says four things says nothing, which is what issue #814
found. Nothing in the tree noticed, because the vocabulary was a habit
and not a rule.

So it is a rule now, read off the annotations rather than off a list of
names somebody keeps in step. What it cannot see is the *contract*: that
`is_p2sh` is total over its values where `check_pub_key` is not is a
promise in prose, and only the return type is here.

`_OTHER_CONTRACT` is what the rule does not cover, one entry per reason.
It ratchets the way every list in `input_validation_test.py` does:
`test_what_is_excepted_still_needs_to_be` fails on an entry that has come
into line, so a name cannot keep an exemption it has stopped needing.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_LIBRARY = Path(__file__).parents[1] / "btclib"

# what each prefix promises the return type is. `verify` is matched
# anywhere in the name and not only at the front: `batch_verify_`,
# `partial_sig_verify` and `anti_exfil_host_verify` are verifications,
# and reading the front alone is what left them out of issue #814's first
# census
_PROMISED: dict[str, str] = {
    "assert_": "None",
    "check_": "bool",
    "is_": "bool",
    "verify": "bool",
}

# an op code implementation is named for the op code, and OP_VERIFY,
# OP_EQUALVERIFY and their kind carry the word: they answer with the
# stack, or with nothing, and are no more verifications in this sense
# than OP_CHECKSIG is a `check_`
_AN_OP_CODE = "op_"

_A_SCRIPT_FAILURE_SAYS_WHERE = (
    "the script engine refuses instead of answering: a ScriptError carries"
    " the command index and the stack depth, which is the whole of what an"
    " engine is asked for, and a bool would drop it"
)

_AN_ASSERT_WITH_A_PAYLOAD = (
    "it is the Signer's own question -- five conditions on the psbt, and"
    " the message they prove it commits to -- so refusing and handing back"
    " what was validated are one answer, not two"
)

_OTHER_CONTRACT: dict[str, str] = {
    "btclib.bip322.assert_signed_message": _AN_ASSERT_WITH_A_PAYLOAD,
    "btclib.script.engine.__init__.verify_amounts": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.__init__.verify_input": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.__init__.verify_transaction": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.script.verify_script": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.tapscript.verify_key_path": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.tapscript.verify_script_path_vc0": (
        _A_SCRIPT_FAILURE_SAYS_WHERE
    ),
}


# A bool need not carry one of the four prefixes: an English predicate is
# the same family and the same contract, and `is_` would cost the reading.
# Six of them, each with the reason it keeps the name it has -- and the
# ratchet below is what closes the vocabulary all the same, an entry that
# has gained a prefix being one this list no longer excuses (issue #814)
_ITS_STANDARD_SPELLING = (
    "the name is the standard's: BIP379's malleability analysis says a"
    " miniscript mixes timelocks and has duplicate keys, and the three"
    " PSBT_GLOBAL_TX_MODIFIABLE bits are named after the field"
)

_A_PREDICATE_WITH_A_SUBJECT = (
    "`reads_back` is the round trip as a question, and the subject is the"
    " script: `is_read_back` would ask who reads it"
)

_ENGLISH_PREDICATE: dict[str, str] = {
    "btclib.descriptors.miniscript.has_duplicate_keys": (_ITS_STANDARD_SPELLING),
    "btclib.descriptors.miniscript.mixes_timelocks": (_ITS_STANDARD_SPELLING),
    "btclib.descriptors.miniscript.reads_back": _A_PREDICATE_WITH_A_SUBJECT,
    "btclib.psbt.psbt.has_sig_hash_single": _ITS_STANDARD_SPELLING,
    "btclib.psbt.psbt.inputs_modifiable": _ITS_STANDARD_SPELLING,
    "btclib.psbt.psbt.outputs_modifiable": _ITS_STANDARD_SPELLING,
}


def _promised_by(name: str) -> str | None:
    """Return the type the name promises, or None if it promises nothing."""
    if name.startswith(_AN_OP_CODE):
        return None
    for prefix, promised in _PROMISED.items():
        if name.startswith(prefix) or (prefix == "verify" and prefix in name):
            return promised
    return None


def _named() -> dict[str, str]:
    """Return every public function whose name promises a return type.

    Methods included, a property being one: `BIP32KeyData.is_private`
    promises a bool as much as `script_pub_key.is_p2sh` does.

    The dotted name is the file's path and keeps the `__init__` of a
    package module, which is what `input_validation_test.py`'s walk does
    and is importable either way: one spelling across the two gates.
    """
    found: dict[str, str] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            if _promised_by(node.name) is None:
                continue
            # every function of this package is annotated, mypy running
            # strict over it, so an unannotated one is a state the tree
            # does not reach
            assert node.returns is not None
            found[f"{module}.{node.name}"] = ast.unparse(node.returns)
    return found


def _public_bools() -> list[str]:
    """Return every public function that answers a bool, however named.

    The dotted name drops the class, as `_named` above does: a method and
    a module function of one name are one entry, which is the spelling
    `input_validation_test.py` uses too.
    """
    found: list[str] = []
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            if node.returns is not None and ast.unparse(node.returns) == "bool":
                found.append(f"{module}.{node.name}")
    return sorted(found)


_NAMED = _named()
_GATED = sorted(set(_NAMED) - _OTHER_CONTRACT.keys())
_PUBLIC_BOOLS = _public_bools()


@pytest.mark.parametrize("dotted", _GATED)
def test_the_name_says_what_the_answer_is(dotted: str) -> None:
    """The rule, over every public name that carries one of the prefixes."""
    promised = _promised_by(dotted.rpartition(".")[2])
    assert _NAMED[dotted] == promised, (
        f"{dotted} returns {_NAMED[dotted]} where its name promises {promised}"
    )


@pytest.mark.parametrize("dotted", sorted(_OTHER_CONTRACT))
def test_what_is_excepted_still_needs_to_be(dotted: str) -> None:
    """An entry of `_OTHER_CONTRACT` cannot outlive the reason for it."""
    promised = _promised_by(dotted.rpartition(".")[2])
    assert _NAMED[dotted] != promised, (
        f"{dotted} now returns {promised}: delete its line from _OTHER_CONTRACT"
    )


def test_the_walk_reaches_what_it_claims() -> None:
    """One name per prefix it must find, and the two kinds it must not.

    A walk that found nothing would pass the test above.
    """
    assert _NAMED["btclib.script.script_pub_key.is_p2sh"] == "bool"
    assert _NAMED["btclib.script.engine.script.check_pub_key"] == "bool"
    assert _NAMED["btclib.script.taproot.check_output_pubkey"] == "bool"
    assert _NAMED["btclib.ecc.dsa.verify_"] == "bool"
    assert _NAMED["btclib.ecc.ssa.batch_verify"] == "bool"
    assert _NAMED["btclib.ecc.dsa.assert_as_valid"] == "None"
    # a method, and a property among them
    assert _NAMED["btclib.bip32.bip32.is_private"] == "bool"

    # an op code is named for the op code
    assert "btclib.script.engine.script_op_codes.op_verify" not in _NAMED
    assert "btclib.script.engine.script_op_codes.op_equalverify" not in _NAMED
    # a private name, and a name that promises nothing
    assert "btclib.hashes._assert_valid_hf" not in _NAMED
    assert "btclib.utils.bytes_from_octets" not in _NAMED


def test_check_says_one_thing() -> None:
    """`check_` is two functions, and issue #814 is why they are named.

    The prefix meant four things at once. Pinning what is left keeps a
    tenth `check_` from being added without the question being asked
    again: a refusal is an `assert_`, a converter is named for what it
    returns, and a query for what it answers.
    """
    checks = {d for d in _NAMED if d.rpartition(".")[2].startswith("check_")}
    assert checks == {
        "btclib.script.engine.script.check_pub_key",
        "btclib.script.taproot.check_output_pubkey",
    }


@pytest.mark.parametrize("dotted", _PUBLIC_BOOLS)
def test_every_public_bool_is_named_by_the_vocabulary(dotted: str) -> None:
    """A bool carries one of the four prefixes, or is named in the list.

    What this closes is the gap the prefixes alone leave: they promise a
    shape to a caller who sees one, and say nothing about a bool that
    carries none. Seven did before issue #814 -- four were renamed and
    three more were, `Block.is_segwit` joining the `Tx.is_segwit` it is
    computed from -- and the six that are left keep their names for the
    reason each entry gives.

    So a bool added from here on either carries a prefix or is a decision
    somebody wrote down, which is what `check_` drifting for four
    meanings cost the tree.
    """
    name = dotted.rpartition(".")[2]
    assert (
        _promised_by(name) is not None
        or name.startswith(_AN_OP_CODE)
        or dotted in _ENGLISH_PREDICATE
    ), f"{dotted} answers a bool and its name promises nothing"


@pytest.mark.parametrize("dotted", sorted(_ENGLISH_PREDICATE))
def test_what_keeps_its_english_name_still_needs_to(dotted: str) -> None:
    """A line of `_ENGLISH_PREDICATE` cannot outlive the name it excuses."""
    assert dotted in _PUBLIC_BOOLS, f"{dotted} is no longer a public bool"
    name = dotted.rpartition(".")[2]
    assert _promised_by(name) is None, (
        f"{dotted} carries a prefix now: delete its line from _ENGLISH_PREDICATE"
    )
