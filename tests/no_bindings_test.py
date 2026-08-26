# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""btclib with btclib_secp256k1 not installed, which is a subprocess.

`btclib._libsecp256k1` asks for the bindings once, at import, and
`curves.curve._libsecp256k1_available` is that answer; so the question
this file asks -- does the library import and answer without them -- can
only be asked of an interpreter that has not imported btclib yet. A
monkeypatch cannot: by the time a test runs, the import has happened and
its answer is bound.

Uninstalling them is not an option either, the suite being one
environment. So the bindings are put out of reach by a meta path finder
that refuses the name, in a child interpreter, and btclib is imported
after that -- which is what `import btclib` does on a machine that never
had them.

This is not the CI job of issue #991 and does not replace it: a finder
that refuses one name leaves the wheel installed and the environment
resolved, where the job installs neither. What it does is make the
absent-bindings configuration answerable in the ordinary suite, on every
platform the matrix runs, rather than only where a second install exists.

What the child returns is compared with what this process computes with
the bindings in reach: agreement between the two implementations is the
property, and a child that merely fails to crash proves nothing about it.

`test_the_two_arms_refuse_the_same_inputs` asks the same question of a
refusal: `tests/py_arm_authority_test.py` counts which vectors reach
each arm and never compares them, and the test above compares only what
both arms compute successfully, so neither would have caught issue
#1227 -- a hybrid taproot internal key answered on one arm and raised
on the other, one input and two answers decided by `pip install`
rather than by btclib. A second child, built the same way, runs a
table of inputs the tree already knows once diverged this way and
compares what each arm refuses them with.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from typing import Any

import pytest

from btclib._libsecp256k1 import ENABLED, INSTALLED, NO_LIBSECP256K1
from btclib.bip32.bip32 import derive, rootxprv_from_seed, xpub_from_xprv
from btclib.curves import (
    bytes_from_point,
    curve,
    is_libsecp256k1_serving,
    mult,
    set_libsecp256k1_serving,
)
from btclib.ecc import dsa, ssa
from btclib.exceptions import BTClibException, BTClibValueError
from btclib.script.taproot import output_pubkey
from tests import needs_bindings

# the seed, key and message the child works from: constants, because the
# two processes have to be asked the same question
_SEED = "0f" * 32
_PRV_KEY = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
_MSG_HASH = bytes(range(32))
_DERIVATION = "m/44h/0h/0h/0/7"
# BIP340 signing is randomized where the caller names no aux -- `sign_`
# draws `secrets.token_bytes` for it, which is BIP340's own *Default
# Signing* -- so the two processes are given the same aux and compared
# octet for octet. ECDSA needs no such argument, RFC6979 making the
# nonce a function of the message and the key
_AUX = bytes(32)

# what the child runs: the finder first, btclib after it, and the answers
# as json on stdout. `-c` and not a file, so that nothing has to be
# written to disk and cleaned up
_CHILD = """
import json, sys


class RefuseTheBindings:
    def find_spec(self, name, path=None, target=None):
        if name == "btclib_secp256k1" or name.startswith("btclib_secp256k1."):
            raise ImportError("btclib_secp256k1 is out of reach")
        return None


sys.meta_path.insert(0, RefuseTheBindings())

import btclib
from btclib._libsecp256k1 import ENABLED, INSTALLED, NO_LIBSECP256K1
from btclib.bip32.bip32 import derive, rootxprv_from_seed, xpub_from_xprv
from btclib.curves import curve, mult
from btclib.ecc import dh, dsa, ellswift, ssa
from btclib.exceptions import BTClibValueError
from btclib.script.engine import script as engine_script
from btclib.script.engine import tapscript as engine_tapscript

assert "btclib_secp256k1" not in sys.modules, "the finder let the bindings in"

rootxprv = rootxprv_from_seed({seed!r})
print(json.dumps({{
    "installed": INSTALLED,
    "dispatch": curve._libsecp256k1_available,
    "point": mult({prv_key}),
    "dsa": dsa.sign_({msg_hash!r}, {prv_key}).serialize().hex(),
    "ssa": ssa.sign_({msg_hash!r}, {prv_key}, {aux!r}).serialize().hex(),
    "xprv": derive(rootxprv, {derivation!r}),
    "xpub": derive(xpub_from_xprv(rootxprv), "m/0/7"),
    "engine": engine_script.dsa_verify(
        {msg_hash!r},
        bytes.fromhex({sec!r}),
        bytes.fromhex({sig!r}),
    ),
}}))
"""


def _child_answers(sec: str, sig: str) -> dict[str, Any]:
    """Run the child and return what it printed, failing on its stderr."""
    source = _CHILD.format(
        seed=_SEED,
        prv_key=_PRV_KEY,
        msg_hash=_MSG_HASH,
        derivation=_DERIVATION,
        aux=_AUX,
        sec=sec,
        sig=sig,
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", source],
        capture_output=True,
        encoding="utf-8",
        check=False,
        # large enough to be uninteresting, and there so that a child
        # that hangs fails as this test rather than as a slow suite: it
        # would otherwise hold an xdist worker until the job's own
        # timeout-minutes, and the report would name neither
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    answers: dict[str, Any] = json.loads(completed.stdout)
    return answers


@needs_bindings
def test_btclib_answers_with_the_bindings_out_of_reach() -> None:
    """Import and answer, and answer what the bindings answer.

    Every layer at once, deliberately: the arithmetic (`mult`), the two
    signature schemes, both BIP32 derivations, and the script engine's
    adapter -- which is the whole of what issue #966 lists as reaching
    the bindings. One child process for them, a python interpreter
    costing more to start than any of them costs to run.

    The child imports all eleven guarded modules and not only the ones it
    then calls: `src/btclib/__init__.py` imports nothing eagerly, so `import
    btclib` is the metadata lookup and no module at all, and a guard
    nothing imports is a guard nothing checks. `ecc.dh`, `ecc.ellswift`
    and `script.engine.tapscript` are the three the calls below would not
    reach on their own.
    """
    # the same question this process answers with the bindings serving
    assert INSTALLED
    assert ENABLED
    assert curve._libsecp256k1_available

    sec = bytes_from_point(mult(_PRV_KEY)).hex()
    sig = dsa.sign_(_MSG_HASH, _PRV_KEY).serialize().hex()
    rootxprv = rootxprv_from_seed(_SEED)

    answers = _child_answers(sec, sig)

    assert answers["installed"] is False
    assert answers["dispatch"] is False
    assert tuple(answers["point"]) == mult(_PRV_KEY)
    assert answers["dsa"] == sig
    assert answers["ssa"] == ssa.sign_(_MSG_HASH, _PRV_KEY, _AUX).serialize().hex()
    assert answers["xprv"] == derive(rootxprv, _DERIVATION)
    assert answers["xpub"] == derive(xpub_from_xprv(rootxprv), "m/0/7")
    assert answers["engine"] is True


@needs_bindings
def test_the_environment_variable_refuses_the_installed_bindings() -> None:
    """`BTCLIB_NO_LIBSECP256K1` is the way in that settles before import.

    A public function cannot do this job on its own: `btclib.
    _libsecp256k1` answers at import, so a caller that wants the Python
    arithmetic from the first call has to say so before the interpreter
    reaches `import btclib`. A test runner is exactly that caller, which
    is why the variable exists beside `set_libsecp256k1_serving` rather
    than instead of it.

    Installed and refused answers what absent answers -- one state, not
    two -- so the assertion is the same as the child above makes.
    """
    probe = (
        "from btclib._libsecp256k1 import ENABLED, INSTALLED;"
        "from btclib.curves import is_libsecp256k1_serving;"
        "print(INSTALLED, ENABLED, is_libsecp256k1_serving())"
    )
    answered = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        capture_output=True,
        encoding="utf-8",
        check=True,
        env={**os.environ, NO_LIBSECP256K1: "1"},
    ).stdout.split()
    assert answered == ["True", "False", "False"]

    # and an empty value is not set: the bindings serve
    answered = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        capture_output=True,
        encoding="utf-8",
        check=True,
        env={**os.environ, NO_LIBSECP256K1: ""},
    ).stdout.split()
    assert answered == ["True", "True", "True"]


def test_the_switch_refuses_to_promise_bindings_that_are_not_there(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asking for C where there is none is refused, not ignored.

    A caller that asked for the bindings and was quietly left on the
    Python arithmetic would be timing Python and calling it C, which is
    the mistake `curves/curve.py` says the seam exists to make
    impossible.
    """
    monkeypatch.setattr(curve, "_bindings_installed", False)
    with pytest.raises(BTClibValueError, match="btclib_secp256k1 is not installed"):
        set_libsecp256k1_serving(serving=True)

    # try/finally and not a monkeypatch for the restore: monkeypatch puts
    # back the value it found, and it would find the False this test has
    # just set -- which is a process-wide switch left off for whatever
    # runs next in this worker
    try:
        # switching them off is allowed whatever is installed: it is the
        # direction that always has an implementation to fall back to
        set_libsecp256k1_serving(serving=False)
        assert not is_libsecp256k1_serving()
    finally:
        monkeypatch.undo()
        set_libsecp256k1_serving(serving=ENABLED)


@needs_bindings
def test_the_switch_is_read_back_by_the_reader() -> None:
    """The pair is one state: what is set is what is read."""
    assert is_libsecp256k1_serving() is curve._libsecp256k1_available
    delegated = mult(_PRV_KEY)

    try:
        set_libsecp256k1_serving(serving=False)
        assert is_libsecp256k1_serving() is False
        # every dispatch reads it, which is what makes the pair worth
        # having: the arithmetic answers the same either way
        assert mult(_PRV_KEY) == delegated
        set_libsecp256k1_serving(serving=True)
        assert is_libsecp256k1_serving() is True
    finally:
        set_libsecp256k1_serving(serving=ENABLED)


# the point taproot's own tests already build from -- (0xC0FFEE)`mult`
# would do as well, and this is any point, not a fixture the taproot
# suite shares
_Q = mult(_PRV_KEY)
_X = _Q[0].to_bytes(32, "big")
_Y = _Q[1].to_bytes(32, "big")

# name -> (the call, whether the two arms are held to its wording too).
# Both taproot entries carry `PubKeyData(..., check_validity=False)`'s
# unproven octets to whichever arm answers next -- issue #887 -- so a
# refusal one arm makes and the other does not is this table's reason
# to exist, not an edge case of it.
#
# "bool private key" and "hybrid internal key" are held to the message
# as well as the class: both refusals run in a shared precondition
# above the arm split -- `int_from_integer` for the first (issue
# #1206), `_output_pubkey_and_internal_key`'s own hybrid check for the
# second (issue #1227) -- so the two arms never see the input until
# after the one btclib sentence has already fired.
#
# "bad-prefix internal key" is held to the class alone. `0x05 || x` is a
# SEC length with no SEC prefix, the fault of neither coordinate, and
# `_sec_from_key` leaves it unproven for `_tweaked_pubkey`'s own parse
# to refuse (issue #887): the bindings arm learns of it from
# `tweak_add`'s bare `ValueError`, the Python one from `PubKeyData.
# point`'s lift, and neither call can say what the other would have
# said. `tests/script/taproot_test.py`'s own
# `test_the_tweak_names_no_half_of_a_sec_it_cannot_blame` holds this
# input to the class alone for the same reason (issues #1214, #1218);
# `dsa.py`'s own rule is that the discrimination is the bindings' but
# the hierarchy has to be btclib's, and this is the general form of
# that rule applied here rather than an exception to it.
_REFUSALS: dict[str, tuple[Callable[[], object], bool]] = {
    "bool private key": (lambda: dsa.sign(_MSG_HASH, True), True),
    "hybrid internal key": (
        lambda: output_pubkey(bytes([0x06]) + _X + _Y),
        True,
    ),
    "bad-prefix internal key": (lambda: output_pubkey(bytes([0x05]) + _X), False),
}

# a second child, built the same way as `_CHILD` above: the finder
# first, then a table of the same inputs `_REFUSALS` names, run against
# whatever each raises rather than what each returns. `installed` and
# `dispatch` are asked again here rather than trusted from the first
# child's own answer, a separate `-c` invocation being a separate
# process this test has not otherwise looked at
_REFUSAL_CHILD = """
import json, sys


class RefuseTheBindings:
    def find_spec(self, name, path=None, target=None):
        if name == "btclib_secp256k1" or name.startswith("btclib_secp256k1."):
            raise ImportError("btclib_secp256k1 is out of reach")
        return None


sys.meta_path.insert(0, RefuseTheBindings())

import btclib
from btclib._libsecp256k1 import INSTALLED
from btclib.curves import curve
from btclib.ecc import dsa
from btclib.exceptions import BTClibException
from btclib.script.taproot import output_pubkey

assert "btclib_secp256k1" not in sys.modules, "the finder let the bindings in"


def refused(call):
    try:
        call()
    except BTClibException as e:
        return [type(e).__name__, str(e)]
    return None  # a call this table names but does not refuse is the finding


print(json.dumps({{
    "installed": INSTALLED,
    "dispatch": curve._libsecp256k1_available,
    "bool private key": refused(lambda: dsa.sign({msg_hash!r}, True)),
    "hybrid internal key": refused(
        lambda: output_pubkey(bytes.fromhex({hybrid_sec!r}))
    ),
    "bad-prefix internal key": refused(
        lambda: output_pubkey(bytes.fromhex({bad_prefix_sec!r}))
    ),
}}))
"""


def _refusal_child_answers() -> dict[str, Any]:
    """Run the refusal child and return what it printed, or fail on stderr."""
    source = _REFUSAL_CHILD.format(
        msg_hash=_MSG_HASH,
        hybrid_sec=(bytes([0x06]) + _X + _Y).hex(),
        bad_prefix_sec=(bytes([0x05]) + _X).hex(),
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", source],
        capture_output=True,
        encoding="utf-8",
        check=False,
        # the same ceiling as `_child_answers`, and the same reason: a
        # hung child fails as this test rather than as a slow suite
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    answers: dict[str, Any] = json.loads(completed.stdout)
    return answers


def _locally_refused(call: Callable[[], object]) -> tuple[str, str]:
    """Run call with the bindings in reach and return what it raised."""
    with pytest.raises(BTClibException) as excinfo:
        call()
    return type(excinfo.value).__name__, str(excinfo.value)


@needs_bindings
def test_the_two_arms_refuse_the_same_inputs() -> None:
    """A refusal is held to one class everywhere, one wording where it can be.

    `tests/py_arm_authority_test.py` counts which vectors of somebody
    else's making reach each arm and never compares them, and
    `test_btclib_answers_with_the_bindings_out_of_reach` above compares
    only what both arms compute successfully -- so neither would have
    caught issue #1227: a hybrid taproot internal key answered on the
    bindings arm and raised on the Python one, one input and two
    answers decided by `pip install` rather than by btclib. This asks
    the question those two do not: given an input, do the two arms
    refuse it the same way.

    `_REFUSALS` names the inputs and, per input, whether the two arms
    are held to its wording -- the comment above the table says which
    and why. Every entry is refused here, with the bindings in reach,
    before the child runs, so a table entry that stopped refusing would
    fail this half rather than silently comparing two successes.
    """
    local = {name: _locally_refused(call) for name, (call, _) in _REFUSALS.items()}

    answers = _refusal_child_answers()
    assert answers["installed"] is False
    assert answers["dispatch"] is False

    for name, (_, compare_message) in _REFUSALS.items():
        got = answers[name]
        assert got is not None, f"{name}: the no-bindings arm did not refuse"
        child_cls, child_msg = got
        local_cls, local_msg = local[name]
        assert child_cls == local_cls, name
        if compare_message:
            assert child_msg == local_msg, name
