# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The vendored consensus vectors, judged by the Python implementation.

btclib keeps two implementations of a signature verification, and an
installation that has the bindings runs one of them: the vectors below
reach the Python one only where something asks for it, so a defect there
is unreachable rather than absent. Issue #129 found two hiding exactly
there, each accepting a transaction the data calls invalid.

This module is what asks. The dispatch is switched off and the same
vector sets run again, so a disagreement between the two implementations
about the *verdict* on a transaction is caught. Unit tests cannot do that
job: neither #129 defect was "this function is lax" -- one was
`Sig.parse` dropping a byte, the other `point_from_octets` refusing a
hybrid key -- and both only became visible as a whole engine accepting a
whole transaction it must refuse.

It is not the same thing as `test.yml`'s `no-bindings` job, and does not
replace it: that job runs the whole suite once, with `btclib_secp256k1`
absent and one implementation available to it. What this module does
that no job will is run the two implementations over the same vectors in
the same session, which is what makes a disagreement visible as a
disagreement rather than as two red suites nobody compares.
"""

from typing import Any

import pytest

# the module, not the name in it: `_libsecp256k1_available` is an
# attribute of `curve`, and every dispatch in the package reads it there
from btclib.curves import curve
from btclib.script.engine import script as engine_script
from btclib.script.engine import tapscript as engine_tapscript

# the modules, not the names in them: `from … import script_test` binds a
# test function into this module too, and pytest then collects it here as
# well -- with its own parametrize and without the fixture below, which
# is 5184 vectors run a second time against the bindings for nothing
from tests import needs_bindings
from tests.script_engine import script_test as script_vector_module
from tests.script_engine import transactions_test as tx_vector_module

# the whole module, because with the bindings absent it is the run
# `script_test` and `transactions_test` have just made, on the same
# arithmetic: this file exists to run the two implementations in one
# session, and there is one implementation in that session. 5186 tests
# not re-run, over vectors two sibling modules have just put through the
# same code -- the count is the argument, and no wall clock is quoted
# beside it because the spread between three runs of the same head is
# the size of the saving
pytestmark = needs_bindings


@pytest.fixture
def python_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the whole engine, and everything under it, in Python.

    One assignment, and it has to be the global rather than a predicate
    per module: `_libsecp256k1_serves` reads
    `curve._libsecp256k1_available`, so clearing it is the package's
    dispatch switched off at once -- the engine's two verifications,
    `ecc.dsa` and `ecc.ssa` beneath them, and the field and group
    arithmetic beneath those. Patching the predicate where a module
    imported it would reach that module alone and leave the arm mixed:
    Python down to the verdict and C under it, which is a configuration
    nothing ships and issue #968 says an arm chosen by availability may
    never be in.

    It is also the only configuration these vectors can be run in that
    exists: with the bindings absent nothing is left to delegate to, so
    a run that keeps the multiplications in C is measuring something no
    installation will do.

    The price is real and was measured rather than assumed: the vectors
    of this module take 2.95 s with the arithmetic delegated and 17.21 s
    without, one process, `-p no:randomly`, one machine. The suite runs
    distributed, so what a contributor waits is the slowest worker and
    not this; and the alternative buys back fourteen seconds by testing a
    configuration nobody installs.
    """
    monkeypatch.setattr(curve, "_libsecp256k1_available", False)


# the sibling test functions are called rather than reimplemented: two
# copies of a vector walk drift, and what has to be identical between the
# two runs is precisely the walk -- only the verifier underneath differs
@pytest.mark.parametrize("vector", script_vector_module.script_vectors())
@pytest.mark.usefixtures("python_verification")
def test_script_vectors(vector: script_vector_module.ScriptVector) -> None:
    """Rerun Core's script vectors with Python verification underneath."""
    script_vector_module.test_script(vector)


@pytest.mark.parametrize("vector", tx_vector_module.legacy_vectors("tx_valid.json"))
@pytest.mark.usefixtures("python_verification")
def test_valid_legacy_vectors(vector: list[Any]) -> None:
    """Rerun tx_valid.json with Python verification underneath."""
    tx_vector_module.test_valid_legacy(vector)


@pytest.mark.parametrize("vector", tx_vector_module.legacy_vectors("tx_invalid.json"))
@pytest.mark.usefixtures("python_verification")
def test_invalid_legacy_vectors(vector: list[Any]) -> None:
    """Rerun tx_invalid.json with Python verification underneath."""
    tx_vector_module.test_invalid_legacy(vector)


@pytest.mark.parametrize("vector", tx_vector_module.taproot_vectors("success"))
@pytest.mark.usefixtures("python_verification")
def test_valid_taproot_vectors(vector: dict[str, Any]) -> None:
    """Rerun the taproot success vectors with Python verification."""
    tx_vector_module.test_valid_taproot(vector)


@pytest.mark.parametrize("vector", tx_vector_module.taproot_vectors("failure"))
@pytest.mark.usefixtures("python_verification")
def test_invalid_taproot_vectors(vector: dict[str, Any]) -> None:
    """Rerun the taproot failure vectors with Python verification."""
    tx_vector_module.test_invalid_taproot(vector)


@pytest.mark.parametrize("delegated", [True, False], ids=["bindings", "python"])
def test_verify_answers_false_for_what_cannot_be_parsed(
    monkeypatch: pytest.MonkeyPatch, *, delegated: bool
) -> None:
    """A malformed signature is a failed CHECKSIG, not an exception.

    The contract of both adapters, and it is one contract for two arms
    that refuse in two different ways: the bindings raise a ValueError of
    "invalid DER signature" or "invalid public key", `point_from_octets`
    raises BTClibValueError, and `ecc.dsa.verify_` and `ecc.ssa.verify_`
    answer False for what they decline. Whichever it is, the interpreter
    loop must see False.

    The vectors above never reach this: DER strictness is enforced
    earlier, by `fix_signature` under any of DERSIG, LOW_S and STRICTENC,
    so by the time the engine verifies, the encoding has been ruled on.
    So the contract is asserted here, and against both arms rather than
    the one this installation happens to have.
    """
    if delegated and not curve._libsecp256k1_available:  # pragma: no cover
        # the id would say `bindings` and the run would be the Python arm:
        # both answer False here, so nothing would go red and half the
        # parametrization would check the same thing twice. Skipped rather
        # than asserted, this file having to pass wherever it is run --
        # and unreachable in every job that runs it: with the bindings
        # installed, `_libsecp256k1_available` is True and the branch is
        # never taken; without them, this module's own `pytestmark =
        # needs_bindings` above skips the whole function before its body
        # runs, so `no-bindings` never reaches it either, and neither does
        # `coverage-union`'s combination of the two runs' data
        pytest.skip("the bindings are not serving in this configuration")
    if not delegated:
        monkeypatch.setattr(curve, "_libsecp256k1_available", False)

    msg_hash = b"\x11" * 32
    # a signature that is not DER at all
    assert not engine_script.dsa_verify(msg_hash, b"\x02" + b"\x33" * 32, b"garbage")
    # and a public key that is not a point: 0x02 with x = 0
    minimal_der = bytes.fromhex("3006020101020101")
    assert not engine_script.dsa_verify(msg_hash, b"\x02" + b"\x00" * 32, minimal_der)

    # the same two refusals of the tapscript adapter: an x that is no
    # x-coordinate, and a signature of the wrong length
    assert not engine_tapscript.ssa_verify(msg_hash, b"\x00" * 32, b"\x00" * 64)
    assert not engine_tapscript.ssa_verify(msg_hash, b"\x33" * 32, b"garbage")
