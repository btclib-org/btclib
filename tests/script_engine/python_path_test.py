#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""The vendored consensus vectors, judged by the python implementation.

The engine imports its signature verification from the bindings, which
are a required dependency, so the python implementations never face
these vectors otherwise: a defect in them is unreachable rather than
absent. Issue #129 found two hiding exactly there, each accepting a
transaction the data calls invalid.

This module is the bindings-less configuration, without the packaging:
the two symbols the engine imports from the bindings are replaced by the
python implementations and the same vector sets run again through them,
so a disagreement between the two implementations about the *verdict*
on a transaction is caught. Unit tests cannot do that job: neither #129
defect was "this function is lax" -- one was `Sig.parse` dropping a
byte, the other `point_from_octets` refusing a hybrid key -- and both
only became visible as a whole engine accepting a whole transaction it
must refuse.

The alternative, a CI job installing without the bindings, is not a job
but a partial revert: all five bindings imports are plain imports, so
`import btclib` itself fails without them and the optional-bindings
install would have to come back in order to be tested.
This costs no packaging change and no fallback code in the library.

The substitution is the one already used for ripemd160 in
tests/hashes_test.py: a module-level name, swapped, to reach the second
implementation of a primitive that has two.
"""

from typing import Any

import pytest

from btclib.curves import point_from_octets
from btclib.ecc import dsa, ssa
from btclib.exceptions import BTClibValueError
from btclib.script.engine import script as engine_script
from btclib.script.engine import tapscript as engine_tapscript

# the modules, not the names in them: `from … import script_test` binds a
# test function into this module too, and pytest then collects it here as
# well -- with its own parametrize and without the fixture below, which
# is 5184 vectors run a second time against the bindings for nothing
from tests.script_engine import script_test as script_vector_module
from tests.script_engine import transactions_test as tx_vector_module


def python_dsa_verify(msg_hash: bytes, pub_key: bytes, sig: bytes) -> bool:
    """The python verify the fixture below installs in the engine.

    `hybrid=True` is the second half of issue #129: `point_from_octets`
    takes the hybrid 0x06/0x07 prefixes only when asked,
    `ec_pubkey_parse` takes them always (eckey_impl.h), and
    consensus wants CHECKSIG to succeed for a hybrid key whenever
    STRICTENC is off. Raising rather than returning False is deliberate
    and is what the bindings do: `dsa_verify` catches ValueError, and
    BTClibValueError is one.
    """
    Q = point_from_octets(pub_key, hybrid=True)
    return dsa.verify_(msg_hash, Q, sig)


def python_ssa_verify(msg_hash: bytes, pub_key: bytes, sig: bytes) -> bool:
    """The BIP340 counterpart, for the tapscript vectors."""
    return ssa.verify_(msg_hash, pub_key, sig)


@pytest.fixture
def python_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route the engine's signature verification through python.

    Two patches per algorithm, and both are needed: the engine holds its
    own reference to the bindings' verify, and `btclib.ecc` would hand
    secp256k1 with sha256 straight back to them -- the very dispatch that
    makes the python path unreachable in the first place.
    """
    monkeypatch.setattr(dsa, "_libsecp256k1_applicable", lambda *_: False)
    monkeypatch.setattr(ssa, "_libsecp256k1_applicable", lambda *_: False)
    monkeypatch.setattr(engine_script, "_libsecp256k1_dsa_verify", python_dsa_verify)
    monkeypatch.setattr(engine_tapscript, "_libsecp256k1_ssa_verify", python_ssa_verify)


# the sibling test functions are called rather than reimplemented: two
# copies of a vector walk drift, and what has to be identical between the
# two runs is precisely the walk -- only the verifier underneath differs
@pytest.mark.parametrize("vector", script_vector_module.script_vectors())
@pytest.mark.usefixtures("python_verification")
def test_script_vectors(vector: script_vector_module.ScriptVector) -> None:
    script_vector_module.test_script(vector)


@pytest.mark.parametrize("vector", tx_vector_module.legacy_vectors("tx_valid.json"))
@pytest.mark.usefixtures("python_verification")
def test_valid_legacy_vectors(vector: list[Any]) -> None:
    tx_vector_module.test_valid_legacy(vector)


@pytest.mark.parametrize("vector", tx_vector_module.legacy_vectors("tx_invalid.json"))
@pytest.mark.usefixtures("python_verification")
def test_invalid_legacy_vectors(vector: list[Any]) -> None:
    tx_vector_module.test_invalid_legacy(vector)


@pytest.mark.parametrize("vector", tx_vector_module.taproot_vectors("success"))
@pytest.mark.usefixtures("python_verification")
def test_valid_taproot_vectors(vector: dict[str, Any]) -> None:
    tx_vector_module.test_valid_taproot(vector)


@pytest.mark.parametrize("vector", tx_vector_module.taproot_vectors("failure"))
@pytest.mark.usefixtures("python_verification")
def test_invalid_taproot_vectors(vector: dict[str, Any]) -> None:
    tx_vector_module.test_invalid_taproot(vector)


def test_dsa_verify_answers_false_for_what_the_bindings_refuse() -> None:
    """A malformed signature is a failed CHECKSIG, not an exception.

    `engine_script.dsa_verify` wraps the bindings' verify in a
    `try/except ValueError` for this, and the vectors never reach it: DER
    strictness is enforced earlier, by `fix_signature` under DERSIG and
    STRICTENC, so by the time the engine verifies, the encoding has
    already been ruled on. What is left is the contract itself, which the
    python substitute above is written to honour -- it raises where the
    bindings raise -- and which the bindings do raise: measured, a
    ValueError of "invalid DER signature" and one of "invalid public
    key".
    """
    msg_hash = b"\x11" * 32
    # a signature that is not DER at all
    assert not engine_script.dsa_verify(msg_hash, b"\x02" + b"\x33" * 32, b"garbage")
    # and a public key that is not a point: 0x02 with x = 0
    minimal_der = bytes.fromhex("3006020101020101")
    assert not engine_script.dsa_verify(msg_hash, b"\x02" + b"\x00" * 32, minimal_der)

    # the same input through the python substitute raises instead, which
    # is the asymmetry the wrapper exists to absorb
    with pytest.raises(BTClibValueError):
        python_dsa_verify(msg_hash, b"\x02" + b"\x00" * 32, minimal_der)
