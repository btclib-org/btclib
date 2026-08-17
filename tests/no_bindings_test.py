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
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from btclib._libsecp256k1 import AVAILABLE
from btclib.bip32.bip32 import derive, rootxprv_from_seed, xpub_from_xprv
from btclib.curves import bytes_from_point, curve, mult
from btclib.ecc import dsa, ssa

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
from btclib._libsecp256k1 import AVAILABLE
from btclib.bip32.bip32 import derive, rootxprv_from_seed, xpub_from_xprv
from btclib.curves import curve, mult
from btclib.ecc import dh, dsa, ellswift, ssa
from btclib.script.engine import script as engine_script
from btclib.script.engine import tapscript as engine_tapscript

assert "btclib_secp256k1" not in sys.modules, "the finder let the bindings in"

rootxprv = rootxprv_from_seed({seed!r})
print(json.dumps({{
    "available": AVAILABLE,
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


def test_btclib_answers_with_the_bindings_out_of_reach() -> None:
    """Import and answer, and answer what the bindings answer.

    Every layer at once, deliberately: the arithmetic (`mult`), the two
    signature schemes, both BIP32 derivations, and the script engine's
    adapter -- which is the whole of what issue #966 lists as reaching
    the bindings. One child process for them, a python interpreter
    costing more to start than any of them costs to run.

    The child imports all eleven guarded modules and not only the ones it
    then calls: `btclib/__init__.py` imports nothing eagerly, so `import
    btclib` is the metadata lookup and no module at all, and a guard
    nothing imports is a guard nothing checks. `ecc.dh`, `ecc.ellswift`
    and `script.engine.tapscript` are the three the calls below would not
    reach on their own.
    """
    # the same question this process answers with the bindings serving
    assert AVAILABLE
    assert curve._libsecp256k1_available

    sec = bytes_from_point(mult(_PRV_KEY)).hex()
    sig = dsa.sign_(_MSG_HASH, _PRV_KEY).serialize().hex()
    rootxprv = rootxprv_from_seed(_SEED)

    answers = _child_answers(sec, sig)

    assert answers["available"] is False
    assert answers["dispatch"] is False
    assert tuple(answers["point"]) == mult(_PRV_KEY)
    assert answers["dsa"] == sig
    assert answers["ssa"] == ssa.sign_(_MSG_HASH, _PRV_KEY, _AUX).serialize().hex()
    assert answers["xprv"] == derive(rootxprv, _DERIVATION)
    assert answers["xpub"] == derive(xpub_from_xprv(rootxprv), "m/0/7")
    assert answers["engine"] is True
