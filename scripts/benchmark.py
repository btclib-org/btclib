# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Timings of btclib's own two arithmetic paths, side by side.

btclib delegates secp256k1 point operations to the btclib_secp256k1
bindings -- curves.curve.mult and ecc.dsa.sign_/ecc.ssa.sign_ for
secp256k1 with sha256 -- and falls back to the pure Python arithmetic of
curves/curve_group.py for every other curve, a zero scalar, the point at
infinity, and everything else the bindings decline. This times point
multiplication and ECDSA/BIP340 sign and verify through both paths, on
one fixed key and message.

The point is not a number to quote: the two paths answer the same
equations, one in C and one in Python, and what this shows is an order
of magnitude, the same one curve.py's own docstrings already measure in
passing next to the code they describe. Nothing here repeats a
measurement or discards an outlier.

The pure Python side is reached by turning btclib's own dispatch off,
which `python_arithmetic_only` below does and says why: every one of the
timed functions asks `_libsecp256k1_applicable` first and would
otherwise answer from the bindings, the very path the other half of this
script already timed.

Not part of the test suite and not run by CI: nothing here is a
correctness check, and `tests/script_engine/python_path_test.py` already
is one, over the vendored consensus vectors rather than a synthetic
message. No third-party dependency either -- btclib_secp256k1 is already
a dependency of btclib itself.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, cast

from btclib.curves import curve
from btclib.ecc import dsa, ssa
from btclib.hashes import reduce_to_hlen
from btclib.to_pub_key import pub_keyinfo_from_prv_key

prvkey = 1
pubkey = pub_keyinfo_from_prv_key(prvkey)[0]
xonly_pubkey = pubkey[1:]
msg_hash = reduce_to_hlen(b"Satoshi Nakamoto")
scalar = 12345

# both signed while the bindings are still the default, and
# deterministically: grind=False takes dsa.sign_'s plain RFC6979 nonce
# with no low-r search, and a fixed aux replaces ssa.sign_'s random
# default, so the pure Python path below can be checked against the very
# same signature instead of a fresh, unrelated one
dsa_sig = dsa.sign_(msg_hash, prvkey, grind=False)
ssa_sig = ssa.sign_(msg_hash, prvkey, aux=bytes(32))


def python_arithmetic_only() -> None:
    """Turn btclib's libsecp256k1 dispatch off, in the three timed here.

    `_libsecp256k1_applicable` is defined in `curves.curve` and imported
    by name into nine modules, so patching one leaves the other eight
    delegating and a row meant to measure Python measures C -- dsa's and
    ssa's own verification calls into curve's double multiplication
    underneath whichever implementation answers the boundary check first.

    Three are enough for the rows below and not for a row that derives a
    public key: `curves.sec_point` asks the same question in
    `bytes_from_prv_key_int`, which is what `benchmark_python.py` found
    when its pure-Python public key came back at bindings speed. A row
    added here has to add its module to the tuple.

    Called once, after the fixtures above are signed: they go through
    the bindings too, and there is no reason to slow those down.

    Cast to Any rather than assigned directly: mypy sees the loop
    variable as a plain module, none of the three concrete modules in
    particular, and a plain module has no `_libsecp256k1_applicable` of
    its own to assign.
    """
    for module in (dsa, ssa, curve):
        cast(Any, module)._libsecp256k1_applicable = lambda *_: False


def mult_bindings() -> None:
    """Time point multiplication through the libsecp256k1 bindings."""
    curve.mult(scalar)


def mult_python() -> None:
    """Time point multiplication through the pure Python arithmetic."""
    curve.mult(scalar)


def dsa_sign_bindings() -> None:
    """Time ECDSA signing through the libsecp256k1 bindings."""
    assert dsa.sign_(msg_hash, prvkey, grind=False) == dsa_sig


def dsa_sign_python() -> None:
    """Time ECDSA signing through btclib's pure Python arithmetic."""
    assert dsa.sign_(msg_hash, prvkey, grind=False) == dsa_sig


def dsa_verify_bindings() -> None:
    """Time ECDSA verification through the libsecp256k1 bindings."""
    assert dsa.verify_(msg_hash, pubkey, dsa_sig)


def dsa_verify_python() -> None:
    """Time ECDSA verification through btclib's pure Python arithmetic."""
    assert dsa.verify_(msg_hash, pubkey, dsa_sig)


def ssa_sign_bindings() -> None:
    """Time BIP340 signing through the libsecp256k1 bindings."""
    assert ssa.sign_(msg_hash, prvkey, aux=bytes(32)) == ssa_sig


def ssa_sign_python() -> None:
    """Time BIP340 signing through btclib's pure Python arithmetic."""
    assert ssa.sign_(msg_hash, prvkey, aux=bytes(32)) == ssa_sig


def ssa_verify_bindings() -> None:
    """Time BIP340 verification through the libsecp256k1 bindings."""
    assert ssa.verify_(msg_hash, xonly_pubkey, ssa_sig)


def ssa_verify_python() -> None:
    """Time BIP340 verification through btclib's pure Python arithmetic."""
    assert ssa.verify_(msg_hash, xonly_pubkey, ssa_sig)


def benchmark(func: Callable[[], None], mult: int = 1) -> None:
    """Call `func` 1000 * `mult` times and print the seconds per 1000.

    `mult` is per function rather than shared: the pure Python path
    measured here is slower than the bindings by more than one order of
    magnitude, so one loop count for both would either take too long on
    the Python side or measure the bindings against the resolution of
    the clock.
    """
    # perf_counter and not time(): the wall clock can step backwards
    # under an NTP correction, and a benchmark is the one place that
    # shows up as a negative duration
    start = time.perf_counter()
    for _ in range(1000 * mult):
        func()
    end = time.perf_counter()
    print(f"{func.__name__:<19}: {((end - start) / mult):.6f}")


benchmark(mult_bindings, 100)
benchmark(dsa_sign_bindings, 100)
benchmark(dsa_verify_bindings, 100)
benchmark(ssa_sign_bindings, 100)
benchmark(ssa_verify_bindings, 100)

python_arithmetic_only()

benchmark(mult_python, 1)
benchmark(dsa_sign_python, 1)
benchmark(dsa_verify_python, 1)
benchmark(ssa_sign_python, 1)
benchmark(ssa_verify_python, 1)
