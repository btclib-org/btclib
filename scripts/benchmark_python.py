# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Timings of the pure-Python implementations against the bindings.

The bindings are the reference line here and not a competitor. `pip
install btclib` installs `btclib_secp256k1`, so a consumer who wants C
already has it, and the question worth a table is what staying in Python
costs against what is there for free: one reference column, and a row for
every pure-Python implementation of the same operation.

Each row carries a second ratio beside it, against `btclib, Python`.
The first column answers what Python costs; the second answers how the
implementations compare with each other, which is the question the first
one leaves a reader dividing out by hand. The bindings row carries
nothing in it, being the reference of the first column.

This is the third of the benchmarks and the only one that forces Python
everywhere:

- `scripts/benchmark.py` times btclib's own two arithmetic paths against
  each other, and needs no dependency to do it
- `scripts/benchmark_libraries.py` times btclib, bindings enabled,
  against other Python bitcoin libraries **as installed** -- which for
  embit, python-bitcoinlib and often pycoin is C, as its own rows say
- this one times them **as Python**, every backend turned off that can be

The rows overlap by name with that second script and not by meaning:
pycoin is C there and Python here, and the difference between the two
numbers is the whole reason both exist.

## How each row is held to Python, and how that was checked

- **btclib**: `_libsecp256k1_applicable` is imported by name into every
  module these rows reach, so every one of them is patched, as
  `benchmark.py` does and for the reason its docstring gives: a partial
  patch leaves a row meant to measure Python measuring C underneath.
  `python_arithmetic_only` below names them and says which row found
  the one that had been left out.
- **pycoin** decides at import: `pycoin.ecdsa.native.secp256k1` and
  `.openssl` each read `PYCOIN_NATIVE` and return their no-op unless it
  names them. `os.environ` is set at the top of this file, before the
  import, because after it the decision is already made.
- **buidl** is imported as `buidl.pecc`, its pure-Python module, rather
  than through `buidl.ecc`, which prefers the compiled `buidl.cecc`
  when a separate build step has produced one.
- **python-ecdsa** and **secp256k1lab** have nothing to turn off: neither
  ships or loads a native backend at all.

`report_setup` prints what each row resolved to, because nothing here
should claim a Python number without checking that it is one.

## secp256k1lab's marker

It is on no index at all: `[tool.uv.sources]` takes it from its git tag,
and it wants >=3.11 where this project supports >=3.10, so the `bench`
group carries the marker that says so and this script imports it
unguarded.

## The row that is not here

**hwilib** would be one: `hwilib.key.point_mul` is a double-and-add over
Python integers, with nothing to turn off, and it would have been the
slowest public key in the table. `hwi` is not in the `bench` group
because of what it drags in -- its latest release caps `cbor2` at <5.8
and `protobuf` at <5.0.0, where the advisories against those two are
fixed in 5.9.0 and 5.29.6. No floor or constraint written in this project
reaches a patched version while those ceilings hold, so the row would
have cost three standing security alerts, two of them high. It is also a
row nobody here would see: `hwi` declares `requires_python <3.13` against
a `.python-version` of 3.14.

Not part of the test suite and not run by CI, as the other two are not:
nothing here is a correctness check, though every row is checked against
btclib's answer before it is timed.
"""

from __future__ import annotations

import os

# before the pycoin import below, and the reason is in the docstring:
# the native lookup runs at import time and never again
os.environ["PYCOIN_NATIVE"] = "none"

import time
from collections.abc import Callable
from hashlib import sha256
from importlib.metadata import version
from typing import Any, cast

import buidl.pecc
import ecdsa
import pycoin.symbols.btc
import secp256k1lab.bip340
from secp256k1lab.secp256k1 import G as LAB_G

from btclib.curves import curve, sec_point
from btclib.ecc import dsa, ssa
from btclib.hashes import reduce_to_hlen
from btclib.to_pub_key import pub_keyinfo_from_prv_key

PYCOIN_GENERATOR = pycoin.symbols.btc.network.generator

PRVKEY = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
PRVKEY_BYTES = PRVKEY.to_bytes(32, "big")
MSG_HASH = reduce_to_hlen(b"Satoshi Nakamoto")
AUX = bytes(32)

# signed while the bindings are still the default and deterministically,
# so that every row below verifies the same signature rather than one of
# its own: grind=False takes dsa.sign_'s plain RFC6979 nonce with no
# low-r search, and a fixed aux replaces ssa.sign_'s random default
DSA_SIG = dsa.sign_(MSG_HASH, PRVKEY, grind=False)
DSA_SIG_BYTES = DSA_SIG.serialize()
SSA_SIG = ssa.sign_(MSG_HASH, PRVKEY, aux=AUX)
SSA_SIG_BYTES = SSA_SIG.serialize()
PUBKEY = pub_keyinfo_from_prv_key(PRVKEY)[0]
XONLY_PUBKEY = PUBKEY[1:]


def _pycoin_backend() -> str:
    """Return which of pycoin's three arithmetic backends this run loaded.

    `PYCOIN_NATIVE` is set above, so the answer is expected to be pure
    Python; it is read back rather than assumed, a benchmark that says
    "Python" on a row that loaded a shared object being worse than no
    benchmark. There is no public flag to read, so this reads the MRO the
    generator ended up with, as `benchmark_libraries.py` does.
    """
    names = [base.__name__ for base in type(PYCOIN_GENERATOR).__mro__]
    if any("noop" not in name and "LibSECP256K1" in name for name in names):
        return "libsecp256k1 -- PYCOIN_NATIVE did not take"
    if any("noop" not in name and "OpenSSL" in name for name in names):
        return "OpenSSL -- PYCOIN_NATIVE did not take"
    return "pure Python"


def report_setup() -> None:
    """Print the versions and what each row actually resolved to."""
    print(f"btclib                {version('btclib')}, bindings the reference")
    print(f"btclib_secp256k1      {version('btclib_secp256k1')}")
    print(f"secp256k1lab          {version('secp256k1lab')}, pure Python")
    print(f"buidl                 {version('buidl')}, through buidl.pecc")
    print(f"ecdsa                 {version('ecdsa')}, pure Python")
    print(f"pycoin                {version('pycoin')}, backend: {_pycoin_backend()}")
    print()


# --------------------------------------------------------------- pub key


def pubkey_btclib() -> None:
    """Time the generator multiplication btclib answers a public key with."""
    pub_keyinfo_from_prv_key(PRVKEY)


def pubkey_lab() -> None:
    """Time secp256k1lab's, which multiplies G through a table of its own."""
    (PRVKEY * LAB_G).to_bytes_compressed()


def pubkey_buidl() -> None:
    """Time buidl's pure-Python S256Point."""
    buidl.pecc.PrivateKey(PRVKEY).point.sec()


def pubkey_ecdsa() -> None:
    """Time python-ecdsa's."""
    ecdsa.SigningKey.from_secret_exponent(
        PRVKEY, curve=ecdsa.SECP256k1
    ).verifying_key.to_string("compressed")


def pubkey_pycoin() -> None:
    """Time pycoin's, its native backends turned off."""
    pycoin.symbols.btc.network.keys.private(secret_exponent=PRVKEY).sec()


# ----------------------------------------------------------------- ECDSA


def dsa_sign_btclib() -> None:
    """Time an ECDSA signature through btclib."""
    dsa.sign_(MSG_HASH, PRVKEY, grind=False)


def dsa_verify_btclib() -> None:
    """Time an ECDSA verification through btclib."""
    dsa.assert_as_valid_(MSG_HASH, PUBKEY, DSA_SIG)


def dsa_sign_ecdsa() -> None:
    """Time an ECDSA signature through python-ecdsa."""
    ECDSA_SIGNING_KEY.sign_digest_deterministic(MSG_HASH, hashfunc=sha256)


def dsa_verify_ecdsa() -> None:
    """Time an ECDSA verification through python-ecdsa."""
    ECDSA_VERIFYING_KEY.verify_digest(ECDSA_SIG, MSG_HASH)


def dsa_sign_pycoin() -> None:
    """Time an ECDSA signature through pycoin's Generator."""
    PYCOIN_GENERATOR.sign(PRVKEY, PYCOIN_DIGEST)


def dsa_verify_pycoin() -> None:
    """Time an ECDSA verification through pycoin's Generator."""
    PYCOIN_GENERATOR.verify(PYCOIN_PUBLIC_PAIR, PYCOIN_DIGEST, PYCOIN_SIG)


def dsa_sign_buidl() -> None:
    """Time an ECDSA signature through buidl's pure-Python module."""
    BUIDL_KEY.sign(BUIDL_DIGEST)


def dsa_verify_buidl() -> None:
    """Time an ECDSA verification through buidl's pure-Python module."""
    BUIDL_KEY.point.verify(BUIDL_DIGEST, BUIDL_SIG)


# ---------------------------------------------------------------- BIP340


def ssa_sign_btclib() -> None:
    """Time a BIP340 signature through btclib."""
    ssa.sign_(MSG_HASH, PRVKEY, aux=AUX)


def ssa_verify_btclib() -> None:
    """Time a BIP340 verification through btclib."""
    ssa.assert_as_valid_(MSG_HASH, XONLY_PUBKEY, SSA_SIG)


def ssa_sign_lab() -> None:
    """Time a BIP340 signature through secp256k1lab."""
    secp256k1lab.bip340.schnorr_sign(MSG_HASH, PRVKEY_BYTES, AUX)


def ssa_verify_lab() -> None:
    """Time a BIP340 verification through secp256k1lab."""
    secp256k1lab.bip340.schnorr_verify(MSG_HASH, XONLY_PUBKEY, SSA_SIG_BYTES)


def ssa_sign_buidl() -> None:
    """Time a BIP340 signature through buidl's pure-Python module."""
    BUIDL_KEY.sign_schnorr(MSG_HASH, AUX)


def ssa_verify_buidl() -> None:
    """Time a BIP340 verification through buidl's pure-Python module."""
    BUIDL_KEY.point.verify_schnorr(MSG_HASH, BUIDL_SSA_SIG)


# ------------------------------------------------------------- the timing


def benchmark(func: Callable[[], None], calls: int) -> float:
    """Return microseconds per call, `calls` calls of `func`.

    A returned number and not a printed one: every row is a ratio against
    the bindings, which is the column this script exists for, so the
    reference has to be in hand before anything is printed.

    `calls` is per function rather than shared: the slowest row here is
    four orders of magnitude off the reference, and one count for all of
    them would either sit for minutes on the slowest or measure the
    fastest against the resolution of the clock.
    """
    # perf_counter and not time(): the wall clock can step backwards
    start = time.perf_counter()
    for _ in range(calls):
        func()
    return (time.perf_counter() - start) / calls * 1e6


def row(
    label: str,
    func: Callable[[], None],
    calls: int,
    bindings: float,
    python: float | None = None,
) -> float:
    """Print one row, and return its microseconds so a later row can divide.

    Two ratios, because the table is read for two questions. Against the
    bindings is what staying in Python costs, which is what this script
    is for; against btclib's own Python path is how the implementations
    compare with each other, which is the number a reader of this project
    would otherwise divide out by hand.

    `btclib, Python` is the reference of the second column and reads
    1.0x there, as the bindings row reads 1.0x in the first: its caller
    passes no `python`, having none to divide by yet.
    """
    us = benchmark(func, calls)
    against_python = f"{us / python:8.1f}x" if python else f"{'1.0x':>9s}"
    print(f"  {label:24s} {us:10.2f} us   {us / bindings:8.1f}x   {against_python}")
    return us


def section(title: str) -> None:
    """Print the heading of one operation's table."""
    print(f"\n{title}")


def head(label: str, us: float) -> None:
    """Print the column headings and the bindings row under them.

    Nothing in the second column on this row: it is the reference of the
    first, and the fraction under one it would carry says nothing the
    first has not said already.
    """
    print(f"  {'':24s} {'':10s}      {'vs C':>8s}   {'vs btclib':>9s}")
    print(f"  {label:24s} {us:10.2f} us   {'1.0x':>9s}   {'--':>9s}")


report_setup()

# the fixtures the third-party rows sign and verify, built once and
# checked against btclib's own answers below
ECDSA_SIGNING_KEY = ecdsa.SigningKey.from_secret_exponent(PRVKEY, curve=ecdsa.SECP256k1)
ECDSA_VERIFYING_KEY = ECDSA_SIGNING_KEY.verifying_key
ECDSA_SIG = ECDSA_SIGNING_KEY.sign_digest_deterministic(MSG_HASH, hashfunc=sha256)
PYCOIN_DIGEST = int.from_bytes(MSG_HASH, "big")
PYCOIN_POINT = PYCOIN_GENERATOR * PRVKEY
PYCOIN_PUBLIC_PAIR = (PYCOIN_POINT[0], PYCOIN_POINT[1])
PYCOIN_SIG = PYCOIN_GENERATOR.sign(PRVKEY, PYCOIN_DIGEST)
BUIDL_KEY = buidl.pecc.PrivateKey(PRVKEY)
BUIDL_DIGEST = int.from_bytes(MSG_HASH, "big")
BUIDL_SIG = BUIDL_KEY.sign(BUIDL_DIGEST)
BUIDL_SSA_SIG = BUIDL_KEY.sign_schnorr(MSG_HASH, AUX)

# every row answers what btclib answers, before any of them is timed: a
# table of numbers is worth nothing if one of the implementations in it
# is computing something else
assert (PRVKEY * LAB_G).to_bytes_compressed() == PUBKEY
assert buidl.pecc.PrivateKey(PRVKEY).point.sec() == PUBKEY
assert ECDSA_VERIFYING_KEY.to_string("compressed") == PUBKEY
assert pycoin.symbols.btc.network.keys.private(secret_exponent=PRVKEY).sec() == PUBKEY
assert secp256k1lab.bip340.schnorr_sign(MSG_HASH, PRVKEY_BYTES, AUX) == SSA_SIG_BYTES
assert secp256k1lab.bip340.schnorr_verify(MSG_HASH, XONLY_PUBKEY, SSA_SIG_BYTES)
assert BUIDL_KEY.point.verify_schnorr(MSG_HASH, BUIDL_SSA_SIG)
assert ECDSA_VERIFYING_KEY.verify_digest(ECDSA_SIG, MSG_HASH)
assert PYCOIN_GENERATOR.verify(PYCOIN_PUBLIC_PAIR, PYCOIN_DIGEST, PYCOIN_SIG)
assert BUIDL_KEY.point.verify(BUIDL_DIGEST, BUIDL_SIG)

# the reference column, every one of it taken before the dispatch goes
# off: these are the numbers a consumer gets from `pip install btclib`
REFERENCE = {
    "pubkey": benchmark(pubkey_btclib, 2000),
    "dsa sign": benchmark(dsa_sign_btclib, 2000),
    "dsa verify": benchmark(dsa_verify_btclib, 2000),
    "ssa sign": benchmark(ssa_sign_btclib, 2000),
    "ssa verify": benchmark(ssa_verify_btclib, 2000),
}


def python_arithmetic_only() -> None:
    """Turn btclib's libsecp256k1 dispatch off, in the namespaces timed here.

    `_libsecp256k1_applicable` is defined in `curves.curve` and imported
    by name into nine modules, so patching it in one leaves the other
    eight delegating and a row meant to measure Python measures C.
    `curves.sec_point` is the one this script needed and `benchmark.py`
    did not: `bytes_from_prv_key_int` asks it there, so a public key
    derived through `to_pub_key` came back at bindings speed with the
    other three patched -- 8.47 us against the 8.39 of the reference,
    which is how the omission was found rather than reasoned about.

    The four here are the ones the rows below reach. The others -- `bms`,
    `commit_nonce`, `dh`, `ellswift`, `pedersen`, `taproot` -- are not
    timed and are left alone; a row added later has to add its module to
    this tuple, which is why they are named rather than globbed.

    Called after the reference above and after every fixture is signed,
    both of which want the bindings.

    Cast to Any rather than assigned directly: mypy sees the loop
    variable as a plain module, none of the four in particular, and a
    plain module has no `_libsecp256k1_applicable` of its own.
    """
    for module in (dsa, ssa, curve, sec_point):
        cast(Any, module)._libsecp256k1_applicable = lambda *_: False


python_arithmetic_only()

section("public key from a private key: a multiplication of the generator")
head("btclib, the bindings", REFERENCE["pubkey"])
PYTHON = row("btclib, Python", pubkey_btclib, 200, REFERENCE["pubkey"])
row("secp256k1lab", pubkey_lab, 100, REFERENCE["pubkey"], PYTHON)
row("python-ecdsa", pubkey_ecdsa, 200, REFERENCE["pubkey"], PYTHON)
row("pycoin", pubkey_pycoin, 20, REFERENCE["pubkey"], PYTHON)
row("buidl.pecc", pubkey_buidl, 10, REFERENCE["pubkey"], PYTHON)

section("ECDSA sign, over a 32-byte digest")
head("btclib, the bindings", REFERENCE["dsa sign"])
PYTHON = row("btclib, Python", dsa_sign_btclib, 50, REFERENCE["dsa sign"])
row("python-ecdsa", dsa_sign_ecdsa, 100, REFERENCE["dsa sign"], PYTHON)
row("pycoin", dsa_sign_pycoin, 20, REFERENCE["dsa sign"], PYTHON)
row("buidl.pecc", dsa_sign_buidl, 10, REFERENCE["dsa sign"], PYTHON)

section("ECDSA verify, over a 32-byte digest")
head("btclib, the bindings", REFERENCE["dsa verify"])
PYTHON = row("btclib, Python", dsa_verify_btclib, 50, REFERENCE["dsa verify"])
row("python-ecdsa", dsa_verify_ecdsa, 50, REFERENCE["dsa verify"], PYTHON)
row("pycoin", dsa_verify_pycoin, 10, REFERENCE["dsa verify"], PYTHON)
row("buidl.pecc", dsa_verify_buidl, 10, REFERENCE["dsa verify"], PYTHON)

section("BIP340 sign, over a 32-byte message")
head("btclib, the bindings", REFERENCE["ssa sign"])
PYTHON = row("btclib, Python", ssa_sign_btclib, 50, REFERENCE["ssa sign"])
row("secp256k1lab", ssa_sign_lab, 50, REFERENCE["ssa sign"], PYTHON)
row("buidl.pecc", ssa_sign_buidl, 5, REFERENCE["ssa sign"], PYTHON)

section("BIP340 verify, over a 32-byte message")
head("btclib, the bindings", REFERENCE["ssa verify"])
PYTHON = row("btclib, Python", ssa_verify_btclib, 50, REFERENCE["ssa verify"])
row("secp256k1lab", ssa_verify_lab, 50, REFERENCE["ssa verify"], PYTHON)
row("buidl.pecc", ssa_verify_buidl, 10, REFERENCE["ssa verify"], PYTHON)
