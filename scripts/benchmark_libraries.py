# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Timings of btclib, bindings enabled, against other Python bitcoin libraries.

btclib, with the `btclib_secp256k1` bindings it depends on and cannot be
installed without, is what `pip install btclib` gives an end user -- so
this times exactly that path, never the pure-Python fallback of
`curves/curve_group.py`, which issue #816's benchmark covers instead.

Every comparand is timed at its own latest PyPI release, on operations it
actually offers: signing a message is compared against a package that
signs, deriving a BIP32 child against one that has BIP32, and nothing
is compared against a package that lacks the feature.

## The candidates, and one that is not here

The issue that asked for this script named six candidates: python-ecdsa,
pycoin, bit, embit, python-bitcoinlib and buidl. `bit` is not among the
rows below: its latest release, 0.8.0 from 2021-12-04, depends on
`coincurve`, whose latest wheel set (21.0.0) stops at cp313 -- no cp314
build exists yet -- and the sdist fails to build on 3.14 with
"RuntimeError: Expected exactly one LICENSE file in cffi distribution",
a coincurve/hatchling packaging defect this repository does not control.
`uv sync --group bench` on `.python-version`'s 3.14 cannot install it, so
it is left out rather than pinned around silently; revisit if a newer
coincurve gains a 3.14 wheel.

## What each comparand is actually running, and how that was checked

A raw ctypes.util.find_library lookup answers "is a shared object
findable on this machine", and that answer moves with what happens to be
installed system-wide -- so two of the rows below are not always timing
what they seem to:

- pycoin optimizes its pure-Python arithmetic with libsecp256k1 or
  OpenSSL through ctypes *if* either is importable at runtime
  (`pycoin.ecdsa.native.secp256k1.libsecp256k1`,
  `pycoin.ecdsa.native.openssl` through the same mechanism); with
  neither found it falls back to the plain-Python `Generator` class.
  `_pycoin_backend()` below reports which one actually ran, because
  nothing here should claim a Python number without checking that it is
  one.
- python-bitcoinlib's `CECKey` defaults to OpenSSL's `EC_KEY` (loaded the
  same way, `ctypes.util.find_library`) and only calls libsecp256k1 if a
  caller opts in with `use_libsecp256k1_for_signing` -- not done here, so
  this row is OpenSSL's C and not Python either way, and stays that on
  every machine that has OpenSSL, which is to say every machine this
  installs on.
- embit does not probe the system at all: `embit/util/prebuilt/` ships a
  compiled libsecp256k1 for six platforms, and `embit.ec` loads the one
  matching `platform.machine()` through ctypes unconditionally. This row
  is always C, and always a libsecp256k1 build embit vendors rather than
  the one `btclib_secp256k1` vendors -- two different builds of the same
  library, not the same binary measured twice.
- buidl tries `buidl.cecc`, a compiled extension against Core's
  secp256k1 that `pip install buidl` does not build (`libsec_build.py`
  is a separate step this script does not run), and falls back to
  `buidl.pecc`, pure Python -- deterministically, since nothing here
  attempts the build. `ecdsa` (the PyPI package) has no native path to
  fall back from: it is pure Python unconditionally.

None of this makes a row invalid -- it is what `pip install <package>`
actually gives a user on this machine, which is the same question this
whole script asks of btclib. It does mean a pycoin row is not always
comparable across two runs of this script on two machines, which is why
the backend it picked is part of the output rather than a footnote.

## What is measured

Three operations, on secp256k1, sha256 where a digest is needed:

- ECDSA sign and verify, over a fixed 32-byte digest -- every comparand
  that exposes ECDSA takes a digest directly rather than a message, so
  none of them hash it a second time on top of the `hashlib.sha256` call
  below.
- BIP340 (Schnorr) sign and verify, over a fixed 32-byte message --
  BIP340 does not hash its message internally, so this is the value
  every implementation signs and checks, byte for byte, and it doubles
  as libsecp256k1's own fixed-size entry point, which is what keeps
  btclib's row on the bindings path (`ecc.ssa.sign_`'s dispatch is
  exactly this size or the arbitrary-size Python fallback, and this
  script wants the former).
- one BIP32 derivation, `m/0h/1` from a fixed 32-byte seed -- a hardened
  step and a normal one, which is what every comparand's own derivation
  function takes a path string or a chain of `child`/`subkey` calls for.
  All four implementations below were checked to agree on the resulting
  public key before any of this was timed.

python-ecdsa and python-bitcoinlib carry neither BIP340 nor BIP32, so
neither has a row in those two tables; pycoin's own `ecdsa.Generator` is
a bare elliptic-curve object with no seed-derivation function either,
which is why its BIP32 row goes through `pycoin.symbols.btc.network`
instead, the layer above that actually has one. Nothing here compares a
feature against a library that lacks it.

Not part of the test suite and not run by CI: it needs five third-party
packages this project does not depend on, declared in the `bench`
dependency group and nowhere else.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from importlib.metadata import version

import bitcoin.core.key as bitcoinlib_key
import buidl.hd
import buidl.libsec_status
import buidl.pecc
import ecdsa
import embit.bip32
import embit.ec
import pycoin.symbols.btc

from btclib.bip32 import bip32
from btclib.ecc import dsa, ssa
from btclib.to_pub_key import pub_keyinfo_from_prv_key

PRVKEY = 1
MSG_HASH = hashlib.sha256(b"Satoshi Nakamoto").digest()
SEED = bytes(range(32))
BIP32_PATH = "m/0h/1"


def _pycoin_backend() -> str:
    """Name the arithmetic pycoin's Generator actually runs, this machine.

    `create_LibSECP256K1Optimizations`/`create_OpenSSLOptimizations` (in
    `pycoin.ecdsa.native.*`) each resolve to a `noop` mixin class when
    the shared library they probe for is not importable -- there is no
    public flag to read instead, so this reads the MRO the generator
    ended up with.
    """
    bases = type(pycoin.symbols.btc.network.generator).__mro__
    names = [base.__name__ for base in bases]
    if any("noop" not in name and "LibSECP256K1" in name for name in names):
        return "libsecp256k1 (via ctypes)"
    if any("noop" not in name and "OpenSSL" in name for name in names):
        return "OpenSSL (via ctypes)"
    return "pure Python"


def report_setup() -> None:
    """Print what is about to be timed, and on what.

    A version number and a backend name, not a benchmark result, because
    the numbers below mean something only next to what produced them.
    """
    print(f"btclib               : {version('btclib')} (bindings enabled)")
    print(f"btclib_secp256k1     : {version('btclib_secp256k1')}")
    print(f"ecdsa                : {version('ecdsa')} (pure Python, no native path)")
    print(f"pycoin               : {version('pycoin')} ({_pycoin_backend()})")
    buidl_backend = (
        "libsecp256k1 (via cffi)"
        if buidl.libsec_status.is_libsec_enabled()
        else "pure Python"
    )
    print(f"buidl                : {version('buidl')} ({buidl_backend})")
    print(
        f"embit                : {version('embit')} "
        "(bundled libsecp256k1, via ctypes, always)"
    )
    libsecp256k1_for_signing = bitcoinlib_key.is_libsec256k1_available()
    print(
        f"python-bitcoinlib    : {version('python-bitcoinlib')} "
        f"(OpenSSL, via ctypes; libsecp256k1 available but unused: "
        f"{libsecp256k1_for_signing})"
    )
    print()


# --- ECDSA sign and verify, over MSG_HASH -----------------------------

btclib_pubkey = pub_keyinfo_from_prv_key(PRVKEY)[0]
btclib_dsa_sig = dsa.sign_(MSG_HASH, PRVKEY)

ecdsa_signing_key = ecdsa.SigningKey.from_secret_exponent(PRVKEY, curve=ecdsa.SECP256k1)
ecdsa_verifying_key = ecdsa_signing_key.verifying_key
ecdsa_sig = ecdsa_signing_key.sign_digest_deterministic(
    MSG_HASH, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der
)

pycoin_generator = pycoin.symbols.btc.network.generator
pycoin_val = int.from_bytes(MSG_HASH, "big")
pycoin_pubpoint = pycoin_generator * PRVKEY
pycoin_public_pair = (pycoin_pubpoint[0], pycoin_pubpoint[1])
pycoin_sig = pycoin_generator.sign(PRVKEY, pycoin_val)

buidl_prvkey = buidl.pecc.PrivateKey(PRVKEY)
buidl_z = int.from_bytes(MSG_HASH, "big")
buidl_sig = buidl_prvkey.sign(buidl_z)

bitcoinlib_key_ = bitcoinlib_key.CECKey()
bitcoinlib_key_.set_secretbytes(PRVKEY.to_bytes(32, "big"))
bitcoinlib_key_.set_compressed(True)
bitcoinlib_pubkey = bitcoinlib_key.CPubKey(bitcoinlib_key_.get_pubkey())
bitcoinlib_sig = bitcoinlib_key_.sign(MSG_HASH)

embit_prvkey = embit.ec.PrivateKey(PRVKEY.to_bytes(32, "big"))
embit_pubkey = embit_prvkey.get_public_key()
embit_dsa_sig = embit_prvkey.sign(MSG_HASH)

assert dsa.verify_(MSG_HASH, btclib_pubkey, btclib_dsa_sig)
assert ecdsa_verifying_key.verify_digest(
    ecdsa_sig, MSG_HASH, sigdecode=ecdsa.util.sigdecode_der
)
assert pycoin_generator.verify(pycoin_public_pair, pycoin_val, pycoin_sig)
assert buidl_prvkey.point.verify(buidl_z, buidl_sig)
assert bitcoinlib_pubkey.verify(MSG_HASH, bitcoinlib_sig)
assert embit_pubkey.verify(embit_dsa_sig, MSG_HASH)


def dsa_sign_btclib() -> None:
    """Time ECDSA signing through btclib, bindings enabled."""
    dsa.sign_(MSG_HASH, PRVKEY)


def dsa_verify_btclib() -> None:
    """Time ECDSA verification through btclib, bindings enabled."""
    assert dsa.verify_(MSG_HASH, btclib_pubkey, btclib_dsa_sig)


def dsa_sign_ecdsa() -> None:
    """Time ECDSA signing through the `ecdsa` PyPI package."""
    ecdsa_signing_key.sign_digest_deterministic(
        MSG_HASH, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der
    )


def dsa_verify_ecdsa() -> None:
    """Time ECDSA verification through the `ecdsa` PyPI package."""
    assert ecdsa_verifying_key.verify_digest(
        ecdsa_sig, MSG_HASH, sigdecode=ecdsa.util.sigdecode_der
    )


def dsa_sign_pycoin() -> None:
    """Time ECDSA signing through pycoin's Generator, backend as reported."""
    pycoin_generator.sign(PRVKEY, pycoin_val)


def dsa_verify_pycoin() -> None:
    """Time ECDSA verification through pycoin's Generator."""
    assert pycoin_generator.verify(pycoin_public_pair, pycoin_val, pycoin_sig)


def dsa_sign_buidl() -> None:
    """Time ECDSA signing through buidl's pure-Python PrivateKey."""
    buidl_prvkey.sign(buidl_z)


def dsa_verify_buidl() -> None:
    """Time ECDSA verification through buidl's pure-Python S256Point."""
    assert buidl_prvkey.point.verify(buidl_z, buidl_sig)


def dsa_sign_bitcoinlib() -> None:
    """Time ECDSA signing through python-bitcoinlib's OpenSSL wrapper."""
    bitcoinlib_key_.sign(MSG_HASH)


def dsa_verify_bitcoinlib() -> None:
    """Time ECDSA verification through python-bitcoinlib's OpenSSL wrapper."""
    assert bitcoinlib_pubkey.verify(MSG_HASH, bitcoinlib_sig)


def dsa_sign_embit() -> None:
    """Time ECDSA signing through embit's bundled libsecp256k1."""
    embit_prvkey.sign(MSG_HASH)


def dsa_verify_embit() -> None:
    """Time ECDSA verification through embit's bundled libsecp256k1."""
    assert embit_pubkey.verify(embit_dsa_sig, MSG_HASH)


# --- BIP340 (Schnorr) sign and verify, over MSG_HASH -------------------

btclib_xonly_pubkey = btclib_pubkey[1:]
btclib_ssa_sig = ssa.sign_(MSG_HASH, PRVKEY)

buidl_aux = bytes(32)
buidl_ssa_sig = buidl_prvkey.sign_schnorr(MSG_HASH, buidl_aux)

embit_ssa_sig = embit_prvkey.schnorr_sign(MSG_HASH)

assert ssa.verify_(MSG_HASH, btclib_xonly_pubkey, btclib_ssa_sig)
assert buidl_prvkey.point.verify_schnorr(MSG_HASH, buidl_ssa_sig)
assert embit_pubkey.schnorr_verify(embit_ssa_sig, MSG_HASH)


def ssa_sign_btclib() -> None:
    """Time BIP340 signing through btclib, bindings enabled."""
    ssa.sign_(MSG_HASH, PRVKEY)


def ssa_verify_btclib() -> None:
    """Time BIP340 verification through btclib, bindings enabled."""
    assert ssa.verify_(MSG_HASH, btclib_xonly_pubkey, btclib_ssa_sig)


def ssa_sign_buidl() -> None:
    """Time BIP340 signing through buidl's pure-Python PrivateKey."""
    buidl_prvkey.sign_schnorr(MSG_HASH, buidl_aux)


def ssa_verify_buidl() -> None:
    """Time BIP340 verification through buidl's pure-Python S256Point."""
    assert buidl_prvkey.point.verify_schnorr(MSG_HASH, buidl_ssa_sig)


def ssa_sign_embit() -> None:
    """Time BIP340 signing through embit's bundled libsecp256k1."""
    embit_prvkey.schnorr_sign(MSG_HASH)


def ssa_verify_embit() -> None:
    """Time BIP340 verification through embit's bundled libsecp256k1."""
    assert embit_pubkey.schnorr_verify(embit_ssa_sig, MSG_HASH)


# --- BIP32 derivation, seed to "m/0h/1" child ---------------------------

# the whole path from SEED, rebuilt inside every function below rather
# than once here: pycoin's BIP32Node keeps a `_subkey_cache` dict keyed
# by index, so a root reused across 1000 calls of the same path answers
# the 999 after the first from that cache and times a dict lookup, not a
# derivation. Rebuilding the root from the seed on every call is the one
# methodology that measures the same thing for all four -- one HMAC-SHA512
# to the root plus the path below it -- and none of the other three reads
# any faster for it: none keeps a cross-call cache of its own


def _btclib_child_pubkey(seed: bytes) -> bytes:
    xprv = bip32.rootxprv_from_seed(seed)
    child = bip32.derive(xprv, BIP32_PATH)
    return bip32.BIP32KeyData.b58decode(bip32.xpub_from_xprv(child)).key


def _pycoin_child_pubkey(seed: bytes) -> bytes:
    root = pycoin.symbols.btc.network.keys.bip32_seed(seed)
    return bytes(root.subkey_for_path("0H/1").sec())


def _embit_child_pubkey(seed: bytes) -> bytes:
    root = embit.bip32.HDKey.from_seed(seed)
    return bytes(root.derive(BIP32_PATH).sec())


def _buidl_child_pubkey(seed: bytes) -> bytes:
    root = buidl.hd.HDPrivateKey.from_seed(seed)
    return bytes(root.traverse(BIP32_PATH).pub.point.sec())


assert (
    _btclib_child_pubkey(SEED)
    == _pycoin_child_pubkey(SEED)
    == _embit_child_pubkey(SEED)
    == _buidl_child_pubkey(SEED)
)


def bip32_derive_btclib() -> None:
    """Time seed-to-child BIP32 derivation through btclib, bindings enabled."""
    _btclib_child_pubkey(SEED)


def bip32_derive_pycoin() -> None:
    """Time seed-to-child BIP32 derivation through pycoin's BIP32Node."""
    _pycoin_child_pubkey(SEED)


def bip32_derive_embit() -> None:
    """Time seed-to-child BIP32 derivation through embit's HDKey."""
    _embit_child_pubkey(SEED)


def bip32_derive_buidl() -> None:
    """Time seed-to-child BIP32 derivation through buidl's HDPrivateKey."""
    _buidl_child_pubkey(SEED)


def benchmark(func: Callable[[], None], calls: int) -> None:
    """Call `func` `calls` times and print microseconds per call.

    `calls` is chosen per function rather than shared: pycoin's and
    buidl's pure-Python rows are three to four orders of magnitude
    slower than the C-backed ones, so one loop count for all of them
    would either sit for minutes on the slowest or measure the fastest
    against the resolution of the clock. Each count below was picked
    from a first timed call to land near 1.5 seconds -- long enough that
    Python's own call overhead is a rounding error next to it, short
    enough that the whole script is a run to wait for, not start and
    leave.
    """
    # perf_counter and not time(): the wall clock can step backwards
    # under an NTP correction, and a benchmark is the one place that
    # shows up as a negative duration
    start = time.perf_counter()
    for _ in range(calls):
        func()
    end = time.perf_counter()
    us_per_call = (end - start) / calls * 1e6
    print(f"{func.__name__:<22}: {us_per_call:10.2f} us/call ({calls} calls)")


report_setup()

print("ECDSA sign (32-byte digest, secp256k1)")
benchmark(dsa_sign_btclib, 50_000)
benchmark(dsa_sign_ecdsa, 5_000)
benchmark(dsa_sign_pycoin, 200)
benchmark(dsa_sign_buidl, 50)
benchmark(dsa_sign_bitcoinlib, 8_000)
benchmark(dsa_sign_embit, 50_000)
print()

print("ECDSA verify (32-byte digest, secp256k1)")
benchmark(dsa_verify_btclib, 50_000)
benchmark(dsa_verify_ecdsa, 3_000)
benchmark(dsa_verify_pycoin, 80)
benchmark(dsa_verify_buidl, 25)
benchmark(dsa_verify_bitcoinlib, 7_000)
benchmark(dsa_verify_embit, 50_000)
print()

print("BIP340 sign (32-byte message)")
benchmark(ssa_sign_btclib, 50_000)
benchmark(ssa_sign_buidl, 20)
benchmark(ssa_sign_embit, 50_000)
print()

print("BIP340 verify (32-byte message)")
benchmark(ssa_verify_btclib, 50_000)
benchmark(ssa_verify_buidl, 25)
benchmark(ssa_verify_embit, 50_000)
print()

print(f"BIP32 derive, seed to {BIP32_PATH} (32-byte seed)")
benchmark(bip32_derive_btclib, 30_000)
benchmark(bip32_derive_pycoin, 75)
benchmark(bip32_derive_embit, 15_000)
benchmark(bip32_derive_buidl, 12)
