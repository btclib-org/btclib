# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a refusal raised in an `except` block chains no secret.

Section 7 of the organization's standard, *A refusal carries no secret*,
allows `raise ... from e` only where `e`'s own text keeps the rule. A site
here is a `raise` statement with a `from` clause, `from None` included, or
one that raises an exception inside an `except` block: the exception being
handled becomes the new one's cause or context. Each case below feeds a
fixed random key where a caller's value goes, and `assert_secret_free`
reads the refusal and every exception it chains. The census asserts that
the sites the cases reach are the sites `_sites` finds in btclib's source
(issue #3137).

The census reads `raise` statements only. An exception that a function an
`except` block calls raises is chained and is no site here, nor is one that
a `raise` with no `from` clause raises in a `finally` block, outside any
`except` block, while another propagates. A refusal raised after the
block that copies the text of the exception it caught is no site either.
"""

from __future__ import annotations

import ast
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from ecc.curves import mult, point_from_octets_var, secp256k1
from typing_extensions import override

import btclib
from btclib.amount import valid_btc_amount
from btclib.b32 import power_of_2_base_conversion, witness_from_address
from btclib.b58 import prv_key_data_from_wif, wif_from_prv_key
from btclib.block import BlockHeader
from btclib.bms import Sig
from btclib.compressor import decompress_script
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    NotAPrvKeyError,
    ScriptError,
)
from btclib.fee import FeeRate
from btclib.key import PrvKeyData, PubKeyData
from btclib.script import taproot
from btclib.script.engine import script as legacy_engine
from btclib.script.engine import taproot_unwrap_script, tapscript
from btclib.script.engine.flags import NO_FLAGS, ScriptFlag
from btclib.script.engine.script import STRICT_DER_FLAGS, fix_signature
from btclib.script.engine.script_op_codes import _call_step, _StepError
from btclib.script.script import serialize
from btclib.script.script_pub_key import ScriptPubKey, script_from_script_pub_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utils import bytes_from_octets
from btclib.utreexo import Proof, UpdateData
from tests.secret_free import assert_secret_free, chained, text_of

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

# a fixed random key, as `assert_secret_free` asks, and its spellings
_KEY = bytes.fromhex("9ed7f12938cd646f2866d454cc247f688b857424cc4ee6bec49c16f1200bd5b9")
_SCALAR = int.from_bytes(_KEY, "big")
_HEX = _KEY.hex()
_WIF = wif_from_prv_key(_SCALAR)
# the same WIF with its last character changed, so its checksum fails
_BAD_WIF = _WIF[:-1] + ("2" if _WIF[-1] != "2" else "3")


def _no_point(start: int) -> bytes:
    """Return the first x from `start` up that no point of secp256k1 has."""
    x = start
    while pow(x**3 + 7, (secp256k1.p - 1) // 2, secp256k1.p) == 1:
        x += 1
    return x.to_bytes(32, "big")


# the key's own neighbourhood: an x that is no point, read as one
_X = _no_point(_SCALAR)
# BIP341 negates a key whose point has an odd y; this tweak takes what is
# left to zero, so a tweaked key is zero and a tweaked point is at infinity
_EVEN_KEY = _SCALAR if mult(_SCALAR)[1] % 2 == 0 else secp256k1.n - _SCALAR
_ZEROING_TWEAK = secp256k1.n - _EVEN_KEY

_SECRETS: list[str | bytes] = []
for _secret in (_KEY, _X, _ZEROING_TWEAK.to_bytes(32, "big")):
    _SECRETS += [_secret, _secret.hex(), str(int.from_bytes(_secret, "big"))]
_SECRETS.append(_WIF)

# a transaction with no output, and an output a tapscript spends
_TX = Tx(2, 0, [TxIn(OutPoint(b"\x01" * 32, 0), b"", 0)], [], check_validity=False)
_PREVOUTS = [TxOut(1000, ScriptPubKey(b"\x51\x20" + bytes(32)))]

_OP_1 = b"\x51"
_OP_DUP = b"\x76"
_OP_DROP = b"\x75"
_OP_EQUALVERIFY = b"\x88"
_SIGHASH_SINGLE = b"\x03"

_PACKAGE = Path(btclib.__file__).parent


def _legacy(script: bytes) -> None:
    """Run a script on a stack holding the key, as a legacy script."""
    legacy_engine.verify_script(script, [_KEY], 0, _TX, 0, NO_FLAGS, False)


def _tapscript(script: bytes) -> None:
    """Run a script on a stack holding the key, as a tapscript."""
    tapscript.verify_script_path_vc0(
        script, [_KEY], _PREVOUTS, _TX, 0, b"", 50, NO_FLAGS
    )


def _legacy_refusal(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    """Refuse the top of the stack as a public key, with btclib's class."""
    PubKeyData(stack[-1])


def _tapscript_refusal(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    """Refuse the top of the stack as a point, with ecc's class."""
    point_from_octets_var(stack[-1])


def _patched(
    table: Mapping[str, Callable[..., None]],
    op: Callable[..., None],
    run: Callable[[], None],
) -> Callable[[pytest.MonkeyPatch], None]:
    """Return a call that runs `run` with OP_DUP of `table` replaced by `op`.

    The arm of the loop for a refusal that is no ScriptError is reached
    through an op code made to raise one.
    """

    def call(monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(table, "OP_DUP", op)
        run()

    return call


def _zeroing(run: Callable[[], object]) -> Callable[[pytest.MonkeyPatch], object]:
    """Return a call that runs `run` with the BIP341 tweak `_ZEROING_TWEAK`.

    The tweak is a hash of the key and the tree, so a sum is zero only by
    chance; the tweak is set instead, and ecc refuses the sum it is given.
    """

    def call(monkeypatch: pytest.MonkeyPatch) -> object:
        monkeypatch.setattr(taproot, "_tap_tweak", lambda *_: _ZEROING_TWEAK)
        return run()

    return call


def _step(*_: object) -> None:
    """Raise, as a caller's step callback may."""
    raise RuntimeError("a step that raises")


# each case: id, call, and the class of the refusal
_CASES: list[tuple[str, Callable[[pytest.MonkeyPatch], object], type[Exception]]] = [
    (
        "WIF of a wrong checksum",
        lambda _: prv_key_data_from_wif(_BAD_WIF),
        NotAPrvKeyError,
    ),
    (
        "base64 of a wrong character",
        lambda _: Sig.b64decode(_HEX + "!"),
        BTClibValueError,
    ),
    ("x of no point", lambda _: decompress_script(4, _X), BTClibValueError),
    (
        "fee rate past the cap",
        lambda _: FeeRate.from_btc_per_kvbyte(str(_SCALAR), round_up=True),
        BTClibValueError,
    ),
    (
        "internal key of no point",
        lambda _: taproot.check_output_pubkey(bytes(32), _OP_1, b"\xc0" + _X),
        BTClibValueError,
    ),
    (
        "taproot spend of an internal key of no point",
        lambda _: taproot_unwrap_script(b"\x51\x20" + bytes(32), [_OP_1, b"\xc0" + _X]),
        ScriptError,
    ),
    (
        "tweaked public key at infinity",
        _zeroing(lambda: taproot.output_pubkey(PrvKeyData(_SCALAR).pub)),
        BTClibValueError,
    ),
    (
        "tweaked private key of zero",
        _zeroing(lambda: taproot.output_prvkey(_SCALAR)),
        BTClibValueError,
    ),
    # the key as r and the key less its first byte as s, so the sequence is
    # one byte short of its length
    (
        "signature of a wrong DER length",
        lambda _: fix_signature(
            b"\x30\x45\x02\x21\x00" + _KEY + b"\x02\x1f" + _KEY[1:] + b"\x01",
            STRICT_DER_FLAGS,
        ),
        ScriptError,
    ),
    (
        "legacy op code refusal",
        lambda _: _legacy(_OP_1 + _OP_EQUALVERIFY),
        ScriptError,
    ),
    (
        "legacy refusal of no code",
        _patched(legacy_engine.OPERATIONS, _legacy_refusal, lambda: _legacy(_OP_DUP)),
        ScriptError,
    ),
    ("legacy stack underflow", lambda _: _legacy(_OP_DROP * 2), ScriptError),
    (
        "tapscript op code refusal",
        lambda _: _tapscript(_OP_1 + _OP_EQUALVERIFY),
        ScriptError,
    ),
    (
        "tapscript refusal of no code",
        _patched(tapscript.OPERATIONS, _tapscript_refusal, lambda: _tapscript(_OP_DUP)),
        ScriptError,
    ),
    ("tapscript stack underflow", lambda _: _tapscript(_OP_DROP * 2), ScriptError),
    (
        "schnorr signature of SIGHASH_SINGLE with no output",
        lambda _: tapscript._check_schnorr_signature(
            _KEY + _KEY + _SIGHASH_SINGLE,
            _X,
            _TX,
            0,
            _PREVOUTS,
            0,
            b"",
            b"",
            None,
            None,
            None,
        ),
        ScriptError,
    ),
    # the step is the caller's, and the error it raises is handed back
    (
        "step callback",
        lambda _: _call_step(_step, 0, _OP_DUP[0], True, [_KEY], [_KEY]),
        _StepError,
    ),
    # "zz" is no hex, so the key is neither an op code nor data
    ("script command", lambda _: serialize(["zz" + _HEX]), BTClibValueError),
    ("tapscript command", lambda _: taproot.serialize(["zz" + _HEX]), BTClibValueError),
    (
        "WIF as a script or an address",
        lambda _: script_from_script_pub_key(_WIF),
        BTClibValueError,
    ),
    (
        "hex of a wrong character",
        lambda _: bytes_from_octets(_HEX[:-1] + "z"),
        BTClibValueError,
    ),
    (
        "str as bech32 digits",
        lambda _: power_of_2_base_conversion(_HEX, 8, 5),  # type: ignore[arg-type]
        BTClibTypeError,
    ),
    ("WIF as a bech32 address", lambda _: witness_from_address(_WIF), BTClibValueError),
    # a block target left out of the deletion: the lengths of what the
    # update reads disagree
    (
        "utreexo update of another forest",
        lambda _: Proof([1, 3], [_KEY, _KEY]).update(
            [_KEY, _KEY], [_KEY], [0], [], UpdateData([], 4, [(0, _KEY)], [])
        ),
        BTClibValueError,
    ),
]


@pytest.mark.parametrize(
    "call, kind", [case[1:] for case in _CASES], ids=[case[0] for case in _CASES]
)
def test_a_chained_refusal_carries_no_secret(
    call: Callable[[pytest.MonkeyPatch], object],
    kind: type[Exception],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No exception of the chain holds a secret fed, in any spelling.

    `assert_secret_free` looks for pieces whose length `WINDOW` gives
    (`tests/secret_free/__init__.py`), so each byte of the key is also
    looked for as `0x` and its hex.
    """
    with pytest.raises(kind) as refusal:
        call(monkeypatch)
    assert len(list(chained(refusal.value))) > 1
    assert_secret_free(refusal.value, _SECRETS)
    for e in chained(refusal.value):
        text = text_of(e)
        assert all(f"0x{byte:02x}" not in text for byte in _KEY)


def _sites(source: str) -> set[tuple[int, int]]:
    """Return the first and last line of each `raise` that chains.

    A `raise` with a `from` clause, or one that raises an exception inside
    an `except` block; a bare `raise` re-raises what is handled and chains
    nothing. A function defined inside an `except` block runs when it is
    called, so its own `raise` is read as any other function's; a call
    inside the block is the case of a function an `except` block calls,
    which the module docstring names.
    """
    found: set[tuple[int, int]] = set()

    def walk(node: ast.AST, handling: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                walk(child, False)
                continue
            if isinstance(child, ast.Raise) and (
                child.cause is not None or (handling and child.exc is not None)
            ):
                found.add((child.lineno, child.end_lineno or child.lineno))
            walk(child, handling or isinstance(child, ast.ExceptHandler))

    walk(ast.parse(source), False)
    return found


def _package_sites() -> set[tuple[str, int, int]]:
    """Return each site of btclib's source: its file, first and last line."""
    return {
        (path.relative_to(_PACKAGE).as_posix(), first, last)
        for path in sorted(_PACKAGE.rglob("*.py"))
        for first, last in _sites(path.read_text(encoding="utf-8"))
    }


def _raised_at(e: BaseException) -> tuple[str, int]:
    """Return the file under btclib and the line an exception was raised at.

    The innermost frame of its traceback that is btclib's, or an empty
    file where none is.
    """
    where = ("", 0)
    for frame, line in traceback.walk_tb(e.__traceback__):
        path = Path(frame.f_code.co_filename)
        if path.is_relative_to(_PACKAGE):
            where = (path.relative_to(_PACKAGE).as_posix(), line)
    return where


def _reached(
    exc: BaseException, sites: set[tuple[str, int, int]]
) -> Iterator[tuple[str, int, int]]:
    """Yield each site an exception of the chain was raised at."""
    for e in chained(exc):
        file, line = _raised_at(e)
        yield from (s for s in sites if s[0] == file and s[1] <= line <= s[2])


def test_the_cases_reach_every_site(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each case reaches a site, and each site is reached by a case.

    A new site fails here until a case reaches it; a refusal raised after
    its `except` block needs none.
    """
    sites = _package_sites()
    reached: set[tuple[str, int, int]] = set()
    for case_id, call, kind in _CASES:
        with monkeypatch.context() as patch, pytest.raises(kind) as refusal:
            call(patch)
        found = set(_reached(refusal.value, sites))
        assert found, case_id
        reached |= found
    assert sorted(sites - reached) == []


# each `raise` that chains carries "# first" on its first line and "# last"
# on its last one
_SHAPES = """
def from_e(x):
    try:
        int(x)
    except ValueError as e:
        raise TypeError(x) from e  # first # last


def multi_line(x):
    try:
        int(x)
    except ValueError as err:
        raise TypeError(  # first
            x
        ) from err  # last


def from_none(x):
    try:
        int(x)
    except ValueError:
        raise TypeError(x) from None  # first # last


def implicit(x):
    try:
        int(x)
    except ValueError:
        if x:
            raise TypeError(x)  # first # last
        raise


def nested(x):
    def inner():
        try:
            int(x)
        except ValueError as e:
            raise TypeError(x) from e  # first # last

    return inner


async def coroutine(x):
    try:
        int(x)
    except ValueError as e:
        raise TypeError(x) from e  # first # last


class Method:
    def method(self, x):
        try:
            int(x)
        except ValueError as e:
            raise TypeError(x) from e  # first # last


def class_body(x):
    try:
        int(x)
    except ValueError:
        class Inside:
            raise TypeError(x)  # first # last


def defined_in_the_block(x):
    try:
        int(x)
    except ValueError:
        def later():
            raise TypeError(x)

        return later


def after_the_block(x):
    try:
        int(x)
    except ValueError:
        pass
    raise TypeError(x)
"""


def test_the_census_reads_each_shape_of_a_chaining_raise() -> None:
    """The shapes a site takes are found, and no other `raise` is."""
    lines = _SHAPES.splitlines()
    firsts = [i for i, line in enumerate(lines, 1) if "# first" in line]
    lasts = [i for i, line in enumerate(lines, 1) if "# last" in line]
    assert _sites(_SHAPES) == set(zip(firsts, lasts, strict=True))


class _Loud:
    """A value whose own `__str__` raises an error holding the key."""

    @override
    def __str__(self) -> str:
        raise ValueError(f"my key is {_HEX}")


class _LoudTime(datetime):
    """A time whose own `timestamp()` raises an error holding the key."""

    @override
    def timestamp(self) -> float:
        raise ValueError(f"my key is {_HEX}")


@pytest.mark.parametrize(
    "call",
    [
        lambda: valid_btc_amount(_Loud()),
        lambda: FeeRate.from_btc_per_kvbyte(_Loud()),
        # an exponent past `_CONTEXT`'s: CPython's Decimal refuses it, and
        # PyPy's reads it as a value past the cap
        lambda: valid_btc_amount(f"1e{_SCALAR}"),
        lambda: BlockHeader(
            1, bytes(32), bytes(32), _LoudTime(2020, 1, 1, tzinfo=UTC), "1d00ffff", 0
        ),
    ],
    ids=["amount", "fee rate", "amount of a huge exponent", "header time"],
)
def test_a_refusal_raised_after_the_block_chains_nothing(
    call: Callable[[], object],
) -> None:
    """A refusal of `_decimal_from_value` or `_timestamp_of` chains nothing.

    The error they catch can be the caller's own, out of its `__str__` or its
    `timestamp()`, and hold anything.
    """
    with pytest.raises(BTClibValueError) as refusal:
        call()
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert_secret_free(refusal.value, _SECRETS)
