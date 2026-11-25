# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a refusal prints the length a built-in holds, not a subclass's.

Section 7 of the organization's standard, *A refusal carries no secret*,
lets a refusal print a value's length. A subclass of a built-in type can
answer any number from its own `__len__`, a key's digits among them, or
raise an error holding its hex. `btclib.utils._length_text` measures
such a value with the built-in's own `__len__`, and never raises. The
cases below feed each shape to it and to refusals that carry a length.
They check each refusal's exact text, and that no exception of its chain
holds the key, or the count an incomplete message carries (issue #3138).
The census at the end reads `src/btclib` for a `len()` call in what a
string formats or an exception is raised with, as `_reads` says.
`tests/refused_type_name_test.py` is the same check for a type's name,
and `tests/refused_counts_test.py` for a number decoded from the octets
a refusal refuses.
"""

from __future__ import annotations

import ast
from collections import deque
from collections.abc import Callable, Sequence
from io import BytesIO
from pathlib import Path
from typing import Any, cast

import pytest
from typing_extensions import TypeIs, override

from btclib.block import Block
from btclib.block.block_filter import BasicBlockFilter
from btclib.consensus import MAX_BLOCK_WEIGHT
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    IncompleteMessageError,
    ScriptError,
)
from btclib.hashes import hash256, merkle_root_from_branch
from btclib.network import xpubversion_from_xprvversion
from btclib.p2p.message import Message, _command_from_bytes
from btclib.script.engine.flags import NO_FLAGS
from btclib.script.engine.script import verify_script
from btclib.script.engine.script_op_codes import ConditionStack, assert_balanced_if
from btclib.script.engine.tapscript import verify_script_path_vc0
from btclib.script.taproot import tree_from_weights, tree_helper
from btclib.testing.blocks import read_bytes
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utils import _length_text
from tests.secret_free import assert_secret_free

# a fixed random key, as `assert_secret_free` asks, and its spellings
_KEY = bytes.fromhex("9ed7f12938cd646f2866d454cc247f688b857424cc4ee6bec49c16f1200bd5b9")
_HEX = _KEY.hex()
# a length a subclass answers, read off the key
_LONG = int.from_bytes(_KEY[:7], "big")
_SECRETS: list[str | bytes] = [_KEY, _HEX, str(_LONG)]


class _LongList(list[object]):
    @override
    def __len__(self) -> int:
        return _LONG


class _LongTuple(tuple[object, ...]):
    __slots__ = ()

    @override
    def __len__(self) -> int:
        return _LONG


class _RaisingList(list[object]):
    @override
    def __len__(self) -> int:
        raise RuntimeError(_HEX)


class _RaisingSized:
    def __len__(self) -> int:
        raise RuntimeError(_HEX)


class _LongDeque(deque[object]):
    @override
    def __len__(self) -> int:
        return _LONG


class _LongSequence(Sequence[object]):
    """A sequence of a caller's own, no list: it holds nothing."""

    @override
    def __len__(self) -> int:
        return _LONG

    @override
    def __getitem__(self, index: int | slice) -> Any:
        raise IndexError(index)


def test_each_shape_answers_len_as_it_claims() -> None:
    """A refusal calling `len()` would print or raise this."""
    assert len(_LongList([1, 2, 3])) == _LONG
    assert len(_LongTuple((1, 2, 3))) == _LONG
    assert len(_LongDeque([1])) == _LONG
    assert len(_LongSequence()) == _LONG
    with pytest.raises(RuntimeError, match=_HEX):
        len(_RaisingList())
    with pytest.raises(RuntimeError, match=_HEX):
        len(_RaisingSized())


def _released() -> memoryview:
    view = memoryview(b"abc")
    view.release()
    return view


def _two_open() -> ConditionStack:
    stack = ConditionStack()
    stack.push(True)
    stack.push(False)
    return stack


def _holding_no_int() -> ConditionStack:
    """Return a `ConditionStack` whose depth a caller set to the key's hex."""
    stack = ConditionStack()
    object.__setattr__(stack, "_size", _HEX)
    return stack


def _deeper_than_a_script() -> ConditionStack:
    """Return a `ConditionStack` whose depth a caller set to `_LONG`."""
    stack = ConditionStack()
    object.__setattr__(stack, "_size", _LONG)
    return stack


def _as_deep_as_a_script() -> ConditionStack:
    """Return a `ConditionStack` as deep as a script can open."""
    stack = ConditionStack()
    object.__setattr__(stack, "_size", MAX_BLOCK_WEIGHT)
    return stack


@pytest.mark.parametrize(
    "value, text",
    [
        (b"abc", "3"),
        (_LongList([1, 2, 3]), "3"),
        (_LongTuple((1, 2, 3)), "3"),
        (_RaisingList([1, 2]), "2"),
        (deque([1, 2]), "2"),
        (_two_open(), "2"),
        (_holding_no_int(), "?"),
        (_as_deep_as_a_script(), str(MAX_BLOCK_WEIGHT)),
        (_deeper_than_a_script(), "?"),
        (_LongDeque([1]), "1"),
        (_LongSequence(), "?"),
        (_RaisingSized(), "?"),
        (_released(), "?"),
        (5, "?"),
    ],
    ids=[
        "bytes",
        "list subclass",
        "tuple subclass",
        "raising list subclass",
        "deque",
        "ConditionStack",
        "ConditionStack holding no int",
        "ConditionStack as deep as a script",
        "ConditionStack deeper than a script",
        "deque subclass",
        "sequence of no built-in type",
        "raising sized",
        "released memoryview",
        "int",
    ],
)
def test_a_length_is_written_never_raising(value: object, text: str) -> None:
    """The length the built-in, deque or `ConditionStack` holds, else "?"."""
    assert _length_text(value) == text


# what a caller passes where a list or a leaf's tuple belongs
_RAISING_BRANCH = cast("Any", _RaisingList())
_LONG_LEAF = cast("Any", _LongTuple((0xC0, ["OP_1"], 0)))
_LONG_PAIR = cast("Any", _LongTuple((1, (0xC0, ["OP_1"]), 0)))
_LONG_SEQUENCE = cast("Any", _LongSequence())
_LONG_STACK = cast("Any", _LongList([b"\x01"]))
_RAISING_STACK = cast("Any", _RaisingList([b"\x01"]))
_TX = Tx(1, 0, [TxIn(OutPoint(b"\x01" * 32, 0), b"", 0)], [TxOut(1, b"")])


class _ShortList(list[object]):
    """A list answering a depth `assert_stack_size` lets through."""

    @override
    def __len__(self) -> int:
        return 999


def _block_with_long_inputs() -> Block:
    """Return block 170, its second transaction's inputs answering `_LONG`."""
    block = Block.parse(read_bytes("block_170.bin"))
    tx = block.transactions[1]
    tx.vin = cast("Any", _LongList(tx.vin))
    return block


class _ThirdLenRaising(list[object]):
    """Inputs answering their length twice, raising the key's hex after."""

    def __init__(self, items: Sequence[object]) -> None:
        super().__init__(items)
        self.asked = 0

    @override
    def __len__(self) -> int:
        self.asked += 1
        if self.asked > 2:
            raise RuntimeError(_HEX)
        return super().__len__()


def _block_with_inputs_asked_twice() -> Block:
    """Return block 170, its second transaction's inputs `_ThirdLenRaising`."""
    block = Block.parse(read_bytes("block_170.bin"))
    tx = block.transactions[1]
    tx.vin = cast("Any", _ThirdLenRaising(tx.vin))
    return block


class _FourBytes(bytes):
    @override
    def __len__(self) -> int:
        return 4


class _RaisingBytes(bytes):
    @override
    def __len__(self) -> int:
        raise RuntimeError(_HEX)


def test_these_shapes_answer_len_as_they_claim() -> None:
    """A refusal asking `len()` again, or of the bytes, would get this."""
    vin = _ThirdLenRaising([1])
    assert len(vin) == 1
    assert len(vin) == 1
    with pytest.raises(RuntimeError, match=_HEX):
        len(vin)
    assert len(_FourBytes(bytes(5))) == 4
    with pytest.raises(RuntimeError, match=_HEX):
        len(_RaisingBytes(bytes(5)))


# (the id, the call, the exception it raises, its exact text)
_REFUSALS: list[tuple[str, Callable[[], object], type[Exception], str]] = [
    (
        "merkle branch, raising __len__",
        lambda: merkle_root_from_branch(bytes(32), _RAISING_BRANCH, 1, hash256),
        BTClibValueError,
        "leaf index too high for a 0-step merkle branch",
    ),
    (
        "script tree leaf, long __len__",
        lambda: tree_helper([_LONG_LEAF]),
        BTClibTypeError,
        "invalid script tree leaf: 3-tuple",
    ),
    (
        "weighted leaf, long __len__",
        lambda: tree_from_weights([_LONG_PAIR]),
        BTClibTypeError,
        "invalid weighted leaf: 3-tuple",
    ),
    (
        "merkle branch, a sequence of no built-in type",
        lambda: merkle_root_from_branch(bytes(32), _LONG_SEQUENCE, 1, hash256),
        BTClibValueError,
        "leaf index too high for a ?-step merkle branch",
    ),
    (
        "script stack depth, long __len__",
        lambda: verify_script(b"\x6a", _LONG_STACK, 0, _TX, 0, NO_FLAGS, False),
        ScriptError,
        "OP_RETURN (command 0, stack depth 1)",
    ),
    (
        "script stack depth, raising __len__",
        lambda: verify_script(b"\x6a", _RAISING_STACK, 0, _TX, 0, NO_FLAGS, False),
        ScriptError,
        "OP_RETURN (command 0, stack depth 1)",
    ),
    (
        "script stack depth, no built-in's",
        lambda: verify_script(
            b"\x6a", cast("Any", deque([b"\x01"])), 0, _TX, 0, NO_FLAGS, False
        ),
        ScriptError,
        "OP_RETURN (command 0, stack depth ?)",
    ),
    (
        "tapscript stack depth, lying __len__",
        lambda: verify_script_path_vc0(
            b"\x6a",
            cast("Any", _ShortList([b"\x01"])),
            [TxOut(1, b"")],
            _TX,
            0,
            b"",
            50,
            NO_FLAGS,
        ),
        ScriptError,
        "OP_RETURN (command 0, stack depth 1)",
    ),
    (
        "unbalanced conditional, a depth no script reaches",
        lambda: assert_balanced_if(_deeper_than_a_script()),
        ScriptError,
        "unbalanced conditional: ? left open",
    ),
    (
        "inputs a block spends, long __len__",
        lambda: BasicBlockFilter.from_block(_block_with_long_inputs(), []),
        BTClibValueError,
        "invalid previous output script count: 0 instead of 1",
    ),
    (
        "inputs a block spends, a third __len__ raising",
        lambda: BasicBlockFilter.from_block(_block_with_inputs_asked_twice(), []),
        BTClibValueError,
        "invalid previous output script count: 0 instead of 1",
    ),
    (
        "xprv version, five bytes answering four",
        lambda: xpubversion_from_xprvversion(_FourBytes(bytes(5))),
        BTClibValueError,
        "unknown xprv version: 5 bytes",
    ),
    (
        "xprv version, raising __len__",
        lambda: xpubversion_from_xprvversion(_RaisingBytes(bytes(5))),
        BTClibValueError,
        "unknown xprv version: 5 bytes",
    ),
]


@pytest.mark.parametrize(
    "call, kind, err_msg",
    [case[1:] for case in _REFUSALS],
    ids=[case[0] for case in _REFUSALS],
)
def test_a_refusal_prints_the_length_held(
    call: Callable[[], object], kind: type[Exception], err_msg: str
) -> None:
    """The length a built-in holds, else "?", whatever `__len__` answers."""
    with pytest.raises(kind) as e:
        call()
    assert str(e.value) == err_msg
    assert_secret_free(e.value, _SECRETS)


class _FiveBytes(bytes):
    @override
    def __len__(self) -> int:
        return 5


class _FiveBytesStream(BytesIO):
    """A stream whose reads answer five for a length, whatever they hold."""

    @override
    def read(self, size: int | None = -1, /) -> bytes:
        return _FiveBytes(super().read(size))


def test_an_incomplete_message_misses_what_the_read_held() -> None:
    """`missing` counts the octets read, not what their `__len__` answers."""
    with pytest.raises(IncompleteMessageError) as e:
        Message.parse(_FiveBytesStream(b"\xf9\xbe\xb4\xd9"))
    assert e.value.missing == 20
    assert e.value.args == ("incomplete message header", 20)


class _LongBytes(bytes):
    """Octets answering a key's digits for a length, kept by each slice."""

    @override
    def __len__(self) -> int:
        return _LONG

    @override
    def __getitem__(self, index: Any) -> Any:
        item = super().__getitem__(index)
        return _LongBytes(item) if isinstance(index, slice) else item


class _LongBytesStream(BytesIO):
    @override
    def read(self, size: int | None = -1, /) -> bytes:
        return _LongBytes(super().read(size))


# a command whose padding holds a "Z" at byte 5
_BAD_PADDING = b"ping\x00Z" + bytes(6)


@pytest.mark.parametrize(
    "refused",
    [
        lambda: Message.parse(_LongBytesStream(bytes(4) + _BAD_PADDING + bytes(8))),
        lambda: pytest.importorskip("btclib.p2p.bip324").message_from_contents(
            _LongBytes(b"\x00" + _BAD_PADDING)
        ),
    ],
)
def test_a_padding_fault_is_counted_in_the_octets_held(
    refused: Callable[[], object],
) -> None:
    """The position is counted in a copy of the octets, not by their methods."""
    with pytest.raises(BTClibValueError) as e:
        refused()
    assert str(e.value) == "invalid command padding at byte 5"
    assert_secret_free(e.value, _SECRETS)


class _FoundAtZero(bytes):
    """Octets whose `find` reports a NUL at byte 0, wherever it is."""

    @override
    def find(self, *args: Any) -> int:
        return 0


class _NoOctets:
    """No octets at all, with the methods the command is read through."""

    def find(self, sub: bytes) -> int:
        return 0

    def __getitem__(self, index: slice) -> bytes:
        return b"\x01"


@pytest.mark.parametrize(
    "octets", [_FoundAtZero(b"ping".ljust(12, b"\x00")), _NoOctets()]
)
def test_a_padding_fault_no_copy_holds_is_written_unknown(octets: object) -> None:
    """A fault only a value's own methods report has no position to print."""
    with pytest.raises(BTClibValueError) as e:
        _command_from_bytes(cast("bytes", octets))
    assert str(e.value) == "invalid command padding at byte ?"


class _InputsHeld(Sequence[object]):
    """A sequence of a caller's own, no list, holding the inputs it is given."""

    def __init__(self, items: Sequence[object]) -> None:
        self._items = list(items)

    @override
    def __len__(self) -> int:
        return len(self._items)

    @override
    def __getitem__(self, index: Any) -> Any:
        return self._items[index]


def test_a_filter_checks_its_count_as_the_block_answers_it() -> None:
    """Only the text reads through `_length`; the check is ISS #3144's.

    Inputs held in a sequence no built-in measures still match their
    scripts, and a count that does not match prints that length as "?".
    """
    block = Block.parse(read_bytes("block_170.bin"))
    script = block.transactions[0].vout[0].script_pub_key.script
    block.transactions[1].vin = cast("Any", _InputsHeld(block.transactions[1].vin))
    assert BasicBlockFilter.from_block(block, [script]).element_count
    with pytest.raises(BTClibValueError) as e:
        BasicBlockFilter.from_block(block, [])
    assert str(e.value) == "invalid previous output script count: 0 instead of ?"


_SRC = Path(__file__).parents[1] / "src" / "btclib"

# the nodes whose body is a scope of its own for a bound name
_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _is_len(node: ast.AST) -> TypeIs[ast.Call]:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "len"
    )


# the endings of the names of the exception classes a call builds
_EXCEPTIONS = ("Error", "Exception", "Warning")


def _carried(node: ast.AST) -> list[ast.expr]:
    """Return the expressions a node writes into a text or an exception.

    A replacement field formats its own, and a `format` call its
    arguments. A `raise` raises its exception, and a call of a name
    ending in one of `_EXCEPTIONS` builds one of its arguments.
    """
    if isinstance(node, ast.FormattedValue):
        return [node.value]
    if isinstance(node, ast.Raise):
        return [] if node.exc is None else [node.exc]
    if isinstance(node, ast.Call):
        func = node.func
        name = func.id if isinstance(func, ast.Name) else ""
        name = func.attr if isinstance(func, ast.Attribute) else name
        if name == "format" or name.endswith(_EXCEPTIONS):
            return [*node.args, *(keyword.value for keyword in node.keywords)]
    return []


def _bound(node: ast.AST) -> list[str]:
    """Return the names the node binds to a `len()` call."""
    if isinstance(node, ast.Assign) and _is_len(node.value):
        return [target.id for target in node.targets if isinstance(target, ast.Name)]
    if (
        isinstance(node, (ast.AnnAssign, ast.NamedExpr))
        and node.value is not None
        and _is_len(node.value)
        and isinstance(node.target, ast.Name)
    ):
        return [node.target.id]
    return []


def _reads(source: str) -> list[int]:
    """Return the lines where a source writes a length `len()` measured.

    It reads what `_carried` returns. A `len()` call anywhere in it, and
    a name in it that the same scope binds to a `len()` call with `=`,
    an annotated `=` or `:=`, are each a line. What it does not read: `%`
    formatting, which ruff's UP031 refuses on a literal; a name bound to
    anything else holding a `len()` call, such as a sum or a list of
    them; a name bound in an enclosing scope; a length turned into text
    by `str()` and joined to one, as `_length_text` itself does; and an
    exception built by a call of a name with none of `_EXCEPTIONS`
    outside a `raise`.
    """
    lines: set[int] = set()

    def walk(scope: ast.AST) -> None:
        bound: set[str] = set()
        names: list[ast.Name] = []
        pending = list(ast.iter_child_nodes(scope))
        while pending:
            node = pending.pop()
            if isinstance(node, _SCOPES):
                walk(node)
                continue
            bound.update(_bound(node))
            for expr in _carried(node):
                for inner in ast.walk(expr):
                    if _is_len(inner):
                        lines.add(inner.lineno)
                    elif isinstance(inner, ast.Name):
                        names.append(inner)
            pending.extend(ast.iter_child_nodes(node))
        lines.update(name.lineno for name in names if name.id in bound)

    walk(ast.parse(source))
    return sorted(lines)


def test_no_refusal_writes_a_length_len_measured() -> None:
    """`_reads` finds no line in `src/btclib`."""
    found = {
        path.relative_to(_SRC).as_posix(): lines
        for path in sorted(_SRC.rglob("*.py"))
        if (lines := _reads(path.read_text()))
    }
    assert not found


@pytest.mark.parametrize(
    "source",
    [
        "def f(x):\n    def g():\n        return f'{len(x)}'\n",
        "class C:\n    def m(self, x):\n        raise E(f'''a\n{len(x)}''')\n",
        "async def f(x):\n    return f'{len(x)}'\n",
        "f = lambda x: f'{len(x)}'\n",
        "def f(x, y):\n    return f'{y:{len(x)}}'\n",
        "def f(x):\n    return f'{len(x) if x else 0}'\n",
        "def f(t, x):\n    return t.format(len(x))\n",
        "def f(t, x):\n    return t.format(n=len(x))\n",
        "def f(x):\n    n = len(x)\n    raise E(f'{n} bytes')\n",
        "def f(x):\n    n: int = len(x)\n    raise E(f'{n - 2} bytes')\n",
        "def f(x):\n    if (n := len(x)) > 2:\n        raise E(f'{n} bytes')\n",
        "def f(s):\n    raise ScriptError('m', c, 0, len(s))\n",
        "def f(s):\n    n = len(s)\n    raise E('m', n)\n",
        "def f(s):\n    error = btclib.IncompleteMessageError('m', 24 - len(s))\n",
        "def f(s):\n    raise make(len(s))\n",
        "MSG = f'{len(X)}'\n",
        "N = len(X)\nMSG = f'{N}'\n",
        "class C:\n    MSG = f'{len(X)}'\n",
        "class C:\n    N = len(X)\n    MSG = f'{N}'\n",
    ],
    ids=[
        "nested function",
        "method, multi-line",
        "async def",
        "lambda",
        "format spec",
        "conditional",
        "format",
        "format keyword",
        "bound name",
        "annotated name",
        "walrus",
        "exception argument",
        "exception argument, bound name",
        "exception built",
        "raised",
        "module",
        "module, bound name",
        "class body",
        "class body, bound name",
    ],
)
def test_the_census_finds_each_shape_of_a_length(source: str) -> None:
    """A `len()`, or a name bound to one, in a text or an exception."""
    assert _reads(source)


@pytest.mark.parametrize(
    "source",
    [
        "def f(x):\n    raise E(f'{_length_text(x)} bytes')\n",
        "def f(x):\n    return f'{bytes.__len__(x)}'\n",
        "def f(x):\n    if len(x) > 2:\n        raise E('too long')\n",
        "def f(x):\n    n = len(x)\n    if n:\n        raise E(f'{_length_text(x)}')\n",
        "def f(x):\n    n = len(x)\n    def g(n):\n        return f'{n}'\n",
        "def f(s):\n    raise ScriptError('m', c, 0, _length(s)) from e\n",
    ],
    ids=[
        "_length_text",
        "bytes.__len__",
        "check",
        "bound, unformatted",
        "other scope",
        "_length",
    ],
)
def test_the_census_spares_a_length_it_does_not_write(source: str) -> None:
    """Another measure, a `len()` only a check reads, another scope's name."""
    assert not _reads(source)
