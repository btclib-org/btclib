# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a refusal prints only what btclib reads of a type, and how.

Section 7 of the organization's standard, *A refusal carries no secret*,
lets a refusal print a value's type name and its length. A class can be
given any name, a key's hex among them, a metaclass can answer any name
for `__name__` or raise from it, and a subclass's `__len__` can answer
any number. `btclib.utils._type_name` and `_length` read both, and the
cases below feed each shape and check the exact text and every exception
of the chain (issue #3128). The census at the end reads `src/btclib` for
an attribute read of `__name__` or `__qualname__`, and for either name
written as a string, which only `utils` writes, to read `type`'s own
descriptor. A type formatted whole, as in `f"{type(x)}"`, is not what it
reads. `tests/refused_lengths_test.py` is the same check for a length a
refusal prints.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from numbers import Number
from pathlib import Path
from typing import Any

import pytest
from typing_extensions import override

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import validated_network_name
from btclib.utils import (
    _LONG_TYPE_NAMES,
    _MAX_QUOTED_NAME_LENGTH,
    _message_text,
    _type_name,
    assert_type,
    bytes_from_octets,
    int_from_json_number,
)
from tests.secret_free import assert_secret_free

# a fixed random key, as `assert_secret_free` asks, and its spellings
_KEY = bytes.fromhex("9ed7f12938cd646f2866d454cc247f688b857424cc4ee6bec49c16f1200bd5b9")
_HEX = _KEY.hex()
# a length a subclass answers, read off the key
_LONG = int.from_bytes(_KEY[:7], "big")
_SECRETS: list[str | bytes] = [_KEY, _HEX, str(_LONG)]


def _renamed() -> object:
    """Return an instance of a class named by the key's hex."""
    kind = type("_Plain", (), {})
    kind.__name__ = _HEX
    return kind()


def _answer(_: type) -> str:
    return _HEX


def _raise(_: type) -> str:
    raise RuntimeError(_HEX)


# a metaclass whose `__name__` answers the key's hex, and one whose raises
_Answering = type("_Answering", (type,), {"__name__": property(_answer)})
_Raising = type("_Raising", (type,), {"__name__": property(_raise)})


def _answered() -> object:
    return _Answering("_Answered", (), {})()


def _raised() -> object:
    return _Raising("_Raised", (), {})()


def test_each_shape_names_its_class_as_it_claims() -> None:
    """A refusal reading `type(value).__name__` would print or raise this."""
    assert type(_renamed()).__name__ == _HEX
    assert type(_answered()).__name__ == _HEX
    with pytest.raises(RuntimeError, match=_HEX):
        _ = type(_raised()).__name__


# (the shape, what a refusal names it as)
_SHAPES: tuple[tuple[Callable[[], object], str], ...] = (
    (_renamed, "a type whose name has 64 characters"),
    (_answered, "_Answered"),
    (_raised, "_Raised"),
)

# (the call, the text of its refusal before the type)
_REFUSALS: tuple[tuple[Callable[[Any], object], str], ...] = (
    (lambda v: assert_type(v, int, "version"), "invalid version type: "),
    (bytes_from_octets, "invalid octets type: "),
    (lambda v: int_from_json_number(v, "version"), "invalid version type: "),
    (validated_network_name, "not a network name: "),
)


@pytest.mark.parametrize("shape, name", _SHAPES, ids=["renamed", "answered", "raised"])
@pytest.mark.parametrize(
    "call, text",
    _REFUSALS,
    ids=["assert_type", "bytes_from_octets", "int_from_json_number", "network"],
)
def test_a_refusal_names_a_type_as_btclib_reads_it(
    shape: Callable[[], object], name: str, call: Callable[[Any], object], text: str
) -> None:
    """The class's own name through `type`'s descriptor, where it is short."""
    with pytest.raises(BTClibTypeError) as e:
        call(shape())
    assert str(e.value) == text + name
    assert_secret_free(e.value, _SECRETS)


def test_a_description_names_a_type_as_btclib_reads_it() -> None:
    """`_message_text` describes a name it does not print by its length."""
    assert _message_text(_renamed()) == "a value of a type whose name has 64 characters"
    assert _message_text(_answered()) == "an _Answered"
    assert _message_text(_raised()) == "a _Raised"


class _Name(str):
    __slots__ = ()

    @override
    def isidentifier(self) -> bool:
        return True

    @override
    def __len__(self) -> int:
        return 1


def test_a_type_name_is_read_as_an_exact_str() -> None:
    """A class's name can be a str subclass, whose methods decide nothing."""
    # the overrides answer, so a check reaching them would be misled
    assert _Name(_HEX).isidentifier()
    assert len(_Name(_HEX)) == 1
    kind = type("_Plain", (), {})
    kind.__name__ = _Name(_HEX)
    # CPython keeps the subclass as the name, PyPy a copy of it
    assert vars(type)["__name__"].__get__(kind, type) == _HEX
    name = _type_name(kind())
    assert type(name) is str
    assert name == "a type whose name has 64 characters"


def test_a_type_name_is_printed_where_it_is_short_or_btclib_s() -> None:
    """An ASCII identifier up to the quoted length, or a long btclib name."""
    short = "A" * _MAX_QUOTED_NAME_LENGTH
    assert _type_name(type(short, (), {})()) == short
    assert _type_name(type(f"{short}A", (), {})()) == (
        "a type whose name has 17 characters"
    )
    assert _type_name(type("\u00e9", (), {})()) == "a type whose name has 1 characters"
    # a name need not be an identifier, as CPython's method-wrapper is not
    assert _type_name(type("a-b", (), {})()) == "a type whose name has 3 characters"
    assert _message_text(type("a-b", (), {})()) == (
        "a value of a type whose name has 3 characters"
    )
    for name in _LONG_TYPE_NAMES:
        assert _type_name(type(name, (), {})()) == name


class _LongBytes(bytes):
    @override
    def __len__(self) -> int:
        return _LONG

    @override
    def __bytes__(self) -> bytes:
        return _LongBytes(b"\x01\x02\x03")


class _LongBytearray(bytearray):
    @override
    def __len__(self) -> int:
        return _LONG


class _LongSized:
    def __len__(self) -> int:
        return _LONG


@pytest.mark.parametrize(
    "octets", [_LongBytes(b"\x01\x02\x03"), _LongBytearray(b"\x01\x02\x03")]
)
def test_a_size_is_that_of_the_octets_held(octets: bytes | bytearray) -> None:
    """A subclass's own `__len__` decides no size a refusal prints."""
    # the overrides answer, so a size reaching them would be theirs
    assert len(octets) == _LONG
    assert type(bytes(_LongBytes(b"\x01"))) is _LongBytes
    with pytest.raises(BTClibValueError) as e:
        bytes_from_octets(octets, 4)
    assert str(e.value) == "invalid size: 3 bytes instead of 4"
    assert_secret_free(e.value, _SECRETS)


def test_a_length_is_read_by_a_built_in_type() -> None:
    """A length is a built-in's own `__len__`'s, or none is printed."""
    assert len(_LongSized()) == _LONG
    assert _message_text(_LongSized()) == "a _LongSized"
    assert _message_text(_LongBytes(b"abc")) == "a _LongBytes of length 3"
    assert _message_text(_LongBytearray(b"abc")) == "a _LongBytearray of length 3"
    released = memoryview(b"abc")
    released.release()
    assert _message_text(released) == "a memoryview"


class _Float(float):
    @override
    def __int__(self) -> int:
        raise ValueError(_HEX)


class _Int(int):
    @override
    def __int__(self) -> int:
        raise ValueError(_HEX)


class _NoIntFloat(float):
    @override
    def __int__(self) -> int:
        raise TypeError(_HEX)


class _Number(Number):
    """A Number with no base type to read it by, whose `int` raises."""

    # typeshed declares `Number.__hash__` abstract, so mypy refuses to
    # instantiate a subclass that defines none
    __hash__ = object.__hash__

    def __init__(self, error: type[Exception]) -> None:
        self.error = error

    def __int__(self) -> int:
        raise self.error(_HEX)


@pytest.mark.parametrize("value", [_Float(1.0), _Int(1), _NoIntFloat(1.0)])
def test_a_json_number_s_own_int_is_not_called(value: Any) -> None:
    """A float or int subclass is read by its base type's own methods."""
    with pytest.raises((ValueError, TypeError)):
        int(value)
    assert int_from_json_number(value, "version") == 1


@pytest.mark.parametrize(
    "value, refusal",
    [
        (_Number(ValueError), "invalid version: not a whole number"),
        (_Number(TypeError), "invalid version type: _Number"),
        (float("inf"), "invalid version: not a whole number"),
    ],
)
def test_a_json_number_s_own_error_is_not_chained(value: Any, refusal: str) -> None:
    """The error `int` raised is neither the refusal's cause nor its context."""
    with pytest.raises((ValueError, TypeError, OverflowError)):
        int(value)
    with pytest.raises((BTClibTypeError, BTClibValueError)) as e:
        int_from_json_number(value, "version")
    assert str(e.value) == refusal
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, _SECRETS)


_SRC = Path(__file__).parents[1] / "src" / "btclib"

# a class's `__name__` and `__qualname__`, as an attribute or a string
_NAMES = ("__name__", "__qualname__")

# the hand-written reprs, each naming its own object's class as the
# reprs `@dataclass` generates do with `self.__class__.__qualname__`:
# that class is the caller's own object's, not a refused argument
_REPRS = {
    ("key.py", "PrvKeyData"),
    ("key.py", "PubKeyData"),
    ("script/script_pub_key.py", "ScriptPubKey"),
    ("script/witness.py", "Witness"),
}


def _reads(source: str) -> tuple[list[int], list[int], list[str]]:
    """Return where a source reads a type's name, and the reprs that do.

    The lines of each attribute read, then those of each string, then
    the class of each `__repr__` defined in a class body that reads
    `type(self).__name__` in its own body, outside any nested function.
    """
    attributes: list[int] = []
    strings: list[int] = []
    reprs: list[str] = []

    def walk(node: ast.AST, owner: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            inner = owner
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = None
                if isinstance(node, ast.ClassDef) and child.name == "__repr__":
                    inner = node.name
            elif isinstance(child, (ast.ClassDef, ast.Lambda)):
                inner = None
            if isinstance(child, ast.Attribute) and child.attr in _NAMES:
                if owner is not None and ast.unparse(child) == "type(self).__name__":
                    reprs.append(owner)
                else:
                    attributes.append(child.lineno)
            elif isinstance(child, ast.Constant) and child.value in _NAMES:
                strings.append(child.lineno)
            walk(child, inner)

    walk(ast.parse(source), None)
    return attributes, strings, reprs


def test_btclib_reads_a_type_s_name_only_through_type_name() -> None:
    """No attribute read of either name, and a string of it only in `utils`.

    Each hand-written repr is the exception, by its class.
    """
    reads = {
        path.relative_to(_SRC).as_posix(): _reads(path.read_text())
        for path in sorted(_SRC.rglob("*.py"))
    }
    assert not {name: read[0] for name, read in reads.items() if read[0]}
    assert {name: len(read[1]) for name, read in reads.items() if read[1]} == {
        "utils.py": 1
    }
    reprs = {(name, owner) for name, read in reads.items() for owner in read[2]}
    assert reprs == _REPRS


@pytest.mark.parametrize(
    "source",
    [
        "def f(x):\n    def g():\n        return type(x).__name__\n",
        "class C:\n    def m(self, x):\n        raise E(f'''a\n{type(x).__name__}''')\n",
        "async def f(x):\n    return type(x).__name__\n",
        "t = type(x)\nn = t.__name__\n",
        "n = x.__class__.__qualname__\n",
        "class C:\n    def __repr__(self):\n        return type(other).__name__\n",
        "class C:\n    def __repr__(self):\n        return (lambda: type(self).__name__)()\n",
        "def __repr__(self):\n    return type(self).__name__\n",
        "class C:\n    def __str__(self):\n        return type(self).__name__\n",
    ],
)
def test_the_census_finds_each_shape_of_a_read(source: str) -> None:
    """An attribute read in a nested function, a method or an f-string."""
    read, written, classes = _reads(source)
    assert read
    assert not written
    assert not classes


def test_the_census_finds_a_read_by_a_string() -> None:
    """`getattr` and a `vars` lookup spell the name as a string."""
    assert _reads("n = getattr(type(x), '__name__')\n")[1]
    assert _reads("n = vars(type)['__qualname__']\n")[1]


def test_the_census_spares_a_repr_naming_its_own_class() -> None:
    """What it spares: `type(self).__name__` in a class's own `__repr__`."""
    source = (
        "class C:\n    def __repr__(self):\n        return f'{type(self).__name__}()'\n"
    )
    assert _reads(source) == ([], [], ["C"])


def test_every_long_type_name_is_btclib_s_own() -> None:
    """Each class btclib defines with a name past the limit, and no other."""
    defined = {
        node.name
        for path in _SRC.rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.ClassDef)
    }
    long = {name for name in defined if len(name) > _MAX_QUOTED_NAME_LENGTH}
    assert set(_LONG_TYPE_NAMES) == long
