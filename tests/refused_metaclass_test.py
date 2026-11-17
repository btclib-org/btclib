# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that the metaclasses below let no error out of a refusal.

Against an abstract base class, `issubclass` hashes a class and can read
its `__mro__`, both through its metaclass, which can answer anything or
raise an error holding a key. `btclib.utils._has_type` reads the MRO of
such a class through `type`'s own descriptor instead, and the cases
below feed each shape to refusals that test against an abstract base
class, checking the exact text and every exception of the chain (issue
#3139). They also feed the iterations behind such a test a class it
takes for an `Iterable` whose `__iter__` is None.
"""

from __future__ import annotations

from abc import ABCMeta
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import Any

import pytest
from typing_extensions import override

from btclib.exceptions import BTClibTypeError
from btclib.p2p.compact_blocks import reconstruct
from btclib.p2p.message import _padding_fault_at
from btclib.script.engine.flags import to_script_flags
from btclib.utils import (
    assert_type,
    bytes_from_octets,
    int_from_json_number,
    list_from_json_array,
)
from tests.secret_free import assert_secret_free

# a fixed random key, as `assert_secret_free` asks, and its spellings
_KEY = bytes.fromhex("9ed7f12938cd646f2866d454cc247f688b857424cc4ee6bec49c16f1200bd5b9")
_HEX = _KEY.hex()
_SECRETS: list[str | bytes] = [_KEY, _HEX]


class _MroRaising(type):
    """A metaclass that raises the key's hex where a class's MRO is read."""

    @override
    def __getattribute__(cls, name: str) -> Any:
        if name in {"__mro__", "__bases__"}:
            raise RuntimeError(_HEX)
        return super().__getattribute__(name)


class _HashRaising(type):
    """A metaclass that raises the key's hex where a class is hashed."""

    @override
    def __hash__(cls) -> int:
        raise RuntimeError(_HEX)


class _MroLying(type):
    """A metaclass that answers a list's MRO for a class that is no list."""

    @override
    def __getattribute__(cls, name: str) -> Any:
        lies = {"__mro__": (cls, list, object), "__bases__": (list,)}
        return lies[name] if name in lies else super().__getattribute__(name)


class _Harmless(type):
    """A metaclass that adds nothing to `type`."""


def _mro_raised() -> object:
    return _MroRaising("_MroRaised", (), {})()


def _hash_raised() -> object:
    return _HashRaising("_HashRaised", (), {})()


def _lied() -> object:
    """Return an instance of a class named by the key's hex."""
    return _MroLying(_HEX, (), {})()


def test_each_metaclass_answers_or_raises_as_it_claims() -> None:
    """`issubclass` against an abstract base class would raise or accept."""
    raised = type(_mro_raised())
    assert raised.__module__ == __name__
    with pytest.raises(RuntimeError, match=_HEX):
        _ = raised.__mro__
    with pytest.raises(RuntimeError, match=_HEX):
        _ = raised.__bases__
    with pytest.raises(RuntimeError, match=_HEX):
        issubclass(raised, Iterable)
    hashed = type(_hash_raised())
    with pytest.raises(RuntimeError, match=_HEX):
        hash(hashed)
    with pytest.raises(RuntimeError, match=_HEX):
        issubclass(hashed, Iterable)
    lying = type(_lied())
    assert lying.__mro__ == (lying, list, object)
    assert lying.__bases__ == (list,)
    assert issubclass(lying, Iterable)


# (the shape, what a refusal names it as)
_SHAPES: tuple[tuple[Callable[[], object], str], ...] = (
    (_mro_raised, "_MroRaised"),
    (_hash_raised, "_HashRaised"),
    (_lied, "a type whose name has 64 characters"),
)

# (the call, the text of its refusal before the type): each tests its
# argument against an abstract base class
_REFUSALS: tuple[tuple[Callable[[Any], object], str], ...] = (
    (lambda v: int_from_json_number(v, "version"), "invalid version type: "),
    (lambda v: bytes_from_octets(b"abc", v), "invalid output size type: "),
    (lambda v: list_from_json_array(v, "inputs"), "invalid inputs type: "),
    (lambda v: assert_type(v, Sequence, "stack"), "invalid stack type: "),
    (reconstruct, "invalid compact_block type: "),
    (to_script_flags, "invalid script flags type: "),
)


@pytest.mark.parametrize("shape, name", _SHAPES, ids=["mro", "hash", "lying"])
@pytest.mark.parametrize(
    "call, text",
    _REFUSALS,
    ids=[
        "int_from_json_number",
        "bytes_from_octets",
        "list_from_json_array",
        "assert_type",
        "reconstruct",
        "to_script_flags",
    ],
)
def test_a_refusal_is_btclib_s_whatever_the_metaclass(
    shape: Callable[[], object], name: str, call: Callable[[Any], object], text: str
) -> None:
    """The library's own refusal, never the metaclass's error or answer."""
    with pytest.raises(BTClibTypeError) as e:
        call(shape())
    assert str(e.value) == text + name
    assert_secret_free(e.value, _SECRETS)


def test_a_class_is_answered_from_what_it_derives_from() -> None:
    """A list or a tuple whose metaclass raises is still one."""
    stack = _MroRaising("_RaisingList", (list,), {})([b"\x01"])
    assert_type(stack, Sequence, "stack")
    assert list_from_json_array(stack, "stack") == [b"\x01"]
    sizes = _HashRaising("_RaisingTuple", (tuple,), {})((3,))
    assert bytes_from_octets(b"abc", sizes) == b"abc"


class _Registered:
    """A class that is a `Sequence` only by its registration."""


Sequence.register(_Registered)


def _own_iter(_: object) -> Iterator[int]:
    return iter((3,))


def test_what_such_a_class_itself_defines_or_registers_does_not_count() -> None:
    """Its own `__iter__` decides nothing, nor does its registration here.

    Its registration is asked through its own metaclass, which adds
    nothing to `type` here and answers False about its ancestors.

    A base's are, where its metaclass is one of the three.
    """
    assert_type(_Registered(), Sequence, "stack")
    derived = _Harmless("_Derived", (_Registered,), {})()
    assert_type(derived, Sequence, "stack")

    other: type = _Harmless("_OtherRegistered", (), {})
    Sequence.register(other)
    below = _Harmless("_Below", (other,), {})
    assert issubclass(below, Sequence)
    with pytest.raises(BTClibTypeError, match="^invalid stack type: _Below$"):
        assert_type(below(), Sequence, "stack")

    registered: type = _Harmless("_SelfRegistered", (), {})
    Sequence.register(registered)
    assert issubclass(registered, Sequence)
    with pytest.raises(BTClibTypeError, match="^invalid stack type: _SelfRegistered$"):
        assert_type(registered(), Sequence, "stack")

    own = _Harmless("_OwnIter", (), {"__iter__": _own_iter})
    assert issubclass(own, Iterable)
    assert tuple(own()) == (3,)
    with pytest.raises(BTClibTypeError, match="^invalid output size type: _OwnIter$"):
        bytes_from_octets(b"abc", own())


class _IterAncestor:
    """A plain class that defines `__iter__`, registered with nothing."""

    def __iter__(self) -> Iterator[int]:
        return iter((3,))


def _iter_none_own() -> object:
    """Return a value of a key-named class that unsets `__iter__`."""
    return _Harmless(_HEX, (_IterAncestor,), {"__iter__": None})()


def _iter_none_between() -> object:
    """Return a value of a key-named class below one that unsets `__iter__`."""
    between = _Harmless("_Between", (_IterAncestor,), {"__iter__": None})
    return _Harmless(_HEX, (between,), {})()


# (the iteration, the text of its refusal before the type)
_ITERATIONS: tuple[tuple[Callable[[Any], object], str], ...] = (
    (lambda v: bytes_from_octets(b"abc", v), "invalid output size type: "),
    (lambda v: list_from_json_array(v, "inputs"), "invalid inputs type: "),
    (to_script_flags, "invalid script flags type: "),
)


@pytest.mark.parametrize(
    "shape", [_iter_none_own, _iter_none_between], ids=["own", "between"]
)
@pytest.mark.parametrize(
    "call, text",
    _ITERATIONS,
    ids=["bytes_from_octets", "list_from_json_array", "to_script_flags"],
)
def test_an_iterable_that_iteration_refuses_is_refused_as_its_type(
    shape: Callable[[], object], call: Callable[[Any], object], text: str
) -> None:
    """Its TypeError names the class, and is neither cause nor context."""
    assert tuple(_IterAncestor()) == (3,)
    value = shape()
    with pytest.raises(TypeError, match=_HEX):
        iter(value)  # type: ignore[call-overload]
    with pytest.raises(BTClibTypeError) as e:
        call(value)
    assert str(e.value) == f"{text}a type whose name has 64 characters"
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, _SECRETS)


class _ObjectRaising(type):
    """A metaclass whose subclass test raises the key's hex for `object`."""

    @override
    def __subclasscheck__(cls, subclass: type) -> bool:
        if subclass is object:
            raise RuntimeError(_HEX)
        return super().__subclasscheck__(subclass)


# an abstract base class of the tests' own, so no other test sees what
# is registered with it
_Abstract = ABCMeta("_Abstract", (), {})


class _RegisteredRaising(metaclass=_ObjectRaising):
    pass


class _Unregistered:
    pass


_Abstract.register(_RegisteredRaising)


@pytest.mark.parametrize(
    "value, name",
    [
        (_RegisteredRaising(), "a type whose name has 18 characters"),
        (_Unregistered(), "_Unregistered"),
    ],
)
def test_a_class_registered_with_the_base_decides_no_refusal(
    value: object, name: str
) -> None:
    """`issubclass` asks a registered class about an ancestor; it raises."""
    with pytest.raises(BTClibTypeError) as e:
        assert_type(value, _Abstract, "stack")
    assert str(e.value) == f"invalid stack type: {name}"
    assert_secret_free(e.value, _SECRETS)


_BUILTINS = (bytes, bytearray, list, tuple, str, int)


class _MroDropping(type):
    """A metaclass whose own `mro()` leaves out a base's built-in."""

    @override
    def mro(cls) -> list[type]:
        return [kind for kind in super().mro() if kind not in _BUILTINS]


def _dropping(base: type, value: object) -> Any:
    """Return `value` as a `base`, its class's MRO leaving `base` out.

    The class is named by the key's hex. It is assigned to `__class__`,
    since PyPy builds no instance of such a class.
    """
    held = type("_Held", (base,), {})(value)
    held.__class__ = _MroDropping(_HEX, (type(held),), {})
    return held


def test_a_metaclass_mro_dropping_a_built_in_is_as_it_claims() -> None:
    """The class's MRO holds no built-in; its base's does."""
    value = _dropping(bytes, b"\x01")
    assert bytes not in type(value).__mro__
    assert bytes in type(value).__mro__[1].__mro__


_MRO_DROPPED: tuple[tuple[Callable[[], object], str], ...] = (
    (lambda: bytes_from_octets(_dropping(bytes, b"\x01")), "invalid octets type"),
    (lambda: bytes_from_octets(_dropping(bytearray, b"\x01")), "invalid octets type"),
    (lambda: bytes_from_octets(_dropping(str, "01")), "invalid octets type"),
    (
        lambda: bytes_from_octets(b"\x01", _dropping(int, 1)),
        "invalid output size type",
    ),
    (lambda: int_from_json_number(_dropping(int, 5), "n"), "invalid n type"),
    (lambda: list_from_json_array(_dropping(list, [1]), "a"), "invalid a type"),
    (lambda: to_script_flags(_dropping(str, "P2SH")), "invalid script flags type"),
    (lambda: assert_type(_dropping(tuple, (1,)), tuple, "t"), "invalid t type"),
)


@pytest.mark.parametrize("refused, what", _MRO_DROPPED)
def test_a_class_is_not_answered_from_a_built_in_its_mro_leaves_out(
    refused: Callable[[], object], what: str
) -> None:
    """A base counts only where the class's MRO holds the base's own."""
    with pytest.raises(BTClibTypeError) as e:
        refused()
    assert str(e.value) == f"{what}: a type whose name has 64 characters"
    assert_secret_free(e.value, _SECRETS)


def test_a_padding_fault_of_such_a_class_is_written_unknown() -> None:
    """`_padding_fault_at` takes it for no `bytes`, and copies nothing."""
    assert _padding_fault_at(_dropping(bytes, b"p\x00Z")) == "?"
    assert _padding_fault_at(_dropping(bytearray, b"p\x00Z")) == "?"
