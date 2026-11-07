# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every `int` parameter of a `_var` function is `Public`, or says why not.

`CONTRIBUTING.md`'s *A `_var` suffix means the operand decides the work*
is the rule: an integer whose value decides the work is annotated
`ecc.alias.Public`, and mypy then refuses a plain `int` at every call. What
mypy cannot tell is whether a parameter that should carry the type does:
this walk reads every `_var` function, at any depth of a module, private
ones, methods and `async def` included, and fails on a parameter, `*args`
and `**kwargs` included, whose annotation names `int` or `Integer`, a union
or a container of them included, that is neither `Public` nor in
`_NOT_OPERANDS` below with its reason. An alias under another name is not
read.

A point, octets or a key is out of the walk: `Public` is an integer, and
for those the suffix alone states the contract.

The walk also reads `_CONTROL`, a source holding each shape it claims to
reach, so that it is shown to find an integer parameter even where
btclib's own `_var` functions hold none.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_PACKAGE = Path(__file__).parents[1] / "src" / "btclib"

_PUBLIC = {"Public", "Sequence[Public]"}
# any annotation naming `int` or `Integer` that is not exactly `Public`: a
# union or a container of one is walked too, an alias under another name
# is not
_INTEGER = re.compile(r"\b(int|Integer)\b")

# an integer parameter of a `_var` function that is not `Public`, by
# dotted name, with the reason why not
_NOT_OPERANDS: dict[str, str] = {}

# a function, a private one, a method, a sequence and a `_var_`, each with
# a `Public` parameter; an `int` one; a plain name, which is not walked;
# an `int` parameter in each place a walk of the top level would miss; and
# an alias of `int` under another name, which the walk does not read
_CONTROL = """
def double_mult_var(u: Public, w: int) -> None: ...
def _jacobi_var(a: Public) -> None: ...
class CurveGroup:
    def y_var(self, x: Public) -> None: ...
def multi_mult_var(scalars: Sequence[Public]) -> None: ...
def _libsecp256k1_multi_mult_var_(scalars: Sequence[Public]) -> None: ...
def mod_inv(a: int) -> None: ...
if TYPE_CHECKING:
    def guarded_var(a: int) -> None: ...
class Outer:
    class Inner:
        def nested_var(self, a: int) -> None: ...
async def async_var(a: int) -> None: ...
def outer() -> None:
    def inner_var(a: int) -> None: ...
def star_var(*n: int, **k: int) -> None: ...
_Position = int
def leaf_var(p: _Position) -> None: ...
"""

_Function = ast.FunctionDef | ast.AsyncFunctionDef


def _var_functions(module: str, source: str) -> dict[str, _Function]:
    """Map each `_var` function of a module, at any depth, to its node."""
    functions: dict[str, _Function] = {}

    # every node is visited, with the dotted name of the functions and
    # classes around it: a `def` under an `if` is the module's own
    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                if child.name.endswith(("_var", "_var_")):
                    functions[f"{prefix}{child.name}"] = child
                visit(child, f"{prefix}{child.name}.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
            else:
                visit(child, prefix)

    visit(ast.parse(source), f"{module}.")
    return functions


def _integer_parameters(functions: dict[str, _Function]) -> dict[str, str]:
    """Map each walked parameter of a `_var` function to its annotation."""
    found: dict[str, str] = {}
    for name, function in functions.items():
        arguments = function.args
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *([arguments.vararg] if arguments.vararg else []),
            *arguments.kwonlyargs,
            *([arguments.kwarg] if arguments.kwarg else []),
        ]:
            # mypy runs strict over the package: no parameter but
            # `self` lacks an annotation
            if argument.annotation is None:
                continue
            annotation = ast.unparse(argument.annotation)
            if annotation in _PUBLIC or _INTEGER.search(annotation):
                found[f"{name}.{argument.arg}"] = annotation
    return found


def _package_functions() -> dict[str, _Function]:
    """Map each `_var` function of the package to its node."""
    functions: dict[str, _Function] = {}
    for path in sorted(_PACKAGE.rglob("*.py")):
        module = ".".join(path.relative_to(_PACKAGE.parent).with_suffix("").parts)
        functions |= _var_functions(module, path.read_text(encoding="utf-8"))
    return functions


def _unexplained(found: dict[str, str], not_operands: dict[str, str]) -> set[str]:
    """Return the integer parameters neither Public nor given a reason."""
    return {
        name
        for name, annotation in found.items()
        if annotation not in _PUBLIC and name not in not_operands
    }


def _stale(found: dict[str, str], not_operands: dict[str, str]) -> set[str]:
    """Return the reasons naming no integer parameter that is not Public."""
    return {name for name in not_operands if found.get(name, "Public") in _PUBLIC}


_FUNCTIONS = _package_functions()
_FOUND = _integer_parameters(_FUNCTIONS)


def test_every_integer_operand_is_public() -> None:
    """An integer parameter of a `_var` function is Public or has a reason."""
    assert not _unexplained(_FOUND, _NOT_OPERANDS)


def test_every_reason_is_still_needed() -> None:
    """A table entry names an integer parameter that is not Public."""
    assert not _stale(_FOUND, _NOT_OPERANDS)


def test_the_walk_reaches_what_it_claims() -> None:
    """Each shape `_CONTROL` holds, and btclib's own `_var` functions."""
    # btclib's own: a function, a private one, and a method
    assert "btclib.script.taproot.output_pubkey_from_merkle_root_var" in _FUNCTIONS
    assert "btclib.script.taproot._tweaked_pubkey_var" in _FUNCTIONS
    assert "btclib.muhash.MuHash3072.digest_var" in _FUNCTIONS
    found = _integer_parameters(_var_functions("control", _CONTROL))
    assert found == {
        "control.double_mult_var.u": "Public",
        "control.double_mult_var.w": "int",
        "control._jacobi_var.a": "Public",
        "control.CurveGroup.y_var.x": "Public",
        "control.multi_mult_var.scalars": "Sequence[Public]",
        # a name ending in `_var_`, the suffix before a trailing underscore
        "control._libsecp256k1_multi_mult_var_.scalars": "Sequence[Public]",
        # under an `if`, in a nested class, an `async def`, in a function,
        # and `*args` and `**kwargs`
        "control.guarded_var.a": "int",
        "control.Outer.Inner.nested_var.a": "int",
        "control.async_var.a": "int",
        "control.outer.inner_var.a": "int",
        "control.star_var.n": "int",
        "control.star_var.k": "int",
    }
    # a plain name is not walked, an int operand of its own notwithstanding
    assert "control.mod_inv.a" not in found
    # nor is an alias that does not spell `int` or `Integer`
    assert "control.leaf_var.p" not in found
    ints = {name for name, annotation in found.items() if annotation == "int"}
    assert _unexplained(found, {}) == ints
    assert not _unexplained(found, dict.fromkeys(ints, "window"))
    reasons = {"control.double_mult_var.w": "window", "control._jacobi_var.a": "x"}
    assert _stale(found, reasons) == {"control._jacobi_var.a"}
    # a reason naming no parameter at all is stale too
    assert _stale(found, {"control.double_mult_var.v": "x"}) == {
        "control.double_mult_var.v"
    }
