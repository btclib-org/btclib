# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the one rule on a private signature: it carries no default.

A default argument is written for a caller the author cannot see, and a
leading underscore says there is none: every call site is in this tree and
can be read. What the default buys is therefore nothing, and what it costs
is the value the call is actually made with -- `_deserialize_scalar`'s
`strict` decides whether BIP66's minimal encoding is enforced,
`_decode_from_bip32_deriv`'s `check_validity` whether anything is
validated at all, and defaulted, each reads as absent at the call site
that most needs to state it. Spelled out, a flag added to a private
function is also a question asked again at every one of its call sites,
where a default answers it for all the ones nobody revisited.

The two underscore spellings pull opposite ways here, and the rule names
one of them. A trailing underscore is public -- `dsa.verify_`, `ssa.sign_`
-- and its signature mirrors the plain sibling's, defaults included, or
the pair is two functions rather than a bypass; a leading underscore is
private, and a default on it is a convenience for nobody.
`_rfc6979_nonce_` carries both and is private: the leading underscore is
what decides. CONTRIBUTING.md's "The public surface" states both
conventions, and this rule beside them.

Two spellings the rule does not reach: a dunder, whose signature is the
interpreter's protocol and a public constructor's where it is `__init__`,
and a public method of a private class, the rule being about the name a
call site reads. A name-mangled `__two_leading_underscores` is private and
is reached.

The library and not this directory, which is a scope and not an oversight:
a test helper's default is doing the opposite work. `_tx(version=1,
lock_time=0)` of `integer_policy_test.py` is a valid transaction with one
field overridden per case, so the defaults *are* the fixture, and what a
caller states is the field under test -- naming the other one at each site
would bury it.

The walk reads the sources instead of importing the modules, so that a
method and a nested function are reached as well; the two tests after the
gate are what keep it from passing on a walk that found nothing.
"""

from __future__ import annotations

import ast
from pathlib import Path

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib"

# the shapes the walk has to be reaching for the gate to mean anything: a
# module-level function, a method of a private class, and a name-mangled
# function. A rename here is a failure worth reading rather than fixing
# blind -- what it asks for is the new name of the same shape
_SHAPES = frozenset(
    {"_to_num", "_derive", "_Decoder._op_code", "__prv_key_path_derivation"}
)

# every private function of a module, with the parameters it defaults:
# what `_private_functions` answers, and what the checker test pins
_EXPECTED: dict[str, list[str]] = {
    "_plain": ["b"],
    "_positional_only": ["a"],
    "_keyword_only": ["flag"],
    "_no_default": [],
    "__mangled": ["a"],
    "_Private._method": ["a"],
    "Public._method": ["flag"],
    "outer._nested": ["b"],
}

# one function per shape, defaulted and clean, private and public: the
# source the checker is measured on, so that what it reports is a
# statement about the tree and not about the walk
_SOURCE = """
def public(a=1): ...


def _plain(a, b=2): ...


def _positional_only(a=1, /): ...


def _keyword_only(*, flag=False): ...


def _no_default(a, b): ...


def __mangled(a=1): ...


class _Private:
    field: int = 0

    def __init__(self, a=1): ...

    def public_method(self, a=1): ...

    def _method(self, a=1): ...


class Public:
    def _method(self, *, flag=True): ...


def outer(a=1):
    def _nested(b=2): ...

    return _nested
"""


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def _defaulted(args: ast.arguments) -> list[str]:
    """Return the parameters of a signature that have a default.

    The positional defaults align to the *end* of the positional
    parameters, positional-only ones included, and the keyword-only
    defaults align one-to-one with `kwonlyargs`, `None` where there is
    none -- a shape a `zip` cannot be read off without `strict`.
    """
    positional = args.posonlyargs + args.args
    defaulted = positional[len(positional) - len(args.defaults) :]
    return [arg.arg for arg in defaulted] + [
        arg.arg
        for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True)
        if default is not None
    ]


def _private_functions(source: str) -> dict[str, list[str]]:
    """Return the private functions of a module, each with its defaults.

    Keyed by qualified name, so a failure names the function and not only
    the file, and carrying the clean ones too: which functions the walk
    reached is itself asserted below.
    """
    found: dict[str, list[str]] = {}

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}{child.name}"
                if child.name.startswith("_") and not _is_dunder(child.name):
                    found[name] = _defaulted(child.args)
                visit(child, f"{name}.")

    visit(ast.parse(source), "")
    return found


def test_no_private_function_takes_a_default_argument() -> None:
    """The gate: the library's private signatures are all bare.

    One failure line per parameter rather than per function, the fix
    being per parameter: drop the default, and pass the value at each
    call site -- which is the diff that makes the composition readable,
    not a cost of the rule.
    """
    offenders = [
        f"{path.relative_to(_LIBRARY.parent)}: {name}({parameter}=...)"
        for path in sorted(_LIBRARY.rglob("*.py"))
        for name, parameters in _private_functions(
            path.read_text(encoding="utf-8")
        ).items()
        for parameter in parameters
    ]
    assert not offenders, (
        "a private function takes no default argument, its callers being"
        " this tree's own: " + ", ".join(offenders)
    )


def test_the_checker_reads_every_shape_a_signature_has() -> None:
    """What the gate is worth, measured on a source with known answers.

    Each half is a way for the gate to pass while enforcing nothing: a
    walk that skips methods, mangled names or nested functions would not
    see a default there, and a walk that took a public function or a
    dunder for private would report one where the rule allows it.
    """
    assert _private_functions(_SOURCE) == _EXPECTED


def test_the_walk_reaches_the_library() -> None:
    """The gate over an empty walk would pass, and say nothing.

    A wrong path, a suffix that matches no file, or a walk that stops at
    module level all read as a library with no private function in it.
    """
    reached: set[str] = set()
    for path in sorted(_LIBRARY.rglob("*.py")):
        reached |= _private_functions(path.read_text(encoding="utf-8")).keys()
    assert reached >= _SHAPES, (
        "the walk no longer reaches: "
        + ", ".join(sorted(_SHAPES - reached))
        + ". If one was renamed, name its replacement -- the shapes are what"
        " the gate above is asserted over"
    )
