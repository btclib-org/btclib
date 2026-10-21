# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A fuzz/corpus/ seed is still a valid serialization of what it parses.

This module reads `fuzz/fuzz_<name>.py` with `ast` and never executes it.
It resolves what a harness *names* against the installed btclib.
`fuzz_harness_test.py` is the other half: it runs each harness's
`fuzz_target` on its seeds.

`ENTRY_POINTS`, a module-level tuple of `"module:Qual.name"` strings,
is what each harness names. Where an entry point takes more than the
input, `ENTRY_POINTS` is a dict from that string to the tuple of what
follows the input in the call, and a name in it stands for the
module-level literal assigned to it above. `.github/scripts/compare_release.py`
calls the entry points as this declaration says.
`test_entry_points_are_declared` below finds it with `ast.literal_eval`;
`test_entry_points_match_the_calls` cross-checks it, arguments included,
against the `.parse`, `.b64decode` and `.*_response` calls `fuzz_target`'s
own body makes, walked with `ast` rather than matched with a regex -- a
character class for the callee, `[A-Za-z_]+.parse`, would still have to
answer which import a bare name resolves to, and one reaching for the
whole dotted call loses `AddrV2.parse` to a class that excludes the digit.

A harness that tries several classes calls `cls.parse(data)` inside a
`for cls in (A, B, ...):` loop rather than naming a callee directly, so
walking the call site alone resolves nothing: `cls` is a loop variable,
not an import. The cross-check reads the loop's own iterable instead,
which is still a tuple of imported names, and cross-checks those in the
callee's place -- so every harness is checked the same way, and none of
them is taken on faith.

`test_every_seed_is_accepted` and `test_accepted_seed_round_trips` are
the corpus half: every seed is tried against every one of its harness's
declared entry points, and passes if at least one accepts it without
raising `BTClibException`. Where the accepting object serializes --
`.serialize()`, or `.b64encode()` behind a `.b64decode()` entry point --
the reserialization has to reproduce the seed's own bytes. A parser that
answers with a plain value has its module's `serialize` named in
`_WRITERS` below: `var_int.parse` and `var_bytes.parse` must reproduce
the bytes, and `script.parse` and `taproot.parse` the weaker form their
harnesses assert, since a script has several encodings of one value: the
octets written parse back to the same commands.

**Trying every declared entry point rather than picking one by filename
convention buys the manifest's simplicity at a stated price: where a
harness's entry points are two names bound to distinct implementations
whose accepted languages overlap, what this gate guarantees is
acceptance by *some* declared entry point, not by the intended one.**
Two names sharing one implementation cannot mask their own regression
(`fuzz_keepalive`'s `Ping.parse` and `Pong.parse` are both
`_NoncePayload.parse`), and two distinct implementations are safe where
one refuses whatever the other's language admits (`fuzz_addrv2`'s
`SendAddrV2.parse` refuses any non-empty payload). Neither case covers
this corpus, measured by running `_accept` over it: `fuzz_block_filters`'
`CFilter.parse` and `CFCheckpt.parse` each accept both `cfilter.bin`
and `cfcheckpt.bin`, `fuzz_compact_blocks`' `GetBlockTxn.parse` and
`BlockTxn.parse` both `getblocktxn.bin` and `blocktxn.bin`,
`fuzz_inventory`'s `inv.bin`, `getdata.bin` and `notfound.bin` are
accepted across payload implementations that share nothing, and
`fuzz_negotiation`'s empty-payload parsers accept each other's seeds by
construction. In those harnesses a parser narrowed to refuse its own
seed passes here while a sibling still accepts and round-trips it --
that masking is the price, it is paid today rather than by some future
entry point, and what covers it is the harness's own fuzzing rather
than this gate. The cross-check above does not see any of it: it proves
a tuple matches what a harness calls, not that the callees it names are
pairwise distinguishable.

A seed may legitimately be empty. `Verack`, `SendAddrV2`, `GetAddr`,
`Mempool`, `SendHeaders` and `WtxidRelay` are real messages whose whole
payload is `b""`, each accepted and reserialized to `b""`, so nothing
here asks a seed to be non-empty -- only that no seed ends in the
newline a fixer appends.
"""

from __future__ import annotations

import ast
import contextlib
import copy
import importlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typing_extensions import override

from btclib import var_bytes, var_int
from btclib.exceptions import BTClibException
from btclib.script import script, taproot

_FUZZ = Path(__file__).parent.parent / "fuzz"
_CORPUS = _FUZZ / "corpus"


def _harness_paths() -> tuple[Path, ...]:
    """Every fuzz/fuzz_*.py, sorted for a stable parametrize order."""
    return tuple(sorted(_FUZZ.glob("fuzz_*.py")))


def _parse_module(source: str, filename: str) -> ast.Module:
    return ast.parse(source, filename=filename)


class _Inline(ast.NodeTransformer):
    """Replace each name by the value `values` gives it."""

    def __init__(self, values: dict[str, Any]) -> None:
        self.values = values

    @override
    def visit_Name(self, node: ast.Name) -> ast.Constant:
        if node.id not in self.values:
            raise ValueError(node.id)
        return ast.Constant(self.values[node.id])


def _literal(node: ast.expr, values: dict[str, Any]) -> Any:
    """Return the literal `node` is, a name standing for its value."""
    return ast.literal_eval(_Inline(values).visit(copy.deepcopy(node)))


def _literals(tree: ast.Module) -> dict[str, Any]:
    """Return each module-level `NAME = <literal>` of `tree`, in order."""
    values: dict[str, Any] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            with contextlib.suppress(ValueError):
                values[node.targets[0].id] = _literal(node.value, values)
    return values


def _entry_points(tree: ast.Module) -> dict[str, tuple[Any, ...]] | None:
    """Return ENTRY_POINTS as a dict from entry point to arguments, or None."""
    value = _literals(tree).get("ENTRY_POINTS")
    if value is None:
        return None
    if isinstance(value, tuple):
        value = dict.fromkeys(value, ())
    assert isinstance(value, dict)
    assert all(isinstance(k, str) and isinstance(v, tuple) for k, v in value.items())
    return value


def _fuzz_target(tree: ast.Module) -> ast.FunctionDef | None:
    """Return the module-level `def fuzz_target(...)`, or None."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "fuzz_target":
            return node
    return None


def _import_bindings(tree: ast.Module) -> dict[str, tuple[str, str]]:
    """Map a module-level `from X import Y [as Z]` local name to (X, Y)."""
    bindings: dict[str, tuple[str, str]] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                bindings[alias.asname or alias.name] = (node.module, alias.name)
    return bindings


def _loop_expansions(func: ast.FunctionDef) -> dict[str, list[str]]:
    """Map a `for X in (A, B, ...):` target to the tuple's own names.

    The only shape this reads: a for loop whose target is a bare name and
    whose iterable is a tuple literal of bare names. Every other loop --
    there is none today -- leaves the target unexpanded, which is what
    lets `_called_specs` below fail loudly on it instead of resolving
    something it did not check.
    """
    expansions: dict[str, list[str]] = {}
    for node in ast.walk(func):
        if (
            isinstance(node, ast.For)
            and isinstance(node.target, ast.Name)
            and isinstance(node.iter, ast.Tuple)
            and all(isinstance(elt, ast.Name) for elt in node.iter.elts)
        ):
            names = [elt.id for elt in node.iter.elts if isinstance(elt, ast.Name)]
            expansions[node.target.id] = names
    return expansions


def _canonical_spec(module: str, remote: str, attr: str) -> str:
    """Return "module:Qual.name", telling a submodule bind from a class one.

    `from btclib import var_bytes; var_bytes.parse(...)` binds a module,
    where `parse` is that module's own function; `from btclib.ecc.bms
    import Sig; Sig.b64decode(...)` binds a class, where `b64decode` is a
    method on it. Trying the submodule import is what
    tells the two apart, both being an ordinary `from X import Y` to the
    AST alone.
    """
    try:
        importlib.import_module(f"{module}.{remote}")
    except ModuleNotFoundError:
        return f"{module}:{remote}.{attr}"
    return f"{module}.{remote}:{attr}"


def _called_specs(
    func: ast.FunctionDef,
    bindings: dict[str, tuple[str, str]],
    values: dict[str, Any],
) -> dict[str, list[tuple[Any, ...]]]:
    """Every .parse, .b64decode and .*_response call `func` makes.

    Each spec maps to what its calls pass after the input, one tuple per
    call, a name read as the value `values` gives it.
    """
    expansions = _loop_expansions(func)
    specs: dict[str, list[tuple[Any, ...]]] = {}
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        if not isinstance(callee, ast.Attribute):
            continue
        if callee.attr not in ("parse", "b64decode") and not callee.attr.endswith(
            "_response"
        ):
            continue
        if not isinstance(callee.value, ast.Name):
            continue
        if node.keywords:
            msg = f"{ast.unparse(node)} passes a keyword, which ENTRY_POINTS cannot say"
            raise AssertionError(msg)
        arguments = tuple(_literal(arg, values) for arg in node.args[1:])
        for name in expansions.get(callee.value.id, [callee.value.id]):
            if name not in bindings:
                msg = f"{name!r} is called with .{callee.attr} and imported nowhere"
                raise AssertionError(msg)
            module, remote = bindings[name]
            spec = _canonical_spec(module, remote, callee.attr)
            specs.setdefault(spec, []).append(arguments)
    return specs


def _resolve(spec: str) -> Any:
    """Import spec's ("module:Qual.name") callable against installed btclib."""
    module_name, _, qualname = spec.partition(":")
    obj: Any = importlib.import_module(module_name)
    for part in qualname.split("."):
        obj = getattr(obj, part)
    return obj


def _reserialize(obj: Any) -> bytes:
    """Reserialize `obj`, supplying the one required argument this corpus needs.

    Every `.serialize` in this tree defaults `check_validity`, except
    `Tx.serialize`, whose `include_witness` has none: BIP144's marker is
    optional on the wire, so the class asks which encoding is wanted
    rather than guessing. True reproduces either byte for byte --
    `Tx.serialize`'s own docstring is where that is argued, the marker
    written only where a witness is actually present -- which is why no
    caller here has to know which of the two a seed carries.
    """
    try:
        return obj.serialize()  # type: ignore[no-any-return]
    except TypeError:
        return obj.serialize(include_witness=True)  # type: ignore[no-any-return]


# The entry points whose parse answers with a plain value, so there is no
# `.serialize` to call: the module's own function writes it back. The flag
# is True where the format has several encodings of one value, and the
# harness then asserts that the written octets parse back to the same
# value rather than that they reproduce the input.
_WRITERS: dict[str, tuple[Callable[[Any], bytes], bool]] = {
    "btclib.var_int:parse": (var_int.serialize, False),
    "btclib.var_bytes:parse": (var_bytes.serialize, False),
    "btclib.script.script:parse": (script.serialize, True),
    "btclib.script.taproot:parse": (taproot.serialize, True),
}


def _written_settles(spec: str, obj: Any) -> bool:
    """Return whether the octets written for `obj` parse back to `obj`."""
    write, _ = _WRITERS[spec]
    reparse = _resolve(spec)
    if obj[-1:] == [script.ERROR_COMMAND]:
        # a place in the bytes and not an instruction, which serialize refuses
        obj = obj[:-1]
    return bool(reparse(write(obj)) == obj)


def _round_trip(spec: str, obj: Any, data: bytes) -> bool | None:
    """Return whether `obj` passes its harness's round trip on `data`.

    None where nothing is checked.
    """
    if spec in _WRITERS:
        write, several_encodings = _WRITERS[spec]
        if several_encodings:
            return _written_settles(spec, obj)
        return write(obj) == data
    attr = spec.rsplit(".", 1)[-1]
    if attr == "b64decode":
        if not hasattr(obj, "b64encode"):
            return None
        return bool(obj.b64encode() == data.decode("ascii"))
    if not hasattr(obj, "serialize"):
        return None
    return _reserialize(obj) == data


def _seed_paths(name: str) -> tuple[Path, ...]:
    return tuple(sorted((_CORPUS / name).glob("*.bin")))


def _accept(
    spec: str, arguments: tuple[Any, ...], data: bytes
) -> tuple[bool, bool | None]:
    """Try `spec` against `data`; return (accepted, round_trip)."""
    entry_point = _resolve(spec)
    try:
        obj = entry_point(data, *arguments)
    except BTClibException:
        return False, None
    return True, _round_trip(spec, obj, data)


# ---- the corpus, read once so every test below parametrizes over it -------

_HARNESSES = _harness_paths()
_SEEDS = tuple(
    (path.stem, seed) for path in _HARNESSES for seed in _seed_paths(path.stem)
)


def test_the_corpus_is_not_empty() -> None:
    """Every assertion below quantifies over _HARNESSES and _SEEDS."""
    assert _HARNESSES, f"{_FUZZ} holds no fuzz_*.py"
    assert _SEEDS, f"{_CORPUS} holds no seed"


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_every_harness_has_a_corpus_directory(path: Path) -> None:
    """A harness with no seeds is one no gate here has ever checked."""
    assert (_CORPUS / path.stem).is_dir(), f"fuzz/corpus/{path.stem}/ does not exist"


def test_every_corpus_directory_has_a_harness() -> None:
    """A directory outliving the harness it was named for is dead weight."""
    harness_names = {path.stem for path in _HARNESSES}
    orphans = sorted(
        d.name for d in _CORPUS.iterdir() if d.is_dir() and d.name not in harness_names
    )
    assert not orphans, (
        f"fuzz/corpus/ directories with no fuzz_*.py: {', '.join(orphans)}"
    )


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_entry_points_are_declared(path: Path) -> None:
    """ENTRY_POINTS exists and is not the empty tuple."""
    tree = _parse_module(path.read_text(encoding="utf-8"), str(path))
    declared = _entry_points(tree)
    assert declared, f"{path.name} declares no non-empty ENTRY_POINTS"


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_entry_points_resolve(path: Path) -> None:
    """Each declared entry point imports against the installed btclib."""
    tree = _parse_module(path.read_text(encoding="utf-8"), str(path))
    declared = _entry_points(tree)
    assert declared
    for spec in declared:
        assert callable(_resolve(spec)), (
            f"{path.name}'s {spec!r} does not resolve to a callable"
        )


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_entry_points_match_the_calls(path: Path) -> None:
    """ENTRY_POINTS is exactly what fuzz_target's own body calls."""
    tree = _parse_module(path.read_text(encoding="utf-8"), str(path))
    declared = _entry_points(tree)
    assert declared
    func = _fuzz_target(tree)
    assert func is not None, f"{path.name} defines no module-level fuzz_target"
    bindings = _import_bindings(tree)
    called = _called_specs(func, bindings, _literals(tree))
    assert set(called) == set(declared), (
        f"{path.name}'s ENTRY_POINTS {sorted(declared)} does not match what"
        f" fuzz_target calls: {sorted(called)}"
    )
    for spec, arguments in declared.items():
        assert all(called_with == arguments for called_with in called[spec]), (
            f"{path.name} calls {spec} with {called[spec]} after the input,"
            f" and its ENTRY_POINTS says {arguments}"
        )


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_corpus_directory_is_not_empty(path: Path) -> None:
    """A harness's own directory holds at least one seed."""
    assert _seed_paths(path.stem), f"fuzz/corpus/{path.stem}/ has no seed"


@pytest.mark.parametrize(
    "seed",
    [seed for _, seed in _SEEDS],
    ids=[str(seed.relative_to(_CORPUS)) for _, seed in _SEEDS],
)
def test_seed_has_no_trailing_newline(seed: Path) -> None:
    """A newline a fixer appended is what broke a seed before (#1402)."""
    assert not seed.read_bytes().endswith(b"\n"), f"{seed} ends with a newline"


@pytest.mark.parametrize(
    "harness, seed",
    _SEEDS,
    ids=[str(seed.relative_to(_CORPUS)) for _, seed in _SEEDS],
)
def test_every_seed_is_accepted(harness: str, seed: Path) -> None:
    """At least one of the harness's declared entry points accepts the seed."""
    tree = _parse_module((_FUZZ / f"{harness}.py").read_text(encoding="utf-8"), harness)
    declared = _entry_points(tree)
    assert declared
    data = seed.read_bytes()
    accepted = [spec for spec, args in declared.items() if _accept(spec, args, data)[0]]
    assert accepted, f"{seed} is refused by every declared entry point: {declared}"


@pytest.mark.parametrize(
    "harness, seed",
    _SEEDS,
    ids=[str(seed.relative_to(_CORPUS)) for _, seed in _SEEDS],
)
def test_accepted_seed_round_trips(harness: str, seed: Path) -> None:
    """Where a round trip is checkable, the seed passes its harness's."""
    tree = _parse_module((_FUZZ / f"{harness}.py").read_text(encoding="utf-8"), harness)
    declared = _entry_points(tree)
    assert declared
    data = seed.read_bytes()
    mismatches = [
        spec
        for spec, args in declared.items()
        for accepted, round_trip in (_accept(spec, args, data),)
        if accepted and round_trip is False
    ]
    assert not mismatches, f"{seed} does not round-trip under: {mismatches}"


@pytest.mark.parametrize(
    "spec, data",
    [
        ("btclib.var_int:parse", b"\xfd\xfc\x00"),
        ("btclib.var_bytes:parse", b"\xfd\x01\x00\x00"),
    ],
)
def test_a_non_canonical_length_is_refused_not_reserialized(
    spec: str, data: bytes
) -> None:
    """A var_int or var_bytes has one encoding: the parser refuses these."""
    with pytest.raises(BTClibException):
        _resolve(spec)(data)


def test_a_script_has_several_encodings_of_one_value() -> None:
    """A push over a wider operator is why a script is held to the weak form."""
    data = bytes.fromhex("4c0141")
    commands = script.parse(data)
    assert script.serialize(commands) != data
    assert _round_trip("btclib.script.script:parse", commands, data) is True
    assert _round_trip("btclib.script.taproot:parse", taproot.parse(data), data)


@pytest.mark.parametrize(
    "data", [b"\x4c\x00", b"\x4d\x00\x00", b"\x4e\x00\x00\x00\x00"]
)
def test_an_empty_push_in_any_width_parses_back_to_the_same_commands(
    data: bytes,
) -> None:
    """Every width of an empty push is the same command, as OP_0 is."""
    assert script.parse(data) == script.parse(b"\x00")
    assert taproot.parse(data) == taproot.parse(b"\x00")
    assert _round_trip("btclib.script.script:parse", script.parse(data), data) is True
    assert _round_trip("btclib.script.taproot:parse", taproot.parse(data), data) is True


def test_the_round_trip_sees_a_difference() -> None:
    """The control: a writer that disagrees with the input is not a pass."""
    assert _round_trip("btclib.var_int:parse", 1, b"\x02") is False
    assert _round_trip("btclib.var_bytes:parse", b"", b"\x01\x00") is False


def test_a_script_ending_in_the_error_command_is_checked_without_it() -> None:
    """A push running past the end is decoded, and its marker not written."""
    data = bytes.fromhex("514c")
    commands = script.parse(data)
    assert commands[-1] == script.ERROR_COMMAND
    assert _round_trip("btclib.script.script:parse", commands, data) is True


# ---- unit tests of the pure ast helpers, for the branches no harness trips


def _module(source: str) -> ast.Module:
    return ast.parse(source, filename="<synthetic>")


def test_entry_points_returns_none_absent() -> None:
    """A module with no ENTRY_POINTS assignment is not mistaken for one."""
    assert _entry_points(_module("x = 1\n")) is None


def test_fuzz_target_returns_none_absent() -> None:
    """A module with no fuzz_target is not mistaken for one."""
    assert _fuzz_target(_module("def other() -> None:\n    pass\n")) is None


def test_called_specs_rejects_an_unbound_callee() -> None:
    """A callee this test cannot trace to an import is a loud failure.

    Never trips on the harnesses this corpus has, each of whose calls
    resolves either directly or through a for loop's own tuple; this is
    what a harness calling something imported neither way would hit
    instead of being silently skipped.
    """
    source = "def fuzz_target(data):\n    unknown.parse(data)\n"
    func = _fuzz_target(_module(source))
    assert func is not None
    with pytest.raises(AssertionError, match="imported nowhere"):
        _called_specs(func, {}, {})


def test_called_specs_ignores_a_bare_name_call() -> None:
    """A call with no namespace in front, `parse(data)`, is not checked.

    Every entry point in this corpus is reached through an imported name
    or a class, never a bare function in local scope, and no harness
    calls one this way today.
    """
    source = "def fuzz_target(data):\n    parse(data)\n"
    func = _fuzz_target(_module(source))
    assert func is not None
    assert _called_specs(func, {}, {}) == {}


def test_called_specs_ignores_a_two_level_attribute() -> None:
    """`foo.bar.parse(data)` is not one of the calls checked either.

    Every current call is one attribute deep -- `Name.attr(...)` -- which
    is what `_import_bindings` resolves; a chain one level deeper has no
    binding this test can look up, and no harness here writes one.
    """
    source = "def fuzz_target(data):\n    foo.bar.parse(data)\n"
    func = _fuzz_target(_module(source))
    assert func is not None
    assert _called_specs(func, {}, {}) == {}


class _Armored:
    """An object that re-armors to the base64 of one octet."""

    def b64encode(self) -> str:
        return "YQ=="


def test_round_trip_of_a_b64decode_entry_point() -> None:
    """A b64decode entry point re-armors, or is parse-only where it cannot.

    No harness declares a b64decode entry point, so both branches are
    exercised on bare objects rather than on any seed.
    """
    spec = "btclib.ecc.bms:Sig.b64decode"
    assert _round_trip(spec, _Armored(), b"YQ==") is True
    assert _round_trip(spec, _Armored(), b"Yg==") is False
    assert _round_trip(spec, object(), b"") is None


def test_an_answer_with_no_serialization_is_parse_only() -> None:
    """Nothing is compared where the accepted object has no `serialize`."""
    assert _round_trip("btclib.var_int:decode", object(), b"") is None


def test_entry_points_with_arguments() -> None:
    """A dict declares arguments, a name read as the literal assigned to it."""
    source = 'N = 1\nENTRY_POINTS = {"m:f": (N, 2), "m:g": ()}\n'
    assert _entry_points(_module(source)) == {"m:f": (1, 2), "m:g": ()}
    assert _entry_points(_module('ENTRY_POINTS = ("m:f",)\n')) == {"m:f": ()}


def test_literals_skips_what_is_not_a_literal() -> None:
    """A call, or a name assigned nowhere above, is no literal."""
    source = "a = f()\nb = a\nc = (1,)\nd = c\n"
    assert _literals(_module(source)) == {"c": (1,), "d": (1,)}


def test_called_specs_reads_the_arguments_after_the_input() -> None:
    """Each call's arguments are read, a name through `values`."""
    source = "def fuzz_target(data):\n    m.f_response(data, N, 2)\n"
    func = _fuzz_target(_module(source))
    assert func is not None
    bindings = {"m": ("btclib", "var_int")}
    assert _called_specs(func, bindings, {"N": 1}) == {
        "btclib.var_int:f_response": [(1, 2)]
    }


def test_called_specs_rejects_a_keyword_argument() -> None:
    """A keyword ENTRY_POINTS cannot declare is a loud failure."""
    source = "def fuzz_target(data):\n    m.f_response(data, count=2)\n"
    func = _fuzz_target(_module(source))
    assert func is not None
    with pytest.raises(AssertionError, match="passes a keyword"):
        _called_specs(func, {"m": ("btclib", "var_int")}, {})
