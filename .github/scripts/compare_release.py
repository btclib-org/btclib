# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""List the inputs on which this tree and the last release answer differently.

Every `fuzz/fuzz_*.py` names the functions it fuzzes in `ENTRY_POINTS`, with
what each takes after the input, in the form `tests/fuzz_corpus_test.py`'s
docstring gives. It is read here with `ast` and never imported. Each
entry point is run on every input of its harness in two interpreters, one
with this tree installed and one with the release from the index, and the
two answers are compared. An answer is one of:

- `refused`: the entry point raised `BTClibException`;
- `accepted <description>`: it returned an object, described by the hex of
  what `serialize()` writes, by `repr` where it is a plain value or a
  dataclass, and by its type name alone otherwise;
- `unserializable <name>`: it returned an object whose description raised;
- `crashed <name>`: it raised anything else;
- `absent`: the entry point is not importable.

A difference is an entry point that accepts on one side only, accepts and
serializes differently, refuses where the other crashes, crashes
differently, or is absent from one side. An entry point absent from both
sides is listed too, as `absent from both`: nothing was compared for it.

The inputs are `fuzz/corpus/<harness>/*.bin` and, where
`--fuzz-artifacts` names a directory, the corpora the `fuzz` workflow
uploads as `cifuzz-corpus-<harness>` tar files.

    uv sync --locked --no-default-groups --group bip324
    uv run --locked --no-default-groups python \
        .github/scripts/compare_release.py \
        --current .venv/bin/python --release <venv>/bin/python

Not a gate. The exit status is 0 whenever the comparison ran, whatever it
found: the markdown on stdout is the report. A difference is not a defect,
and a pull request that causes an intended one names it.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import copy
import dataclasses
import importlib
import json
import subprocess
import sys
import tarfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from typing_extensions import override

_ROOT = Path(__file__).resolve().parents[2]
# one interpreter's whole run, in seconds. The two run one after the other
# and together take at most half the job's `timeout-minutes` in
# release-diff.yml, so this timeout fires before the job is cancelled and
# the log names the interpreter that ran out of time.
_TIMEOUT = 300
# rows listed in the report before it says how many more there are
_MAX_ROWS = 200
# the longest answer shown in a row, in characters, and how many of the
# characters before the first difference come with it
_CLIP = 72
_CONTEXT = 8
# what `repr` is trusted to print the same way in both interpreters
_PLAIN = (type(None), bool, int, float, str, bytes, list, tuple, dict)

ABSENT = "absent"
# the kinds of row listed once per entry point, not per input
_ABSENT_ONE = "entry point absent"
_ABSENT_BOTH = "absent from both"
# the first word of an outcome where the entry point returned an object
_ACCEPTED = ("accepted", "unserializable")
# one record of a probe: (harness, entry point, input name, outcome)
Record = tuple[str, str, str, str]


# ---- the probe: runs inside each interpreter, with its btclib ------------


def _resolve(spec: str) -> Any:
    """Return the callable `spec` ("module:Qual.name") names."""
    module_name, _, qualname = spec.partition(":")
    obj: Any = importlib.import_module(module_name)
    for part in qualname.split("."):
        obj = getattr(obj, part)
    return obj


def _reserialize(obj: Any) -> bytes:
    """Return `obj.serialize()`, `Tx`'s `include_witness` being required."""
    try:
        return obj.serialize()  # type: ignore[no-any-return]
    except TypeError:
        return obj.serialize(include_witness=True)  # type: ignore[no-any-return]


def _describe(obj: Any) -> str:
    """Return what the accepted `obj` is, in a form both sides print alike."""
    if hasattr(obj, "serialize"):
        return _reserialize(obj).hex()
    if dataclasses.is_dataclass(obj) or isinstance(obj, _PLAIN):
        return repr(obj)
    return type(obj).__name__


def _answer(
    parser: Any, refusal: type[Exception], data: bytes, arguments: tuple[Any, ...]
) -> str:
    """Run `parser` on `data`, then `arguments`, and return its outcome."""
    try:
        obj = parser(data, *arguments)
    except refusal:
        return "refused"
    except Exception as exc:  # noqa: BLE001
        return f"crashed {type(exc).__name__}"
    try:
        return f"accepted {_describe(obj)}"
    except Exception as exc:  # noqa: BLE001
        return f"unserializable {type(exc).__name__}"


def _probe(request: dict[str, Any]) -> dict[str, Any]:
    """Run every entry point of `request` on its inputs; report what ran."""
    btclib = importlib.import_module("btclib")
    refusal = importlib.import_module("btclib.exceptions").BTClibException
    parsers: dict[str, Any] = {}
    for entries in request["entries"].values():
        for spec, _ in entries:
            try:
                parsers[spec] = _resolve(spec)
            except (ImportError, AttributeError):
                parsers[spec] = None
    records: list[Record] = []
    for harness, name, hex_data in request["inputs"]:
        data = bytes.fromhex(hex_data)
        for spec, arguments in request["entries"][harness]:
            parser = parsers[spec]
            outcome = (
                ABSENT
                if parser is None
                else _answer(parser, refusal, data, ast.literal_eval(arguments))
            )
            records.append((harness, spec, name, outcome))
    return {
        "version": getattr(btclib, "__version__", "unknown"),
        "file": btclib.__file__,
        "records": records,
    }


# ---- the driver: runs in the workflow's interpreter ----------------------


@dataclass(frozen=True)
class Run:
    """What one interpreter answered."""

    version: str
    file: str
    records: tuple[Record, ...]


@dataclass(frozen=True)
class Difference:
    """A report row: a difference, or an entry point absent from both."""

    kind: str
    harness: str
    spec: str
    name: str
    release: str
    current: str


class _Inline(ast.NodeTransformer):
    """Replace each name by the value `values` gives it."""

    def __init__(self, values: dict[str, Any]) -> None:
        self.values = values

    @override
    def visit_Name(self, node: ast.Name) -> ast.Constant:
        if node.id not in self.values:
            raise ValueError(node.id)
        return ast.Constant(self.values[node.id])


def _literals(tree: ast.Module) -> dict[str, Any]:
    """Return each module-level `NAME = <literal>`, a name read as its value."""
    values: dict[str, Any] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            with contextlib.suppress(ValueError):
                inlined = _Inline(values).visit(copy.deepcopy(node.value))
                values[node.targets[0].id] = ast.literal_eval(inlined)
    return values


def entry_points(harness: Path) -> dict[str, tuple[Any, ...]]:
    """Return what each entry point of a harness takes after the input."""
    tree = ast.parse(harness.read_text(encoding="utf-8"), filename=str(harness))
    value = _literals(tree).get("ENTRY_POINTS")
    if isinstance(value, tuple):
        value = dict.fromkeys(value, ())
    if isinstance(value, dict) and all(
        isinstance(k, str) and isinstance(v, tuple) for k, v in value.items()
    ):
        return value
    msg = f"{harness} declares no ENTRY_POINTS tuple of strings or dict of tuples"
    raise ValueError(msg)


def tar_inputs(path: Path) -> list[tuple[str, bytes]]:
    """Return the regular files of a tar, read in memory and never extracted."""
    found: list[tuple[str, bytes]] = []
    with tarfile.open(path) as tar:
        for member in tar.getmembers():
            handle = tar.extractfile(member) if member.isfile() else None
            if handle is not None:
                found.append(
                    (f"fuzz artifact {member.name.removeprefix('./')}", handle.read())
                )
    return found


def collect(
    harness_dir: Path, artifacts: Path | None
) -> tuple[dict[str, list[tuple[str, str]]], list[tuple[str, str, str]]]:
    """Return the entry points per harness and the inputs, as hex.

    An entry point comes with the `repr` of its arguments, which the probe
    reads back with `ast.literal_eval`: JSON has no bytes and no tuple.
    """
    entries: dict[str, list[tuple[str, str]]] = {}
    inputs: list[tuple[str, str, str]] = []
    for harness in sorted(harness_dir.glob("fuzz_*.py")):
        entries[harness.stem] = [
            (spec, repr(arguments)) for spec, arguments in entry_points(harness).items()
        ]
        seeds = sorted((harness_dir / "corpus" / harness.stem).glob("*.bin"))
        for seed in seeds:
            name = f"corpus/{harness.stem}/{seed.name}"
            inputs.append((harness.stem, name, seed.read_bytes().hex()))
        if artifacts is not None:
            for tar in sorted(artifacts.glob(f"cifuzz-corpus-{harness.stem}/*.tar")):
                inputs.extend(
                    (harness.stem, name, data.hex()) for name, data in tar_inputs(tar)
                )
    return entries, inputs


def run_probe(python: str, request: dict[str, Any]) -> Run:
    """Run the probe in the interpreter `python` and return its answer."""
    result = subprocess.run(  # noqa: S603
        [python, "-I", str(Path(__file__).resolve()), "--probe"],
        input=json.dumps(request),
        capture_output=True,
        encoding="utf-8",
        check=False,
        timeout=_TIMEOUT,
    )
    if result.returncode != 0:
        msg = f"{python} --probe exited {result.returncode}:\n{result.stderr}"
        raise RuntimeError(msg)
    answer = json.loads(result.stdout)
    records = tuple(tuple(record) for record in answer["records"])
    return Run(answer["version"], answer["file"], records)


def _kind(release: str, current: str) -> str | None:
    """Return a row's kind: how two outcomes differ, or `absent from both`.

    `absent from both` is where neither side has the entry point. None is
    where both have it and agree.
    """
    heads = (release.split(" ", 1)[0], current.split(" ", 1)[0])
    if ABSENT in heads:
        return _ABSENT_BOTH if release == current else _ABSENT_ONE
    if release == current:
        return None
    taken = [head in _ACCEPTED for head in heads]
    if taken[0] != taken[1]:
        return "accepted by one, not the other"
    if all(taken):
        return "serialized differently"
    if heads[0] != heads[1]:
        return "refused by one, crashed in the other"
    return "crashed differently"


def _tally(outcomes: list[str]) -> str:
    """Return how many inputs ended each way, an accepted object not shown."""
    counts = Counter(
        "accepted" if outcome.startswith("accepted ") else outcome
        for outcome in outcomes
    )
    return ", ".join(f"{n} {outcome}" for outcome, n in sorted(counts.items()))


def compare(release: Run, current: Run) -> list[Difference]:
    """Return the rows, an absent entry point once and not per input.

    The row of an absent entry point counts each side's outcomes.
    """
    differences: list[Difference] = []
    absent: dict[tuple[str, str, str], tuple[list[str], list[str]]] = {}
    for (harness, spec, name, was), (_, _, _, now) in zip(
        release.records, current.records, strict=True
    ):
        kind = _kind(was, now)
        if kind in {_ABSENT_ONE, _ABSENT_BOTH}:
            sides = absent.setdefault((kind, harness, spec), ([], []))
            sides[0].append(was)
            sides[1].append(now)
        elif kind is not None:
            differences.append(Difference(kind, harness, spec, name, was, now))
    differences += [
        Difference(kind, harness, spec, "(every input)", _tally(was), _tally(now))
        for (kind, harness, spec), (was, now) in absent.items()
    ]
    return sorted(differences, key=lambda d: (d.kind, d.harness, d.spec, d.name))


def _cell(text: str, start: int = 0) -> str:
    """Return `text` from `start`, clipped and safe inside a table cell."""
    shown = text[start : start + _CLIP]
    head = "..." if start else ""
    tail = f"... ({len(text)} characters)" if start + _CLIP < len(text) else ""
    escaped = f"{head}{shown}{tail}".replace("|", "\\|")
    return f"`{escaped}`"


def _cells(release: str, current: str) -> tuple[str, str]:
    """Return two table cells, clipped from where the answers first differ."""
    same = 0
    while same < min(len(release), len(current)) and release[same] == current[same]:
        same += 1
    start = max(0, same - _CONTEXT)
    return _cell(release, start), _cell(current, start)


def render(release: Run, current: Run, differences: list[Difference]) -> str:
    """Return the markdown report."""
    inputs = {(harness, name) for harness, _, name, _ in current.records}
    seeds = sum(name.startswith("corpus/") for _, name in inputs)
    artifacts = len(inputs) - seeds
    lines = [
        "## Entry points: this tree against the last release",
        "",
        f"Release: btclib {release.version}, from `{release.file}`.",
        f"This tree: btclib {current.version}, from `{current.file}`.",
        f"Entry point and input pairs run on each side: {len(current.records)}.",
        f"Inputs: {seeds} from `fuzz/corpus/`, {artifacts} from the fuzz artifacts.",
        "",
    ]
    if not differences:
        lines.append("No difference.")
        return "\n".join(lines) + "\n"
    lines += [
        f"Rows: {len(differences)}. A difference that is intended is",
        "named in the pull request that causes it.",
        "",
        "| kind | harness | entry point | input | release | this tree |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for d in differences[:_MAX_ROWS]:
        was, now = _cells(d.release, d.current)
        name = _cell(d.name)
        lines.append(
            f"| {d.kind} | `{d.harness}` | `{d.spec}` | {name} | {was} | {now} |"
        )
    if len(differences) > _MAX_ROWS:
        lines += ["", f"Not listed: {len(differences) - _MAX_ROWS} more."]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    """Run the comparison, or the probe where `--probe` is given."""
    if argv == ["--probe"]:
        sys.stdout.write(json.dumps(_probe(json.load(sys.stdin))))
        return 0
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--current", required=True, help="python with this tree")
    parser.add_argument("--release", required=True, help="python with the release")
    parser.add_argument("--harness-dir", type=Path, default=_ROOT / "fuzz")
    parser.add_argument("--fuzz-artifacts", type=Path, default=None)
    args = parser.parse_args(argv)
    entries, inputs = collect(args.harness_dir, args.fuzz_artifacts)
    request = {"entries": entries, "inputs": inputs}
    release = run_probe(args.release, request)
    current = run_probe(args.current, request)
    sys.stdout.write(render(release, current, compare(release, current)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
