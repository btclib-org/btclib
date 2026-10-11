# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""List the inputs on which this tree's parsers and the last release's differ.

Every `fuzz/fuzz_*.py` names the parsers it fuzzes in `ENTRY_POINTS`, read
here with `ast` and never imported, as `tests/fuzz_corpus_test.py` does.
Each parser is run on every input of its harness in two interpreters, one
with this tree installed and one with the release from the index, and the
two answers are compared. An answer is one of:

- `refused`: the parser raised `BTClibException`;
- `accepted <hex>`: it returned an object, shown by what `serialize()`
  writes, or by `repr` where the object is a plain value or a dataclass,
  and by its type name alone where it is anything else;
- `unserializable <name>`: it returned an object whose description raised;
- `crashed <name>`: it raised anything else;
- `absent`: the parser is not importable.

A difference is a parser that accepts on one side only, accepts and
serializes differently, refuses where the other crashes, crashes
differently, or is absent from one side.

The inputs are `fuzz/corpus/<harness>/*.bin` and, where
`--fuzz-artifacts` names a directory, the corpora the `fuzz` workflow
uploads as `cifuzz-corpus-<harness>` tar files.

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
import dataclasses
import importlib
import json
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
# the first word of an outcome where the parser returned an object
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
    spec: str, parser: Any, refusal: type[Exception], data: bytes, request_id: int
) -> str:
    """Run `parser` on `data` and return its outcome."""
    # an Electrum decoder also takes the id of the request it answers
    args = (data, request_id) if spec.endswith("_response") else (data,)
    try:
        obj = parser(*args)
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
    for specs in request["entries"].values():
        for spec in specs:
            try:
                parsers[spec] = _resolve(spec)
            except (ImportError, AttributeError):
                parsers[spec] = None
    records: list[Record] = []
    for harness, name, hex_data in request["inputs"]:
        data = bytes.fromhex(hex_data)
        for spec in request["entries"][harness]:
            parser = parsers[spec]
            outcome = (
                ABSENT
                if parser is None
                else _answer(spec, parser, refusal, data, request["request_id"])
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
    """One parser and input on which the release and this tree differ."""

    kind: str
    harness: str
    spec: str
    name: str
    release: str
    current: str


def entry_points(harness: Path) -> tuple[str, ...]:
    """Return the `ENTRY_POINTS` tuple of a harness, read unimported."""
    tree = ast.parse(harness.read_text(encoding="utf-8"), filename=str(harness))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "ENTRY_POINTS"
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, tuple) and all(isinstance(v, str) for v in value):
                return value
    msg = f"{harness} declares no ENTRY_POINTS tuple of strings"
    raise ValueError(msg)


def request_id(harness_dir: Path) -> int:
    """Return the `REQUEST_ID` the Electrum harness answers, read with `ast`."""
    for harness in sorted(harness_dir.glob("fuzz_*.py")):
        tree = ast.parse(harness.read_text(encoding="utf-8"), filename=str(harness))
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "REQUEST_ID"
            ):
                value = ast.literal_eval(node.value)
                if isinstance(value, int):
                    return value
    msg = f"no harness of {harness_dir} declares an integer REQUEST_ID"
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
) -> tuple[dict[str, tuple[str, ...]], list[tuple[str, str, str]]]:
    """Return the entry points per harness and the inputs, as hex."""
    entries: dict[str, tuple[str, ...]] = {}
    inputs: list[tuple[str, str, str]] = []
    for harness in sorted(harness_dir.glob("fuzz_*.py")):
        entries[harness.stem] = entry_points(harness)
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
    """Return how two outcomes differ, or None where they do not."""
    if release == current:
        return None
    heads = (release.split(" ", 1)[0], current.split(" ", 1)[0])
    if ABSENT in heads:
        return "entry point absent"
    taken = [head in _ACCEPTED for head in heads]
    if taken[0] != taken[1]:
        return "accepted by one, not the other"
    if all(taken):
        return "serialized differently"
    if heads[0] != heads[1]:
        return "refused by one, crashed in the other"
    return "crashed differently"


def compare(release: Run, current: Run) -> list[Difference]:
    """Return every difference, an absent entry point once and not per input."""
    differences: list[Difference] = []
    absent: set[tuple[str, str]] = set()
    for (harness, spec, name, was), (_, _, _, now) in zip(
        release.records, current.records, strict=True
    ):
        kind = _kind(was, now)
        if kind is None:
            continue
        if kind == "entry point absent":
            if (harness, spec) in absent:
                continue
            absent.add((harness, spec))
            name = "(every input)"  # noqa: PLW2901
            was, now = (s if s == ABSENT else "present" for s in (was, now))  # noqa: PLW2901
        differences.append(Difference(kind, harness, spec, name, was, now))
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
        "## Parsers: this tree against the last release",
        "",
        f"Release: btclib {release.version}, from `{release.file}`.",
        f"This tree: btclib {current.version}, from `{current.file}`.",
        f"Parser and input pairs run on each side: {len(current.records)}.",
        f"Inputs: {seeds} from `fuzz/corpus/`, {artifacts} from the fuzz artifacts.",
        "",
    ]
    if not differences:
        lines.append("No difference.")
        return "\n".join(lines) + "\n"
    lines += [
        f"{len(differences)} differences. A difference that is intended is named",
        "in the pull request that causes it.",
        "",
        "| kind | harness | parser | input | release | this tree |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for d in differences[:_MAX_ROWS]:
        was, now = _cells(d.release, d.current)
        name = _cell(d.name)
        lines.append(
            f"| {d.kind} | `{d.harness}` | `{d.spec}` | {name} | {was} | {now} |"
        )
    if len(differences) > _MAX_ROWS:
        lines += ["", f"{len(differences) - _MAX_ROWS} more differences not listed."]
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
    request = {
        "entries": entries,
        "inputs": inputs,
        "request_id": request_id(args.harness_dir),
    }
    release = run_probe(args.release, request)
    current = run_probe(args.current, request)
    sys.stdout.write(render(release, current, compare(release, current)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
