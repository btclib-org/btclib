# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the release comparison of `.github/scripts`.

The script is loaded by path, `.github/scripts` being no package. Its
probe runs here in the interpreter of the suite; the driver is run with
that interpreter on both sides, and with a stand-in for the probe where a
difference is needed.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import io
import json
import re
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "compare_release.py"


@pytest.fixture
def cmp(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Return the script, imported by path and registered before it runs."""
    spec = importlib.util.spec_from_file_location("compare_release", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "compare_release", module)
    spec.loader.exec_module(module)
    return module


def _run(cmp: ModuleType, *records: tuple[str, str, str, str]) -> Any:
    return cmp.Run("1", "/site/btclib/__init__.py", records)


def _harness(directory: Path, name: str, entries: str) -> None:
    directory.mkdir(exist_ok=True)
    (directory / f"{name}.py").write_text(f"ENTRY_POINTS = {entries}\n")


def _tar(path: Path, files: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w") as tar:
        root = tarfile.TarInfo("./")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        for name, data in files.items():
            info = tarfile.TarInfo(f"./{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def test_entry_points_are_read_without_importing(cmp: Any, tmp_path: Path) -> None:
    """A harness importing atheris, which is not installed, is still read."""
    (tmp_path / "fuzz_a.py").write_text(
        'import atheris\nENTRY_POINTS = ("m:f", "m:C.g")\n'
    )
    assert cmp.entry_points(tmp_path / "fuzz_a.py") == ("m:f", "m:C.g")


@pytest.mark.parametrize("source", ["x = 1\n", "ENTRY_POINTS = ['m:f']\n"])
def test_entry_points_refuse_what_is_not_a_tuple_of_strings(
    cmp: Any, tmp_path: Path, source: str
) -> None:
    """No declaration, or a list, is an error and not an empty comparison."""
    (tmp_path / "fuzz_a.py").write_text(source)
    with pytest.raises(ValueError, match="declares no ENTRY_POINTS"):
        cmp.entry_points(tmp_path / "fuzz_a.py")


def test_tar_inputs_reads_files_only(cmp: Any, tmp_path: Path) -> None:
    """The directory entry is skipped and the names lose their `./`."""
    _tar(tmp_path / "a.tar", {"0001": b"\x01", "0002": b""})
    assert cmp.tar_inputs(tmp_path / "a.tar") == [
        ("fuzz artifact 0001", b"\x01"),
        ("fuzz artifact 0002", b""),
    ]


def test_tar_inputs_skips_a_member_with_no_content(cmp: Any, tmp_path: Path) -> None:
    """A link is no input, `extractfile` answering None for it."""
    with tarfile.open(tmp_path / "a.tar", "w") as tar:
        link = tarfile.TarInfo("./link")
        link.type = tarfile.SYMTYPE
        link.linkname = "target"
        tar.addfile(link)
    assert cmp.tar_inputs(tmp_path / "a.tar") == []


def test_collect_gathers_seeds_and_artifacts(cmp: Any, tmp_path: Path) -> None:
    """Each harness gets its entry points, its seeds and its artifact files."""
    fuzz = tmp_path / "fuzz"
    _harness(fuzz, "fuzz_a", '("m:f",)')
    _harness(fuzz, "fuzz_b", '("m:g", "m:h")')
    (fuzz / "corpus" / "fuzz_a").mkdir(parents=True)
    (fuzz / "corpus" / "fuzz_a" / "s.bin").write_bytes(b"\xab")
    (fuzz / "corpus" / "fuzz_a" / "notes.txt").write_bytes(b"not a seed")
    (fuzz / "corpus" / "fuzz_b").mkdir()
    artifacts = tmp_path / "art"
    _tar(artifacts / "cifuzz-corpus-fuzz_b" / "x.tar", {"0001": b"\xcd"})

    entries, inputs = cmp.collect(fuzz, artifacts)

    assert entries == {"fuzz_a": ("m:f",), "fuzz_b": ("m:g", "m:h")}
    assert inputs == [
        ("fuzz_a", "corpus/fuzz_a/s.bin", "ab"),
        ("fuzz_b", "fuzz artifact 0001", "cd"),
    ]
    assert cmp.collect(fuzz, None)[1] == [("fuzz_a", "corpus/fuzz_a/s.bin", "ab")]


@dataclasses.dataclass(frozen=True)
class _Data:
    height: int


class _Plain:
    pass


class _Serial:
    def serialize(self) -> bytes:
        return b"\x01\x02"


class _NeedsWitness:
    def serialize(self, *, include_witness: bool) -> bytes:
        return b"\x03" if include_witness else b"\x04"


@pytest.mark.parametrize(
    "obj, expected",
    [
        (256, "256"),
        ([1, b"x"], "[1, b'x']"),
        (_Plain(), "_Plain"),
        (_Serial(), "0102"),
        (_NeedsWitness(), "03"),
        (0.5, "0.5"),
        (_Data(3), "_Data(height=3)"),
    ],
)
def test_describe(cmp: Any, obj: object, expected: str) -> None:
    """An object is shown by its serialization, a plain value by its repr."""
    assert cmp._describe(obj) == expected


def test_probe_answers_each_kind_of_outcome(cmp: Any) -> None:
    """Accepted, refused, crashed and absent, and the request id of Electrum."""
    request = {
        "entries": {
            "h": [
                "btclib.var_int:parse",
                "builtins:int",
                "btclib.no_such_module:parse",
                "btclib.var_int:no_such_name",
                "btclib.electrum:estimate_fee_response",
            ]
        },
        "inputs": [["h", "one", "fdfd00"], ["h", "two", "fd00"]],
        "request_id": 1,
    }
    answer = cmp._probe(request)
    outcome = {(spec, name): out for _, spec, name, out in answer["records"]}
    assert outcome["btclib.var_int:parse", "two"] == "refused"
    assert outcome["builtins:int", "two"] == "crashed ValueError"
    assert outcome["btclib.no_such_module:parse", "one"] == "absent"
    assert outcome["btclib.var_int:no_such_name", "one"] == "absent"
    assert outcome["btclib.var_int:parse", "one"].startswith("accepted ")
    assert outcome["btclib.electrum:estimate_fee_response", "two"] == "refused"
    assert answer["file"].endswith("__init__.py")
    assert answer["version"]


def test_run_probe_in_a_subprocess(cmp: Any) -> None:
    """The script run by path answers what the in-process probe answers."""
    request = {
        "entries": {"h": ["btclib.var_int:parse"]},
        "inputs": [["h", "one", "fdfd00"]],
        "request_id": 1,
    }
    run = cmp.run_probe(sys.executable, request)
    in_process = cmp._probe(request)
    assert run.records == tuple(tuple(r) for r in in_process["records"])
    assert run.version == in_process["version"]


def test_run_probe_reports_a_failed_interpreter(cmp: Any) -> None:
    """A probe that exits non-zero is an error and not an empty comparison."""
    with pytest.raises(RuntimeError, match="--probe exited"):
        cmp.run_probe(sys.executable, {"entries": {}, "inputs": "not pairs"})


@pytest.mark.parametrize(
    "was, now, kind",
    [
        ("refused", "refused", None),
        ("accepted 01", "accepted 01", None),
        ("absent", "absent", None),
        ("refused", "accepted 01", "accepted by one, not the other"),
        ("accepted 01", "crashed KeyError", "accepted by one, not the other"),
        ("accepted 01", "accepted 02", "serialized differently"),
        ("crashed KeyError", "crashed ValueError", "crashed differently"),
        ("refused", "crashed KeyError", "refused by one, crashed in the other"),
        ("crashed KeyError", "refused", "refused by one, crashed in the other"),
        ("accepted 01", "unserializable KeyError", "serialized differently"),
        ("unserializable KeyError", "refused", "accepted by one, not the other"),
        ("unserializable A", "unserializable B", "serialized differently"),
        ("absent", "refused", "entry point absent"),
        ("accepted 01", "absent", "entry point absent"),
    ],
)
def test_kind(cmp: Any, was: str, now: str, kind: str | None) -> None:
    """Each pair of outcomes is classified, or is no difference."""
    assert cmp._kind(was, now) == kind


def test_compare_lists_an_absent_parser_once(cmp: Any) -> None:
    """A parser the release lacks is one row, not one per input."""
    release = _run(
        cmp, ("h", "m:f", "a", "absent"), ("h", "m:f", "b", "absent"),
        ("h", "m:g", "a", "refused"),
    )  # fmt: skip
    current = _run(
        cmp, ("h", "m:f", "a", "accepted 01"), ("h", "m:f", "b", "refused"),
        ("h", "m:g", "a", "accepted 02"),
    )  # fmt: skip
    found = cmp.compare(release, current)
    assert [(d.kind, d.spec, d.name, d.release, d.current) for d in found] == [
        ("accepted by one, not the other", "m:g", "a", "refused", "accepted 02"),
        ("entry point absent", "m:f", "(every input)", "absent", "present"),
    ]


def test_compare_sees_no_difference(cmp: Any) -> None:
    """Equal runs list nothing."""
    run = _run(cmp, ("h", "m:f", "a", "refused"))
    assert cmp.compare(run, run) == []


def test_render_without_a_difference(cmp: Any) -> None:
    """The report says so, and names both versions and their files."""
    run = _run(cmp, ("h", "m:f", "a", "refused"))
    text = cmp.render(run, run, [])
    assert "No difference." in text
    assert "/site/btclib/__init__.py" in text


def test_render_clips_and_escapes_a_row(cmp: Any) -> None:
    """A long answer is cut and a pipe cannot end the cell."""
    release = _run(cmp, ("h", "m:f", "a|b", "accepted " + "00" * 100))
    current = _run(cmp, ("h", "m:f", "a|b", "refused"))
    text = cmp.render(release, current, cmp.compare(release, current))
    assert "Differences: 1." in text
    assert "a\\|b" in text
    assert "... (209 characters)" in text


def test_render_limits_the_rows(cmp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rows past the cap are counted and not listed."""
    monkeypatch.setattr(cmp, "_MAX_ROWS", 1)
    release = _run(cmp, ("h", "m:f", "a", "refused"), ("h", "m:f", "b", "refused"))
    current = _run(
        cmp, ("h", "m:f", "a", "accepted 01"), ("h", "m:f", "b", "accepted 02")
    )
    text = cmp.render(release, current, cmp.compare(release, current))
    assert "Not listed: 1 more." in text
    assert text.count("\n| accepted by one") == 1


def test_main_compares_two_interpreters(
    cmp: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The same interpreter on both sides finds nothing, and exits 0."""
    fuzz = tmp_path / "fuzz"
    _harness(fuzz, "fuzz_a", '("btclib.var_int:parse",)')
    with (fuzz / "fuzz_a.py").open("a") as handle:
        handle.write("REQUEST_ID = 1\n")
    (fuzz / "corpus" / "fuzz_a").mkdir(parents=True)
    (fuzz / "corpus" / "fuzz_a" / "s.bin").write_bytes(b"\xfd\x00\x01")
    argv = ["--current", sys.executable, "--release", sys.executable]
    assert cmp.main([*argv, "--harness-dir", str(fuzz)]) == 0
    assert "No difference." in capsys.readouterr().out


def test_main_runs_the_probe(
    cmp: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--probe` reads a request on stdin and writes the answer."""
    request = {
        "entries": {"h": ["btclib.var_int:parse"]},
        "inputs": [["h", "x", "00"]],
        "request_id": 1,
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(request)))
    assert cmp.main(["--probe"]) == 0
    assert json.loads(capsys.readouterr().out)["records"] == [
        ["h", "btclib.var_int:parse", "x", "accepted 0"]
    ]


def test_request_id_is_read_from_a_harness(cmp: Any, tmp_path: Path) -> None:
    """The id an Electrum harness answers is read, and its absence is loud."""
    (tmp_path / "fuzz_a.py").write_text("x = 1\n")
    with pytest.raises(ValueError, match="REQUEST_ID"):
        cmp.request_id(tmp_path)
    (tmp_path / "fuzz_b.py").write_text("REQUEST_ID = 7\n")
    assert cmp.request_id(tmp_path) == 7
    (tmp_path / "fuzz_b.py").write_text('REQUEST_ID = "7"\n')
    with pytest.raises(ValueError, match="REQUEST_ID"):
        cmp.request_id(tmp_path)


def test_a_changed_float_or_dataclass_is_a_difference(cmp: Any) -> None:
    """A value that is neither serialized nor a type name alone is compared."""
    for was, now in ((0.5, 1.0), (_Data(1), _Data(2))):
        before = _run(cmp, ("h", "m:f", "a", "accepted " + cmp._describe(was)))
        after = _run(cmp, ("h", "m:f", "a", "accepted " + cmp._describe(now)))
        found = cmp.compare(before, after)
        assert [d.kind for d in found] == ["serialized differently"]


def test_render_shows_the_cells_from_where_they_differ(cmp: Any) -> None:
    """Two long answers differing late do not print as the same cell."""
    common = "ab" * 100
    release = _run(cmp, ("h", "m:f", "a", f"accepted {common}01"))
    current = _run(cmp, ("h", "m:f", "a", f"accepted {common}02"))
    text = cmp.render(release, current, cmp.compare(release, current))
    row = next(line for line in text.splitlines() if line.startswith("| serialized"))
    cells = row.split("|")
    assert cells[-3] != cells[-2]
    assert "01" in cells[-3]
    assert "02" in cells[-2]


class _BrokenSerialize:
    def serialize(self) -> bytes:
        msg = "cannot"
        raise KeyError(msg)


def test_an_object_that_cannot_be_described_is_an_outcome(cmp: Any) -> None:
    """The probe reports it and goes on, so the comparison has a report."""
    answer = cmp._answer("m:p", lambda _data: _BrokenSerialize(), ValueError, b"", 1)
    assert answer == "unserializable KeyError"


def test_render_says_where_the_inputs_came_from(cmp: Any) -> None:
    """The report counts the seeds and the artifact inputs apart."""
    run = _run(
        cmp,
        ("h", "m:f", "corpus/h/a.bin", "refused"),
        ("h", "m:g", "corpus/h/a.bin", "refused"),
        ("h", "m:f", "fuzz artifact 01", "refused"),
    )
    text = cmp.render(run, run, [])
    assert "Inputs: 1 from `fuzz/corpus/`, 1 from the fuzz artifacts." in text
    assert "run on each side: 3." in text


def test_both_probes_fit_in_half_the_job(cmp: Any) -> None:
    """The script's timeout fires before the workflow cancels the job."""
    workflow = _SCRIPT.parents[1] / "workflows" / "release-diff.yml"
    text = workflow.read_text(encoding="utf-8")
    minutes = re.findall(r"^ +timeout-minutes: (\d+)$", text, re.MULTILINE)
    assert len(minutes) == 1
    half_the_job = int(minutes[0]) * 60 / 2
    assert half_the_job >= 2 * cmp._TIMEOUT
