# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `.github/scripts/normalize_sdist.py`.

The script is loaded by path, `.github/scripts` being no package, as the
other scripts under it are tested.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import runpy
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "normalize_sdist.py"

_EPOCH = 1_700_000_000


@pytest.fixture
def script() -> ModuleType:
    """Return the script, imported by path."""
    spec = importlib.util.spec_from_file_location("normalize_sdist", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_archive(
    path: Path,
    *,
    mtime: int = 12345,
    file_mode: int = 0o664,
    dir_mode: int = 0o700,
    uid: int = 1000,
    gid: int = 1000,
    uname: str = "builder",
    gname: str = "builder",
) -> None:
    """Write a two-member sdist: one directory, one file, given metadata.

    The defaults are not `uv_build`'s: a normalization that only ever sees
    the values it is about to write proves nothing about the rewrite.
    """
    with tarfile.open(path, "w:gz") as archive:
        directory = tarfile.TarInfo("pkg")
        directory.type = tarfile.DIRTYPE
        directory.mtime = mtime
        directory.mode = dir_mode
        directory.uid, directory.gid = uid, gid
        directory.uname, directory.gname = uname, gname
        archive.addfile(directory)

        content = b"content"
        member = tarfile.TarInfo("pkg/module.py")
        member.mtime = mtime
        member.mode = file_mode
        member.uid, member.gid = uid, gid
        member.uname, member.gname = uname, gname
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))


def read_members(path: Path) -> list[tarfile.TarInfo]:
    """Read every member of an archive back, for the test to inspect."""
    with tarfile.open(path, "r:gz") as archive:
        return archive.getmembers()


def test_normalize_rewrites_mtime_ownership_and_mode(
    script: ModuleType, tmp_path: Path
) -> None:
    """Every member's mtime, ownership and mode move to the fixed values."""
    archive = tmp_path / "pkg-1.0.tar.gz"
    write_archive(archive)

    script.normalize(archive, _EPOCH)

    directory, file_member = read_members(archive)
    assert {directory.mtime, file_member.mtime} == {_EPOCH}
    assert {directory.uid, file_member.uid} == {0}
    assert {directory.gid, file_member.gid} == {0}
    assert {directory.uname, file_member.uname} == {""}
    assert {directory.gname, file_member.gname} == {""}
    assert directory.isdir()
    assert directory.mode == 0o755
    assert file_member.isfile()
    assert file_member.mode == 0o644


def test_normalize_preserves_order_and_content(
    script: ModuleType, tmp_path: Path
) -> None:
    """The member order and their bytes are the archive's own, untouched."""
    archive = tmp_path / "pkg-1.0.tar.gz"
    write_archive(archive)

    script.normalize(archive, _EPOCH)

    members = read_members(archive)
    assert [m.name for m in members] == ["pkg", "pkg/module.py"]
    with tarfile.open(archive, "r:gz") as reopened:
        extracted = reopened.extractfile("pkg/module.py")
        assert extracted is not None
        assert extracted.read() == b"content"


def test_normalize_clears_pax_headers(script: ModuleType, tmp_path: Path) -> None:
    """A PAX record from a sub-second mtime does not survive the rewrite.

    `member.mtime = epoch` alone leaves the old extended header in place --
    it is `member.pax_headers` that carries it, not `member.mtime` -- which
    is why the script clears it explicitly rather than relying on the new
    value being an integer.
    """
    archive = tmp_path / "pkg-1.0.tar.gz"
    with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as source:
        member = tarfile.TarInfo("pkg/module.py")
        member.mtime = 12345.5
        content = b"content"
        member.size = len(content)
        source.addfile(member, io.BytesIO(content))
    with tarfile.open(archive, "r:gz") as reopened:
        (before,) = reopened.getmembers()
    assert before.pax_headers == {"mtime": "12345.5"}

    script.normalize(archive, _EPOCH)

    (after,) = read_members(archive)
    assert after.pax_headers == {}
    assert after.mtime == _EPOCH


def test_normalize_matches_what_uv_build_already_writes_but_for_mtime(
    script: ModuleType, tmp_path: Path
) -> None:
    """`mtime` is the one field the rewrite changes against `uv_build`.

    `uv_build` already writes root ownership and the same two modes this
    script picks (ISS 1277); only its `mtime` of `0` is not `SOURCE_DATE_EPOCH`
    -- so an archive built exactly like that changes digest on the `mtime`
    rewrite alone (ISS 1278), which is what a rebuild without this step
    would miss.
    """
    archive = tmp_path / "pkg-1.0.tar.gz"
    write_archive(
        archive,
        mtime=0,
        file_mode=0o644,
        dir_mode=0o755,
        uid=0,
        gid=0,
        uname="",
        gname="",
    )
    before = hashlib.sha256(archive.read_bytes()).hexdigest()

    script.normalize(archive, _EPOCH)

    after = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert before != after
    directory, file_member = read_members(archive)
    assert directory.mode == 0o755
    assert file_member.mode == 0o644


def test_main_says_how_to_be_called_when_it_is_not(
    script: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    """No dist directory, or two of them, is the usage rather than a crash."""
    assert script.main(["prog"]) == 2
    assert capsys.readouterr().err == "usage: prog <dist directory>\n"


def test_main_refuses_to_default_source_date_epoch_to_now(
    script: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset is a failure, not "now": the script's own docstring has why."""
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)

    assert script.main(["prog", str(tmp_path)]) == 1
    assert "SOURCE_DATE_EPOCH is not set" in capsys.readouterr().err


def test_main_names_a_dist_directory_with_no_sdist(
    script: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory with a wheel and no sdist is named, not silently skipped."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(_EPOCH))
    (tmp_path / "btclib-1.0-py3-none-any.whl").write_bytes(b"")

    assert script.main(["prog", str(tmp_path)]) == 1
    assert f"no sdist in {tmp_path}" in capsys.readouterr().err


def test_main_normalizes_every_sdist_and_reports_it(
    script: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The success path: every `*.tar.gz` in the directory is rewritten."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(_EPOCH))
    archive = tmp_path / "pkg-1.0.tar.gz"
    write_archive(archive)

    assert script.main(["prog", str(tmp_path)]) == 0

    assert f"normalized {archive}" in capsys.readouterr().out
    directory, file_member = read_members(archive)
    assert directory.mtime == _EPOCH
    assert file_member.mtime == _EPOCH


def test_the_main_guard_runs_the_script_as___main__(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cover `if __name__ == "__main__":` without a subprocess.

    This project collects no coverage from a child interpreter, so a real
    subprocess would leave the guard as uncovered as it is in
    `mutation_counts.py`. `runpy.run_path` executes the file fresh with
    `__name__` set to `"__main__"` in this one.
    """
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(_EPOCH))
    archive = tmp_path / "pkg-1.0.tar.gz"
    write_archive(archive)
    monkeypatch.setattr(sys, "argv", ["prog", str(tmp_path)])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(_SCRIPT), run_name="__main__")

    assert excinfo.value.code == 0
