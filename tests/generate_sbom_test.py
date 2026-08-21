# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the bill-of-materials writer of `.github/scripts`.

The script reads a wheel's `METADATA` and the bytes of the two
distribution files, and nothing else -- no clock, no network, no source
tree -- so the wheels here are synthetic and carry the metadata each test
is about. The sdist is a file with content: only its digest is read.

Two properties are worth more than the field-by-field assertions, and are
what the release pipeline depends on. The document validates against the
CycloneDX 1.6 JSON schema, checked once against the published schema and
its two `$ref` files -- not asserted here, that would need the schema
vendored and a validator installed for one test. And it is reproducible:
`test_the_document_is_the_same_bytes_twice` is the one that fails if a
clock or a `uuid4` ever reaches it, which would leave a rebuilt release
differing from the published one in the one field nobody could check.

The script is loaded by path, `.github/scripts` being no package.
"""

from __future__ import annotations

import importlib.util
import json
import runpy
import sys
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "generate_sbom.py"

# an instant in August 2026, as SOURCE_DATE_EPOCH carries one: seconds
_EPOCH = 1786407122
_METADATA = """Metadata-Version: 2.4
Name: btclib
Version: 2026.9
Summary: A library for 'bitcoin cryptography'
License-Expression: MIT
Project-URL: homepage, https://btclib.org
Requires-Python: >=3.10
"""


@pytest.fixture
def script() -> ModuleType:
    """Return the script, imported by path."""
    spec = importlib.util.spec_from_file_location("generate_sbom", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_dist(
    directory: Path,
    *,
    requirements: tuple[str, ...] = (),
    metadata: str = _METADATA,
    members: tuple[str, ...] = ("btclib-2026.9.dist-info/METADATA",),
    version: str = "2026.9",
) -> tuple[Path, Path]:
    """Write a wheel carrying this metadata, and an sdist beside it."""
    text = metadata + "".join(f"Requires-Dist: {r}\n" for r in requirements)
    wheel = directory / f"btclib-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for member in members:
            archive.writestr(member, text)
    sdist = directory / f"btclib-{version}.tar.gz"
    sdist.write_bytes(b"an sdist, read for its digest alone")
    return wheel, sdist


def sbom(script: ModuleType, directory: Path, **kwargs: Any) -> dict[str, Any]:
    """Return the document for a dist directory written on the spot."""
    wheel, sdist = write_dist(directory, **kwargs)
    document: dict[str, Any] = script.build_sbom(wheel, sdist, _EPOCH)
    return document


def test_the_document_describes_the_distribution(
    script: ModuleType, tmp_path: Path
) -> None:
    """The root component is btclib, at the version the wheel declares."""
    document = sbom(script, tmp_path)

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["metadata"]["timestamp"] == "2026-08-11T00:12:02Z"
    component = document["metadata"]["component"]
    assert component["name"] == "btclib"
    assert component["version"] == "2026.9"
    assert component["purl"] == "pkg:pypi/btclib@2026.9"
    assert component["licenses"] == [{"expression": "MIT"}]
    assert component["description"] == "A library for 'bitcoin cryptography'"
    assert component["properties"] == [
        {"name": "btclib:requires-python", "value": ">=3.10"}
    ]
    # no component-level hash, the component being two files
    assert "hashes" not in component


def test_the_two_files_are_named_with_their_digests(
    script: ModuleType, tmp_path: Path
) -> None:
    """One externalReference per distribution file, carrying its SHA-256."""
    document = sbom(script, tmp_path)

    references = document["metadata"]["component"]["externalReferences"]
    distributions = [r for r in references if r["url"].startswith("btclib-2026.9")]
    assert [r["url"] for r in distributions] == [
        "btclib-2026.9-py3-none-any.whl",
        "btclib-2026.9.tar.gz",
    ]
    for reference in distributions:
        (digest,) = reference["hashes"]
        assert digest["alg"] == "SHA-256"
        assert len(digest["content"]) == 64


def test_a_project_url_becomes_a_reference_of_its_kind(
    script: ModuleType, tmp_path: Path
) -> None:
    """The labels of `[project.urls]` map onto CycloneDX's own vocabulary."""
    metadata = _METADATA + "Project-URL: repository, https://github.com/o/r\n"
    document = sbom(script, tmp_path, metadata=metadata)

    references = document["metadata"]["component"]["externalReferences"]
    assert {"type": "website", "url": "https://btclib.org", "comment": "homepage"} in (
        references
    )
    assert {
        "type": "vcs",
        "url": "https://github.com/o/r",
        "comment": "repository",
    } in references


def test_a_label_with_no_mapping_is_recorded_as_other(
    script: ModuleType, tmp_path: Path
) -> None:
    """A url is never dropped for want of a word for what it is."""
    metadata = _METADATA + "Project-URL: pull_requests, https://example.org/pulls\n"
    document = sbom(script, tmp_path, metadata=metadata)

    references = document["metadata"]["component"]["externalReferences"]
    assert {
        "type": "other",
        "url": "https://example.org/pulls",
        "comment": "pull_requests",
    } in references


def test_a_pinned_requirement_carries_its_version(
    script: ModuleType, tmp_path: Path
) -> None:
    """`==` is the one specifier that names a version rather than a range."""
    document = sbom(script, tmp_path, requirements=("btclib_secp256k1==0.8.0",))

    (component,) = document["components"]
    assert component["name"] == "btclib-secp256k1"
    assert component["version"] == "0.8.0"
    assert component["purl"] == "pkg:pypi/btclib-secp256k1@0.8.0"
    assert component["scope"] == "required"
    assert component["properties"] == [
        {"name": "btclib:requires-dist", "value": "btclib_secp256k1==0.8.0"}
    ]


def test_a_floor_carries_no_version(script: ModuleType, tmp_path: Path) -> None:
    """A range is not a version, and what the wheel declares is a range.

    Which is the shape every release carries: RELEASING.md replaces each
    direct reference with a `>=` floor before the tag, and what an
    installer then resolves is not a fact about these files.
    """
    document = sbom(script, tmp_path, requirements=("btclib_secp256k1>=0.8.0",))

    (component,) = document["components"]
    assert "version" not in component
    assert component["purl"] == "pkg:pypi/btclib-secp256k1"
    assert component["properties"] == [
        {"name": "btclib:requires-dist", "value": "btclib_secp256k1>=0.8.0"}
    ]


def test_a_direct_reference_carries_its_vcs_url(
    script: ModuleType, tmp_path: Path
) -> None:
    """Between releases each sibling is a `git+https://...@main` reference."""
    url = "git+https://github.com/btclib-org/btclib-secp256k1.git@main"
    document = sbom(script, tmp_path, requirements=(f"btclib_secp256k1 @ {url}",))

    (component,) = document["components"]
    assert component["externalReferences"] == [{"type": "vcs", "url": url}]
    # percent-encoded, the `+` and the `@` of the url being the two
    # characters that would otherwise end a purl qualifier
    assert component["purl"] == (
        "pkg:pypi/btclib-secp256k1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com"
        "%2Fbtclib-org%2Fbtclib-secp256k1.git%40main"
    )


def test_an_extra_makes_a_requirement_optional(
    script: ModuleType, tmp_path: Path
) -> None:
    """A dependency the wheel asks for only when an extra is asked for."""
    requirement = 'coverage>=7; extra == "test"'
    document = sbom(script, tmp_path, requirements=(requirement,))

    (component,) = document["components"]
    assert component["scope"] == "optional"


def test_a_marker_that_is_not_an_extra_leaves_it_required(
    script: ModuleType, tmp_path: Path
) -> None:
    """An interpreter version says where a dependency installs, not whether."""
    document = sbom(script, tmp_path, requirements=('tomli; python_version < "3.11"',))

    (component,) = document["components"]
    assert component["scope"] == "required"


def test_the_extras_of_a_requirement_are_recorded(
    script: ModuleType, tmp_path: Path
) -> None:
    """A name with extras keeps them, the purl having no field for them."""
    document = sbom(script, tmp_path, requirements=("requests[socks]>=2",))

    (component,) = document["components"]
    assert {"name": "btclib:extras", "value": "socks"} in component["properties"]


def test_the_dependency_graph_names_every_component(
    script: ModuleType, tmp_path: Path
) -> None:
    """The root depends on each, and each on nothing: one level, declared."""
    document = sbom(
        script,
        tmp_path,
        requirements=("bitcoin-core-rpc==1.0", "btclib_secp256k1==2.0"),
    )

    refs = [component["bom-ref"] for component in document["components"]]
    root, *leaves = document["dependencies"]
    assert root == {"ref": "pkg:pypi/btclib@2026.9", "dependsOn": refs}
    assert leaves == [{"ref": ref, "dependsOn": []} for ref in refs]


def test_the_components_are_sorted(script: ModuleType, tmp_path: Path) -> None:
    """Sorted by reference, so the metadata's own order cannot move them."""
    document = sbom(
        script, tmp_path, requirements=("zope.interface==7.0", "attrs==25.0")
    )

    assert [c["name"] for c in document["components"]] == ["attrs", "zope-interface"]


def test_a_requirement_the_script_cannot_read_stops_it(
    script: ModuleType, tmp_path: Path
) -> None:
    """Refused rather than guessed at.

    A dependency the document omits in silence is the one failure a bill of
    materials must not have.
    """
    with pytest.raises(SystemExit, match="cannot read the requirement"):
        sbom(script, tmp_path, requirements=("== 1.0",))


@pytest.mark.parametrize(
    "members, expected",
    [
        ((), "carries 0 dist-info/METADATA members"),
        (
            ("a-1.dist-info/METADATA", "b-2.dist-info/METADATA"),
            "carries 2 dist-info/METADATA members",
        ),
    ],
)
def test_a_wheel_without_exactly_one_metadata_stops_it(
    script: ModuleType, tmp_path: Path, members: tuple[str, ...], expected: str
) -> None:
    """One wheel is one distribution, and its metadata is one member."""
    with pytest.raises(SystemExit, match=expected):
        sbom(script, tmp_path, members=members)


def test_metadata_with_no_name_stops_it(script: ModuleType, tmp_path: Path) -> None:
    """A wheel whose metadata is missing the two fields that identify it."""
    with pytest.raises(SystemExit, match="declares no Name or no Version"):
        sbom(script, tmp_path, metadata="Metadata-Version: 2.4\n")


def test_metadata_with_no_summary_or_licence_omits_them(
    script: ModuleType, tmp_path: Path
) -> None:
    """Every optional field is optional, rather than reported as empty."""
    metadata = "Metadata-Version: 2.4\nName: btclib\nVersion: 2026.9\n"
    document = sbom(script, tmp_path, metadata=metadata)

    component = document["metadata"]["component"]
    assert "description" not in component
    assert "licenses" not in component
    assert "properties" not in component


def test_main_says_how_to_be_called_when_it_is_not(
    script: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two directories, no more and no fewer."""
    assert script.main(["prog", "dist"]) == 2
    err = capsys.readouterr().err
    assert err == "usage: prog <dist directory> <output directory>\n"


def test_main_refuses_to_run_without_source_date_epoch(
    script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No default of "now", for normalize_sdist.py's reason.

    A default makes the document differ from the released one, and whoever
    found that out is the one person who could not fix it.
    """
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)

    assert script.main(["prog", str(tmp_path), str(tmp_path)]) == 1


@pytest.mark.parametrize("pattern", ["*.whl", "*.tar.gz"])
def test_main_refuses_a_dist_directory_that_is_not_one_pair(
    script: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pattern: str,
) -> None:
    """A stale artifact beside the fresh one is not silently skipped over."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(_EPOCH))
    write_dist(tmp_path)
    write_dist(tmp_path, version="2026.8")
    (
        tmp_path
        / f"btclib-2026.8{'.tar.gz' if pattern == '*.whl' else '-py3-none-any.whl'}"
    ).unlink()

    with pytest.raises(SystemExit, match=f"expected one {pattern.replace('*', '.')}"):
        script.main(["prog", str(tmp_path), str(tmp_path / "sbom")])


def test_main_names_the_file_after_the_wheel(
    script: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The caller passes a directory and needs to know no version.

    Which in a rehearsal it does not: the `build` job patches a
    `.dev<run*100+attempt>` into the version before building, so the name
    the workflow would have to construct is not the one in pyproject.toml.
    """
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(_EPOCH))
    write_dist(tmp_path, version="2026.9.dev7")
    output = tmp_path / "sbom"

    assert script.main(["prog", str(tmp_path), str(output)]) == 0

    written = output / "btclib-2026.9.dev7.cdx.json"
    assert f"wrote {written}" in capsys.readouterr().out
    assert json.loads(written.read_text(encoding="utf-8"))["specVersion"] == "1.6"


def test_the_document_is_the_same_bytes_twice(
    script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reproducibility the release assets and their attestation want.

    Everything here is derived: the timestamp from `SOURCE_DATE_EPOCH`,
    the serial number from the purl and the two digests. A clock or a
    `uuid4` reaching either is what this fails on.
    """
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(_EPOCH))
    write_dist(tmp_path, requirements=("btclib_secp256k1>=0.8.0",))

    first, second = (tmp_path / "one", tmp_path / "two")
    assert script.main(["prog", str(tmp_path), str(first)]) == 0
    assert script.main(["prog", str(tmp_path), str(second)]) == 0

    name = "btclib-2026.9.cdx.json"
    assert (first / name).read_bytes() == (second / name).read_bytes()


def test_the_main_guard_runs_the_script_as___main__(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cover `if __name__ == "__main__":` without a subprocess.

    `runpy.run_path` executes the file fresh with `__name__` set to
    `"__main__"` in this interpreter, this project collecting no coverage
    from a child one.
    """
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(_EPOCH))
    write_dist(tmp_path)
    monkeypatch.setattr(sys, "argv", ["prog", str(tmp_path), str(tmp_path / "sbom")])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(_SCRIPT), run_name="__main__")

    assert excinfo.value.code == 0
