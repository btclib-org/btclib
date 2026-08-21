# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Check a built wheel and sdist against an allowlist of their members.

`twine check`, `check-wheel-contents` and `pyroma` read the *metadata* of
a distribution file: whether it is syntactically valid, whether the long
description renders, whether the classifiers and urls are the ones a
package should declare. None of them reads the members, so what is in the
archive was checked by nothing -- and the archive is what a user installs.

Three questions, one per section below, and the constants that answer
them are the policy: `docs/source/package-content-policy.md` states it in
prose, for a reader who has an unpacked sdist -- which carries that page
and not this file -- and for the rules no member list can carry at all.
`tests/verify_dist_contents_test.py` compares the page against these
constants in both directions, so neither is free to drift from the other,
which is what makes the second copy safe rather than one more thing to
be wrong.

**What may be in there.** The wheel gets a strict allowlist, it being what
lands on `sys.path`: Python source under `btclib/`, `btclib/py.typed`,
whatever sits in a `_data/` directory, and the `.dist-info` metadata
setuptools writes. Anything else fails, which is what makes a `.pth` file,
a stray top-level module and a bundled shared object all one rule rather
than three.

The sdist gets a structural check instead, and not an extension allowlist,
because MANIFEST.in already is one: `recursive-include tests *.json` is
the statement of what a vendored vector may be, and a second copy of it
here would be one more edit per vector while catching nothing that file
lets through. What this adds is what MANIFEST.in cannot say -- that every
member is under the archive's own root directory, that every member is a
regular file or a directory (a tar can carry a symlink, a hardlink or a
device node, where a zip cannot), that no directory holds the metadata of
some *other* distribution, and which files may sit at the root, where
MANIFEST.in's `include *.md` and `include *.yaml` ship whatever lands
beside them.

**What may never be in there**, whichever archive: a short list of
suffixes and names, checked against every member including the ones the
`_data/` amnesty above admits by directory rather than by extension. It is
belt and braces for the wheel and the only rule of its kind for the sdist.

**What has to be in there.** `uv build` builds the sdist and then the
wheel from it, so the two carry the same `btclib/` payload, and comparing
them is a completeness check with nothing to keep in step: a data file the
tree has and the wheel does not is issue #393, and this is its pre-publish
half -- check-manifest gates the tree against the sdist, this gates the
sdist against the wheel, and #393's own smoke test gates what PyPI serves.
`py.typed` is named on its own because PEP 561 makes its absence silent:
the package installs, imports and type checks as `Any`.

Every offending member is reported rather than the first: a policy failure
is usually a class of files, and a build is hundreds of members.

Run it on a freshly built dist directory, after `uv build`:

    uv run --no-project --python 3.14 \
        .github/scripts/verify_dist_contents.py dist/

The `dist` job of test.yml runs it on every pull request, and the same
job -- reached through release.yml's `test` call -- on the files it is
about to publish.
"""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

# no distribution file of this project carries any of these, and each is
# something an installed wheel would *run* or a packaging accident would
# bundle: a `.pth` executes at interpreter startup, before the first
# import; the four native suffixes are a compiled extension, which this
# project has none of -- the secp256k1 bindings are a separate
# distribution, resolved at install time and never vendored; a `.pyc` is
# a compiled module whose source nobody reviewed; and an archive inside
# an archive is a nested distribution, i.e. a second package installing
# with the first
FORBIDDEN_SUFFIXES = (
    ".dll",
    ".dylib",
    ".egg",
    ".exe",
    ".pth",
    ".pyc",
    ".pyd",
    ".so",
    ".tar.gz",
    ".whl",
    ".zip",
)

# the two names Python imports for their side effects alone, at startup,
# from the root of site-packages. Both end in `.py`, so the wheel's
# allowlist would admit either under `btclib/` -- inert there, and named
# here because the rule is about the name and not about where it happens
# to be harmless
FORBIDDEN_NAMES = ("sitecustomize.py", "usercustomize.py")

# what setuptools writes into `.dist-info`, and no more. `entry_points.txt`
# is deliberately absent: pyproject.toml declares no `[project.scripts]`,
# and an entry point is a code path a user runs without importing anything,
# so one appearing here is a packaging change that has to be read
WHEEL_METADATA_FILES = frozenset({"METADATA", "RECORD", "WHEEL", "top_level.txt"})

# the members without which the wheel is broken in a way that installs
# cleanly: `py.typed` for PEP 561, the metadata for `btclib.__version__`
# (issue #150), and `__init__.py` because a wheel with no package at all
# is the shape a misconfigured `packages.find` produces
WHEEL_REQUIRED = frozenset({"btclib/__init__.py", "btclib/py.typed"})

# the directories of the sdist, which is the development tree: the
# package, its suite, the documentation sources, and the metadata
# setuptools generates beside them
SDIST_DIRECTORIES = frozenset({"btclib", "btclib.egg-info", "docs", "tests"})

# the files that may sit at the root of the sdist. MANIFEST.in ships these
# by glob -- `include *.md`, `include *.yaml`, `include *.jsonc` -- so a
# new file beside them is shipped without a packaging decision being made;
# this is where that decision is recorded. A dotted name is here because
# the lint gate has to be runnable from an unpacked sdist, which is
# MANIFEST.in's own reason for carrying it
SDIST_ROOT_SUFFIXES = (".jsonc", ".md", ".toml", ".yaml")
SDIST_ROOT_NAMES = frozenset(
    {
        ".python-version",
        ".secrets.baseline",
        "COPYRIGHT",
        "LICENSE",
        "MANIFEST.in",
        "PKG-INFO",
        "setup.cfg",
        "uv.lock",
    }
)

# generated metadata, and nothing else, under `btclib.egg-info/`
SDIST_EGG_INFO_NAMES = frozenset({"PKG-INFO"})
SDIST_EGG_INFO_SUFFIXES = (".txt",)

# the sdist is broken without these in a way that is not obvious either:
# PKG-INFO is the metadata PyPI reads off the archive, and pyproject.toml
# is what makes it buildable at all
SDIST_REQUIRED = frozenset({"PKG-INFO", "pyproject.toml"})


def forbidden_reason(path: str) -> str | None:
    """Say why this member may never be in a distribution file, or None."""
    name = path.rsplit("/", 1)[-1]
    if name in FORBIDDEN_NAMES:
        return f"is {name}, which Python imports at startup"
    for suffix in FORBIDDEN_SUFFIXES:
        if path.endswith(suffix):
            return f"carries the forbidden suffix {suffix}"
    if "__pycache__" in path.split("/"):
        return "is under __pycache__"
    return None


def wheel_member_reason(path: str, dist_info: str) -> str | None:
    """Say why this wheel member is not on the allowlist, or None."""
    forbidden = forbidden_reason(path)
    if forbidden is not None:
        return forbidden
    if path.startswith(f"{dist_info}/"):
        relative = path[len(dist_info) + 1 :]
        if relative in WHEEL_METADATA_FILES or relative.startswith("licenses/"):
            return None
        return f"is under {dist_info}/ and is not one of its files"
    if not path.startswith("btclib/"):
        return "is neither package code nor package metadata"
    if path.endswith(".py") or path == "btclib/py.typed" or "/_data/" in path:
        return None
    return "is under btclib/ and is neither Python source nor a _data file"


def verify_wheel(wheel: Path) -> tuple[list[str], set[str]]:
    """Return the wheel's complaints and its `btclib/` payload."""
    # the file name is what carries the version, canonically: a wheel is
    # named {distribution}-{version}-{python}-{abi}-{platform}.whl, so the
    # first two fields are read from there rather than from the metadata
    # the check below is about to judge
    distribution, version = wheel.name.split("-")[:2]
    dist_info = f"{distribution}-{version}.dist-info"

    with zipfile.ZipFile(wheel) as archive:
        # a zip may carry an entry per directory; setuptools writes none,
        # and a wheel that starts to is not a policy change
        members = [name for name in archive.namelist() if not name.endswith("/")]

    complaints = [
        f"{wheel.name}: {name} {reason}"
        for name in members
        for reason in [wheel_member_reason(name, dist_info)]
        if reason is not None
    ]
    required = WHEEL_REQUIRED | {f"{dist_info}/{name}" for name in WHEEL_METADATA_FILES}
    complaints += [
        f"{wheel.name}: {name} is missing" for name in sorted(required - set(members))
    ]
    payload = {name for name in members if name.startswith("btclib/")}
    return complaints, payload


def sdist_shape_reason(member: tarfile.TarInfo, root: str) -> str | None:
    """Say why this sdist member is not a plain path under the root."""
    path = member.name
    if not (member.isfile() or member.isdir()):
        return f"is neither a regular file nor a directory (type {member.type!r})"
    if path.startswith("/") or ".." in path.split("/"):
        return "is not a relative path within the archive"
    if path != root and not path.startswith(f"{root}/"):
        return f"is outside the archive's own {root}/ directory"
    return forbidden_reason(path)


def sdist_root_reason(name: str, *, is_dir: bool) -> str | None:
    """Say why this member at the root of the sdist is not allowed."""
    if is_dir:
        if name in SDIST_DIRECTORIES:
            return None
        return "is a directory the sdist does not ship"
    if name in SDIST_ROOT_NAMES or name.endswith(SDIST_ROOT_SUFFIXES):
        return None
    return "is a root file the sdist does not ship"


def sdist_nested_reason(parts: list[str], *, is_dir: bool) -> str | None:
    """Say why this member below the sdist's root is not allowed."""
    # the metadata of another distribution, vendored or left behind by a
    # build in the tree the sdist was made from. `btclib.egg-info` is this
    # project's own, and one of the root directories above
    for part in parts[1:]:
        if part.endswith((".dist-info", ".egg-info")):
            return f"holds the metadata of another distribution, {part}"
    if parts[0] not in SDIST_DIRECTORIES:
        return "is not under one of the directories the sdist ships"
    if is_dir or parts[0] != "btclib.egg-info":
        return None
    if parts[-1] in SDIST_EGG_INFO_NAMES or parts[-1].endswith(SDIST_EGG_INFO_SUFFIXES):
        return None
    return "is under btclib.egg-info/ and is not metadata"


def sdist_member_reason(member: tarfile.TarInfo, root: str) -> str | None:
    """Say why this sdist member fails the structural check, or None."""
    shape = sdist_shape_reason(member, root)
    if shape is not None:
        return shape
    relative = member.name[len(root) :].strip("/")
    if not relative:
        return None
    parts = relative.split("/")
    if len(parts) == 1:
        return sdist_root_reason(relative, is_dir=member.isdir())
    return sdist_nested_reason(parts, is_dir=member.isdir())


def verify_sdist(sdist: Path) -> tuple[list[str], set[str]]:
    """Return the sdist's complaints and its `btclib/` payload."""
    # {name}-{version}.tar.gz, so the root directory the members sit under
    # is the file's own name without the extension
    root = sdist.name[: -len(".tar.gz")]

    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()

    complaints = [
        f"{sdist.name}: {member.name} {reason}"
        for member in members
        for reason in [sdist_member_reason(member, root)]
        if reason is not None
    ]
    files = {
        member.name[len(root) :].strip("/") for member in members if member.isfile()
    }
    complaints += [
        f"{sdist.name}: {name} is missing" for name in sorted(SDIST_REQUIRED - files)
    ]
    payload = {name for name in files if name.startswith("btclib/")}
    return complaints, payload


def one_of(dist_dir: Path, pattern: str) -> tuple[Path | None, list[str]]:
    """Return the single file matching the pattern, and any complaint."""
    # exactly one, not the newest of several: a stale artifact from an
    # earlier build in the same directory is precisely what a check on
    # the published files must not skip over
    matches = sorted(dist_dir.glob(pattern))
    if len(matches) == 1:
        return matches[0], []
    found = ", ".join(match.name for match in matches) if matches else "none"
    return None, [f"{dist_dir}: expected one {pattern}, found {found}"]


def verify(dist_dir: Path) -> list[str]:
    """Return every complaint about the wheel and the sdist in dist_dir."""
    wheel, complaints = one_of(dist_dir, "*.whl")
    sdist, sdist_complaints = one_of(dist_dir, "*.tar.gz")
    complaints += sdist_complaints
    if wheel is None or sdist is None:
        return complaints

    wheel_complaints, wheel_payload = verify_wheel(wheel)
    sdist_complaints, sdist_payload = verify_sdist(sdist)
    complaints += wheel_complaints + sdist_complaints

    # the wheel is built from the sdist, so the two carry one payload; a
    # difference either way is a file that reaches a user installing from
    # source and not one installing the wheel, or the reverse
    complaints += [
        f"{sdist.name} ships {name}, {wheel.name} does not"
        for name in sorted(sdist_payload - wheel_payload)
    ]
    complaints += [
        f"{wheel.name} ships {name}, {sdist.name} does not"
        for name in sorted(wheel_payload - sdist_payload)
    ]
    if not complaints:
        print(f"{wheel.name} and {sdist.name} carry what they may and no more")  # noqa: T201
        print(f"one payload of {len(wheel_payload)} files, in both")  # noqa: T201
    return complaints


def main(argv: list[str]) -> int:
    """Verify the wheel and the sdist of the directory named on the line."""
    if len(argv) != 2:
        print(f"usage: {argv[0]} <dist directory>", file=sys.stderr)  # noqa: T201
        return 2

    complaints = verify(Path(argv[1]))
    for complaint in complaints:
        # the workflow annotation, so a failure is readable from the run
        # summary rather than only from the log
        print(f"::error::{complaint}", file=sys.stderr)  # noqa: T201
    return 1 if complaints else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
