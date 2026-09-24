# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`[tool.mypy] exclude` is a regex, not a glob, and reaches every source file.

`mypy.modulefinder.matches_exclude` (uv.lock's pinned mypy) is
`re.search(pattern, subpath)`, unanchored unless the pattern itself
anchors -- so `"build"` drops any path merely containing that substring,
not only the top-level `build/` directory a packaging tool writes.
`tests/build_system_test.py`, `tests/wait_for_readthedocs_build_test.py`,
`tests/block/build_test.py` and `.github/scripts/wait_for_readthedocs_build.py`
left the type gate this way, none of them imported by anything the gate
does reach, with `mypy src/btclib tests .github/scripts` exiting 0
throughout (issue #2115). `src/btclib/block/build.py` also carries the
substring and stayed in: it is imported by a module the crawl does reach
(`genesis.py`), and an import mypy follows is checked whatever the
crawl's own exclude says.

This module reads pyproject.toml rather than importing mypy, which
`CONTRIBUTING.md`'s own gate command runs from `lint`, a group
`test`'s own environment does not carry. It parses the file with
`tomllib` rather than matching its text, as mypy itself does: the
sdist's `pyproject.toml` is the build backend's normalized copy, with
the comments gone and the arrays laid out anew, and a pattern written
against the committed file's layout finds nothing there (issue #2252).
"""

import re
import tomllib
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_PYPROJECT = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
_CONTRIBUTING = (_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

# the roots CONTRIBUTING.md's own gate command names, read out rather
# than repeated: a root added or dropped there is a root this test
# starts or stops walking without a second edit here
_GATE_ROOTS = re.compile(r"^uv run mypy (?P<roots>\S.*)$", re.MULTILINE)


def _mypy_exclude_patterns() -> tuple[str, ...]:
    section = _PYPROJECT.get("tool", {}).get("mypy")
    assert isinstance(section, dict), "[tool.mypy] is not in pyproject.toml"
    exclude_list = section.get("exclude")
    assert isinstance(exclude_list, list), "[tool.mypy] carries no exclude list"
    return tuple(exclude_list)


def _gate_roots() -> tuple[str, ...]:
    match = _GATE_ROOTS.search(_CONTRIBUTING)
    assert match is not None, "CONTRIBUTING.md carries no `uv run mypy` line"
    return tuple(match.group("roots").split())


def _excluded(relative_posix_path: str, patterns: tuple[str, ...]) -> bool:
    """Whether mypy's own crawl would drop this path, its own way of asking.

    `re.search`, unanchored, over every pattern -- `matches_exclude`'s own
    logic, without importing the package that carries it.
    """
    return any(re.search(pattern, relative_posix_path) for pattern in patterns)


def _census(roots: tuple[str, ...]) -> tuple[str, ...]:
    """Every `.py` file under the gate's own roots, relative to the root."""
    files: list[str] = []
    for root in roots:
        files.extend(
            str(path.relative_to(_ROOT).as_posix())
            for path in sorted((_ROOT / root).rglob("*.py"))
        )
    return tuple(files)


def test_the_exclude_reaches_the_directory_it_names() -> None:
    """A real `build/` output stays out, proving the control has teeth."""
    patterns = _mypy_exclude_patterns()
    assert _excluded("build/lib/btclib/version.py", patterns)


def test_the_exclude_drops_nothing_the_gate_command_names() -> None:
    """Every source the documented command walks is one mypy still checks.

    An exclude entry unanchored the way `"build"` was drops any path
    carrying that substring, silently -- the census below is what makes
    that regression visible again the next time an entry is loosened.
    """
    patterns = _mypy_exclude_patterns()
    census = _census(_gate_roots())
    excluded = [path for path in census if _excluded(path, patterns)]
    assert not excluded, f"the exclude drops {excluded} from the type gate"
