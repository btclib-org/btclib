# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `.github/scripts/assert_bindings_serving.py`.

The script is loaded by path, `.github/scripts` being no package, as the
other scripts under it are tested. Whether the bindings serve is
patched rather than read, so each answer is tested in every environment.
"""

from __future__ import annotations

import importlib.util
import runpy
from pathlib import Path
from types import ModuleType

import ecc.curves
import pytest

_SCRIPT = (
    Path(__file__).parents[1] / ".github" / "scripts" / "assert_bindings_serving.py"
)


@pytest.fixture
def script() -> ModuleType:
    """Return the script, imported by path."""
    spec = importlib.util.spec_from_file_location("assert_bindings_serving", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_serving_bindings_pass(
    script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Bindings that serve answer 0, silently."""
    monkeypatch.setattr(script, "is_libsecp256k1_serving", lambda: True)

    assert script.main() == 0
    assert capsys.readouterr().out == ""


def test_bindings_that_do_not_serve_fail_and_say_so(
    script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Bindings that do not serve answer 1, with the line the step prints."""
    monkeypatch.setattr(script, "is_libsecp256k1_serving", lambda: False)

    assert script.main() == 1
    assert capsys.readouterr().out == (
        "btclib_secp256k1 does not serve under the floor resolution\n"
    )


def test_the_main_guard_runs_the_script_as___main__(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cover `if __name__ == "__main__":` without a subprocess.

    This project collects no coverage from a child interpreter, so a real
    subprocess would leave the guard uncovered. `runpy.run_path` executes
    the file fresh with `__name__` set to `"__main__"` in this one, and
    the fresh import reads `is_libsecp256k1_serving` from `ecc.curves`,
    so that is where it is patched.
    """
    monkeypatch.setattr(ecc.curves, "is_libsecp256k1_serving", lambda: True)

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(_SCRIPT), run_name="__main__")

    assert excinfo.value.code == 0
