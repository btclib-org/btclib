#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib` package metadata."""

import importlib
import importlib.metadata

import pytest

import btclib


def test_version() -> None:
    assert btclib.__version__ == importlib.metadata.version("btclib")


def test_version_without_installed_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A source tree with no metadata beside it stays importable.

    The suite cannot exercise that situation as it is, the package being
    installed in the environment running it, so the lookup is made to fail
    and the module re-executed. It is the import that is under test, not
    the string: importing used to raise PackageNotFoundError (issue #150).
    """

    def raise_package_not_found(_: str) -> str:
        raise importlib.metadata.PackageNotFoundError

    # patch the attribute of the module, not the name btclib imported: the
    # `from importlib.metadata import version` line looks it up again on
    # reload, which is what makes this reachable at all
    monkeypatch.setattr(importlib.metadata, "version", raise_package_not_found)
    try:
        assert importlib.reload(btclib).__version__ == "unknown"
    finally:
        # reload once more with the lookup restored, so the module every
        # other test sees carries the real version again. monkeypatch would
        # undo the patch by itself, but not the module state it produced
        monkeypatch.undo()
        importlib.reload(btclib)

    assert btclib.__version__ == importlib.metadata.version("btclib")
