# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`tests.workflow_files`, tested where an unpacked sdist runs it.

Both of its callers, `interpreters_test.py` and `what_runs_when_test.py`,
read `.github/workflows` and are in `source-exclude`, so the sdist ships
the helper and neither caller. Its own test reads nothing outside the
directory it builds, which is what lets it ship too (issue #2252).
"""

from pathlib import Path

from tests import workflow_files


def test_workflow_files_reads_the_names_github_runs(tmp_path: Path) -> None:
    """`.yml` and `.yaml` are read alike, `.yXml` is not a workflow.

    One text under three names, the extension the whole of the
    difference: the two spellings GitHub runs come back and the third,
    which a `*.y*ml` glob would take, does not.
    """
    text = "name: extra\non: push\n"
    for name in ("os-extra.yml", "os-extra.yaml", "os-extra.yXml"):
        (tmp_path / name).write_text(text, encoding="utf-8")
    found = sorted(path.name for path in workflow_files(tmp_path))
    assert found == ["os-extra.yaml", "os-extra.yml"]
