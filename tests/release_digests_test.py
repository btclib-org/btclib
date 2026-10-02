# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every job that handles `dist` in a release checks it against the digests.

`reusable-build.yml` outputs the sha256 of each file it built. The jobs
below refuse a file changed, added or missing before they publish, attach
or check it (issue #2449). Read with a regex, as `interpreters_test.py`
does: no dependency group here carries a yaml parser.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOWS = _ROOT / ".github" / "workflows"

_DIFF = "diff - <(printf '%s\\n' \"$DIGESTS\" | grep -F '  dist/')"
_JOB = re.compile(r"^  (?P<name>[\w-]+):\n(?P<body>(?:(?:    .*)?\n)+)", re.MULTILINE)


def _jobs(text: str) -> dict[str, str]:
    """Return each job's body, by name."""
    return {m["name"]: m["body"] for m in _JOB.finditer(text)}


def _handles_dist(body: str) -> bool:
    """Whether the job downloads `dist` or hands it to a reusable workflow."""
    download = r"download-artifact@.*\n\s+with:\n\s+name: dist\n"
    return bool(re.search(download, body) or "dist-artifact: dist\n" in body)


def _check_step(body: str) -> str:
    """Return the step that checks the digests, up to the next step."""
    start = body.index("- name: Check the files are the ones the build job built")
    end = re.search(r"\n      (?:- name:|#)", body[start:])
    return body[start : start + end.start()] if end else body[start:]


def test_the_jobs_that_publish_check_the_digests_first() -> None:
    """The jobs publishing or attaching `dist` get the build's digests."""
    jobs = _jobs((_WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    handling = sorted(n for n, body in jobs.items() if _handles_dist(body))
    assert handling == ["github-release", "publish-pypi", "publish-testpypi"]
    for name in ("publish-pypi", "publish-testpypi"):
        body = jobs[name]
        assert re.search(r"needs:\s*\[\s*build,", body), name
        step = _check_step(body)
        assert "shell: bash\n" in step, name
        assert "DIGESTS: ${{ needs.build.outputs.digests }}" in step, name
        assert _DIFF in step, name
        assert body.index(step) < body.index("gh-action-pypi-publish"), name
    release = jobs["github-release"]
    assert re.search(r"needs:\s*\[[^\]]*\bbuild\b", release)
    assert "digests: ${{ needs.build.outputs.digests }}" in release


def test_the_dist_job_checks_what_it_downloads_on_a_release() -> None:
    """`test.yml` takes the digests as an input and checks the download."""
    release = (_WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert "digests: ${{ needs.build.outputs.digests }}" in release
    test = (_WORKFLOWS / "test.yml").read_text(encoding="utf-8")
    body = _jobs(test)["dist"]
    step = _check_step(body)
    assert "if: inputs.use-signed-dist\n" in step
    assert "shell: bash\n" in step
    assert "DIGESTS: ${{ inputs.digests }}" in step
    assert _DIFF in step
    assert body.index("name: dist\n") < body.index(step)
    assert body.index(step) < body.index("verify_dist_contents.py")


def test_the_patterns_read_a_job_a_dist_download_and_a_step() -> None:
    """The controls the tests above need."""
    text = (
        "jobs:\n  a:\n    steps:\n      - uses: actions/download-artifact@x\n"
        "        with:\n          name: dist\n  b:\n    steps:\n      - run: x\n"
        "  c:\n    with:\n      dist-artifact: dist\n"
    )
    jobs = _jobs(text)
    assert sorted(jobs) == ["a", "b", "c"]
    assert _handles_dist(jobs["a"])
    assert not _handles_dist(jobs["b"])
    assert _handles_dist(jobs["c"])
    assert not _handles_dist(jobs["a"].replace("name: dist", "name: sbom"))
    step = "      - name: Check the files are the ones the build job built\n"
    assert _check_step(step + "        if: x\n      - name: next\n") == (
        step.strip() + "\n        if: x"
    )
