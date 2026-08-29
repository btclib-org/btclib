# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Wait until the index serves the version a release just published.

`pypi-install.yml` installs whatever the resolver picks, and the index
does not serve a new file the instant the upload returns: a run that
starts too early installs the version the release replaces and reports a
pass for it, which is worse than reporting nothing. So a run with a
release behind it waits for the version its tag names, and fails rather
than let the matrix measure the wrong thing.

The budget is a deadline and not a count of attempts. A wait stated as
attempts times an interval is a product to be multiplied out before it
can be compared with the job's own `timeout-minutes`, and a wait that
outlasts that is killed inside itself: the run then carries the runner's
message about a cancelled job where this was written to name the page to
go and read (issue #1165). Every request is bounded by what is left of
the deadline as well as by its own timeout, so the whole wait ends
within `--timeout` of its first request for anything the index does
between answers. What is not bounded here is a single answer arriving a
byte at a time: `urlopen`'s timeout is a socket timeout and applies per
blocking read, so that case is the job's `timeout-minutes` to end.

No trigger reaches the verdict this exists for. What is waited on is
somebody else's upload, so neither a release nor a rehearsal can arrange
for it to be late, and a trigger added to reach the loop reaches its
first attempt instead. `tests/wait_for_pypi_release_test.py` is
therefore the only thing that drives the retry, the deadline and the
error path: it substitutes the transport and the clock, and advances the
clock past the deadline itself.

The tag is empty on every trigger but a release call, and an empty tag is
nothing to wait for rather than an error -- which is what makes this
runnable on a schedule and a dispatch, where a step only a release runs
is a step whose defect ships with a release.

    uv run --no-project --python 3.14 \
        .github/scripts/wait_for_pypi_release.py btclib "$TAG"
"""

from __future__ import annotations

import argparse
import sys
import time
from http import HTTPStatus
from http.client import HTTPException
from urllib.request import Request, urlopen

# the JSON API of the index, which answers one document per version and
# 404 until the version is there. `pip index` and a resolver run would
# answer the same question through a cache this cannot see
INDEX = "https://pypi.org/pypi"

# what a release has to arrive within, in seconds, and the one number the
# job's `timeout-minutes` is compared against
DEFAULT_TIMEOUT = 300.0
# between two questions to the index: long enough not to hammer it, short
# enough that the wait ends near the upload rather than near the deadline
DEFAULT_INTERVAL = 15.0
# one question's own bound, so that a connection that hangs spends part of
# the deadline rather than all of it
DEFAULT_REQUEST_TIMEOUT = 10.0


def served(url: str, timeout: float) -> bool:
    """Return whether the index answers this version's document."""
    request = Request(url, method="GET")  # noqa: S310
    try:
        with urlopen(request, timeout=timeout) as answer:  # noqa: S310
            status: int = answer.status
    # every way the index can fail to answer is one more reason to wait:
    # a 404 while the upload is still landing is an HTTPError, a
    # connection refused or timed out is an OSError, and a truncated
    # answer is an HTTPException. None of them is this script's verdict,
    # which the deadline alone decides
    except (OSError, HTTPException):
        return False
    return status == HTTPStatus.OK


def wait(
    package: str,
    version: str,
    timeout: float,
    interval: float,
    request_timeout: float,
) -> int:
    """Poll the index for one version, and say what the deadline decided."""
    url = f"{INDEX}/{package}/{version}/json"
    started = time.monotonic()
    deadline = started + timeout
    while (left := deadline - time.monotonic()) > 0:
        if served(url, min(request_timeout, left)):
            waited = time.monotonic() - started
            print(f"the index serves {version} after {waited:.0f} s")
            return 0
        print(f"{version} is not served yet")
        time.sleep(min(interval, max(deadline - time.monotonic(), 0.0)))
    print(f"::error::{version} is not on the index {timeout:.0f} s later")
    return 1


def main(argv: list[str] | None = None) -> int:
    """Read the tag from the command line and wait for what it names."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", help="the name the index serves it under")
    parser.add_argument("tag", help="the release tag, empty on every other run")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    parser.add_argument(
        "--request-timeout", type=float, default=DEFAULT_REQUEST_TIMEOUT
    )
    args = parser.parse_args(argv)

    version = args.tag.removeprefix("v")
    if not version:
        print("no release behind this run: nothing to wait for")
        return 0
    return wait(
        args.package, version, args.timeout, args.interval, args.request_timeout
    )


if __name__ == "__main__":
    sys.exit(main())
