# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Wait until read the docs serves the documentation a tag names.

`release.yml`'s `documented` job is the sentinel on a release whose
documentation build never starts, and this is the wait behind it:
`/en/<tag>/` answers 200 once read the docs has built the tag.

The budget is a deadline and not a count of attempts. A wait stated as
attempts times an interval is a product to be multiplied out before it
can be compared with the job's own `timeout-minutes`, and a wait that
outlasts that is killed inside itself: the run then carries the runner's
message about a cancelled job where this was written to name the page to
go and read (issue #1165). Every request is bounded by what is left of
the deadline as well as by its own timeout, so the whole wait ends within
`--timeout` of its first request for anything read the docs does between
answers. What is not bounded here is a single answer arriving a byte at a
time: `urlopen`'s timeout is a socket timeout and applies per blocking
read, so that case is the job's `timeout-minutes` to end.

The last answer is carried to the end rather than discarded, so the
annotation names the HTTP status or the transport failure it saw and not
only that nothing was served, and sends a reader to the builds page
beside it. What the rendered URL cannot distinguish, and why the v3 API
is not asked instead, is `release.yml`'s comment above the job.

No trigger reaches the verdict this exists for. The job runs on a tag
push alone, so a rehearsal has no tag to ask about and a dispatch
pointing the wait at a branch would spend the whole deadline on a URL
that answers 404 by construction -- which is why this takes no empty tag
as nothing to wait for, the way the release wait beside it does.
`tests/wait_for_readthedocs_build_test.py` is therefore the only thing
that drives the retry, the deadline and the error path: it substitutes
the transport and the clock, and advances the clock past the deadline
itself.

    uv run --no-project --python 3.14 \
        .github/scripts/wait_for_readthedocs_build.py btclib "$TAG"
"""

from __future__ import annotations

import argparse
import sys
import time
from http import HTTPStatus
from http.client import HTTPException
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# read the docs serves this only once the tag has a successful build,
# which is the whole of the question asked here
SITE = "https://{project}.readthedocs.io/en/{tag}/"
BUILDS = "https://app.readthedocs.org/projects/{project}/builds/"

# the Cloudflare zone in front of read the docs bans the interpreter's own
# default (`Python-urllib/3.14`) outright -- a 403 on every request,
# measured against a tag that is in fact served -- so a request sent
# without one never reaches the "build not finished yet" question this
# exists to ask; `curl`'s default is not banned, which is why the loop
# this replaces never needed one
USER_AGENT = "btclib-readthedocs-wait/1.0"

# what a build has to arrive within, in seconds, and the one number the
# job's `timeout-minutes` is compared against
DEFAULT_TIMEOUT = 900.0
# between two questions to the site: long enough not to hammer it, short
# enough that the wait ends near the build rather than near the deadline
DEFAULT_INTERVAL = 30.0
# one question's own bound, so that a connection that hangs spends part of
# the deadline rather than all of it
DEFAULT_REQUEST_TIMEOUT = 10.0


def unserved(url: str, timeout: float) -> str | None:
    """Return what stood in the way, or `None` where the page is served."""
    headers = {"User-Agent": USER_AGENT}
    request = Request(url, method="GET", headers=headers)  # noqa: S310
    try:
        with urlopen(request, timeout=timeout) as answer:  # noqa: S310
            status: int = answer.status
    # a 404 while no build has succeeded is an `HTTPError`, which carries
    # a status; a connection refused or timed out is an `OSError` and a
    # truncated answer an `HTTPException`, neither of which has one. None
    # of them is this script's verdict, which the deadline alone decides,
    # and each is named rather than discarded so that the annotation can
    # say what the last one was
    except HTTPError as failure:
        return f"HTTP {failure.code}"
    except (OSError, HTTPException) as failure:
        return f"{type(failure).__name__}: {failure}"
    return None if status == HTTPStatus.OK else f"HTTP {status}"


def wait(
    project: str,
    tag: str,
    timeout: float,
    interval: float,
    request_timeout: float,
) -> int:
    """Poll the site for one tag, and say what the deadline decided."""
    url = SITE.format(project=project, tag=tag)
    started = time.monotonic()
    deadline = started + timeout
    last_seen = "no request has been made yet"
    while (left := deadline - time.monotonic()) > 0:
        seen = unserved(url, min(request_timeout, left))
        if seen is None:
            waited = time.monotonic() - started
            print(f"{url} is served after {waited:.0f} s")
            return 0
        last_seen = seen
        print(f"{url} answered {seen}")
        time.sleep(min(interval, max(deadline - time.monotonic(), 0.0)))
    builds = BUILDS.format(project=project)
    print(
        f"::error::tag {tag}: {url} was never served in {timeout:.0f} s;"
        f" last seen: {last_seen}. Read the builds page on {builds}"
        " -- it says why, this job only says that"
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    """Read the tag from the command line and wait for what it names."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", help="the name read the docs serves it under")
    parser.add_argument("tag", help="the release tag, which is also the version")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    parser.add_argument(
        "--request-timeout", type=float, default=DEFAULT_REQUEST_TIMEOUT
    )
    args = parser.parse_args(argv)

    return wait(
        args.project, args.tag, args.timeout, args.interval, args.request_timeout
    )


if __name__ == "__main__":
    sys.exit(main())
