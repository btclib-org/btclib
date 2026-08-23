# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Rewrite an sdist so that two builds of one commit are the same bytes.

The backend already does that, and this runs anyway. `uv_build` writes a
fixed timestamp into every member of both archives and ignores
`SOURCE_DATE_EPOCH` entirely, which is measurable in one command:

    uv build -o a && SOURCE_DATE_EPOCH=1000000000 uv build -o b \
      && shasum -a 256 a/* b/*

answers with one digest per artefact across the two directories, and
`tarfile` reports a single distinct `mtime` of 0 in the `.tar.gz` against
`(1980, 1, 1)` in the wheel's zip entries. Nothing here has to be done for
the archive to be reproducible today.

What this buys is that the property belongs to this repository rather than
to the backend. A fixed `mtime` of 0 is uv's choice and uv is free to
revisit it, while a release rebuilt from its tag has to give the bytes the
attestation vouches for however many backends later that is. Rewriting the
metadata to a value derived from the commit makes the answer this tree's,
and turns a backend change from a broken rebuild into a no-op.

What is *in* the archive is already deterministic; what is not is the
metadata of the members. This rewrites that metadata and nothing else:
every timestamp becomes `SOURCE_DATE_EPOCH`, ownership becomes root with
no names, and the gzip header carries the same timestamp instead of the
moment it was compressed. The order of the members and every byte of
their content are the archive's own.

`PAX_FORMAT` with the extended headers cleared, rather than
`USTAR_FORMAT`: an integral timestamp needs no PAX record, so the two
formats write the same bytes today -- and the day a path in the sdist
outgrows ustar's 100 characters, pax records it and ustar would have
refused it.

Run it after `uv build` and before anything reads dist/:

    uv run --no-project --python 3.14 \
        .github/scripts/normalize_sdist.py dist/

RELEASING.md has the command that verifies a published release against a
rebuild of its tag, and the two bounds on what that proves.
"""

from __future__ import annotations

import gzip
import io
import os
import sys
import tarfile
from pathlib import Path


def normalize(archive: Path, epoch: int) -> None:
    """Rewrite one archive in place, member metadata at `epoch`."""
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            # extractfile returns None for anything that is not a regular
            # file, and a directory member is one of the two cases this
            # script exists for, so the two are told apart rather than
            # asserted
            stream = source.extractfile(member) if member.isfile() else None
            members.append((member, stream.read() if stream is not None else None))

    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w", format=tarfile.PAX_FORMAT) as target:
        for member, content in members:
            member.mtime = epoch
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            # the records this exists to remove: tarfile writes one per
            # field it cannot express in the ustar header, and the
            # sub-second mtime above was such a field. Replaced rather than
            # cleared, the attribute being a Mapping to a type checker
            member.pax_headers = {}
            target.addfile(member, io.BytesIO(content) if content is not None else None)

    compressed = io.BytesIO()
    # mtime, not the clock, and filename empty: gzip stores both in its
    # header, and the name of a temporary file is not the archive's
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=compressed, mtime=epoch, compresslevel=9
    ) as compressor:
        compressor.write(tar.getvalue())
    archive.write_bytes(compressed.getvalue())


def main(argv: list[str]) -> int:
    """Normalize every sdist in the directory named on the command line."""
    if len(argv) != 2:
        print(f"usage: {argv[0]} <dist directory>", file=sys.stderr)  # noqa: T201
        return 2

    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        # not a default of "now": a default would make the failure a
        # reproducibility bug found by whoever tried to verify a release,
        # which is the one person who cannot fix it
        print("SOURCE_DATE_EPOCH is not set", file=sys.stderr)  # noqa: T201
        return 1

    archives = sorted(Path(argv[1]).glob("*.tar.gz"))
    if not archives:
        print(f"no sdist in {argv[1]}", file=sys.stderr)  # noqa: T201
        return 1

    for archive in archives:
        normalize(archive, int(epoch))
        print(f"normalized {archive}")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
