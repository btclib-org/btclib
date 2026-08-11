# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Rewrite an sdist so that two builds of one commit are the same bytes.

`SOURCE_DATE_EPOCH` is enough for the wheel and reaches nothing in the
sdist. setuptools honours the variable in the wheel writer it vendors and
in no other place, which is one file of the installed package and says so
whichever release is current:

    uv run --isolated --no-project --with setuptools python -c "
    import pathlib, setuptools
    root = pathlib.Path(setuptools.__file__).parent
    print(setuptools.__version__, [str(p.relative_to(root))
        for p in root.rglob('*.py')
        if 'SOURCE_DATE_EPOCH' in p.read_text(encoding='utf-8')])"

So every member of the `.tar.gz` keeps whichever clock produced it: the
directory setuptools stages the sdist in carries the build's, and each
file copied into that directory carries the checkout's. Both are
sub-second, both land in a PAX `mtime` record, and two checkouts of one
commit disagree in the digits after the point:

    28 mtime=1786407122.0157955
    28 mtime=1786407123.6693566

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
