# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Write a CycloneDX bill of materials for a built wheel and sdist.

A release says where its files came from -- PEP 740 attestations on the
index, a build provenance attestation over the copies attached to the
GitHub release -- and said nothing about what is *in* them. This is the
second half: one CycloneDX 1.6 document naming the distribution, its
licence, the two files and their digests, and every dependency their
metadata declares.

**The wheel's metadata is the source, not pyproject.toml.** They agree on
a release and not in a rehearsal, where the `build` job appends
`.dev<run*100+attempt>` to the version before building: the document has to
describe the files beside it, so it reads the archive it is given. Which
also means the only version it can report for a dependency is the one the
metadata pins, and that is deliberate -- what a user's installer resolves
is not a fact about these files, so a resolved version recorded here would
be a claim the wheel does not make. A requirement pinned with `==` gets a
`version`; anything else gets the specifier as a property and no version.

**It is reproducible, like the files it describes.** The timestamp is
`SOURCE_DATE_EPOCH`, which the `build` job exports from the commit date
for the wheel and the sdist normalizer, and the serial number is a UUID5
over the purl and the two digests -- so a rebuild of a tag writes the same
bytes here too, and the attestation over the release assets covers this
file as well. Nothing is read from the clock, and nothing is random:
`uuid4` would make a rebuild differ in the one field nobody could check.

Run it on a freshly built dist directory, after `uv build` and after the
sdist normalizer, whose rewrite changes the digest this records:

    uv run --no-project --python 3.14 \
        .github/scripts/generate_sbom.py dist/ sbom/

The output is named `<distribution>-<version>.cdx.json` after the wheel,
so the workflow does not have to know the version -- which in a rehearsal
it does not. RELEASING.md has the command that regenerates it from a tag
and verifies it against the attestation.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import sys
import zipfile
from email import message_from_bytes
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

# PEP 508, cut down to the two forms a distribution's `Requires-Dist` takes
# here: a name with a version specifier, and a name with a direct
# reference. Anything else is refused rather than guessed at -- a
# requirement this cannot read is a dependency the document would omit in
# silence, which is the one failure a bill of materials must not have
REQUIREMENT = re.compile(
    r"""
    ^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)   # the name
    (?:\[(?P<extras>[^][]+)\])?                             # its extras
    (?:\s*@\s*(?P<url>[^\s;]+)                              # a direct reference
      |(?P<specifier>[^;]*))                                # or a specifier
    (?:\s*;\s*(?P<marker>.+))?$                             # its environment marker
    """,
    re.VERBOSE,
)

# one `==` and one version, which is the only specifier that names a
# version rather than a range of them
PINNED = re.compile(r"^==\s*(?P<version>[^,\s]+)$")

# how the labels of pyproject.toml's `[project.urls]` map onto the
# externalReference types CycloneDX defines. A label with no mapping is
# recorded as "other" rather than dropped: the document is a description,
# and losing a url because the vocabulary has no word for it is worse than
# saying "other"
REFERENCE_TYPES = {
    "changelog": "release-notes",
    "documentation": "documentation",
    "download": "distribution",
    "homepage": "website",
    "issues": "issue-tracker",
    "repository": "vcs",
}


def canonical_name(name: str) -> str:
    """Return the PEP 503 normalized form of a distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def file_hash(path: Path) -> str:
    """Return the SHA-256 of a file, read a megabyte at a time."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def wheel_metadata(wheel: Path) -> Message:
    """Return the parsed METADATA of a wheel."""
    with zipfile.ZipFile(wheel) as archive:
        names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(names) != 1:
            msg = f"{wheel.name} carries {len(names)} dist-info/METADATA members"
            raise SystemExit(msg)
        return message_from_bytes(archive.read(names[0]))


def purl(name: str, version: str | None, url: str | None) -> str:
    """Return the package url of a PyPI distribution, qualified by its vcs."""
    reference = f"pkg:pypi/{canonical_name(name)}"
    if version is not None:
        reference += f"@{version}"
    if url is not None:
        # percent-encoded, the qualifier value being part of a url itself:
        # the `git+https://...@main` of a direct reference carries the two
        # characters that would otherwise end the qualifier
        reference += f"?vcs_url={quote(url, safe='')}"
    return reference


def component(requirement: str) -> dict[str, Any]:
    """Return the component one `Requires-Dist` line describes."""
    match = REQUIREMENT.match(requirement.strip())
    if match is None:
        msg = f"cannot read the requirement {requirement!r}"
        raise SystemExit(msg)

    specifier = (match["specifier"] or "").strip()
    pinned = PINNED.match(specifier)
    version = pinned["version"] if pinned is not None else None
    marker = match["marker"]
    reference = purl(match["name"], version, match["url"])

    entry: dict[str, Any] = {
        "type": "library",
        "bom-ref": reference,
        "name": canonical_name(match["name"]),
        "purl": reference,
        # an extra names a dependency the wheel asks for only when the
        # extra is; nothing else in a marker makes a requirement optional
        # to a bill of materials, an interpreter version being a condition
        # on where it installs rather than on whether it is needed
        "scope": (
            "optional" if marker is not None and "extra ==" in marker else "required"
        ),
        # the line as the metadata carries it, which is the whole of what
        # this document knows about the dependency: the fields above are a
        # reading of it, and the reading is checkable against it
        "properties": [{"name": "btclib:requires-dist", "value": requirement}],
    }
    if version is not None:
        entry["version"] = version
    if match["extras"] is not None:
        entry["properties"].append({"name": "btclib:extras", "value": match["extras"]})
    if match["url"] is not None:
        entry["externalReferences"] = [{"type": "vcs", "url": match["url"]}]
    return entry


def timestamp(epoch: int) -> str:
    """Return the epoch as the UTC ISO 8601 instant CycloneDX asks for."""
    # `isoformat` spells the zone "+00:00" and the schema's own examples
    # end in "Z"; both are valid ISO 8601 and one of them is what every
    # other tool writes
    when = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return when.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def distribution_reference(path: Path) -> dict[str, Any]:
    """Return the externalReference for one of the distribution files."""
    return {
        "type": "distribution",
        # the name alone, and no url: the file is published to PyPI and
        # attached to a GitHub release, so a url here would name one of
        # the two copies and read as the authoritative one
        "url": path.name,
        "hashes": [{"alg": "SHA-256", "content": file_hash(path)}],
    }


def build_sbom(wheel: Path, sdist: Path, epoch: int) -> dict[str, Any]:
    """Return the CycloneDX document describing the two files."""
    metadata = wheel_metadata(wheel)
    name = metadata["Name"]
    version = metadata["Version"]
    if name is None or version is None:
        msg = f"{wheel.name} declares no Name or no Version"
        raise SystemExit(msg)
    reference = purl(name, version, None)

    references = [distribution_reference(wheel), distribution_reference(sdist)]
    for entry in metadata.get_all("Project-URL", []):
        label, _, url = entry.partition(", ")
        references.append(
            {"type": REFERENCE_TYPES.get(label, "other"), "url": url, "comment": label}
        )

    root: dict[str, Any] = {
        "type": "library",
        "bom-ref": reference,
        "name": canonical_name(name),
        "version": version,
        "purl": reference,
        # no component-level `hashes`: the component is two files with two
        # digests, and a hash over both would be a number nothing else can
        # recompute. The digests are on the two references above, where a
        # verifier can check each against the file it has
        "externalReferences": references,
    }
    summary = metadata["Summary"]
    if summary is not None:
        root["description"] = summary
    # PEP 639, which is what pyproject.toml's `license = "MIT"` writes:
    # a SPDX expression, and CycloneDX takes one as such rather than as a
    # licence name it would have to match against a list
    expression = metadata["License-Expression"]
    if expression is not None:
        root["licenses"] = [{"expression": expression}]
    requires_python = metadata["Requires-Python"]
    if requires_python is not None:
        root["properties"] = [
            {"name": "btclib:requires-python", "value": requires_python}
        ]

    components = sorted(
        (
            component(requirement)
            for requirement in metadata.get_all("Requires-Dist", [])
        ),
        key=lambda entry: str(entry["bom-ref"]),
    )
    serial = f"{reference}:{file_hash(wheel)}:{file_hash(sdist)}"
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        # derived and not random, so that a rebuild of a tag writes this
        # file byte for byte as the release did
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, serial)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp(epoch),
            "tools": {
                "components": [
                    {"type": "application", "name": ".github/scripts/generate_sbom.py"}
                ]
            },
            "component": root,
        },
        "components": components,
        "dependencies": [
            {"ref": reference, "dependsOn": [entry["bom-ref"] for entry in components]},
            *({"ref": entry["bom-ref"], "dependsOn": []} for entry in components),
        ],
    }


def one_of(directory: Path, pattern: str) -> Path:
    """Return the single file in the directory matching the pattern."""
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        found = ", ".join(match.name for match in matches) if matches else "none"
        msg = f"{directory}: expected one {pattern}, found {found}"
        raise SystemExit(msg)
    return matches[0]


def main(argv: list[str]) -> int:
    """Write the bill of materials of one dist directory into another."""
    if len(argv) != 3:
        print(f"usage: {argv[0]} <dist directory> <output directory>", file=sys.stderr)  # noqa: T201
        return 2

    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        # not a default of "now", for normalize_sdist.py's reason: a
        # default makes the document differ from the released one, and
        # whoever finds that out is the one person who cannot fix it
        print("SOURCE_DATE_EPOCH is not set", file=sys.stderr)  # noqa: T201
        return 1

    dist_dir = Path(argv[1])
    wheel = one_of(dist_dir, "*.whl")
    sdist = one_of(dist_dir, "*.tar.gz")
    sbom = build_sbom(wheel, sdist, int(epoch))

    # named after the wheel's own first two fields, {distribution} and
    # {version}, so the caller needs to know neither -- which in a
    # rehearsal, where the version carries a `.dev<run*100+attempt>` the
    # workflow patched in, it does not
    distribution, version = wheel.name.split("-")[:2]
    output = Path(argv[2]) / f"{distribution}-{version}.cdx.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(sbom, indent=2, sort_keys=True)
    output.write_text(f"{text}\n", encoding="utf-8")
    print(f"wrote {output}")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
