#!/usr/bin/env python3
# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Compare how btclib and btcd read the same octets.

Every file under the directories named on the command line is decoded by
btclib, through each entry point the harness of its fuzzer lists, and by
btcd's `wire` package, through `fuzz/btcd_decode`. The two answers are
compared, and every input they read differently is listed:

- one accepts and the other refuses;
- both accept and write different octets back;
- one crashes: a Python exception that is not a `BTClibException`, or a
  Go panic.

A directory is read as the corpus of the fuzzer it is named after, either
`fuzz_tx` or `cifuzz-corpus-fuzz_tx`, which is the name of the artifact
`fuzz.yml` uploads, so `fuzz/corpus` and a directory holding downloaded
artifacts are both given as they are. Every file below such a directory
is an input, and a `.tar` is unpacked first, which is how `gh run download`
leaves an artifact.

`var_int.parse` and `var_bytes.parse` read a stream and leave what follows
to the caller, so a refusal of unread octets is the comparison's: it asks
them to read the whole input, as btcd's decoder does.

An entry point btcd has no decoder for, and a message command that either
library does not know, are counted and not compared.

A disagreement that a rule of `KNOWN` explains is counted under the rule
instead. The exit status is 1 when any input is listed, 0
when none is.

    uv run --locked python fuzz/btcd_oracle.py fuzz/corpus
"""

from __future__ import annotations

import argparse
import ast
import importlib
import inspect
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from btclib import var_int
from btclib.exceptions import BTClibException, BTClibValueError
from btclib.p2p.message import Message
from btclib.tx.tx import Tx

_FUZZ = Path(__file__).resolve().parent
_DECODER_SOURCE = _FUZZ / "btcd_decode"
_ARTIFACT_PREFIX = "cifuzz-corpus-"
_TORV2 = 3  # BIP155's network id
_TORV2_SIZE = 10  # the length BIP155's table gives it
# the ids whose length btclib and btcd both check
_CHECKED_SIZES = {1: 4, 2: 16, 4: 32, 5: 32, 6: 16}
_SHOWN = 160  # characters of a serialization or a reason printed per outcome

# Each entry point of the harnesses that btcd decodes, and the kind
# `btcd_decode` calls it. An entry point missing here has no btcd decoder.
KINDS = {
    "btclib.tx.tx:Tx.parse": "tx",
    "btclib.p2p.data:TxPayload.parse": "tx",
    "btclib.block.block:Block.parse": "block",
    "btclib.p2p.data:BlockPayload.parse": "block",
    "btclib.p2p.message:Message.parse": "message",
    "btclib.p2p.merkleblock:MerkleBlock.parse": "merkleblock",
    "btclib.p2p.address:Addr.parse": "addr",
    "btclib.p2p.addrv2:AddrV2.parse": "addrv2",
    "btclib.p2p.addrv2:SendAddrV2.parse": "sendaddrv2",
    "btclib.p2p.handshake:Version.parse": "version",
    "btclib.p2p.handshake:Verack.parse": "verack",
    "btclib.p2p.inventory:Inv.parse": "inv",
    "btclib.p2p.inventory:GetData.parse": "getdata",
    "btclib.p2p.inventory:NotFound.parse": "notfound",
    "btclib.p2p.inventory:GetBlocks.parse": "getblocks",
    "btclib.p2p.inventory:GetHeaders.parse": "getheaders",
    "btclib.p2p.inventory:Headers.parse": "headers",
    "btclib.p2p.keepalive:Ping.parse": "ping",
    "btclib.p2p.keepalive:Pong.parse": "pong",
    "btclib.p2p.negotiation:GetAddr.parse": "getaddr",
    "btclib.p2p.negotiation:Mempool.parse": "mempool",
    "btclib.p2p.negotiation:SendHeaders.parse": "sendheaders",
    "btclib.p2p.negotiation:WtxidRelay.parse": "wtxidrelay",
    "btclib.p2p.negotiation:FeeFilter.parse": "feefilter",
    "btclib.p2p.reject:Reject.parse": "reject",
    "btclib.p2p.block_filters:GetCFilters.parse": "getcfilters",
    "btclib.p2p.block_filters:GetCFHeaders.parse": "getcfheaders",
    "btclib.p2p.block_filters:GetCFCheckpt.parse": "getcfcheckpt",
    "btclib.p2p.block_filters:CFilter.parse": "cfilter",
    "btclib.p2p.block_filters:CFHeaders.parse": "cfheaders",
    "btclib.p2p.block_filters:CFCheckpt.parse": "cfcheckpt",
    "btclib.var_int:parse": "var_int",
    "btclib.var_bytes:parse": "var_bytes",
}

# Core's Unserialize leaves what follows to the caller (serialize.h lines
# 918-930).
_STREAM_KINDS = ("var_int", "var_bytes")

ACCEPTED = "accepted"
REFUSED = "refused"
UNSUPPORTED = "unsupported"
CRASH = "crash"


@dataclass(frozen=True)
class Outcome:
    """What one library made of one input."""

    status: str
    detail: str = ""  # the serialization in hex, or the reason


@dataclass(frozen=True)
class Rule:
    """A class of disagreement that is understood, and why."""

    name: str
    kinds: tuple[str, ...]
    why: str  # one line, with the Bitcoin Core line it rests on
    matches: Callable[[Outcome, Outcome, bytes], bool]  # (btclib, btcd, input)


def _read_var_int(octets: bytes, at: int) -> tuple[int, int]:
    """Return the CompactSize at `at` and the index after it."""
    first = octets[at]
    if first < 0xFD:
        return first, at + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    value = int.from_bytes(octets[at + 1 : at + 1 + width], "little")
    return value, at + 1 + width


def _addrv2_entries(octets: bytes) -> list[tuple[bytes, int, int]] | None:
    """Return the entries of an addrv2 serialization, or None if it is not one.

    An entry is the time, the services as a CompactSize, the network id,
    the address as var_bytes and the port. Each is returned as its octets,
    its network id and its address size.
    """
    entries = []
    try:
        count, at = _read_var_int(octets, 0)
        for _ in range(count):
            start = at
            _, at = _read_var_int(octets, at + 4)
            network = octets[at]
            size, at = _read_var_int(octets, at + 1)
            at += size + 2
            entries.append((octets[start:at], network, size))
    except (IndexError, KeyError):
        return None
    return entries


def _without_unknown_networks(serialized: str) -> str:
    """Return an addrv2 serialization without the entries of ids outside 1-6."""
    entries = _addrv2_entries(bytes.fromhex(serialized))
    if entries is None:
        return ""  # not an addrv2 serialization: equal to nothing
    kept = [octets for octets, network, _ in entries if 1 <= network <= 6]
    return (var_int.serialize(len(kept)) + b"".join(kept)).hex()


def _only_torv2_has_wrong_size(data: bytes) -> bool:
    """Return whether addrv2 `data` has an id 3 address not 10 octets long.

    Every other id both libraries check must have its size, so that the
    one wrong TORV2 does not explain a refusal that another entry caused.
    """
    entries = _addrv2_entries(data)
    return (
        entries is not None
        and any(n == _TORV2 and size != _TORV2_SIZE for _, n, size in entries)
        and all(_CHECKED_SIZES.get(n, size) == size for _, n, size in entries)
    )


# Triaged against Bitcoin Core at a8b69bdeaf. A disagreement one of these
# explains is counted under its rule and does not fail the run; any other
# does. None of them is a defect of btclib. Each is keyed by what the two
# libraries answered, never by a list of inputs.
KNOWN = (
    Rule(
        "version-fields-optional",
        ("version",),
        "btclib requires addr_from through start_height, which Core reads only"
        " where octets remain (handshake.py's docstring; net_processing.cpp"
        " 3884-3899); btcd also accepts addr_from without the nonce, which"
        " Core refuses (3889-3890)",
        lambda ours, theirs, data: (
            ours.status == REFUSED
            and theirs.status == ACCEPTED
            and ours.detail.startswith("BTClibValueError: not enough")
            and len(theirs.detail) > len(data) * 2
            and theirs.detail.startswith(data.hex())
        ),
    ),
    Rule(
        "relay-flag-byte",
        ("version",),
        "Core reads the relay flag as any byte (serialize.h line 280);"
        " btclib refuses a byte above 1, which it could not write back",
        lambda ours, theirs, _: (
            ours.status == REFUSED
            and theirs.status == ACCEPTED
            and "invalid relay flag" in ours.detail
        ),
    ),
    Rule(
        "var-int-above-max-size",
        ("var_int",),
        "btcd has no range check; Core refuses above MAX_SIZE"
        " (serialize.h line 359), as btclib does",
        lambda ours, theirs, _: (
            ours.status == REFUSED
            and theirs.status == ACCEPTED
            and "var_int too big" in ours.detail
        ),
    ),
    Rule(
        "zero-flag-after-empty-vin",
        ("tx", "block"),
        "btcd refuses a zero flag byte after an empty input list; Core reads"
        " an empty transaction (primitives/transaction.h lines 212-218)",
        lambda ours, theirs, data: (
            ours.status == ACCEPTED
            and ours.detail == data.hex()
            and theirs.status == REFUSED
            and "flag byte is 00" in theirs.detail
        ),
    ),
    Rule(
        "addrv2-unknown-network-dropped",
        ("addrv2",),
        "Core ignores an address of a network id outside 1-6 and btclib keeps"
        " its octets (netaddress.h line 470); btcd drops them as Core does",
        lambda ours, theirs, _: (
            ours.status == theirs.status == ACCEPTED
            and theirs.detail == _without_unknown_networks(ours.detail)
        ),
    ),
    Rule(
        "addrv2-torv2-size",
        ("addrv2",),
        "btcd refuses a TORV2 address that is not 10 octets long; Core has no"
        " case for id 3 in SetNetFromBIP155Network (netaddress.cpp lines 52-97)"
        " and so reads an address of any size up to 512 and ignores it"
        " (netaddress.h lines 304, 432-435, 468-470); btclib accepts it too,"
        " and keeps its octets",
        lambda ours, theirs, data: (
            ours.status == ACCEPTED
            and theirs.status == REFUSED
            and theirs.detail == "invalid address size"
            and _only_torv2_has_wrong_size(data)
        ),
    ),
)


@dataclass(frozen=True)
class Job:
    """One input read through one entry point."""

    fuzzer: str
    entry: str
    kind: str
    path: Path
    label: str  # the directory's name and the path below it


def _resolve(entry: str) -> Any:
    module_name, _, qualname = entry.partition(":")
    obj: Any = importlib.import_module(module_name)
    for name in qualname.split("."):
        obj = getattr(obj, name)
    return obj


def entry_points(harness: Path) -> tuple[str, ...]:
    """Return the `ENTRY_POINTS` of a harness, read without importing it."""
    for node in ast.parse(harness.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "ENTRY_POINTS" for t in node.targets
        ):
            return tuple(ast.literal_eval(node.value))
    err_msg = f"{harness} declares no ENTRY_POINTS"
    raise SystemExit(err_msg)


def fuzzer_directories(roots: list[Path]) -> dict[Path, str]:
    """Return every directory under the roots that holds one fuzzer's inputs."""
    found: dict[Path, str] = {}
    for root in roots:
        for directory in [root, *sorted(p for p in root.rglob("*") if p.is_dir())]:
            name = directory.name.removeprefix(_ARTIFACT_PREFIX)
            if (_FUZZ / f"{name}.py").is_file() and name.startswith("fuzz_"):
                found[directory] = name
    return found


def unpack(roots: list[Path], into: Path) -> list[Path]:
    """Return the roots, with each `.tar` below them unpacked into `into`."""
    unpacked = list(roots)
    for root in roots:
        for archive in sorted(root.rglob("*.tar")):
            target = into / archive.stem
            target.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive) as tar:
                tar.extractall(target, filter="data")
            unpacked.append(target)
    return unpacked


def _commands() -> dict[str, Any]:
    """Return the btclib payload class of each command it has one for."""
    classes = {}
    for entry, kind in KINDS.items():
        if kind in ("message", "var_int", "var_bytes"):
            continue
        cls = _resolve(entry.rpartition(".")[0])
        if hasattr(cls, "command"):
            classes[cls.command] = cls
    return classes


def _structural(function: Any, *args: Any) -> Any:
    """Call `function`, with `check_validity=False` where it takes the flag.

    btcd's decoders read a structure and leave its validity to the caller:
    a block's proof of work and merkle root, a transaction's duplicate
    inputs. btclib's `parse` checks them by default, so the comparison turns
    that off to ask the same question.
    """
    if "check_validity" in inspect.signature(function).parameters:
        return function(*args, check_validity=False)
    return function(*args)


def _read_whole(parse: Callable[[Any], Any], data: bytes) -> Any:
    """Return what `parse` reads from `data`, refusing octets left unread."""
    stream = io.BytesIO(data)
    parsed = parse(stream)
    if left := len(data) - stream.tell():
        err_msg = f"{left} trailing octets"
        raise BTClibValueError(err_msg)
    return parsed


def read_with_btclib(entry: str, data: bytes, commands: dict[str, Any]) -> Outcome:
    """Return what btclib makes of `data` through `entry`."""
    kind = KINDS.get(entry)
    if kind is None:
        return Outcome(UNSUPPORTED, "no btcd decoder")
    try:
        if kind == "message":
            message = Message.parse(data)
            cls = commands.get(message.command)
            if cls is None:
                return Outcome(
                    UNSUPPORTED, f"btclib has no class for {message.command!r}"
                )
            payload = _structural(_structural(cls.parse, message.payload).serialize)
            return Outcome(
                ACCEPTED,
                Message(message.magic, message.command, payload).serialize().hex(),
            )
        parse = _resolve(entry)
        parsed = (
            _read_whole(parse, data)
            if kind in _STREAM_KINDS
            else _structural(parse, data)
        )
        if kind == "var_int":
            out = _resolve("btclib.var_int:serialize")(parsed)
        elif kind == "var_bytes":
            out = _resolve("btclib.var_bytes:serialize")(parsed)
        elif isinstance(parsed, Tx):
            out = _structural(parsed.serialize, True)
        else:
            out = _structural(parsed.serialize)
    except BTClibException as exc:
        return Outcome(REFUSED, f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001 -- a crash is what this reports
        return Outcome(CRASH, f"{type(exc).__name__}: {exc}")
    return Outcome(ACCEPTED, out.hex())


def build_decoder(out_dir: Path) -> Path:
    """Build `fuzz/btcd_decode` into `out_dir` and return the executable."""
    executable = out_dir / "btcd_decode"
    subprocess.run(  # noqa: S603 -- a fixed command
        ["go", "build", "-o", str(executable), "."],  # noqa: S607
        cwd=_DECODER_SOURCE,
        check=True,
    )
    return executable


def read_with_btcd(decoder: Path, jobs: list[Job]) -> list[Outcome]:
    """Return what btcd makes of each job, in order."""
    requests = "".join(
        json.dumps({"kind": job.kind, "path": str(job.path)}) + "\n" for job in jobs
    )
    done = subprocess.run(  # noqa: S603 -- the decoder the caller named
        [str(decoder)],
        input=requests,
        capture_output=True,
        encoding="utf-8",
        check=True,
    )
    outcomes = []
    for line in done.stdout.splitlines():
        answer = json.loads(line)
        status = {"panic": CRASH}.get(answer["status"], answer["status"])
        detail = answer.get("hex") if status == ACCEPTED else answer.get("error", "")
        outcomes.append(Outcome(status, detail or ""))
    if len(outcomes) != len(jobs):
        err_msg = f"btcd_decode answered {len(outcomes)} of {len(jobs)} inputs"
        raise SystemExit(err_msg)
    return outcomes


def _first_difference(a: str, b: str) -> int:
    """Return the index of the first octet two hex strings differ at."""
    octets = min(len(a), len(b)) // 2
    return next(
        (i for i in range(octets) if a[2 * i : 2 * i + 2] != b[2 * i : 2 * i + 2]),
        octets,
    )


def disagreement(ours: Outcome, theirs: Outcome) -> str | None:
    """Return how the two outcomes differ, or None when they agree."""
    if UNSUPPORTED in (ours.status, theirs.status):
        return None
    if CRASH in (ours.status, theirs.status):
        return "crash"
    if ours.status != theirs.status:
        return f"btclib {ours.status}, btcd {theirs.status}"
    if ours.status == ACCEPTED and ours.detail != theirs.detail:
        return f"both accept, serializations differ at octet {_first_difference(ours.detail, theirs.detail)}"
    return None


def explained_by(kind: str, ours: Outcome, theirs: Outcome, data: bytes) -> Rule | None:
    """Return the rule that explains this disagreement, if one does."""
    return next(
        (r for r in KNOWN if kind in r.kinds and r.matches(ours, theirs, data)), None
    )


def collect_jobs(roots: list[Path]) -> tuple[list[Job], Counter[str]]:
    """Return one job per input and entry point, and the entry points left."""
    jobs = []
    skipped: Counter[str] = Counter()
    for directory, fuzzer in sorted(fuzzer_directories(roots).items()):
        entries = entry_points(_FUZZ / f"{fuzzer}.py")
        files = sorted(
            p for p in directory.rglob("*") if p.is_file() and p.suffix != ".tar"
        )
        for entry in entries:
            kind = KINDS.get(entry)
            if kind is None:
                skipped[entry] += len(files)
                continue
            jobs.extend(
                Job(
                    fuzzer,
                    entry,
                    kind,
                    path,
                    f"{directory.name}/{path.relative_to(directory)}",
                )
                for path in files
            )
    return jobs, skipped


def main(argv: list[str] | None = None) -> int:
    """List the inputs btclib and btcd read differently."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("roots", nargs="+", type=Path, help="corpus directories")
    parser.add_argument(
        "--decoder",
        type=Path,
        help="a built fuzz/btcd_decode; built with `go build` when absent",
    )
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as tmp:
        return _compare(args, Path(tmp))


def _compare(args: argparse.Namespace, tmp: Path) -> int:
    jobs, skipped = collect_jobs(unpack(args.roots, tmp / "unpacked"))
    if not jobs:
        err_msg = "no input found: name a directory called fuzz_<name> or cifuzz-corpus-fuzz_<name>"
        raise SystemExit(err_msg)
    commands = _commands()
    ours = [
        read_with_btclib(job.entry, job.path.read_bytes(), commands) for job in jobs
    ]
    decoder = args.decoder or build_decoder(tmp)
    theirs = read_with_btcd(decoder, jobs)

    listed = 0
    known: Counter[str] = Counter()
    compared: Counter[str] = Counter()
    for job, a, b in zip(jobs, ours, theirs, strict=True):
        if UNSUPPORTED in (a.status, b.status):
            skipped[job.entry] += 1
            continue
        compared[job.entry] += 1
        why = disagreement(a, b)
        if why is None:
            continue
        rule = explained_by(job.kind, a, b, job.path.read_bytes())
        if rule is not None:
            known[rule.name] += 1
            continue
        listed += 1
        print(f"{job.label}  [{job.entry}]  {why}")  # noqa: T201
        for name, outcome in (("btclib", a), ("btcd", b)):
            print(f"    {name:6} {outcome.status}: {outcome.detail[:_SHOWN]}")  # noqa: T201

    print(f"compared {sum(compared.values())} reads, listed {listed}")  # noqa: T201
    for rule in KNOWN:
        if known[rule.name]:
            print(f"known: {rule.name} x{known[rule.name]}: {rule.why}")  # noqa: T201
    for entry, n in sorted(skipped.items()):
        print(f"not compared: {entry} x{n}")  # noqa: T201
    return 1 if listed else 0


if __name__ == "__main__":
    sys.exit(main())
