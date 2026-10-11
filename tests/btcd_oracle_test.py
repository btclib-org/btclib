# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`fuzz/btcd_oracle.py` lists the inputs btclib and btcd read differently.

The Go side is not run here: it needs a toolchain and the network, and
`btcd-oracle.yml` runs it. What is held here is the Python side, with a
stand-in decoder that answers from a fixed table.
"""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest

from btclib.hashes import hash256

_FUZZ = Path(__file__).parent.parent / "fuzz"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "btcd_oracle", _FUZZ / "btcd_oracle.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


oracle = _load()

_SEGWIT_TX = (_FUZZ / "corpus" / "fuzz_tx" / "segwit.bin").read_bytes()
_MAGIC = bytes.fromhex("f9beb4d9")


def _fake_decoder(
    monkeypatch: pytest.MonkeyPatch, answers: list[dict[str, str]]
) -> str:
    """Make btcd's side answer `answers` and return the path to name it by."""

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        stdout = "".join(json.dumps(a) + "\n" for a in answers)
        return subprocess.CompletedProcess(command, 0, stdout=stdout)

    monkeypatch.setattr(oracle.subprocess, "run", run)
    return "decoder"


def test_every_kind_names_an_entry_point_of_a_harness() -> None:
    """A kind of the table is an entry point some harness declares."""
    declared = {
        entry
        for harness in _FUZZ.glob("fuzz_*.py")
        for entry in oracle.entry_points(harness)
    }
    assert set(oracle.KINDS) <= declared


def test_a_harness_without_entry_points_is_refused(tmp_path: Path) -> None:
    """A harness that declares no entry point is an error."""
    harness = tmp_path / "fuzz_none.py"
    harness.write_text("X = 1\n")
    with pytest.raises(SystemExit, match="declares no ENTRY_POINTS"):
        oracle.entry_points(harness)


@pytest.mark.parametrize(
    "ours, theirs, expected",
    [
        (("accepted", "00"), ("accepted", "00"), None),
        (
            ("accepted", "00"),
            ("accepted", "01"),
            "both accept, serializations differ at octet 0",
        ),
        (
            ("accepted", "00"),
            ("accepted", "0001"),
            "both accept, serializations differ at octet 1",
        ),
        (("accepted", "00"), ("refused", "x"), "btclib accepted, btcd refused"),
        (("refused", "x"), ("accepted", "00"), "btclib refused, btcd accepted"),
        (("refused", "x"), ("refused", "y"), None),
        (("crash", "x"), ("refused", "y"), "crash"),
        (("accepted", "00"), ("crash", "y"), "crash"),
        (("unsupported", ""), ("accepted", "00"), None),
        (("accepted", "00"), ("unsupported", ""), None),
    ],
)
def test_disagreement(
    ours: tuple[str, str], theirs: tuple[str, str], expected: str | None
) -> None:
    """Each pair of outcomes is told apart as the report words it."""
    assert (
        oracle.disagreement(oracle.Outcome(*ours), oracle.Outcome(*theirs)) == expected
    )


def _message(command: bytes, payload: bytes) -> bytes:
    return (
        _MAGIC
        + command.ljust(12, b"\x00")
        + len(payload).to_bytes(4, "little")
        + hash256(payload)[:4]
        + payload
    )


@pytest.mark.parametrize(
    "entry, data, status",
    [
        ("btclib.tx.tx:Tx.parse", _SEGWIT_TX, "accepted"),
        ("btclib.tx.tx:Tx.parse", b"\x00", "refused"),
        ("btclib.var_int:parse", b"\x01", "accepted"),
        ("btclib.var_bytes:parse", b"\x01\x02", "accepted"),
        ("btclib.script.script:parse", b"", "unsupported"),
        ("btclib.p2p.message:Message.parse", _message(b"verack", b""), "accepted"),
        (
            "btclib.p2p.message:Message.parse",
            _message(b"cmpctblock", b""),
            "unsupported",
        ),
        ("btclib.p2p.message:Message.parse", b"", "refused"),
    ],
)
def test_btclib_side(entry: str, data: bytes, status: str) -> None:
    """Each entry point is accepted, refused or unsupported by btclib."""
    outcome = oracle.read_with_btclib(entry, data, oracle._commands())
    assert outcome.status == status


def test_btclib_side_reports_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exception that is not a BTClibException is a crash."""

    def boom(_: bytes) -> None:
        raise IndexError

    monkeypatch.setattr("btclib.var_int.parse", boom)
    outcome = oracle.read_with_btclib("btclib.var_int:parse", b"\x01", {})
    assert outcome.status == "crash"


def test_tar_artifacts_are_unpacked(tmp_path: Path) -> None:
    """A downloaded artifact's tar is read as its fuzzer's inputs."""
    root = tmp_path / "downloaded" / "cifuzz-corpus-fuzz_var_int"
    root.mkdir(parents=True)
    with tarfile.open(root / "cifuzz-corpus-fuzz_var_int.tar", "w") as tar:
        info = tarfile.TarInfo("0000")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"\x01"))
    roots = oracle.unpack([tmp_path / "downloaded"], tmp_path / "out")
    jobs, skipped = oracle.collect_jobs(roots)
    assert [job.path.name for job in jobs] == ["0000"]
    assert not skipped


def test_main_lists_what_the_two_read_differently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A disagreement is printed and the exit status is 1."""
    corpus = tmp_path / "fuzz_var_int"
    corpus.mkdir()
    (corpus / "one.bin").write_bytes(b"\x01")
    decoder = _fake_decoder(
        monkeypatch,
        [{"kind": "var_int", "path": "x", "status": "refused", "error": "no"}],
    )
    assert oracle.main([str(corpus), "--decoder", decoder]) == 1
    out = capsys.readouterr().out
    assert "btclib accepted, btcd refused" in out
    assert "listed 1" in out


def test_main_exits_zero_when_they_agree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Agreement prints nothing but the totals and exits 0."""
    corpus = tmp_path / "fuzz_var_int"
    corpus.mkdir()
    (corpus / "one.bin").write_bytes(b"\x01")
    decoder = _fake_decoder(
        monkeypatch,
        [{"kind": "var_int", "path": "x", "status": "accepted", "hex": "01"}],
    )
    assert oracle.main([str(corpus), "--decoder", decoder]) == 0
    assert "not compared: btclib.var_int" not in capsys.readouterr().out


def test_main_refuses_a_decoder_that_skips_an_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A decoder answering fewer inputs than asked is an error."""
    corpus = tmp_path / "fuzz_var_int"
    corpus.mkdir()
    (corpus / "one.bin").write_bytes(b"\x01")
    decoder = _fake_decoder(monkeypatch, [])
    with pytest.raises(SystemExit, match="answered 0 of 1"):
        oracle.main([str(corpus), "--decoder", decoder])


def test_main_refuses_a_directory_with_no_fuzzer(tmp_path: Path) -> None:
    """A directory named after no fuzzer holds no input."""
    with pytest.raises(SystemExit, match="no input found"):
        oracle.main([str(tmp_path)])


_TIME = "00000000"
_PORT = "0000"


def _addrv2(*entries: tuple[str, str, str]) -> str:
    """Return an addrv2 serialization of (services, network id, address)."""
    out = f"{len(entries):02x}"
    for services, network, address in entries:
        size = f"{len(address) // 2:02x}"
        out += _TIME + services + network + size + address + _PORT
    return out


_IPV4 = ("00", "01", "7f000001")
_I2P = ("00", "05", "00" * 32)
_UNKNOWN = ("00", "09", "ab")
_VERSION = "62ea0000" + "00" * 90


@pytest.mark.parametrize(
    "kind, ours, theirs, data, rule",
    [
        (
            "version",
            ("refused", "BTClibValueError: not enough data for the nonce"),
            ("accepted", _VERSION + "00"),
            _VERSION,
            "version-fields-optional",
        ),
        (
            "version",
            ("refused", "BTClibValueError: not enough data for the nonce"),
            ("accepted", _VERSION),
            _VERSION,
            None,
        ),
        (
            "version",
            ("refused", "BTClibValueError: not enough data for the nonce"),
            ("accepted", "ff" + _VERSION + "00"),
            _VERSION,
            None,
        ),
        (
            "version",
            ("refused", "BTClibValueError: invalid relay flag: 20"),
            ("accepted", "00"),
            "00",
            "relay-flag-byte",
        ),
        (
            "var_int",
            ("refused", "BTClibValueError: var_int too big: 00"),
            ("accepted", "00"),
            "00",
            "var-int-above-max-size",
        ),
        (
            "tx",
            ("accepted", "0102"),
            ("refused", "MsgTx.BtcDecode: witness tx but flag byte is 00"),
            "0102",
            "zero-flag-after-empty-vin",
        ),
        (
            "tx",
            ("accepted", "0103"),
            ("refused", "MsgTx.BtcDecode: witness tx but flag byte is 00"),
            "0102",
            None,
        ),
        (
            "addrv2",
            ("accepted", _addrv2(_IPV4, _UNKNOWN)),
            ("accepted", _addrv2(_IPV4)),
            "",
            "addrv2-unknown-network-dropped",
        ),
        (
            "addrv2",
            ("accepted", _addrv2(_I2P)),
            ("accepted", _addrv2()),
            "",
            None,
        ),
        (
            "addrv2",
            ("accepted", _addrv2(_IPV4)),
            ("accepted", _addrv2()),
            "",
            None,
        ),
        ("addrv2", ("accepted", "01"), ("accepted", "00"), "", None),
        ("tx", ("refused", "x"), ("accepted", "00"), "", None),
        (
            "message",
            ("refused", "BTClibValueError: not enough"),
            ("accepted", "0"),
            "",
            None,
        ),
    ],
)
def test_known_differences(
    kind: str,
    ours: tuple[str, str],
    theirs: tuple[str, str],
    data: str,
    rule: str | None,
) -> None:
    """A triaged class is explained by its rule, and by no other."""
    found = oracle.explained_by(
        kind,
        oracle.Outcome(*ours),
        oracle.Outcome(*theirs),
        bytes.fromhex(data),
    )
    assert (found.name if found else None) == rule


def test_main_counts_a_known_difference_and_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A rule's disagreement is counted under it and does not fail the run."""
    corpus = tmp_path / "fuzz_var_int"
    corpus.mkdir()
    (corpus / "big.bin").write_bytes(bytes.fromhex("fe00000003"))
    decoder = _fake_decoder(
        monkeypatch,
        [{"kind": "var_int", "path": "x", "status": "accepted", "hex": "fe00000003"}],
    )
    assert oracle.main([str(corpus), "--decoder", decoder]) == 0
    assert "known: var-int-above-max-size x1" in capsys.readouterr().out
