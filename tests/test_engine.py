import json
import os

import pytest

from malview import PEEngine
from malview.exceptions import FileNotFoundError, InvalidPEFileError, UnsupportedFileError
from pe_builder import build_pe


@pytest.fixture
def engine():
    return PEEngine(enable_yara=False)


def test_metadata(engine, make_pe):
    result = engine.analyze(make_pe(timestamp=1_600_000_000))
    assert result.metadata.architecture == "x86"
    assert result.metadata.is_64bit is False
    assert result.metadata.is_dll is False
    assert result.metadata.compile_time == "2020-09-13T12:26:40+00:00"  # UTC, not local time
    assert not result.metadata.has_fake_timestamp()


def test_dll_flag_and_unknown_machine(engine, make_pe):
    result = engine.analyze(make_pe(dll=True, machine=0xAA64))
    assert result.metadata.is_dll is True
    assert result.metadata.architecture.startswith("unknown")


def test_sections_and_imports(engine, suspicious_pe):
    result = engine.analyze(suspicious_pe)
    by_name = {s.name: s for s in result.sections}

    assert set(by_name) == {".text", ".packed", ".idata"}
    assert by_name[".text"].characteristics == ["R", "X"]
    assert by_name[".text"].entropy == 0.0
    assert by_name[".packed"].characteristics == ["R", "W", "X"]
    assert by_name[".packed"].entropy > 7.5
    assert by_name[".packed"].is_suspicious()
    assert not by_name[".text"].is_suspicious()

    imports = {i.dll_name: i.functions for i in result.imports}
    assert imports["KERNEL32.dll"] == [
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "ExitProcess"]
    assert [i.dll_name for i in result.get_suspicious_imports()] == ["KERNEL32.dll"]


def test_risk_assessment(engine, suspicious_pe, benign_pe):
    bad = engine.analyze(suspicious_pe).assess_risk()
    categories = {a.category for a in bad.anomalies}
    assert {"entropy", "section", "import"} <= categories
    assert bad.risk_level in {"HIGH", "CRITICAL"}

    good = engine.analyze(benign_pe).assess_risk()
    assert good.risk_level == "LOW"
    assert good.anomalies == []


def test_json_round_trip(engine, suspicious_pe):
    data = json.loads(engine.analyze(suspicious_pe).to_json())
    assert data["hashes"]["sha256"] and len(data["hashes"]["sha256"]) == 64
    assert {s["name"] for s in data["sections"]} == {".text", ".packed", ".idata"}


def test_missing_file(engine, tmp_path):
    with pytest.raises(FileNotFoundError):
        engine.analyze(str(tmp_path / "nope.exe"))


def test_not_a_pe(engine, tmp_path):
    path = tmp_path / "notes.exe"
    path.write_text("just some text, not a PE")
    with pytest.raises(InvalidPEFileError):
        engine.analyze(str(path))


@pytest.mark.parametrize("length", [0, 2, 0x40])
def test_truncated_headers(engine, tmp_path, length):
    path = tmp_path / "truncated.exe"
    path.write_bytes(build_pe()[:length])
    with pytest.raises(InvalidPEFileError):
        engine.analyze(str(path))


@pytest.mark.parametrize("length", range(0x40, 0x420, 0x20))
def test_truncation_never_crashes(engine, tmp_path, suspicious_pe, length):
    # pefile is lenient (a file cut off after the headers still parses, with
    # empty sections), which is useful for damaged samples. Whatever happens,
    # the engine must either return a result or raise InvalidPEFileError.
    with open(suspicious_pe, "rb") as f:
        data = f.read()
    path = tmp_path / "cut.exe"
    path.write_bytes(data[:length])
    try:
        result = engine.analyze(str(path))
    except InvalidPEFileError:
        return
    result.assess_risk()
    result.to_json()


def test_directory_rejected(engine, tmp_path):
    with pytest.raises(UnsupportedFileError):
        engine.analyze(str(tmp_path))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
def test_fifo_rejected_without_blocking(engine, tmp_path):
    # Opening a FIFO for reading blocks until a writer appears; the engine
    # must refuse it before pefile or the hasher ever opens it.
    fifo = tmp_path / "trap.exe"
    os.mkfifo(fifo)
    with pytest.raises(UnsupportedFileError):
        engine.analyze(str(fifo))


def test_size_limit(make_pe):
    path = make_pe()
    with pytest.raises(UnsupportedFileError, match="limit"):
        PEEngine(enable_yara=False, max_file_size=100).analyze(path)
