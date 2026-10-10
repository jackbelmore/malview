import random

import pytest

from pe_builder import RWX, TEXT, build_pe


@pytest.fixture
def make_pe(tmp_path):
    """Write a synthetic PE to tmp_path and return its path as a string."""
    def _make(name="sample.exe", **kwargs):
        path = tmp_path / name
        path.write_bytes(build_pe(**kwargs))
        return str(path)
    return _make


@pytest.fixture
def suspicious_pe(make_pe):
    """A PE with a W+X high-entropy section and injection-style imports."""
    return make_pe(
        sections=[
            (".text", TEXT, b"\x90" * 0x200),
            (".packed", RWX, random.Random(0).randbytes(4096)),
        ],
        imports={
            "KERNEL32.dll": ["VirtualAlloc", "CreateProcessW", "ExitProcess"],
            "USER32.dll": ["MessageBoxA"],
        },
    )


@pytest.fixture
def benign_pe(make_pe):
    return make_pe(
        name="benign.exe",
        sections=[(".text", TEXT, b"\x00" * 0x200)],
        imports={"KERNEL32.dll": ["ExitProcess", "GetStdHandle"]},
    )


@pytest.fixture(autouse=True)
def _no_ambient_config(monkeypatch):
    """Tests must not pick up a real API key or rules from the environment."""
    for var in ("VT_API_KEY", "MALVIEW_YARA_RULES", "MALVIEW_CAPA_RULES"):
        monkeypatch.delenv(var, raising=False)
