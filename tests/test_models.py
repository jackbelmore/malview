import pytest

from malview.models import ImportInfo, PEMetadata, is_suspicious_api


@pytest.mark.parametrize("name", [
    "VirtualAlloc", "CreateProcessA", "CreateProcessW", "LoadLibraryExW",
    "RegSetValueExA", "URLDownloadToFileW", "ShellExecuteA", "InternetOpenW",
])
def test_suspicious_api_variants(name):
    assert is_suspicious_api(name)


@pytest.mark.parametrize("name", ["ExitProcess", "GetStdHandle", "A", "W", "", "CreateProcessX"])
def test_not_suspicious(name):
    assert not is_suspicious_api(name)


def test_import_info_reports_wide_variant():
    # Regression: real binaries import CreateProcessW, never CreateProcess,
    # and an exact-match check missed it.
    imp = ImportInfo(dll_name="KERNEL32.dll", functions=["ExitProcess", "CreateProcessW"])
    assert imp.is_suspicious()
    assert imp.suspicious_functions() == ["CreateProcessW"]


@pytest.mark.parametrize("ts,fake", [
    ("2020-09-13T12:26:40+00:00", False),
    ("1985-01-01T00:00:00+00:00", True),
    ("2999-01-01T00:00:00+00:00", True),
    ("not a date", False),
    (None, False),
])
def test_fake_timestamp(ts, fake):
    meta = PEMetadata(file_size=1, architecture="x86", compile_time=ts,
                      is_dll=False, is_64bit=False, entry_point=0)
    assert meta.has_fake_timestamp() is fake
