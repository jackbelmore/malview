import pytest

from malview.models import (
    ImportInfo,
    PEMetadata,
    ScanResult,
    YaraMatch,
    is_suspicious_api,
    yara_match_kind,
)


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

def _m(namespace, *tags, rule="r"):
    return YaraMatch(rule_name=rule, namespace=namespace, tags=list(tags), meta={})


@pytest.mark.parametrize("match,kind", [
    (_m("packers/packer_compiler_signatures", "PECheck"), "info"),
    (_m("packers/peid", "PEiD"), "info"),                       # compiler/packer EP signature
    (_m("packers/packer", "Packer", "PEiD"), "packer"),
    (_m("packers/packer"), "packer"),
    (_m("malware/MALW_PE_sections", "packer", "PE"), "packer"),  # heuristic under malware/
    (_m("malware/APT_Dubnium"), "malware"),
    (_m("utils/base64", "trojan"), "malware"),
    (_m("cve_rules/CVE-2012-0158"), "exploit"),
    (_m("utils/base64"), "other"),
])
def test_yara_match_kind(match, kind):
    assert yara_match_kind(match) == kind


def _result(matches):
    meta = PEMetadata(file_size=1, architecture="x86", compile_time=None,
                      is_dll=False, is_64bit=False, entry_point=0)
    return ScanResult(file_path="x", hashes={}, metadata=meta, sections=[], imports=[],
                      yara_matches=matches)


def test_informational_matches_are_not_scored():
    # A normal MSVC console binary matches these; it shouldn't look suspicious.
    risk = _result([
        _m("packers/packer_compiler_signatures", "PECheck", rule="IsPE32"),
        _m("packers/peid", "PEiD", rule="Microsoft_Visual_Cpp_8"),
    ]).assess_risk()
    assert (risk.risk_level, risk.score) == ("LOW", 0)


def test_malware_summary_names_the_malware_rule():
    risk = _result([
        _m("packers/peid", "PEiD", rule="Microsoft_Visual_Cpp_8"),
        _m("malware/APT_Dubnium", rule="Dubnium_Sample"),
    ]).assess_risk()
    assert risk.risk_level == "CRITICAL"
    assert risk.summary.endswith("Dubnium_Sample")
