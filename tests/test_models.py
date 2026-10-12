import pytest

from malview.models import (
    ImportInfo,
    PEMetadata,
    ScanResult,
    YaraMatch,
    is_injection_api,
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

def _m(namespace, *tags, rule="r", meta=None):
    return YaraMatch(rule_name=rule, namespace=namespace, tags=list(tags), meta=meta or {})


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
    (_m("packers/packer", rule="Borland"), "info"),            # compiler name, not a packer
    (_m("packers/packer_compiler_signatures", rule="borland_delphi"), "info"),
    (_m("packers/packer_compiler_signatures", rule="AutoIt"), "packer"),
    # Written for memory dumps; matched every MinGW binary via "data_end".
    (_m("malware/MALW_Miscelanea", "banker", rule="spyeye",
        meta={"filetype": "memory"}), "other"),
    (_m("malware/x", meta={"filetype": "js-html"}), "other"),
    (_m("malware/x", meta={"filetype": "EXE"}), "malware"),
    (_m("malware/x", meta={"filetype": "unknown"}), "malware"),
    (_m("packers/Javascript_exploit_and_obfuscation"), "other"),  # JS, not a PE packer
    (_m("malware/MALW_Rooter", "Rooter", "Family", rule="RooterStrings"), "other"),
])
def test_yara_match_kind(match, kind):
    assert yara_match_kind(match) == kind


def _result(matches, imports=()):
    meta = PEMetadata(file_size=1, architecture="x86", compile_time=None,
                      is_dll=False, is_64bit=False, entry_point=0)
    return ScanResult(file_path="x", hashes={}, metadata=meta, sections=[],
                      imports=list(imports), yara_matches=matches)


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


@pytest.mark.parametrize("name,injection", [
    ("WriteProcessMemory", True), ("CreateRemoteThread", True), ("SetWindowsHookExW", True),
    ("VirtualAllocEx", True), ("NtUnmapViewOfSection", True),
    ("VirtualAlloc", False), ("LoadLibraryW", False), ("GetProcAddress", False),
    ("CreateProcessW", False),
])
def test_injection_api(name, injection):
    assert is_injection_api(name) is injection
    assert is_suspicious_api(name)  # still listed for the analyst


def test_signed_installer_is_not_flagged():
    # Regression: a signed GOG (Inno Setup, Delphi) installer scored HIGH
    # 60/100, "likely malicious": +20 for Delphi compiler rules as a packer,
    # +15 twice for the same loader APIs because kernel32.dll appears in its
    # import table four times, and +10 for having them at all.
    risk = _result(
        [
            _m("packers/packer", rule="Borland"),
            _m("packers/packer_compiler_signatures", rule="borland_delphi"),
            _m("capabilities/capabilities", rule="win_registry"),
            _m("packers/packer_compiler_signatures", "PECheck", rule="IsPE32"),
        ],
        imports=[
            ImportInfo("kernel32.dll", ["VirtualAlloc", "LoadLibraryExW", "GetProcAddress"]),
            ImportInfo("user32.dll", ["MessageBoxW"]),
            ImportInfo("kernel32.dll", ["VirtualProtect", "VirtualAlloc", "LoadLibraryW",
                                        "GetProcAddress", "CreateProcessW"]),
        ],
    ).assess_risk()
    assert [a for a in risk.anomalies if a.category == "import"] == []
    assert (risk.risk_level, risk.score) == ("LOW", 10)


def test_injection_imports_are_one_anomaly_across_repeated_dlls():
    risk = _result([], imports=[
        ImportInfo("KERNEL32.dll", ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"]),
        ImportInfo("kernel32.dll", ["CreateRemoteThread", "WriteProcessMemory"]),
    ]).assess_risk()
    imports = [a for a in risk.anomalies if a.category == "import"]
    assert len(imports) == 1
    assert imports[0].description == (
        "Imports process-injection APIs: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread")
    assert risk.score == 15 + 10


def test_high_entropy_data_ranks_below_high_entropy_code():
    from malview.models import SectionInfo
    def sec(name, chars):
        return SectionInfo(name=name, virtual_address=0, virtual_size=1, raw_size=1,
                           entropy=7.9, characteristics=chars)
    result = _result([])
    result.sections = [sec(".rsrc", ["R"]), sec(".text", ["R", "X"])]
    severities = {a.description.split("'")[1]: a.severity
                  for a in result.detect_anomalies() if a.category == "entropy"}
    assert severities == {".rsrc": "medium", ".text": "high"}
