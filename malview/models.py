"""Data models for PE analysis results."""

import json
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from datetime import datetime, timezone
from collections import defaultdict


# APIs commonly used by malware. Names are the base Win32 names; the ANSI/Wide
# variants (CreateProcessA, CreateProcessW, ...) are matched by
# is_suspicious_api() below.
SUSPICIOUS_APIS = frozenset({
    # Memory manipulation
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
    # Process injection and hollowing
    'WriteProcessMemory', 'CreateRemoteThread', 'SetWindowsHookEx',
    'QueueUserAPC', 'SetThreadContext', 'NtUnmapViewOfSection',
    # Code loading
    'LoadLibrary', 'LoadLibraryEx', 'GetProcAddress',
    # Cryptography (sometimes obfuscation)
    'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
    # Registry manipulation
    'RegSetValueEx', 'RegCreateKeyEx', 'RegDeleteKey',
    # Network
    'InternetOpen', 'InternetConnect', 'URLDownloadToFile',
    # Process manipulation
    'CreateProcess', 'ShellExecute', 'WinExec',
    # Anti-debugging
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
})

# The subset that writes into or redirects *another* process. Ordinary
# programs rarely import these, so they raise an anomaly. The rest of
# SUSPICIOUS_APIS (VirtualAlloc, LoadLibrary, GetProcAddress, CreateProcess,
# registry calls, ...) turns up in nearly every installer and in most
# runtimes' startup code, so on its own it only adds the small "suspicious
# import" bonus and is listed for the analyst.
INJECTION_APIS = frozenset({
    'VirtualAllocEx', 'VirtualProtectEx', 'WriteProcessMemory',
    'CreateRemoteThread', 'SetWindowsHookEx', 'QueueUserAPC',
    'SetThreadContext', 'NtUnmapViewOfSection',
})

# Rules in the packers/ directory that identify a compiler, linker or
# framework rather than a packer, so they're shown but not scored. Without
# this, every Delphi program (including every Inno Setup installer) scored
# +20 as "packed": "Borland" matches the string "Borland" anywhere, and
# borland_delphi is Delphi's normal startup code. From
# packer_compiler_signatures.yar, IsSuspicious, SkDUndetectabler (a crypter)
# and AutoIt (often used to wrap malware) still count.
COMPILER_ID_RULES = frozenset({
    'Borland',                                                  # packer.yar
    'borland_cpp', 'borland_delphi', 'borland_delphi_dll', 'borland_component',
    'free_pascal', 'PureBasic', 'PureBasicDLL', 'PureBasic4xDLL',
    'MicrosoftVisualCV80', 'Cygwin', 'MinGW_1', 'FASM', 'PellesC',
    'QtFrameWork', 'masm32_tasm32', 'IsGoLink',
})


# Matches that describe a file rather than flag it are shown but not scored:
# - PECheck: Yara-Rules' file-property rules (IsPE32, IsConsole, ...).
# - PEiD: entry-point signatures from the PEiD database, which identify
#   compilers (e.g. Microsoft_Visual_Cpp_8) as often as packers and are
#   prone to false positives. PEiD rules also tagged Packer still count.
def _is_informational(tags: set) -> bool:
    return "pecheck" in tags or ("peid" in tags and "packer" not in tags)


# Rule files under packers/ that are about other file types, not PE packers.
_NON_PE_RULE_FILES = frozenset({
    "javascript_exploit_and_obfuscation", "jjencode", "tweetable-polyglot-png",
})

# Rules that fire on common benign software. Shown, not scored.
NOISY_RULES = frozenset({
    # Any 3 of the strings "seed", "prot", "ownin", "feed0", "nown" (each
    # NUL-terminated): found in big DLLs with string tables, such as
    # Microsoft's dxcompiler.dll. "Rooter" fires whenever RooterStrings does.
    'RooterStrings', 'Rooter',
})

# Some Yara-Rules rules say what they were written for in their "filetype"
# meta. Rules for memory dumps, scripts or documents are shown but not scored
# on a PE file: "spyeye" (filetype "memory") fires on any one of a dozen
# strings, one of which, "data_end", is a symbol in every MinGW-built binary.
_PE_FILETYPES = frozenset({"exe", "dll", "pe", "pe,dll", "win32 exe", "binary", "unknown"})


def _targets_other_filetype(meta: dict) -> bool:
    filetype = str(meta.get("filetype", "")).strip().lower()
    return bool(filetype) and filetype not in _PE_FILETYPES


def yara_match_kind(match: "YaraMatch") -> str:
    """Classify a YARA match as "info", "packer", "exploit", "malware" or "other".

    Tags win over the rule's directory: Yara-Rules keeps some generic
    heuristics under malware/ (e.g. suspicious_packer_section, tagged
    "packer"), and those shouldn't be reported as a malware family.
    """
    tags = {t.lower() for t in match.tags}
    namespace = match.namespace.lower()
    if _is_informational(tags) or match.rule_name in COMPILER_ID_RULES:
        return "info"
    if (_targets_other_filetype(match.meta or {})
            or match.rule_name in NOISY_RULES
            or namespace.rsplit("/", 1)[-1] in _NON_PE_RULE_FILES):
        return "other"
    if "packer" in tags or "packer" in namespace:
        return "packer"
    if "exploit" in namespace or "cve" in namespace:
        return "exploit"
    if "malware" in namespace or tags & {"malware", "trojan", "ransomware", "apt"}:
        return "malware"
    return "other"


def _in_api_set(name: str, apis: frozenset) -> bool:
    if name in apis:
        return True
    return len(name) > 1 and name[-1] in "AW" and name[:-1] in apis


def is_suspicious_api(name: str) -> bool:
    """True if `name` is in SUSPICIOUS_APIS, allowing an A/W suffix.

    Most of these APIs are only ever imported as their ANSI or Wide variant
    (a real binary imports CreateProcessW, never CreateProcess), so an exact
    match alone misses them.
    """
    return _in_api_set(name, SUSPICIOUS_APIS)


def is_injection_api(name: str) -> bool:
    """True if `name` is in INJECTION_APIS, allowing an A/W suffix."""
    return _in_api_set(name, INJECTION_APIS)


@dataclass
class PEMetadata:
    """Basic PE file metadata."""
    file_size: int
    architecture: str  # "x86", "x64", "unknown"
    compile_time: Optional[str]  # ISO format timestamp
    is_dll: bool
    is_64bit: bool
    entry_point: int

    def has_fake_timestamp(self) -> bool:
        """Check if compilation timestamp is suspicious."""
        if not self.compile_time:
            return False
        try:
            compile_dt = datetime.fromisoformat(self.compile_time.replace('Z', '+00:00'))
        except ValueError:
            return False
        now = datetime.now(timezone.utc)
        # Future date or before 1990 (early Windows era)
        return compile_dt.year > now.year or compile_dt.year < 1990


@dataclass
class Anomaly:
    """Detected anomaly in PE file."""
    severity: str  # "low", "medium", "high"
    category: str  # "timestamp", "entropy", "section", "import", etc.
    description: str
    emoji: str = "⚠️"


@dataclass
class RiskAssessment:
    """Overall risk assessment of the PE file."""
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    score: int  # 0-100
    anomalies: List[Anomaly]
    summary: str

    def get_emoji(self) -> str:
        """Get emoji for risk level."""
        mapping = {
            "LOW": "✅",
            "MEDIUM": "⚠️",
            "HIGH": "🔴",
            "CRITICAL": "🚨"
        }
        return mapping.get(self.risk_level, "❓")


@dataclass
class SectionInfo:
    """PE section information with suspicious detection."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: List[str]  # ["R", "W", "X"]

    def is_suspicious(self) -> bool:
        """
        Detect suspicious section characteristics.

        Returns:
            True if section has W+X or high entropy with executable flag
        """
        has_wx = "W" in self.characteristics and "X" in self.characteristics
        high_entropy = self.entropy > 7.0
        is_executable = "X" in self.characteristics
        return has_wx or (high_entropy and is_executable)


@dataclass
class ImportInfo:
    """DLL import information with suspicious API detection."""
    dll_name: str
    functions: List[str]

    def suspicious_functions(self) -> List[str]:
        """Imported functions that are commonly used in malware."""
        return [func for func in self.functions if is_suspicious_api(func)]

    def is_suspicious(self) -> bool:
        """
        Detect suspicious API imports.

        Returns:
            True if any imported function is commonly used in malware
        """
        return any(is_suspicious_api(func) for func in self.functions)


@dataclass
class Capability:
    """Capability detected by capa (FLARE capability detector)."""
    namespace: str  # e.g., "anti-analysis/anti-debugging"
    name: str  # e.g., "check for debugger"
    description: str
    matches: List[str]  # Addresses where capability was detected


@dataclass
class StringFinding:
    """String finding from floss (obfuscated string solver)."""
    string: str  # The decoded string
    type: str  # "static", "decoded", or "stack"
    address: Optional[int] = None  # Location in binary


@dataclass
class YaraMatch:
    """YARA rule match."""
    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict[str, str]


@dataclass
class VTReport:
    """VirusTotal enrichment (high level)."""
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    reputation: Optional[int] = None
    tags: Optional[List[str]] = None


@dataclass
class ScanResult:
    """
    Complete PE analysis result following the Hybrid Engine pattern.

    Fast data (sync): hashes, metadata, sections, imports
    Slow data (async): capabilities, strings, yara_matches
    """
    file_path: str
    hashes: Dict[str, str]
    metadata: PEMetadata
    sections: List[SectionInfo]
    imports: List[ImportInfo]
    capabilities: Optional[List[Capability]] = None  # Phase 2 (capa)
    strings: Optional[List[StringFinding]] = None  # Phase 2 (floss)
    yara_matches: Optional[List[YaraMatch]] = None  # YARA detections
    vt_report: Optional[VTReport] = None  # VirusTotal enrichment
    vt_status: Optional[str] = None  # VT lookup status ("ok", "not_found", etc.)

    def to_json(self) -> str:
        """
        Serialize to JSON string.

        Returns:
            Indented JSON representation of the scan result
        """
        return json.dumps(asdict(self), indent=2)

    def get_suspicious_sections(self) -> List[SectionInfo]:
        """Get all sections flagged as suspicious."""
        return [s for s in self.sections if s.is_suspicious()]

    def get_suspicious_imports(self) -> List[ImportInfo]:
        """Get all import DLLs with suspicious APIs."""
        return [i for i in self.imports if i.is_suspicious()]

    def has_suspicious_indicators(self) -> bool:
        """Check if any suspicious indicators are present."""
        return bool(self.get_suspicious_sections() or self.get_suspicious_imports())

    def categorize_capabilities(self) -> Dict[str, List[Capability]]:
        """Group capabilities by high-level category."""
        if not self.capabilities:
            return {}

        categories = defaultdict(list)

        for cap in self.capabilities:
            namespace = cap.namespace.lower()

            # Map namespaces to friendly categories
            if "file" in namespace or "filesystem" in namespace:
                categories["File System"].append(cap)
            elif "process" in namespace or "thread" in namespace:
                categories["Process Control"].append(cap)
            elif "registry" in namespace:
                categories["Registry"].append(cap)
            elif "network" in namespace or "socket" in namespace or "http" in namespace:
                categories["Network"].append(cap)
            elif "crypto" in namespace or "encoding" in namespace or "hash" in namespace:
                categories["Encoding/Crypto"].append(cap)
            elif "anti" in namespace or "debug" in namespace or "evasion" in namespace:
                categories["Anti-Analysis"].append(cap)
            elif "persistence" in namespace or "startup" in namespace:
                categories["Persistence"].append(cap)
            elif "inject" in namespace or "shellcode" in namespace:
                categories["Code Injection"].append(cap)
            elif "keylog" in namespace or "screen" in namespace or "clipboard" in namespace:
                categories["Data Collection"].append(cap)
            elif "pe" in namespace or "load" in namespace:
                categories["PE Manipulation"].append(cap)
            else:
                categories["Other"].append(cap)

        return dict(categories)

    def detect_anomalies(self) -> List[Anomaly]:
        """Detect anomalies in the PE file."""
        anomalies = []

        # Check for fake timestamp
        if self.metadata.has_fake_timestamp():
            compile_time = self.metadata.compile_time
            anomalies.append(Anomaly(
                severity="medium",
                category="timestamp",
                description=f"Suspicious compilation timestamp: {compile_time}",
                emoji="📅"
            ))

        # Check for high entropy sections. Encrypted or compressed *code* is
        # the packing signal; compressed resources and lookup tables in data
        # sections are common in ordinary software, so they rank lower.
        for section in self.sections:
            if section.entropy > 7.5:
                anomalies.append(Anomaly(
                    severity="high" if "X" in section.characteristics else "medium",
                    category="entropy",
                    description=f"Section '{section.name}' has very high entropy ({section.entropy:.2f}) - possible packing/encryption",
                    emoji="🔒"
                ))
            elif section.entropy > 7.0 and "X" in section.characteristics:
                anomalies.append(Anomaly(
                    severity="medium",
                    category="entropy",
                    description=f"Executable section '{section.name}' has high entropy ({section.entropy:.2f})",
                    emoji="⚠️"
                ))

        # Check for W+X sections
        for section in self.sections:
            if "W" in section.characteristics and "X" in section.characteristics:
                anomalies.append(Anomaly(
                    severity="high",
                    category="section",
                    description=f"Section '{section.name}' is both writable and executable (W+X)",
                    emoji="🚨"
                ))

        # Process-injection imports: one anomaly per file. A DLL can appear
        # in the import table more than once (Delphi programs list kernel32
        # several times), and each entry used to count separately.
        injection_funcs = list(dict.fromkeys(
            f for imp in self.imports for f in imp.functions if is_injection_api(f)
        ))
        if injection_funcs:
            shown = ", ".join(injection_funcs[:5])
            more = f" (+{len(injection_funcs) - 5} more)" if len(injection_funcs) > 5 else ""
            anomalies.append(Anomaly(
                severity="medium",
                category="import",
                description=f"Imports process-injection APIs: {shown}{more}",
                emoji="🔧"
            ))

        # Check for anti-debugging capabilities
        if self.capabilities:
            anti_debug_caps = [cap for cap in self.capabilities
                               if "anti-debug" in cap.namespace.lower() or "anti-analysis" in cap.namespace.lower()]
            if anti_debug_caps:
                anomalies.append(Anomaly(
                    severity="high",
                    category="capability",
                    description=f"Detected {len(anti_debug_caps)} anti-debugging/anti-analysis techniques",
                    emoji="🛡️"
                ))

        return anomalies

    def assess_risk(self) -> RiskAssessment:
        """Calculate overall risk assessment with improved YARA-weighted scoring."""
        anomalies = self.detect_anomalies()
        score = 0

        # PRIORITY 1: YARA matches (HIGHEST confidence - 40-60 points)
        malware_matches = []
        if self.yara_matches:
            kinds = [(yara_match_kind(m), m) for m in self.yara_matches]
            malware_matches = [m for kind, m in kinds if kind == "malware"]
            packer_matches = [m for kind, m in kinds if kind == "packer"]
            exploit_matches = [m for kind, m in kinds if kind == "exploit"]

            if malware_matches:
                score += 60  # Direct malware family match = very high confidence
                anomalies.append(Anomaly(
                    severity="high",
                    category="yara",
                    description=f"YARA detected malware family: {malware_matches[0].rule_name}",
                    emoji="🚨"
                ))
            if exploit_matches:
                score += 40  # Exploit kit detection
            if packer_matches:
                score += 20  # Packed executable (suspicious but not proof)

        # PRIORITY 2: Capability-based scoring (MEDIUM confidence - 10-25 points)
        if self.capabilities:
            categories = self.categorize_capabilities()
            if "Code Injection" in categories:
                score += 25
            if "Anti-Analysis" in categories:
                score += 20
            if "Persistence" in categories:
                score += 15
            if "Network" in categories:
                score += 10

        # PRIORITY 3: Anomalies (LOW-MEDIUM confidence - 5-30 points)
        severity_scores = {"low": 5, "medium": 15, "high": 30}
        for anomaly in anomalies:
            score += severity_scores.get(anomaly.severity, 0)

        # PRIORITY 4: Basic indicators (LOWEST confidence - 5-10 points)
        if self.get_suspicious_sections():
            score += 10
        if self.get_suspicious_imports():
            score += 10

        # Cap score at 100
        score = min(score, 100)

        # Determine risk level with YARA-aware thresholds
        if malware_matches:
            # If YARA directly identified malware, always HIGH or CRITICAL
            risk_level = "CRITICAL" if score >= 60 else "HIGH"
            summary = f"YARA identified as malware: {malware_matches[0].rule_name}"
        elif score < 20:
            risk_level = "LOW"
            summary = "Few or no suspicious indicators"
        elif score < 50:
            risk_level = "MEDIUM"
            summary = "Some suspicious indicators - worth a closer look"
        elif score < 75:
            risk_level = "HIGH"
            summary = "Several suspicious indicators - prioritise for analysis"
        else:
            risk_level = "CRITICAL"
            summary = "Strong suspicious indicators - treat as hostile until analysed"

        return RiskAssessment(
            risk_level=risk_level,
            score=score,
            anomalies=anomalies,
            summary=summary
        )
