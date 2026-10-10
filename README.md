# malview

Static triage for Windows PE files: a CLI and a terminal UI that combine
pefile, YARA, and Mandiant's capa and FLOSS into one report, with a heuristic
risk score that tells you where to look first.

It was built to speed up the first pass on a suspicious executable: hashes,
headers, sections, imports, rule matches and decoded strings in one place,
without running the sample.

<!-- TODO(user): add a screenshot of the TUI, e.g. docs/tui.png -->

## What it reports

**Fast pass** (pure Python, under a second for typical files):

- MD5 / SHA-1 / SHA-256, architecture, DLL/EXE, entry point, compile time (UTC)
- Sections with Shannon entropy and R/W/X flags; W+X sections and
  high-entropy executable sections are flagged
- Import table, flagging APIs commonly used for injection, loading,
  persistence, networking and anti-debugging (including their `A`/`W` variants)
- Anomalies: implausible timestamps, packing indicators, suspicious imports
- **YARA** matches against [Yara-Rules](https://github.com/Yara-Rules/rules),
  grouped by category
- A 0–100 **risk score** (LOW / MEDIUM / HIGH / CRITICAL)

**Slow pass** (`--async`, optional tools):

- **capa** capabilities (anti-analysis, injection, persistence, network, ...),
  with a file-scope fallback if full analysis times out
- **FLOSS** decoded and stack strings

**Optional enrichment:**

- `--vt`: VirusTotal detections for the file's hash (hash lookup only, nothing
  is uploaded)
- `--proc-events` (Windows): recent process-creation events whose parent is the
  analysed binary, from Sysmon or the Security log. `sysmon-minimal.xml` is a
  minimal Sysmon config that logs process creation.

## Example

From a synthetic PE built by the test suite: one high-entropy W+X section
named `UPX1` and injection-style imports.

```text
🚨 RISK ASSESSMENT
--------------------------------------------------------------------------------
  Overall Risk: CRITICAL (Score: 100/100)
  File shows severe malicious indicators - high confidence malware

  3 Suspicious Indicators Found:
    🔒 Section 'UPX1' has very high entropy (7.98) - possible packing/encryption
    🚨 Section 'UPX1' is both writable and executable (W+X)
    🔧 KERNEL32.dll imports suspicious APIs: VirtualAlloc, LoadLibraryA, GetProcAddress

🎯 YARA DETECTIONS
--------------------------------------------------------------------------------
  10 YARA rule(s) matched:
    📦 [malware/MALW_PE_sections] suspicious_packer_section
        The packer/protector section names/keywords
    📦 [packers/packer] PENinja
    ℹ️ [packers/packer_compiler_signatures] IsPE32
    ...
```

## Install

Python 3.11+.

```bash
git clone https://github.com/jackbelmore/malview.git
cd malview
python3 -m venv venv && . venv/bin/activate     # Windows: py -3 -m venv venv; .\venv\Scripts\activate
pip install -r requirements.txt

# YARA and capa rules (pinned commits, into the gitignored rules/ directory)
scripts/fetch-rules.sh

# Optional, for --async (large; may need a C toolchain if no wheel is available)
pip install -r requirements-optional.txt
```

On Windows without bash, fetch the rules by hand at the commits listed in
`scripts/fetch-rules.sh` into `rules\yara` and `rules\capa`, or point
`MALVIEW_YARA_RULES` / `MALVIEW_CAPA_RULES` at existing copies.

> **Analyse samples in a disposable VM or container.** malview never executes
> the sample, but the parsers it relies on see hostile input. See
> [SECURITY.md](SECURITY.md).

## Usage

```bash
python cli.py sample.exe                 # summary with risk assessment
python cli.py sample.exe -v              # full detail: every section, import, rule
python cli.py sample.exe --json | jq .   # machine-readable; diagnostics go to stderr
python cli.py sample.exe --async         # add capa + FLOSS
VT_API_KEY=... python cli.py sample.exe --vt

python tui.py [directory]                # browse and analyse; q quits, r refreshes
./run analyze 'C:\path\to\file.exe'      # WSL: Windows paths are converted
```

| Setting | Default | Purpose |
|---|---|---|
| `--yara-rules DIR` / `MALVIEW_YARA_RULES` | `rules/yara/` | YARA rules directory (`--no-yara` to skip) |
| `MALVIEW_CAPA_RULES` | `rules/capa/` | capa rules; if absent, capa uses its built-in rules |
| `VT_API_KEY` | unset | VirusTotal API key for `--vt` |
| `--fast-capa` | off | shorter capa/FLOSS timeouts, no fallback |

Only regular files up to 256 MiB are analysed (`PEEngine(max_file_size=...)`
to change it).

## How the risk score works

The score adds up weighted signals, capped at 100:

| Signal | Points |
|---|---|
| YARA rule in the malware category | +60, and the level is at least HIGH |
| YARA exploit / CVE rule | +40 |
| YARA packer rule | +20 |
| capa: injection / anti-analysis / persistence / network | +25 / +20 / +15 / +10 |
| Each anomaly (high / medium / low) | +30 / +15 / +5 |
| Any suspicious section; any suspicious import | +10 each |

YARA matches that describe a file rather than flag it (Yara-Rules' `PECheck`
rules such as `IsPE32`, and PEiD compiler signatures) are shown but not
scored. Otherwise every ordinary MSVC binary would look suspicious. It's a
triage aid: a high score means "look here first", not a verdict.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest        # 104 tests, no network, no samples needed
ruff check .
```

The tests build minimal PE32 files in memory (`tests/pe_builder.py`) with
chosen sections, permissions, entropy and imports, so the repository contains
no binaries. They cover parsing, scoring, malformed and truncated input,
FIFOs and oversized files, YARA loading, the VirusTotal client (mocked), CLI
output, and the TUI rendering hostile file, section and DLL names headlessly.
CI runs them on Python 3.11–3.13, along with ruff, shellcheck and a gitleaks
scan of the full history.

## Layout

```
cli.py                  CLI entry point
tui.py                  Textual TUI
malview/
  engine.py             PE analysis (fast pass) and async orchestration
  models.py             result types, anomaly detection, risk scoring
  yara_scanner.py       rule loading and matching
  tools.py              capa / FLOSS wrappers
  vt_client.py          VirusTotal hash lookup
  proc_events.py        Windows process-creation events via PowerShell
  progress.py, utils.py
scripts/fetch-rules.sh  pinned rule download
tests/                  pytest suite and synthetic PE builder
docs/design/            original planning documents
```

## Limitations and roadmap

- The TUI shows Overview, Sections and Imports. YARA, capa and FLOSS results
  are in the CLI only for now, and the TUI analyses on the UI thread.
- PE only: MSI, archives and documents aren't unpacked. To analyse an MSI,
  extract it first (`msiextract`) and point malview at the PEs inside.
- Planned but not implemented: an HTTP security-header check and NVD CVE
  lookup ("Sentry", see `docs/design/`).

## How this was built

<!-- TODO(user): confirm and edit this section. The repo's history doesn't
record how AI tools were used for the original Dec 2025 – Jan 2026 build, so
the first bullet needs your account of it. -->

- **Original tool (Dec 2025 – Jan 2026):** TODO: describe how you built it,
  and which AI tools (if any) helped with which parts. The specs in
  `docs/design/` are from this period.
- **Preparing it for publication (Oct 2026):** done with Claude Code (Claude
  Opus 5.5). Every commit from that pass carries a `Co-Authored-By: Claude`
  trailer. That pass:
  - rewrote history to remove vendored third-party rules and an accidentally
    committed Ghidra project
  - fixed bugs found while writing tests:
    - suspicious-API detection missed `A`/`W` variants
    - YARA namespaces never triggered malware scoring, and index files
      doubled matches
    - informational rules inflated scores
    - `--proc-events` crashed
    - `--json` output was polluted by log lines
    - the TUI didn't start on current Textual, and could be crashed by
      markup in DLL or section names
  - added input hardening, pinned rule downloads, the test suite and CI

## License

MIT for malview's own code (see [LICENSE](LICENSE)). The rule sets it
downloads keep their own licences (Yara-Rules: GPL-2.0; capa-rules:
Apache-2.0); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
