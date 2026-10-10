# Security

malview exists to look at files that are probably malicious, so it treats every
input sample as hostile. This file covers what it does to stay safe, what it
does not protect against, and how to report problems.

## Threat model

**Assets:** the analyst's machine and anything reachable from it (files,
credentials, network), and the analyst's API keys.

**Adversary:** whoever crafted the sample. They control every byte of the file
and its name, and may have built it specifically to break analysis tools.

**Not in scope:** a compromised Python environment, or malicious rule sets
(the rule sets are third-party code-like input; see "Rule sets" below).

## What malview does

- **It never runs the sample.** The fast pass reads bytes, parses headers with
  pefile, hashes and measures entropy, and matches YARA rules. The optional
  slow pass runs `capa` and `floss` as separate processes. Neither executes
  the sample on the host CPU, but FLOSS does *emulate* parts of it (via
  vivisect) to recover decoded strings, and both are large parsers exposed to
  hostile input.
- **External tools get an argument list, not a shell string**, the sample as
  an absolute path (so a file named `-r` can't be read as an option), and a
  timeout after which the process is killed.
- **Only regular files are read, up to a size limit** (256 MiB by default). A
  FIFO or device named `*.exe` in a sample folder would otherwise hang the
  tool, and a huge file is a cheap way to stall it.
- **Malformed input is an error, not a crash.** Anything pefile raises while
  parsing becomes `InvalidPEFileError`; the test suite feeds truncated and
  non-PE files to check this.
- **Names from the sample are treated as text, not markup.** File, section,
  DLL and function names are attacker-controlled. The TUI escapes them, so a
  DLL called `[/bold]x.dll` can't crash it and `[@click=...]` can't become a
  clickable action.
- **Diagnostics go to stderr**, so `--json` output can be piped safely into
  other tools.

## VirusTotal (`--vt`)

- Only the SHA-256 is sent, as a GET lookup of an existing report. The file
  is never uploaded. Anything that isn't a 64-character hex digest is rejected
  before a request is built.
- The API key is read from the `VT_API_KEY` environment variable, sent only
  in the `x-apikey` header, and never written to output or error messages.
- Operational note: a hash lookup still tells VirusTotal, and anyone watching
  that hash through VT's paid intelligence features, that someone is looking
  at it. Leave `--vt` off for samples from incidents where that matters.

## Process events (`--proc-events`, Windows only)

This runs PowerShell `Get-WinEvent` to read Sysmon (Event ID 1) or Security
(4688) process-creation events. The only value interpolated into the
PowerShell script is the look-back window, which argparse has already parsed
as an integer; filtering by parent image name happens in Python afterwards.
Reading the Security log needs administrator rights.

## Rule sets

`scripts/fetch-rules.sh` downloads Yara-Rules and capa-rules at exact commit
hashes and checks the checked-out commit before using it, so a moved tag or a
tampered branch can't silently change what gets loaded. The rules remain
third-party content; review changes before bumping the pins.

## What it does not protect against

- **Bugs in the parsers.** pefile, libyara, capa and vivisect all process
  attacker-controlled bytes. A crafted file could crash them, make them very
  slow, or, in the worst case, exploit a memory-safety bug in native code.
- **Treat the risk score as a triage hint, not a verdict.** It's a heuristic
  over imports, section properties and rule matches. Informational rules
  (PE-property and PEiD compiler signatures) are shown but not scored.

So: **analyse samples in a disposable VM or container**, with no shared
folders you care about and no network unless you use `--vt`. Keep samples in
password-protected archives when they're not being analysed. This repository's
`.gitignore` blocks common binary extensions so samples aren't committed by
accident.

## Supply chain

- Dependencies are pinned to exact versions in `requirements*.txt`.
- CI pins GitHub Actions to full commit SHAs and the gitleaks image to a
  digest, runs with a read-only token, and doesn't persist checkout
  credentials.
- Every push is scanned for secrets with gitleaks across the full history.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository
(Security tab → "Report a vulnerability"), so the details aren't public until
there's a fix. If that isn't available, open an issue saying you have
something to report, without the details.
