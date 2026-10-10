# Sloth Security Suite: Expansion Plan

**Goal:** Transform "Sloth Static Analysis" from a dedicated PE file analyzer into a comprehensive "Security Workbench" by adding dynamic web scanning and vulnerability lookup capabilities (The "Sentry" features).

## Phase 1: Core Logic Implementation (The "Brain")
We will create a new module `malview/web.py` to handle the dynamic analysis logic. This keeps the code clean and separate from the PE analysis engine.

**New Dependencies:**
- `requests` (for HTTP headers)
- `nvdlib` (for CVE lookups)

**New File:** `malview/web.py`
- `check_security_headers(url)`: Fetches URL and grades headers (HSTS, CSP, X-Frame-Options).
- `check_cve(keyword)`: Queries NVD for recent vulnerabilities related to a product (e.g., "nginx 1.18").

## Phase 2: CLI Integration (The "Terminal")
Before breaking the TUI, we enable these features in the CLI.

**Update:** `cli.py`
- Add `--scan-url <URL>` argument.
- Add `--cve-lookup <PRODUCT>` argument.
- Reuse the existing `rich` console output style for beautiful reports.

## Phase 3: TUI Integration (The "Dashboard")
We will upgrade `tui.py` to support multiple "Modes".

**Update:** `tui.py`
- **Navigation:** Add a `ModeSwitcher` (Tabs or Sidebar) to switch between "File Analysis" and "Web Scanner".
- **New Screen:** `WebScanScreen`.
    - Input box for URL.
    - `DataTable` for Header results (Green/Red indicators).
    - `ListView` for CVE matches.

## Phase 4: "Vibe" Polish
- Add "Cyberpunk" styling to the TUI (neon borders, pulsing text for "Scanning...").
- Add a "Risk Score" that combines static and dynamic findings if applicable.

## Action Plan
1. [ ] Install new requirements.
2. [ ] Create `malview/web.py`.
3. [ ] Update `cli.py` to test the new module.
4. [ ] Build the `WebScanScreen` in `tui.py`.
