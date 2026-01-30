# Sloth Security Suite: Integration Design

**Goal:** Merge "Sentry" (Web/CVE) into "Sloth" (PE Analysis) to create a Unified Security Workbench.

## 1. User Interaction (The "Dual Mode" Concept)

We will use **Subcommands** for the CLI and a **Sidebar/Tab Switcher** for the TUI.

### CLI Usage
Old way: `python cli.py malware.exe` (Implicitly PE mode)
New way: `python cli.py <command> [arguments]`

- **PE Analysis (Legacy compatible):**
  `python cli.py pe malware.exe`
  (We will keep `python cli.py malware.exe` working by checking if the first arg is a file, for backward compatibility).

- **Web Scanner (New):**
  `python cli.py web https://google.com`
  `python cli.py web --headers https://google.com`

- **CVE Lookup (New):**
  `python cli.py cve "nginx 1.18"`

### TUI Usage
The TUI (`python tui.py`) will become a dashboard.
- **Left Sidebar:** A permanent "Mode Switcher" (replacing the file tree being always visible).
    - [📂 PE Analyzer] -> Shows the File Tree & Analysis Tabs.
    - [🌐 Sentry Web] -> Shows URL Input & Scan Results.
    - [🔍 CVE Search] -> Shows Search Bar & Vulnerability List.

## 2. Architecture Changes

### A. Module Structure
We need to keep `pefile` logic separate from `requests` logic.

```
malview/
├── __init__.py
├── engine.py          # Existing PE Engine
├── web.py             # NEW: Web Analysis Engine (Sentry)
├── cve.py             # NEW: CVE Lookup Engine (Sentry)
├── models.py          # Update to include WebScanResult
└── ...
```

### B. CLI Refactor (`cli.py`)
We will use `argparse` with `add_subparsers`.

```python
parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command")

# PE Subparser
pe_parser = subparsers.add_parser("pe", help="Analyze PE file")
pe_parser.add_argument("file_path")

# Web Subparser
web_parser = subparsers.add_parser("web", help="Scan website headers")
web_parser.add_argument("url")
```

### C. TUI Refactor (`tui.py`)
We will introduce a "Main Screen" that holds the Mode Switcher.

```python
class SlothApp(App):
    def compose(self):
        yield Header()
        yield Horizontal(
            # Mode Switcher (Sidebar)
            Vertical(
                Button("PE Analyzer", id="btn-pe"),
                Button("Web Scanner", id="btn-web"),
                id="sidebar"
            ),
            # Content Area (Switched via 'ContentSwitcher')
            ContentSwitcher(
                PEAnalysisScreen(id="screen-pe"),
                WebScanScreen(id="screen-web"),
                initial="screen-pe"
            )
        )
```

## 3. Implementation Plan
1.  **Dependencies:** Add `requests` and `nvdlib` to `requirements.txt`.
2.  **Backend:** Implement `malview/web.py` (Header checks) and `malview/cve.py`.
3.  **CLI:** Update `cli.py` to support `pe`, `web`, and `cve` commands.
4.  **TUI:** Create the `WebScanScreen` widget and integrate the `ContentSwitcher`.

## 4. "Vibe" Enhancements
- **Web Scanner:** Use green/red ASCII art for header status (✅/❌).
- **CVE Search:** Use a table with "Criticality" color-coded (Red for Critical, Yellow for Medium).
