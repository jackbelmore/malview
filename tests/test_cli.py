import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_cli(*args, env_extra=None):
    env = {k: v for k, v in os.environ.items()
           if k not in {"VT_API_KEY", "MALVIEW_YARA_RULES", "MALVIEW_CAPA_RULES"}}
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(ROOT / "cli.py"), *args],
        capture_output=True, text=True, timeout=60, env=env, cwd=ROOT,
    )


def test_json_stdout_is_pure_json(suspicious_pe, tmp_path):
    # Regression: rule-loading messages used to be printed to stdout, which
    # made `cli.py sample.exe --json | jq` fail.
    rules = tmp_path / "rules" / "malware"
    rules.mkdir(parents=True)
    (rules / "r.yar").write_text("rule Never { condition: false }")

    proc = run_cli(suspicious_pe, "--json", "--yara-rules", str(rules.parent))
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["metadata"]["architecture"] == "x86"
    assert "Loaded 1 YARA rule files" in proc.stderr


def test_human_report(suspicious_pe):
    proc = run_cli(suspicious_pe, "--no-yara")
    assert proc.returncode == 0, proc.stderr
    assert "RISK ASSESSMENT" in proc.stdout
    assert "CreateProcessW" in proc.stdout or "VirtualAlloc" in proc.stdout


def test_verbose_report(suspicious_pe):
    proc = run_cli(suspicious_pe, "--no-yara", "-v")
    assert proc.returncode == 0, proc.stderr
    assert ".packed" in proc.stdout


def test_bad_input_exits_nonzero(tmp_path):
    bad = tmp_path / "x.exe"
    bad.write_text("nope")
    proc = run_cli(str(bad), "--no-yara")
    assert proc.returncode == 1
    assert "Invalid PE" in proc.stderr


def test_vt_without_key_warns(suspicious_pe):
    proc = run_cli(suspicious_pe, "--no-yara", "--vt")
    assert proc.returncode == 0
    assert "VT_API_KEY not set" in proc.stderr


def test_proc_events_does_not_crash(suspicious_pe):
    # Regression: cli.py used Path without importing it, so --proc-events
    # died with NameError. On non-Windows hosts PowerShell is absent and the
    # section should report that instead.
    proc = run_cli(suspicious_pe, "--no-yara", "--proc-events")
    assert proc.returncode == 0, proc.stderr
    assert "PROCESS CREATION EVENTS" in proc.stdout
