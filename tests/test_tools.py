import os

import pytest

from malview import proc_events, tools


def test_capa_rules_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "DEFAULT_CAPA_RULES_DIR", tmp_path / "missing")
    assert tools._capa_rules_dir() is None


def test_capa_rules_empty_dir_ignored(tmp_path, monkeypatch):
    # An empty rules dir (e.g. an uninitialised checkout) must not be passed
    # to capa -r, which would fail with "no rules".
    monkeypatch.setenv("MALVIEW_CAPA_RULES", str(tmp_path))
    assert tools._capa_rules_dir() is None


def test_capa_rules_from_env(tmp_path, monkeypatch):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "rule.yml").write_text("rule: {}\n")
    monkeypatch.setenv("MALVIEW_CAPA_RULES", str(tmp_path))
    assert tools._capa_rules_dir() == tmp_path


def test_sample_arg_cannot_look_like_an_option(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    arg = tools._sample_arg("-r")
    assert os.path.isabs(arg)
    assert not arg.startswith("-")


def test_proc_events_hours_must_be_an_integer(monkeypatch):
    # hours is interpolated into a PowerShell script; anything that isn't an
    # integer must be rejected before PowerShell is ever started.
    monkeypatch.setattr(proc_events, "_run_powershell",
                        lambda script: pytest.fail("PowerShell should not run"))
    with pytest.raises(ValueError):
        proc_events.fetch_process_events("x.exe", hours="1); Remove-Item C:\\ #")
    with pytest.raises(ValueError):
        proc_events.fetch_process_events("x.exe", hours=0)
