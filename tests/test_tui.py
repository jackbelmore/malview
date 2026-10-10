"""Headless TUI tests: untrusted names from a sample must render as text."""

import asyncio

import pytest

from pe_builder import TEXT

pytest.importorskip("textual")

from textual.widgets import DataTable, Static  # noqa: E402

import tui  # noqa: E402

HOSTILE = "[/bold][@click=app.quit]x"


@pytest.fixture
def hostile_pe(make_pe):
    # Markup in the file name, a section name and a DLL name. (pefile drops
    # import *function* names containing brackets, but DLL and section names
    # come through as-is.)
    return make_pe(
        name="[i]evil.exe",
        sections=[("[/b]", TEXT, b"\x00" * 0x200)],
        imports={HOSTILE + ".dll": ["CreateProcessW"]},
    )


def _run(app, action, check=lambda app: None):
    """Drive the app headlessly; `check` runs while widgets are still mounted."""
    async def go():
        async with app.run_test() as pilot:
            action(app)
            await pilot.pause()
            check(app)
    asyncio.run(go())


def test_hostile_names_do_not_break_rendering(hostile_pe, tmp_path, monkeypatch):
    monkeypatch.setenv("MALVIEW_YARA_RULES", str(tmp_path))  # empty: no rules
    seen = {}

    def check(app):
        seen["overview"] = str(app.query_one("#overview-content", Static).render())
        seen["imports"] = str(app.query_one("#imports-content", Static).render())
        seen["section"] = str(app.query_one("#sections-table", DataTable).get_row_at(0)[0])

    # Before the fix this raised MarkupError out of run_test().
    _run(tui.MalwareAnalysisTUI(start_path=str(tmp_path)),
         lambda a: a.analyze_file(hostile_pe), check)

    assert "[i]evil.exe" in seen["overview"]
    assert HOSTILE + ".dll" in seen["imports"]
    assert "CreateProcessW" in seen["imports"]
    assert seen["section"] == "[/b]"


def test_non_pe_selection_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("MALVIEW_YARA_RULES", str(tmp_path))
    bad = tmp_path / "[b]broken.exe"
    bad.write_text("not a PE")
    app = tui.MalwareAnalysisTUI(start_path=str(tmp_path))
    _run(app, lambda a: a.analyze_file(str(bad)))  # must not raise
