import pytest

from malview import PEEngine
from malview.yara_scanner import YaraScanner
from pe_builder import DATA, TEXT

MARKER = b"MALVIEW-TEST-MARKER"


@pytest.fixture
def rules_dir(tmp_path):
    """A small rules tree shaped like Yara-Rules/rules.

    tmp_path itself contains "test_" (pytest names it after the test), which
    also guards against the old filter that skipped any path containing "test".
    """
    root = tmp_path / "rules"
    (root / "malware").mkdir(parents=True)
    (root / "packers").mkdir()
    (root / "deprecated").mkdir()
    (root / "malware" / "MALW_marker.yar").write_text(
        'rule Marker_Family { strings: $a = "MALVIEW-TEST-MARKER" condition: $a }'
    )
    # Same file name in two directories must not overwrite each other.
    (root / "malware" / "common.yar").write_text("rule Common_In_Malware { condition: false }")
    (root / "packers" / "common.yar").write_text("rule Common_In_Packers { condition: false }")
    # Upstream-style index that #includes the rule above: must be skipped,
    # otherwise every match is reported twice.
    (root / "malware_index.yar").write_text('include "./malware/MALW_marker.yar"\n')
    (root / "deprecated" / "old.yar").write_text("rule Deprecated_Always { condition: true }")
    (root / "broken.yar").write_text("rule Broken { condition: this is not yara }")
    return root


@pytest.fixture
def marked_pe(make_pe):
    return make_pe(
        name="marked.exe",
        sections=[(".text", TEXT, b"\x00" * 0x200), (".data", DATA, MARKER + b"\x00" * 64)],
    )


def test_loads_and_matches_once(rules_dir, marked_pe):
    scanner = YaraScanner(str(rules_dir))
    matches = scanner.scan(marked_pe)
    assert [(m.namespace, m.rule_name) for m in matches] == [("malware/MALW_marker", "Marker_Family")]
    assert list(scanner.categorize_matches(matches)) == ["malware"]


def test_no_match_on_clean_file(rules_dir, benign_pe):
    assert YaraScanner(str(rules_dir)).scan(benign_pe) == []


def test_missing_rules_dir_is_not_fatal(tmp_path, benign_pe, capsys):
    scanner = YaraScanner(str(tmp_path / "does-not-exist"))
    assert scanner.rules is None
    assert scanner.scan(benign_pe) == []
    assert "fetch-rules.sh" in capsys.readouterr().err


def test_env_var(monkeypatch, rules_dir, marked_pe):
    monkeypatch.setenv("MALVIEW_YARA_RULES", str(rules_dir))
    assert YaraScanner().scan(marked_pe)


def test_engine_scores_yara_malware_match(rules_dir, marked_pe):
    result = PEEngine(yara_rules_path=str(rules_dir)).analyze(marked_pe)
    assert [m.rule_name for m in result.yara_matches] == ["Marker_Family"]
    risk = result.assess_risk()
    assert risk.risk_level in {"HIGH", "CRITICAL"}
    assert "Marker_Family" in risk.summary
