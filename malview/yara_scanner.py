"""YARA scanner for malware detection."""

import os
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yara

# Where scripts/fetch-rules.sh puts the Yara-Rules collection.
DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "yara"
RULES_ENV_VAR = "MALVIEW_YARA_RULES"


def _log(message: str) -> None:
    # stderr, so that `cli.py --json` keeps stdout as pure JSON.
    print(message, file=sys.stderr)


def default_rules_path() -> Path:
    """$MALVIEW_YARA_RULES if set, else rules/yara/ in the repo."""
    env = os.environ.get(RULES_ENV_VAR)
    return Path(env) if env else DEFAULT_RULES_DIR


@dataclass
class YaraMatch:
    """YARA rule match result."""
    rule_name: str
    namespace: str  # e.g., "malware", "packer", "antidebug"
    tags: List[str]
    meta: dict
    strings: List[tuple]  # Matched strings


class YaraScanner:
    """YARA rule scanner for PE files."""

    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize YARA scanner.

        Args:
            rules_path: Path to a YARA rules directory. If None, uses
                       $MALVIEW_YARA_RULES, then rules/yara/ in the repo.
        """
        self.rules_path = Path(rules_path) if rules_path else default_rules_path()
        self.rules = None
        self._load_rules()

    @staticmethod
    def _wanted(rel: Path) -> bool:
        """Skip deprecated rules and the upstream *index.yar include files.

        The index files #include every rule in their directory, so compiling
        them alongside the individual files reports each match twice.
        """
        return "deprecated" not in rel.parts and "index" not in rel.name.lower()

    def _load_rules(self):
        """Load YARA rules from the rules directory."""
        if not self.rules_path.is_dir():
            _log(
                f"Warning: YARA rules not found at {self.rules_path}. "
                f"Run scripts/fetch-rules.sh or set {RULES_ENV_VAR}; "
                "continuing without YARA."
            )
            return

        # Compile every .yar/.yara file individually so that one broken or
        # unsupported rule doesn't take the whole set down.
        try:
            rule_files = {}
            failed_count = 0

            # Collect all rule files. Filters look at the path *relative to
            # the rules directory*, so where the rules live doesn't matter.
            all_rule_files = []
            for pattern in ("*.yar", "*.yara"):
                for rule_file in self.rules_path.rglob(pattern):
                    if self._wanted(rule_file.relative_to(self.rules_path)):
                        all_rule_files.append(rule_file)

            # Try to compile each file individually
            for rule_file in sorted(all_rule_files):
                # Namespace = path relative to the rules dir, e.g.
                # "malware/MALW_Atmos". The top-level directory is what the
                # risk scoring and categorisation key on, and the full path
                # keeps same-named files in different directories apart.
                namespace = rule_file.relative_to(self.rules_path).with_suffix("").as_posix()
                try:
                    # Test compile this single file
                    yara.compile(filepath=str(rule_file))
                    rule_files[namespace] = str(rule_file)
                except Exception as e:
                    # Skip rules that fail (e.g., require unavailable modules)
                    failed_count += 1
                    if "cuckoo" in str(e) or "sync" in str(e):
                        # These rules require Cuckoo Sandbox integration
                        pass
                    else:
                        _log(f"Skipping {rule_file.name}: {str(e)[:50]}")

            if rule_files:
                # Compile all valid rules together
                self.rules = yara.compile(filepaths=rule_files)
                _log(f"Loaded {len(rule_files)} YARA rule files ({failed_count} skipped)")
            else:
                _log("Warning: No YARA rules could be loaded")

        except Exception as e:
            _log(f"Error loading YARA rules: {e}")
            self.rules = None

    def scan(self, file_path: str) -> List[YaraMatch]:
        """
        Scan a file with YARA rules.

        Args:
            file_path: Path to file to scan

        Returns:
            List of YaraMatch objects for matching rules
        """
        if self.rules is None:
            return []

        noisy_rules = {"PoetRat_Python", "domain"}  # overly chatty rules

        try:
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message=".*too many matches for string.*",
                    category=RuntimeWarning,
                )
                matches = self.rules.match(
                    file_path,
                    timeout=60,
                    externals=None,
                )
        except Exception as e:
            # Ignore known noisy rules warnings; emit others
            msg = str(e)
            if any(name in msg for name in noisy_rules):
                return []
            _log(f"Error scanning with YARA: {e}")
            return []

        results = []

        for match in matches:
            if match.rule in noisy_rules:
                continue

            yara_match = YaraMatch(
                rule_name=match.rule,
                namespace=match.namespace,
                tags=match.tags,
                meta=match.meta,
                strings=[(s.identifier, s.instances) for s in match.strings]
            )
            results.append(yara_match)

        return results

    def categorize_matches(self, matches: List[YaraMatch]) -> dict:
        """
        Categorize YARA matches by type.

        Args:
            matches: List of YaraMatch objects

        Returns:
            Dictionary mapping categories to lists of matches
        """
        categories = {
            "malware": [],
            "packer": [],
            "exploit": [],
            "antidebug": [],
            "capabilities": [],
            "crypto": [],
            "other": []
        }

        for match in matches:
            namespace = match.namespace.lower().split("/")[0]
            rule_name = match.rule_name.lower()

            # Categorize based on namespace and rule name
            if "malware" in namespace or any(x in rule_name for x in ["trojan", "backdoor", "ransomware", "apt"]):
                categories["malware"].append(match)
            elif "packer" in namespace or any(x in rule_name for x in ["upx", "aspack", "themida", "vmprotect"]):
                categories["packer"].append(match)
            elif "exploit" in namespace or "cve" in namespace:
                categories["exploit"].append(match)
            elif "antidebug" in namespace or "antivm" in namespace:
                categories["antidebug"].append(match)
            elif "capabilities" in namespace:
                categories["capabilities"].append(match)
            elif "crypto" in namespace:
                categories["crypto"].append(match)
            else:
                categories["other"].append(match)

        return {k: v for k, v in categories.items() if v}  # Remove empty categories
