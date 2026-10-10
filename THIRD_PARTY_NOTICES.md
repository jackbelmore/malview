# Third-party notices

malview's own code is MIT-licensed (see `LICENSE`). It uses, but does not
include, the following.

## Rule sets (downloaded by `scripts/fetch-rules.sh`, not distributed here)

| Rule set | Pinned commit | Licence |
|---|---|---|
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | `0f93570194a80d2f2032869055808b0ddcdfb360` | GPL-2.0 |
| [mandiant/capa-rules](https://github.com/mandiant/capa-rules) v9.4.0 | `2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80` | Apache-2.0 |

The rules are fetched into the gitignored `rules/` directory on your machine
and stay under their own licences. Earlier revisions of this repository
copied the Yara-Rules files in; that history was rewritten before
publication so the repository contains no third-party rules.

## Python dependencies (installed from PyPI)

| Package | Licence |
|---|---|
| [textual](https://github.com/Textualize/textual), [rich](https://github.com/Textualize/rich) | MIT |
| [pefile](https://github.com/erocarrera/pefile) | MIT |
| [yara-python](https://github.com/VirusTotal/yara-python) | Apache-2.0 |
| [flare-capa](https://github.com/mandiant/capa), [flare-floss](https://github.com/mandiant/flare-floss) (optional) | Apache-2.0 |
