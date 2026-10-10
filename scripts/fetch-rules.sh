#!/usr/bin/env bash
# Fetch the third-party rule sets malview uses into rules/ (gitignored).
#
# Each set is pinned to an exact commit and the checkout is verified against
# it, so a moved tag or a compromised branch can't silently change what gets
# loaded. Bump the commits deliberately.
#
#   scripts/fetch-rules.sh          # YARA + capa rules
#   scripts/fetch-rules.sh yara     # just one of them
set -euo pipefail

# Yara-Rules/rules, master as of 2022-04-12 (the project's last commit). GPL-2.0.
YARA_REPO=https://github.com/Yara-Rules/rules.git
YARA_COMMIT=0f93570194a80d2f2032869055808b0ddcdfb360

# mandiant/capa-rules v9.4.0. Apache-2.0. Keep in step with your flare-capa version.
CAPA_REPO=https://github.com/mandiant/capa-rules.git
CAPA_COMMIT=2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
rules_dir="$root/rules"
tmp=""
trap '[[ -n $tmp ]] && rm -rf "$tmp"' EXIT

fetch() {  # fetch NAME REPO COMMIT
    local name=$1 repo=$2 commit=$3
    local dest="$rules_dir/$name" got

    if [[ -d $dest/.git ]] && [[ $(git -C "$dest" rev-parse HEAD) == "$commit" ]]; then
        echo "$name: already at ${commit:0:12}"
        return
    fi

    # Shallow fetch of exactly one commit into a temp dir, then swap it in.
    tmp="$(mktemp -d "$rules_dir/.$name.XXXXXX")"
    git -C "$tmp" init -q
    git -C "$tmp" fetch -q --depth 1 "$repo" "$commit"
    git -C "$tmp" -c advice.detachedHead=false checkout -q FETCH_HEAD
    got="$(git -C "$tmp" rev-parse HEAD)"
    if [[ $got != "$commit" ]]; then
        echo "$name: expected $commit, got $got" >&2
        exit 1
    fi
    rm -rf "$dest"
    mv "$tmp" "$dest"
    tmp=""
    echo "$name: ${commit:0:12} -> ${dest#"$root"/}"
}

mkdir -p "$rules_dir"
targets=("$@")
[[ ${#targets[@]} -eq 0 ]] && targets=(yara capa)
for t in "${targets[@]}"; do
    case $t in
        yara) fetch yara "$YARA_REPO" "$YARA_COMMIT" ;;
        capa) fetch capa "$CAPA_REPO" "$CAPA_COMMIT" ;;
        *) echo "unknown rule set: $t (expected yara or capa)" >&2; exit 2 ;;
    esac
done
