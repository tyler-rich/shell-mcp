#!/usr/bin/env bash
# release/notes.sh: print the CHANGELOG section of VERSION, the body of its
# release notes. The section starts at a line "## [VERSION]" (optionally
# followed by " - <date>") and ends before the next "## " line. Fails when
# the file or the section is missing, or the section has no text: a release
# without written notes is refused.
#
#   bash scripts/release/notes.sh VERSION [CHANGELOG]
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
	echo "usage: $0 VERSION [CHANGELOG]" >&2
	exit 2
fi
version="$1"
file="${2:-$(dirname "$0")/../../CHANGELOG.md}"
if [[ ! -f "$file" ]]; then
	echo "release notes: $file does not exist; write the ## [$version] section first" >&2
	exit 1
fi
body="$(awk -v head="## [$version]" '
	index($0, head) == 1 && (length($0) == length(head) || substr($0, length(head) + 1, 3) == " - ") { found = 1; next }
	found && /^## / { exit }
	found { print }
' "$file")"
if ! grep -q '[^[:space:]]' <<<"$body"; then
	echo "release notes: $file has no text under '## [$version]'; write the section first" >&2
	exit 1
fi
# Without the blank lines around the section's text.
printf '%s\n' "$body" | awk '
	{ line[NR] = $0 }
	END {
		s = 1; while (s <= NR && line[s] !~ /[^[:space:]]/) s++
		e = NR; while (e >= s && line[e] !~ /[^[:space:]]/) e--
		for (i = s; i <= e; i++) print line[i]
	}'
