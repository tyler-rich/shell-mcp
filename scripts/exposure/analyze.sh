#!/usr/bin/env bash
# analyze.sh <image> <scores file> [--record]: runs inside one of the
# exposure images (run.sh), with this repository mounted read-only. Reads a
# tar of generated units (<policy>/shell-mcp-privd@.service, and the broad
# unit when the policy has one) on stdin and rates each with
#   systemd-analyze security --offline=true
# which reads the unit file and needs no PID 1.
#
# For each policy's core unit it compares the score with the one recorded in
# the scores file for this image and policy ("<image> <policy> <score>") and
# fails when it is above it, or when there is no record. A score below the
# record passes with a NOTE: lower the record. The broad unit is
# root-equivalent by design: its score is printed, never enforced. With
# --record, prints the file's lines for the scores measured and exits 0.
set -euo pipefail

image="${1:?usage: analyze.sh <image> <scores file> [--record]}"
scores="${2:?usage: analyze.sh <image> <scores file> [--record]}"
record=""
[[ "${3:-}" == "--record" ]] && record=1

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar -xf - -C "$work"

score_of() { # score_of <unit file>: the overall exposure level, e.g. 1.3
	local out
	out="$(systemd-analyze security --offline=true --no-pager "$1" 2>&1)" || true
	sed -n 's/.*Overall exposure level for [^:]*: \([0-9][0-9]*\.[0-9]\).*/\1/p' <<<"$out" | head -n1
}

echo "exposure: $image: $(systemctl --version | head -n1)"
fail=0
found=0
for dir in "$work"/*/; do
	[[ -d "$dir" ]] || continue
	found=1
	policy="$(basename "$dir")"
	core="$(score_of "$dir/shell-mcp-privd@.service")"
	if [[ -z "$core" ]]; then
		echo "FAIL $image $policy: no exposure level in the output of systemd-analyze"
		fail=1
		continue
	fi
	if [[ -f "$dir/shell-mcp-privd-broad@.service" ]]; then
		echo "info $image $policy: broad unit $(score_of "$dir/shell-mcp-privd-broad@.service") (root-equivalent by design; not enforced)"
	fi
	if [[ -n "$record" ]]; then
		echo "$image $policy $core"
		continue
	fi
	want="$(awk -v i="$image" -v p="$policy" '$1 == i && $2 == p { print $3 }' "$scores")"
	if [[ -z "$want" ]]; then
		echo "FAIL $image $policy: core unit $core, no recorded score in ${scores##*/} (run.sh --record prints the lines)"
		fail=1
	elif awk -v g="$core" -v w="$want" 'BEGIN { exit !(g > w) }'; then
		echo "FAIL $image $policy: core unit $core is worse than the recorded $want"
		fail=1
	elif [[ "$core" != "$want" ]]; then
		echo "NOTE $image $policy: core unit $core is better than the recorded $want; lower the record"
	else
		echo "ok   $image $policy: core unit $core (recorded $want)"
	fi
done
[[ -n "$found" ]] || { echo "FAIL $image: no units on stdin"; exit 1; }
exit "$fail"
