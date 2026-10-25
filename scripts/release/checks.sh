#!/usr/bin/env bash
# release/checks.sh: the commit a release builds must have passed CI and
# CodeQL. For each required check name (ci, analyze (go)), the latest check
# runs on exactly that commit must exist, be completed, and every one of them
# must have concluded success. On main the commit is the dev -> main merge
# commit, which both workflows run on (push to main).
#
#   bash scripts/release/checks.sh REPOSITORY COMMIT
# Needs gh, authenticated with a token that can read checks.
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 OWNER/REPO COMMIT" >&2
	exit 2
fi
repo="$1" commit="$2"
if ! [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
	echo "release checks: commit '$commit' is not a full commit id" >&2
	exit 2
fi

fail=0
for name in "ci" "analyze (go)"; do
	if ! runs="$(gh api -X GET "repos/$repo/commits/$commit/check-runs" -f check_name="$name" -f filter=latest -f per_page=100 \
		--jq '.check_runs[] | "\(.id) \(.status) \(.conclusion)"')"; then
		echo "release checks: FAIL — cannot read the '$name' check runs of $commit" >&2
		fail=1
		continue
	fi
	if [[ -z "$runs" ]]; then
		echo "release checks: FAIL — '$name' never ran on $commit" >&2
		fail=1
		continue
	fi
	bad="$(awk '$2 != "completed" || $3 != "success"' <<<"$runs")"
	if [[ -n "$bad" ]]; then
		echo "release checks: FAIL — '$name' on $commit is not a success (check run id, status, conclusion):" >&2
		sed 's/^/  /' <<<"$bad" >&2
		fail=1
		continue
	fi
	echo "release checks: '$name' succeeded on $commit ($(wc -l <<<"$runs") check run(s))"
done
exit "$fail"
