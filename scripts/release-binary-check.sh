#!/usr/bin/env bash
# release-binary-check: fail unless every binary given is a release build.
# CI and ci-local run it on the cross-built binaries, and CI on the image's.
#   - CGO_ENABLED=0: the gate and the helper rely on it (psx is then
#     syscall.AllThreadsSyscall).
#   - Not the helper's e2e bypass build (shellmcp_e2e_bypass).
#   - Not the server's elicitation diagnostic build (shellmcp_diag).
#   - Not the Landlock forced-psx test build (landlock_forcepsx): neither in
#     the build settings nor in the code, whose errors name the tag.
#
#   bash scripts/release-binary-check.sh BINARY...
# Needs go (for go version -m). release-binary-check_test.sh is its test.
set -euo pipefail

if [[ $# -eq 0 ]]; then
	echo "usage: $0 BINARY..." >&2
	exit 2
fi
status=0
for bin in "$@"; do
	if ! info="$(go version -m "$bin" 2>&1)"; then
		echo "$bin: not a Go binary: $info" >&2
		status=1
		continue
	fi
	if ! grep -q 'CGO_ENABLED=0' <<<"$info"; then
		echo "$bin was built with cgo" >&2
		status=1
	fi
	for tag in shellmcp_e2e_bypass shellmcp_diag landlock_forcepsx; do
		if grep -q "$tag" <<<"$info"; then
			echo "$bin was built with the $tag tag" >&2
			status=1
		fi
	done
	if grep -aq landlock_forcepsx "$bin"; then
		echo "$bin contains the landlock_forcepsx test build" >&2
		status=1
	fi
	if [[ $status -eq 0 ]]; then
		echo "release build: $bin"
	fi
done
exit "$status"
