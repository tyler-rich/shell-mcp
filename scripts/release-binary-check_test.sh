#!/usr/bin/env bash
# Proves release-binary-check.sh cannot pass vacuously: it must pass the gate
# and the helper built as releases are, and fail each test-only build (cgo,
# the helper's e2e bypass, the server's diagnostic build, the Landlock
# forced-psx build of the gate and of the helper). The forced-psx code must be
# visible in the binary itself, not only in its build settings. Needs go and
# a C compiler (the golang image has both).
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
check="$repo/scripts/release-binary-check.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$repo"

pass=0
fail=0
ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; [[ -z "${2:-}" ]] || sed 's/^/     /' <<<"$2"; fail=$((fail + 1)); }

build() { # build <name> <cgo> <pkg> [go build args…]
	local name="$1" cgo="$2" pkg="$3"
	shift 3
	CGO_ENABLED="$cgo" go build -trimpath -ldflags '-s -w' "$@" -o "$work/$name" "./cmd/$pkg"
}

expect() { # expect <name> <want-exit> <want-substring> <binary>
	local name="$1" want="$2" needle="$3" bin="$work/$4" out code=0
	out="$(bash "$check" "$bin" 2>&1)" || code=$?
	if [[ "$code" == "$want" ]] && grep -q -F -- "$needle" <<<"$out"; then
		ok "$name"
	else
		bad "$name (exit $code, want $want; looking for: $needle)" "$out"
	fi
}

build gate 0 shell-mcp-gate
build privd 0 shell-mcp-privd
build gate-cgo 1 shell-mcp-gate
build privd-bypass 0 shell-mcp-privd -tags shellmcp_e2e_bypass
build server-diag 0 shell-mcp -tags shellmcp_diag
build gate-forcepsx 0 shell-mcp-gate -tags landlock_forcepsx
build privd-forcepsx 0 shell-mcp-privd -tags landlock_forcepsx

expect "release gate passes" 0 "release build: $work/gate" gate
expect "release helper passes" 0 "release build: $work/privd" privd
expect "cgo gate fails" 1 "was built with cgo" gate-cgo
expect "e2e bypass helper fails" 1 "shellmcp_e2e_bypass" privd-bypass
expect "diagnostic server fails" 1 "shellmcp_diag" server-diag
expect "forced-psx gate fails" 1 "landlock_forcepsx" gate-forcepsx
expect "forced-psx helper fails" 1 "landlock_forcepsx" privd-forcepsx

# The forced-psx code itself is in the tagged binaries and not in the release
# ones, so the check holds even without the build settings.
for b in gate-forcepsx privd-forcepsx; do
	if grep -aq 'landlock_forcepsx test build' "$work/$b"; then ok "$b carries the forced-psx code"; else bad "$b carries the forced-psx code"; fi
done
for b in gate privd; do
	if grep -aq landlock_forcepsx "$work/$b"; then bad "$b is free of landlock_forcepsx"; else ok "$b is free of landlock_forcepsx"; fi
done

echo "release-binary-check self-test: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
