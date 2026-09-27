#!/usr/bin/env bash
# Proves deps-current.sh cannot pass vacuously: on a scratch copy of the
# module it must fail when a real go.mod requirement is behind its newest
# release, and when the go line is behind the newest stable Go. Needs go,
# curl and network access to the module proxy.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
check="$repo/scripts/deps-current.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
fail=0
expect() { # expect <name> <want-exit> <want-substring> <dir>
	local name="$1" want="$2" needle="$3" dir="$4" out code=0
	out="$(DEPS_CURRENT_DIR="$dir" bash "$check" 2>&1)" || code=$?
	if [[ "$code" == "$want" ]] && grep -q -F -- "$needle" <<<"$out"; then
		echo "ok   $name"
		pass=$((pass + 1))
	else
		echo "FAIL $name (exit $code, want $want; looking for: $needle)"
		sed 's/^/     /' <<<"$out"
		fail=$((fail + 1))
	fi
}

copy() {
	local dst="$work/$1"
	mkdir -p "$dst"
	cp -R "$repo/go.mod" "$repo/go.sum" "$repo/cmd" "$repo/internal" "$dst/"
	echo "$dst"
}

# 1. The repository as committed passes.
expect "current repository passes" 0 "all current" "$(copy current)"

# 2. A direct go.mod requirement one release behind fails and is named.
behind="$(copy behind)"
mod="go.yaml.in/yaml/v3"
prev="$(cd "$behind" && go list -m -versions "$mod" | tr ' ' '\n' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | tail -n2 | head -n1)"
(cd "$behind" && go get "$mod@$prev" >/dev/null 2>&1)
if ! grep -q -F "$mod $prev" "$behind/go.mod"; then
	echo "FAIL could not downgrade $mod to $prev in the scratch copy"
	exit 1
fi
expect "requirement behind fails" 1 "$mod $prev ->" "$behind"

# 3. An indirect go.mod requirement behind fails too.
indirect="$(copy indirect)"
imod="golang.org/x/sync"
iprev="$(cd "$indirect" && go list -m -versions "$imod" | tr ' ' '\n' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | tail -n2 | head -n1)"
(cd "$indirect" && go get "$imod@$iprev" >/dev/null 2>&1)
expect "indirect requirement behind fails" 1 "$imod $iprev ->" "$indirect"

# 4. A go line older than the newest stable Go fails.
oldgo="$(copy oldgo)"
(cd "$oldgo" && go mod edit -go=1.26.0 -toolchain=none)
expect "old go line fails" 1 "go.mod 'go 1.26.0' is older" "$oldgo"

echo "deps-current tests: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
