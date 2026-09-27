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
	mkdir -p "$dst/.github/workflows" "$dst/scripts"
	cp -R "$repo/go.mod" "$repo/go.sum" "$repo/cmd" "$repo/internal" "$dst/"
	cp "$repo/.github/workflows/ci.yml" "$dst/.github/workflows/"
	cp "$repo/scripts/ci-local.sh" "$dst/scripts/"
	echo "$dst"
}

# add_direct <dir> <module>: require <module> at its newest version as a
# direct (not // indirect) requirement, without importing it.
add_direct() {
	local dir="$1" mod="$2" ver
	ver="$(cd "$dir" && go list -m -f '{{.Version}}' "$mod@latest")"
	(cd "$dir" && go get "$mod@$ver" >/dev/null 2>&1)
	sed -i "s#^\(\t$mod $ver\) // indirect#\1#" "$dir/go.mod"
	if ! grep -q -P "^\t\Q$mod $ver\E$" "$dir/go.mod"; then
		echo "FAIL could not add $mod $ver as a direct requirement"
		exit 1
	fi
}

# 1. The repository as committed passes; a next major that has only
#    pre-releases (go.yaml.in/yaml/v4 at the time of writing) is info only.
current="$(copy current)"
expect "current repository passes" 0 "all current" "$current"
expect "next-major pre-releases are info only" 0 "info — next major has only pre-releases: go.yaml.in/yaml/v4" "$current"

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

# 5. A direct /vN requirement whose /vN+1 has a stable release fails, even
#    when it is on the newest release of its own major.
major="$(copy major)"
add_direct "$major" github.com/golang-jwt/jwt/v4
expect "stable next major (/vN+1) fails" 1 "github.com/golang-jwt/jwt/v4 has a stable next major: github.com/golang-jwt/jwt/v5" "$major"

# 6. A direct v0/v1 requirement whose /v2 has a stable release fails.
major2="$(copy major2)"
add_direct "$major2" github.com/urfave/cli
expect "stable /v2 of a v1 module fails" 1 "github.com/urfave/cli has a stable next major: github.com/urfave/cli/v2" "$major2"

# 7. A golangci-lint pin older than its newest stable release fails.
oldlint="$(copy oldlint)"
sed -i 's/^\(  GOLANGCI_LINT_VERSION: \).*/\1v2.13.2/' "$oldlint/.github/workflows/ci.yml"
sed -i 's#golangci/golangci-lint:v[0-9.]*@#golangci/golangci-lint:v2.13.2@#' "$oldlint/scripts/ci-local.sh"
expect "old golangci-lint pin fails" 1 "golangci-lint v2.13.2 is older than the newest stable" "$oldlint"

# 8. A govulncheck pin older than its newest stable release fails.
oldvuln="$(copy oldvuln)"
sed -i 's/^\(  GOVULNCHECK_VERSION: \).*/\1v1.1.4/' "$oldvuln/.github/workflows/ci.yml"
sed -i 's/^govulncheck_version="v[0-9.]*"/govulncheck_version="v1.1.4"/' "$oldvuln/scripts/ci-local.sh"
expect "old govulncheck pin fails" 1 "govulncheck v1.1.4 is older than the newest stable" "$oldvuln"

# 9. The two files pinning a tool must agree.
drift="$(copy drift)"
sed -i 's/^govulncheck_version="v[0-9.]*"/govulncheck_version="v1.1.4"/' "$drift/scripts/ci-local.sh"
expect "tool pin drift between files fails" 1 "govulncheck is pinned differently" "$drift"

echo "deps-current tests: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
