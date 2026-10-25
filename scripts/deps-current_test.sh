#!/usr/bin/env bash
# Proves deps-current.sh cannot pass vacuously: on a scratch copy of the
# module it must fail when a real go.mod requirement is behind its newest
# release, when the go line is behind the newest stable Go, when a CI tool pin
# is behind or drifts, and when ci-local's golangci-lint runs on a Go older than
# go.mod's go line; and that the Go check follows the published golang image
# (deps-current-go.sh, against a fake go.dev and registry, offline). Needs go,
# curl and network access to the module proxy for the other cases.
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

# setup_failed <what>: a scratch copy could not be prepared; counts as a
# failure (never a vacuous pass) and the remaining cases still run.
setup_failed() {
	echo "FAIL $1"
	fail=$((fail + 1))
}

copy() {
	local dst="$work/$1"
	mkdir -p "$dst"
	mkdir -p "$dst/.github/workflows" "$dst/scripts"
	cp -R "$repo/go.mod" "$repo/go.sum" "$repo/Dockerfile" "$repo/cmd" "$repo/internal" "$dst/"
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
sed -i 's/^golangci_lint_version="v[0-9.]*"/golangci_lint_version="v2.13.2"/' "$oldlint/scripts/ci-local.sh"
if ! grep -q '^golangci_lint_version="v2.13.2"$' "$oldlint/scripts/ci-local.sh"; then
	setup_failed "could not set the golangci-lint pin in the scratch ci-local.sh"
else
	expect "old golangci-lint pin fails" 1 "golangci-lint v2.13.2 is older than the newest stable" "$oldlint"
fi

# 8. A govulncheck pin older than its newest stable release fails.
oldvuln="$(copy oldvuln)"
sed -i 's/^\(  GOVULNCHECK_VERSION: \).*/\1v1.1.4/' "$oldvuln/.github/workflows/ci.yml"
sed -i 's/^govulncheck_version="v[0-9.]*"/govulncheck_version="v1.1.4"/' "$oldvuln/scripts/ci-local.sh"
expect "old govulncheck pin fails" 1 "govulncheck v1.1.4 is older than the newest stable" "$oldvuln"

# 9. The two files pinning a tool must agree.
drift="$(copy drift)"
sed -i 's/^govulncheck_version="v[0-9.]*"/govulncheck_version="v1.1.4"/' "$drift/scripts/ci-local.sh"
expect "tool pin drift between files fails" 1 "govulncheck is pinned differently" "$drift"

# 10. ci-local's lint step runs on the Dockerfile's Go image; a Go there
#     older than go.mod's go line fails (with GOTOOLCHAIN=local it cannot load
#     the module).
oldlintgo="$(copy oldlintgo)"
sed -i 's#^\(FROM .*golang:\)[0-9][0-9.]*-#\11.26.0-#' "$oldlintgo/Dockerfile"
if ! grep -q '^FROM .*golang:1.26.0-' "$oldlintgo/Dockerfile"; then
	setup_failed "could not set the Go image version in the scratch Dockerfile"
else
	expect "lint Go older than go.mod fails" 1 "golangci-lint in scripts/ci-local.sh runs on Go 1.26.0, older than go.mod's go" "$oldlintgo"
fi

# 11. A lint step that runs a prebuilt golangci-lint image (which bundles its
#     own Go) instead of building it in the Go image fails.
lintimage="$(copy lintimage)"
sed -i 's#^in_lint() {.*#in_lint() { docker run "${common[@]}" "golangci/golangci-lint:v2.14.0" golangci-lint "$@"; }#' "$lintimage/scripts/ci-local.sh"
if ! grep -q '^in_lint() { docker run ' "$lintimage/scripts/ci-local.sh"; then
	setup_failed "could not point the scratch ci-local.sh lint step at an image"
else
	expect "lint step outside the Go image fails" 1 "golangci-lint in scripts/ci-local.sh does not run with the Go image's go" "$lintimage"
fi

# --- Go toolchain vs. published golang image (offline) ---------------------------
# deps-current-go.sh runs with a fake curl first on PATH: go.dev and the
# registry are canned responses, so these cases never touch the network. The
# release list mimics go.dev's ?mode=json&include=all layout, including the
# per-file "version" keys, and the versions are invented.
gocheck="$repo/scripts/deps-current-go.sh"
fakebin="$work/fakebin"
mkdir -p "$fakebin"
cat >"$fakebin/curl" <<'FAKE'
#!/usr/bin/env bash
# Fake curl for deps-current_test.sh. FAKE_GO_RELEASES: file served for
# go.dev; FAKE_IMAGES: space-separated golang tags that exist; FAKE_FAIL:
# go|token|manifest makes that request fail like a network error;
# FAKE_MANIFEST_STATUS forces a manifest HTTP status.
set -euo pipefail
url="" write="" headers=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	-w) write="$2"; shift ;;
	-H) if [[ "$2" == "@-" ]]; then headers+="$(cat)"$'\n'; else headers+="$2"$'\n'; fi; shift ;;
	https://*) url="$1" ;;
	esac
	shift
done
case "$url" in
https://go.dev/dl/*)
	[[ "${FAKE_FAIL:-}" == go ]] && { echo "curl: (6) fake resolve failure" >&2; exit 6; }
	cat "$FAKE_GO_RELEASES" ;;
https://auth.docker.io/token\?service=registry.docker.io\&scope=repository:library/golang:pull)
	[[ "${FAKE_FAIL:-}" == token ]] && { echo "curl: (28) fake timeout" >&2; exit 28; }
	printf '{"token":"fake-anon-token","access_token":"fake-anon-token","expires_in":300}\n' ;;
https://registry-1.docker.io/v2/library/golang/manifests/*)
	[[ "${FAKE_FAIL:-}" == manifest ]] && { echo "curl: (7) fake connect failure" >&2; exit 7; }
	tag="${url##*/}" code=404
	if ! grep -q -x -F 'Authorization: Bearer fake-anon-token' <<<"$headers"; then
		code=401
	elif [[ -n "${FAKE_MANIFEST_STATUS:-}" ]]; then
		code="$FAKE_MANIFEST_STATUS"
	elif [[ " ${FAKE_IMAGES:-} " == *" $tag "* ]]; then
		code=200
	fi
	[[ "$write" == '%{http_code}' ]] && printf '%s' "$code" ;;
*) echo "fake curl: unexpected URL $url" >&2; exit 2 ;;
esac
FAKE
chmod +x "$fakebin/curl"

# releases <file> <version:stable>...: write a go.dev-shaped release list.
releases() {
	local file="$1" sep="" v s
	shift
	{
		echo "["
		for e in "$@"; do
			v="${e%%:*}" s="${e##*:}"
			printf '%s {\n  "version": "go%s",\n  "stable": %s,\n  "files": [\n   {\n    "filename": "go%s.src.tar.gz",\n    "version": "go%s",\n    "sha256": "00"\n   }\n  ]\n }' "$sep" "$v" "$s" "$v" "$v"
			sep=$',\n'
		done
		printf '\n]\n'
	} >"$file"
}
releases "$work/rel-new.json" 1.27.3:true 1.27.2:true 1.27.1:true 1.28rc1:false 1.26.10:true
releases "$work/rel-gap.json" 1.27.9:true 1.27.8:true 1.27.7:true 1.27.6:true 1.27.5:true 1.27.4:true 1.27.3:true

# gomod <dir> <go version>: a scratch module with only a go line.
gomod() {
	mkdir -p "$1"
	printf 'module example.test/scratch\n\ngo %s\n' "$2" >"$1/go.mod"
	echo "$1"
}

expect_go() { # expect_go <name> <want-exit> <want-substring> <dir> [VAR=value...]
	local name="$1" want="$2" needle="$3" dir="$4" out code=0
	shift 4
	out="$(env PATH="$fakebin:$PATH" DEPS_CURRENT_DIR="$dir" FAKE_GO_RELEASES="$work/rel-new.json" "$@" bash "$gocheck" 2>&1)" || code=$?
	if [[ "$code" == "$want" ]] && grep -q -F -- "$needle" <<<"$out"; then
		echo "ok   $name"
		pass=$((pass + 1))
	else
		echo "FAIL $name (exit $code, want $want; looking for: $needle)"
		sed 's/^/     /' <<<"$out"
		fail=$((fail + 1))
	fi
}

# 12. The newest stable Go has its image and go.mod is older: fail as before.
expect_go "newer Go with image fails" 1 "go.mod 'go 1.27.2' is older than the newest stable Go 1.27.3" \
	"$(gomod "$work/go-a" 1.27.2)" FAKE_IMAGES="1.27.3-trixie 1.27.2-trixie"
# 13. The newest stable Go has no image yet and go.mod is on the newest Go
#     that has one: pass, and name the Go version awaiting its image.
expect_go "newer Go without image passes" 0 "deps-current: INFO — Go 1.27.3 is released but golang:1.27.3-trixie is not published yet" \
	"$(gomod "$work/go-b" 1.27.2)" FAKE_IMAGES="1.27.2-trixie 1.27.1-trixie"
expect_go "newer Go without image reports the target" 0 "matches Go 1.27.2, the newest stable Go with a published golang:1.27.2-trixie image" \
	"$work/go-b" FAKE_IMAGES="1.27.2-trixie 1.27.1-trixie"
# 14. The registry cannot be queried: fail closed, whichever request breaks.
expect_go "registry token error fails" 1 "deps-current: FAIL — cannot query the registry for golang:1.27.3-trixie" \
	"$(gomod "$work/go-c" 1.27.2)" FAKE_IMAGES="1.27.2-trixie" FAKE_FAIL=token
expect_go "registry manifest error fails" 1 "deps-current: FAIL — cannot query the registry for golang:1.27.3-trixie" \
	"$work/go-c" FAKE_IMAGES="1.27.2-trixie" FAKE_FAIL=manifest
expect_go "unexpected registry status fails" 1 "deps-current: FAIL — cannot query the registry for golang:1.27.3-trixie (HTTP 429)" \
	"$work/go-c" FAKE_IMAGES="1.27.2-trixie" FAKE_MANIFEST_STATUS=429
expect_go "go.dev error fails" 1 "could not determine the newest Go release" \
	"$work/go-c" FAKE_IMAGES="1.27.3-trixie" FAKE_FAIL=go
# 15. go.mod older than the newest Go that has an image: fail.
expect_go "go.mod older than newest Go with image fails" 1 "go.mod 'go 1.27.1' is older than Go 1.27.2, the newest stable Go with a published golang:1.27.2-trixie image" \
	"$(gomod "$work/go-d" 1.27.1)" FAKE_IMAGES="1.27.2-trixie 1.27.1-trixie"
# 16. go.mod on a Go whose image is not published yet: fail (nothing can build it).
expect_go "go.mod ahead of the newest image fails" 1 "go.mod go 1.27.3 is newer than Go 1.27.2, the newest stable Go with a published golang:1.27.2-trixie image" \
	"$(gomod "$work/go-f" 1.27.3)" FAKE_IMAGES="1.27.2-trixie"
# 17. Current: go.mod on the newest stable Go, whose image exists.
expect_go "current Go passes" 0 "go.mod go 1.27.3 (toolchain implied by go line) matches newest stable Go 1.27.3" \
	"$(gomod "$work/go-e" 1.27.3)" FAKE_IMAGES="1.27.3-trixie 1.27.2-trixie"
# 18. The walk back is bounded: no image among the newest releases fails.
expect_go "no image among the newest releases fails" 1 "deps-current: FAIL — none of the 5 newest stable Go releases (1.27.9 … 1.27.5) has a published golang:<version>-trixie image" \
	"$(gomod "$work/go-g" 1.27.3)" FAKE_GO_RELEASES="$work/rel-gap.json" FAKE_IMAGES="1.27.3-trixie"

echo "deps-current tests: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
