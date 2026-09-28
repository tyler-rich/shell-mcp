#!/usr/bin/env bash
# ci-local: run the CI gate locally inside digest-pinned Linux containers, as a
# non-root user, so Linux-only code (gate, helper) is built, vetted, linted and
# tested on Linux even from a Windows workstation. Works from Git Bash on
# Windows and from bash on Linux. Needs docker; nothing else on the host.
#
#   bash scripts/ci-local.sh          # everything
#   CI_LOCAL_SKIP_PROBES=1 bash …     # skip the Landlock / systemd probes
set -euo pipefail

# Git Bash would rewrite /container/paths into C:/… paths; docker needs them raw.
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")/.."
# Windows-style path for docker under Git Bash, plain path elsewhere.
repo="$({ pwd -W 2>/dev/null || pwd; })"

# --- Pinned images -----------------------------------------------------------
# The Go image is read from the Dockerfile's builder stage, so Dependabot's
# docker updates move CI-local, CI and the image build together.
go_image="$(awk 'toupper($1) == "FROM" && $2 ~ /^golang:/ { print $2; exit }' Dockerfile)"
# golangci-lint: keep in step with `version:` in .github/workflows/ci.yml.
lint_image="golangci/golangci-lint:v2.14.0@sha256:ad862ba6b3798cbe0fd9fd7408d498fd74fbd2623a92406b2fd3898faf0bf98f"
# govulncheck runs from its module at a pinned version (verified by the Go
# checksum database); keep in step with ci.yml.
govulncheck_version="v1.8.0"

if [[ "$go_image" != *@sha256:* ]]; then
	echo "ci-local: the Dockerfile's golang builder image is not pinned by digest" >&2
	exit 1
fi

# --- Container user and caches ----------------------------------------------
# Never root. On Linux use the invoking user (so the bind-mounted checkout is
# readable); on Windows, Docker Desktop's bind mounts are readable by any uid.
if [[ "$(uname -s)" == Linux ]] && [[ "$(id -u)" != 0 ]]; then
	run_as="$(id -u):$(id -g)"
else
	run_as="65532:65532"
fi
cache_volume="shell-mcp-ci-cache"
docker volume create "$cache_volume" >/dev/null
docker run --rm -u 0:0 -v "$cache_volume:/cache" "$go_image" \
	sh -c "mkdir -p /cache/build /cache/mod /cache/lint /cache/tmp && chown -R $run_as /cache && chmod 0700 /cache/tmp" >/dev/null

common=(
	--rm -u "$run_as"
	-e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod
	-e GOLANGCI_LINT_CACHE=/cache/lint -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local
	# The gate refuses fixtures whose parent directories are group/other-writable,
	# so tests need a private TMPDIR (the default /tmp is world-writable); with
	# SHELL_MCP_REQUIRE_SECURE_TMP set they fail rather than skip without one.
	# (The MPTCP tests skip here: Docker Desktop's kernel has no MPTCP, so
	# their control case cannot run; CI requires them.)
	-e TMPDIR=/cache/tmp -e SHELL_MCP_REQUIRE_SECURE_TMP=1
	-v "$cache_volume:/cache" -v "$repo:/src:ro" -w /src
)
in_go() { docker run "${common[@]}" "$go_image" "$@"; }
in_lint() { docker run "${common[@]}" "$lint_image" "$@"; }

# --- Steps ----------------------------------------------------------------------
names=()
results=()
notes=()
overall=0

step() { # step <name> <note-on-failure> <command…>
	local name="$1" note="$2"
	shift 2
	echo
	echo "=== $name"
	local code=0
	"$@" || code=$?
	names+=("$name")
	if [[ $code -eq 0 ]]; then
		results+=("PASS")
		notes+=("")
	else
		results+=("FAIL")
		notes+=("exit $code${note:+; $note}")
		overall=1
	fi
}

probe() { # probe <name> <command…>: informational, never fails the run
	local name="$1"
	shift
	echo
	echo "=== $name"
	local out code=0
	out="$("$@" 2>&1)" || code=$?
	echo "$out"
	names+=("$name")
	if [[ $code -eq 0 ]]; then results+=("YES"); else results+=("NO"); fi
	notes+=("$(tail -n1 <<<"$out" | cut -c1-90)")
}

gofmt_check() {
	local out
	out="$(in_go gofmt -l .)"
	if [[ -n "$out" ]]; then
		echo "gofmt: files need formatting:"
		echo "$out"
		return 1
	fi
	echo "gofmt: clean"
}

cross_build() { # cross_build <goarch>
	in_go sh -c "set -e; for c in shell-mcp shell-mcp-gate shell-mcp-privd; do
		CGO_ENABLED=0 GOOS=linux GOARCH=$1 go build -trimpath -ldflags '-s -w' -o /tmp/\$c ./cmd/\$c
		# The gate relies on CGO_ENABLED=0 (psx then uses syscall.AllThreadsSyscall).
		go version -m /tmp/\$c | grep -q 'CGO_ENABLED=0' || { echo \"\$c was built with cgo\" >&2; exit 1; }
		echo \"built \$c linux/$1 (CGO_ENABLED=0)\"
	done"
}

step "gofmt" "" gofmt_check
step "go vet" "" in_go go vet ./...
step "golangci-lint" "" in_lint golangci-lint run ./...
step "go test -race" "" in_go go test -race -count=1 ./...
step "govulncheck" "" in_go go run "golang.org/x/vuln/cmd/govulncheck@$govulncheck_version" ./...
step "build linux/amd64" "" cross_build amd64
step "build linux/arm64" "" cross_build arm64
step "deps-current" "run go get -u ./... && go mod tidy, or bump go.mod's go line" in_go bash scripts/deps-current.sh
step "deps-current self-test" "" in_go bash scripts/deps-current_test.sh

if [[ -z "${CI_LOCAL_SKIP_PROBES:-}" ]]; then
	probe "Landlock in test container" in_go go run ./scripts/probe/landlock
	probe "systemd container (unprivileged)" bash scripts/probe/systemd.sh
fi

# --- Summary ----------------------------------------------------------------------
echo
echo "=== Summary ($go_image)"
printf '| %-34s | %-6s | %s\n' "Check" "Result" "Notes"
printf '|%s|%s|%s\n' "------------------------------------" "--------" "------"
for i in "${!names[@]}"; do
	printf '| %-34s | %-6s | %s\n' "${names[$i]}" "${results[$i]}" "${notes[$i]}"
done
exit "$overall"
