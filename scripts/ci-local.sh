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

# --- Pinned image and tools ----------------------------------------------------
# The Go image is read from the Dockerfile's builder stage, so Dependabot's
# docker updates move CI-local, CI and the image build together.
go_image="$(awk 'toupper($1) == "FROM" && $2 ~ /^golang:/ { print $2; exit }' Dockerfile)"
# golangci-lint and govulncheck run from their modules at pinned versions,
# built by `go run` in the Go image above and verified by their go.sum and
# the Go checksum database; keep them in step with GOLANGCI_LINT_VERSION and
# GOVULNCHECK_VERSION in ci.yml. Building golangci-lint with the Go image means
# the Go that loads this module for linting is always the Go the tests use: a
# prebuilt golangci-lint image bundles its own Go, and with GOTOOLCHAIN=local
# that Go cannot load the module once go.mod's go line moves past it.
# deps-current checks both pins and that the lint step runs this way.
golangci_lint_version="v2.15.0"
govulncheck_version="v1.9.0"

if [[ "$go_image" != *@sha256:* ]]; then
	echo "ci-local: the Dockerfile's golang builder image is not pinned by digest" >&2
	exit 1
fi

# --- Only our own containers -------------------------------------------------
# Every container this run starts carries run_label, and this script lists,
# stops and removes containers only through it (CLAUDE.md): never by name
# pattern, never all running containers, never prune. `docker run --rm`
# removes a container when it exits, but an interrupted docker client leaves
# its container running, so the labelled containers are removed when the run
# ends, however it ends. An interrupt ends the run instead of failing one
# step and going on. The systemd probe labels its container the same way.
run_label="shell-mcp.ci-local=$(date +%s)-$$-$RANDOM"
export SHELL_MCP_CI_LOCAL_LABEL="$run_label"
# This run's own TMPDIR on the shared cache volume (below). It is removed
# when the run ends, however it ends, before the run's containers are.
run_tmp="/cache/tmp/${run_label#*=}"
tmp_made=""
remove_own_containers() {
	local ids
	if [[ -n "$tmp_made" ]]; then
		docker run --rm --label "$run_label" -u 0:0 -v "$cache_volume:/cache" "$go_image" rm -rf "$run_tmp" >/dev/null 2>&1 || true
	fi
	ids="$(docker ps -aq --filter "label=$run_label" 2>/dev/null || true)"
	if [[ -n "$ids" ]]; then
		# shellcheck disable=SC2086 # one container id per word
		docker rm -f $ids >/dev/null 2>&1 || true
	fi
}
trap remove_own_containers EXIT
trap 'echo "ci-local: interrupted" >&2; exit 130' INT TERM

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
# The caches belong to the container user. /cache/tmp holds every run's
# TMPDIR, so nothing under it is chowned recursively: chown(2) moves the
# change time of every file it touches, even to the same owner, and the
# helper's and the gate's tests refuse a file whose change time moved
# between two checks, so a second run starting meanwhile would fail the
# first one's tests. /cache/tmp stays root's, 0755; each run gets its own
# 0700 directory under it.
tmp_made=1
docker run --rm --label "$run_label" -u 0:0 -v "$cache_volume:/cache" "$go_image" \
	sh -c "mkdir -p /cache/build /cache/mod /cache/lint /cache/tmp && chown -R $run_as /cache/build /cache/mod /cache/lint && chown $run_as /cache && chown 0:0 /cache/tmp && chmod 0755 /cache/tmp && mkdir -m 0700 $run_tmp && chown $run_as $run_tmp" >/dev/null

common=(
	--rm --label "$run_label" -u "$run_as"
	-e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod
	-e GOLANGCI_LINT_CACHE=/cache/lint -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local
	# The gate refuses fixtures whose parent directories are group/other-writable,
	# so tests need a private TMPDIR (the default /tmp is world-writable); with
	# SHELL_MCP_REQUIRE_SECURE_TMP set they fail rather than skip without one.
	# (The MPTCP tests skip here: Docker Desktop's kernel has no MPTCP, so
	# their control case cannot run; CI requires them.)
	-e TMPDIR="$run_tmp" -e SHELL_MCP_REQUIRE_SECURE_TMP=1
	-v "$cache_volume:/cache" -v "$repo:/src:ro" -w /src
)
in_go() { docker run "${common[@]}" "$go_image" "$@"; }
in_lint() { in_go go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$golangci_lint_version" "$@"; }

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
		# CGO_ENABLED=0 (psx then uses syscall.AllThreadsSyscall), and none of
		# the test-only builds (e2e bypass, diagnostic, Landlock forced-psx).
		bash scripts/release-binary-check.sh /tmp/\$c
		echo \"built \$c linux/$1 (CGO_ENABLED=0)\"
	done"
}

step "gofmt" "" gofmt_check
step "go vet" "" in_go go vet ./...
step "go vet (test-only build tags)" "" in_go sh -c "go vet -tags e2e ./test/e2e/ && go vet -tags shellmcp_e2e_bypass ./internal/privd/... ./cmd/shell-mcp-privd/ && go vet -tags shellmcp_diag ./cmd/shell-mcp/ ./internal/tools/ && go vet -tags landlock_forcepsx ./..."
step "golangci-lint" "" in_lint run ./...
step "golangci-lint (test-only build tags)" "" in_lint run --build-tags=e2e,shellmcp_e2e_bypass,shellmcp_diag,landlock_forcepsx ./...
step "go test -race" "" in_go go test -race -timeout 20m -count=1 ./...
# The Landlock forced-psx test build, which CI's psx entry runs, for the
# packages that apply the sandbox (the helper's unit tests stub it). This
# kernel is below ABI 8 anyway; it proves the forced code enforces here.
step "go test -race (forcepsx: gate)" "" in_go env SHELL_MCP_EXPECT_LANDLOCK_PATH=psx go test -race -timeout 20m -count=1 -tags landlock_forcepsx ./internal/gate/... ./cmd/shell-mcp-gate/
step "go test -race (test build, fsx)" "" in_go go test -race -timeout 20m -count=1 -tags shellmcp_e2e_bypass ./internal/gate/fsx/
step "e2e runner-only guards" "" in_go sh -c "CGO_ENABLED=0 go test -c -trimpath -tags e2e -o /tmp/e2e.test ./test/e2e && E2E_TEST_BIN=/tmp/e2e.test bash test/e2e/guard_test.sh"
step "go test -race (diagnostic build, server)" "" in_go sh -c "go test -race -timeout 20m -count=1 -tags shellmcp_diag ./cmd/shell-mcp/ ./internal/tools/ && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -tags shellmcp_diag -o /tmp/shell-mcp-diag.exe ./cmd/shell-mcp"
step "govulncheck" "" in_go go run "golang.org/x/vuln/cmd/govulncheck@$govulncheck_version" ./...
step "build linux/amd64" "" cross_build amd64
step "build linux/arm64" "" cross_build arm64
step "deps-current" "run go get -u ./... && go mod tidy, or bump go.mod's go line" in_go bash scripts/deps-current.sh
step "deps-current self-test" "" in_go bash scripts/deps-current_test.sh
step "release-binary-check self-test" "" in_go bash scripts/release-binary-check_test.sh
# The ci-local test runs this script against a fake docker; not from itself.
if [[ -z "${CI_LOCAL_UNDER_TEST:-}" ]]; then
	step "ci-local self-test" "" in_go bash scripts/ci-local_test.sh
fi

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
