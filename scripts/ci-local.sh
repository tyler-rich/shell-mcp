#!/usr/bin/env bash
# ci-local: run the CI gate locally inside digest-pinned Linux containers, as a
# non-root user, so Linux-only code (gate, helper) is built, vetted, linted and
# tested on Linux even from a Windows workstation. Works from Git Bash on
# Windows and from bash on Linux. Needs docker; nothing else on the host.
#
#   bash scripts/ci-local.sh          # the full gate: run it before every push
#   bash scripts/ci-local.sh --quick  # gofmt, vet, lint, go test -race and
#                                     # doccheck only, for iterating: NOT the
#                                     # full gate, never reported as ci-local passing
#   CI_LOCAL_SKIP_PROBES=1 bash …     # skip the Landlock / systemd probes
set -euo pipefail

quick=""
for arg in "$@"; do
	case "$arg" in
	--quick) quick=1 ;;
	*)
		echo "ci-local: unknown argument $arg (usage: ci-local.sh [--quick])" >&2
		exit 2
		;;
	esac
done
quick_notice="QUICK MODE: this is NOT the full gate. Do not report it as ci-local passing; run bash scripts/ci-local.sh (no flags) before every push and PR."
if [[ -n "$quick" ]]; then
	echo "ci-local: $quick_notice"
fi

# Git Bash would rewrite /container/paths into C:/… paths; docker needs them raw.
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")/.."
# Windows-style path for docker under Git Bash, plain path elsewhere.
repo="$({ pwd -W 2>/dev/null || pwd; })"

# --- Pinned image and tools ----------------------------------------------------
# The Go image is read from the Dockerfile's builder stage, so Dependabot's
# docker updates move CI-local, CI and the image build together.
go_image="$(awk 'toupper($1) == "FROM" { for (i = 2; i <= NF; i++) if ($i ~ /^golang:/) { print $i; exit } }' Dockerfile)"
# golangci-lint, govulncheck and actionlint run from their modules at pinned versions,
# built by `go run` in the Go image above and verified by their go.sum and
# the Go checksum database; keep them in step with GOLANGCI_LINT_VERSION and
# GOVULNCHECK_VERSION (and ACTIONLINT_VERSION) in ci.yml. Building golangci-lint with the Go image means
# the Go that loads this module for linting is always the Go the tests use: a
# prebuilt golangci-lint image bundles its own Go, and with GOTOOLCHAIN=local
# that Go cannot load the module once go.mod's go line moves past it.
# deps-current checks the pins and that the lint step runs this way.
golangci_lint_version="v2.15.0"
govulncheck_version="v1.9.0"
actionlint_version="v1.7.12"

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
# ends, however it ends. An interrupt stops every lane and ends the run
# instead of failing one step and going on. The systemd probe labels its
# container the same way.
run_label="shell-mcp.ci-local=$(date +%s)-$$-$RANDOM"
export SHELL_MCP_CI_LOCAL_LABEL="$run_label"
# This run's own TMPDIR on the shared cache volume (below), a directory per
# lane. It is removed when the run ends, however it ends, before the run's
# containers are.
run_tmp="/cache/tmp/${run_label#*=}"
tmp_made=""
# Each step's result, one file per lane (lanes run in subshells).
results_dir="$(mktemp -d)"
lane_pids=()
stop_lanes() {
	local p
	for p in "${lane_pids[@]}"; do
		kill -TERM "$p" 2>/dev/null || true
	done
}
remove_own_containers() {
	local ids
	stop_lanes
	if [[ -n "$tmp_made" ]]; then
		docker run --rm --label "$run_label" -u 0:0 -v "$cache_volume:/cache" "$go_image" rm -rf "$run_tmp" >/dev/null 2>&1 || true
	fi
	ids="$(docker ps -aq --filter "label=$run_label" 2>/dev/null || true)"
	if [[ -n "$ids" ]]; then
		# shellcheck disable=SC2086 # one container id per word
		docker rm -f $ids >/dev/null 2>&1 || true
	fi
	rm -rf "$results_dir"
}
trap remove_own_containers EXIT
trap 'echo "ci-local: interrupted" >&2; stop_lanes; exit 130' INT TERM

# --- Lanes, their users and caches ---------------------------------------------
# The steps run in three lanes: go (vet, lint, the tests, the builds),
# network (the self-tests and checks that mostly wait on the network) and
# containers (exposure, setup-check, caddy-check). Two groups run at once:
# go and then network, beside containers. (All three at once showed a
# failure of TestExecMemoryLimit on the first runs, so the go lane's tests
# share the machine only with the containers lane: ARCHIVE §14.)
# CI_LOCAL_SERIAL=1 runs the lanes one after another, as before.
#
# Never root. Each lane has its own uid, caches and TMPDIR: RLIMIT_NPROC
# counts every task of a uid on the kernel, and the gate gives its
# children a limit of a few tasks, so a lane's processes must not share a
# uid with the go lane's tests; nor may any lane be 65532, the uid the
# server image and caddy-check run as in the containers lane (ARCHIVE §14).
# On Windows Docker Desktop's bind mounts are readable by any uid. On Linux
# every lane runs as the invoking user (so the bind-mounted checkout is
# readable), and so one lane at a time; CI_LOCAL_FIXED_UIDS=1 gives the
# lanes their own uids there too, for a checkout other users can read.
if [[ "$(uname -s)" == Linux ]] && [[ "$(id -u)" != 0 ]] && [[ -z "${CI_LOCAL_FIXED_UIDS:-}" ]]; then
	go_as="$(id -u):$(id -g)"
	network_as="$go_as"
	containers_as="$go_as"
	parallel=""
	echo "ci-local: on Linux every lane runs as $go_as, so one lane at a time (CI_LOCAL_FIXED_UIDS=1 for a lane uid each)"
else
	go_as="65530:65530"
	network_as="65531:65531"
	containers_as="65533:65533"
	parallel=1
fi
if [[ -n "${CI_LOCAL_SERIAL:-}" ]]; then
	parallel=""
fi
# CI_LOCAL_CACHE_VOLUME: another volume, such as a new one for a run with
# empty Go caches (the scripts of the containers lane use it too).
cache_volume="${CI_LOCAL_CACHE_VOLUME:-shell-mcp-ci-cache}"
export CI_LOCAL_CACHE_VOLUME="$cache_volume"
docker volume create "$cache_volume" >/dev/null
# The caches belong to their lane's user. /cache/tmp holds every run's
# TMPDIR, so nothing under it is chowned recursively: chown(2) moves the
# change time of every file it touches, even to the same owner, and the
# helper's and the gate's tests refuse a file whose change time moved
# between two checks, so a second run starting meanwhile would fail the
# first one's tests. /cache/tmp stays root's, 0755; each run gets its own
# 0755 directory under it, and each lane a 0700 directory in that.
tmp_made=1
docker run --rm --label "$run_label" -u 0:0 -v "$cache_volume:/cache" "$go_image" \
	sh -c "mkdir -p /cache/build /cache/mod /cache/lint /cache/lane-network/build /cache/lane-network/mod /cache/lane-network/lint /cache/lane-containers/build /cache/lane-containers/mod /cache/tmp &&
		chown -R $go_as /cache/build /cache/mod /cache/lint && chown -R $network_as /cache/lane-network && chown -R $containers_as /cache/lane-containers &&
		chown $go_as /cache && chown 0:0 /cache/tmp && chmod 0755 /cache/tmp && mkdir -m 0755 $run_tmp &&
		mkdir -m 0700 $run_tmp/go $run_tmp/network $run_tmp/containers &&
		chown $go_as $run_tmp/go && chown $network_as $run_tmp/network && chown $containers_as $run_tmp/containers" >/dev/null

# in_go <command…>: in the Go image as the current lane's user, with its
# caches and TMPDIR.
lane=main
in_go() {
	local as cache tmp
	case "$lane" in
	network) as="$network_as" cache=/cache/lane-network tmp="$run_tmp/network" ;;
	containers) as="$containers_as" cache=/cache/lane-containers tmp="$run_tmp/containers" ;;
	*) as="$go_as" cache=/cache tmp="$run_tmp/go" ;;
	esac
	# The gate refuses fixtures whose parent directories are group/other-writable,
	# so tests need a private TMPDIR (the default /tmp is world-writable); with
	# SHELL_MCP_REQUIRE_SECURE_TMP set they fail rather than skip without one.
	# (The MPTCP tests skip here: Docker Desktop's kernel has no MPTCP, so
	# their control case cannot run; CI requires them.)
	docker run --rm --label "$run_label" -u "$as" \
		-e HOME=/tmp -e GOCACHE="$cache/build" -e GOMODCACHE="$cache/mod" \
		-e GOLANGCI_LINT_CACHE="$cache/lint" -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local \
		-e TMPDIR="$tmp" -e SHELL_MCP_REQUIRE_SECURE_TMP=1 \
		-v "$cache_volume:/cache" -v "$repo:/src:ro" -w /src "$go_image" "$@"
}
in_lint() { in_go go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$golangci_lint_version" "$@"; }

# --- Steps ----------------------------------------------------------------------
exec 3>&1
# record <name> <result> <time> <note>: one summary row, in the lane's file.
record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$results_dir/$lane.tsv"; }
# progress <line>: to the terminal while lanes run at once (their output
# goes to their logs, printed when they finish).
progress() { if [[ -n "$parallel" ]]; then echo "ci-local [$lane] $*" >&3; fi; }

step() { # step <name> <note-on-failure> <command…>
	local name="$1" note="$2"
	shift 2
	echo
	echo "=== $name"
	progress "start $name"
	local code=0 t0=$SECONDS
	"$@" || code=$?
	local t=$((SECONDS - t0))
	if [[ $code -eq 0 ]]; then
		record "$name" "PASS" "${t}s" ""
		progress "PASS  $name (${t}s)"
	else
		record "$name" "FAIL" "${t}s" "exit $code${note:+; $note}"
		progress "FAIL  $name (${t}s)"
	fi
}

# lane_end: the lane's last row, so a lane that ended early is a failure.
lane_end() { record "-" "END" "-" ""; }

# not_run <name> <why>: a check this run does not run, never reported as passed.
not_run() { record "$1" "NOT RUN" "-" "$2"; }

# full step|probe <name> …: a step of the full gate only; NOT RUN in quick mode.
full() {
	if [[ -n "$quick" ]]; then
		not_run "$2" "quick mode: not the full gate"
	else
		"$@"
	fi
}

probe() { # probe <name> <command…>: informational, never fails the run
	local name="$1"
	shift
	echo
	echo "=== $name"
	local out code=0 t0=$SECONDS
	out="$("$@" 2>&1)" || code=$?
	echo "$out"
	local r=YES
	if [[ $code -ne 0 ]]; then r=NO; fi
	record "$name" "$r" "$((SECONDS - t0))s" "$(tail -n1 <<<"$out" | cut -c1-90)"
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

# The release build (scripts/release/build.sh) as the release workflow runs
# it, twice: every file must be byte-identical between the two (unsigned; the
# workflow signs). The commit and its time are read here, on the host.
release_snapshot() {
	local commit epoch
	commit="$(git rev-parse HEAD)"
	epoch="$(git log -1 --format=%ct HEAD)"
	in_go env SOURCE_DATE_EPOCH="$epoch" bash -c 'set -e
		v="0.0.0-dryrun.${1:0:7}"
		bash scripts/release/build.sh "$v" "$1" /tmp/release-a >/dev/null
		bash scripts/release/build.sh "$v" "$1" /tmp/release-b >/dev/null
		(cd /tmp/release-a && sha256sum -- *) >/tmp/a.sums
		(cd /tmp/release-b && sha256sum -- *) | diff /tmp/a.sums -
		cat /tmp/a.sums
		echo "release snapshot: $(wc -l </tmp/a.sums) files, identical in two builds"' _ "$commit"
}

# The offline exposure check (handoff N-28): the generated core units rated by
# systemd-analyze security --offline in the systemd of Debian 13, Ubuntu 24.04
# and 26.04, against scripts/exposure/scores.txt; and its negative control, a
# unit with the ProtectHome=yes of N-28 undone, which must be refused.
exposure_weakened_fails() {
	local out
	out="$(mktemp)"
	if EXPOSURE_WEAKEN='e2e:s/^ProtectHome=yes$/ProtectHome=read-only/' bash scripts/exposure/run.sh >"$out" 2>&1; then
		cat "$out"
		rm -f "$out"
		echo "exposure: a weakened unit passed the check"
		return 1
	fi
	grep -h FAIL "$out"
	rm -f "$out"
	echo "exposure: the weakened unit was refused, as it must be"
}

lane_go() {
	lane=go
	step "gofmt" "" gofmt_check
	step "go vet" "" in_go go vet ./...
	step "go vet (test-only build tags)" "" in_go sh -c "go vet -tags e2e ./test/e2e/ && go vet -tags shellmcp_e2e_bypass ./internal/privd/... ./cmd/shell-mcp-privd/ && go vet -tags shellmcp_diag ./cmd/shell-mcp/ ./internal/tools/ && go vet -tags landlock_forcepsx ./... && go vet -tags shellmcp_gitconfig_hook ./internal/gate/... ./cmd/shell-mcp-gate/ && go vet -tags shellmcp_confine_hook ./internal/gate/... ./internal/privd/... ./cmd/shell-mcp-gate/ ./cmd/shell-mcp-privd/"
	step "golangci-lint" "" in_lint run ./...
	step "golangci-lint (test-only build tags)" "" in_lint run --build-tags=e2e,shellmcp_e2e_bypass,shellmcp_diag,landlock_forcepsx,shellmcp_gitconfig_hook,shellmcp_confine_hook ./...
	step "go test -race" "" in_go go test -race -timeout 20m -count=1 ./...
	# The Landlock forced-psx test build, which CI's psx entry runs, for the
	# packages that apply the sandbox (the helper's unit tests stub it). This
	# kernel is below ABI 8 anyway; it proves the forced code enforces here.
	full step "go test -race (forcepsx: gate)" "" in_go env SHELL_MCP_EXPECT_LANDLOCK_PATH=psx go test -race -timeout 20m -count=1 -tags landlock_forcepsx ./internal/gate/... ./cmd/shell-mcp-gate/
	full step "go test -race (test build, fsx)" "" in_go go test -race -timeout 20m -count=1 -tags shellmcp_e2e_bypass ./internal/gate/fsx/
	# The gate's git-configuration hook build (handoff N-20), as CI runs it.
	full step "go test -race (git config hook build)" "" in_go go test -race -timeout 20m -count=1 -tags shellmcp_gitconfig_hook -run 'TestGitConfigChangedAfterCheck|TestProductionOptionsHaveNoGitConfigHook' ./internal/gate/ops/
	# fsx's read-confinement hook build (handoff N-12), as CI runs it.
	full step "go test -race (read-confinement hook build)" "" in_go go test -race -timeout 20m -count=1 -tags shellmcp_confine_hook -run 'TestConfineLayers' ./internal/gate/fsx/
	full step "e2e runner-only guards" "" in_go sh -c "CGO_ENABLED=0 go test -c -trimpath -tags e2e -o /tmp/e2e.test ./test/e2e && E2E_TEST_BIN=/tmp/e2e.test bash test/e2e/guard_test.sh"
	full step "go test -race (diagnostic build, server)" "" in_go sh -c "go test -race -timeout 20m -count=1 -tags shellmcp_diag ./cmd/shell-mcp/ ./internal/tools/ && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -tags shellmcp_diag -o /tmp/shell-mcp-diag.exe ./cmd/shell-mcp"
	full step "govulncheck" "" in_go go run "golang.org/x/vuln/cmd/govulncheck@$govulncheck_version" ./...
	full step "build linux/amd64" "" cross_build amd64
	full step "build linux/arm64" "" cross_build arm64
	full step "release snapshot build (twice)" "" release_snapshot
	lane_end
}

lane_network() {
	lane=network
	# The workflows (G2), as the deps-current job runs it (.github/actionlint.yaml).
	full step "actionlint" "" in_go go run "github.com/rhysd/actionlint/cmd/actionlint@$actionlint_version"
	step "doc links and section references" "" in_go go run ./scripts/doccheck
	full step "release scripts self-test" "" in_go bash scripts/release/release_test.sh
	full step "verify-release self-test" "" in_go bash scripts/verify-release_test.sh
	full step "deps-current" "run go get -u ./... && go mod tidy, or bump go.mod's go line" in_go bash scripts/deps-current.sh
	full step "deps-current self-test" "" in_go bash scripts/deps-current_test.sh
	full step "release-binary-check self-test" "" in_go bash scripts/release-binary-check_test.sh
	full step "e2e shards self-test" "" in_go bash test/e2e/shards_test.sh
	# The ci-local test runs this script against a fake docker; not from itself.
	if [[ -z "${CI_LOCAL_UNDER_TEST:-}" ]]; then
		full step "ci-local self-test" "" in_go bash scripts/ci-local_test.sh
	fi
	lane_end
}

lane_containers() {
	lane=containers
	# The scripts below run their own containers: as this lane's user, with
	# this lane's caches.
	export SHELL_MCP_CI_RUN_AS="$containers_as" SHELL_MCP_CI_CACHE=/cache/lane-containers
	full step "exposure (offline, systemd 255/257/259)" "" bash scripts/exposure/run.sh
	full step "exposure self-test (weakened unit)" "" exposure_weakened_fails
	# The setup check (handoff §3.8): install, host-key and privd install on
	# Debian 13, Ubuntu 24.04 and 26.04 containers run as their own root,
	# unprivileged (handoff §7 Q2; the only containers of this run that are not
	# a non-root user), and execx's credential tests as the Go image's root.
	# Labelled like every other container here. Its own assertions need real
	# containers, so the ci-local self-test (a fake docker) leaves it out.
	if [[ -z "${CI_LOCAL_UNDER_TEST:-}" ]]; then
		full step "setup-check (Debian 13, Ubuntu 24.04, 26.04)" "" bash scripts/setup-check/run.sh
	fi
	# deploy/caddy/Caddyfile against the reference compose, and caddy validate in
	# a test-only pinned image (no network, read-only, no capabilities, non-root;
	# handoff §4.G). Real containers, so the self-test (a fake docker) leaves it out.
	if [[ -z "${CI_LOCAL_UNDER_TEST:-}" ]]; then
		full step "caddy-check (deploy/caddy)" "" bash scripts/caddy-check/run.sh
	fi
	lane_end
}

lanes=(go network containers)
# The groups that run at once, each its lanes in order.
groups=("go network" "containers")
if [[ -n "$parallel" ]]; then
	echo "ci-local: lanes go then network, beside containers (CI_LOCAL_SERIAL=1 for one at a time); each group's output follows when it ends"
	for g in "${groups[@]}"; do
		(for l in $g; do "lane_$l"; done) >"$results_dir/${g// /-}.log" 2>&1 &
		lane_pids+=("$!")
	done
	for p in "${lane_pids[@]}"; do
		wait "$p" || true # a lane's failures are its steps' rows
	done
	lane_pids=()
	for g in "${groups[@]}"; do
		echo
		echo "##### lanes: $g"
		cat "$results_dir/${g// /-}.log"
	done
else
	for l in "${lanes[@]}"; do
		"lane_$l"
	done
fi
lane=main

if [[ -z "${CI_LOCAL_SKIP_PROBES:-}" ]]; then
	full probe "Landlock in test container" in_go go run ./scripts/probe/landlock
	full probe "systemd container (unprivileged)" bash scripts/probe/systemd.sh
fi

# --- What only CI runs ------------------------------------------------------------
# Checks CI runs that this run cannot: reported as NOT RUN, never as passed.
not_run "e2e-host (every e2e test)" "runner VM only: the e2e-host shards and e2e-host-coverage (init's bind form among them)"
not_run "gitleaks" "CI only (the gitleaks job)"
not_run "image build, Trivy, Grype" "CI only (the image job)"
not_run "CodeQL (go, actions)" "CI only (the codeql workflow)"
not_run "MPTCP tests" "skip on a kernel without MPTCP (Docker Desktop's); CI requires them"
not_run "Landlock tests above this ABI" "skip above this kernel's Landlock ABI; CI requires ABI 7 and 8"

# --- Summary ----------------------------------------------------------------------
# Every lane's rows, in lane order. Each lane's last row is an end marker:
# a lane that ended early (killed, or a crash) is a failed run.
overall=0
echo
echo "=== Summary ($go_image)${quick:+ — QUICK MODE, NOT the full gate}"
printf '| %-34s | %-7s | %6s | %s\n' "Check" "Result" "Time" "Notes"
printf '|%s|%s|%s|%s\n' "------------------------------------" "---------" "--------" "------"
for l in "${lanes[@]}" main; do
	ended=""
	if [[ -f "$results_dir/$l.tsv" ]]; then
		while IFS=$'\t' read -r name result t note; do
			if [[ "$result" == END ]]; then
				ended=1
				continue
			fi
			printf '| %-34s | %-7s | %6s | %s\n' "$name" "$result" "$t" "$note"
			if [[ "$result" == FAIL ]]; then overall=1; fi
		done <"$results_dir/$l.tsv"
	fi
	if [[ "$l" != main && -z "$ended" ]]; then
		printf '| %-34s | %-7s | %6s | %s\n' "lane $l" "FAIL" "-" "ended before its last step"
		overall=1
	fi
done
echo "wall time: $((SECONDS / 60))m$((SECONDS % 60))s${parallel:+ (lanes at once)}"
if [[ -n "$quick" ]]; then
	echo "ci-local: $quick_notice"
fi
exit "$overall"
