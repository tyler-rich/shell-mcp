#!/usr/bin/env bash
# Proves scripts/ci-local.sh touches only containers it started itself: it
# runs ci-local against a fake docker (first on PATH) that logs every call,
# and checks that
#   - every container ci-local starts (its own and the systemd probe's)
#     carries the label shell-mcp.ci-local=<run id>, one id per run;
#   - it never prunes, and never lists, stops, kills or removes a container
#     except through that label (or a part label, below): the fake reports a
#     foreign container to any unfiltered `docker ps`, and it must never be
#     named;
#   - a script it runs (exposure, the systemd probe) removes only its own
#     containers, by its part label: the run's containers, which steps
#     running beside it own, are removed once, when the run ends;
#   - on exit, and when interrupted mid-step, it removes the containers that
#     carry its label.
# Needs bash and setsid (Linux); docker is never called for real.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'FAKE'
#!/usr/bin/env bash
# Fake docker for ci-local_test.sh: logs its argv (one call per line, args
# separated by spaces), answers what ci-local and the systemd probe ask.
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case "$1" in
ps)
	if [[ "$*" == *"--filter label=shell-mcp.ci-local.part="* ]]; then
		echo ctr-part-1
	elif [[ "$*" == *"--filter label=shell-mcp.ci-local="* ]]; then
		echo ctr-ours-1
	else
		echo ctr-foreign-1
	fi
	;;
run)
	if [[ -n "${FAKE_DOCKER_HANG_ON:-}" && "$*" == *"$FAKE_DOCKER_HANG_ON"* ]]; then
		touch "$FAKE_DOCKER_LOG.hanging"
		sleep 60
	fi
	if [[ "$*" == *" -d "* ]]; then echo ctr-probe-1; fi
	;;
exec) echo running ;;
esac
exit 0
FAKE
chmod 0755 "$work/bin/docker"

pass=0
fail=0
ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() {
	echo "FAIL $1"
	[[ -n "${2:-}" ]] && sed 's/^/     /' "$2"
	fail=$((fail + 1))
}

# check_log <name> <log>: the label and cleanup rules for one run's calls.
check_log() {
	local name="$1" log="$2" ids
	if ! grep -q '^run ' "$log"; then
		bad "$name: ci-local started no container (fake docker not used?)" "$log"
		return
	fi
	if grep '^run ' "$log" | grep -v -q -- '--label shell-mcp.ci-local=[^ ]'; then
		bad "$name: a container was started without the run label" <(grep '^run ' "$log" | grep -v -- '--label shell-mcp.ci-local=')
	else
		ok "$name: every container carries the run label"
	fi
	ids="$({ grep -o -- '--label shell-mcp.ci-local=[^ ]*' "$log" || true; } | sort -u | wc -l)"
	if [[ "$ids" -eq 1 ]]; then
		ok "$name: one run id"
	else
		bad "$name: $ids different run ids" "$log"
	fi
	if grep -q -E '(^| )prune( |$)' "$log"; then
		bad "$name: ci-local prunes" "$log"
	else
		ok "$name: nothing is pruned"
	fi
	if grep -q 'ctr-foreign-1' "$log" || grep -E '^(ps|container ls|container list)( |$)' "$log" | grep -v -q -E -- '--filter label=shell-mcp\.ci-local(\.part)?='; then
		bad "$name: a container was listed or named without the run label" "$log"
	else
		ok "$name: containers are listed only by the run label"
	fi
	if grep -E '^(stop|kill|rm|container (stop|kill|rm))( |$)' "$log" | grep -v -q -E 'ctr-ours-1|ctr-part-1|ctr-probe-1|shell-mcp-probe-systemd-'; then
		bad "$name: stopped or removed something it did not start" "$log"
	else
		ok "$name: stops and removes only its own containers"
	fi
}

common_env=(CI_LOCAL_UNDER_TEST=1 PATH="$work/bin:$PATH")

# 1. A complete run: labels throughout, and the labelled containers are
#    removed at exit.
log1="$work/run.log"
: >"$log1"
if env "${common_env[@]}" FAKE_DOCKER_LOG="$log1" bash "$repo/scripts/ci-local.sh" >"$work/run.out" 2>&1; then
	ok "complete run: exit 0 against the fake docker"
else
	bad "complete run: ci-local failed against the fake docker" "$work/run.out"
fi
check_log "complete run" "$log1"
if tail -n 2 "$log1" | grep -q -- '^ps -aq --filter label=shell-mcp.ci-local=' && tail -n 1 "$log1" | grep -q '^rm -f ctr-ours-1$'; then
	ok "complete run: its labelled containers are removed at exit"
else
	bad "complete run: no removal by label at exit" "$log1"
fi
# The run label's containers belong to every step: removed once, at the end,
# never by a script's own cleanup while other lanes' containers run.
n="$(grep -c '^rm -f ctr-ours-1$' "$log1" || true)"
if [[ "$n" -eq 1 ]] && grep -q '^ps -aq --filter label=shell-mcp.ci-local.part=' "$log1"; then
	ok "complete run: scripts remove only their own part; the run's containers once, at the end"
else
	bad "complete run: the run's containers removed $n times (want 1, at the end); part-label cleanup: $(grep -c -- '--filter label=shell-mcp.ci-local.part=' "$log1" || true)" "$log1"
fi

# 2. Interrupted while a step's container runs: SIGTERM to the whole process
#    group. (Ctrl-C sends SIGINT, which ci-local traps the same way; a
#    background job of a non-interactive shell starts with SIGINT ignored,
#    and an ignored signal cannot be trapped, so the test uses SIGTERM.) The
#    labelled containers are removed and the run ends.
log2="$work/int.log"
: >"$log2"
env "${common_env[@]}" FAKE_DOCKER_LOG="$log2" FAKE_DOCKER_HANG_ON="go test -race" \
	setsid bash "$repo/scripts/ci-local.sh" >"$work/int.out" 2>&1 &
pid=$!
for _ in $(seq 1 100); do
	[[ -e "$log2.hanging" ]] && break
	sleep 0.1
done
if [[ ! -e "$log2.hanging" ]]; then
	bad "interrupted run: never reached the test step" "$work/int.out"
	kill -KILL -- "-$pid" 2>/dev/null || true
else
	kill -TERM -- "-$pid"
	code=0
	wait "$pid" || code=$?
	if [[ "$code" -ne 0 ]]; then
		ok "interrupted run: exits non-zero ($code)"
	else
		bad "interrupted run: exited 0" "$work/int.out"
	fi
	check_log "interrupted run" "$log2"
	if sed -n '/go test -race/,$p' "$log2" | grep -q '^rm -f ctr-ours-1$'; then
		ok "interrupted run: its labelled containers are removed"
	else
		bad "interrupted run: no removal by label after the interrupt" "$log2"
	fi
	if sed -n '/go test -race/,$p' "$log2" | grep -q '^run .*govulncheck'; then
		bad "interrupted run: kept running steps after the interrupt" "$log2"
	else
		ok "interrupted run: stops at the interrupt"
	fi
fi

# 3. The full gate (no flags) never calls itself quick.
if grep -q -i 'quick' "$work/run.out"; then
	bad "complete run: the full gate mentions quick mode" "$work/run.out"
else
	ok "complete run: the full gate does not mention quick mode"
fi

# 4. --quick: its steps only, every other step NOT RUN, and it says, at the
#    start and in its last line, that it is not the full gate.
log4="$work/quick.log"
: >"$log4"
code=0
env "${common_env[@]}" FAKE_DOCKER_LOG="$log4" bash "$repo/scripts/ci-local.sh" --quick >"$work/quick.out" 2>&1 || code=$?
if [[ "$code" -eq 0 ]]; then ok "quick run: exit 0 against the fake docker"; else bad "quick run: exit $code" "$work/quick.out"; fi
check_log "quick run" "$log4"
if grep -q '^run .*go test -race' "$log4" && grep -q '^run .*golangci-lint' "$log4" && grep -q '^run .*doccheck' "$log4"; then
	ok "quick run: runs vet, lint, the race tests and doccheck"
else
	bad "quick run: a quick step did not run" "$log4"
fi
if grep -q -E '^run .*(govulncheck@|deps-current|scripts/exposure|release_test|go test -race .*-tags landlock_forcepsx)' "$log4"; then
	bad "quick run: ran a step of the full gate only" "$log4"
else
	ok "quick run: no full-gate-only step ran"
fi
if grep -q -E '^\| govulncheck +\| NOT RUN' "$work/quick.out"; then
	ok "quick run: the steps it skips are NOT RUN in the summary"
else
	bad "quick run: govulncheck is not NOT RUN in the summary" "$work/quick.out"
fi
if head -n 3 "$work/quick.out" | grep -q 'NOT the full gate' && tail -n 1 "$work/quick.out" | grep -q 'NOT the full gate'; then
	ok "quick run: says it is NOT the full gate, first and last"
else
	bad "quick run: no NOT-the-full-gate notice at the start and the end" "$work/quick.out"
fi

# 5. An unknown argument is refused before anything runs.
log5="$work/arg.log"
: >"$log5"
code=0
env "${common_env[@]}" FAKE_DOCKER_LOG="$log5" bash "$repo/scripts/ci-local.sh" --fast >"$work/arg.out" 2>&1 || code=$?
if [[ "$code" -ne 0 ]] && ! grep -q '^run ' "$log5"; then
	ok "unknown argument: refused, nothing run"
else
	bad "unknown argument: exit $code" "$work/arg.out"
fi

# 6. The lanes with their own uids (as on Windows; CI_LOCAL_FIXED_UIDS=1
#    asks for them on Linux): each lane's containers run as its uid, with
#    its own caches and TMPDIR, and none as 65532, the server image's uid
#    (setup-check runs it beside the tests, and RLIMIT_NPROC counts per uid).
log6="$work/lanes.log"
: >"$log6"
code=0
env "${common_env[@]}" FAKE_DOCKER_LOG="$log6" CI_LOCAL_FIXED_UIDS=1 bash "$repo/scripts/ci-local.sh" >"$work/lanes.out" 2>&1 || code=$?
if [[ "$code" -eq 0 ]]; then ok "lanes: exit 0 against the fake docker"; else bad "lanes: exit $code" "$work/lanes.out"; fi
check_log "lanes" "$log6"
lane_ok() { # lane_ok <what> <pattern of its run line> <uid> <cache> <tmp lane>
	local l
	l="$(grep -E -- "^run .*$2" "$log6" | head -n 1)"
	if [[ -n "$l" && "$l" == *" -u $3:$3 "* && "$l" == *"GOCACHE=$4/build "* && "$l" == *"TMPDIR=/cache/tmp/"*"/$5 "* ]]; then
		ok "lanes: $1 runs as $3 with its own cache and TMPDIR"
	else
		bad "lanes: $1: ${l:-no run line}"
	fi
}
lane_ok "the go lane (go test -race)" 'go test -race -timeout 20m -count=1 \./\.\.\.' 65530 /cache go
lane_ok "the network lane (deps-current)" 'bash scripts/deps-current\.sh' 65531 /cache/lane-network network
if grep -E '^run .*scripts/exposure/gen\.sh' "$log6" | grep -q -- ' -u 65533:65533 .*GOCACHE=/cache/lane-containers/build '; then
	ok "lanes: the containers lane (exposure) runs as 65533 with its own cache"
else
	bad "lanes: the containers lane (exposure)" <(grep -E '^run .*exposure' "$log6")
fi
if grep -E '^run ' "$log6" | grep -q -- ' -u 65532:65532 '; then
	bad "lanes: a container ran as 65532" <(grep -E '^run .* -u 65532:65532 ' "$log6")
else
	ok "lanes: no container of a lane runs as 65532"
fi

# 7. The lanes run at once: while the go lane's go test -race hangs, the
#    network and containers lanes still run their steps; then the interrupt
#    stops every lane and removes the labelled containers.
lanes_hang() { # lanes_hang <log> <out> <env…>: start, wait for the hang
	local log="$1" out="$2"
	shift 2
	: >"$log"
	env "${common_env[@]}" FAKE_DOCKER_LOG="$log" FAKE_DOCKER_HANG_ON="go test -race -timeout 20m -count=1 ./..." "$@" \
		setsid bash "$repo/scripts/ci-local.sh" >"$out" 2>&1 &
	hang_pid=$!
	for _ in $(seq 1 100); do
		[[ -e "$log.hanging" ]] && break
		sleep 0.1
	done
}
lanes_hang "$work/par.log" "$work/par.out" CI_LOCAL_FIXED_UIDS=1
if [[ ! -e "$work/par.log.hanging" ]]; then
	bad "parallel lanes: never reached the test step" "$work/par.out"
	kill -KILL -- "-$hang_pid" 2>/dev/null || true
else
	for _ in $(seq 1 100); do
		grep -q '^run .*deps-current_test\.sh' "$work/par.log" && grep -q '^run .*scripts/exposure/gen\.sh' "$work/par.log" && break
		sleep 0.1
	done
	if grep -q '^run .*deps-current_test\.sh' "$work/par.log" && grep -q '^run .*scripts/exposure/gen\.sh' "$work/par.log"; then
		ok "parallel lanes: the network and containers lanes run while the go lane's tests run"
	else
		bad "parallel lanes: the other lanes waited for the go lane" "$work/par.log"
	fi
	kill -TERM -- "-$hang_pid"
	wait "$hang_pid" || true
	if sed -n '/go test -race -timeout 20m -count=1 \.\/\.\.\./,$p' "$work/par.log" | grep -q '^run .*govulncheck'; then
		bad "parallel lanes: the go lane kept running after the interrupt" "$work/par.log"
	else
		ok "parallel lanes: the interrupt stops the go lane"
	fi
	if tail -n 1 "$work/par.log" | grep -q '^rm -f ctr-ours-1$'; then
		ok "parallel lanes: the labelled containers are removed after the interrupt"
	else
		bad "parallel lanes: no removal by label after the interrupt" "$work/par.log"
	fi
fi

# 8. CI_LOCAL_SERIAL=1: one lane after another, so nothing of another lane
#    runs while the go lane's tests hang.
lanes_hang "$work/ser.log" "$work/ser.out" CI_LOCAL_FIXED_UIDS=1 CI_LOCAL_SERIAL=1
if [[ ! -e "$work/ser.log.hanging" ]]; then
	bad "serial lanes: never reached the test step" "$work/ser.out"
	kill -KILL -- "-$hang_pid" 2>/dev/null || true
else
	sleep 2
	if grep -q '^run .*deps-current' "$work/ser.log"; then
		bad "serial lanes: the network lane ran beside the go lane" "$work/ser.log"
	else
		ok "serial lanes: one lane at a time"
	fi
	kill -TERM -- "-$hang_pid"
	wait "$hang_pid" || true
fi

echo "ci-local tests: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
