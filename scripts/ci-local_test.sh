#!/usr/bin/env bash
# Proves scripts/ci-local.sh touches only containers it started itself: it
# runs ci-local against a fake docker (first on PATH) that logs every call,
# and checks that
#   - every container ci-local starts (its own and the systemd probe's)
#     carries the label shell-mcp.ci-local=<run id>, one id per run;
#   - it never prunes, and never lists, stops, kills or removes a container
#     except through that label: the fake reports a foreign container to any
#     unfiltered `docker ps`, and it must never be named;
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
	if [[ "$*" == *"--filter label=shell-mcp.ci-local="* ]]; then
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
	if grep -q 'ctr-foreign-1' "$log" || grep -E '^(ps|container ls|container list)( |$)' "$log" | grep -v -q -- '--filter label=shell-mcp.ci-local='; then
		bad "$name: a container was listed or named without the run label" "$log"
	else
		ok "$name: containers are listed only by the run label"
	fi
	if grep -E '^(stop|kill|rm|container (stop|kill|rm))( |$)' "$log" | grep -v -q -E 'ctr-ours-1|ctr-probe-1|shell-mcp-probe-systemd-'; then
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

echo "ci-local tests: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
