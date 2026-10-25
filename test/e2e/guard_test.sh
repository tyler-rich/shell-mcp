#!/usr/bin/env bash
# Proves the end-to-end entry points refuse to run anywhere but a
# GitHub-hosted Actions runner, before they do anything else:
#   - test/e2e/setup.sh (it creates accounts, units and policies as root);
#   - the e2e test binary, when E2E_TEST_BIN names it (go test -c -tags e2e).
# Each case runs under `env -i` with a PATH whose first directory holds a
# stub for every system command setup.sh calls; a stub only logs its name.
# A refusal must exit 64 at once, say why, and leave the log holding at most
# `uname` (the guard's own check). The control case (Linux, GITHUB_ACTIONS=
# true, RUNNER_ENVIRONMENT=github-hosted) must get past the guard, to the
# E2E_BIN check, which still changes nothing.
#
# Safe anywhere: nothing here changes the machine, and every case that could
# reach setup.sh's real work stops before it (refusal, or E2E_BIN unset).
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
setup="$repo/test/e2e/setup.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

stubs="$work/stubs"
mkdir -p "$stubs"
log="$work/calls.log"
for c in getent groupadd useradd usermod passwd chown chmod install mkdir rm mv cp ln find \
	systemctl systemd-run ssh-keygen sshd ss journalctl dpkg-deb dpkg-query apt-get pgrep \
	mktemp seq sleep cut tee polkitd pkaction sudo docker; do
	printf '#!/bin/sh\necho %s >>"%s"\nexit 0\n' "$c" "$log" >"$stubs/$c"
	chmod +x "$stubs/$c"
done
# uname answers what the case says (FAKE_UNAME).
printf '#!/bin/sh\necho uname >>"%s"\necho "${FAKE_UNAME:-Linux}"\n' "$log" >"$stubs/uname"
chmod +x "$stubs/uname"

pass=0
fail=0
check() { # check <name> <want exit> <want stderr substring> <only calls allowed> <command…>
	local name="$1" want="$2" msg="$3" allowed="$4"
	shift 4
	: >"$log"
	local code=0 start end
	start=$(date +%s)
	"$@" >"$work/out" 2>&1 || code=$?
	end=$(date +%s)
	local calls
	calls="$(sort -u "$log" | tr '\n' ' ' | sed 's/ $//')"
	if [[ $code -ne $want ]]; then
		echo "FAIL $name: exit $code, want $want; output: $(head -c 300 "$work/out")"
		fail=$((fail + 1))
	elif ! grep -qF -- "$msg" "$work/out"; then
		echo "FAIL $name: output lacks \"$msg\": $(head -c 300 "$work/out")"
		fail=$((fail + 1))
	elif [[ -n "$calls" && "$calls" != "$allowed" ]]; then
		echo "FAIL $name: ran \"$calls\" (allowed: \"$allowed\")"
		fail=$((fail + 1))
	elif ((end - start > 5)); then
		echo "FAIL $name: took $((end - start)) s"
		fail=$((fail + 1))
	else
		echo "ok   $name"
		pass=$((pass + 1))
	fi
}

base=(env -i "PATH=$stubs:/usr/bin:/bin" "HOME=$work" "E2E_BIN=$work/bin")
refusal="refusing to run"

# --- setup.sh ------------------------------------------------------------------
check "setup.sh: nothing set" 64 "$refusal" "uname" "${base[@]}" bash "$setup"
check "setup.sh: a workstation (no Actions variables)" 64 "$refusal" "uname" "${base[@]}" FAKE_UNAME=Linux bash "$setup"
check "setup.sh: not Linux" 64 "$refusal" "uname" "${base[@]}" FAKE_UNAME=MINGW64_NT-10.0 GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted bash "$setup"
check "setup.sh: GITHUB_ACTIONS only" 64 "$refusal" "uname" "${base[@]}" GITHUB_ACTIONS=true bash "$setup"
check "setup.sh: self-hosted runner" 64 "$refusal" "uname" "${base[@]}" GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=self-hosted bash "$setup"
check "setup.sh: GITHUB_ACTIONS=1" 64 "$refusal" "uname" "${base[@]}" GITHUB_ACTIONS=1 RUNNER_ENVIRONMENT=github-hosted bash "$setup"
# Control: on a GitHub-hosted Linux runner the guard passes, and the script
# stops at its own E2E_BIN check (no inputs here), still changing nothing.
check "setup.sh: control, GitHub-hosted Linux runner" 2 "missing" "uname" \
	env -i "PATH=$stubs:/usr/bin:/bin" "HOME=$work" "E2E_BIN=$work/no-such-dir" GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted bash "$setup"

# --- the e2e test binary ----------------------------------------------------
if [[ -n "${E2E_TEST_BIN:-}" ]]; then
	check "e2e.test: nothing set" 64 "$refusal" "" "${base[@]}" "$E2E_TEST_BIN" -test.run '.*'
	check "e2e.test: self-hosted runner" 64 "$refusal" "" "${base[@]}" GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=self-hosted "$E2E_TEST_BIN" -test.run '.*'
	check "e2e.test: listing is refused too" 64 "$refusal" "" "${base[@]}" "$E2E_TEST_BIN" -test.list '.*'
	if grep -q '^=== RUN' "$work/out"; then
		echo "FAIL e2e.test: a test started"
		fail=$((fail + 1))
	fi
else
	echo "skip e2e.test cases: set E2E_TEST_BIN to the built e2e test binary"
fi

echo "guard tests: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
