#!/usr/bin/env bash
# Proves test/e2e/shards.sh: the shard lists follow the manifest and
# together are every test, each once; the coverage check passes only when
# every shard finished, every test passed in its own shard and in no other,
# nothing failed or skipped, and execx's credential tests passed. Invented
# test names and logs; nothing here changes the machine. Also checks the
# real manifest against the real e2e test names (go test -list).
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
sh="$repo/test/e2e/shards.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0
fail=0
ok() { echo "ok   $*"; pass=$((pass + 1)); }
bad() { echo "FAIL $*"; fail=$((fail + 1)); }

# expect <want-exit: 0 or nonzero> <name> <grep pattern or ""> <command…>
expect() {
	local want="$1" name="$2" pat="$3"
	shift 3
	local out code=0
	out="$("$@" 2>&1)" || code=$?
	if [[ "$want" == 0 && $code -ne 0 ]] || [[ "$want" != 0 && $code -eq 0 ]]; then
		bad "$name (exit $code, want ${want/nonzero/non-zero})"
		sed 's/^/     /' <<<"$out"
		return
	fi
	if [[ -n "$pat" ]] && ! grep -qE -- "$pat" <<<"$out"; then
		bad "$name (no line matching: $pat)"
		sed 's/^/     /' <<<"$out"
		return
	fi
	ok "$name"
}

m="$work/manifest"
cat >"$m" <<'EOF'
# invented
1 TestSlowA
2 TestSlowB
2 TestSlowC
EOF
all="$work/all"
printf '%s\n' TestFirst TestSlowA TestMiddle TestSlowB TestSlowC TestLast >"$all"

expect 0 "count is one more than the highest shard named" '^3$' bash "$sh" count "$m"
expect 0 "shard 1 is its named tests" '^TestSlowA$' bash "$sh" list "$m" "$all" 1
expect 0 "the last shard is every other test, in the binary's order" '' \
	bash -c 'test "$(bash "$1" list "$2" "$3" 3 | paste -sd " ")" = "TestFirst TestMiddle TestLast"' _ "$sh" "$m" "$all"
expect 0 "together the lists are every test, each once" '' \
	bash -c 'for s in 1 2 3; do bash "$1" list "$2" "$3" $s; done | sort | diff - <(sort "$3")' _ "$sh" "$m" "$all"
expect nonzero "a shard beyond the last is refused" 'no shard 4' bash "$sh" list "$m" "$all" 4
expect nonzero "shard 0 is refused" 'no shard 0' bash "$sh" list "$m" "$all" 0
printf '1 TestGone\n' >"$work/m-gone"
expect nonzero "a named test the binary lacks is refused" 'not a test of the binary: TestGone' bash "$sh" list "$work/m-gone" "$all" 1
printf '1 TestSlowA\n2 TestSlowA\n' >"$work/m-dup"
expect nonzero "a test named twice is refused" 'named more than once: TestSlowA' bash "$sh" list "$work/m-dup" "$all" 1
printf '1 TestSlowA extra\n' >"$work/m-bad"
expect nonzero "a malformed line is refused" 'malformed' bash "$sh" list "$work/m-bad" "$all" 1
: >"$work/empty"
expect nonzero "an empty test list is refused" 'no tests listed' bash "$sh" list "$m" "$work/empty" 1
printf 'TestA\nTestB\n' >"$work/l2"
expect 0 "the run pattern matches exactly the listed tests" '^\^\(TestA\|TestB\)\$$' bash "$sh" regex "$work/l2"

# A complete, passing set of shard results.
good="$work/good"
mkshards() { # mkshards <dir>
	local s t
	for s in 1 2 3; do
		mkdir -p "$1/e2e-shard-$s"
		cp "$all" "$1/e2e-shard-$s/all-tests"
		bash "$sh" list "$m" "$all" $s >"$1/e2e-shard-$s/list"
		: >"$1/e2e-shard-$s/log"
		while read -r t; do
			printf '=== RUN   %s\n    --- PASS: %s/sub (0.10s)\n--- PASS: %s (1.00s)\n' "$t" "$t" "$t" >>"$1/e2e-shard-$s/log"
		done <"$1/e2e-shard-$s/list"
	done
	{
		for t in TestCredentialSwitch TestCredentialNoGroups TestCredentialNPROC TestCredentialRefusedValuesAsRoot TestNilCredentialAsRoot TestCredentialCallSites; do
			echo "--- PASS: $t (0.01s)"
		done
		echo "--- SKIP: TestCredentialRefusedWhenNotRoot (0.00s)"
	} >"$1/e2e-shard-3/credential.log"
}
mkshards "$good"
expect 0 "every shard passed: coverage passes" 'total: 6 e2e tests in 3 shards, 6 passed \(and 6 subtests\)' bash "$sh" cover "$m" "$good"

# cover_case <name> <pattern> <mutation run in the copy's directory>
cover_case() {
	local name="$1" pat="$2" mut="$3" d
	d="$work/case-$((pass + fail))"
	cp -r "$good" "$d"
	(cd "$d" && eval "$mut")
	expect nonzero "$name" "$pat" bash "$sh" cover "$m" "$d"
}
cover_case "a shard that did not finish" 'shard 2: no log' 'rm e2e-shard-2/log'
cover_case "a missing shard" 'shard 3: no all-tests' 'rm -r e2e-shard-3'
cover_case "a test that did not run" 'shard 3: TestMiddle NOT RUN' 'grep -v "TestMiddle" e2e-shard-3/log >x; mv x e2e-shard-3/log'
cover_case "a failed test" 'shard 1: TestSlowA FAIL' 'sed -i "s/^--- PASS: TestSlowA /--- FAIL: TestSlowA /" e2e-shard-1/log'
cover_case "a failed subtest" 'failed or skipped' 'sed -i "s/    --- PASS: TestSlowB\/sub/    --- FAIL: TestSlowB\/sub/" e2e-shard-2/log'
cover_case "a skipped test" 'shard 3: TestLast SKIP' 'sed -i "s/^--- PASS: TestLast /--- SKIP: TestLast /" e2e-shard-3/log'
cover_case "a test of another shard ran here" 'ran tests of other shards: TestSlowA' 'echo "--- PASS: TestSlowA (1.00s)" >>e2e-shard-3/log'
cover_case "a list that is not the manifest's" 'shard 1: its list is not the manifest' 'echo TestFirst >>e2e-shard-1/list; echo "--- PASS: TestFirst (1.00s)" >>e2e-shard-1/log'
cover_case "a shard built from other tests" 'differ from shard 1' 'echo TestExtra >>e2e-shard-2/all-tests'
cover_case "a test in two shards" 'TestMiddle' 'echo TestMiddle >>e2e-shard-1/list; echo "--- PASS: TestMiddle (1.00s)" >>e2e-shard-1/log'
cover_case "no credential log" 'no credential.log' 'rm e2e-shard-3/credential.log'
cover_case "a credential test that did not pass" 'TestCredentialNPROC did not pass as root' 'sed -i "/TestCredentialNPROC/d" e2e-shard-3/credential.log'
cover_case "a credential test that skipped" 'TestCredentialSwitch' 'sed -i "s/--- PASS: TestCredentialSwitch/--- SKIP: TestCredentialSwitch/" e2e-shard-3/credential.log'

# The real manifest against the real e2e tests, read from the source (the
# binary's -test.list needs the runner): Go lists a package's tests file by
# file in name order, each in declaration order.
real="$work/real-all"
LC_ALL=C awk '/^func Test[A-Za-z0-9_]*\(t \*testing\.T\)/ { sub(/^func /, ""); sub(/\(.*/, ""); print }' $(LC_ALL=C ls "$repo"/test/e2e/*_test.go) >"$real"
expect 0 "the source has e2e tests" '' test -s "$real"
n="$(bash "$sh" count "$repo/test/e2e/shards.txt")"
expect 0 "the real manifest's shards together are every e2e test" '' 	bash -c 'for ((s = 1; s <= $4; s++)); do bash "$1" list "$2" "$3" $s; done | sort | diff - <(sort "$3")' _ "$sh" "$repo/test/e2e/shards.txt" "$real" "$n"
expect 0 "TestApprovalWebFlow and TestGateKeyRotation are in different shards" '' 	bash -c 'a=$(awk "\$2 == \"TestApprovalWebFlow\" { print \$1 }" "$1"); b=$(awk "\$2 == \"TestGateKeyRotation\" { print \$1 }" "$1"); test -n "$a" && test -n "$b" && test "$a" != "$b"' _ "$repo/test/e2e/shards.txt"

echo "shards_test: $pass passed, $fail failed"
((fail == 0))
