#!/usr/bin/env bash
# The e2e-host shards (test/e2e/shards.txt). Changes nothing on the machine.
#
#   shards.sh count <manifest>
#       the number of shards: one more than the highest shard named
#   shards.sh list <manifest> <all-tests> <shard>
#       the tests of <shard>, one per line, in the binary's order
#       (<all-tests>: the binary's -test.list output, one test per line)
#   shards.sh regex <list>
#       the -test.run pattern that runs exactly the tests of <list>
#   shards.sh cover <manifest> <dir>
#       the coverage check: <dir>/e2e-shard-<n>/ holds each shard's all-tests,
#       list and log (the e2e binary's -test.v output), and the last shard's
#       credential.log (execx's credential tests as root). Every shard is
#       there, all agree on the binary's tests, the lists are disjoint and
#       together are all of them, each test passed in its shard and in no
#       other, nothing failed or skipped, and the credential tests passed.
#       Prints the counts.
set -euo pipefail

# nomatch_ok <command…>: grep's "no line selected" (status 1) is not an error.
nomatch_ok() { "$@" || [[ $? -eq 1 ]]; }

die() {
	echo "shards: $*" >&2
	exit 1
}

# manifest <file>: "<shard> <test>" lines, comments and blanks dropped.
manifest() {
	awk '!/^[[:space:]]*(#|$)/ {
		if (NF != 2 || $1 !~ /^[1-9][0-9]*$/ || $2 !~ /^Test[A-Za-z0-9_]*$/) { print "bad line " NR ": " $0 > "/dev/stderr"; bad = 1 }
		else print $1, $2
	} END { exit bad }' "$1"
}

count() {
	local m
	m="$(manifest "$1")" || die "$1: malformed"
	[[ -n "$m" ]] || die "$1: names no test"
	awk '$1 > n { n = $1 } END { print n + 1 }' <<<"$m"
}

list() { # list <manifest> <all-tests> <shard>
	local m n
	m="$(manifest "$1")" || die "$1: malformed"
	n="$(count "$1")"
	[[ "$3" =~ ^[1-9][0-9]*$ ]] && ((10#$3 <= n)) || die "no shard $3 (shards: 1 to $n)"
	[[ -s "$2" ]] || die "$2: no tests listed"
	# Every named test must exist, and be named once.
	local dup
	dup="$(awk '{ print $2 }' <<<"$m" | sort | uniq -d)"
	[[ -z "$dup" ]] || die "named more than once: $dup"
	local missing
	missing="$(awk '{ print $2 }' <<<"$m" | nomatch_ok grep -vxF -f "$2")"
	[[ -z "$missing" ]] || die "named in $1 but not a test of the binary: $missing"
	if ((10#$3 == n)); then
		# The last shard: every test no other shard names.
		awk '{ print $2 }' <<<"$m" | nomatch_ok grep -vxF -f - "$2"
	else
		awk -v s="$3" '$1 == s { print $2 }' <<<"$m" | nomatch_ok grep -xF -f - "$2"
	fi
}

regex() { # regex <list>
	[[ -s "$1" ]] || die "$1: empty list"
	printf '^(%s)$\n' "$(paste -sd '|' "$1")"
}

cover() { # cover <manifest> <dir>
	local n s d fail=0
	n="$(count "$1")"
	local all="$2/e2e-shard-1/all-tests"
	[[ -s "$all" ]] || die "shard 1: no all-tests"
	local seen
	seen="$(mktemp)"
	# shellcheck disable=SC2064 # expand now
	trap "rm -f '$seen'" RETURN
	local top=0 sub=0
	for ((s = 1; s <= n; s++)); do
		d="$2/e2e-shard-$s"
		for f in all-tests list log; do
			[[ -f "$d/$f" ]] || { echo "FAIL shard $s: no $f (the shard did not finish)"; fail=1; continue 2; }
		done
		cmp -s "$all" "$d/all-tests" || { echo "FAIL shard $s: the binary's tests differ from shard 1's"; fail=1; }
		# The list is what this script computes from the manifest.
		cmp -s <(list "$1" "$all" "$s") "$d/list" || { echo "FAIL shard $s: its list is not the manifest's"; fail=1; }
		[[ -s "$d/list" ]] || { echo "FAIL shard $s: runs no test"; fail=1; }
		while read -r t; do
			r="$(awk -v t="$t" '$1 == "---" && $3 == t { sub(/:$/, "", $2); print $2; exit }' "$d/log")"
			[[ "$r" == PASS ]] || { echo "FAIL shard $s: $t ${r:-NOT RUN}"; fail=1; }
		done <"$d/list"
		# A test of another shard must not have run here.
		local extra
		extra="$(awk '/^--- (PASS|FAIL|SKIP): Test/ { print $3 }' "$d/log" | nomatch_ok grep -vxF -f "$d/list")"
		[[ -z "$extra" ]] || { echo "FAIL shard $s: ran tests of other shards: $(tr '\n' ' ' <<<"$extra")"; fail=1; }
		if grep -qE -- '--- (FAIL|SKIP)' "$d/log"; then
			echo "FAIL shard $s: a test or subtest failed or skipped:"
			grep -m 20 -E -- '--- (FAIL|SKIP)' "$d/log"
			fail=1
		fi
		cat "$d/list" >>"$seen"
		local tp sp
		tp="$(nomatch_ok grep -cE '^--- PASS: Test' "$d/log")"
		sp="$(nomatch_ok grep -cE '^[[:space:]]+--- PASS: Test' "$d/log")"
		echo "shard $s: $(wc -l <"$d/list") tests listed, $tp passed (and $sp subtests)"
		top=$((top + tp))
		sub=$((sub + sp))
	done
	local dup
	dup="$(sort "$seen" | uniq -d)"
	[[ -z "$dup" ]] || { echo "FAIL in more than one shard: $(tr '\n' ' ' <<<"$dup")"; fail=1; }
	cmp -s <(sort -u "$seen") <(sort "$all") || {
		echo "FAIL the shards' lists are not exactly the binary's tests:"
		diff <(sort -u "$seen") <(sort "$all") || [[ $? -eq 1 ]]
		fail=1
	}
	# execx's credential tests, as root, in the last shard.
	local cred="$2/e2e-shard-$n/credential.log"
	if [[ ! -f "$cred" ]]; then
		echo "FAIL shard $n: no credential.log"
		fail=1
	else
		for t in TestCredentialSwitch TestCredentialNoGroups TestCredentialNPROC TestCredentialRefusedValuesAsRoot TestNilCredentialAsRoot TestCredentialCallSites; do
			grep -q -- "^--- PASS: $t " "$cred" || { echo "FAIL credential test $t did not pass as root"; fail=1; }
		done
		# The non-root refusal test is the one that skips as root.
		if grep -E -- '--- (SKIP|FAIL)' "$cred" | grep -v -- '--- SKIP: TestCredentialRefusedWhenNotRoot '; then fail=1; fi
		echo "credential tests (as root): $(nomatch_ok grep -cE '^--- PASS: Test' "$cred") passed"
	fi
	echo "total: $(wc -l <"$all") e2e tests in $n shards, $top passed (and $sub subtests)"
	((fail == 0)) || die "coverage check failed"
	echo "coverage: every e2e test ran in exactly one shard and passed"
}

case "${1:-}" in
count) (($# == 2)) || die "usage: count <manifest>"; count "$2" ;;
list) (($# == 4)) || die "usage: list <manifest> <all-tests> <shard>"; list "$2" "$3" "$4" ;;
regex) (($# == 2)) || die "usage: regex <list>"; regex "$2" ;;
cover) (($# == 3)) || die "usage: cover <manifest> <dir>"; cover "$2" "$3" ;;
*) die "usage: shards.sh count|list|regex|cover …" ;;
esac
