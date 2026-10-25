#!/usr/bin/env bash
# Self-test of the release scripts that decide what may be released: the
# version a run builds (version.sh), the CHANGELOG section a release needs
# (notes.sh), the CI and CodeQL check the tagged commit needs (checks.sh,
# against a fake gh), the notes' verification block (render-notes.sh) and the
# release build's refusals of its arguments (build.sh). Offline; needs bash,
# awk and GNU coreutils. Every case that must refuse is shown refusing.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sha="0123456789abcdef0123456789abcdef01234567"

pass=0
fail=0
expect() { # expect <name> <want-exit> <want-output-substring> <command…>
	local name="$1" want="$2" needle="$3" out code=0
	shift 3
	out="$("$@" 2>&1)" || code=$?
	if [[ "$code" == "$want" ]] && grep -q -F -- "$needle" <<<"$out"; then
		echo "ok   $name"
		pass=$((pass + 1))
	else
		echo "FAIL $name (exit $code, want $want; looking for: $needle)"
		sed 's/^/     /' <<<"$out"
		fail=$((fail + 1))
	fi
}

# --- version.sh ---------------------------------------------------------------
v="$here/version.sh"
expect "tag v0.1.0" 0 "0.1.0 0.1.0" bash "$v" tag v0.1.0 "$sha"
expect "tag v10.20.30" 0 "10.20.30 10.20.30" bash "$v" tag v10.20.30 "$sha"
for bad in 0.1.0 v0.1 v0.1.0-rc1 v0.1.0+meta v01.1.0 v0.01.0 v0.1.00 V0.1.0 "v0.1.0 " vfoo ""; do
	expect "tag '$bad' refused" 1 "is not vX.Y.Z" bash "$v" tag "$bad" "$sha"
done
expect "dispatch 0.1.0" 0 "0.1.0-dryrun.0123456 0.1.0" bash "$v" dispatch 0.1.0 "$sha"
expect "dispatch v0.1.0 refused" 1 "is not X.Y.Z" bash "$v" dispatch v0.1.0 "$sha"
expect "dispatch 0.1.0-rc1 refused" 1 "is not X.Y.Z" bash "$v" dispatch 0.1.0-rc1 "$sha"
expect "pull request" 0 "0.0.0-dryrun.0123456 -" bash "$v" pull_request "" "$sha"
expect "short commit refused" 1 "not a full commit id" bash "$v" tag v0.1.0 0123456
expect "unknown mode refused" 2 "unknown mode" bash "$v" release v0.1.0 "$sha"

# --- notes.sh -------------------------------------------------------------------
n="$here/notes.sh"
cat >"$work/CHANGELOG.md" <<'EOF'
# Changelog

## [0.2.0]

## [0.1.10] - 2026-11-01

Not this one.

## [0.1.1]



## [0.1.0] - 2026-10-30

First release.

- Gate, helper and server.

## [0.0.9]

Older.
EOF
expect "section with date" 0 "First release." bash "$n" 0.1.0 "$work/CHANGELOG.md"
expect "section ends at the next heading" 0 "- Gate, helper and server." bash "$n" 0.1.0 "$work/CHANGELOG.md"
out="$(bash "$n" 0.1.0 "$work/CHANGELOG.md")"
expect "next section not included" 0 "ok" bash -c '! grep -q Older <<<"$1" && echo ok' _ "$out"
expect "no blank lines around the text" 0 "ok" bash -c '[[ "$1" == "First release."$'"'"'\n\n'"'"'"- Gate, helper and server." ]] && echo ok' _ "$out"
expect "0.1.1 is not 0.1.10's prefix match" 1 "has no text under '## [0.1.1]'" bash "$n" 0.1.1 "$work/CHANGELOG.md"
expect "0.1.1 does not match 0.1.10" 0 "Not this one." bash "$n" 0.1.10 "$work/CHANGELOG.md"
expect "empty section refused" 1 "has no text under '## [0.2.0]'" bash "$n" 0.2.0 "$work/CHANGELOG.md"
expect "missing section refused" 1 "has no text under '## [0.3.0]'" bash "$n" 0.3.0 "$work/CHANGELOG.md"
expect "missing file refused" 1 "does not exist" bash "$n" 0.1.0 "$work/none.md"

# --- checks.sh (fake gh) ----------------------------------------------------------
fakebin="$work/bin"
mkdir -p "$fakebin"
cat >"$fakebin/gh" <<'FAKE'
#!/usr/bin/env bash
# Fake gh for release_test.sh: answers the check-runs query for the check
# name given with -f check_name=..., from FAKE_CI / FAKE_CODEQL (lines of
# "<id> <status> <conclusion>"); FAKE_FAIL=<name> makes that query fail.
name=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	-f) [[ "$2" == check_name=* ]] && name="${2#check_name=}"; shift ;;
	esac
	shift
done
[[ "${FAKE_FAIL:-}" == "$name" ]] && { echo "gh: HTTP 502" >&2; exit 1; }
case "$name" in
ci) printf '%s' "${FAKE_CI:-}" ;;
"analyze (go)") printf '%s' "${FAKE_CODEQL:-}" ;;
*) echo "fake gh: unexpected check name '$name'" >&2; exit 2 ;;
esac
FAKE
chmod +x "$fakebin/gh"
c="$here/checks.sh"
ok1=$'1 completed success'
ok2=$'1 completed success\n2 completed success'
expect "both succeeded" 0 "'analyze (go)' succeeded" env PATH="$fakebin:$PATH" FAKE_CI="$ok1" FAKE_CODEQL="$ok2" bash "$c" o/r "$sha"
expect "ci missing" 1 "'ci' never ran" env PATH="$fakebin:$PATH" FAKE_CI="" FAKE_CODEQL="$ok1" bash "$c" o/r "$sha"
expect "codeql missing" 1 "'analyze (go)' never ran" env PATH="$fakebin:$PATH" FAKE_CI="$ok1" FAKE_CODEQL="" bash "$c" o/r "$sha"
expect "ci failed" 1 "'ci' on $sha is not a success" env PATH="$fakebin:$PATH" FAKE_CI="1 completed failure" FAKE_CODEQL="$ok1" bash "$c" o/r "$sha"
expect "ci still running" 1 "'ci' on $sha is not a success" env PATH="$fakebin:$PATH" FAKE_CI="1 in_progress null" FAKE_CODEQL="$ok1" bash "$c" o/r "$sha"
expect "one of two codeql runs failed" 1 "2 completed cancelled" env PATH="$fakebin:$PATH" FAKE_CI="$ok1" FAKE_CODEQL=$'1 completed success\n2 completed cancelled' bash "$c" o/r "$sha"
expect "ci skipped is not a success" 1 "1 completed skipped" env PATH="$fakebin:$PATH" FAKE_CI="1 completed skipped" FAKE_CODEQL="$ok1" bash "$c" o/r "$sha"
expect "unreadable checks fail" 1 "cannot read the 'ci' check runs" env PATH="$fakebin:$PATH" FAKE_FAIL=ci FAKE_CODEQL="$ok1" bash "$c" o/r "$sha"
expect "short commit refused" 2 "not a full commit id" env PATH="$fakebin:$PATH" bash "$c" o/r abc

# --- render-notes.sh ------------------------------------------------------------------
r="$here/render-notes.sh"
expect "notes name the tag identity" 0 "--certificate-identity https://github.com/o/r/.github/workflows/release-build.yml@refs/tags/v0.1.0" \
	bash "$r" 0.1.0 - ghcr.io/o/r "sha256:$sha$sha" o/r refs/tags/v0.1.0
expect "notes pin the digest" 0 "ghcr.io/o/r:0.1.0@sha256:$sha$sha" \
	bash "$r" 0.1.0 - ghcr.io/o/r "sha256:$sha$sha" o/r refs/tags/v0.1.0
expect "notes without a CHANGELOG section refused" 1 "does not exist" \
	bash -c 'cd "$1" && cp "$2" ./render-notes.sh && cp "$3" ./notes.sh && bash ./render-notes.sh 0.1.0 0.1.0 r d o/r refs/tags/v0.1.0' _ "$work" "$r" "$n"

# --- build.sh argument refusals (nothing is built) ---------------------------------
b="$here/build.sh"
expect "build: rc version refused" 2 "is neither X.Y.Z" bash "$b" 0.1.0-rc1 "$sha" "$work/out1"
expect "build: v prefix refused" 2 "is neither X.Y.Z" bash "$b" v0.1.0 "$sha" "$work/out1"
expect "build: short commit refused" 2 "not a full commit id" bash "$b" 0.1.0 abc "$work/out1"
mkdir -p "$work/full" && touch "$work/full/x"
expect "build: non-empty output refused" 2 "is not empty" bash "$b" 0.1.0 "$sha" "$work/full"

echo "release script tests: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
