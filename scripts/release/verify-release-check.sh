#!/usr/bin/env bash
# release/verify-release-check.sh: run scripts/verify-release.sh, the
# script users run (handoff §4.F), against the files the release workflow has
# just signed, with the cosign and gh a user would use, and against tampered
# copies of them, each of which must be refused for its own reason:
#   - a changed binary (its checksum, its bundle);
#   - a changed SHA256SUMS (the checksum it changed, SHA256SUMS's bundle);
#   - a missing bundle;
#   - another release's identity (the files verified as another version).
# A wrong issuer cannot be made with real signatures; the self-test covers it
# (scripts/verify-release_test.sh, a fake cosign that checks the issuer).
# A release (PUBLISH=true) must pass, as cosign+gh and with --sums against
# the SHA256SUMS that scripts/release/verify.sh has just verified. A dry
# run's files are signed by the run's own ref, never a tag: they must be
# refused in every mode, with the checks still run and the tag's identity
# refusing their signatures (decided in S8-4: a dry run is never verified).
#
#   bash scripts/release/verify-release-check.sh DIR VERSION PUBLISH
# Needs cosign, gh (GH_TOKEN) and GNU coreutils. Writes only in a temporary
# directory; DIR is left as it is.
set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 DIR VERSION PUBLISH" >&2
	exit 2
fi
dir="$1" version="$2" publish="$3"
script="$(cd "$(dirname "$0")/.." && pwd)/verify-release.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
c="$work/files"
bin="shell-mcp-gate_${version}_linux_amd64"
identity="https://github.com/tyler-rich/shell-mcp/.github/workflows/release-build.yml@refs/tags/v"

fresh() {
	rm -rf "$c"
	cp -R "$dir" "$c"
}

fail=0
# expect <name> <want-exit> <needle>… -- <args…>: run the script; each needle
# must be in its output.
expect() {
	local name="$1" want="$2" out code=0 needles=()
	shift 2
	while [[ "$1" != -- ]]; do
		needles+=("$1")
		shift
	done
	shift
	out="$(sh "$script" "$@" 2>&1)" || code=$?
	local miss=""
	for n in "${needles[@]}"; do
		grep -q -F -- "$n" <<<"$out" || miss="$miss [$n]"
	done
	if [[ "$code" == "$want" && -z "$miss" ]]; then
		echo "ok   $name"
	else
		echo "FAIL $name (exit $code, want $want; missing:$miss)"
		sed 's/^/     /' <<<"$out"
		fail=1
	fi
}

fresh
if [[ "$publish" == true ]]; then
	expect "the release verifies (cosign and gh)" 0 "every check passed (cosign+gh) for $identity$version" -- "$version" --dir "$c"
	expect "the release verifies with --sums" 0 "every check passed (sums)" -- "$version" --dir "$c" --sums "$dir/SHA256SUMS"
else
	expect "a dry run's files are refused (cosign and gh)" 1 "dry-run files are never verified" "ok   checksum: $bin" \
		"FAIL cosign: $bin does not verify for $identity$version" "FAIL gh attestation: $bin has no provenance" -- "$version" --dir "$c"
	expect "a dry run's files are refused with --sums" 1 "dry-run files are never verified" "ok   checksum: $bin" -- "$version" --dir "$c" --sums "$dir/SHA256SUMS"
fi

fresh
printf 'x' >>"$c/$bin"
expect "a changed binary is refused" 1 "FAIL checksum: $bin does not match SHA256SUMS" "FAIL cosign: $bin does not verify" \
	"FAIL gh attestation: $bin has no provenance" -- "$version" --dir "$c"

fresh
sed -i "s/^[0-9a-f]\{64\}\(  $bin\)$/$(printf '0%.0s' $(seq 64))\1/" "$c/SHA256SUMS"
expect "a changed SHA256SUMS is refused" 1 "FAIL checksum: $bin does not match SHA256SUMS" "FAIL cosign: SHA256SUMS does not verify" -- "$version" --dir "$c"

fresh
rm "$c/$bin.sigstore.json"
expect "a missing bundle is refused" 1 "FAIL cosign: $bin: no bundle $bin.sigstore.json" -- "$version" --dir "$c"

fresh
expect "another release's identity is refused" 1 "FAIL cosign: SHA256SUMS does not verify for ${identity}0.0.1" -- 0.0.1 --dir "$c"

if [[ $fail -ne 0 ]]; then
	echo "verify-release check: FAILED" >&2
	exit 1
fi
echo "verify-release check: every case as required ($([[ "$publish" == true ]] && echo release || echo dry run))"
