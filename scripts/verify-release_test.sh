#!/usr/bin/env bash
# Self-test of scripts/verify-release.sh (handoff §4.F) with a fake cosign
# and a fake gh on PATH that record their arguments and verify only what a
# fixture "signed": a fake bundle passes when it holds the blob's SHA-256,
# the certificate identity and the issuer it is checked against, as a real
# bundle does; a fake attestation when it holds the file's SHA-256, the
# repository, the signer workflow and the source ref. So a changed file, a
# wrong identity, a wrong issuer or a missing bundle fails as with the real
# tools. Every case that must refuse is shown refusing. Runs the script with
# /bin/sh (dash on Debian and Ubuntu: POSIX only). Offline; needs bash and
# GNU coreutils.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/verify-release.sh"
sh_bin="$(command -v sh)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

repo="tyler-rich/shell-mcp"
workflow=".github/workflows/release-build.yml"
issuer="https://token.actions.githubusercontent.com"
v="0.3.0"
identity="https://github.com/$repo/$workflow@refs/tags/v$v"

# --- PATH: the tools the script may use, and the fakes --------------------------
tools="$work/tools" fakes="$work/fakes"
mkdir -p "$tools" "$fakes"
for t in sh grep awk cut sha256sum cmp cat; do
	ln -s "$(command -v "$t")" "$tools/$t"
done
export FAKE_LOG="$work/fake.log" FAKE_ATTEST="$work/attestations"
cat >"$fakes/cosign" <<'EOF'
#!/bin/sh
echo "cosign $*" >>"$FAKE_LOG"
[ "$1" = verify-blob ] || exit 3
shift
bundle="" id="" iss=""
while [ $# -gt 1 ]; do
	case "$1" in
	--bundle) bundle="$2" ;;
	--certificate-identity) id="$2" ;;
	--certificate-oidc-issuer) iss="$2" ;;
	*) exit 4 ;;
	esac
	shift 2
done
[ "${FAKE_COSIGN_ALWAYS:-}" = 1 ] && exit 0
[ "$(cat "$bundle")" = "$(sha256sum -- "$1" | cut -d' ' -f1) $id $iss" ]
EOF
cat >"$fakes/gh" <<'EOF'
#!/bin/sh
echo "gh $*" >>"$FAKE_LOG"
[ "$1 $2" = "attestation verify" ] || exit 3
f="$3"
shift 3
repo="" signer="" ref=""
while [ $# -gt 1 ]; do
	case "$1" in
	--repo) repo="$2" ;;
	--signer-workflow) signer="$2" ;;
	--source-ref) ref="$2" ;;
	*) exit 4 ;;
	esac
	shift 2
done
[ $# -eq 0 ] || exit 4
[ "${FAKE_GH_ALWAYS:-}" = 1 ] && exit 0
grep -qxF -- "$(sha256sum -- "$f" | cut -d' ' -f1) $repo $signer $ref" "$FAKE_ATTEST"
EOF
chmod 0755 "$fakes/cosign" "$fakes/gh"
mkdir -p "$work/only-cosign" "$work/only-gh"
ln -s "$fakes/cosign" "$work/only-cosign/cosign"
ln -s "$fakes/gh" "$work/only-gh/gh"
path_none="$tools" path_cosign="$work/only-cosign:$tools" path_gh="$work/only-gh:$tools" path_both="$fakes:$tools"

# release <dir> <version> [<identity> [<issuer> [<ref>]]]: release files as the
# workflow makes them (a subset), SHA256SUMS, a bundle for each binary, the
# archive and SHA256SUMS, and an attestation for each listed file.
release() {
	local d="$1" ver="$2" id="${3:-$identity}" iss="${4:-$issuer}" ref="${5:-refs/tags/v$2}" f
	rm -rf "$d"
	mkdir -p "$d"
	for f in "shell-mcp_${ver}_linux_amd64" "shell-mcp-gate_${ver}_linux_amd64" "shell-mcp-privd_${ver}_linux_arm64" \
		"shell-mcp_${ver}_examples.tar.gz" "shell-mcp_${ver}_linux_amd64.cdx.json" LICENSE; do
		printf 'invented content of %s\n' "$f" >"$d/$f"
	done
	(cd "$d" && sha256sum -- * >SHA256SUMS)
	for f in "shell-mcp_${ver}_linux_amd64" "shell-mcp-gate_${ver}_linux_amd64" "shell-mcp-privd_${ver}_linux_arm64" \
		"shell-mcp_${ver}_examples.tar.gz" SHA256SUMS; do
		printf '%s %s %s' "$(sha256sum -- "$d/$f" | cut -d' ' -f1)" "$id" "$iss" >"$d/$f.sigstore.json"
	done
	: >"$FAKE_ATTEST"
	for f in "$d"/*; do
		case "$f" in *.sigstore.json | */SHA256SUMS) continue ;; esac
		echo "$(sha256sum -- "$f" | cut -d' ' -f1) $repo $repo/$workflow $ref" >>"$FAKE_ATTEST"
	done
}

pass=0
fail=0
# expect <name> <want-exit> <path> <needle> <args…>: run the script with PATH
# and look for needle in its output ("" for none).
expect() {
	local name="$1" want="$2" p="$3" needle="$4" out code=0
	shift 4
	: >"$FAKE_LOG"
	out="$(PATH="$p" "$sh_bin" "$script" "$@" 2>&1)" || code=$?
	if [[ "$code" == "$want" ]] && { [[ -z "$needle" ]] || grep -q -F -- "$needle" <<<"$out"; }; then
		echo "ok   $name"
		pass=$((pass + 1))
	else
		echo "FAIL $name (exit $code, want $want; looking for: $needle)"
		sed 's/^/     /' <<<"$out"
		fail=$((fail + 1))
	fi
}
# check <name> <command…>: the command must succeed.
check() {
	local name="$1"
	shift
	if "$@"; then
		echo "ok   $name"
		pass=$((pass + 1))
	else
		echo "FAIL $name"
		fail=$((fail + 1))
	fi
}

r="$work/r"

# --- Usage ------------------------------------------------------------------------
release "$r" "$v"
expect "no arguments" 2 "$path_both" "usage"
for bad in v0.3.0 0.3 0.3.0-rc1 0.3.0+meta "0.3.0 " 0.3.0-dryrun 0.3.0-dryrun.012345 0.3.0-dryrun.XYZ1234; do
	expect "version '$bad' refused" 2 "$path_both" "usage" "$bad" --dir "$r"
done
expect "unknown flag" 2 "$path_both" "usage" "$v" --dir "$r" --verbose
expect "--dir not a directory" 2 "$path_both" "is not a directory" "$v" --dir "$work/absent"
expect "--sums not a file" 2 "$path_both" "is not a file" "$v" --dir "$r" --sums "$work/absent"

# --- No tool -----------------------------------------------------------------------
expect "neither cosign nor gh, no --sums: refused" 1 "$path_none" "neither cosign nor gh is installed" "$v" --dir "$r"
expect "the refusal says how to get one" 1 "$path_none" "pass --sums <file>" "$v" --dir "$r"

# --- cosign ------------------------------------------------------------------------
expect "cosign: a release verifies" 0 "$path_cosign" "every check passed (cosign) for $identity" "$v" --dir "$r"
check "cosign: five bundles checked, each with the tag's identity and GitHub's issuer" \
	test "$(grep -c -F -- "--certificate-identity $identity --certificate-oidc-issuer $issuer " "$FAKE_LOG")" = 5
check "cosign: SHA256SUMS among them" grep -q -F -- "--bundle $r/SHA256SUMS.sigstore.json " "$FAKE_LOG"
check "cosign: never a branch's identity" bash -c '! grep -q refs/heads "$1"' _ "$FAKE_LOG"
check "cosign: no gh call without gh" bash -c '! grep -q "^gh " "$1"' _ "$FAKE_LOG"

# --- gh ------------------------------------------------------------------------------
expect "gh: a release verifies" 0 "$path_gh" "every check passed (gh) for $identity" "$v" --dir "$r"
check "gh: an attestation for each of the six listed files, at the tag" \
	test "$(grep -c -F -- "--repo $repo --signer-workflow $repo/$workflow --source-ref refs/tags/v$v" "$FAKE_LOG")" = 6
check "gh: none for SHA256SUMS (it has none)" bash -c '! grep -q "verify $1/SHA256SUMS " "$2"' _ "$r" "$FAKE_LOG"
expect "cosign and gh: both run" 0 "$path_both" "every check passed (cosign+gh)" "$v" --dir "$r"

# --- Tampering ------------------------------------------------------------------------
gate="shell-mcp-gate_${v}_linux_amd64"
release "$r" "$v"
printf 'x' >>"$r/$gate"
for p in cosign gh; do
	pv="path_$p"
	expect "$p: a changed binary fails its checksum" 1 "${!pv}" "FAIL checksum: $gate does not match SHA256SUMS" "$v" --dir "$r"
done
expect "cosign: a changed binary fails its bundle" 1 "$path_cosign" "FAIL cosign: $gate does not verify" "$v" --dir "$r"
expect "gh: a changed binary has no attestation" 1 "$path_gh" "FAIL gh attestation: $gate" "$v" --dir "$r"

release "$r" "$v"
sed -i "s/^[0-9a-f]\{64\}\(  $gate\)$/$(printf 'a%.0s' $(seq 64))\1/" "$r/SHA256SUMS"
expect "cosign: a changed SHA256SUMS fails the checksum it changed" 1 "$path_cosign" "FAIL checksum: $gate does not match SHA256SUMS" "$v" --dir "$r"
expect "cosign: a changed SHA256SUMS fails its bundle" 1 "$path_cosign" "FAIL cosign: SHA256SUMS does not verify" "$v" --dir "$r"

# A file added with its own consistent line: only SHA256SUMS's bundle catches it.
release "$r" "$v"
printf 'not a release file\n' >"$r/extra_${v}_linux_amd64"
(cd "$r" && sha256sum -- "extra_${v}_linux_amd64" >>SHA256SUMS)
expect "cosign: a line added to SHA256SUMS fails its bundle" 1 "$path_cosign" "FAIL cosign: SHA256SUMS does not verify" "$v" --dir "$r"

release "$r" "$v"
printf 'not a release file\n' >"$r/notes.txt"
expect "a file not listed in SHA256SUMS is refused" 1 "$path_cosign" "FAIL notes.txt: present but not listed in SHA256SUMS" "$v" --dir "$r"

release "$r" "$v"
rm "$r/$gate.sigstore.json"
expect "cosign: a missing bundle is refused" 1 "$path_cosign" "FAIL cosign: $gate: no bundle $gate.sigstore.json" "$v" --dir "$r"

release "$r" "$v" "https://github.com/$repo/$workflow@refs/heads/main"
expect "cosign: a branch's signature (wrong identity) is refused" 1 "$path_cosign" "FAIL cosign: SHA256SUMS does not verify for $identity" "$v" --dir "$r"
release "$r" "$v" "https://github.com/$repo/$workflow@refs/tags/v0.2.0"
expect "cosign: another release's signature is refused" 1 "$path_cosign" "FAIL cosign: $gate does not verify" "$v" --dir "$r"
release "$r" "$v" "$identity" "https://accounts.example.test"
expect "cosign: a wrong issuer is refused" 1 "$path_cosign" "FAIL cosign: SHA256SUMS does not verify" "$v" --dir "$r"
release "$r" "$v" "$identity" "$issuer" refs/heads/main
expect "gh: a branch's attestation is refused" 1 "$path_gh" "FAIL gh attestation: $gate has no provenance" "$v" --dir "$r"

release "$r" "$v"
expect "files of another release are refused" 1 "$path_cosign" "FAIL $gate: not a file of release 0.3.1" 0.3.1 --dir "$r"

# --- --sums ----------------------------------------------------------------------------
release "$r" "$v"
cp "$r/SHA256SUMS" "$work/verified-SHA256SUMS"
expect "--sums: the files match the verified SHA256SUMS" 0 "$path_none" "its signature was checked elsewhere, not here" "$v" --dir "$r" --sums "$work/verified-SHA256SUMS"
expect "--sums: says so in its result" 0 "$path_none" "every check passed (sums)" "$v" --dir "$r" --sums "$work/verified-SHA256SUMS"
expect "--sums: no cosign or gh even when installed" 0 "$path_both" "every check passed (sums)" "$v" --dir "$r" --sums "$work/verified-SHA256SUMS"
check "--sums: cosign and gh not called" test ! -s "$FAKE_LOG"
printf 'x' >>"$r/$gate"
expect "--sums: a changed binary fails" 1 "$path_none" "FAIL checksum: $gate does not match SHA256SUMS" "$v" --dir "$r" --sums "$work/verified-SHA256SUMS"
release "$r" "$v"
cp "$r/SHA256SUMS" "$work/verified-SHA256SUMS"
echo "$(printf 'b%.0s' $(seq 64))  extra" >>"$r/SHA256SUMS"
expect "--sums: a SHA256SUMS in --dir that differs is refused" 1 "$path_none" "SHA256SUMS differs from the verified" "$v" --dir "$r" --sums "$work/verified-SHA256SUMS"
release "$r" "$v"
cp "$r/SHA256SUMS" "$work/verified-SHA256SUMS"
printf 'x\n' >"$r/notes.txt"
expect "--sums: an unlisted file is refused" 1 "$path_none" "FAIL notes.txt: present but not listed" "$v" --dir "$r" --sums "$work/verified-SHA256SUMS"

# --- A dry run's files are never verified ------------------------------------------------
# Signed for its own version and accepted by fakes that pass everything: the
# script still refuses, in every mode (the maintainer's rule, S8-4).
dry="0.0.0-dryrun.0123456"
release "$r" "$dry"
cp "$r/SHA256SUMS" "$work/verified-SHA256SUMS"
export FAKE_COSIGN_ALWAYS=1 FAKE_GH_ALWAYS=1
for m in cosign gh both; do
	pv="path_$m"
	expect "dry run, $m: never verified" 1 "${!pv}" "dry-run files are never verified" "$dry" --dir "$r"
done
expect "dry run, --sums: never verified" 1 "$path_none" "dry-run files are never verified" "$dry" --dir "$r" --sums "$work/verified-SHA256SUMS"
expect "dry run, no tool: never verified" 1 "$path_none" "dry-run files are never verified" "$dry" --dir "$r"
expect "dry run: the checks still run (checksums)" 1 "$path_both" "ok   checksum: shell-mcp-gate_${dry}_linux_amd64" "$dry" --dir "$r"
unset FAKE_COSIGN_ALWAYS FAKE_GH_ALWAYS

# --- The same identity and issuer as the release workflow's own check --------------------
mirror() {
	local a b
	a="$(
		unset identity issuer workflow
		repo="$1" ref="refs/tags/v$v"
		eval "$(grep -E '^(workflow|issuer)=' "$here/release/verify.sh")"
		eval "$(grep -E '^identity=' "$here/release/verify.sh")"
		echo "$identity|$issuer"
	)"
	b="$(
		unset identity issuer workflow repo
		version="$v"
		eval "$(grep -E '^(repo|workflow|issuer)=' "$script")"
		eval "$(grep -E '^identity=' "$script")"
		echo "$identity|$issuer"
	)"
	[[ -n "$a" && "$a" == "$b" && "$a" == "https://github.com/$repo/$workflow@refs/tags/v$v|$issuer" ]]
}
check "the identity and issuer are scripts/release/verify.sh's for a release tag" mirror "$repo"

# --- What it never does ------------------------------------------------------------------
check "no network tool of its own (curl, wget, nc)" bash -c '! grep -Eq "(^|[^a-z])(curl|wget|nc) " "$1"' _ "$script"
check "no sudo, su or pkexec" bash -c '! grep -Eq "(^|[^a-z])(sudo|su|pkexec) " "$1"' _ "$script"
release "$r" "$v"
before="$(cd "$r" && ls -la --time-style=+%s && sha256sum -- *)"
PATH="$path_both" "$sh_bin" "$script" "$v" --dir "$r" >/dev/null 2>&1 || true
after="$(cd "$r" && ls -la --time-style=+%s && sha256sum -- *)"
check "it writes nothing in --dir" test "$before" = "$after"

echo
echo "verify-release self-test: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
