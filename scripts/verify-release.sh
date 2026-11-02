#!/bin/sh
# verify-release.sh: verify the shell-mcp release files in a directory before
# you install any of them (handoff §4.F, README "Verifying a release").
#
#   sh verify-release.sh <version> [--dir <dir>] [--sums <verified SHA256SUMS>]
#
# <version> is the release, X.Y.Z. --dir (default: the current directory)
# holds the files you downloaded: any of the binaries, the examples archive,
# the SBOMs, LICENSE and NOTICE, with SHA256SUMS and the *.sigstore.json
# bundles. Run the script from somewhere else: every file in --dir must be a
# release file.
#
#   - Every file present (but the bundles and SHA256SUMS) must be listed in
#     SHA256SUMS and match its hash, and every binary and archive must be of
#     <version>.
#   - With cosign: SHA256SUMS, each binary and the archive verify against
#     their bundles, signed by release-build.yml at refs/tags/v<version> and
#     GitHub's OIDC issuer (the identity and issuer of
#     scripts/release/verify.sh, which the release workflow runs).
#   - With gh: each listed file has a provenance attestation signed by
#     release-build.yml at refs/tags/v<version> (gh attestation verify).
#   - With both, both run. With neither, --sums <file> names a SHA256SUMS you
#     verified with cosign elsewhere and copied over: the files are checked
#     against it, and only against it. Without cosign, gh or --sums it
#     refuses.
#
# It never downloads anything itself (cosign and gh fetch what their own
# verification needs), never falls back to comparing a hash with what a
# server returns, writes nothing, and needs no root. Exit 0 only when every
# check passed; 1 when any failed or it refused; 2 for usage. A dry run's
# files (X.Y.Z-dryrun.<commit>) are checked and always refused: they are
# never a release. The root of trust is still the README's commands, run once
# with cosign: this script, inside the archive it verifies, cannot vouch for
# itself.
set -eu

repo="tyler-rich/shell-mcp"
workflow=".github/workflows/release-build.yml"
issuer="https://token.actions.githubusercontent.com"

usage() {
	echo "usage: verify-release.sh <version> [--dir <dir>] [--sums <verified SHA256SUMS>]" >&2
	exit 2
}

[ $# -ge 1 ] || usage
version="$1"
shift
dryrun=0
if printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
	:
elif printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+-dryrun\.[0-9a-f]{7,40}$'; then
	dryrun=1
else
	echo "verify-release: '$version' is not a release version X.Y.Z (without the v)" >&2
	usage
fi
if [ "$dryrun" = 1 ]; then
	echo "NOTE $version is a dry run's version: its files are checked and then refused; dry-run files are never verified"
fi
dir="."
sums=""
while [ $# -gt 0 ]; do
	case "$1" in
	--dir)
		[ $# -ge 2 ] || usage
		dir="$2"
		shift 2
		;;
	--sums)
		[ $# -ge 2 ] || usage
		sums="$2"
		shift 2
		;;
	*) usage ;;
	esac
done
[ -d "$dir" ] || {
	echo "verify-release: --dir $dir is not a directory" >&2
	exit 2
}
if [ -n "$sums" ] && [ ! -f "$sums" ]; then
	echo "verify-release: --sums $sums is not a file" >&2
	exit 2
fi
identity="https://github.com/$repo/$workflow@refs/tags/v$version"

have() { command -v "$1" >/dev/null 2>&1; }
if have sha256sum; then
	hash_of() { sha256sum -- "$1" | cut -d' ' -f1; }
elif have shasum; then
	hash_of() { shasum -a 256 -- "$1" | cut -d' ' -f1; }
else
	echo "verify-release: needs sha256sum (GNU coreutils) or shasum" >&2
	exit 1
fi

mode=""
if [ -n "$sums" ]; then
	mode="sums"
else
	have cosign && mode="cosign"
	have gh && mode="${mode:+$mode+}gh"
fi
if [ -z "$mode" ]; then
	echo "verify-release: refused: neither cosign nor gh is installed, and no --sums was given." >&2
	echo "  Install cosign (https://github.com/sigstore/cosign/releases) or the GitHub CLI (https://cli.github.com), or" >&2
	echo "  verify SHA256SUMS with cosign on another machine (README, \"Verifying a release\"), copy it here and pass --sums <file>." >&2
	exit 1
fi

fail=0
ok() { echo "ok   $*"; }
bad() {
	echo "FAIL $*"
	fail=1
}

list="${sums:-$dir/SHA256SUMS}"
if [ ! -f "$list" ]; then
	echo "verify-release: $list is missing: download SHA256SUMS with the files" >&2
	exit 1
fi
if [ "$mode" = sums ]; then
	echo "NOTE --sums: the files are checked against $sums only; its signature was checked elsewhere, not here"
	if [ -f "$dir/SHA256SUMS" ]; then
		if cmp -s "$sums" "$dir/SHA256SUMS"; then
			ok "$dir/SHA256SUMS is the verified one"
		else
			bad "$dir/SHA256SUMS differs from the verified $sums"
		fi
	fi
fi

# SHA256SUMS: "<64 hex> <name>" or "<64 hex> *<name>", one per line, names of
# release files only (no path, no space).
if grep -Evq '^[0-9a-f]{64}  ?\*?[A-Za-z0-9._+-]+$' "$list"; then
	bad "$list has a line that is not '<sha256> <file name>'"
fi
listed_hash() { awk -v f="$1" '{ n = $2; sub(/^\*/, "", n); if (n == f) { print $1; exit } }' "$list"; }

# Every file present, but SHA256SUMS and the bundles, must be listed and match.
present=0
for p in "$dir"/* "$dir"/.[!.]*; do
	[ -e "$p" ] || continue
	f="${p##*/}"
	case "$f" in
	SHA256SUMS | *.sigstore.json) continue ;;
	esac
	if [ ! -f "$p" ]; then
		bad "$f: not a regular file"
		continue
	fi
	present=$((present + 1))
	want="$(listed_hash "$f")"
	if [ -z "$want" ]; then
		bad "$f: present but not listed in SHA256SUMS"
		continue
	fi
	if [ "$(hash_of "$p")" = "$want" ]; then
		ok "checksum: $f"
	else
		bad "checksum: $f does not match SHA256SUMS"
	fi
	case "$f" in
	*_linux_amd64 | *_linux_arm64 | *_examples.tar.gz)
		case "$f" in
		*_"$version"_linux_amd64 | *_"$version"_linux_arm64 | shell-mcp_"$version"_examples.tar.gz) ;;
		*) bad "$f: not a file of release $version" ;;
		esac
		;;
	esac
done
[ "$present" -gt 0 ] || bad "no release file to verify in $dir"

# cosign: SHA256SUMS, each binary and the archive, against their bundles.
case "$mode" in
*cosign*)
	for p in "$dir/SHA256SUMS" "$dir"/*_linux_amd64 "$dir"/*_linux_arm64 "$dir"/*_examples.tar.gz; do
		[ -f "$p" ] || continue
		f="${p##*/}"
		if [ ! -f "$p.sigstore.json" ]; then
			bad "cosign: $f: no bundle $f.sigstore.json"
			continue
		fi
		if cosign verify-blob --bundle "$p.sigstore.json" --certificate-identity "$identity" \
			--certificate-oidc-issuer "$issuer" "$p" >/dev/null 2>&1; then
			ok "cosign: $f"
		else
			bad "cosign: $f does not verify for $identity"
		fi
	done
	[ -f "$dir/SHA256SUMS" ] || bad "cosign: SHA256SUMS is not in $dir: it is what signs the files without a bundle"
	;;
esac

# gh: a provenance attestation for each listed file present.
case "$mode" in
*gh*)
	for p in "$dir"/*; do
		[ -f "$p" ] || continue
		f="${p##*/}"
		case "$f" in
		SHA256SUMS | *.sigstore.json) continue ;;
		esac
		[ -n "$(listed_hash "$f")" ] || continue
		if gh attestation verify "$p" --repo "$repo" --signer-workflow "$repo/$workflow" \
			--source-ref "refs/tags/v$version" >/dev/null 2>&1; then
			ok "gh attestation: $f"
		else
			bad "gh attestation: $f has no provenance from $repo/$workflow at refs/tags/v$version"
		fi
	done
	;;
esac

if [ "$dryrun" = 1 ]; then
	echo "FAIL $version is a dry run: dry-run files are never verified"
	echo "verify-release: REFUSED (a dry run)" >&2
	exit 1
fi
if [ "$fail" -ne 0 ]; then
	echo "verify-release: FAILED: install none of these files" >&2
	exit 1
fi
echo "verify-release: ok: every check passed ($mode) for $identity"
