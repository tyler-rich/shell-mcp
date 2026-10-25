#!/usr/bin/env bash
# release/build.sh: build the release files into OUTDIR.
#   - shell-mcp, shell-mcp-gate and shell-mcp-privd for linux/amd64 and
#     linux/arm64, named <binary>_<version>_linux_<arch>; each one must pass
#     scripts/release-binary-check.sh;
#   - shell-mcp_<version>_examples.tar.gz: examples/, deploy/, LICENSE and
#     NOTICE under shell-mcp_<version>/, reproducible (sorted names, the
#     commit's time, owner 0:0);
#   - LICENSE and NOTICE.
# SBOMs and SHA256SUMS are added by the release workflow.
#
#   bash scripts/release/build.sh VERSION COMMIT OUTDIR
#
# The binaries are built exactly as the Dockerfile builds the image's
# shell-mcp (the release workflow checks that they are byte-identical):
# CGO_ENABLED=0, -trimpath, -buildvcs=false, and these ldflags. Needs go
# (GOTOOLCHAIN=local, so the go.mod toolchain is the one installed), git and
# GNU tar.
set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 VERSION COMMIT OUTDIR" >&2
	exit 2
fi
version="$1" commit="$2" out="$3"
# A release version, or a dry run's <version>-dryrun.<commit>.
if ! [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-dryrun\.[0-9a-f]{7,40})?$ ]]; then
	echo "release build: version '$version' is neither X.Y.Z nor X.Y.Z-dryrun.<commit>" >&2
	exit 2
fi
if ! [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
	echo "release build: commit '$commit' is not a full commit id" >&2
	exit 2
fi

repo="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
if [[ -n "$(ls -A "$out")" ]]; then
	echo "release build: $out is not empty" >&2
	exit 2
fi
cd "$repo"
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly

go mod verify
ldflags="-s -w -X main.version=${version} -X main.commit=${commit}"
for arch in amd64 arm64; do
	for c in shell-mcp shell-mcp-gate shell-mcp-privd; do
		bin="$out/${c}_${version}_linux_${arch}"
		CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$bin" "./cmd/$c"
		bash scripts/release-binary-check.sh "$bin"
	done
done

# The archive's times are the commit's, so the same commit gives the same
# bytes. SOURCE_DATE_EPOCH, when set, is used instead (ci-local's snapshot
# build reads the time on the host, where the checkout's git is).
epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct "$commit")}"
prefix="shell-mcp_${version}"
# Staged so that the modes are fixed (directories 0755, files 0644) whatever
# the checkout's are.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/$prefix"
cp -R examples deploy LICENSE NOTICE "$stage/$prefix/"
find "$stage/$prefix" -type d -exec chmod 0755 {} +
find "$stage/$prefix" -type f -exec chmod 0644 {} +
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
	-C "$stage" -cf - "$prefix" | gzip -n -9 >"$out/${prefix}_examples.tar.gz"
cp LICENSE NOTICE "$out/"
chmod 0644 "$out/LICENSE" "$out/NOTICE" "$out/${prefix}_examples.tar.gz"
chmod 0755 "$out"/*_linux_*
ls -l "$out"
