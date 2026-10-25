#!/usr/bin/env bash
# release/version.sh: the version a release run builds, from how it started.
#   tag          REF is the tag; it must be vX.Y.Z (no suffix, no leading
#                zeros); prints "X.Y.Z X.Y.Z" (the build's version, then the
#                CHANGELOG section it needs).
#   dispatch     REF is the dry run's requested version X.Y.Z; prints
#                "X.Y.Z-dryrun.<commit> X.Y.Z".
#   pull_request REF is ignored; prints "0.0.0-dryrun.<commit> -" (no
#                CHANGELOG section is needed).
#
#   bash scripts/release/version.sh MODE REF COMMIT
set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 tag|dispatch|pull_request REF COMMIT" >&2
	exit 2
fi
mode="$1" ref="$2" commit="$3"
semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
if ! [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
	echo "release version: commit '$commit' is not a full commit id" >&2
	exit 1
fi
short="${commit:0:7}"
case "$mode" in
tag)
	if ! [[ "$ref" =~ ^v${semver}$ ]]; then
		echo "release version: tag '$ref' is not vX.Y.Z (a release tag has no suffix and no leading zeros)" >&2
		exit 1
	fi
	echo "${ref#v} ${ref#v}"
	;;
dispatch)
	if ! [[ "$ref" =~ ^${semver}$ ]]; then
		echo "release version: requested version '$ref' is not X.Y.Z" >&2
		exit 1
	fi
	echo "${ref}-dryrun.${short} ${ref}"
	;;
pull_request)
	echo "0.0.0-dryrun.${short} -"
	;;
*)
	echo "release version: unknown mode '$mode'" >&2
	exit 2
	;;
esac
