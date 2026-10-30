#!/usr/bin/env bash
# gen.sh <out dir>: write the generated units of the example privileged policy
# and of every end-to-end privileged policy into <out dir>/<policy>/, for the
# offline exposure check (run.sh). Runs in the Go image, as a non-root user, in
# a private working directory; it writes only below <out dir> and that
# directory, and runs nothing from the policies.
#
# The end-to-end policies are not copied: the block of test/e2e/setup.sh
# between its BEGIN and END privileged-policies lines is evaluated, with
# $bin and $landlock set, so they cannot drift from the policies the e2e job
# installs. (That block only writes $bin/privileged*.yaml; setup.sh itself,
# which changes the machine, is never run here.) The two binaries those
# policies name that this image lacks, the end-to-end probe and jq, are
# replaced by the probe built here: a unit does not depend on which program
# a command runs, only on its declarations.
set -euo pipefail

out="${1:?usage: gen.sh <out dir>}"
repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"

work="$(mktemp -d "${TMPDIR:-/tmp}/exposure.XXXXXX")"
trap 'rm -rf "$work"' EXIT
chmod 0700 "$work"
bin="$work/bin"
mkdir -p "$bin" "$work/pol"

block="$(sed -n '/^# BEGIN privileged-policies/,/^# END privileged-policies/p' test/e2e/setup.sh)"
case "$block" in *'# END privileged-policies'*) ;; *)
	echo "gen.sh: test/e2e/setup.sh lacks the privileged-policies block" >&2
	exit 1
	;;
esac
landlock=required
eval "$block"

go build -o "$work/example-probe" ./internal/gate/gatetest/testdata/probe
cp examples/privileged/privileged.yaml "$work/pol/example.yaml"
for f in "$bin"/privileged*.yaml; do
	n="${f##*/privileged}"
	n="e2e${n%.yaml}"
	sed -e "s#/usr/local/bin/example-probe#$work/example-probe#" -e "s#/usr/bin/jq#$work/example-probe#" "$f" >"$work/pol/$n.yaml"
done

mkdir -p "$out"
pols="$(printf '%s:' "$work"/pol/*.yaml)"
EXPOSURE_OUT="$out" EXPOSURE_POLICIES="${pols%:}" go test -count=1 -v -run TestGenerateUnits ./scripts/exposure/gen >&2
