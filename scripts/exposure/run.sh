#!/usr/bin/env bash
# run.sh [--record]: the offline exposure check (handoff N-28). Generates the
# helper's units for the example privileged policy and every end-to-end
# privileged policy (gen.sh, in the Go image), then rates each core unit with
# systemd-analyze security --offline in an image per supported systemd: Debian
# 13 (257), Ubuntu 24.04 (255) and Ubuntu 26.04 (259), pinned by digest in
# Dockerfile. It fails when a core unit scores above the value recorded in
# scores.txt for that image and policy; --record prints the lines to record.
# Needs docker; used by scripts/ci-local.sh and CI. Containers carry a label,
# run as a non-root user; the analysis has no network (the image builds and the
# generator, which downloads Go modules on a cold cache, do).
#
# EXPOSURE_WEAKEN=<policy>:<sed expression> applies the expression to that
# policy's core unit before it is rated, for the check's own negative test
# (run.sh's caller shows the check failing on a weakened unit).
set -euo pipefail
export MSYS_NO_PATHCONV=1

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && { pwd -W 2>/dev/null || pwd; })"
dir_native="$(cd "$here" && { pwd -W 2>/dev/null || pwd; })"
cd "$here/../.."
label="${SHELL_MCP_CI_LOCAL_LABEL:-shell-mcp.ci-local=exposure-$$-$RANDOM}"
# Everything this script creates also carries part, and its cleanup removes
# only that: under ci-local the run label is shared with the steps of the
# other lanes, whose containers must keep running (ci-local removes every
# container of the run label when the run ends).
part="shell-mcp.ci-local.part=exposure-$$-$RANDOM"
record="${1:-}"
case "$record" in "" | --record) ;; *)
	echo "usage: run.sh [--record]" >&2
	exit 2
	;;
esac

go_image="$(awk 'toupper($1) == "FROM" { for (i = 2; i <= NF; i++) if ($i ~ /^golang:/) { print $i; exit } }' Dockerfile)"
if [[ "$go_image" != *@sha256:* ]]; then
	echo "exposure: the Dockerfile's golang builder image is not pinned by digest" >&2
	exit 1
fi
if [[ "$(uname -s)" == Linux ]] && [[ "$(id -u)" != 0 ]]; then
	run_as="$(id -u):$(id -g)"
else
	run_as="65532:65532"
fi
# Under scripts/ci-local.sh: its containers lane's user and Go caches (a
# uid of its own: RLIMIT_NPROC counts per uid, beside the other lanes).
run_as="${SHELL_MCP_CI_RUN_AS:-$run_as}"
ci_cache="${SHELL_MCP_CI_CACHE:-/cache}"
cache_volume="${CI_LOCAL_CACHE_VOLUME:-shell-mcp-ci-cache}"
if [[ "$run_as" == 0:* ]]; then
	echo "exposure: run as a non-root user" >&2
	exit 1
fi

remove_own_containers() {
	local ids
	ids="$(docker ps -aq --filter "label=$part" 2>/dev/null || true)"
	if [[ -n "$ids" ]]; then
		# shellcheck disable=SC2086 # one container id per word
		docker rm -f $ids >/dev/null 2>&1 || true
	fi
}
trap remove_own_containers EXIT

images=(debian13 ubuntu2404 ubuntu2604)
for i in "${images[@]}"; do
	docker build -q --label "$label" --label "$part" --target "$i" -t "shell-mcp-exposure:$i" -f "$dir_native/Dockerfile" "$dir_native" >/dev/null
done

# Standalone (CI), the Go cache volume is created and given to the container
# user, as ci-local does for its own run; under ci-local it already is.
docker volume create "$cache_volume" >/dev/null
if [[ -z "${SHELL_MCP_CI_LOCAL_LABEL:-}" ]]; then
	docker run --rm --label "$label" --label "$part" -u 0:0 -v "$cache_volume":/cache "$go_image" \
		sh -c "mkdir -p /cache/build /cache/mod && chown -R $run_as /cache/build /cache/mod && chown $run_as /cache" >/dev/null
fi

# The generated units, as a tar on stdout of the Go image. The working
# directory is a private tmpfs the container user owns (exec: go run).
units_tar="$(mktemp)"
trap 'rm -f "$units_tar"; remove_own_containers' EXIT
docker run --rm --label "$label" --label "$part" -u "$run_as" \
	-e HOME=/tmp -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local -e GOCACHE="$ci_cache/build" -e GOMODCACHE="$ci_cache/mod" \
	--tmpfs "/work:exec,uid=${run_as%%:*},gid=${run_as##*:},mode=0700" -e TMPDIR=/work \
	-v "$cache_volume":/cache -v "$repo:/src:ro" -w /src "$go_image" \
	bash -c 'bash scripts/exposure/gen.sh /work/out >&2 && tar -C /work/out -cf - .' >"$units_tar"

if [[ -n "${EXPOSURE_WEAKEN:-}" ]]; then
	pol="${EXPOSURE_WEAKEN%%:*}"
	expr="${EXPOSURE_WEAKEN#*:}"
	w="$(mktemp -d)"
	tar -xf "$units_tar" -C "$w"
	sed -i -e "$expr" "$w/$pol/shell-mcp-privd@.service"
	tar -C "$w" -cf "$units_tar" .
	rm -rf "$w"
fi

overall=0
for i in "${images[@]}"; do
	docker run --rm -i --label "$label" --label "$part" -u "$run_as" --network none --read-only \
		--tmpfs "/tmp:uid=${run_as%%:*},gid=${run_as##*:},mode=0700" \
		--tmpfs "/run:uid=${run_as%%:*},gid=${run_as##*:},mode=0755" \
		-v "$repo:/src:ro" "shell-mcp-exposure:$i" \
		bash /src/scripts/exposure/analyze.sh "$i" /src/scripts/exposure/scores.txt ${record:+--record} <"$units_tar" || overall=1
done
exit "$overall"
