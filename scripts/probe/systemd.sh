#!/usr/bin/env bash
# Reports whether a systemd-enabled container can boot on this Docker host
# without --privileged (Session 1c's helper e2e needs one). Prints one line;
# exit 0 if systemd reached running or degraded, 3 otherwise.
set -euo pipefail
export MSYS_NO_PATHCONV=1

# Git Bash: pass Windows-style paths to docker (MSYS_NO_PATHCONV disables its
# automatic conversion).
here="$(cd "$(dirname "$0")" && { pwd -W 2>/dev/null || pwd; })"
image="shell-mcp-probe-systemd:local"
name="shell-mcp-probe-systemd-$$"
# The container carries a label, and only containers with it are removed:
# ci-local's run label when ci-local runs this probe, its own otherwise.
label="${SHELL_MCP_CI_LOCAL_LABEL:-shell-mcp.ci-local=probe-$$-$RANDOM}"
remove_own_containers() {
	local ids
	ids="$(docker ps -aq --filter "label=$label" 2>/dev/null || true)"
	if [[ -n "$ids" ]]; then
		# shellcheck disable=SC2086 # one container id per word
		docker rm -f $ids >/dev/null 2>&1 || true
	fi
}

docker build -q -t "$image" -f "$here/Dockerfile.systemd" "$here" >/dev/null
trap remove_own_containers EXIT

# CLAUDE.md cgroup exception. No --privileged, no added capabilities, no other
# host mount; the image is built from this repository on a digest-pinned base.
# systemd must create its own cgroup scopes, which it cannot do on Docker's
# read-only cgroup mount, so the host's cgroup2 hierarchy is mounted
# read-write inside a private cgroup namespace. That grants the container
# write access to the host (or VM) cgroup tree: run this on disposable test
# machines only (a workstation's Docker VM, a CI runner). The tmpfs mounts are
# what systemd expects; container=docker lets it detect the container.
docker run -d -t --name "$name" --label "$label" --cgroupns=private \
	-v /sys/fs/cgroup:/sys/fs/cgroup:rw -e container=docker \
	--tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
	"$image" >/dev/null

state="unknown"
for _ in $(seq 1 30); do
	state="$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)"
	case "$state" in running | degraded) break ;; esac
	sleep 1
done
case "$state" in
running | degraded)
	echo "systemd-container: available (is-system-running=$state; unprivileged, cgroupns=private, rw cgroup2)"
	;;
*)
	echo "systemd-container: unavailable (is-system-running=${state:-none}; container $(docker inspect -f '{{.State.Status}}, exit {{.State.ExitCode}}' "$name" 2>/dev/null || echo gone))"
	echo "  docker: $(docker info --format 'server {{.ServerVersion}}, cgroup driver {{.CgroupDriver}}, cgroup v{{.CgroupVersion}}' 2>/dev/null || echo unknown)"
	echo "  last log lines:"
	docker logs "$name" 2>&1 | tail -n 20 | sed 's/^/  /'
	exit 3
	;;
esac
