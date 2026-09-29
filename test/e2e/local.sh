#!/usr/bin/env bash
# Local end-to-end run of the gate and the privileged helper against a real
# systemd, journald and polkit inside a disposable systemd container (the
# CI job "e2e-host" runs the same setup and tests on the runner VM's own
# systemd instead). Needs docker only; builds everything in the pinned Go
# image, copies the binaries into the container (no host path is mounted
# into it), runs test/e2e/setup.sh and the e2e tests as root inside it, and
# removes the container.
#
#   bash test/e2e/local.sh                 # everything
#   bash test/e2e/local.sh -run 'Helper'   # extra arguments go to the test binary
#
# E2E_LANDLOCK (default best-effort here: Docker Desktop's kernel may lack
# the Landlock ABI that `required` needs) is passed to setup.sh.
set -euo pipefail
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")/../.."
repo="$({ pwd -W 2>/dev/null || pwd; })"
here="$repo/test/e2e"
go_image="$(awk 'toupper($1) == "FROM" && $2 ~ /^golang:/ { print $2; exit }' Dockerfile)"
image="shell-mcp-e2e-systemd:local"
name="shell-mcp-e2e-$$"
cache_volume="shell-mcp-ci-cache"
landlock="${E2E_LANDLOCK:-best-effort}"

# --- Build (non-root, in the pinned Go image, into the cache volume) --------
docker volume create "$cache_volume" >/dev/null
docker run --rm -u 0:0 -v "$cache_volume:/cache" "$go_image" \
	sh -c 'mkdir -p /cache/build /cache/mod /cache/e2e-bin && rm -rf /cache/e2e-bin/* && chown -R 65532:65532 /cache/build /cache/mod /cache/e2e-bin'
docker run --rm -u 65532:65532 -e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod \
	-e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local -e CGO_ENABLED=0 \
	-v "$cache_volume:/cache" -v "$repo:/src:ro" -w /src "$go_image" sh -c '
set -e
out=/cache/e2e-bin
go build -trimpath -o $out/shell-mcp-gate ./cmd/shell-mcp-gate
go build -trimpath -o $out/shell-mcp-privd ./cmd/shell-mcp-privd
go build -trimpath -tags shellmcp_e2e_bypass -o $out/shell-mcp-privd-bypass ./cmd/shell-mcp-privd
go build -trimpath -ldflags "-X main.outside=/etc/example-other/secret.txt" -o $out/example-probe ./internal/gate/gatetest/testdata/probe
go test -c -trimpath -tags e2e -o $out/e2e.test ./test/e2e
cp test/e2e/setup.sh $out/setup.sh
chmod 0755 $out/*
echo "e2e: built $(ls $out | tr "\n" " ")"'

# --- Start the systemd container ----------------------------------------------
docker build -q -t "$image" -f "$here/Dockerfile.systemd" "$here" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
# CLAUDE.md cgroup exception (the same recipe as scripts/probe/systemd.sh):
# no --privileged, no added capabilities, no host path mounted; the image is
# built from this repository on a digest-pinned base. systemd must create
# its own cgroup scopes, which it cannot do on Docker's read-only cgroup
# mount, so the host's cgroup2 hierarchy is mounted read-write inside a
# private cgroup namespace. That grants the container write access to the
# host (or VM) cgroup tree: run this on disposable test machines only (a
# workstation's Docker VM, a CI runner). The tmpfs mounts are what systemd
# expects; container=docker lets it detect the container.
docker run -d -t --name "$name" --cgroupns=private \
	-v /sys/fs/cgroup:/sys/fs/cgroup:rw -e container=docker \
	--tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
	"$image" >/dev/null
state="unknown"
for _ in $(seq 1 60); do
	state="$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)"
	case "$state" in running | degraded) break ;; esac
	sleep 1
done
case "$state" in running | degraded) ;; *)
	echo "e2e: systemd did not start in the container (is-system-running=$state)" >&2
	docker logs "$name" 2>&1 | tail -n 20 >&2
	exit 3
	;;
esac

# Copy the binaries in through a tar stream (no host path is mounted).
docker run --rm -v "$cache_volume:/cache:ro" "$go_image" tar -C /cache/e2e-bin -cf - . |
	docker exec -i "$name" sh -c 'mkdir -p /opt/e2e-bin && tar -C /opt/e2e-bin -xf -'

# Can this container run a unit with the core unit's namespacing at all?
# (Docker gives the container no CAP_SYS_ADMIN, which systemd needs to set
# up mount and network namespaces for a unit.)
if ! docker exec "$name" systemd-run --wait --quiet -p ProtectSystem=strict -p PrivateNetwork=yes -p PrivateTmp=yes /usr/bin/true 2>/dev/null; then
	echo "e2e: this container cannot run units with ProtectSystem=/PrivateNetwork=/PrivateTmp= (systemd needs CAP_SYS_ADMIN to set up namespaces);" >&2
	echo "e2e: the helper's core unit cannot start here. The runner-host job runs these tests on a VM's own systemd." >&2
	docker exec "$name" sh -c 'systemd-run --wait -p ProtectSystem=strict /usr/bin/true; journalctl -n 5 --no-pager' >&2 || true
	exit 4
fi

docker exec -e E2E_BIN=/opt/e2e-bin -e E2E_LANDLOCK="$landlock" "$name" bash /opt/e2e-bin/setup.sh
code=0
docker exec -e E2E_BIN=/opt/e2e-bin -e E2E_LANDLOCK="$landlock" -e E2E_SECURITY_MAX="${E2E_SECURITY_MAX:-}" \
	"$name" /opt/e2e-bin/e2e.test -test.v -test.count=1 "$@" || code=$?
docker exec "$name" systemd-analyze security --no-pager shell-mcp-privd@.service | tail -n 3 || true
exit "$code"
