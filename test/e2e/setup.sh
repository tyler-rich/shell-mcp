#!/usr/bin/env bash
# Runner-only, checked before anything else runs: this script changes the
# machine, so it refuses unless it is on Linux, under GitHub Actions
# (GITHUB_ACTIONS=true) and on a GitHub-hosted runner
# (RUNNER_ENVIRONMENT=github-hosted). test/e2e/guard_test.sh proves it exits
# at once anywhere else.
if [ "$(uname -s)" != Linux ] || [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
	echo "setup.sh: refusing to run: it changes the machine and runs only on a GitHub-hosted Actions runner (Linux, GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted)" >&2
	exit 64
fi

# End-to-end setup for the gate and the privileged helper on the DISPOSABLE
# GitHub-hosted runner VM (CI job "e2e-host", run under sudo there). Run as
# root. Never run it on a real host: it creates accounts, installs
# binaries, policies, systemd units, a polkit rule and a second sshd, and
# writes under /etc, /usr/local and /var/lib.
#
# Everything here is invented test data. Test identities use the documented
# test id range 4200001-4200009, above distribution, systemd dynamic-user
# and common container id ranges:
#   svc-shell       4200001  the gate's service account (the helper's client_uid)
#   svc-shell-priv  4200002  the helper's socket group
#   svc-other       4200003  a second account in the socket group (the wrong peer)
#   example-app     4200004  an owner the helper may chown to
#
#   E2E_BIN       directory holding the built binaries and this script's inputs
#   E2E_LANDLOCK  required (default) or best-effort, for both policies
set -euo pipefail

bin="${E2E_BIN:?set E2E_BIN to the directory holding the built binaries}"
landlock="${E2E_LANDLOCK:-required}"
case "$landlock" in required | best-effort) ;; *)
	echo "E2E_LANDLOCK must be required or best-effort" >&2
	exit 2
	;;
esac
for f in shell-mcp shell-mcp-gate shell-mcp-privd shell-mcp-privd-bypass example-probe e2e.test; do
	test -x "$bin/$f" || {
		echo "missing $bin/$f" >&2
		exit 2
	}
done

# --- Accounts ----------------------------------------------------------------
getent group svc-shell-priv >/dev/null || groupadd -g 4200002 svc-shell-priv
getent group svc-shell >/dev/null || groupadd -g 4200001 svc-shell
getent passwd svc-shell >/dev/null || useradd -u 4200001 -g svc-shell -G svc-shell-priv,systemd-journal -M -d /home/svc-shell -s /bin/sh svc-shell
getent group svc-other >/dev/null || groupadd -g 4200003 svc-other
getent passwd svc-other >/dev/null || useradd -u 4200003 -g svc-other -G svc-shell-priv -M -d /home/svc-other -s /bin/sh svc-other
getent group example-app >/dev/null || groupadd -g 4200004 example-app
getent passwd example-app >/dev/null || useradd -u 4200004 -g example-app -M -d /nonexistent -s /usr/sbin/nologin example-app
passwd -l svc-shell >/dev/null
passwd -l svc-other >/dev/null

# --- Binaries (root:root 0755) ----------------------------------------------
# The gate and the helper refuse binaries whose directories are group- or
# other-writable (SECURITY §5, D-016). Some CI images ship /usr/local/bin
# and /opt world-writable (0777); make the install directories what a target must
# have. This changes only this disposable machine.
for d in /usr/local /usr/local/bin /opt; do
	chown root:root "$d"
	chmod go-w "$d"
done
install -o root -g root -m 0755 "$bin/shell-mcp-gate" /usr/local/bin/shell-mcp-gate
install -o root -g root -m 0755 -d /usr/local/libexec
install -o root -g root -m 0755 "$bin/shell-mcp-privd" /usr/local/libexec/shell-mcp-privd
install -o root -g root -m 0755 "$bin/example-probe" /usr/local/bin/example-probe
# The test binaries stay in the root-owned input directory.
chown -R root:root "$bin"
chmod 0755 "$bin"

# --- Application directories and the backup store ---------------------------
umount /etc/example-app/e2e-mounted/point 2>/dev/null || true # a rerun: the tmpfs below
install -o root -g root -m 0755 -d /etc/example-app /etc/example-other /var/log/example-app
# A privileged write root under an ancestor of its own, whose directories the
# chain-rule test (priv_exec_chain_test.go) opens one at a time.
install -o root -g root -m 0755 -d /srv/e2e-priv-exec /srv/e2e-priv-exec/root
# A tmpfs mounted inside the privileged write root (priv_delete_tools_test.go):
# the helper's delete never deletes a mount point nor descends into one.
install -o root -g root -m 0755 -d /etc/example-app/e2e-mounted /etc/example-app/e2e-mounted/point
mount -t tmpfs -o size=1m,mode=0755 e2e-priv-delete-mount /etc/example-app/e2e-mounted/point
printf 'on the mount\n' >/etc/example-app/e2e-mounted/point/inside.txt
printf 'key: value\n' >/etc/example-app/app.conf
chmod 0640 /etc/example-app/app.conf
printf 'outside\n' >/etc/example-other/secret.txt
chmod 0644 /etc/example-other/secret.txt
install -o root -g root -m 0700 -d /var/lib/shell-mcp /var/lib/shell-mcp/backups

# --- apt: a local file repository, and nothing else --------------------------
# The package tests must be deterministic and need no internet. Stop
# everything that runs apt on its own (timers, unattended upgrades,
# PackageKit) so nothing else holds the dpkg lock, wait for anything already
# running, and point apt at one local flat repository only (the original
# sources are moved aside on this disposable machine). The tests write the
# repository's index (e2e_test.go, aptRepo); the packages are invented and
# install one text file each. example-hello recommends example-extra, so
# the tests can show --no-install-recommends; example-other is on no
# allow-list.
for u in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service packagekit.service; do
	systemctl stop "$u" 2>/dev/null || true
	systemctl mask "$u" >/dev/null 2>&1 || true
done
for _ in $(seq 1 150); do
	pgrep -x 'apt|apt-get|dpkg|unattended-upgr|packagekitd' >/dev/null || break
	sleep 2
done
install -d -o root -g root -m 0755 /etc/apt/e2e-disabled
find /etc/apt/sources.list.d -maxdepth 1 -type f \( -name '*.list' -o -name '*.sources' \) -exec mv {} /etc/apt/e2e-disabled/ \;
if [ -f /etc/apt/sources.list ]; then mv /etc/apt/sources.list /etc/apt/e2e-disabled/sources.list.orig; fi
install -d -o root -g root -m 0755 /srv/e2e-apt
printf 'deb [trusted=yes] file:/srv/e2e-apt ./\n' >/etc/apt/sources.list.d/e2e-local.list
chmod 0644 /etc/apt/sources.list.d/e2e-local.list
mkdeb() { # mkdeb <name> <version> [<recommends>]
	local d
	d="$(mktemp -d)"
	install -d "$d/DEBIAN" "$d/usr/share/$1"
	printf '%s %s\n' "$1" "$2" >"$d/usr/share/$1/version"
	{
		printf 'Package: %s\nVersion: %s\nArchitecture: all\n' "$1" "$2"
		printf 'Maintainer: shell-mcp end-to-end tests <e2e@example.test>\n'
		if [ -n "${3:-}" ]; then printf 'Recommends: %s\n' "$3"; fi
		printf 'Description: invented package for the shell-mcp end-to-end tests\n'
	} >"$d/DEBIAN/control"
	dpkg-deb --root-owner-group --build "$d" "$bin/debs/${1}_${2}_all.deb" >/dev/null
	rm -rf "$d"
}
install -d -o root -g root -m 0755 "$bin/debs"
mkdeb example-hello 1.0 example-extra
mkdeb example-hello 1.1 example-extra
mkdeb example-extra 1.0
mkdeb example-other 1.0
# The package operations' stop points and results (broad_test.go, S4c-7).
# example-conf has a configuration file, so a removal that never purges is
# visible (config-files). example-slow's postinst sleeps 8 s (an early
# answer, a hang-up). example-slow-a's sleeps 18 s and example-slow-b
# pre-depends on it, so apt configures example-slow-a in a dpkg run of its
# own before it unpacks example-slow-b: a SIGINT during that run stops apt
# before example-slow-b. example-stuck's postinst never ends.
# Both sleeps end at once when /run/shell-mcp-e2e-pkg-fast exists (the
# tests' cleanup). Invented packages; never shipped.
mkdeb_x() { # mkdeb_x <name> <version> <pre-depends> <postinst body> <conffile>
	local d
	d="$(mktemp -d)"
	install -d "$d/DEBIAN" "$d/usr/share/$1"
	printf '%s %s\n' "$1" "$2" >"$d/usr/share/$1/version"
	{
		printf 'Package: %s\nVersion: %s\nArchitecture: all\n' "$1" "$2"
		printf 'Maintainer: shell-mcp end-to-end tests <e2e@example.test>\n'
		if [ -n "$3" ]; then printf 'Pre-Depends: %s\n' "$3"; fi
		printf 'Description: invented package for the shell-mcp end-to-end tests\n'
	} >"$d/DEBIAN/control"
	if [ -n "$4" ]; then
		printf '#!/bin/sh\n%s\n' "$4" >"$d/DEBIAN/postinst"
		chmod 0755 "$d/DEBIAN/postinst"
	fi
	if [ -n "$5" ]; then
		install -d "$d$(dirname "$5")"
		printf 'invented setting\n' >"$d$5"
		printf '%s\n' "$5" >"$d/DEBIAN/conffiles"
	fi
	dpkg-deb --root-owner-group --build "$d" "$bin/debs/${1}_${2}_all.deb" >/dev/null
	rm -rf "$d"
}
wait_fast='i=0; while [ ! -e /run/shell-mcp-e2e-pkg-fast ] && [ $i -lt'
mkdeb_x example-conf 1.0 '' '' /etc/example-conf/example-conf.conf
mkdeb_x example-conf 1.1 '' '' /etc/example-conf/example-conf.conf
mkdeb_x example-slow 1.0 '' "$wait_fast 8 ]; do sleep 1; i=\$((i+1)); done" ''
mkdeb_x example-slow-a 1.0 '' "$wait_fast 18 ]; do sleep 1; i=\$((i+1)); done" ''
mkdeb_x example-slow-b 1.0 example-slow-a '' ''
mkdeb_x example-stuck 1.0 '' "$wait_fast 600 ]; do sleep 1; i=\$((i+1)); done" ''

# --- Policies ---------------------------------------------------------------
install -o root -g root -m 0755 -d /etc/shell-mcp
gate_policy() { # gate_policy <units> <verbs>
	cat <<EOF
version: 1
max_tier: destructive
sandbox:
  landlock: $landlock
paths:
  read: [/etc/example-app]
services:
  status: ["example-*.service"]
  control:
    units: [$1]
    verbs: [$2]
journal:
  units: ["example-app.service"]
  max_lines: 200
privileged:
  enabled: true
  socket: /run/shell-mcp/privd.sock
  broad_socket: /run/shell-mcp/privd-broad.sock
  max_tier: destructive
EOF
}
# The gate allows two units and three verbs; the polkit rule is generated
# from a narrower policy (one unit, two verbs), so the tests can show polkit
# refusing what the gate would allow.
gate_policy '"example-app.service", "example-other.service"' 'restart, reload, stop' >/etc/shell-mcp/gate.yaml
gate_policy '"example-app.service"' 'restart, reload' >"$bin/gate-rule.yaml"
chmod 0644 /etc/shell-mcp/gate.yaml "$bin/gate-rule.yaml"

# The read tools' policy (read_tools_test.go), selected by its own SSH key
# (principal e2e-read). max_tier is operator and it declares one operator
# command, so the tests can show the gate running it at ceiling operator and
# refusing it at the read tool's ceiling (read). Its git remote is never
# contacted: the read ops are local.
cat >/etc/shell-mcp/gate-read.yaml <<EOF
version: 1
max_tier: operator
sandbox:
  landlock: $landlock
paths:
  read: [/srv/example-app]
  deny: ["/srv/example-app/tree/private/**"]
services:
  status: ["example-*.service"]
journal:
  units: ["example-app.service", "example-journal.service"]
  max_lines: 200
git:
  repos:
    - path: /srv/example-app/repo
      remote: https://git.example.test/example-app.git
commands:
  - id: probe-echo
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["echo", "{regex:^[A-Za-z0-9_-]{1,80}\$}"]]
  - id: probe-exit
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["exit", "{int:0-3}"]]
  - id: probe-operator
    path: /usr/local/bin/example-probe
    tier: operator
    templates: [["echo", "operator"]]
  - id: probe-sleep
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["ignore-term", "60s"]]
EOF
chmod 0644 /etc/shell-mcp/gate-read.yaml
/usr/local/bin/shell-mcp-gate check-policy --policy /etc/shell-mcp/gate-read.yaml >/dev/null

# The operator tools' policy (operator_tools_test.go), selected by its own
# SSH key (principal e2e-operator). Two write roots under one read root: a
# work directory and a directory of repositories. services.control allows
# stop, which the polkit rule (from gate-rule.yaml) does not, so the tests
# can show polkit refusing what the gate allows. The git remote is the
# tests' local HTTPS server on the fixed port 44443 (the only TCP port the
# sandbox opens); the second repository's origin is something else, and the third is
# for the git discard tests (discard_exec_test.go). max_tier
# is destructive and it declares a destructive command, so the tests can
# show the gate running it at ceiling destructive and refusing it at the
# operator tool's ceiling.
cat >/etc/shell-mcp/gate-operator.yaml <<EOF
version: 1
max_tier: destructive
sandbox:
  landlock: $landlock
  tcp_connect_ports: [44443]
paths:
  read: [/srv/example-ops]
  write: [/srv/example-ops/work, /srv/example-ops/repos]
services:
  status: ["example-*.service"]
  control:
    units: ["example-app.service"]
    verbs: [restart, stop]
git:
  repos:
    - path: /srv/example-ops/repos/app
      remote: https://127.0.0.1:44443/example-ops.git
    - path: /srv/example-ops/repos/foreign
      remote: https://127.0.0.1:44443/example-ops.git
    - path: /srv/example-ops/repos/discard
      remote: https://127.0.0.1:44443/example-ops.git
commands:
  - id: probe-echo
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["echo", "{regex:^[A-Za-z0-9_-]{1,80}\$}"]]
  - id: probe-stdin
    path: /usr/local/bin/example-probe
    tier: operator
    templates: [["stdin"]]
  - id: probe-exit
    path: /usr/local/bin/example-probe
    tier: operator
    templates: [["exit", "{int:0-3}"]]
  - id: probe-destructive
    path: /usr/local/bin/example-probe
    tier: destructive
    templates: [["echo", "destructive"]]
EOF
chmod 0644 /etc/shell-mcp/gate-operator.yaml
/usr/local/bin/shell-mcp-gate check-policy --policy /etc/shell-mcp/gate-operator.yaml >/dev/null

# The gate hardening tests' policy (gate_hardening_test.go, handoff N-11 and
# N-18), run with --policy straight from the tests (no SSH key): commands
# given a {path:read}, a {path:write} and a cwd under /srv/e2e-gate, whose
# write root the service account owns, and moves within that write root;
# probe-compose has the shape of POLICY §4's `compose -f {path:read}`
# example (the probe echoes it). The listed repository is for the closed
# repository rule (gate_git_chain_test.go, handoff N-20); its origin is the
# operator tests' local HTTPS server. The tests make every directory and
# file beneath it.
rm -rf /srv/e2e-gate
install -o root -g root -m 0755 -d /srv/e2e-gate
install -o svc-shell -g svc-shell -m 0755 -d /srv/e2e-gate/work
cat >/etc/shell-mcp/gate-hardening.yaml <<EOF
version: 1
max_tier: destructive
sandbox:
  landlock: $landlock
  tcp_connect_ports: [44443]
paths:
  read: [/srv/e2e-gate]
  write: [/srv/e2e-gate/work]
  deny: ["/srv/e2e-gate/work/denied/**"]
git:
  repos:
    - path: /srv/e2e-gate/work/git/repo
      remote: https://127.0.0.1:44443/example-ops.git
commands:
  - id: probe-compose
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["echo", "compose", "-f", "{path:read}", "ps", "--format", "json"]]
  - id: probe-cat
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["cat", "{path:read}"], ["cat", "t"], ["echo", "{path:read}"], ["pwd"]]
  - id: probe-put
    path: /usr/local/bin/example-probe
    tier: operator
    templates: [["write", "{path:write}"], ["echo", "{path:write}"]]
EOF
chmod 0644 /etc/shell-mcp/gate-hardening.yaml
/usr/local/bin/shell-mcp-gate check-policy --policy /etc/shell-mcp/gate-hardening.yaml >/dev/null

# The multi-call policy (multicall_test.go, S-MC): commands on this
# machine's own coreutils (on Ubuntu 26.04 the uutils multi-call binary).
# It is not checked here: the tests check it, and before S-MC it is
# refused.
cat >/etc/shell-mcp/gate-multicall.yaml <<EOF
version: 1
max_tier: read
sandbox:
  landlock: $landlock
paths:
  read: [/srv/e2e-gate]
commands:
  - id: mc-chown-version
    path: /usr/bin/chown
    tier: read
    templates: [["--version"]]
  - id: mc-stat-owner
    path: /usr/bin/stat
    tier: read
    templates: [["--format=%U", "{path:read}"]]
EOF
chmod 0644 /etc/shell-mcp/gate-multicall.yaml

# Static read-tool fixtures: a tree with a directory symlink whose target is
# absolute (os.Root refuses to follow it), a file on the built-in deny list
# and one under the policy's deny pattern. Fixtures with token- or key-shaped
# content, the certificate and the git repository are made by the tests.
fx=/srv/example-app
rm -rf "$fx"
install -o root -g root -m 0755 -d "$fx" "$fx/tree" "$fx/tree/sub" "$fx/tree/private" "$fx/certs"
printf 'one\ntwo\nthree\n' >"$fx/tree/sub/file.txt"
printf 'machine example.test\n' >"$fx/tree/.netrc"
printf 'denied by the policy\n' >"$fx/tree/private/note.txt"
chmod 0644 "$fx/tree/sub/file.txt" "$fx/tree/.netrc" "$fx/tree/private/note.txt"
ln -s "$fx/tree/sub" "$fx/tree/abs-link"

# Operator-tool roots: the service account owns the two write roots; a file
# in the read root outside them shows a write being refused. The tests make
# the files and the repositories.
ox=/srv/example-ops
umount "$ox/work/mounted/point" 2>/dev/null || true # a rerun: the tmpfs below
rm -rf "$ox"
install -o root -g root -m 0755 -d "$ox"
install -o svc-shell -g svc-shell -m 0755 -d "$ox/work" "$ox/repos"
printf 'read only\n' >"$ox/readonly.txt"
chmod 0644 "$ox/readonly.txt"
# A tmpfs mounted inside a write root (delete_tools_test.go): the delete
# operations never delete a mount point nor descend into one, so both the
# mount point and the directory holding it are refused.
install -o svc-shell -g svc-shell -m 0755 -d "$ox/work/mounted" "$ox/work/mounted/point"
mount -t tmpfs -o size=1m,mode=0755,uid=4200001,gid=4200001 e2e-delete-mount "$ox/work/mounted/point"
printf 'on the mount\n' >"$ox/work/mounted/point/inside.txt"

# priv_policy <extra line for probe-signal> <extra line for probe-broad> <allow_upgrade>
priv_policy() {
	cat <<EOF
version: 1
client_uid: 4200001
socket_group: svc-shell-priv
max_tier: destructive
sandbox:
  landlock: $landlock
limits:
  default_timeout_s: 30
  max_timeout_s: 60
  max_delete_entries: 100
paths:
  read: [/etc/example-app, /var/log/example-app]
  write: [/etc/example-app, /srv/e2e-priv-exec/root]
  deny: ["/etc/example-app/secrets/**"]
owners:
  users: [root, example-app]
  groups: [root, example-app]
modes:
  max: "0755"
backups:
  keep: 3
commands:
  - id: probe-echo
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["echo", "{regex:^[a-z-]+\$}"]]
  # The chain-rule tests' own commands (priv_exec_chain_test.go), one per
  # unit and tier, so that their requests never meet another test's journal
  # count.
  - id: probe-cat
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["cat", "{path:read}"], ["pwd"], ["echo", "{path:read}"], ["cat", "t"]]
  - id: probe-chain-op
    path: /usr/local/bin/example-probe
    tier: operator
    templates: [["write", "{path:write}"], ["echo", "{path:write}"]]
  - id: probe-broad-cat
    path: /usr/local/bin/example-probe
    tier: read
    unit: broad
    templates: [["cat", "{path:read}"], ["pwd"], ["echo", "{path:read}"], ["cat", "t"]]
  - id: probe-broad-chain-op
    path: /usr/local/bin/example-probe
    tier: operator
    unit: broad
    templates: [["write", "{path:write}"], ["echo", "{path:write}"]]
  - id: probe-root-op
    path: /usr/local/bin/example-probe
    tier: operator
    templates: [["write", "{path:write}"], ["ignore-term", "61s"], ["detach", "62s"]]
  - id: probe-attrs
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["rlimits"], ["procattrs"], ["ignore-term", "60s"]]
  - id: probe-read-outside
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["read-outside"]]
  - id: probe-connect
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["connect", "{int:1-65535}"]]
  - id: probe-signal
    path: /usr/local/bin/example-probe
    tier: operator
$1    templates: [["signal", "{int:2-4194304}"]]
  - id: probe-visible
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["visible", "{int:1-4194304}"]]
  - id: probe-environ
    path: /usr/local/bin/example-probe
    tier: read
    templates: [["read-environ", "{int:1-4194304}"]]
  - id: probe-unix
    path: /usr/local/bin/example-probe
    tier: read
    templates:
      - ["unix-connect", "{enum:/run/dbus/system_bus_socket|/var/run/dbus/system_bus_socket|/run/shell-mcp-e2e.sock}"]
      - ["abstract-connect", "{regex:^[a-z0-9-]{1,64}\$}"]
  - id: probe-broad
    path: /usr/local/bin/example-probe
    tier: read
    unit: broad
$2    templates:
      - ["echo", "{regex:^[a-z-]+\$}"]
      - ["connect", "{int:1-65535}"]
      - ["unix-connect", "{enum:/run/dbus/system_bus_socket|/var/run/dbus/system_bus_socket|/run/shell-mcp-e2e.sock}"]
      - ["abstract-connect", "{regex:^[a-z0-9-]{1,64}\$}"]
      - ["status"]
      - ["rlimits"]
      - ["procattrs"]
      - ["ignore-term", "60s"]
      - ["drop-ignore-term", "4200004", "60s"]
  - id: probe-broad-op
    path: /usr/local/bin/example-probe
    tier: operator
    unit: broad
    templates: [["write", "{path:write}"], ["ignore-term", "63s"], ["detach", "64s"]]
power:
  allowed: [reboot]
  acknowledge: "e2e: priv_power is called only with reboot.target and poweroff.target runtime-masked"
packages:
  enabled: true
  manager: apt
  install: [example-hello, example-conf, example-slow, example-slow-a, example-slow-b, example-stuck]
  remove: [example-hello, example-conf]
  allow_update_index: true
  allow_upgrade: $3
EOF
}
priv_policy '' '' false >"$bin/privileged.yaml"
priv_policy '    capabilities: [CAP_KILL]
' '' false >"$bin/privileged-cap-kill.yaml"
priv_policy '' '    capabilities: [CAP_SYS_TIME]
' false >"$bin/privileged-sys-time.yaml"
priv_policy '' '' true >"$bin/privileged-upgrade.yaml"
# Short limits for the package stop points (broad_test.go): max_timeout_s 24
# gives a 6 s stop allowance, so SIGINT at 18 s and the kill at 24 s.
priv_policy '' '' true | sed 's/^  default_timeout_s: 30$/  default_timeout_s: 10/; s/^  max_timeout_s: 60$/  max_timeout_s: 24/' >"$bin/privileged-pkgstage.yaml"
# The smallest backup store cap (64 MiB), for the store-cap test.
priv_policy '' '' false | sed 's/^  keep: 3$/  keep: 3\n  max_store_bytes: 67108864/' >"$bin/privileged-small-store.yaml"
# PRIVILEGED §6's worked chown example on this machine's own coreutils
# (multicall_test.go, S-MC), and chown's version, in the core unit.
priv_policy '' '' false | awk '{ print } /^commands:$/ && !done { done = 1
	print "  - id: mc-chown"
	print "    path: /usr/bin/chown"
	print "    tier: operator"
	print "    description: \"give mc-owned to example-app\""
	print "    templates: [[\"--no-dereference\", \"example-app:example-app\", \"/srv/e2e-priv-exec/root/mc-owned\"]]"
	print "  - id: mc-chown-version"
	print "    path: /usr/bin/chown"
	print "    tier: read"
	print "    templates: [[\"--version\"]]" }' >"$bin/privileged-multicall.yaml"
chmod 0600 "$bin"/privileged*.yaml
install -o root -g root -m 0600 "$bin/privileged.yaml" /etc/shell-mcp/privileged.yaml

# --- Placeholder units ------------------------------------------------------
for app in example-app example-other; do
	cat >"/etc/systemd/system/$app.service" <<EOF
[Unit]
Description=Placeholder application for the shell-mcp end-to-end tests

[Service]
ExecStartPre=/usr/bin/echo $app starting
ExecStart=/usr/bin/sleep infinity

[Install]
WantedBy=multi-user.target
EOF
	chmod 0644 "/etc/systemd/system/$app.service"
done

# --- Helper units and polkit rule -------------------------------------------
/usr/local/libexec/shell-mcp-privd check-policy --policy /etc/shell-mcp/privileged.yaml
/usr/local/libexec/shell-mcp-privd units --policy /etc/shell-mcp/privileged.yaml --out /etc/systemd/system
/usr/local/bin/shell-mcp-gate polkit --policy "$bin/gate-rule.yaml" --user svc-shell >/etc/polkit-1/rules.d/60-shell-mcp.rules
chmod 0644 /etc/polkit-1/rules.d/60-shell-mcp.rules

systemctl daemon-reload
systemctl enable --now example-app.service example-other.service
systemctl enable --now shell-mcp-privd.socket shell-mcp-privd-broad.socket
systemctl restart polkit.service 2>/dev/null || systemctl restart polkitd.service 2>/dev/null || true

# --- A dedicated test sshd for the server's SSH client ----------------------
# A second sshd, on 127.0.0.1:2222 only, with its own configuration, host
# keys and keys file, so the machine's own sshd is untouched. It has an
# Ed25519 and an ECDSA host key (the client must negotiate the pinned type),
# and two client keys for svc-shell, each with restrict, from= and the gate
# as its forced command: one usable from 127.0.0.1, one only from
# 192.0.2.1 (TEST-NET-1, never this machine). The directives follow
# SECURITY §5 and are checked with `sshd -t` against this machine's OpenSSH.
if [ -x /usr/sbin/sshd ]; then
	sd=/etc/shell-mcp-e2e-sshd
	install -o root -g root -m 0755 -d "$sd" "$sd/authorized_keys.d"
	rm -f "$sd"/ssh_host_* "$bin"/e2e-client-key*
	ssh-keygen -q -t ed25519 -N '' -C e2e-host-ed25519 -f "$sd/ssh_host_ed25519_key"
	ssh-keygen -q -t ecdsa -b 256 -N '' -C e2e-host-ecdsa -f "$sd/ssh_host_ecdsa_key"
	ssh-keygen -q -t ed25519 -N '' -C e2e-client -f "$bin/e2e-client-key"
	ssh-keygen -q -t ed25519 -N '' -C e2e-client-other-from -f "$bin/e2e-client-key-other-from"
	ssh-keygen -q -t ed25519 -N '' -C e2e-client-read -f "$bin/e2e-client-key-read"
	ssh-keygen -q -t ed25519 -N '' -C e2e-client-operator -f "$bin/e2e-client-key-operator"
	chmod 0600 "$bin/e2e-client-key" "$bin/e2e-client-key-other-from" "$bin/e2e-client-key-read" "$bin/e2e-client-key-operator"
	forced='command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/gate.yaml --principal e2e-ssh"'
	forced_read='command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/gate-read.yaml --principal e2e-read"'
	forced_operator='command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/gate-operator.yaml --principal e2e-operator"'
	{
		printf 'restrict,from="127.0.0.1",%s %s\n' "$forced" "$(cut -d' ' -f1,2 "$bin/e2e-client-key.pub")"
		printf 'restrict,from="192.0.2.1",%s %s\n' "$forced" "$(cut -d' ' -f1,2 "$bin/e2e-client-key-other-from.pub")"
		printf 'restrict,from="127.0.0.1",%s %s\n' "$forced_read" "$(cut -d' ' -f1,2 "$bin/e2e-client-key-read.pub")"
		printf 'restrict,from="127.0.0.1",%s %s\n' "$forced_operator" "$(cut -d' ' -f1,2 "$bin/e2e-client-key-operator.pub")"
	} >"$sd/authorized_keys.d/svc-shell"
	chmod 0644 "$sd/authorized_keys.d/svc-shell"
	printf '%s\n' \
		'Port 2222' \
		'ListenAddress 127.0.0.1' \
		"HostKey $sd/ssh_host_ed25519_key" \
		"HostKey $sd/ssh_host_ecdsa_key" \
		'PidFile /run/shell-mcp-e2e-sshd.pid' \
		"AuthorizedKeysFile $sd/authorized_keys.d/%u" \
		'AllowUsers svc-shell' \
		'AuthenticationMethods publickey' \
		'PubkeyAuthentication yes' \
		'PasswordAuthentication no' \
		'KbdInteractiveAuthentication no' \
		'UsePAM yes' \
		'StrictModes yes' \
		'PermitRootLogin no' \
		'PermitTTY no' \
		'AllowTcpForwarding no' \
		'AllowStreamLocalForwarding no' \
		'AllowAgentForwarding no' \
		'X11Forwarding no' \
		'PermitTunnel no' \
		'PermitUserRC no' \
		'MaxSessions 8' \
		'LogLevel VERBOSE' >"$sd/sshd_config"
	chmod 0644 "$sd/sshd_config"
	install -o root -g root -m 0755 -d /run/sshd
	/usr/sbin/sshd -t -f "$sd/sshd_config"
	systemctl stop shell-mcp-e2e-sshd.service 2>/dev/null || true
	systemd-run --quiet --unit=shell-mcp-e2e-sshd --collect /usr/sbin/sshd -D -e -f "$sd/sshd_config"
	for _ in $(seq 1 50); do
		ss -ltn | grep -q '127.0.0.1:2222 ' && break
		sleep 0.2
	done
	# Not fatal here: the server SSH tests then fail under E2E_REQUIRE_ALL
	# (the CI job), and the other tests still run and report.
	if ss -ltn | grep -q '127.0.0.1:2222 '; then
		echo "e2e setup: test sshd on 127.0.0.1:2222 ($(/usr/sbin/sshd -V 2>&1 | head -n1))"
	else
		echo "e2e setup: the test sshd did not start" >&2
		journalctl --no-pager -n 30 -u shell-mcp-e2e-sshd.service >&2 || true
	fi
else
	echo "e2e setup: no /usr/sbin/sshd; the server SSH tests will skip (or fail under E2E_REQUIRE_ALL)"
fi

echo "e2e setup: done (landlock $landlock)"
systemctl --version | head -n1
pkaction --version 2>/dev/null || true
