#!/usr/bin/env bash
# End-to-end setup for the gate and the privileged helper on a DISPOSABLE
# systemd machine: the GitHub-hosted runner VM (CI job "e2e-host", run
# under sudo there) or the local systemd test container
# (test/e2e/local.sh). Run as root. Never run it on a real host: it
# creates accounts, installs binaries, policies, systemd units and a polkit
# rule, and writes under /etc, /usr/local and /var/lib.
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
for f in shell-mcp-gate shell-mcp-privd shell-mcp-privd-bypass example-probe e2e.test; do
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
install -o root -g root -m 0755 "$bin/shell-mcp-gate" /usr/local/bin/shell-mcp-gate
install -o root -g root -m 0755 -d /usr/local/libexec
install -o root -g root -m 0755 "$bin/shell-mcp-privd" /usr/local/libexec/shell-mcp-privd
install -o root -g root -m 0755 "$bin/example-probe" /usr/local/bin/example-probe
# The test binaries stay in the root-owned input directory.
chown -R root:root "$bin"
chmod 0755 "$bin"

# --- Application directories and the backup store ---------------------------
install -o root -g root -m 0755 -d /etc/example-app /etc/example-other /var/log/example-app
printf 'key: value\n' >/etc/example-app/app.conf
chmod 0640 /etc/example-app/app.conf
printf 'outside\n' >/etc/example-other/secret.txt
chmod 0644 /etc/example-other/secret.txt
install -o root -g root -m 0700 -d /var/lib/shell-mcp /var/lib/shell-mcp/backups

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
  max_tier: destructive
EOF
}
# The gate allows two units and three verbs; the polkit rule is generated
# from a narrower policy (one unit, two verbs), so the tests can show polkit
# refusing what the gate would allow.
gate_policy '"example-app.service", "example-other.service"' 'restart, reload, stop' >/etc/shell-mcp/gate.yaml
gate_policy '"example-app.service"' 'restart, reload' >"$bin/gate-rule.yaml"
chmod 0644 /etc/shell-mcp/gate.yaml "$bin/gate-rule.yaml"

priv_policy() { # priv_policy <extra line for probe-signal>
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
  write: [/etc/example-app]
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
EOF
}
priv_policy '' >"$bin/privileged.yaml"
priv_policy '    capabilities: [CAP_KILL]
' >"$bin/privileged-cap-kill.yaml"
chmod 0600 "$bin/privileged.yaml" "$bin/privileged-cap-kill.yaml"
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
systemctl enable --now shell-mcp-privd.socket
systemctl restart polkit.service 2>/dev/null || systemctl restart polkitd.service 2>/dev/null || true

echo "e2e setup: done (landlock $landlock)"
systemctl --version | head -n1
pkaction --version 2>/dev/null || true
