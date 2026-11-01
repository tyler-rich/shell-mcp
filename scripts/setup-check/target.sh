#!/usr/bin/env bash
# target.sh <command> …: runs inside a setup-check target container, as the
# container's own root (scripts/setup-check/run.sh starts it, unprivileged,
# with Docker's default capabilities and the repository read-only at /src).
# It changes only that throwaway container. Every name, id and address is a
# placeholder (TARGET-SETUP's svc-shell 60123, svc-shell-priv 60124); the
# policies are invented for the test and use landlock: best-effort, because
# a CI kernel may lack Landlock ABI 4.
#
#   prepare            install the binaries copied to /opt/setup-check and
#                      the test policies (TARGET-SETUP §3, §5)
#   snapshot           a hash of every path's type, mode, owner, size and
#                      mtime, for the dry-run comparison
#   temps              every install temp file left anywhere
#   hand <from> <key>  TARGET-SETUP §4, §7 and §8 by hand, for the operator
#                      policy and the key file <key>
#   hand-units         TARGET-SETUP §9.2 by hand (units --out, the store)
#   break <case>       set up one refusal case of TARGET-SETUP §12.1
set -euo pipefail

bin=/opt/setup-check

policies() {
	install -o root -g root -m 0755 -d /etc/shell-mcp /srv/setup-check
	cat >/etc/shell-mcp/read-only.yaml <<'EOF'
# setup-check test policy (invented): read-only.
version: 1
max_tier: read
sandbox:
  landlock: best-effort
paths:
  read: [/srv/setup-check]
EOF
	cat >/etc/shell-mcp/operator.yaml <<'EOF'
# setup-check test policy (invented): service control and the journal.
version: 1
max_tier: operator
sandbox:
  landlock: best-effort
paths:
  read: [/srv/setup-check]
services:
  status: ["example-app.service"]
  control:
    units: ["example-app.service"]
    verbs: [restart]
journal:
  units: ["example-app.service"]
EOF
	cat >/etc/shell-mcp/admin.yaml <<'EOF'
# setup-check test policy (invented): forwarding to the helper.
version: 1
max_tier: read
sandbox:
  landlock: best-effort
paths:
  read: [/srv/setup-check]
privileged:
  enabled: true
  socket: /run/shell-mcp/privd.sock
  max_tier: read
EOF
	cat >/etc/shell-mcp/privileged.yaml <<'EOF'
# setup-check test policy (invented): the helper's.
version: 1
client_uid: 60123
socket_group: svc-shell-priv
max_tier: read
sandbox:
  landlock: best-effort
paths:
  read: [/srv/setup-check]
EOF
	chmod 0644 /etc/shell-mcp/read-only.yaml /etc/shell-mcp/operator.yaml /etc/shell-mcp/admin.yaml
	chmod 0600 /etc/shell-mcp/privileged.yaml
}

case "${1:-}" in
prepare)
	# TARGET-SETUP §3.
	install -o root -g root -m 0755 "$bin/shell-mcp-gate" /usr/local/bin/shell-mcp-gate
	install -o root -g root -m 0755 -d /usr/local/libexec
	install -o root -g root -m 0755 "$bin/shell-mcp-privd" /usr/local/libexec/shell-mcp-privd
	install -o root -g root -m 0755 "$bin/shell-mcp" /usr/local/bin/shell-mcp
	# Some images ship /usr/local group-writable; a target must not.
	chmod go-w /usr/local /usr/local/bin
	policies
	# sshd -t and sshd -D need the privilege separation directory.
	install -o root -g root -m 0755 -d /run/sshd
	;;
snapshot)
	find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run/sshd.pid \) -prune -o -printf '%p|%y|%m|%U|%G|%s|%T@\n' |
		LC_ALL=C sort | sha256sum | cut -d' ' -f1
	;;
temps)
	find / -xdev \( -path /proc -o -path /sys \) -prune -o -name '.*.shell-mcp-*' -print
	;;
hand)
	from="${2:?from}"
	key="$(cut -d' ' -f1,2 "${3:?key file}")"
	# TARGET-SETUP §4, as written there (usermod -L since S8-1).
	groupadd --gid 60123 svc-shell
	useradd --uid 60123 --gid svc-shell --home-dir /var/lib/svc-shell --create-home --shell /bin/sh svc-shell 2>/dev/null
	usermod -L svc-shell
	usermod -aG systemd-journal svc-shell
	mkdir -p /etc/systemd/system/user-60123.slice.d
	printf '[Slice]\nMemoryMax=4G\nMemorySwapMax=0\n' >/etc/systemd/system/user-60123.slice.d/50-shell-mcp.conf
	# TARGET-SETUP §7.
	install -o root -g root -m 0755 -d /etc/ssh/authorized_keys.d
	cat >/etc/ssh/sshd_config.d/60-shell-mcp.conf <<'EOF'
Match User svc-shell
    AuthorizedKeysFile /etc/ssh/authorized_keys.d/%u
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitTTY no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserRC no
    MaxSessions 8
EOF
	echo "restrict,from=\"$from\",command=\"/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/operator.yaml --principal operator\" $key shell-mcp-operator" \
		>/etc/ssh/authorized_keys.d/svc-shell
	# TARGET-SETUP §8.
	shell-mcp-gate polkit --policy /etc/shell-mcp/operator.yaml --user svc-shell >/tmp/60-shell-mcp.rules
	install -o root -g root -m 0644 /tmp/60-shell-mcp.rules /etc/polkit-1/rules.d/60-shell-mcp.rules
	;;
hand-units)
	# TARGET-SETUP §9.2.
	/usr/local/libexec/shell-mcp-privd units --policy /etc/shell-mcp/privileged.yaml --out /etc/systemd/system >/dev/null
	install -o root -g root -m 0700 -d /var/lib/shell-mcp /var/lib/shell-mcp/backups
	;;
break)
	case "${2:?case}" in
	docker-group)
		groupadd --gid 1999 docker 2>/dev/null || true
		groupadd --gid 60123 svc-shell
		useradd --uid 60123 --gid svc-shell --home-dir /var/lib/svc-shell --create-home --shell /bin/sh svc-shell 2>/dev/null
		usermod -aG docker svc-shell
		;;
	uid-in-use) useradd --uid 60123 --no-create-home --shell /usr/sbin/nologin example-app 2>/dev/null ;;
	keys-world-writable)
		install -o root -g root -m 0755 -d /etc/ssh/authorized_keys.d
		: >/etc/ssh/authorized_keys.d/svc-shell
		chmod 0666 /etc/ssh/authorized_keys.d/svc-shell
		;;
	strictmodes-no) printf 'StrictModes no\n' >/etc/ssh/sshd_config.d/10-setup-check.conf ;;
	match-wins) printf 'Match User svc-shell\n    PermitTTY yes\n' >/etc/ssh/sshd_config.d/10-setup-check.conf ;;
	line-without-restrict)
		install -o root -g root -m 0755 -d /etc/ssh/authorized_keys.d
		ssh-keygen -q -t ed25519 -N '' -C hand-added -f /tmp/hand-added
		echo "from=\"192.0.2.10\",command=\"/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/read-only.yaml\" $(cat /tmp/hand-added.pub)" \
			>/etc/ssh/authorized_keys.d/svc-shell
		;;
	policy-with-space) cp /etc/shell-mcp/read-only.yaml "/etc/shell-mcp/read only.yaml" ;;
	privileged-0644) chmod 0644 /etc/shell-mcp/privileged.yaml ;;
	*)
		echo "target.sh: unknown case $2" >&2
		exit 2
		;;
	esac
	;;
*)
	echo "usage: target.sh prepare|snapshot|temps|hand <from> <key>|hand-units|break <case>" >&2
	exit 2
	;;
esac
