#!/usr/bin/env bash
# target.sh <command> …: runs inside a setup-check target container, as the
# container's own root (scripts/setup-check/run.sh starts it, unprivileged,
# with Docker's default capabilities and the repository read-only at /src).
# It changes only that throwaway container. Every name, id and address is a
# placeholder (TARGET-SETUP's svc-shell 60123, svc-shell-priv 60124,
# svc-shell-std 60125, and svc-shell-ops 60126 for a third account); the
# policies are invented for the test and use landlock: best-effort, because
# a CI kernel may lack Landlock ABI 4.
#
#   prepare            install the binaries copied to /opt/setup-check and
#                      the test policies (TARGET-SETUP §3, §5)
#   prepare-bare       the binaries only (policy new writes the policies)
#   app                the examples' example-app account and directories
#   answers <preset> <landlock>
#                      the example answers at /root/<preset>.yaml
#   bad-answers <case> answers policy new must refuse, at /root/bad-<case>.yaml
#   snapshot           a hash of every path's type, mode, owner, size and
#                      mtime, for the dry-run comparison
#   temps              every install temp file left anywhere
#   hand <from> <key>  TARGET-SETUP §4, §7 and §8 by hand, for the operator
#                      policy and the key file <key>
#   hand-shared <from> <admin.pub> <ro.pub>
#                      0.2.0's shared layout by hand: svc-shell in the
#                      socket group with the admin and read-only keys
#   hand-split <from> <op.pub>
#                      PR #90's hand steps on it: svc-shell-std 60125, its
#                      block, the service key, the read-only line moved,
#                      its polkit rule
#   state              the managed files and account entries, to compare
#   hup-sshd           SIGHUP to sshd -D (the reload, without systemd)
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
	cat >/etc/shell-mcp/service.yaml <<'EOF'
# setup-check test policy (invented): service control without the journal,
# so that it shares an account with read-only.yaml (an account's keys agree
# on systemd-journal: TARGET-SETUP §4).
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
	chmod 0644 /etc/shell-mcp/read-only.yaml /etc/shell-mcp/operator.yaml /etc/shell-mcp/service.yaml /etc/shell-mcp/admin.yaml
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
prepare-bare)
	# TARGET-SETUP §3 only: no /etc/shell-mcp and no policy, which policy
	# new writes (POLICY §9).
	install -o root -g root -m 0755 "$bin/shell-mcp-gate" /usr/local/bin/shell-mcp-gate
	install -o root -g root -m 0755 -d /usr/local/libexec
	install -o root -g root -m 0755 "$bin/shell-mcp-privd" /usr/local/libexec/shell-mcp-privd
	install -o root -g root -m 0755 "$bin/shell-mcp" /usr/local/bin/shell-mcp
	chmod go-w /usr/local /usr/local/bin
	install -o root -g root -m 0755 -d /run/sshd
	;;
app)
	# The examples' application account and directories (placeholders), which
	# the admin answers' owners and roots name.
	groupadd --gid 1001 example-app
	useradd --uid 1001 --gid example-app --no-create-home --shell /usr/sbin/nologin example-app
	install -o root -g root -m 0755 -d /srv/app /srv/app/config /srv/app/deploy /srv/app/cache /etc/example-app /etc/example-app/conf.d \
		/var/log/example-app /etc/systemd/system/example-app.service.d
	;;
answers)
	# /root/<preset>.yaml: examples/policies/<preset>.answers.yaml, with
	# landlock: best-effort added when $3 says so (a kernel without ABI 4).
	cp "/src/examples/policies/${2:?preset}.answers.yaml" "/root/$2.yaml"
	if [ "${3:?landlock}" = best-effort ]; then printf 'landlock: best-effort\n' >>"/root/$2.yaml"; fi
	chmod 0600 "/root/$2.yaml"
	;;
bad-answers)
	# /root/bad-<case>.yaml: answers each command must refuse before writing.
	case "${2:?case}" in
	gate-protected) printf 'preset: operator\naccount: { user: svc-shell, uid: 60123 }\nwrite: [/etc/ssh]\n' ;;
	root-never) printf 'preset: admin\naccount: { user: svc-shell, uid: 60123 }\nroot:\n  socket_group: { name: svc-shell-priv, gid: 60124 }\n  write: [/etc/ssh]\n' ;;
	root-no-acknowledge) printf 'preset: admin\naccount: { user: svc-shell, uid: 60123 }\nroot:\n  socket_group: { name: svc-shell-priv, gid: 60124 }\n  power: { allowed: [reboot] }\n' ;;
	*)
		echo "target.sh: unknown case $2" >&2
		exit 2
		;;
	esac >"/root/bad-$2.yaml"
	chmod 0600 "/root/bad-$2.yaml"
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
hand-shared)
	# 0.2.0's TARGET-SETUP §4 and §7 as written then: one account for every
	# key, in the helper's socket group, with the admin key (forwarding) and
	# the read-only key. No journal or polkit: neither policy needs one.
	from="${2:?from}"
	admin="$(cut -d' ' -f1,2 "${3:?admin key file}")"
	ro="$(cut -d' ' -f1,2 "${4:?read-only key file}")"
	groupadd --gid 60123 svc-shell
	useradd --uid 60123 --gid svc-shell --home-dir /var/lib/svc-shell --create-home --shell /bin/sh svc-shell 2>/dev/null
	usermod -L svc-shell
	groupadd --gid 60124 svc-shell-priv
	usermod -aG svc-shell-priv svc-shell
	mkdir -p /etc/systemd/system/user-60123.slice.d
	printf '[Slice]\nMemoryMax=4G\nMemorySwapMax=0\n' >/etc/systemd/system/user-60123.slice.d/50-shell-mcp.conf
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
	{
		echo "restrict,from=\"$from\",command=\"/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/admin.yaml --principal admin\" $admin shell-mcp-admin"
		echo "restrict,from=\"$from\",command=\"/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/read-only.yaml --principal readonly\" $ro shell-mcp-readonly"
	} >/etc/ssh/authorized_keys.d/svc-shell
	;;
hand-split)
	# PR #90's hand steps, as TARGET-SETUP's reference part writes them, on a
	# hand-shared host: §4 "A second service account" (svc-shell-std 60125;
	# not in systemd-journal: neither of its policies has a journal
	# section), §7 "With a second account" (the drop-in command as written),
	# the service key's line added for it (service.yaml, services.control),
	# §7 "Moving a line" (the read-only key, as written), and §8 "Per
	# account" (its polkit rule).
	from="${2:?from}"
	op="$(cut -d' ' -f1,2 "${3:?service key file}")"
	groupadd --gid 60125 svc-shell-std
	useradd --uid 60125 --gid svc-shell-std --home-dir /var/lib/svc-shell-std --create-home --shell /bin/sh svc-shell-std 2>/dev/null
	usermod -L svc-shell-std
	mkdir -p /etc/systemd/system/user-60125.slice.d
	printf '[Slice]\nMemoryMax=4G\nMemorySwapMax=0\n' >/etc/systemd/system/user-60125.slice.d/50-shell-mcp.conf
	f=/etc/ssh/sshd_config.d/60-shell-mcp.conf
	test "$(head -n1 "$f")" = "Match User svc-shell" && test "$(grep -c '^Match ' "$f")" = 1 &&
		{ cat "$f"; echo; sed '1s/^Match User svc-shell$/Match User svc-shell-std/' "$f"; } >/root/60-shell-mcp.conf &&
		install -o root -g root -m 0644 /root/60-shell-mcp.conf "$f" && rm /root/60-shell-mcp.conf ||
		{
			echo "target.sh hand-split: TARGET-SETUP §7's drop-in command did not run" >&2
			exit 1
		}
	echo "restrict,from=\"$from\",command=\"/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/service.yaml --principal service\" $op shell-mcp-service" \
		>/etc/ssh/authorized_keys.d/svc-shell-std
	chmod 0644 /etc/ssh/authorized_keys.d/svc-shell-std
	(
		cd /etc/ssh/authorized_keys.d
		grep -F -- '--principal readonly"' svc-shell >/root/moved.keys
		cat /root/moved.keys >&2
		cat svc-shell-std /root/moved.keys 2>/dev/null >/root/svc-shell-std.keys
		install -o root -g root -m 0644 /root/svc-shell-std.keys svc-shell-std
		grep -vF -- '--principal readonly"' svc-shell >/root/svc-shell.keys
		install -o root -g root -m 0644 /root/svc-shell.keys svc-shell
		rm /root/moved.keys /root/svc-shell-std.keys /root/svc-shell.keys
	)
	(
		cd /tmp
		shell-mcp-gate polkit --policy /etc/shell-mcp/service.yaml --user svc-shell-std >60-shell-mcp-svc-shell-std.rules
		install -o root -g root -m 0644 60-shell-mcp-svc-shell-std.rules /etc/polkit-1/rules.d/60-shell-mcp-svc-shell-std.rules
		rm 60-shell-mcp-svc-shell-std.rules
	)
	;;
state)
	# What two hosts with the same accounts must agree on, byte for byte:
	# the files install manages (owner, mode, type, SHA-256), the accounts'
	# and groups' entries, and the password field (locked).
	shopt -s nullglob
	for p in /etc/ssh/sshd_config.d/60-shell-mcp.conf /etc/ssh/authorized_keys.d /etc/ssh/authorized_keys.d/* \
		/etc/systemd/system/user-*.slice.d /etc/systemd/system/user-*.slice.d/* /etc/polkit-1/rules.d/60-shell-mcp*.rules /var/lib/svc-shell*; do
		stat -c '%U:%G %a %F %n' "$p"
		if [ -f "$p" ]; then sha256sum "$p"; fi
	done
	getent passwd svc-shell svc-shell-std svc-shell-ops || true
	getent group svc-shell svc-shell-std svc-shell-ops svc-shell-priv systemd-journal || true
	grep -E '^svc-shell(-std|-ops)?:' /etc/shadow | cut -d: -f1,2
	;;
hup-sshd)
	# The reload of a container's sshd -D (no systemd): SIGHUP re-executes it
	# with the new configuration.
	kill -HUP "$(cat /run/sshd.pid)"
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
	no-privsep-dir) rm -rf /run/sshd ;;
	privileged-0644) chmod 0644 /etc/shell-mcp/privileged.yaml ;;
	*)
		echo "target.sh: unknown case $2" >&2
		exit 2
		;;
	esac
	;;
*)
	echo "usage: target.sh prepare|prepare-bare|app|answers <preset> <landlock>|bad-answers <case>|snapshot|temps|hand <from> <key>|hand-shared <from> <admin> <ro>|hand-split <from> <op>|state|hup-sshd|hand-units|break <case>" >&2
	exit 2
	;;
esac
