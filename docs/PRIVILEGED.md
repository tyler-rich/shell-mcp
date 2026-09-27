# Privileged helper (normative)

`shell-mcp-privd` is how shell-mcp performs actions that need root — without sudo, setuid, or a root shell. The gate stays unprivileged and sandboxed; when a request needs root it **asks** the helper over a local Unix socket, and the helper decides against its **own** root-owned policy, inside its **own** systemd sandbox.

This document is normative. The helper implements it exactly; changing it is a STOP-and-ask.

## 1. Why a helper instead of sudo

| | sudo from the gate | Privileged helper |
|---|---|---|
| Gate sandbox | Impossible: sudo needs setuid, which `no_new_privs` (required by Landlock) blocks. The gate would have to run unsandboxed. | The gate keeps `no_new_privs` + Landlock for every request. |
| How permission is expressed | sudoers rules that match argv text; wildcards match across arguments | Typed checks: "is this resolved path inside a declared root", "is this owner on the allow-list", "does this argv match a template" |
| What runs as root | Whatever command sudo starts — fully unconfined root | One small process, confined by systemd: only the capabilities it needs, writes only to declared paths, no network (core unit) |
| Who can call it | The service account, from any process it runs | Only the configured UID, verified by the kernel on the socket (`SO_PEERCRED`) |
| Non-TTY setup on the host | NOPASSWD rules for a service account | None — no sudoers file at all |

## 2. Components on each target

| Component | Owner / mode | Notes |
|---|---|---|
| `/usr/local/libexec/shell-mcp-privd` | `root:root 0755` | The helper binary (same Go module, third binary). |
| `/etc/shell-mcp/privileged.yaml` | `root:root 0600` | The privileged policy (§4). Only root reads it. |
| `shell-mcp-privd.socket` + `shell-mcp-privd@.service` | generated, `root:root 0644` in `/etc/systemd/system/` | **Core** unit: tight sandbox, no network (§5.1). |
| `shell-mcp-privd-broad.socket` + `shell-mcp-privd-broad@.service` | generated, same | **Broad** unit: for package management and commands declared `sandbox: broad` (§5.2). Only installed when the policy uses it. |
| Socket group (placeholder name `svc-shell-priv`) | system group | The gate's service account is its only member; sockets are `root:<group> 0660`. |
| `/var/lib/shell-mcp/backups/` | `root:root 0700` | Previous versions of files the helper overwrites or deletes (§6). |

Units are **generated** from the policy by `shell-mcp-privd units --policy /etc/shell-mcp/privileged.yaml` and embed the policy's SHA-256 (`Environment=SHELL_MCP_PRIVD_POLICY_SHA256=…`). The helper refuses to serve if the policy on disk no longer matches, so a policy edit without regenerating the units (whose `ReadWritePaths=` came from the old policy) fails closed.

Sockets use `Accept=yes`: systemd starts one short-lived helper instance per connection, which serves exactly one request and exits. There is no long-running root daemon.

## 3. Trust and authentication

1. The gate connects to `/run/shell-mcp/privd.sock` (or `privd-broad.sock`). File permissions (`0660`, group-owned) are the first gate.
2. The helper reads `SO_PEERCRED` on the accepted socket and requires `uid == client_uid` from its policy. Anything else: close without a response and audit-log it.
3. One request per connection, same wire format as the gate protocol v1 (ARCHITECTURE §4), ops prefixed `priv_`. Request ≤ 2 MiB, response ≤ 4 MiB, strict decoding (unknown fields and duplicate keys are errors).
4. The helper **never trusts the gate**: it re-validates tier, paths, owners, modes, templates and sizes against its own policy. The gate's policy and the helper's policy are independent; both must allow an operation.

**What approval does and does not cover.** Human approval (D-006) is enforced by the MCP server, which holds the HMAC key. It stops a prompt-injected model from acting without the user. It cannot stop a **fully compromised server**, which could skip the prompt — that case is bounded by the gate policy, the privileged policy and the helper's sandbox. Write the privileged policy for that worst case.

## 4. Privileged policy schema

```yaml
version: 1
client_uid: 60123               # example — the gate service account's pinned UID (D-020); required
socket_group: svc-shell-priv    # must exist; must not be in the D-020 deny list
max_tier: operator              # read | operator | destructive
limits:
  max_read_bytes: 1048576
  max_write_bytes: 1048576
  max_output_bytes: 1048576
  default_timeout_s: 60
  max_timeout_s: 900            # package operations can be slow; hard ceiling 1800
  max_delete_entries: 1000
paths:
  read:  [/etc/example-app, /var/log/example-app]      # root-readable roots
  write: [/etc/example-app]                            # root-writable roots (implicitly readable)
  persistence:                                          # write roots inside normally-protected persistence areas
    - path: /etc/systemd/system/example-app.service.d
      acknowledge: "drop-ins for example-app only"      # required non-empty justification; flagged by check-policy
  deny: ["/etc/example-app/secrets/**"]
owners:                          # the only users/groups chown/chgrp may set
  users: [root, example-app]
  groups: [root, example-app]
modes:
  max: "0755"                    # no bits outside this mask; setuid/setgid/sticky never allowed
backups:
  keep: 10                       # per file; 0 disables backups (not recommended)
commands:                        # run as root, templates exactly as POLICY.md §4
  - id: nginx-test
    path: /usr/sbin/nginx
    tier: read
    templates: [["-t"]]
  - id: renew-certs
    path: /usr/local/bin/example-renew
    tier: operator
    sandbox: broad               # needs network → runs under the broad unit
    root_equivalent: false
    templates: [["--all"]]
  - id: reboot-host
    path: /usr/sbin/reboot       # a normally hard-denied binary (§5.3 list B)
    tier: destructive
    capabilities: [CAP_SYS_BOOT] # added to the core unit's bounding set; flagged by check-policy
    acknowledge: "planned maintenance only"
    templates: [[]]
packages:
  enabled: false
  manager: apt                   # only apt in v1
  install: [htop, jq]            # exact package names allowed for install
  remove: [htop]                 # exact package names allowed for removal
  allow_update_index: true       # apt-get update
  allow_upgrade: false           # apt-get upgrade of everything installed
```

Rules:
- Strict parsing, as the gate policy. Roots absolute and already clean; not `/`, `/proc`, `/sys`, `/dev`, `/run`.
- `paths.write` may not overlap the **never** set (§5.3). Paths in the gate's normal protected set (POLICY §3) that are *not* in the never set — systemd unit directories, cron directories, `/etc/profile.d`, `/usr/local/bin`, … — may only appear under `paths.persistence` with an `acknowledge` string.
- Commands resolve and ownership-check exactly as the gate's (root-owned binary and parents, not group/other-writable), with the same placeholder rules (no leading `-`, typed placeholders, `{path:read}`/`{path:write}` resolved against *this* policy's roots).
- `capabilities:` may add only: `CAP_SYS_BOOT`, `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, `CAP_SYS_TIME`, `CAP_KILL`, `CAP_SYS_ADMIN` (the last requires `root_equivalent: true`). Every addition is reflected in the generated unit and reported by `check-policy`.
- `sandbox: broad` and `packages` are **root-equivalent** (a package's maintainer scripts run arbitrary code as root). Both require the broad unit and are always reported as such.

## 5. Sandboxes

### 5.1 Core unit (generated)

`User=root`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH` (+ declared `capabilities`), `ProtectSystem=strict`, `ReadWritePaths=<paths.write> <paths.persistence> /var/lib/shell-mcp/backups`, `InaccessiblePaths=` the never-readable credential paths, `ProtectHome=read-only`, `PrivateTmp=yes`, `PrivateDevices=yes`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectHostname=yes`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service` minus `@mount @module @reboot @swap @raw-io @debug @obsolete` (adjusted only for declared capabilities), `UMask=0077`, `RuntimeMaxSec=<max_timeout_s + 30>`, `TasksMax=64`, `MemoryMax=256M`. Inside that, the helper also applies Landlock from its policy before reading the request. (The implementing session verifies each directive against `systemd.exec(5)` for the systemd version in the e2e image and records the `systemd-analyze security` score.)

### 5.2 Broad unit (generated, only when used)

For `packages` and `sandbox: broad` commands. Network allowed, `ProtectSystem=` off (package managers write `/usr`, `/etc`, `/var`), full root capabilities. Still: `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectKernelModules=yes`, `ProtectKernelTunables=yes`, `ProtectClock=yes`, `RestrictSUIDSGID=` off (packages ship setuid binaries), `RuntimeMaxSec`, `TasksMax`, `MemoryMax`. Commands run with `DEBIAN_FRONTEND=noninteractive` and `-o Dpkg::Options::=--force-confold` (existing config files are never overwritten by package upgrades). Every broad operation is approval-gated and audit-logged at WARN.

### 5.3 What the helper will never do

**List A — never, in any policy** (the helper refuses to load a policy that tries):
- Identity and access: users, groups, passwords (`/etc/passwd`, `/etc/group`, `/etc/shadow*`, `/etc/gshadow*`), sudoers, PAM (`/etc/pam.d`, `/etc/security`), SSH server config and keys (`/etc/ssh`), any `authorized_keys`, polkit rules (`/etc/polkit-1`, `/usr/share/polkit-1`).
- This project's trust anchors: `/etc/shell-mcp`, the gate and helper binaries, the helper's units, `/run/shell-mcp`.
- Credential reads: shadow files, private keys (the built-in read deny list of POLICY §3 applies here too, plus private-key content sniffing).
- Commands from POLICY §5 groups 1–10 (shells, interpreters, launchers, debuggers, pagers/editors, privilege changers, tunnels, session tools, identity and scheduling administration); setuid/setgid/sticky bits.

**List B — declarable only with `acknowledge` (and capabilities where needed):** POLICY §5 groups 11–13 (power, kernel and storage, firewall), and writes to persistence areas (systemd unit directories, cron directories, `/etc/profile.d`, `/usr/local/bin`, `/usr/local/sbin`, `/etc/ld.so.conf.d`). These are legitimate administration and also the easiest ways to lose or own a host; `check-policy` lists every one.

## 6. Operations

| Op | Tier | Approval | Notes |
|---|---|---|---|
| `priv_read_file`, `priv_list_dir`, `priv_stat` | read | no | Within privileged read/write roots; deny list and private-key sniffing apply. |
| `priv_write_file` | operator | **yes** | Atomic (temp + fsync + rename + dir fsync); previous version copied to backups first; owner and mode preserved unless given (owner from `owners`, mode within `modes.max`); read-back SHA-256 verified; `expected_sha256` optimistic concurrency. |
| `priv_mkdir`, `priv_chown`, `priv_chmod`, `priv_copy`, `priv_move` | operator | **yes** | Owners from the allow-list only; modes within the mask; never setuid/setgid/sticky. |
| `priv_list_backups`, `priv_restore_backup` | read / operator | no / **yes** | Restore is itself backed up first. |
| `priv_delete` | destructive | **yes** | Backed up first when within `max_delete_entries`; otherwise refused. |
| `priv_exec` | per command | **yes** for operator+ | Template-matched, run as root in the core or broad unit; same exec engine and output caps as the gate. |
| `priv_pkg_update_index` | operator | **yes** | Broad unit. |
| `priv_pkg_install` | operator | **yes** | Only names in `packages.install`; `--no-install-recommends`. |
| `priv_pkg_upgrade` | operator | **yes** | Only if `allow_upgrade: true`; preview lists what would change (`apt-get -s upgrade`). |
| `priv_pkg_remove` | destructive | **yes** | Only names in `packages.remove`; never `--purge` of config in v1. |

Every write-class op returns a preview first (the server shows it in the approval request): the diff summary for writes, the resolved argv for exec, the simulated transaction for package operations.

## 7. Self-checks (fail closed)

The helper refuses to serve when: it is not uid 0; `NoNewPrivs` is not 1; its capability bounding set is broader than the generated unit declares; stdin is not a Unix socket; the policy or its binary is not root-owned or is group/other-writable; the policy fails validation; the policy SHA-256 differs from `SHELL_MCP_PRIVD_POLICY_SHA256`; the peer UID is not `client_uid`; Landlock is unavailable and the policy does not say `sandbox: best-effort` (core unit only).

## 8. Audit

One journald line per request from the helper unit: gate principal (forwarded, informational only), peer UID, op, sanitized arguments (paths, owners, modes, command id, package names — never content), backup id, outcome, duration. Broad operations log at WARN.
