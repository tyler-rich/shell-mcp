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
| `shell-mcp-privd-broad.socket` + `shell-mcp-privd-broad@.service` | generated, same | **Broad** unit: for package management, commands declared `unit: broad` and the power operation (§5.2). Generated and installed only when the policy uses it (`packages.enabled`, a `unit: broad` command, or `power`). |
| Socket group (placeholder name `svc-shell-priv`) | system group | The gate's service account is its only member; sockets are `root:<group> 0660`. |
| `/run/shell-mcp/` | `root:root 0711` | Created by systemd for the socket (`DirectoryMode=0711`). `SocketUser=`/`SocketGroup=` apply to the socket node only, so the directory stays root's; the gate needs only search permission to reach the socket by name, not to list the directory. |
| `/var/lib/shell-mcp/backups/` | `root:root 0700` | Previous versions of files the helper overwrites or deletes (§6). Created at install; the core unit lists it in `ReadWritePaths=` and does not start without it. |

Units are **generated** from the policy by `shell-mcp-privd units --policy /etc/shell-mcp/privileged.yaml` and embed the policy's SHA-256 (`Environment=SHELL_MCP_PRIVD_POLICY_SHA256=…`), its `client_uid` (`Environment=SHELL_MCP_PRIVD_CLIENT_UID=…`, so the peer check reads nothing from disk, §7) and which unit they are (`Environment=SHELL_MCP_PRIVD_UNIT=core` or `…=broad`). Each instance knows its unit and refuses an operation meant for the other one (`helper_wrong_unit`, §6), so the helper, not the gate, is authoritative for routing. The helper refuses to serve if the policy on disk no longer matches, so a policy edit without regenerating the units (whose `ReadWritePaths=` came from the old policy) fails closed; it tells the gate so (`helper_policy_mismatch`).

Sockets use `Accept=yes`: systemd starts one short-lived helper instance per connection, which serves exactly one request and exits. There is no long-running root daemon.

## 3. Trust and authentication

1. The gate connects to `/run/shell-mcp/privd.sock` (or `privd-broad.sock`). File permissions (`0660`, group-owned) are the first gate.
2. The helper reads `SO_PEERCRED` on the accepted socket and requires the uid to equal the unit's `SHELL_MCP_PRIVD_CLIENT_UID` (generated from the policy's `client_uid`; once the peer has passed, the policy's value must equal it too, §7). Anything else: close without a response and audit-log it. This is the first thing the helper does (§7).
3. One request per connection, same wire format as the gate protocol v1 (ARCHITECTURE §4), ops prefixed `priv_`. Request ≤ 2 MiB, response ≤ 4 MiB, strict decoding (unknown fields and duplicate keys are errors).
4. The helper **never trusts the gate**: it re-validates tier, paths, owners, modes, templates and sizes against its own policy. The gate's policy and the helper's policy are independent; both must allow an operation.

**What approval does and does not cover.** Human approval (D-006) is enforced by the MCP server, which holds the HMAC key. It stops a prompt-injected model from acting without the user. It cannot stop a **fully compromised server**, which could skip the prompt — that case is bounded by the gate policy, the privileged policy and the helper's sandbox. Write the privileged policy for that worst case.

## 4. Privileged policy schema

```yaml
version: 1
client_uid: 60123               # example — the gate service account's pinned UID (D-020); required; never 0
socket_group: svc-shell-priv    # must exist locally; must not be in the D-020 deny list or gid 0
max_tier: operator              # read | operator | destructive
sandbox:
  landlock: required            # required (default) | best-effort — as in the gate policy (§7)
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
    unit: broad                  # needs network → runs under the broad unit; core is the default
    root_equivalent: false
    templates: [["--all"]]
  - id: firewall-list
    path: /usr/sbin/nft          # a normally hard-denied binary (§5.3 list B)
    tier: read
    acknowledge: "firewall rules are listed, never changed"
    templates: [["list", "ruleset"]]
power:                           # the built-in priv_power operation (§6); omitted = not allowed
  allowed: [reboot]              # reboot | poweroff
  acknowledge: "planned maintenance windows only"   # required, one line (list B, POLICY §5 group 11)
packages:
  enabled: false
  manager: apt                   # only apt in v1
  install: [htop, jq]            # exact package names allowed for install
  remove: [htop]                 # exact package names allowed for removal
  allow_update_index: true       # apt-get update
  allow_upgrade: false           # apt-get upgrade of everything installed
```

`examples/privileged/privileged.yaml` is a complete, commented example with placeholders; a test loads it and generates both unit pairs from it.

Rules:
- Strict parsing, as the gate policy. Roots absolute and already clean; not `/`, `/proc`, `/sys`, `/dev`, `/run`. A root may appear under both `paths.read` and `paths.write` (write roots are readable anyway).
- `paths.write` and `paths.persistence` may not be, be inside, or contain a path on the **never** set (§5.3), nor be inside a `.git` directory; `paths.read` may not be or be inside a never-set path (a read root such as `/etc` may contain them: the deny list and the unit's `InaccessiblePaths=` keep credentials out). Paths in the gate's normal protected set (POLICY §3) that are *not* in the never set — systemd unit directories, cron directories, `/etc/profile.d`, `/usr/local/sbin`, … — may only appear under `paths.persistence` with an `acknowledge` string (one line). `/usr/local/bin` holds the gate binary, so it is never a write root.
- Commands resolve and ownership-check exactly as the gate's (root-owned binary and parents, not group/other-writable, binary identity check), with the same placeholder rules (no leading `-`, typed placeholders, `{path:read}`/`{path:write}` resolved against *this* policy's roots; `{unit}` is not available). A command may carry a one-line `description`. POLICY §5 groups 1–10 are refused by name (as written and resolved) and by identity; groups 11–13 need a non-empty `acknowledge`. `systemctl`, `journalctl`, `git` and this project's own binaries may not be commands.
- `unit:` is `core` (default) or `broad`. `capabilities:` may add only the capabilities below, each valid only where it has an effect; every addition is reflected in the generated unit and reported by `check-policy`:

  | Capability | Core unit | Broad unit |
  |---|---|---|
  | `CAP_SYS_BOOT` | yes (the unit then keeps `@reboot` in its syscall filter) | yes (already in its full set) |
  | `CAP_KILL` | yes (the unit then uses `ProtectProc=default`, §5.1, and Landlock leaves signals unscoped) | yes (already in its full set) |
  | `CAP_SYS_ADMIN` | yes, with `root_equivalent: true` | yes, with `root_equivalent: true` |
  | `CAP_SYS_TIME` | no — `ProtectClock=yes` removes it from the bounding set and filters `@clock` | yes — the broad unit then drops `ProtectClock=yes` (§5.2) |
  | `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE` | no — the core unit has a private network namespace and only `AF_UNIX` sockets | yes (already in its full set) |

  Capabilities of broad-unit commands never reach the core unit's bounding set.
- `modes.max` is 3–4 octal digits without setuid, setgid, sticky or world-write bits (default `0755`); the default modes of new files (`0640`) and directories (`0750`) are capped by it too. `backups.keep` is 0..100 (default 10). Limit ceilings: `max_read_bytes` and `max_output_bytes` ≤ 4 MiB, `max_write_bytes` ≤ 1 MiB, `max_timeout_s` ≤ 1800, `max_delete_entries` ≤ 10000.
- `unit: broad`, `packages` and `power` need the broad unit; `unit: broad` and `packages` are **root-equivalent** (a package's maintainer scripts run arbitrary code as root). All three are always reported by `check-policy`.
- `packages`: `manager` is `apt` (default); `install` and `remove` hold at most 256 exact Debian package names each (Debian Policy §5.6.1: lower-case letters, digits, `+`, `-`, `.`, at least two characters, alphanumeric first, at most 128 bytes), without duplicates. An `install` name may not end in `-` and a `remove` name may not end in `+`: apt-get reads those suffixes as "remove" and "install" when no package has that exact name, which would turn one operation into the other. With `enabled: true`, `/usr/bin/apt-get` must resolve to a root-owned, not group/other-writable executable.
- `power`: `allowed` lists `reboot`, `poweroff` or both, without duplicates; `acknowledge` is a required one-line justification. A policy whose `max_tier` is below `destructive` gets a warning (priv_power is destructive).

## 5. Sandboxes

### 5.1 Core unit (generated)

`User=root`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH` (+ declared `capabilities`), `ProtectSystem=strict`, `ReadWritePaths=<paths.write> <paths.persistence> /var/lib/shell-mcp/backups`, `InaccessiblePaths=` the never-readable credential paths (`-/etc/shadow -/etc/shadow- -/etc/gshadow -/etc/gshadow- -/etc/sudoers -/etc/sudoers.d -/etc/security/opasswd -/etc/ssh -/root/.ssh`; the directive takes no globs, and `-` ignores a path this host lacks), `ProtectHome=read-only`, `TemporaryFileSystem=/run:ro`, `ProtectProc=invisible` (`default` when a core-unit command declares `CAP_KILL`), `ProcSubset=pid`, `PrivateTmp=yes`, `PrivateDevices=yes`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectHostname=yes`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service` minus `@mount @module @reboot @swap @raw-io @debug @obsolete` (adjusted only for declared capabilities: `CAP_SYS_BOOT` keeps `@reboot`), `UMask=0077`, `RuntimeMaxSec=<max_timeout_s + 30>`, `TasksMax=64`, `MemoryMax=256M`. The generated service also carries what running it needs — `ExecStart=`, `StandardInput=socket`, `StandardOutput=socket`, `StandardError=journal`, `SyslogIdentifier=shell-mcp-privd`, `Environment=SHELL_MCP_PRIVD_POLICY_SHA256=<hash>`, `Environment=SHELL_MCP_PRIVD_CLIENT_UID=<client_uid>` (never 0 or 4294967295), `Environment=SHELL_MCP_PRIVD_UNIT=core`, and `CollectMode=inactive-or-failed` so finished instances do not accumulate — and the socket `ListenStream=/run/shell-mcp/privd.sock`, `Accept=yes`, `SocketUser=root`, `SocketGroup=<socket_group>`, `SocketMode=0660`, `DirectoryMode=0711`, `MaxConnections=16`. A path or name that a unit file would reinterpret (whitespace, quotes, `\`, `%`, `$`, a component starting with `-`) makes `units` refuse rather than quote it. Inside that, the helper also applies Landlock from its policy before reading the request: read+execute on `/usr /bin /sbin /lib /lib64` and each command's binary; read on the read roots, `/etc/passwd`, `/etc/group`, `/etc/ld.so.cache` and its own `/proc/<pid>`; read+write (no execute) on the write and persistence roots and the backup store; `/dev/null`, `/dev/urandom`; no socket and no TCP rule, so from ABI 4 every TCP bind and connect is denied; from ABI 8 signals and abstract Unix sockets are scoped to the helper's own domain, except that signals are left unscoped when a core-unit command declares `CAP_KILL` (otherwise the capability could reach no process outside the helper). (Every directive was verified against `systemd.exec(5)`, `systemd.socket(5)` and `systemd.resource-control(5)` for systemd 257 and 259; see ARCHIVE §14, S1c and S1d, with the `systemd-analyze security` score.)

Why these directives, and why not others:

- **`/run` is an empty read-only tmpfs.** `/run` holds the system bus socket, systemd's private socket, and the sockets of other root services (a container engine's, for example). Below Landlock ABI 9, which governs pathname Unix-socket connects, root can connect to any socket file it can reach, and each of those is root-equivalent for a root client — the system bus alone lets root have PID 1 start any unit, outside every sandbox. `TemporaryFileSystem=/run:ro` hides all of them; `/var/run` is the usual symlink to `/run`, so it points into the same empty tmpfs (`units` and `check-policy` refuse a host where `/var/run` is anything else). The helper needs nothing under `/run`: its connection and its journal stream are file descriptors set up before the namespace. (`InaccessiblePaths=/run` would not work on systemd 257: after setting up the namespace it remounts its own `/run/systemd/incoming`, which an inaccessible `/run` removes, so the unit would fail to start. A tmpfs lets systemd create that mount point.) **Abstract Unix sockets** are not files; they belong to a network namespace, and `PrivateNetwork=yes` gives the core unit its own ("`AF_UNIX` sockets in the abstract socket namespace of the host will become unavailable", `systemd.exec(5)`, 257 and 259). So the core unit reaches no local IPC endpoint of the host at all; Landlock's abstract-socket scope (ABI 8) adds the same inside it.
- **`ProtectProc=invisible`, `ProcSubset=pid`.** Other users' processes are hidden from the core unit and only process directories are visible in its `/proc`. `systemd.exec(5)` notes that root is unaffected by `ProtectProc=` unless it lacks `CAP_SYS_PTRACE`: hidepid lets a process see another only when it may ptrace it, and the core unit's bounding set has no `CAP_SYS_PTRACE`, so it applies to the helper. When a core-unit command declares `CAP_KILL`, the unit uses `ProtectProc=default` instead, because signalling a process requires finding it first.
- **Never `PrivateUsers=`, `RootDirectory=` or `RootImage=`.** A private user namespace maps the host's users away, so `chown` to an owner from `owners` could not work; a separate root filesystem defeats working on the host's own files. The generator refuses to emit them.

### 5.2 Broad unit (generated, only when used)

For `packages`, commands declared `unit: broad` and `power`; generated only when the policy uses one of them. Network allowed, `ProtectSystem=` off (package managers write `/usr`, `/etc`, `/var`), full root capabilities. Still: `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectKernelModules=yes`, `ProtectKernelTunables=yes`, `ProtectClock=yes`, `RestrictSUIDSGID=` off (packages ship setuid binaries), `RuntimeMaxSec`, `TasksMax`, `MemoryMax`. Package operations run apt-get with `DEBIAN_FRONTEND=noninteractive` and `-o Dpkg::Options::=--force-confold` (existing config files are never overwritten by package upgrades). Every broad operation that changes something is approval-gated, and everything the broad unit serves is audit-logged at WARN.

The generated service is exactly: `ExecStart=`, `StandardInput=socket`, `StandardOutput=socket`, `StandardError=journal`, `SyslogIdentifier=shell-mcp-privd`, the same `SHELL_MCP_PRIVD_POLICY_SHA256` and `SHELL_MCP_PRIVD_CLIENT_UID` lines as the core unit, `Environment=SHELL_MCP_PRIVD_UNIT=broad`, `User=root`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectKernelModules=yes`, `ProtectKernelTunables=yes`, `ProtectClock=yes`, `RuntimeMaxSec=<max_timeout_s + 30>`, `TasksMax=256`, `MemoryMax=1G` (apt-get and dpkg with maintainer scripts need more than one core-unit request), and `CollectMode=inactive-or-failed`; nothing for the network, `ProtectSystem=`, the capability bounding set or `RestrictSUIDSGID=`, which are therefore off. The socket is the core unit's with `ListenStream=/run/shell-mcp/privd-broad.sock`. There is no Landlock sandbox in the broad unit.

**`CAP_SYS_TIME` relaxes `ProtectClock=`.** `ProtectClock=yes` removes `CAP_SYS_TIME` and `CAP_WAKE_ALARM` from the bounding set and filters the clock-setting system calls, so a broad command that declares `CAP_SYS_TIME` could not use it. When one does, the broad unit is generated without `ProtectClock=`; that is the only directive a capability may relax, in either unit, and the core unit keeps it.

**Self-check.** The broad instance's bounding set may be at most root's full set without `CAP_SYS_MODULE` (dropped by `ProtectKernelModules=yes`) and, while it keeps `ProtectClock=yes`, without `CAP_SYS_TIME` and `CAP_WAKE_ALARM`; anything broader is `helper_capabilities_broad`.

**What `ProtectKernelModules=`, `ProtectKernelTunables=` and `ProtectClock=` cost.** A package whose maintainer scripts load kernel modules, write `/proc/sys` or `/sys`, or set the clock fails inside the broad unit; so does installing into `/usr/lib/modules`, which `ProtectKernelModules=` hides. Kernel and kernel-module packages are therefore not installable through the helper in v1. (`ProtectClock=` would add a read-only rule for the RTC devices only where a device policy is already in force; the broad unit has none, so it keeps access to every device — systemd 257 and 259, `unit_patch_contexts()`.)

### 5.3 What the helper will never do

**List A — never, in any policy** (the helper refuses to load a policy that tries):
- Identity and access: users, groups, passwords (`/etc/passwd`, `/etc/group`, `/etc/shadow*`, `/etc/gshadow*`), sudoers, PAM (`/etc/pam.d`, `/etc/security`), SSH server config and keys (`/etc/ssh`), any `authorized_keys`, polkit rules (`/etc/polkit-1`, `/usr/share/polkit-1`).
- This project's trust anchors: `/etc/shell-mcp`, the gate and helper binaries, the helper's units, `/run/shell-mcp`.
- Credential reads: shadow files, private keys (the built-in read deny list of POLICY §3 applies here too, plus private-key content sniffing).
- Commands from POLICY §5 groups 1–10 (shells, interpreters, launchers, debuggers, pagers/editors, privilege changers, tunnels, session tools, identity and scheduling administration); setuid/setgid/sticky bits.

**List B — declarable only with `acknowledge` (and capabilities where needed):** POLICY §5 groups 11–13 (power, kernel and storage, firewall), the built-in power operation (the `power` section, §4), and writes to persistence areas (systemd unit directories, cron directories, `/etc/profile.d`, `/usr/local/bin`, `/usr/local/sbin`, `/etc/ld.so.conf.d`). These are legitimate administration and also the easiest ways to lose or own a host; `check-policy` lists every one.

## 6. Operations

| Op | Tier | Approval | Notes |
|---|---|---|---|
| `priv_read_file`, `priv_list_dir`, `priv_stat` | read | no | Within privileged read/write roots; deny list and private-key sniffing apply. |
| `priv_write_file` | operator | **yes** | Atomic (temp + fsync + rename + dir fsync); previous version copied to backups first; owner and mode preserved unless given (owner from `owners`, mode within `modes.max`); read-back SHA-256 verified; `expected_sha256` optimistic concurrency. |
| `priv_mkdir`, `priv_chown`, `priv_chmod`, `priv_copy`, `priv_move` | operator | **yes** | Owners from the allow-list only; modes within the mask; never setuid/setgid/sticky. |
| `priv_list_backups`, `priv_restore_backup` | read / operator | no / **yes** | Restore is itself backed up first. |
| `priv_delete` | destructive | **yes** | Backed up first when within `max_delete_entries`; otherwise refused. |
| `priv_exec` | per command | **yes** for operator+ | Template-matched, run as root in the command's unit (core or broad); same exec engine and output caps as the gate. Args may carry `unit` (`core` or `broad`), a routing label the server supplies so that the gate, which cannot read this policy, can pick the socket (how the server learns a command's unit is S4c's); the helper runs a command only in its declared unit and refuses a label that disagrees (`helper_wrong_unit`). |
| `priv_pkg_update_index` | operator | **yes** | Broad unit. Only if `allow_update_index: true`. `apt-get -q update`. |
| `priv_pkg_install` | operator | **yes** | Broad unit. 1..20 names, each in `packages.install`; `--no-install-recommends`. |
| `priv_pkg_upgrade` | operator | **yes** | Broad unit. Only if `allow_upgrade: true`; `apt-get upgrade` (installs no new packages, removes none). |
| `priv_pkg_remove` | destructive | **yes** | Broad unit. 1..20 names, each in `packages.remove`; never a purge of configuration in v1. |
| `priv_pkg_install_preview`, `priv_pkg_upgrade_preview`, `priv_pkg_remove_preview` | read | no | Broad unit. The same transaction simulated (`apt-get -s`: no change, no lock); returns the packages that would be installed (name, version), upgraded (name, from, to) and removed (name, version, purge), `complete: false` when the simulation failed, was cut or had a line that did not parse, the exit code and stderr. The same policy checks as the operation. |
| `priv_power` | destructive | **yes** | Broad unit. `action` `reboot` or `poweroff`, only if listed in `power.allowed`. Asks systemd over the system bus to start `reboot.target` or `poweroff.target` with job mode `replace-irreversibly` — what `systemctl reboot` does when it talks to PID 1: an orderly shutdown. Returns the job path. systemd authorizes the call because the caller is root; a systemd refusal is `not_authorized` (access denied) or `exec_failed` (naming the D-Bus error, e.g. a masked target). Never the `reboot(2)` system call, never `Manager.Reboot()` (`systemctl --force`: services are not stopped), and no capability is added to any unit. |

**Package operations** run `/usr/bin/apt-get` with a fixed argv — `-q -y -o Dpkg::Options::=--force-confold -o Dpkg::Use-Pty=0 -o APT::Get::AutomaticRemove=false`, then `--no-install-recommends` (install, upgrade) or `-o APT::Get::Purge=false` (remove), `-s` for a preview, the command, and package names only after `--`, which ends apt-get's option parsing (verified in apt 3.0.3 and 3.1.16) — and the fixed command environment plus `DEBIAN_FRONTEND=noninteractive`. There is never a free-form apt argument. When apt-get fails because another process holds the dpkg frontend, administration or package-list lock, it is run again every 2 s for at most `min(60 s, timeout / 2)` (apt refuses before changing anything when it cannot lock); after that the operation is `exec_failed` saying the package database is locked. Otherwise a failed transaction is data: `ok: true` with the exit code and the capped, redacted stdout and stderr.

**Routing.** The core unit's instance serves the file operations, backups and core commands; the broad unit's serves the package operations, their previews, `priv_power` and broad commands. The gate sends each op to `privileged.socket` or `privileged.broad_socket` accordingly (ARCHITECTURE §3), but each instance checks, before anything else about the request, that the operation belongs to its unit, and refuses it otherwise with `helper_wrong_unit` — never executed, whatever the gate sent where.

Every write-class op returns a preview first (the server shows it in the approval request): the diff summary for writes, the resolved argv for exec, the simulated transaction for package operations.

**Backups.** Before any overwrite (write, copy or move over a file), delete or restore, the helper copies what would be lost into `/var/lib/shell-mcp/backups/` through the same verified descriptors the operation uses: for a file, `<id>.data` (its bytes); for a directory tree, `<id>.tar` (its directories and regular files with their modes and owners; a tree holding a symlink or special file cannot be backed up, so it is not deleted). Beside it, `<id>.meta.json` records the backup id (`YYYYMMDDTHHMMSSZ-<16 hex>`), kind, original path, owner, group, mode, size, SHA-256, time, op and request id. Both are `root:root 0600`, written under temporary names, fsynced and renamed data first, so a backup exists exactly when its metadata does. `backups.keep` versions are kept per original path; older ones are removed after each new backup. A backup larger than 64 MiB, a missing or group/other-accessible store, or any write error is `backup_failed`, and the operation changes nothing. A file replaced or rewritten while it was being backed up is not destroyed, and a recursive delete stops before removing any entry the backup did not see. `priv_list_backups` lists metadata (newest first, filtered by path); `priv_restore_backup` restores a file (with its recorded owner and mode, backing up the current version first) or a tree (only where nothing exists now), after checking the data's SHA-256.

**Write-class results** carry `backup_ids`, the backups written first; owners and groups are names from `owners`; modes are octal strings within `modes.max`. `priv_exec` has no stdin in v1 (the privileged policy declares no stdin limit).

## 7. Self-checks (fail closed)

The helper refuses to serve when: stdin is not a connected Unix stream socket; the unit's `SHELL_MCP_PRIVD_CLIENT_UID` is missing or not a uid in 1..4294967294; the peer UID is not that value; it is not uid 0; `NoNewPrivs` is not 1; it was built with cgo, or its binary is not root-owned or is group/other-writable; the policy is missing, unreadable, not root-owned or group/other-writable; the policy fails parsing or validation; the policy SHA-256 differs from `SHELL_MCP_PRIVD_POLICY_SHA256`; the policy's `client_uid` differs from `SHELL_MCP_PRIVD_CLIENT_UID`; the unit's `SHELL_MCP_PRIVD_UNIT` is not `core` or `broad`, or is `broad` for a policy that uses no broad unit; its capability bounding set is broader than its unit declares (the core unit's computed set; for the broad unit, root's full set without what its directives drop, §5.2); Landlock is unavailable and the policy does not set `sandbox.landlock: best-effort` (core unit only: the broad unit has no Landlock sandbox).

The checks run in that order, in four steps. **No byte is read from the connection until all of them have passed.**

1. **Authenticate the peer**, from the connection and the unit's environment alone: the socket checks (`fstat`, `getsockopt`, `getpeername`), the unit's client uid, and `SO_PEERCRED`. Nothing is read from disk. A failure closes the connection **without writing a byte** (the gate reports `helper_refused`) and logs one WARN line naming the check (`stdin`, `unit_client_uid` or `peer_uid`) with outcome `refused`. Nothing is ever written to an unauthenticated peer, and it learns nothing about the installation: whatever else is broken, it gets the same silent close.
2. **Every other self-check**, for the authenticated peer. A failure is answered with one response — no id, since the request is unread, and a one-line message that names the failed check and at most a policy field name (never a local path, a value from the root-only policy or a parser's message) — and logged at WARN with the check and the code as the outcome:

   | Check (journal) | Code |
   |---|---|
   | `uid`, `no_new_privs`, `binary`, `policy_file`, `unit` | `helper_install_insecure` |
   | `policy` (parse or validation) | `helper_policy_invalid` |
   | `policy_hash` | `helper_policy_mismatch` |
   | `client_uid` | `helper_client_uid_mismatch` |
   | `capabilities` | `helper_capabilities_broad` |

   The gate passes these codes through unchanged (ARCHITECTURE §4.2).
3. **Landlock** (core unit): a refusal is `helper_sandbox_unavailable` — not the gate's own `sandbox_unavailable`, so the operator can tell which component lacks the sandbox — answered without an id, logged at WARN with the check `landlock`, and the instance exits 1 like the other answered self-check failures.
4. **Only then read the request.** Every outcome from here on is a response carrying the request's id. The first check on it is its unit: an operation meant for the other unit is refused with `helper_wrong_unit` (for `priv_exec`, once the command is known to be declared), before its tier or anything else.

## 8. Audit

One journald line per connection from the helper unit (stderr, `SyslogIdentifier=shell-mcp-privd`), as one JSON object: the request id, peer UID and PID, op, sanitized arguments (paths, owners, modes, command id and argument count, backup id, flags — never content, command arguments or output), the backup ids written, outcome and duration. The gate principal is not forwarded (the request reaches the helper unchanged); the gate's own audit line for the same request id carries it, so the two lines join on the id (a lowercase UUID v4, validated by both). Priorities: info on success, notice on a refused operation, WARN on a refused connection (a failed self-check or peer check, with the check's name; the outcome is `refused` when the connection was closed without a byte, else the code it was answered with, §7). Everything the broad unit serves logs at WARN (it is root-equivalent); the line carries the package names (identifiers from the allow-lists, never output), the power action and the `unit` label.
