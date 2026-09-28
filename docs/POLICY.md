# Target policy (normative)

This document specifies the **gate** policy. Root actions are governed by a separate privileged policy read only by the helper — see `docs/PRIVILEGED.md`.

The policy is a YAML file on each target, owned by root, selected per SSH key by the forced command's `--policy` flag. **It is the security boundary** (D-016): write it for the worst case — "what would I accept a fully compromised MCP server doing with this key?"

The gate parses it strictly: unknown keys, wrong types, duplicate ids and unanchored regexes are errors, and the gate refuses to serve (`install_insecure`) until `shell-mcp-gate check-policy` passes.

## 1. Top-level schema

```yaml
version: 1                      # schema version; must equal the gate's
max_tier: read                  # read | operator | destructive — ceiling for every op and command
sandbox:
  landlock: required            # required (default) | best-effort — best-effort is reported by hello/check
  system_read_exec: []          # extra read+execute dirs for declared binaries (defaults cover /usr, /bin, /sbin, /lib*, /etc)
  tcp_connect_ports: []         # TCP ports gate children may connect to (e.g. 443 for git pulls); empty = none
limits:
  default_timeout_s: 30
  max_timeout_s: 300            # hard ceiling ≤ 600
  max_output_bytes: 1048576     # per stream (stdout, stderr), ≤ 4 MiB
  max_stdin_bytes: 1048576      # ≤ 1 MiB
  max_read_bytes: 1048576       # read_file ceiling, ≤ 4 MiB
  max_write_bytes: 1048576      # write_file ceiling, ≤ 1 MiB
  max_find_results: 1000        # ≤ 10000
  max_find_depth: 8             # ≤ 32
  max_delete_entries: 1000      # recursive delete ceiling, ≤ 10000
  max_processes: 2000           # processes op ceiling
paths:
  read:  [/srv/app, /etc/example-app, /var/log/example-app]
  write: [/srv/app/config]      # write roots are implicitly readable
  deny:  ["/srv/app/secrets/**", "**/*.key"]   # added to the built-in deny list (§3); cannot remove built-ins
services:
  status: ["example-app.service", "example-*.service"]   # glob over unit names (fnmatch, no "/")
  control:
    units: ["example-app.service"]                        # exact names only — become the generated polkit rule
    verbs: [restart, reload]                              # subset of start|stop|restart|reload
journal:
  units: ["example-app.service"]                          # exact names or globs; "*" allows all units
  max_lines: 2000                                         # ≤ 10000
git:
  repos:
    - path: /srv/app/deploy                               # must be inside a read root (write root for pull/discard)
      remote: https://git.example.test/org/deploy.git     # pull refuses if origin differs
privileged:                     # forwarding to the privileged helper (docs/PRIVILEGED.md); omitted = disabled
  enabled: false
  socket: /run/shell-mcp/privd.sock
  broad_socket: /run/shell-mcp/privd-broad.sock   # only if the helper policy uses the broad unit
  max_tier: operator            # ceiling for forwarded priv_* ops, ≤ max_tier above
redact:
  patterns: ['(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*\S+']   # RE2, added to built-ins
commands: []                    # §4
```

Defaults: omitted sections allow nothing. An empty policy with `max_tier: read` exposes only `hello`, `policy`, `sysinfo`, `disk`, and `processes`.

## 2. Tiers

| Tier | Meaning |
|---|---|
| `read` | No state change on the host. |
| `operator` | Changes state reversibly: service lifecycle, writes inside write roots with read-back, fast-forward pulls. |
| `destructive` | Deletes data or discards work. Requires the server's `admin` profile, a human approval through elicitation, and `max_tier: destructive` here. |

An op or command above `max_tier` is refused with `tier_denied` before any other processing.

## 3. Paths

- All roots and requested paths must be absolute and already clean (no `.`/`..` components, no trailing slash except `/` itself, no NUL, ≤ 4096 bytes). The gate rejects unclean input instead of cleaning it.
- The root for a request is the **longest** configured root that is a path-prefix (on component boundaries) of the requested path.
- Operations run through `os.Root` opened at that root, so `..` and symlinks cannot escape it. After opening, the gate reads `/proc/self/fd/N` and re-checks the real path against the root and the deny list. A symlink as the **final** component is refused (`path_denied`) for every op except `stat` (which reports it as a symlink without following).
- `/` may not be a root. `/proc`, `/sys`, `/dev`, `/run` may not be roots or inside one (the native `sysinfo`/`disk`/`processes` ops read what they need themselves).

**Built-in read deny list** (always applied; policy `deny` adds to it):
`/etc/shadow*`, `/etc/gshadow*`, `/etc/sudoers`, `/etc/sudoers.d/**`, `/etc/ssh/*_key`, `/etc/ssh/authorized_keys.d/**`, `/root/**`, `/home/*/.ssh/**`, `**/.ssh/**`, `**/.gnupg/**`, `**/.docker/config.json`, `**/.kube/config`, `**/.netrc`, `**/.git-credentials`, `**/.pgpass`, `/var/lib/shell-mcp/**`.
Additionally, any file whose first 64 KiB contain a `-----BEGIN … PRIVATE KEY-----` header is refused for `read_file`.

**Built-in protected set** (never writable; a write root equal to, inside, or containing any of these is a policy error):
`/etc/shell-mcp`, the gate binary's path, `/etc/ssh`, `/etc/sudoers`, `/etc/sudoers.d`, `/etc/pam.d`, `/etc/security`, `/etc/systemd`, `/usr/lib/systemd`, `/lib/systemd`, `/run/systemd`, `/etc/cron*`, `/var/spool/cron`, `/etc/profile`, `/etc/profile.d`, `/etc/environment`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d`, `/etc/ld.so.preload`, `/etc/passwd`, `/etc/group`, `/etc/shadow*`, `/etc/gshadow*`, `/etc/fstab`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/root`, the service user's home directory, and `**/.ssh`.

Write rules: temp file in the same directory → write → `fsync` → `rename` → re-open and SHA-256 compare (`verify_failed` on mismatch). Existing mode and owner are preserved when the caller can; new files get `0640` unless `mode` is given. Modes with setuid, setgid, or world-write bits are refused. `copy`/`move` never overwrite unless `overwrite: true`, and both source and destination must satisfy their tier's roots.

## 4. Commands (argv templates)

```yaml
commands:
  - id: zfs-pool-status               # [a-z0-9][a-z0-9-]{0,62}
    path: /usr/sbin/zpool              # absolute; resolved and ownership-checked at load
    tier: read
    description: "ZFS pool health"     # shown to the model via the policy op; no deployment details
    templates:
      - ["status"]
      - ["status", "-x"]
      - ["list", "-H", "-o", "name,size,alloc,free,health"]
  - id: apt-upgradable
    path: /usr/bin/apt
    tier: read
    templates:
      - ["list", "--upgradable"]
  - id: compose-ps
    path: /usr/bin/docker
    tier: read
    root_equivalent: true              # REQUIRED acknowledgement for docker/podman/ctr/nerdctl/kubectl
    templates:
      - ["compose", "-f", "{path:read}", "ps", "--format", "json"]
  - id: cert-renew
    path: /usr/local/bin/example-renew
    tier: operator                     # runs as the service user, sandboxed; there is no sudo option
    templates:
      - ["--domain", "{enum:app.example.test|api.example.test}"]
```

**Matching:** the request carries `command_id` and `args`. The args must match **one template exactly** — same token count, each literal equal, each placeholder satisfied. There is no prefix matching, no optional tokens, no free flags. `argv[0]` is always the resolved `path`.

**Placeholders** (a token that is exactly `{type}` or `{type:param}`):

| Placeholder | Accepts |
|---|---|
| `{path:read}` / `{path:write}` | Absolute clean path that the gate resolves under a read/write root and that passes the deny list. The resolved path is what is passed. |
| `{unit}` | A unit name matching `services.status`. |
| `{int:MIN-MAX}` | Decimal integer in range. |
| `{enum:a\|b\|c}` | One of the listed literals. |
| `{regex:^…$}` | RE2 regex, must be anchored with `^…$`, max 256 chars. |

**Universal placeholder rules:** a placeholder value may never start with `-`, contain NUL, newline, or exceed 1024 bytes. (Option injection is the most common way a "safe" binary becomes unsafe.)

**Privilege:** there is none. Policy commands run as the service user inside the gate's `no_new_privs` + Landlock domain; setuid binaries therefore cannot gain privilege, and there is no `sudo` option. A command that only works as root does not belong in v1.

**Execution environment:** `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, `HOME=<service user home>`, `PAGER=cat`, `SYSTEMD_PAGER=`, `SYSTEMD_COLORS=0`, `GIT_TERMINAL_PROMPT=0`, `NO_COLOR=1`, `TERM=dumb`. Nothing from the request or sshd is inherited. `cwd` (optional) must be inside a read root; default is `/`. `stdin` (optional) ≤ `limits.max_stdin_bytes`; otherwise stdin is `/dev/null`.

## 4a. Sandbox

Before reading the request, the gate sets `no_new_privs` and applies a Landlock ruleset to all its threads; every child inherits it. The ruleset is derived from this file:

| Access | Paths |
|---|---|
| read + execute | `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/etc` (read only), plus `sandbox.system_read_exec` |
| read | `paths.read` roots; `/proc` (for native system ops); journal directories when `journal` is configured |
| read + write | `paths.write` roots (no execute) |
| single files | `/dev/null` (read, write, truncate) and `/dev/urandom` (read) — these two files only, never `/dev` itself, no ioctl; many declared binaries open them |
| unix socket connect | the system D-Bus socket when `services.control` is configured; the helper socket(s) when `privileged.enabled`. On kernels whose Landlock ABI does not govern pathname Unix-socket connects, file permissions and the helper's peer-UID check are the controls — `hello` reports which applies. |
| TCP connect | only `sandbox.tcp_connect_ports`; no TCP bind at all. Landlock does not govern Multipath TCP sockets, so after Landlock the gate installs a seccomp filter that makes `socket(AF_INET/AF_INET6, …, IPPROTO_MPTCP)` fail with `EPROTONOSUPPORT` (programs fall back to plain TCP, which these rules govern); `hello` reports "MPTCP blocked by seccomp" |
| IPC scope | signals and abstract Unix sockets limited to the gate's own domain where the kernel ABI supports it for the whole process: ABI 8 (`LANDLOCK_RESTRICT_SELF_TSYNC`). Below ABI 8 each thread is restricted separately and gets its own domain, so scoping would stop the gate signalling its own children; it is not enabled there and `hello` reports it as not enforced |

Landlock is allow-list only and cannot carve an exception *inside* an allowed tree, so the deny list (§3) is still enforced in userspace, and Unix permissions still protect files such as `/etc/shadow` under the readable `/etc`. `landlock: required` (default) makes the gate refuse to serve with `sandbox_unavailable` when the kernel lacks Landlock or the ABI needed for the configured rules; `best-effort` must be chosen explicitly and the effective ABI is reported by `hello` and `check-policy`.

## 4b. Service control and polkit

`services.control` lists exact unit names and verbs. The gate runs `systemctl --no-ask-password <verb> -- <unit>` as the service user; systemd asks polkit, which authorizes it only through the rule generated by `shell-mcp-gate polkit --policy <file> --user <name>`:

```js
// Generated by shell-mcp-gate — do not edit by hand.
polkit.addRule(function (action, subject) {
  if (action.id !== "org.freedesktop.systemd1.manage-units" || subject.user !== "svc-shell") {
    return polkit.Result.NOT_HANDLED;
  }
  var allowed = { "example-app.service": ["restart", "reload"] };
  var verbs = allowed[action.lookup("unit")];
  if (verbs && verbs.indexOf(action.lookup("verb")) !== -1) {
    return polkit.Result.YES;
  }
  return polkit.Result.NOT_HANDLED;
});
```

A denied action surfaces as `not_authorized`. Glob patterns are never allowed in `services.control.units`. (The session that implements this verifies the rule syntax and the `unit`/`verb` details against the installed polkit and systemd documentation.)

## 5. Hard-deny list (built-in, non-removable)

A command whose resolved binary's base name (after following symlinks, e.g. `/usr/bin/awk → mawk`) is in this table is a policy error in the **gate** policy. The **helper** policy (docs/PRIVILEGED.md §5.3) treats groups 1–10 the same way and allows groups 11–13 only with an `acknowledge` string.

| # | Group | Binaries |
|---|---|---|
| 1 | Shells | `sh bash dash zsh ksh mksh csh tcsh fish ash rbash busybox toybox` |
| 2 | Interpreters | `python python2 python3 python3.* pypy* perl perl5.* ruby irb node nodejs deno bun php php* lua lua5.* luajit tclsh wish Rscript julia` |
| 3 | Text-program languages | `awk gawk mawk nawk` |
| 4 | Launchers and wrappers | `env xargs nohup setsid timeout nice ionice stdbuf flock watch parallel` |
| 5 | Debuggers and tracers | `strace ltrace gdb lldb valgrind` |
| 6 | Pagers and editors | `less more most man pg vi vim vim.* nvim view ex ed nano pico emacs joe mcedit` |
| 7 | Privilege changers | `su sudo doas pkexec runuser setpriv chroot nsenter unshare capsh newgrp sg` |
| 8 | Tunnels and transfer | `ssh scp sftp rsync nc ncat netcat socat telnet ftp tftp` |
| 9 | Session tools | `script expect screen tmux` |
| 10 | Identity and scheduling administration | `useradd usermod userdel groupadd groupmod passwd chpasswd chage visudo vipw vigr crontab at batch` |
| 11 | Power | `reboot shutdown poweroff halt kexec init telinit` |
| 12 | Kernel and storage | `insmod rmmod modprobe sysctl mount umount mkfs mkfs.* fdisk sfdisk parted wipefs dd` |
| 13 | Firewall | `iptables ip6tables nft ufw firewall-cmd` |

`systemctl`, `journalctl` and `git` may not appear as gate policy commands — their safe forms are built-in operations.

## 6. GTFOBins warnings

`check-policy` embeds a list of binaries with documented escape techniques (file read/write, command execution, SUID abuse) and prints a WARN for each policy command that uses one, with the technique categories. Warnings do not block, but every warned command should be reviewed: prefer a built-in operation, tighten the template, and never pass `{path:write}` to a binary that can execute or write arbitrary files.

## 7. Git hardening (built-in git ops)

Every git invocation is:

```
git -C <repo> --no-pager --no-optional-locks \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.pager=cat \
    -c core.sshCommand=/bin/false -c credential.helper= \
    -c protocol.file.allow=never -c protocol.ext.allow=never \
    -c safe.directory=<repo> <subcommand> …
```

with `GIT_CONFIG_NOSYSTEM=1` in the environment. Repo-local configuration can otherwise execute commands during read-only operations (`core.fsmonitor`) or pulls (hooks, `core.sshCommand`). `git_pull` refuses when `remote.origin.url` differs from the policy's `remote`, when the working tree is dirty, or when the pull is not a fast-forward. (Session S1b verifies each flag against the installed git's documentation.)

## 8. Example: read-only policy

```yaml
version: 1
max_tier: read
paths:
  read: [/srv/app, /etc/example-app, /var/log/example-app]
services:
  status: ["*"]
journal:
  units: ["*"]
  max_lines: 1000
git:
  repos:
    - path: /srv/app/deploy
      remote: https://git.example.test/org/deploy.git
commands:
  - id: apt-upgradable
    path: /usr/bin/apt
    tier: read
    templates: [["list", "--upgradable"]]
```
