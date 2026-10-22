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
  status: ["example-app.service", "example-*.service"]   # glob over unit names (fnmatch, no "/"); also what service_list shows
  control:
    units: ["example-app.service"]                        # exact names only — become the generated polkit rule
    verbs: [restart, reload]                              # subset of start|stop|restart|reload
journal:
  units: ["example-app.service"]                          # exact names or globs; "*" allows all units
  max_lines: 2000                                         # ≤ 10000
git:
  repos:
    - path: /srv/app/deploy                               # must be inside a read root (write root for pull/discard)
      remote: https://git.example.test/org/deploy.git     # https:// only (§7); pull refuses if origin differs
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

**Git remotes must be `https://` URLs with a host** (no query or fragment). SSH remotes cannot work — the gate sets `core.sshCommand=/bin/false` and `ssh` is hard-denied — and `file://` (and plain local paths) are disabled by `protocol.file.allow=never`, so the loader rejects anything else with a one-line reason. `check-policy` warns when a remote's port (443 unless given) is not in `sandbox.tcp_connect_ports`, because `git_pull` could then never connect.

## 2. Tiers

| Tier | Meaning |
|---|---|
| `read` | No state change on the host. |
| `operator` | Changes state reversibly: service lifecycle, writes inside write roots with read-back, fast-forward pulls. |
| `destructive` | Deletes data or discards work. Requires the server's `admin` profile, a human approval (D-006), and `max_tier: destructive` here. |

An op or command above `max_tier` is refused with `tier_denied` before any other processing.

**The request's ceiling.** Every request also names a `ceiling` tier (ARCHITECTURE §4.1): the tier of the server tool that sent it, so `shell_run_read_command` sends `read` and an operator tool `operator`. The gate refuses any op or `exec` command whose tier is above **min(`max_tier`, `ceiling`)**, in the same check and at the same point: first, before anything else about the request. A request without a ceiling, or with a value other than `read`, `operator` or `destructive`, is `bad_request`. The ceiling can only lower the limit, never raise it above `max_tier`; the refusal says which limit applied. For `priv_*` ops the gate uses min(`privileged.max_tier`, `ceiling`) and forwards the ceiling unchanged, and the helper applies it again (PRIVILEGED §6).

The ceiling is defence in depth against server mistakes and races — a tool that would otherwise check a command's tier with one request and run it with another, while root edits the policy in between — and it makes the server's profile a second enforcement point on the host. It is not a defence against a compromised server, which can send any ceiling: `max_tier` and the rest of this policy remain the boundary for that, so write them for the worst case as above.

## 3. Paths

- All roots and requested paths must be absolute and already clean (no `.`/`..` components, no trailing slash except `/` itself, no NUL, ≤ 4096 bytes). The gate rejects unclean input instead of cleaning it.
- The root for a request is the **longest** configured root that is a path-prefix (on component boundaries) of the requested path.
- Operations run through `os.Root` opened at that root, so `..` and symlinks cannot escape it. After opening, the gate reads `/proc/self/fd/N` and re-checks the real path against the root and the deny list. A symlink as the **final** component is refused (`path_denied`) for every op except `stat` (which reports it as a symlink without following).
- `/` may not be a root. `/proc`, `/sys`, `/dev`, `/run` may not be roots or inside one (the native `sysinfo`/`disk`/`processes` ops read what they need themselves: a fixed list of files — `/etc/os-release` or `/usr/lib/os-release`, `/proc/uptime`, `/proc/loadavg`, `/proc/meminfo`, `/proc/stat`, `/proc/self/mountinfo` and `/proc/<pid>/{stat,status,cmdline}` — never a path from a request).
- os.Root refuses a directory symlink with an **absolute** target even when it points back inside the root. Such a refusal is `path_denied` with a message that says so (without naming any path); stat the symlink to see its target and retry with the resolved path.

**Built-in read deny list** (always applied; policy `deny` adds to it):
`/etc/shadow*`, `/etc/gshadow*`, `/etc/sudoers`, `/etc/sudoers.d/**`, `/etc/ssh/*_key`, `/etc/ssh/authorized_keys.d/**`, `/root/**`, `/home/*/.ssh/**`, `**/.ssh/**`, `**/.gnupg/**`, `**/.docker/config.json`, `**/.kube/config`, `**/.netrc`, `**/.git-credentials`, `**/.pgpass`, `/var/lib/shell-mcp/**`, `/proc/*/environ`, `/proc/*/mem`, `/proc/*/task/*/environ`, `/proc/*/task/*/mem`, `/proc/kcore`.
The `/proc` entries (per process and per thread) are defence in depth: no root may be `/proc` or inside it (above), and the helper's Landlock ruleset grants nothing there (PRIVILEGED §5.1). They still refuse on their own if either rule ever gives way. The gate and the privileged helper apply this list alike. A refusal names the rule that applied: a built-in rule by its pattern, a policy `deny` entry only by its index (`paths.deny[N]`), so a privileged policy's values never reach the wire.
Additionally, any file whose first 64 KiB contain a `-----BEGIN … PRIVATE KEY-----` header is refused for `read_file`.

**Built-in protected set** (never writable; a write root equal to, inside, or containing any of these is a policy error):
`/etc/shell-mcp`, the gate binary's path, `/etc/ssh`, `/etc/sudoers`, `/etc/sudoers.d`, `/etc/pam.d`, `/etc/security`, `/etc/systemd`, `/usr/lib/systemd`, `/lib/systemd`, `/run/systemd`, `/etc/cron*`, `/var/spool/cron`, `/etc/profile`, `/etc/profile.d`, `/etc/environment`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d`, `/etc/ld.so.preload`, `/etc/passwd`, `/etc/group`, `/etc/shadow*`, `/etc/gshadow*`, `/etc/fstab`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/root`, the service user's home directory, `**/.ssh`, and `**/.git`.

**`.git` is never writable through the file operations.** `write_file`, `mkdir`, `copy`, `move`, `chmod`, `delete` and `{path:write}` placeholders refuse any path with a `.git` component (`path_denied`), and a recursive delete or directory move of a tree that contains one is refused. A write root may contain a repository but may not be, or be inside, its `.git`. Repository configuration, hooks and attributes can make git run commands or fetch from another host; the built-in git operations (§7) write there through git itself. The one exception is `git_discard` (§7, "Discarding changes"), and it covers exactly three names in the verified `<repo>/.git` of a listed repository: it creates `.git/index.lock` and a temporary index `.git/.shell-mcp-index-<32 hex>` (each `O_CREAT|O_EXCL|O_NOFOLLOW` on the `.git` descriptor), and renames that temporary index onto `.git/index`. No file operation and no other path under `.git` is affected.

Write rules: temp file in the same directory → write → `fsync` → `rename` → re-open and SHA-256 compare (`verify_failed` on mismatch). Existing mode and owner are preserved when the caller can; new files get `0640` unless `mode` is given. Modes with setuid, setgid, or world-write bits are refused. `copy`/`move` never overwrite unless `overwrite: true`, and both source and destination must satisfy their tier's roots.

**`chmod` never acts through a hard link.** `chmod` changes an inode, not a name, and the inode's other names can lie outside the write roots: the roots, and the Landlock sandbox (§4a, which has no chmod right), confine paths, not inodes. So `chmod` refuses a file (anything but a directory) whose link count is above 1, with `path_denied` naming the path and the count. The count is read by `fstat` on the descriptor that `fchmod` then acts on, never by another lookup; a link made after that check is equivalent to one made after the change. `chmod` also refuses a file or directory that has setuid, setgid or sticky bits (`policy_denied`): a requested mode cannot carry them, so chmod could only clear them, and clearing a shared directory's sticky bit or a setgid directory's bit is not harmless (handoff N-2). The privileged helper's `priv_chmod` and `priv_chown` apply both rules to every entry they change, and change an entry only when no account but root could have put it there (PRIVILEGED §6, "Chown and chmod"). The helper also reads, or keeps the owner of, a file under a directory another account could write only when that account could have read or written it itself (PRIVILEGED §6, "Files another account could have moved in"); the gate's own reads and writes run as the service account, which reads only what it may read and cannot give a file another account's ownership, so they need no such rule.

**Create-only commits are atomic.** `write_file` with `expect_absent: true` (mutually exclusive with `expected_sha256`; both is `bad_request`), and `copy` and `move` without `overwrite`, refuse with `exists` a destination that exists at the moment of the commit, not only when it was checked, and leave it untouched. Write and copy commit the temp file with a hard link inside the parent's `os.Root` (`link(2)` fails with `EEXIST` if the name exists, a symlink included), then remove the temp name, then verify by re-reading. Move uses `renameat2(2)` with `RENAME_NOREPLACE` on the parent directories' descriptors that the gate opened through `os.Root` and re-checked, with single-component names: `os.Root`'s own `Rename` has no flags (Go 1.27), and a hard link cannot move a directory, nor be undone without risking a source replaced meanwhile. There is no check-then-rename fallback: a filesystem that refuses the hard link (`EPERM`, `EOPNOTSUPP`, `ENOSYS`, for example one without hard links) or does not support `RENAME_NOREPLACE` (`EINVAL`, `ENOSYS`, for example NFS) is `bad_request` with a message naming the limitation, and nothing changes. A replace bound to the destination's content is a verified replace (below); an unconditional replace keeps `rename(2)`. The privileged helper applies the same rules (PRIVILEGED §6).

**Bound replaces are verified.** `write_file` with `expected_sha256`, and `copy` and `move` with `overwrite` and `expected_destination_sha256` (64 lowercase hex digits, valid only with `overwrite`; the destination must be a regular file with that content, otherwise `exists`, or `not_found` when it is gone; an approved overwrite sends it, ARCHITECTURE §3), replace only the file they checked. Linux has no conditional rename-over, so the commit is a `renameat2(2)` `RENAME_EXCHANGE` of the new file (the temp file, or the moved source) and the destination, on the parent directories' verified descriptors with single-component names, followed by a check that the inode exchanged out is the one that was hashed: the same inode, size and modification time. Anything else (a file renamed over the destination, or one rewritten in place, after the check) is exchanged back and the operation refused with `exists`, nothing replaced and a move's source left where it was; only then is the old inode's name removed. A filesystem without `RENAME_EXCHANGE` (`EINVAL`, `ENOSYS`, for example NFS) refuses these replaces with `bad_request` ("the filesystem does not support RENAME_EXCHANGE, which a verified replace needs …"), never a check-then-rename. What remains is the helper's (PRIVILEGED §6, verified replaces): a process that already holds the old file open for writing and writes through that descriptor after the check writes into an inode that is then removed; a process with write access to the directory could swap the exchanged-out name in the moment before its check (it could replace the destination itself); and the check compares inode, size and mtime, never the change time, which the exchange itself changes. So the destination's owner (or anyone who may write it and set its times) could edit it in place, keep its size, and reset its mtime with `utimensat(2)` at the exact moment between the check and the exchange; that edit is then overwritten. Mtime comparisons are only as fine as the kernel's timestamps, so a same-size rewrite within one clock tick is the same case without the reset. **Unconditional replaces** keep `rename(2)` and replace whatever regular file is under the name at the commit, as before: `write_file` without `expected_sha256` or `expect_absent`, and `copy` and `move` with `overwrite` and no `expected_destination_sha256` (what an unapproved call sends). Their checks (type, setuid, setgid, sticky and world-write bits) hold up to a few system calls before the rename; `old_sha256` in a write's or copy's result is the hash of the file as checked.

**A delete removes exactly what its preview listed, or stops.** `delete_preview` walks the path under a write root one directory at a time, each opened as an `os.Root` from its parent's handle and re-checked (requested and real path against the roots, the deny list and the protected set; `statx` identity). It returns the type, the entry count (the path included), the bytes of the regular files, the first 50 entries (the path, then depth-first in byte order of names) and `preview_sha256`: a SHA-256 over every entry's path, type, size, device, inode, change time and, where the filesystem reports it, birth time. So an entry added, removed, renamed, resized, modified or replaced by another inode changes it, also when an inode number is reused. Both `delete_preview` and `delete` refuse: a root of the policy (read or write) and a tree holding one; anything outside the write roots, on the deny list or in the protected set, `.git` included, and a tree holding such an entry (`path_denied`); a final symlink (`path_denied`); a mount point, the root of another filesystem (a directory on another device), and a tree holding one (`path_denied`, compared by `statx` mount id); a character or block device node and a tree holding one (`path_denied`: the sandbox (§4a) grants no right to create one, which setting it aside needs); a non-empty directory without `recursive` (`bad_request`); and more than `limits.max_delete_entries` entries (`too_large`). Symlinks inside a tree are removed as links, never followed. `delete` requires the preview's hash as `expected_preview_sha256` (ARCHITECTURE §4.1), walks the tree again, and refuses with `exists`, deleting nothing, unless the hash is the same. It then removes the listed entries bottom-up, re-opening each directory by name from its parent's handle and requiring the identity it saw; it never reads a directory again and never addresses an entry by a path from the root. Each entry is checked under its name, set aside under a random name in the same directory with `renameat2(2)` and `RENAME_NOREPLACE`, checked again there, and only then unlinked (`AT_REMOVEDIR` for a directory, which fails if it gained entries); an entry that is not what the preview saw, or a directory that gained entries, is put back under its name and the deletion stops with `exists`, whose message says how many of the entries were deleted. Linux has no conditional unlink (`unlinkat` removes whatever is under a name at that moment), which is why each entry is set aside before it is checked. What remains is described in ARCHIVE §14 (2026-10-18, and 2026-10-18 S4b-2b for the third case): a process that finds the random name and replaces it between the second check and the unlink, which needs write access to that directory (and so could delete the entry itself); on a filesystem that reports no birth time, an inode number reused within the moment between the first check and setting the entry aside; and a process that already holds a listed file open for writing and writes through that descriptor after the entry's last check (the second check here; the content check in a discard) and before its unlink, a window of a few system calls, whose write lands in an inode that is then removed. Only a file lease could close the last one, and leases need the file's owner (or `CAP_LEASE`), which the service account usually is not. A filesystem without `RENAME_NOREPLACE` is refused with `bad_request` before anything is deleted; there is no fallback to a plain unlink. The privileged helper's `priv_delete` applies the same rules, through the same code, with its policy's hash in the preview hash and a backup written from the plan before anything is removed (PRIVILEGED §6, "Delete").

**Which fields each step compares.** At the recompute: the whole hash (every entry's path, type, size, device, inode, change time and birth time); nothing has been changed yet, so no timestamp has moved. When an entry is checked under its name: device, inode, type, mount id and birth time, and for a non-directory the size and change time, except for an inode this delete already renamed or unlinked under another of its names (a hard link), whose change time that moved, which is compared by object and size only. After it is set aside: device, inode, type, mount id and birth time; never the change time, which a rename may move. Before a directory is removed: nothing beyond that; its times and size move as its entries are removed, and `AT_REMOVEDIR` is the kernel's own check that it is empty. Change-time comparisons are as fine as the kernel's timestamps, which can be one clock tick.

**Filesystems without `RENAME_NOREPLACE`.** Delete, and move without `overwrite`, are refused (`bad_request`, nothing changed) on a filesystem that does not support `RENAME_NOREPLACE`: for example NFS (every version; the Linux client refuses every rename flag), and FUSE filesystems whose server does not implement rename2 (the kernel then refuses the flag). SMB/CIFS is not such an example: the Linux client supports `RENAME_NOREPLACE` since 3.17 (rename(2), `cifs_rename2`), relying on the server's refusal to replace an existing name. `shell-mcp-gate check-policy` probes each write root (it creates, renames and removes a `.shell-mcp-probe-*` file inside it) and prints a WARN for a root whose filesystem does not support the flag, or that it could not probe. It probes `RENAME_EXCHANGE` the same way (two such files, exchanged, both removed), which bound replaces need (above): NFS supports neither flag.

**Entries set aside and not removed.** A delete that puts an entry back and finds its name taken again (something created it meanwhile), or a gate that dies between setting an entry aside and removing or restoring it (a timeout, the SSH session closing, SIGKILL), leaves that entry in its directory under a name starting with `.shell-mcp-delete-` followed by 32 hex digits. When the gate notices (the put-back failed), the refusal's message names both the temporary path and the path the entry appeared under, and the gate's audit line names the temporary path (`set_aside`). Such an entry is never deleted by the gate: `delete_preview` and `delete` refuse any path that is, or contains, a name with that prefix (`path_denied`). To recover, on the host: `find <write root> -name '.shell-mcp-delete-*'`; inspect each entry; move it back under the path the message named (once that path is free) or to another name, or remove it if it is not wanted. Until then the tree that holds it cannot be deleted through the gate.

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

**Previews.** `exec_preview` (read tier) resolves a request exactly as `exec` does, through the same code: the command's tier against min(`max_tier`, `ceiling`) first, then the template match with path placeholders resolved under their roots, then the `cwd`. It runs nothing and returns the command id, tier, description, `root_equivalent`, the template that matched, the resolved argv (`argv[0]` the resolved binary), the resolved `cwd`, the policy's SHA-256 and `preview_sha256` over all of them. `exec` takes that hash as an optional `expected_preview_sha256`: when it is given, `exec` resolves the request again and refuses with `exists`, running nothing, unless it hashes the same. So a policy edit (another binary or template for the id, another tier), a path placeholder or `cwd` that now resolves elsewhere, or anything else that changes what would run, stops an approved command. The approved `shell_run_command` always sends it (TOOLS.md).

**Placeholders** (a token that is exactly `{type}` or `{type:param}`):

| Placeholder | Accepts |
|---|---|
| `{path:read}` / `{path:write}` | Absolute clean path that the gate resolves under a read/write root and that passes the deny list. The resolved path is what is passed. In the privileged policy, a root command looks that path up again itself, so the helper also requires every directory from `/` to its parent (and to the `cwd`'s) to be root's, neither group- nor world-writable and not sticky, and a directory given as a placeholder, or as the `cwd`, to be so itself, or refuses with `path_denied` (PRIVILEGED §6, "Commands"). |
| `{unit}` | A unit name matching `services.status`. |
| `{int:MIN-MAX}` | Decimal integer in range. |
| `{enum:a\|b\|c}` | One of the listed literals. |
| `{regex:^…$}` | RE2 regex, must be anchored with `^…$`, max 256 chars. |

**Universal placeholder rules:** a placeholder value may never start with `-`, contain NUL, newline, or exceed 1024 bytes. (Option injection is the most common way a "safe" binary becomes unsafe.)

**Privilege:** there is none. Policy commands run as the service user inside the gate's `no_new_privs` + Landlock domain; setuid binaries therefore cannot gain privilege, and there is no `sudo` option. A command that only works as root belongs in the privileged policy instead, where it runs through the privileged helper, previewed and, from tier operator, approved (`docs/PRIVILEGED.md` §6, "Commands", with a worked example of a fixed root command for an application-owned tree).

**Execution environment:** `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, `HOME=<service user home>`, `PAGER=cat`, `SYSTEMD_PAGER=`, `SYSTEMD_COLORS=0`, `GIT_TERMINAL_PROMPT=0`, `NO_COLOR=1`, `TERM=dumb`. Nothing from the request or sshd is inherited. `cwd` (optional) must be inside a read root; default is `/`. `stdin` (optional) ≤ `limits.max_stdin_bytes`; otherwise stdin is `/dev/null`.

## 4a. Sandbox

Before reading the request, the gate sets `no_new_privs` and applies a Landlock ruleset to all its threads; every child inherits it. The ruleset is derived from this file:

| Access | Paths |
|---|---|
| read + execute | `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/etc` (read only), plus `sandbox.system_read_exec` |
| read | `paths.read` roots; `/proc` (for native system ops); journal directories when `journal` is configured |
| read + write | `paths.write` roots (no execute) |
| single files | `/dev/null` (read, write, truncate) and `/dev/urandom` (read) — these two files only, never `/dev` itself, no ioctl; many declared binaries open them |
| unix socket connect | the directory of the system D-Bus socket (`/run/dbus`) when any service feature is configured — `services.status` (which also enables `service_list` and `{unit}` placeholders) or `services.control` — because `systemctl` reaches systemd over the system bus; the directory that really holds the syslog socket (`/dev/log` resolved, `/run/systemd/journal` on systemd hosts) always, for the audit line; the helper socket(s)' directory when `privileged.enabled`. Grants are on the directory holding the socket (the kernel accepts every right on a directory; no runner has the ABI to test file-level socket rules). On kernels whose Landlock ABI does not govern pathname Unix-socket connects (below 9), file permissions and the helper's peer-UID check are the controls — `hello` reports which applies. |
| TCP connect | only `sandbox.tcp_connect_ports`; no TCP bind at all. Landlock does not govern Multipath TCP sockets, so after Landlock the gate installs a seccomp filter that makes `socket(AF_INET/AF_INET6, …, IPPROTO_MPTCP)` fail with `EPROTONOSUPPORT` (programs fall back to plain TCP, which these rules govern); `hello` reports "MPTCP blocked by seccomp" |
| UDP | **unrestricted in v1.** Landlock governs UDP only from ABI 10, which the target kernels (Debian 13, Ubuntu 26.04 LTS) do not have, and restricting it would deny DNS to every command and to `git_pull`. |
| IPC scope | signals and abstract Unix sockets limited to the gate's own domain where the kernel ABI supports it for the whole process: ABI 8 (`LANDLOCK_RESTRICT_SELF_TSYNC`). Below ABI 8 each thread is restricted separately and gets its own domain, so scoping would stop the gate signalling its own children; it is not enabled there and `hello` reports it as not enforced |

The gate starts every command (declared commands, `git`, `systemctl`, `journalctl`) by re-executing its own binary as the exec trampoline (ARCHITECTURE §2, `internal/gate/execx`), which puts the child's limits (`RLIMIT_CORE=0`, `RLIMIT_NOFILE`, `RLIMIT_NPROC`) in force before the command's first instruction. Under Landlock the gate binary must therefore sit under a read + execute directory — `/usr/local/bin/shell-mcp-gate` does; `check-policy` warns otherwise. No rule is added for it.

Landlock is allow-list only and cannot carve an exception *inside* an allowed tree, so the deny list (§3) is still enforced in userspace, and Unix permissions still protect files such as `/etc/shadow` under the readable `/etc`. `landlock: required` (default) makes the gate refuse to serve with `sandbox_unavailable` when the kernel lacks Landlock or the ABI needed for the configured rules; `best-effort` must be chosen explicitly and the effective ABI is reported by `hello` and `check-policy`. The refusal is actionable: it states the kernel's Landlock ABI (or that it has none), the minimum the policy needs under `required` (ABI 4), and that `best-effort` is the alternative; a failure to install the MPTCP seccomp filter says so, with the same alternative.

## 4b. Service control and polkit

`services.control` lists exact unit names and verbs. The gate runs `systemctl --no-ask-password <verb> -- <unit>` as the service user; systemd asks polkit, which authorizes it only through the rule generated by `shell-mcp-gate polkit --policy <file> --user <name>`:

```js
// Generated by shell-mcp-gate polkit — do not edit by hand.
// Policy sha256: <the policy's SHA-256>
// Lets svc-shell run exactly these systemctl verbs on exactly these units.
polkit.addRule(function (action, subject) {
  if (action.id !== "org.freedesktop.systemd1.manage-units" || subject.user !== "svc-shell") {
    return polkit.Result.NOT_HANDLED;
  }
  var allowed = {
    "example-app.service": ["restart", "reload"]
  };
  var unit = action.lookup("unit");
  if (typeof unit !== "string" || !Object.prototype.hasOwnProperty.call(allowed, unit)) {
    return polkit.Result.NOT_HANDLED;
  }
  if (allowed[unit].indexOf(action.lookup("verb")) !== -1) {
    return polkit.Result.YES;
  }
  return polkit.Result.NOT_HANDLED;
});
```

Every unit gets every verb in `services.control.verbs` (units × verbs). The generator refuses a glob or any unit name that is not exact (with a type suffix), an unknown or repeated verb, `root` as the user, and an empty `services.control`; `polkit` loads and validates the policy exactly as `serve` would. The `hasOwnProperty` lookup keeps a unit name that happens to match an `Object.prototype` member from reaching `indexOf` on a non-array. Install as `/etc/polkit-1/rules.d/60-shell-mcp.rules`, `root:root 0644`.

Verified at the source (systemd 257.13 on Debian 13, 259.5 on Ubuntu 26.04 LTS; polkit 126 and 127):

- Unit start/stop/restart/reload call polkit for `org.freedesktop.systemd1.manage-units` with the details `unit` (the unit id) and `verb`: `start`, `stop`, `restart`, `reload` (`try-restart` and `reload-or-…` for other systemctl verbs, which the rule never allows). systemd added these details in v226.
- polkit reads `/etc/polkit-1/rules.d/*.rules` in lexical order; `polkit.addRule`, `action.lookup()` (undefined when absent), `subject.user` and `polkit.Result.YES`/`NOT_HANDLED` are as used above. Both versions run rules with Duktape (ECMAScript 5.1); the rule uses nothing newer.

A denied action surfaces as `not_authorized`. systemctl reports a polkit denial in one of two ways: polkit "no" is `org.freedesktop.DBus.Error.AccessDenied`, exit status 4 (`EXIT_NOPERMISSION`); a challenge that `--no-ask-password` cannot answer (no rule, default `auth_admin`) is `InteractiveAuthorizationRequired`, exit status 1 with "Interactive authentication required." (257) or "…requires interactive authentication…" (259). The gate maps both to `not_authorized`; any other failure is `exec_failed`. After a successful action the gate re-reads the unit's status. Glob patterns are never allowed in `services.control.units`.

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

**Packages are never changed by a gate command.** Gate commands run as the service account, which cannot install, upgrade or remove packages; a read command such as `apt list --upgradable` (the example above) only reads. Package changes run only through the privileged helper's package operations, as root in its broad unit, each bound to an approved transaction of exact package versions and verified against dpkg's status afterwards (PRIVILEGED §6, "Package operations").

**The host is never rebooted or powered off by a gate command.** Group 11 (power) is hard-denied for gate commands. A reboot or power-off runs only through the privileged helper's power operation, when its policy lists that action: answered first, requested from logind after a stated delay unless cancelled, never while a package operation runs, and refused while a systemd inhibitor lock blocks it (PRIVILEGED §6, "Power").

**Binary identity check.** A hard link or a copy would give a hard-denied binary an innocent name. After a command's binary is resolved, the gate compares it — by device and inode, and by SHA-256 when the sizes match — with every file under `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin` and `/usr/local/sbin` (following symlinks) whose name is in the table above. A match is a policy error naming the denied binary. Consequently a multi-call binary that a denied name links to (for example one tool reached as both a firewall command and an innocent-sounding helper) is refused under every name.

**Limitation in v1: coreutils on hosts with a multi-call coreutils.** Where coreutils is a single multi-call binary — for example Ubuntu 26.04's Rust coreutils, whose `du`, `df`, `stat` and every other command are hard links to one binary that also answers to `chroot`, `env`, `nice`, `nohup`, `stdbuf` and `timeout` — every coreutils command is refused by the identity check, so none can be declared (in the gate or the privileged policy). Declare tools from other packages (for example util-linux `findmnt`), or use the built-in operations. A later design session (plan §5) decides whether argv[0]-dispatched multi-call binaries can be allowed.

## 6. GTFOBins warnings

`check-policy` embeds a list of binaries with documented escape techniques and prints a WARN for each policy command that uses one, with the technique categories (command execution, file read, file write, SUID abuse) and a link to the binary's page on gtfobins.org. Warnings do not block, but every warned command should be reviewed: prefer a built-in operation, tighten the template, and never pass `{path:write}` to a binary that can execute or write arbitrary files. The list is this project's own (names and coarse categories, written from each binary's documented behaviour and checked against the public index); nothing is copied from GTFOBins, whose content is GPL-3.0.

## 7. Git hardening (built-in git ops)

Every git invocation is:

```
git -C <repo> --no-pager --no-optional-locks \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.pager=cat \
    -c core.sshCommand=/bin/false -c credential.helper= \
    -c protocol.file.allow=never -c protocol.ext.allow=never \
    -c safe.directory=<repo> \
    -c maintenance.auto=false -c gc.auto=0 -c gc.autoDetach=false \
    -c core.ignorecase=false <subcommand> …
```

The last line keeps git from starting automatic maintenance or gc, and pins case sensitivity. With git's defaults, a pull ends by running `git maintenance run --auto --detach` (after the fetch and again after the merge). That process daemonizes (`fork`, the parent exits, `setsid`): it leaves the gate's process group, so the gate's group kill cannot reach it, and it outlives the request (still inside the gate's Landlock + `no_new_privs` domain). `core.ignorecase=true` in a repo on a case-sensitive filesystem would hide untracked files that differ only in case from tracked ones, from `status` and from `clean` (so `git_discard_preview` would under-report). Command-line `-c` values override the repository's own configuration and are passed to git's child processes. Both are tested two-sided: git's defaults leave detached processes after a pull while `git_pull` leaves none; `core.ignorecase=true` hides an untracked file while `git_status` lists it.

**Repositories on case-folding filesystems are not supported by the git operations.** Because the gate always passes `core.ignorecase=false`, git treats every repository as case-sensitive. On a case-folding filesystem — casefold (`+F`) directories, CIFS/SMB mounts, or similar — git would then misjudge which files are tracked and untracked, so `git_status`, `git_discard_preview` and `git_discard` could report or remove the wrong files. Keep repositories listed in `git.repos` on an ordinary case-sensitive Linux filesystem.

with exactly this environment: the gate's fixed variables (§4) plus `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_DIR=<repo>/.git` and `GIT_WORK_TREE=<repo>`, and, for `git_discard`'s commands on its temporary index only, `GIT_INDEX_FILE=<repo>/.git/.shell-mcp-index-<32 hex>`. Nothing else reaches git — the gate inherits no variable, so no `GIT_CONFIG_COUNT`/`KEY`/`VALUE`, no `GIT_ASKPASS` — and the only configuration git reads is the command line above and the repository's own `.git/config`.

**The repository's own configuration is checked before every git operation.** Repo-local configuration can make git run commands — `filter.<driver>.clean`/`smudge` (status, diff, reset, pull), `diff.<driver>.textconv` and `diff.external` (diff, log), `core.askPass`, `include.path` — or talk to another host (`url.<base>.insteadOf` rewrites the pull URL while `remote.origin.url` still matches). The gate reads it with `git config --local --no-includes --list -z` (which runs nothing) and refuses unless every key is on the list below **and** carries a value git accepts for it. A malformed value is refused too, because it can crash git (a valueless `remote.<name>.tagOpt` segfaults) or make it die part-way through an operation (a non-numeric `gc.auto` stops 2.55's merge after the fast-forward has happened). The list holds keys git uses only as data for the gate's fixed commands (`status`, `log`, `diff`, `pull --ff-only --no-rebase`, `reset --hard`, `clean`), checked in the documentation and source of git 2.47.3 and 2.55.0 (the CI image). No key on it can name a program, a path git executes or reads configuration from, a URL, a proxy, credentials, an include, a filter, a hook, an editor, a pager, a signing program, or another git directory or work tree:

| Key family | Keys and accepted values | Why it is inert here |
|---|---|---|
| Written by `git init`/`clone` | `core.repositoryformatversion` (integer); `core.filemode`, `core.bare`, `core.ignorecase` (always overridden by `-c core.ignorecase=false`), `core.precomposeunicode`, `core.symlinks` (boolean); `core.logallrefupdates` (boolean or `always`); `remote.origin.url`, `remote.origin.fetch`; `branch.<name>.remote`, `branch.<name>.merge` | Repository layout and the origin the policy already pins (`git_pull` also checks the URL). |
| Identity | `user.name`, `user.email` (a value) | The gate never commits; git uses them only as the reflog identity. |
| Line endings | `core.autocrlf` (boolean or `input`), `core.eol` (`lf`, `crlf`, `native`), `core.safecrlf` (boolean or `warn`) | Built-in conversions of file content; no program. |
| Pull strategy | `pull.rebase`, `branch.<name>.rebase` (boolean, `merges`, `interactive`, `m`, `i`); `pull.ff` (boolean or `only`) | Never read for the gate's `pull --ff-only --no-rebase`: the command line wins (`builtin/pull.c`), so even `interactive` starts no editor (tested). |
| Defaults | `init.defaultBranch` (a value) | Read only by `init`, `clone` and `remote show`. |
| Pruning and tags | `fetch.prune`, `remote.origin.prune` (boolean); `remote.origin.tagOpt` (exactly `--tags` or `--no-tags`) | They delete stale remote-tracking refs, or choose which tags to fetch, from the pinned origin. |
| Colors | `color.<command>` (`never`, `always`, `auto` or boolean); `color.<command>.<slot>` (a color: names, `bright…`, 0–255, `#rgb`/`#rrggbb`, attributes with optional `no`/`no-`). `color.blame.*` is excluded. | Colors only. Even with `always`, none of the output the gate parses carries escape codes (the porcelain and name-only printers never color; tested). `color.blame.highlightRecent` is a list of colors and dates, and blame never runs. |
| Hints | `advice.<name>` (boolean) | Toggles hint messages on stderr. |
| Auto-gc threshold | `gc.auto` (integer, optional `k`/`m`/`g`) | A number, and always overridden by `-c gc.auto=0`; it stays on the list so that repositories that set it are not refused. `gc.autoDetach`, `gc.*` otherwise and `maintenance.*` stay out. |

Everything else is refused with `policy_denied`. That includes `filter.*` (so **Git LFS repositories are not supported in v1**: LFS works through filter programs), `diff.*`, `merge.*`, `url.*`, `include.*` and `includeIf.*`, `core.askPass`/`editor`/`pager`/`worktree`/`hooksPath`/`fsmonitor`/`sshCommand`/`gitProxy`, `http.*`, `credential.*`, `gpg.*`, `user.signingKey`, other remotes, `remote.origin.pushurl`/`proxy`/`uploadpack`/`receivepack`, `extensions.*` and `submodule.*`. The refusal names the key and the command that removes it, run in the repository on the host: `git config --remove-section <section.subsection>` for a key under a subsection (a whole driver, url rewrite or remote), otherwise `git config --unset-all <key>`. Because `.git` is never writable through the file operations (§3), a caller cannot plant such configuration through the gate.

**The repository is pinned.** The repo must be listed in `git.repos` (and inside a write root for `git_pull` and `git_discard`); `<repo>/.git` must be a real directory inside the root — a gitfile, a symlink or a `commondir` (linked worktree) is refused.

**Operations.** `git_status` (`status --porcelain=v2 --branch -z`), `git_log` (`log --no-show-signature --no-ext-diff --no-textconv`, hash, author, date, subject), `git_diff` (`diff --no-ext-diff --no-textconv [--cached]`, redacted, capped), `git_discard_preview` and `git_discard` (below; never `reset --hard` or `clean -f`). `git_pull` runs `pull --ff-only --no-rebase --no-recurse-submodules` and refuses when `remote.origin.url` — or the URL git would actually use (`ls-remote --get-url origin`) — differs from the policy's `remote`, when tracked files have uncommitted changes, or when the pull is not a fast-forward (checked with `merge-base --is-ancestor HEAD FETCH_HEAD` after the refused merge); it returns the old and new HEAD and the number of changed files. Its TCP connect is governed by `sandbox.tcp_connect_ports`.

**Discarding changes (`git_discard_preview`, `git_discard`).** A discard restores the tracked files and the index to HEAD and, with `include_untracked: true` (default false), removes untracked files and directories; it discards exactly what its preview listed, or stops. The repository must be listed and inside a write root (for the preview too). Both ops refuse:
- a merge, rebase, `am`, cherry-pick, revert or bisect in progress (`policy_denied`: `MERGE_HEAD`, `CHERRY_PICK_HEAD`, `REVERT_HEAD`, `BISECT_LOG`, `rebase-merge`, `rebase-apply` or `sequencer` in `.git`), an unmerged index entry, and any submodule (gitlink) change;
- a repository without commits (`bad_request`);
- a tracked path that is now a directory, or a tracked path whose directory is now a file, unless `include_untracked` removes exactly that untracked entry (the refusal says so); an entry in the way that `git clean -d` does not list as untracked (it holds ignored files or a nested repository, or sits where a tracked file is) is never removed (`bad_request`, naming it);
- an untracked symlink, with `include_untracked` (`path_denied`: untracked symlinks are never removed);
- anything the file rules refuse at a listed path (the deny list, the protected set, a mount point, a device node, a FIFO or socket, a set-aside name), and more than `limits.max_delete_entries` paths and untracked entries (`too_large`); the bytes hashed are bounded at 256 MiB per preview (`too_large`);
- `.git/index.lock` existing (`exists`): another git process holds it, or left it, or a gate stopped while discarding left it (its content then starts with `shell-mcp-gate`, and the message says so). The gate never removes a lock it did not create in the same request. **Recovery:** on the host, check that no git process is running in the repository, then remove `.git/index.lock` (and any `.git/.shell-mcp-index-*` a stopped gate left), and preview again.

Ignored files are never touched (there is no `git clean -x`), nested repositories are skipped and listed, and HEAD, branches, tags and the stash are never changed. Entries flagged assume-unchanged or skip-worktree in the index lose the flag (the new index is HEAD's tree) and their files are not touched.

*The preview* runs `status --porcelain=v2 -z --no-renames --untracked-files=no --ignore-submodules=none` (a rename is a deletion and an addition) and `clean -n -d`, observes every listed path in the work tree without following anything (absent, a file and the SHA-256 of its content, a symlink and the SHA-256 of its target, or a directory; device, inode, change and birth time, size and permission bits), and walks every untracked path as a delete preview (§3). It returns HEAD, the counts (`restore`: tracked paths in HEAD; `remove`: paths staged as new; `untracked` and `untracked_entries`), the first 50 entries in byte order of paths (path, status letters or `??`, `restore` or `remove`), the skipped repositories, and `preview_sha256`: a SHA-256 over `include_untracked`, HEAD, every listed path's status letters, submodule field, HEAD, index and work-tree modes, HEAD and index object ids and work-tree entry, every untracked path with its delete preview hash, and the skipped repositories. An index entry staged after the preview, a file edited, replaced or chmod-ed, an untracked file created (with `include_untracked`) or a commit changes it.

*The discard* takes `expected_preview_sha256` (required) and `include_untracked`, and:
1. creates `.git/index.lock` exclusively, as git does before it changes the index, and holds it to the end, so no git process can change the index meanwhile (a concurrent `git add` fails on the lock); it is released on every exit path, also on errors and timeouts;
2. recomputes the preview and refuses with `exists`, changing nothing, unless its hash is the expected one;
3. sets aside every listed file and symlink in its own directory (the steps of a delete, §3: checked under its name, renamed to `.shell-mcp-delete-<32 hex>` with `RENAME_NOREPLACE`, then checked again: the same object, size and permission bits, and the same content SHA-256);
4. removes each untracked path exactly as its delete preview listed it (§3);
5. has git build HEAD's index in the temporary index (`read-tree <HEAD>`), write the restored files from it with `checkout-index -q --stdin -z` without `-f`, which creates each file (`O_EXCL`), never replaces one and never removes a directory in the way, refresh it, and list with `status` what still differs from it;
6. for each listed path that now matches HEAD, removes what it set aside, if its size and change time are still what they were when its content was checked (a write through a descriptor opened before the discard keeps it, named, and stops the discard); a path that does not match (something wrote it, or took its name, during the discard) is not restored: what was set aside is put back, or, when its name was taken, left under its temporary name, which the refusal names;
7. only when every listed path verified, renames the temporary index onto `.git/index`; otherwise the index is left as it was and the discard stops with `exists`, saying how many of the entries were discarded ("the index was not changed; preview the repository again to see what remains").

Every git command the discard runs carries the hardening flags above, so no hook runs (`core.hooksPath=/dev/null`; `read-tree` and `update-index` would otherwise run `post-index-change`).

*What remains* (ARCHIVE §14, 2026-10-18 S4b-2b). A change made after the preview is never discarded, with three exceptions, the same as a delete's (§3): a process that finds an entry's random temporary name and replaces it between its last check and its removal (it needs write access to that directory, so it could discard the entry itself); on a filesystem that reports no birth time, an inode number reused between an entry's first check and setting it aside; and a write through a descriptor opened before the discard set the file aside, made in the moment between the last check of the entry set aside and its removal (one system call; a write any earlier moves its change time and keeps it). Change times are as fine as the kernel's timestamps (§3). A file created under a free name (a listed one being set aside, or a new one) is never touched, an edit or replacement at any other moment stops the discard, and a commit, a staging change or a lock held by git refuses it before anything changes.

Verified against git 2.47.3 (Debian 13, and the CI and local test images) and the git 2.53 documentation (Ubuntu 26.04 LTS): every flag above exists; `safe.directory` is honoured from the command line (the "command" scope is protected configuration); an empty `credential.helper` resets the helper list; `core.hooksPath=/dev/null` disables hooks (tested on 2.47.3: a `post-checkout` hook runs without it and not with it; 2.53 documents it); `clean` messages are translatable, so git runs with `LC_ALL=C.UTF-8`.

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
