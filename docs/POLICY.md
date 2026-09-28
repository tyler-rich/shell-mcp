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
| `destructive` | Deletes data or discards work. Requires the server's `admin` profile, a human approval through elicitation, and `max_tier: destructive` here. |

An op or command above `max_tier` is refused with `tier_denied` before any other processing.

## 3. Paths

- All roots and requested paths must be absolute and already clean (no `.`/`..` components, no trailing slash except `/` itself, no NUL, ≤ 4096 bytes). The gate rejects unclean input instead of cleaning it.
- The root for a request is the **longest** configured root that is a path-prefix (on component boundaries) of the requested path.
- Operations run through `os.Root` opened at that root, so `..` and symlinks cannot escape it. After opening, the gate reads `/proc/self/fd/N` and re-checks the real path against the root and the deny list. A symlink as the **final** component is refused (`path_denied`) for every op except `stat` (which reports it as a symlink without following).
- `/` may not be a root. `/proc`, `/sys`, `/dev`, `/run` may not be roots or inside one (the native `sysinfo`/`disk`/`processes` ops read what they need themselves: a fixed list of files — `/etc/os-release` or `/usr/lib/os-release`, `/proc/uptime`, `/proc/loadavg`, `/proc/meminfo`, `/proc/stat`, `/proc/self/mountinfo` and `/proc/<pid>/{stat,status,cmdline}` — never a path from a request).
- os.Root refuses a directory symlink with an **absolute** target even when it points back inside the root. Such a refusal is `path_denied` with a message that says so (without naming any path); stat the symlink to see its target and retry with the resolved path.

**Built-in read deny list** (always applied; policy `deny` adds to it):
`/etc/shadow*`, `/etc/gshadow*`, `/etc/sudoers`, `/etc/sudoers.d/**`, `/etc/ssh/*_key`, `/etc/ssh/authorized_keys.d/**`, `/root/**`, `/home/*/.ssh/**`, `**/.ssh/**`, `**/.gnupg/**`, `**/.docker/config.json`, `**/.kube/config`, `**/.netrc`, `**/.git-credentials`, `**/.pgpass`, `/var/lib/shell-mcp/**`.
Additionally, any file whose first 64 KiB contain a `-----BEGIN … PRIVATE KEY-----` header is refused for `read_file`.

**Built-in protected set** (never writable; a write root equal to, inside, or containing any of these is a policy error):
`/etc/shell-mcp`, the gate binary's path, `/etc/ssh`, `/etc/sudoers`, `/etc/sudoers.d`, `/etc/pam.d`, `/etc/security`, `/etc/systemd`, `/usr/lib/systemd`, `/lib/systemd`, `/run/systemd`, `/etc/cron*`, `/var/spool/cron`, `/etc/profile`, `/etc/profile.d`, `/etc/environment`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d`, `/etc/ld.so.preload`, `/etc/passwd`, `/etc/group`, `/etc/shadow*`, `/etc/gshadow*`, `/etc/fstab`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/root`, the service user's home directory, `**/.ssh`, and `**/.git`.

**`.git` is never writable through the file operations.** `write_file`, `mkdir`, `copy`, `move`, `chmod`, `delete` and `{path:write}` placeholders refuse any path with a `.git` component (`path_denied`), and a recursive delete or directory move of a tree that contains one is refused. A write root may contain a repository but may not be, or be inside, its `.git`. Repository configuration, hooks and attributes can make git run commands or fetch from another host; the built-in git operations (§7) write there through git itself.

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
| unix socket connect | the directory of the system D-Bus socket (`/run/dbus`) when any service feature is configured — `services.status` (which also enables `service_list` and `{unit}` placeholders) or `services.control` — because `systemctl` reaches systemd over the system bus; the directory that really holds the syslog socket (`/dev/log` resolved, `/run/systemd/journal` on systemd hosts) always, for the audit line; the helper socket(s)' directory when `privileged.enabled`. Grants are on the directory holding the socket (the kernel accepts every right on a directory; no runner has the ABI to test file-level socket rules). On kernels whose Landlock ABI does not govern pathname Unix-socket connects (below 9), file permissions and the helper's peer-UID check are the controls — `hello` reports which applies. |
| TCP connect | only `sandbox.tcp_connect_ports`; no TCP bind at all. Landlock does not govern Multipath TCP sockets, so after Landlock the gate installs a seccomp filter that makes `socket(AF_INET/AF_INET6, …, IPPROTO_MPTCP)` fail with `EPROTONOSUPPORT` (programs fall back to plain TCP, which these rules govern); `hello` reports "MPTCP blocked by seccomp" |
| UDP | **unrestricted in v1.** Landlock governs UDP only from ABI 10, which the target kernels (Debian 13, Ubuntu 26.04 LTS) do not have, and restricting it would deny DNS to every command and to `git_pull`. |
| IPC scope | signals and abstract Unix sockets limited to the gate's own domain where the kernel ABI supports it for the whole process: ABI 8 (`LANDLOCK_RESTRICT_SELF_TSYNC`). Below ABI 8 each thread is restricted separately and gets its own domain, so scoping would stop the gate signalling its own children; it is not enabled there and `hello` reports it as not enforced |

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

**Binary identity check.** A hard link or a copy would give a hard-denied binary an innocent name. After a command's binary is resolved, the gate compares it — by device and inode, and by SHA-256 when the sizes match — with every file under `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin` and `/usr/local/sbin` (following symlinks) whose name is in the table above. A match is a policy error naming the denied binary. Consequently a multi-call binary that a denied name links to (for example one tool reached as both a firewall command and an innocent-sounding helper) is refused under every name.

## 6. GTFOBins warnings

`check-policy` embeds a list of binaries with documented escape techniques and prints a WARN for each policy command that uses one, with the technique categories (command execution, file read, file write, SUID abuse) and a link to the binary's page on gtfobins.org. Warnings do not block, but every warned command should be reviewed: prefer a built-in operation, tighten the template, and never pass `{path:write}` to a binary that can execute or write arbitrary files. The list is this project's own (names and coarse categories, written from each binary's documented behaviour and checked against the public index); nothing is copied from GTFOBins, whose content is GPL-3.0.

## 7. Git hardening (built-in git ops)

Every git invocation is:

```
git -C <repo> --no-pager --no-optional-locks \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.pager=cat \
    -c core.sshCommand=/bin/false -c credential.helper= \
    -c protocol.file.allow=never -c protocol.ext.allow=never \
    -c safe.directory=<repo> <subcommand> …
```

with exactly this environment: the gate's fixed variables (§4) plus `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_DIR=<repo>/.git` and `GIT_WORK_TREE=<repo>`. Nothing else reaches git — the gate inherits no variable, so no `GIT_CONFIG_COUNT`/`KEY`/`VALUE`, no `GIT_ASKPASS` — and the only configuration git reads is the command line above and the repository's own `.git/config`.

**The repository's own configuration is checked before every git operation.** Repo-local configuration can make git run commands — `filter.<driver>.clean`/`smudge` (status, diff, reset, pull), `diff.<driver>.textconv` and `diff.external` (diff, log), `core.askPass`, `include.path` — or talk to another host (`url.<base>.insteadOf` rewrites the pull URL while `remote.origin.url` still matches). The gate reads it with `git config --local --no-includes --list -z` (which runs nothing) and refuses unless every key is on the list below **and** carries a value git accepts for it. A malformed value is refused too, because it can crash git (a valueless `remote.<name>.tagOpt` segfaults) or make it die part-way through an operation (a non-numeric `gc.auto` stops 2.55's merge after the fast-forward has happened). The list holds keys git uses only as data for the gate's fixed commands (`status`, `log`, `diff`, `pull --ff-only --no-rebase`, `reset --hard`, `clean`), checked in the documentation and source of git 2.47.3 and 2.55.0 (the CI image). No key on it can name a program, a path git executes or reads configuration from, a URL, a proxy, credentials, an include, a filter, a hook, an editor, a pager, a signing program, or another git directory or work tree:

| Key family | Keys and accepted values | Why it is inert here |
|---|---|---|
| Written by `git init`/`clone` | `core.repositoryformatversion` (integer); `core.filemode`, `core.bare`, `core.ignorecase`, `core.precomposeunicode`, `core.symlinks` (boolean); `core.logallrefupdates` (boolean or `always`); `remote.origin.url`, `remote.origin.fetch`; `branch.<name>.remote`, `branch.<name>.merge` | Repository layout and the origin the policy already pins (`git_pull` also checks the URL). |
| Identity | `user.name`, `user.email` (a value) | The gate never commits; git uses them only as the reflog identity. |
| Line endings | `core.autocrlf` (boolean or `input`), `core.eol` (`lf`, `crlf`, `native`), `core.safecrlf` (boolean or `warn`) | Built-in conversions of file content; no program. |
| Pull strategy | `pull.rebase`, `branch.<name>.rebase` (boolean, `merges`, `interactive`, `m`, `i`); `pull.ff` (boolean or `only`) | Never read for the gate's `pull --ff-only --no-rebase`: the command line wins (`builtin/pull.c`), so even `interactive` starts no editor (tested). |
| Defaults | `init.defaultBranch` (a value) | Read only by `init`, `clone` and `remote show`. |
| Pruning and tags | `fetch.prune`, `remote.origin.prune` (boolean); `remote.origin.tagOpt` (exactly `--tags` or `--no-tags`) | They delete stale remote-tracking refs, or choose which tags to fetch, from the pinned origin. |
| Colors | `color.<command>` (`never`, `always`, `auto` or boolean); `color.<command>.<slot>` (a color: names, `bright…`, 0–255, `#rgb`/`#rrggbb`, attributes with optional `no`/`no-`). `color.blame.*` is excluded. | Colors only. Even with `always`, none of the output the gate parses carries escape codes (the porcelain and name-only printers never color; tested). `color.blame.highlightRecent` is a list of colors and dates, and blame never runs. |
| Hints | `advice.<name>` (boolean) | Toggles hint messages on stderr. |
| Auto-gc threshold | `gc.auto` (integer, optional `k`/`m`/`g`) | A number. `gc.autoDetach`, `gc.*` otherwise and `maintenance.*` stay out. |

Everything else is refused with `policy_denied`. That includes `filter.*` (so **Git LFS repositories are not supported in v1**: LFS works through filter programs), `diff.*`, `merge.*`, `url.*`, `include.*` and `includeIf.*`, `core.askPass`/`editor`/`pager`/`worktree`/`hooksPath`/`fsmonitor`/`sshCommand`/`gitProxy`, `http.*`, `credential.*`, `gpg.*`, `user.signingKey`, other remotes, `remote.origin.pushurl`/`proxy`/`uploadpack`/`receivepack`, `extensions.*` and `submodule.*`. The refusal names the key and the command that removes it, run in the repository on the host: `git config --remove-section <section.subsection>` for a key under a subsection (a whole driver, url rewrite or remote), otherwise `git config --unset-all <key>`. Because `.git` is never writable through the file operations (§3), a caller cannot plant such configuration through the gate.

**The repository is pinned.** The repo must be listed in `git.repos` (and inside a write root for `git_pull` and `git_discard`); `<repo>/.git` must be a real directory inside the root — a gitfile, a symlink or a `commondir` (linked worktree) is refused.

**Operations.** `git_status` (`status --porcelain=v2 --branch -z`), `git_log` (`log --no-show-signature --no-ext-diff --no-textconv`, hash, author, date, subject), `git_diff` (`diff --no-ext-diff --no-textconv [--cached]`, redacted, capped), `git_discard_preview` (the tracked files `reset --hard` would restore and what `clean -n -d` would remove) and `git_discard` (`reset --hard` then `clean -f -d`; ignored files are kept and nested repositories skipped). `git_pull` runs `pull --ff-only --no-rebase --no-recurse-submodules` and refuses when `remote.origin.url` — or the URL git would actually use (`ls-remote --get-url origin`) — differs from the policy's `remote`, when tracked files have uncommitted changes, or when the pull is not a fast-forward (checked with `merge-base --is-ancestor HEAD FETCH_HEAD` after the refused merge); it returns the old and new HEAD and the number of changed files. Its TCP connect is governed by `sandbox.tcp_connect_ports`.

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
