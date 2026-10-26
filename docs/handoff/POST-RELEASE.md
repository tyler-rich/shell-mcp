# Post-release handoff: the open items after 0.1.0

> Session post-release-scope, 2026-10-25. Documentation only: no code, test, workflow or dependency change in this PR.
> It checks every item `v0.1.0` shipped as open (CHANGELOG `## [0.1.0]`, handoff `docs/handoff/S4C-PRIVILEGED.md` §2.1, ARCHIVE §14) against the code as released (`v0.1.0`, the same tree as `dev` at #59 for everything below), and plans the next version.
> **Status: proposed, not decided.** Nothing here is marked done or dropped; every recommendation is for the maintainer. §8 lists the decisions needed.
> Measurements were made in throwaway, labelled, unprivileged containers (`debian:trixie-slim@sha256:62bd423a…f034ad`, `ubuntu:26.04@sha256:c098726d…fb944`) with invented layouts (`/srv/app`, `example.test`); no real host was touched.

## 0. Overview

| Item | What | Severity (this review) | Recommendation | Schema / protocol / other impact | Proposed session |
|---|---|---|---|---|---|
| **N-30** (new) | Nothing bounds the memory of the gate's children: git, and every declared command | **Medium** | **Next version, first** | Gate policy: a new `limits` key (STOP). execx: one more child rlimit. No protocol, error-code, envelope, Landlock or unit change | S6-1 |
| **N-25** (revised) | A gitlink's own `.git` stalls git (FIFO) **or makes it allocate without bound (a large sparse ref file)** | **Medium** (was low: the memory half is new) | **Next version:** the memory half through N-30 (S6-1); the stall is accepted as bounded by the request timeout and documented | None beyond N-30 | S6-1 |
| **N-22** | A command's `{path:read}` passed as the gate's open descriptor | Low–medium (closes an accepted residual) | **Next version**, opt-in; it does not help `docker compose` (§3) | Gate policy: a new placeholder `{path:read:fd}` (STOP: placeholder semantics). Protocol: `exec_preview` gains `fds`, its hash domain moves to v2 (STOP). execx passes descriptors. No error code, envelope, Landlock or unit change | S6-2 |
| **N-26** (+ **N-31**, new) | What a `#!` script runs is not looked at; the GTFOBins warning ignores a script's interpreter | Low (needs root to declare; a review gap, not a bypass) | **Next version:** every script in the privileged policy needs `acknowledge`; the gate keeps its WARN; the GTFOBins warning also checks the interpreter | Privileged policy: no new key, the acknowledge list (list B) extended (STOP). Existing privileged policies with scripts stop loading until acknowledged | S6-3 |
| **N-5** (refined) | Overwrite previews hash the destination through the read op | Low | **Next version, low priority**; its real reach is replacing a private-key file through `shell_priv_write_file` (§5) | Protocol: two read-tier ops `hash_file`, `priv_hash_file` (STOP). Gate move's commit-side hash cap raised with it. No schema, error-code, envelope, Landlock or unit change | S6-4 |
| **N-28** | The core unit's `systemd-analyze security` exposure is exactly at CI's 1.4 | Informational | **Leave the threshold and the unit alone.** Optionally add an offline exposure check of the golden units (systemd 257 and 259) to ci-local and CI; the one safe hardening (`ProtectHome=yes` where no root is under `/home`) is a proposal only | Unit directive change only if the proposal is taken (STOP) | S6-5 (optional) |
| N-14 | No operation runs `dpkg --configure -a` | Low (operational) | Defer: the documented recovery template works | A new op would be a protocol change | — |
| X-5, X-6 | Privileged redaction patterns; the gate's audit line for `priv_*` | Documented | Propose to drop as work items (documented, never proposed) | — | — |
| plan §6, S4d | Other package managers, seccomp, OAuth, multi-principal, non-Linux; approval front ends | — | Defer, unchanged; N-30 is not a reason to start seccomp | — | — |
| N-29 | Pin the reference deployment to the released digest | Process | Repeat for every release, in its own PR after the tag | — | after each release |

**Next version: `0.2.0`** (§7), released when S6-1, S6-2 and S6-3 are merged; S6-4 and S6-5 may ride along or follow.

## 1. N-30 (new): the gate's children have no memory bound

**What, from the code.**
- `execx.childLimits` (`internal/gate/execx/execx.go`) sets exactly `RLIMIT_CORE=0`, `RLIMIT_NOFILE` and `RLIMIT_NPROC`; the trampoline applies them (`trampoline.go`). Nothing bounds address space or data, and the gate process itself runs in the SSH session with whatever the host gives it (by default no `MemoryMax=` on the service account's slice).
- The helper is bounded: the generated units carry `MemoryMax=256M` (core) and `MemoryMax=1G` (broad) (`internal/privd/units/testdata/*.service.golden`).
- So any gate child that reads a file another local account controls can grow until the host's OOM killer acts. Two such readers exist today: git in a submodule's `.git` (N-25, below) and declared commands under the owner-matched `{path:read}` exception (POLICY §4).

**Measured** (Ubuntu 26.04, container memory capped at 2 GiB so the host was safe):
- `jq -c keys` on a 4 GiB sparse file (no disk cost to the account that makes it): grew to the 2 GiB cap and was still running at 20 s. With `prlimit --data=268435456`: aborted after 1.1 s at 131 MiB.
- git: see N-25.

**Severity and reach.** Medium. The account that plants the file needs only write access to a directory that a listed repository's gitlink, or a declared command's owner-matched `{path:read}`, points into: an application account that owns its own tree. The trigger is any read-tier tool call that reaches the file (a routine `shell_git_status` from the model), so it needs no approval and no profile above `read-only`. The effect is host-wide memory pressure: the OOM killer chooses the victim, which need not be the gate's child.

**Options.**
- **(a) `RLIMIT_DATA` for every gate child**, from a new gate-policy limit (`limits.max_memory_mb`, default to be measured; proposed 1024, range 64–16384). It counts heap and private writable mappings, not read-only file mappings (git's packs), so it bounds the allocation without breaking `mmap`. Breaks: any declared command or git operation that legitimately needs more; the default must be measured against large repositories (a 1 M-entry index) and the Go and Rust binaries in the example policies, whose runtimes reserve address space without writing it.
- (b) `RLIMIT_AS`: simpler accounting, but Go and Rust runtimes and git's pack `mmap` reserve large address ranges, so it would break legitimate commands at any useful bound. Rejected.
- (c) A cgroup per request: the gate is unprivileged and has no delegated cgroup; out of reach without systemd changes on every target. Rejected.
- (d) Documentation only: TARGET-SETUP recommends `MemoryMax=` on the service account's `user-<uid>.slice` (a drop-in). Bounds the account as a whole, so one request can still starve the account's other requests, and depends on the session being placed in that slice by `pam_systemd`. Recommended **in addition** to (a), as the operator's outer bound.

**Recommendation:** (a) + (d) in the next version, first (S6-1). A fixed bound with no key is the fallback if the maintainer prefers no schema change (then a policy cannot raise it).

**Impact.** Gate policy schema: one optional key (STOP). execx: a fourth child limit, which the helper's commands would also get unless the helper passes its own value (its units already bound it; proposal: the helper keeps relying on `MemoryMax=`, so no privileged schema change). No protocol, error-code or envelope change: a command killed or failing on its limit reports its exit status or signal as today; a git operation whose git fails reports the existing failure mapping (to confirm in the session).

**Tests (failing first).**
- execx: the child-limits probe (`childLimitsError`, which today expects three limits) also reports `RLIMIT_DATA` at the policy's value: fails on today's code.
- gate ops: a declared test command that allocates past the limit is stopped and reported, not left to grow; `gatetest.BuildGitRecorder` records each git process's `/proc/self/limits`, and every git process of every operation carries the limit (fails first).
- e2e-host: example-app plants a sparse `refs/heads/x` (1 GiB, so a tests-only run cannot hurt the runner) in a gitlink's `.git` and a sparse file at an owner-matched `{path:read}`; `git_status` and the command answer within seconds and the gate's process stays under the bound. On the tests-only head both read the whole file.

## 2. N-25: a gitlink's `.git` stalls git, or makes it allocate

**What, from the code.** Unchanged since PR #51: every gate status and work-tree diff runs with `--ignore-submodules=all` (`gitx.GitCommands`), and git still resolves a populated gitlink's HEAD inside its own process before it applies the flag (`ce_compare_gitlink`, handoff N-25, ARCHIVE PR #51). The closed repository rule (`fsx.CheckGitRepo`) covers the repository and its `.git`, not directories inside the work tree.

**Measured** (the gate's status argv and `GIT_DIR`/`GIT_WORK_TREE`, the gitlink made stat-dirty, under `timeout 8`; git 2.47.3 on Debian 13, git 2.53.0 on Ubuntu 26.04, same results):

| What the account puts in the gitlink's `.git` | Result |
|---|---|
| `.git` itself a FIFO, a symlink to `/dev/urandom`, a gitfile | runs at once (git stats `.git` and wants a regular file or a directory) |
| `HEAD` a FIFO; `HEAD` naming `refs/heads/x`, a FIFO; `packed-refs` a FIFO; `config` a FIFO; `commondir` a FIFO | **blocks until killed** (8 s here; the request timeout in the gate) |
| `HEAD` a symlink to `/dev/urandom` or `/dev/zero`, or a 4 GiB sparse file; a unix socket | runs at once |
| `HEAD` naming `refs/heads/x`, a **4 GiB sparse file** | **git allocated about 2 GiB in 3–5 s** and was killed by the container's 2 GiB cap; under `prlimit --data=256 MiB` it failed in 0.2 s ("Out of memory, realloc failed") |
| `packed-refs` a 4 GiB sparse file | 2 GiB resident in 3–4 s, then "unterminated line"; this one is an `mmap` (page cache, reclaimable), so `RLIMIT_DATA` does not stop it but it does not exhaust memory either |
| `config` a 4 GiB sparse file | fails at once ("bad config line 1") |

A device node cannot be planted (it needs `CAP_MKNOD`), and a symlink to the devices the gate's sandbox grants is harmless here.

**Can a FIFO or a large file be refused cheaply before git reads it? No, not soundly.** The account owns the gitlink's directory, so it can replace any entry after the gate's check and before git's read; a pre-check of `HEAD`, the ref it names, `packed-refs`, `config` and `commondir` is a time-of-check-to-time-of-use race by construction, and the set of files git reads follows refs the account chooses. A sound pre-check exists only if the whole gitlink directory and its `.git` tree are closed (root's or the service account's, not group/other-writable), which is option (c) of N-23 again: it refuses every repository whose submodule checkout belongs to an application account. git itself has no option that skips `ce_compare_gitlink` without writing the index.

**Recommendation.**
- **The memory half: fixed by N-30 (S6-1).** That is the real exposure.
- **The stall: accept and document** (TOOLS and POLICY §7): it is bounded by `limits.default_timeout_s` (30 s by default) and kills git's process group, and nothing runs. A per-operation git deadline below the request timeout would shorten it, but needs a schema key or changes every large repository's budget; not proposed.

**Tests:** S6-1's e2e case above; the stall needs no new test (the timeout path is covered).

## 3. N-22: a `{path:read}` passed as the gate's open descriptor

**What, from the code.** `resolver.ResolvePath` (`internal/gate/ops/exec.go`) calls `execFS.ResolveRead`, which opens the target (`openTarget`, `O_RDONLY|O_NONBLOCK`), checks the chain or the owner-matched exception (`execChain`), **closes the descriptor** and returns the real path as a string (`internal/gate/fsx/read.go`). The command looks that string up again. Under the owner-matched exception, the owning account can swap a component for a symlink in between and redirect the read to any file the service account can read inside the gate's Landlock domain, deny-listed files included (POLICY §3, §4; e2e `TestGateExecOwnerMatchedReadRace`). The trampoline marks every descriptor from 3 up close-on-exec before the exec (`unix.CloseRange(trampolineFD, …, CLOSE_RANGE_CLOEXEC)`, `internal/gate/execx/trampoline.go`), so no descriptor can reach a command today.

**Measured: which commands work with `/dev/fd/3`.** Each command was given its file as `/dev/fd/3`, opened by the parent as the gate would open it; then the file was unlinked after the open and another put at its path (a stand-in for the swap). Debian 13 (GNU coreutils 9.7, jq 1.7, docker-compose 2.26.1, nginx 1.26.3) and Ubuntu 26.04 (uutils coreutils 0.10.0, jq 1.8.1, docker-compose 2.40.3, nginx 1.28.3) gave the same results:

| Command | Works with the descriptor | After the swap it read | How (strace) |
|---|---|---|---|
| `cat`, `head`, `tail`, `grep`, `sort`, `diff F /dev/null`, `jq`, `xmllint`, `openssl x509 -in`, `tar -tzf` | yes, same output | **the opened file** | `openat("/dev/fd/3")`: a reopen of the same inode |
| `wc -l`, `sha256sum`, `grep -H`, `file -L`, `nginx -t -c` | yes, but the output names `/dev/fd/3` | the opened file | as above |
| `stat -L`, `du -L` | yes | the opened file | `statx("/dev/fd/3")` following the link |
| `stat`, `du` **without `-L`** | **no: silently wrong** (they report the `/dev/fd/3` symlink itself, 64 bytes) | — | `statx` without following |
| `findmnt --target` (both example policies) | yes | **no gain:** it `readlink`s `/proc/<pid>/fd/3` and then walks and `statx`es the real path, so the race returns | `readlink`, then the path |
| `docker compose -f F config` | **only without relative paths**: relative `env_file`, build contexts and other files resolve from `/dev/fd` ("env file /dev/fd/app.env not found"), and the project name becomes `fd` | — | `openat("/dev/fd/3")` |
| `docker compose -p x --project-directory <dir> -f F config` | yes | the opened compose file, **but every file it references is still read by path** (the race remains for those) | as above, then paths under the project directory |
| `yq` (Debian, Ubuntu) and `zcat` | worked in the probe, but both are `#!` scripts (`/usr/bin/python3`, `/bin/sh`) that the gate refuses as commands anyway | | |
| a directory descriptor: `ls /dev/fd/4` | yes, and after the directory was renamed away and another put in its place, it listed the opened one | | |

So the opt-in helps commands that just read their file (the common read-only shapes), does nothing for commands that canonicalise (`findmnt`), and does not fix POLICY §4's motivating `compose -f {path:read}` example: compose reads the descriptor but resolves everything else by path from the project directory, which the owning account controls anyway.

**Severity and reach.** Low–medium: it closes an accepted residual (a redirect within what the service account can read, never root, never outside Landlock; output redaction masks PEM keys), only for policies that use the owner-matched exception, and only for commands of the first two rows.

**Design options.**
- **(a) A new placeholder `{path:read:fd}` (recommended).** Same matching and resolution as `{path:read}` (roots, deny list, chain rule, owner-matched exception). The target must be a regular file or a directory (a FIFO, socket or device is `path_denied`, so the command is never handed something that blocks). The gate keeps the descriptor it checked, the trampoline gives the `k`-th such token descriptor `4+k` (3 stays the control socket, which is close-on-exec) and clears close-on-exec on exactly those, and the argv carries `/dev/fd/<n>`. At most 8 per template. Explicit in the template, so the operator and the approver see which argument is a descriptor.
- (b) A per-command key (`pass_reads: descriptor`): coarser, and a command with two read placeholders could not mix the forms.
- (c) The file as stdin (`{path:read:stdin}`): many commands accept `-`, but it collides with the request's `stdin_b64` and allows one file.
- (d) Make the descriptor form mandatory under the owner-matched exception: closes the residual for every policy, but breaks `findmnt`, compose and `stat`/`du` templates that work today. Not recommended now; a possible later tightening once the opt-in has been used.

**The exact gate-policy schema change (option a).**
- `commands[].templates[][]` accepts one more token: `{path:read:fd}`. `internal/template` gets a kind `PathReadFD`; `Resolver` gets a method returning the opened file with the path (`ResolvePathFD(value) (*os.File, string, error)`).
- The **privileged policy refuses it** at load ("root commands get closed paths only"): N-10's rule leaves no race to close there, and the helper keeps its current exec path. `check-policy` (gate) prints `ok … commands[<id>]: {path:read:fd} …` naming the measured limits (canonicalising commands, relative paths, `stat`/`du` without `-L`).
- Requirement: `/dev/fd` is a symlink to `/proc/self/fd` on the target (systemd hosts have it); `check-policy` checks it. To verify in S6-2, on the e2e runner: that a reopen through `/dev/fd/<n>` passes the gate's Landlock ruleset (the open is checked against the file's own path, which is under a read root; no rule covers `/dev` or `/proc` today).

**Preview and approval.** `exec_preview` gains `fds: [{"fd": n, "path": "<resolved path>"}]`, and its hash domain becomes `shell-mcp exec preview v2`, covering each descriptor's path and its file identity (device, inode). The approval page shows the argv with `/dev/fd/<n>` and, under it, "fd n: <path>, opened by the gate". `exec` recomputes the hash from its own opened descriptors, so a file replaced between the approval and the run is `exists` ("resolves differently than its preview"), which today's string hash cannot see. Read-tier commands are not approval-gated, so for them the gain is the descriptor alone. The server's `CommandOutput.argv` shows `/dev/fd/<n>`; it gains the same `fds` list. Protocol: one data field on `exec_preview` and on `exec`, and the hash domain (STOP: wire protocol).

**Tests (failing first).** template: `{path:read:fd}` parses in the gate's policy and is refused in the privileged policy (both fail today: unknown placeholder). fsx: the descriptor resolver refuses a FIFO, a socket and a symlink and returns the opened file. execx: a probe lists `/proc/self/fd`: exactly 0–2 plus the passed descriptors at their numbers (fails today: 0–2 only). gate ops: `exec_preview` shows `fds`; a swap between preview and exec gives `exists`. e2e-host: `TestGateExecOwnerMatchedReadRace` gets a twin with `{path:read:fd}` in which the denied and service-account files are never read in any round, while the string form keeps reaching them (the existing test is the proof that the test sees the race); the reopen works under Landlock.

**Recommendation:** next version (S6-2), opt-in (a). If the maintainer values compose most, defer instead: it does not help that case.

## 4. N-26 and N-31: `#!` scripts

**What, from the code.** `resolveProgram` (`internal/gate/policy/parse.go`, shared with the helper) parses a script's first line as `binfmt_script` does (`ProbeContent`, `content.go`), judges the interpreter by every rule (hard-deny list, ownership, content, identity, five scripts deep) and WARNs "is a #! script run by …". The interpreters that pass are the ones on no list: for example `nft -f` (list B, acknowledged), `make -f`, `sed -f`, compiled tools that read a program. What the script itself runs is not inspected (POLICY §5; handoff N-26).

**N-31 (new, found reading the code).** The GTFOBins warning is computed from the command's written and resolved names only: `EscapeWarning(field, false, CanonicalName(written), CanonicalName(ran))` in the gate's `resolveCommand`, and the same two names in the helper's `command` (`internal/privd/policy/parse.go`). A script whose interpreter is on the list (`make`: exec; `sed`: exec, read, write) gets the generic script WARN but no GTFOBins warning. Not run, read from the code.

**Severity and reach.** Low. The script and its directories must be root-owned and not writable by others (the ownership checks), so only root can declare or change it; the threat is an operator who does not see what a script runs, or a template whose arguments become code to the interpreter (a `make -f` script given `{regex:…}` arguments of the form `NAME=value` can set `SHELL`). It is a review gap, not a bypass of the gate.

**Options**, and what each breaks:
- **(a) WARN only** (today). Breaks nothing.
- **(b) Refuse when the interpreter is never-listed.** Already done by S-MC (#53): a shell, an interpreter, `env` and the rest of groups 1–10 refuse the script. Nothing more to do.
- **(c) Require an `acknowledge` for every script in the privileged policy** (recommended), reported as a finding (category `script`, naming the interpreter) in `check-policy` and the policy summary, as N-13's package tools are; the gate keeps the WARN (its scripts run as the service account inside the sandbox). No new key: the existing `commands[].acknowledge`, with list B extended (STOP: the acknowledge list). Breaks: every existing privileged policy that declares a script, including PRIVILEGED §4's `example-renew` shape when it is one, until the acknowledge is added (an upgrade note in the CHANGELOG).
- **(d) Refuse every script in the privileged policy**, or in both (handoff N-26 (b), (c)). Breaks `example-renew` as a script, and every wrapper an operator wrote to keep the argv small; pushes operators to compiled wrappers, which are no easier to review.
- **(e) Judge the script's contents.** Not possible in general (it is a program). A narrower variant, pinning the script's SHA-256 in the policy so a changed script (a package upgrade) refuses until re-reviewed, is a schema change and applies equally to binaries; recorded, not proposed.

**Recommendation:** (c), with N-31's fix (the GTFOBins warning also checks the interpreter's canonical name, gate and helper) in the same PR (S6-3).

**Tests (failing first).** privileged policy: a script command without `acknowledge` is refused naming the interpreter; with it, a `script` finding in `check-policy` and in `priv_policy`'s summary (today: accepted with a WARN). Gate and privileged policy: a script run by `make` or `sed` gets the GTFOBins WARN naming the interpreter (today: none). e2e: `TestMulticallCheckPolicy` gains the two cases on the runner's own `make` or `sed`.

## 5. N-5: destination previews hash through the read op

**What, from the code, and where the handoff is stale.**
- As recorded: `boundFilePreview` (`internal/tools/priv_write.go`) hashes an existing destination through `read_file` or `priv_read_file`; `fsx.ReadFile` refuses a file whose first 64 KiB hold a private key (`path_denied`) and gives no hash above 256 MiB (`maxHashBytes`), which the preview turns into `too_large`. The gate's `writePreview` (`internal/tools/preview.go`) reads an existing file the same way, so writes are in scope too.
- **Not recorded: the commit side is capped too.** A move with `expected_destination_sha256` hashes the destination at the commit through `hashTarget` (`internal/gate/fsx/helper.go`), which refuses above 256 MiB, so a hash-only preview op alone would not make a gate move over a larger file approvable. (Writes and copies hash the replaced file in `writeAtomic` without a cap.)
- **Not recorded: in the helper, the size half is moot.** Every privileged replace backs the old file up first, and one backup is at most 64 MiB (`maxBackupBytes`, `internal/privd/ops/backups.go`), so a privileged write, copy or move over anything above 64 MiB is refused whatever the preview does.
- Since #50: #52 (a copy's owner) and #53 change nothing here; copy sources stay within `max_read_bytes` (≤ 4 MiB) and writes within `max_write_bytes` (≤ 1 MiB).

**Severity and reach.** Low; it fails closed. The case with real reach is **replacing a private key**: rotating a TLS key file with `shell_priv_write_file` (always approval-gated) cannot be approved because the preview's read of the old key is refused, though writing key content is allowed. The gate's own writes are gated only when `SHELL_MCP_APPROVAL_TIERS` includes `operator`. The 256 MiB half matters only for gate moves and for gate writes or copies over large files.

**Options.**
- **(a) As recorded:** `hash_file` (gate) and `priv_hash_file` (helper, core unit, read tier) answering `{path, size, sha256}` and the stat identity, under the same resolution, deny list and (helper) moved-in read rule, hashing to the end within the request's deadline, no content and so no private-key sniff; the previews use them; the gate move's `hashTarget` cap is raised to the same deadline-bounded hash. Two op names (STOP: protocol); no envelope or error-code change.
- (b) Only the private-key half: the same ops with the 256 MiB cap kept. Smaller; leaves the gate's large moves as they are.
- (c) Defer: the workaround (delete first, then create-only) stays documented.

**Recommendation:** (a) in the next version, low priority (S6-4); (b) if the maintainer wants the smallest change. The hash of a private key reveals nothing usable, and the deny list still applies to the path.

**Tests (failing first).** tools: a write, copy and move preview over a file starting with a PEM private key, and (gate) over a 300 MiB sparse file, today `path_denied` and `too_large`, then `ok` with a hash; the hash ops' answers have no content field and their audit lines no hash; fsx: a gate move with `expected_destination_sha256` over a 300 MiB sparse file commits; helper: the same over 65 MiB is still `backup_failed` (documents the backup cap).

## 6. N-28: the core unit's exposure at the threshold

**Measured offline** (`systemd-analyze security --offline=yes` on the generator's golden units, `internal/privd/units/testdata`; no PID 1, no privileged container):
- `minimal.service.golden` (no declared capabilities): **1.4 on systemd 259 (Ubuntu 26.04) and on systemd 257 (Debian 13)**, the same as CI's online 1.4. So the score on Debian 13's systemd, which the handoff said was not measured, is the same (offline).
- `example.service.golden` (with `CAP_KILL` and `CAP_SYS_BOOT`, so `ProtectProc=default`): 1.7 on both; such a policy's unit already rates worse than CI's threshold, which applies to the e2e policy's unit only.
- The items left on the minimal unit: `User=root` 0.4; `~@privileged` and `~@resources` 0.2 each; the DAC and chown capability groups 0.2 each; `PrivateUsers=` 0.2; `RootDirectory=`, `AF_UNIX`, `ProtectHome=` and the `char-rtc:r` device ACL (from `ProtectClock=yes`) 0.1 each.

**What each change would gain, alone** (the score after it), and why it is or is not safe:

| Change | Score | Safe? |
|---|---|---|
| `ProtectHome=yes` (or `tmpfs`) instead of `read-only` | 1.3 | **Yes, for a policy with no privileged root under `/home`** (or `/run/user`); the generator would emit it conditionally. Nothing in the core unit reads `/home` except through a root |
| `SystemCallFilter=~@privileged` | 1.3 | No: `chown` is in `@privileged` (`priv_chown`, every write that sets an owner) |
| `SystemCallFilter=~@resources` | 1.3 | No: `setrlimit`/`prlimit64` are in `@resources`, and the exec trampoline sets the child limits with them |
| drop `CAP_CHOWN` | 1.2 | No: chown, and every owner the helper sets |
| `PrivateUsers=yes` | 1.2 | No, never (PRIVILEGED §5.1) |
| `RestrictAddressFamilies=none` | 1.4 | No gain, and no: execx's control channel is a `socketpair(AF_UNIX)` |
| `PrivateIPC=`, `DevicePolicy=closed`, `KeyringMode=private`, `RemoveIPC=`, `NotifyAccess=none`, `~@cpu-emulation`, `~@clock`, `~@reboot`, `RestrictFileSystems=`, `ProtectProc=invisible`, `PrivateMounts=`, dropping a DAC capability | 1.4 | no gain |
| (control) removing `IPAddressDeny=any` | 1.6 | the check sees a loosening |

**Conclusion.** At most 0.1 can be gained without breaking an operation, and only for policies without roots under `/home`. Because the threshold is "the measured score, with no slack, may only improve", lowering the unit to 1.3 would by that rule move the threshold to 1.3, so hardening buys no margin against a systemd scoring change unless the maintainer decides to keep 1.4 as the threshold above a 1.3 unit.

**Recommendation.** Leave the threshold and the unit as they are, and keep the handoff's what-to-check list. Optionally (S6-5): run the offline analysis on the golden units in `scripts/ci-local.sh` and CI on both systemd 257 and 259 images (a test/CI change), so a unit change is caught before e2e-host and the Debian score is recorded; and, only if the maintainer wants it, the conditional `ProtectHome=yes` (a generated-unit directive change, STOP). The test's "fails first" side: the same check run against a golden copy without `IPAddressDeny=any` reports 1.6 and fails the threshold.

## 7. Other open items, and the next version

- **N-14** (no operation for `dpkg --configure -a`): the documented broad-unit template works and is the operator's reviewed exception. Defer; a new op would be a protocol change for a rare recovery.
- **X-5** (no redaction patterns in the privileged policy) and **X-6** (the gate's audit line for `priv_*` lacks owner, group, backup id and packages): documented in S4c-1, never proposed. Proposed: drop as work items, keep the documentation.
- **plan §6 deferred decisions** (other package managers, seccomp for gate children, OAuth, multi-principal, non-Linux) and **S4d** (approval front ends): unchanged, deferred. N-30 is a memory bound, not a reason to start seccomp.
- **N-29** (the digest pin): repeat in its own PR after every release.
- Done items re-checked and still done: N-15 (decided, documented), N-24, N-27; release finding A (#59).

**Version.** Propose **`0.2.0`**. The next changes add a gate-policy key (N-30) and a placeholder (N-22), and refuse privileged policies that declare a script without an acknowledge (N-26). A `0.1.0` gate refuses a policy with the new key or placeholder (strict parsing), and some `0.1.0` privileged policies stop loading, so the release is not backward compatible in the policy, which is a minor bump while the major version is 0. If the protocol changes are amended in place in v1 (as in #18, before release), a new server must refuse an old gate's missing ops with an actionable error; if the protocol version is bumped, F-06's existing mismatch refusal covers it. Either is a STOP decision.

**What would justify the release:** S6-1 merged is enough on its own (a medium, read-tier memory exhaustion with a fix). Proposed: release after S6-1, S6-2 and S6-3, so that the policy-compatibility changes arrive together, each with its CHANGELOG upgrade note; S6-4 and S6-5 when ready. If the maintainer wants S6-1 out alone and quickly, a `0.1.1` is possible only with the fixed bound (no schema key).

## 8. Proposed session order (one PR per concern)

| Session | Branch | Concern | Depends on |
|---|---|---|---|
| **S6-1** | `sec/gate-child-memory` | N-30 and N-25's memory half: `RLIMIT_DATA` for the gate's children from `limits.max_memory_mb`; TARGET-SETUP's slice `MemoryMax=`; N-25's stall documented as accepted | maintainer's decisions 1, 2 |
| **S6-2** | `feat/gate-read-fd` | N-22: `{path:read:fd}`, descriptors through execx, `exec_preview` v2 | decisions 3, 4 |
| **S6-3** | `sec/script-acknowledge` | N-26 (c) and N-31 | decision 5 |
| S6-4 | `feat/hash-preview-ops` | N-5 (a) or (b) | decisions 4, 6 |
| S6-5 (optional) | `chore/unit-exposure-offline` | N-28: offline exposure check in ci-local and CI; the conditional `ProtectHome=yes` only if decided | decision 7 |
| Release | `dev → main`, tag by the owner | CHANGELOG `## [0.2.0]` with upgrade notes; then N-29 | decision 8 |

Each is Opus 5.5 at High (D-022), and each starts with the D-013 refresh.

**Decisions needed from the maintainer.**
1. N-30: a policy key (`limits.max_memory_mb`, default to be measured, about 1 GiB) or a fixed bound; and whether the helper's commands get it too or keep relying on `MemoryMax=`.
2. N-25: accept the FIFO stall as timeout-bounded (documented), rather than closing gitlink directories.
3. N-22: do it now as an opt-in placeholder (and the name `{path:read:fd}`), or defer because it does not help compose.
4. Protocol: amend v1 in place for `exec_preview`'s `fds` and v2 hash domain (N-22) and the two hash ops (N-5), or bump the protocol version.
5. N-26: option (c), every privileged script acknowledged (list B extended), with N-31's warning.
6. N-5: option (a), (b) or defer.
7. N-28: leave as is; whether to add the offline check (S6-5); whether to propose `ProtectHome=yes`.
8. Version `0.2.0`, released after S6-1 to S6-3; or `0.1.1` for S6-1 alone.
9. X-5 and X-6: drop as work items.
