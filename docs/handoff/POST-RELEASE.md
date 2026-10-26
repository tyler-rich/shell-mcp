# Post-release handoff: the open items after 0.1.0

> Session post-release-scope, 2026-10-25. Documentation only: no code, test, workflow or dependency change in this PR.
> It checks every item `v0.1.0` shipped as open (CHANGELOG `## [0.1.0]`, handoff `docs/handoff/S4C-PRIVILEGED.md` §2.1, ARCHIVE §14) against the code as released (`v0.1.0`, the same tree as `dev` at #59 for everything below), and plans the next version.
> **Status: decided by the maintainer on 2026-10-25.** §9 records every decision; where a decision differs from or refines the recommendation, the item's section says so under **Decision**. Nothing is implemented here, and nothing is marked done. X-5 and X-6 are dropped as work items (§7).
> Measurements were made in throwaway, labelled, unprivileged containers (`debian:trixie-slim@sha256:62bd423a…f034ad`, `ubuntu:26.04@sha256:c098726d…fb944`) with invented layouts (`/srv/app`, `example.test`); no real host was touched.

## 0. Overview

| Item | What | Severity (this review) | Decision (maintainer, 2026-10-25) | Schema / protocol / other impact | Session |
|---|---|---|---|---|---|
| **N-30** (new) | Nothing bounds the memory of the gate's children: git, and every declared command | **Medium** | **Next version, first:** `limits.max_memory_mb` in the gate policy and in the privileged policy, applied as `RLIMIT_DATA` to the gate's and the helper's children, default measured to fit every example policy's commands (about 1 GiB); the helper units' `MemoryMax=` as the second layer, the unit change shown to the maintainer before it is implemented | Gate and privileged policy: one `limits` key each. execx: one more child rlimit. Generated units: `MemoryMax=` (proposal first). No protocol, error-code, envelope or Landlock change | S6-1 |
| **N-25** (revised) | A gitlink's own `.git` stalls git (FIFO) **or makes it allocate without bound (a large sparse ref file)** | **Medium** (was low: the memory half is new) | The memory half fixed by N-30 (S6-1); **the FIFO stall accepted** as bounded by the request timeout, and documented | None beyond N-30 | S6-1 |
| **N-22** | A command's `{path:read}` passed as the gate's open descriptor | Low–medium (closes an accepted residual) | **Next version, opt-in `{path:read:fd}`** (name approved), with a `check-policy` WARN for programs measured to give wrong or no-gain results with a descriptor | Gate policy: a new placeholder (approved). **Protocol version bumped** (approved): `exec_preview` gains `fds` and a v2 hash domain. execx passes descriptors. No error code, envelope, Landlock or unit change | S6-2 |
| **N-26** (+ **N-31**, new) | What a `#!` script runs is not looked at; the GTFOBins warning ignores a script's interpreter | Low (needs root to declare; a review gap, not a bypass) | **Next version:** every `#!` script in the privileged policy needs `acknowledge`; the gate keeps its WARN; the GTFOBins warning also checks the interpreter (N-31) | Privileged policy: no new key, the acknowledge list (list B) extended (approved). Existing privileged policies with scripts stop loading until acknowledged | S6-3 |
| **N-5** (refined) | Overwrite previews hash the destination through the read op | Low | **The private-key half only** (option b): a private-key file can be rotated with `shell_priv_write_file` and approved; the 256 MiB cap and the gate move's commit-side cap are **deferred** | Protocol: two read-tier ops `hash_file`, `priv_hash_file`, in the bumped version. No schema, error-code, envelope, Landlock or unit change | S6-4 |
| **N-28** | The core unit's `systemd-analyze security` exposure is exactly at CI's 1.4 | Informational | **Add the offline exposure check; take `ProtectHome=yes`** for policies with no privileged root under `/home`, `/root` or `/run/user` (`read-only`, as today, otherwise); the threshold follows the new score | Generated core unit: `ProtectHome=` conditional (approved). CI and ci-local: the offline check | S6-5 |
| N-14 | No operation runs `dpkg --configure -a` | Low (operational) | Deferred: the documented recovery template works | A new op would be a protocol change | — |
| X-5, X-6 | Privileged redaction patterns; the gate's audit line for `priv_*` | Documented | **Dropped as work items** (reasons in §7) | — | — |
| plan §6, S4d | Other package managers, seccomp, OAuth, multi-principal, non-Linux; approval front ends | — | Deferred, unchanged; N-30 is not a reason to start seccomp | — | — |
| N-29 | Pin the reference deployment to the released digest | Process | Repeat for every release, in its own PR after the tag | — | after each release |

**Next version: `0.2.0`** (decided), released when S6-1, S6-2 and S6-3 are merged; S6-4 and S6-5 are in it if they are merged by then (§7, §8).

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

**Decision (maintainer, 2026-10-25):** (a) with a policy key, in both policies, and (d).
- `limits.max_memory_mb` in the gate policy, applied as `RLIMIT_DATA` to every child the gate starts (git and declared commands). The default is measured in S6-1 to fit every example policy's commands (`examples/policies/*.yaml`, `examples/privileged/privileged.yaml`) and the built-in git operations on a large repository, about 1 GiB; the session records the measurements and the range.
- **The same key in the privileged policy**, applied to the helper's commands (`priv_exec`) and, where the helper runs a program for a built-in operation (apt-get, dpkg), to that program too, unless S6-1's measurements show a package transaction needs more than the broad unit allows (then it says so before implementing).
- **The helper units' `MemoryMax=` as the second layer.** Found while recording this: the generated units already carry `MemoryMax=256M` (core) and `MemoryMax=1G` (broad), fixed in `internal/privd/units/units.go`. So the layer exists, but its values do not follow the policy: under a core-unit `MemoryMax=256M`, a 1 GiB `RLIMIT_DATA` would never be reached, and the cgroup's OOM kill would end the whole instance (the helper with its command) instead of failing the command's allocation. S6-1 therefore proposes, and shows the maintainer before implementing, how `MemoryMax=` relates to the key: derived from it with room for the helper itself (for example `max_memory_mb` plus a fixed allowance per unit), or kept fixed with the key's range capped below it. Either is a generated-unit directive change (STOP, approved to propose).
- TARGET-SETUP recommends `MemoryMax=` on the service account's slice (option d) as the operator's outer bound for the gate.

**Impact.** Gate policy schema: one optional key (STOP). execx: a fourth child limit, which the helper's commands would also get unless the helper passes its own value (its units already bound it; proposal: the helper keeps relying on `MemoryMax=`, so no privileged schema change; superseded by the decision below, which adds the key to the privileged policy too). No protocol, error-code or envelope change: a command killed or failing on its limit reports its exit status or signal as today; a git operation whose git fails reports the existing failure mapping (to confirm in the session).

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

**Decision (maintainer, 2026-10-25):** as recommended. The memory half is fixed by N-30 in S6-1; the FIFO stall is accepted as bounded by the request timeout, and S6-1 documents it (POLICY §7, the git tools in TOOLS.md, and the handoff's N-25): a FIFO among a gitlink's git files makes a git operation answer `timeout` after the request's limit, with git's process group killed and nothing run.

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

**Decision (maintainer, 2026-10-25):** (a), in the next version, named `{path:read:fd}`, with two additions.
- **A `check-policy` WARN** for a `{path:read:fd}` given to a program measured above to give wrong results, or no gain, with a descriptor, recognised by the written, resolved and canonical name (as the GTFOBins warning is):
  - `stat` and `du` in a template without `-L` (or `--dereference`): they report the `/dev/fd/<n>` link itself, silently wrong;
  - `findmnt`: it reads the link back to the real path and looks that up, so the race returns;
  - `docker compose` and `docker-compose`: relative paths in the file resolve from `/dev/fd` and the project is named `fd`; with `--project-directory` every file the compose file names is still read by path.

  The programs whose output names `/dev/fd/<n>` instead of the path (`wc`, `sha256sum`, `grep -H`, `file`, `nginx -t`) give correct results and get no WARN; POLICY §4 lists them. S6-2 re-measures the list on its CI images and adds any other program it finds wrong, with the measurement.
- **The protocol version is bumped, not amended in place,** so a mismatched server and gate fail with a clear upgrade message (F-06). Before designing it, S6-2 confirms at the source what the `hello` exchange and the server's version check already support (what the server sends, what the gate answers, which side refuses and with what message), and designs the bump from that. The new version also carries S6-4's ops if S6-4 lands before the release; otherwise S6-4 bumps again.

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

**Decision (maintainer, 2026-10-25):** (c) and N-31, as recommended: every `#!` script in the privileged policy needs `acknowledge` (list B extended; a `script` finding naming the interpreter), the gate keeps its WARN, and the GTFOBins warning in both programs also checks every interpreter on the script chain. The CHANGELOG's `0.2.0` section carries the upgrade note for privileged policies that declare a script.

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

**Decision (maintainer, 2026-10-25):** (b), the private-key half only, so that a private-key file can be rotated with `shell_priv_write_file` and approved. The hash ops keep the 256 MiB cap; the previews use them for an existing destination (the privileged write, copy and move previews, and the gate's twins, which share `boundFilePreview` and `writePreview`). **Deferred:** the 256 MiB cap itself and the gate move's commit-side cap (`hashTarget`). The ops join the bumped protocol version (N-22's decision). Tests as above without the 300 MiB cases, which stay refused (`too_large`) and are kept as a test of the deferred half.

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

**Decision (maintainer, 2026-10-25):** both, and the threshold follows the new score.
- **The offline exposure check** in `scripts/ci-local.sh` and CI, on the golden units, on a systemd 257 and a systemd 259 image.
- **`ProtectHome=` conditional in the generated core unit.** What the analysis supports: `ProtectHome=yes` hides `/home`, `/root` and `/run/user` entirely, so it is safe only when **no privileged root, read or write, lies under any of them**. A read root there needs `read-only` (under `yes` it would be invisible), and so does a write root (`read-only` plus its `ReadWritePaths=` entry, as today). So: `yes` when no root is under `/home`, `/root` or `/run/user`; `read-only`, as today, otherwise, read root or write root alike. (A root under `/root` is already refused for writes by the protected set and for reads by the deny list, and `/run` is a read-only tmpfs in the core unit, so in practice the condition is `/home`.) The broad unit is unchanged. `check-policy` reports which one the policy gets.
- **The threshold follows the new score.** The e2e privileged policy has no root under `/home` (its roots are `/etc/example-app`, `/var/log/example-app` and `/srv/e2e-priv-exec/root`, `test/e2e/setup.sh`), so its core unit should rate 1.3; S6-5 measures it on the runner and sets `E2E_SECURITY_MAX` to the measured value, recorded in ARCHIVE with the systemd version, still with no slack.
- Tests, failing first: the generator's golden files gain a policy with a `/home` read root (keeps `read-only`) and one with a `/home` write root (keeps `read-only`), and the existing goldens change to `yes` (today's generator fails them); the offline check fails on a broadened copy (above).

## 7. Other open items, and the next version

- **N-14** (no operation for `dpkg --configure -a`): the documented broad-unit template works and is the operator's reviewed exception. Defer; a new op would be a protocol change for a rare recovery.
- **X-5** (no redaction patterns in the privileged policy) and **X-6** (the gate's audit line for `priv_*` lacks owner, group, backup id and packages): documented in S4c-1, never proposed. **Dropped as work items (maintainer, 2026-10-25); the documentation stays.** Reasons:
  - **X-5.** Every privileged result already passes the helper's built-in rules (PEM private keys) and then the server's built-in rules and `SHELL_MCP_REDACT_PATTERNS` before it reaches a client (PRIVILEGED §6), so the operator's patterns already apply to root output. A pattern list in the privileged policy would duplicate them in a second place to keep in step, as a privileged schema change, for no output that the server's patterns do not already cover. What it would add (redaction before the bytes leave the target) protects only against a compromised server, which can send any request the policies allow anyway.
  - **X-6.** The helper's own journal line for each request already carries the owner, group, backup id and packages, and joins the gate's line on the request id (ARCHITECTURE §4, `id`; PRIVILEGED §8). Copying them into the gate's line would widen what the gate logs about arguments for no information the target's journal lacks.
- **plan §6 deferred decisions** (other package managers, seccomp for gate children, OAuth, multi-principal, non-Linux) and **S4d** (approval front ends): unchanged, deferred. N-30 is a memory bound, not a reason to start seccomp.
- **N-29** (the digest pin): repeat in its own PR after every release.
- Done items re-checked and still done: N-15 (decided, documented), N-24, N-27; release finding A (#59).

**Version: `0.2.0` (decided, maintainer, 2026-10-25).** The next changes add a key to both policies (N-30) and a placeholder (N-22), refuse privileged policies that declare a script without an acknowledge (N-26), and bump the protocol version (decided with N-22). A `0.1.0` gate or helper refuses a policy with the new key or placeholder (strict parsing), some `0.1.0` privileged policies stop loading, and a `0.1.0` server and a `0.2.0` gate (or the reverse) refuse each other with the version mismatch (F-06). So the server, the gate and the helper are upgraded together, which the CHANGELOG's upgrade notes say; a minor bump while the major version is 0.

**What justifies the release:** S6-1, S6-2 and S6-3 merged, so the policy and protocol compatibility changes arrive together, each with its CHANGELOG upgrade note. S6-4 and S6-5 are in `0.2.0` if they are merged by then; otherwise they wait for the next release (S6-4 then bumps the protocol again).

## 8. Session order (one PR per concern)

| Order | Session | Branch | Concern | Stops inside the session |
|---|---|---|---|---|
| 1 | **S6-1** | `sec/gate-child-memory` | N-30 and N-25's memory half: `limits.max_memory_mb` in the gate and privileged policies, `RLIMIT_DATA` for the gate's and the helper's children, the default measured against every example policy; TARGET-SETUP's slice `MemoryMax=`; N-25's FIFO stall documented as accepted | **Before implementing the unit change:** show the maintainer how the helper units' `MemoryMax=` (today fixed at 256M and 1G) relates to the key |
| 2 | **S6-2** | `feat/gate-read-fd` | N-22: `{path:read:fd}`, descriptors through execx, `exec_preview`'s `fds` and v2 hash, the descriptor `check-policy` WARN; the protocol version bump | **First:** confirm at the source what `hello` and the server's version check support, then design the bump from it |
| 3 | **S6-3** | `sec/script-acknowledge` | N-26 (c) and N-31 | — |
| 4 | S6-4 | `feat/priv-key-preview-hash` | N-5 (b): `hash_file` and `priv_hash_file` for overwrite previews, the 256 MiB cap kept | in the protocol version S6-2 introduced, if before the release; else a further bump |
| 5 | S6-5 | `chore/unit-exposure-offline` | N-28: the offline exposure check in ci-local and CI (systemd 257 and 259); the conditional `ProtectHome=` in the core unit; `E2E_SECURITY_MAX` set to the measured new score | after S6-1, which also changes the generated units and their goldens |
| — | Release | `dev → main`, tag by the owner | CHANGELOG `## [0.2.0]` with the upgrade notes (policy keys, the placeholder, scripts acknowledged, protocol version: upgrade server, gate and helper together); then N-29 | when S6-1 to S6-3 are merged; S6-4 and S6-5 if merged by then |

S6-1 comes first (the one medium item, read-tier, no approval needed to reach it). S6-2 before S6-4, because S6-4's ops join the protocol version S6-2 introduces. S6-5 after S6-1, so the two unit changes do not touch the generator and its goldens at once. Each is Opus 5.5 at High (D-022), and each starts with the D-013 refresh.

## 9. Decisions (maintainer, 2026-10-25)

1. **N-30:** a key `limits.max_memory_mb` in the gate policy, default measured to fit every example policy's commands (about 1 GiB), applied as `RLIMIT_DATA` to the gate's children; the same key in the privileged policy for the helper's commands; `MemoryMax=` in the helper's generated units as a second layer, the unit change shown to the maintainer before it is implemented (S6-1). Recorded with it: the units already carry a fixed `MemoryMax=` (§1).
2. **N-25:** the FIFO stall accepted as bounded by the request timeout, and documented.
3. **N-22:** in the next version, opt-in `{path:read:fd}` (name approved), with a `check-policy` WARN for programs that give wrong results with a descriptor: `stat` and `du` without `-L`, `findmnt`, `docker compose` (§3).
4. **Protocol:** the version is bumped, not amended in place, so a mismatched server and gate fail with a clear upgrade message; S6-2 confirms what the `hello` exchange already supports before designing it.
5. **N-26:** the acknowledge required for every privileged `#!` script, plus N-31 (the GTFOBins warning also checks the interpreter).
6. **N-5:** the private-key half only, so a private-key file can be rotated with `shell_priv_write_file` and approved; the rest deferred.
7. **N-28:** the offline exposure check added; `ProtectHome=yes` for policies with no root under `/home` (`read-only` where any root, read or write, is there, §6); the threshold follows the new score.
8. **Version `0.2.0`**, after S6-1 to S6-3; S6-4 and S6-5 join it if they are merged by then.
9. **X-5 and X-6:** dropped as work items, reasons in §7.
