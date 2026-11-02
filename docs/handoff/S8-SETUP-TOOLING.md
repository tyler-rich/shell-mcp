# S8 handoff: setup tooling

> Session S8-scope, 2026-11-01. Documentation only: no code, test, workflow or other non-doc file changes in this PR.
> It scopes eight items (A–H) that move what `docs/TARGET-SETUP.md`, `deploy/README.md` and `docs/CLIENTS.md` §3.2 already prescribe into idempotent subcommands, and splits them into four implementation sessions.
> **Status: decided, 2026-11-01.** The maintainer answered §7's twelve questions; each is recorded there as a decision, and §3, §4 and §6 follow them. §7 Q13 arose from Q11's decision, because the trampoline refuses a parent with another uid. It was decided the same day: an execx credential option, off by default, root only, used by A's check-policy step alone (§4.A). No locked decision, schema, protocol, unit directive or hash binding changes here; where an item would need one, it says so and does not build that part (§5).
> **Audience (the maintainer's rule for this handoff and every S8 session).** This is a public project. Every default, preset, example and doc must suit any deployer: plain `docker compose` and stack editors, any reverse proxy, small and very large hosts. None may suit only one environment (§3.9).
> Every name below is a placeholder, as in TARGET-SETUP: the service account `svc-shell` (uid/gid 60123), the socket group `svc-shell-priv` (gid 60124), the server at `192.0.2.10`, `target-a.example.test`, `mcp.example.test`, `approve.example.test`, the proxy network `172.30.80.0/24`.

## 0. Summary

**The problem.** The binaries check and generate pieces of an install but never install them, so a deployer transcribes TARGET-SETUP by hand. The steps transcribed most often are also the ones where a typo weakens the install and nothing fails: a key line without `restrict`, a `from=` that is a whole /16, a secret owned by the wrong uid, a privileged policy edited without regenerating its units.

**The rule for every item.** A subcommand writes exactly the files TARGET-SETUP (or `deploy/README.md`, CLIENTS §3.2) already prescribes, with the same owner and mode, and refuses every case that today only a careful reader would catch. No security property changes: same files, same modes, same refusals, plus refusals for the typos. Nothing uses `sudo` or a setuid binary, nothing is piped from the network into a shell, nothing trusts a value read from the network.

**The proposed CLI surface.**

| Item | Command | Runs on | As |
|---|---|---|---|
| A | `shell-mcp-gate install --policy <file> --principal <label> --from <addr>[,<addr>] --key <file.pub> --user <name> --uid <n> --gid <n> [--socket-group <name> --socket-gid <n>] [--memory-max <size>] [--owner-scan-paths <dir>[,<dir>]] [--dry-run] [--no-reload] [--replace-key]` | target | root |
| A | `shell-mcp-gate host-key` | target | any |
| B | `shell-mcp-privd install --policy <file> --accept <sha256> [--gate-policy <file>]… [--dry-run] [--no-start]` (without `--accept` it prints the review and stops, exit 3) | target | root |
| C | `shell-mcp init --dir <dir> [--uid 65532 --gid 65532] [--approver <name>] [--dry-run]` | server host or the image | root, or the uid itself |
| C | `shell-mcp init compose --dir <dir> --form secrets\|bind --image <ref@sha256:…> --host-key <pin> --target-host … [--approve-host …]` | server host or the image | any |
| D | `shell-mcp-gate policy new --answers <file> --out <file>\|-` and `shell-mcp-privd policy new --answers <file> --out <file>\|-` | target | root |
| E | `shell-mcp doctor [--json] [--mcp-url <url>] [--ca-file <file>]` (`check` unchanged) | inside the server container | 65532 |
| F | `verify-release.sh <version> [--sums <verified SHA256SUMS>]` in the repository and the examples archive | workstation or target | any |
| G | `deploy/caddy/Caddyfile` (an example) and `deploy/caddy/README.md` (what any reverse proxy needs); no compose file, no image | server host | — |
| H | A ten-step quick start in `docs/TARGET-SETUP.md` (and README), the current guide kept as its reference part | — | — |

**Pushback, in short (§5).** D is an answers file, not an interactive wizard, and each binary writes its own policy. E's dynamic proxy check (did the server see the real client?) cannot be done without a new unauthenticated route, so `doctor` checks it statically and keeps the log-line procedure. And the broad helper socket cannot be probed, for a policy whose only broad use is `unit: broad` commands, without a protocol change. `doctor` reports it "not probed" (decided, §7 Q9). F cannot verify a release without cosign or `gh`: hashing a download against what the attestations API returns over TLS proves only that GitHub served the same bytes twice, so the fallback is `sha256sum` against a `SHA256SUMS` verified elsewhere, never against the network. `init` never prints or stores a secret in an environment-store form.

**The split (§6).** Four sessions, as expected: S8-1 A+B, S8-2 C, S8-3 D, S8-4 E+F+G+H. S8-1 also commits the container harness the S5b checks used but never committed (finding F-13), which every later session tests in.

## 1. What a deployer types today

The S5b guide, read against the code. "Typo risk" marks steps where a mistake weakens the install and nothing fails.

| TARGET-SETUP | Step | Tool today | Typo risk | Item |
|---|---|---|---|---|
| §1 | LSM list, systemd and sshd versions | none (check-policy reports the ABI) | — | A reports |
| §2 | download, `sha256sum -c`, `cosign verify-blob` ×4, `gh attestation verify` | none | an unverified binary | F |
| §3 | `install` ×3, unpack examples | none | — | H (stays manual) |
| §4 | free-id checks (`getent` ×3, `find -xdev`), `groupadd`, `useradd`, `passwd -l`, groups, `id` | none | an id in use; a privileged group | A |
| §4 | user slice drop-in, `daemon-reload`, `systemctl show` | none | no `MemorySwapMax=0` | A |
| §5 | `install -d /etc/shell-mcp`, copy an example, edit every placeholder, `check-policy` as the account | `check-policy` | a placeholder left in | D, A runs the check |
| §6 | write roots, repositories | `check-policy` warns | — | stays manual (an application decision) |
| §7 | `install -d authorized_keys.d`, write `60-shell-mcp.conf`, `sshd -t`, `sshd -T -C` ×2, the key line, `StrictModes` and `stat` checks, `reload ssh`, `ssh-keygen -lf` | none | no `restrict`; a wide `from=`; a group-writable keys file; a policy path with a shell metacharacter | A |
| §8 | `polkit` > file, `install` it | `polkit` | rule not regenerated | A |
| §9.1 | install the privileged policy 0600, set `client_uid`, `socket_group`, `check-policy` | `check-policy` | `client_uid` not the account's | D |
| §9.2 | `units --out`, backups directory, `systemd-analyze verify` ×2 | `units` | units not regenerated after an edit | B |
| §9.3 | `daemon-reload`, `enable --now` ×2, `ls -l /run/shell-mcp` | none | broad socket left enabled after the policy drops it | B |
| §9.4 | `systemd-analyze security` | none | — | B reports |
| §9.5 | add `privileged:` to the gate policy, `check-policy` | `check-policy` | socket path mistyped | D, B cross-checks |
| §10 | `shell-mcp check`, `journalctl` ×2 | `check` | — | E |
| deploy/README "Secrets" | `mkdir`, token pipeline, `ssh-keygen`, `chmod`, `chown 65532` | none | a secret owned by the wrong uid | C |
| CLIENTS §3.2 | `docker run -it … approver add`, the approval variables | `approver add` | secrets directory not writable by 65532 (F-9) | C |
| CLIENTS §1 | proxy layout, `SHELL_MCP_TRUSTED_PROXIES` from the log line | none | trusting the Docker gateway | E (static), G |

## 2. Findings: TARGET-SETUP and the code, checked at the source

Checked this session by reading the code named and, for F-1, F-7 and the sshd facts, in throwaway containers (`debian:trixie-slim`, `ubuntu:24.04` and `ubuntu:26.04`, the digests `scripts/exposure/Dockerfile` pins; labelled, `--rm`, unprivileged, `no-new-privileges`, no host mount; OpenSSH 10.0p2, 9.6p1 and 10.2p1; systemd 257, 255 and 259). None of these needs a code change before S8; each is resolved by the item named.

- **F-1. `passwd -l` is a setuid binary; the tools may not run it.** `/usr/bin/passwd` is `4755 root` on all three images. TARGET-SETUP §4 and SECURITY §5 step 1 tell a human to run it, which is fine; CLAUDE.md forbids our code to invoke any setuid binary. `usermod -L` (`0755`, not setuid) gives the same result: after `useradd` the shadow field is already `!` on all three, it stays `!` after `usermod -L`, and `passwd -S` reports `L`. **A uses `usermod -L`**, and H's quick start says so. SECURITY §5 step 1's wording can stay (it describes the locked state). TARGET-SETUP §4 switches to `usermod -L` for the hand-run path too (decided, §7 Q12; S8-1's docs commit).
- **F-2. `units` prints next steps that differ from TARGET-SETUP §9.2.** `cmd/shell-mcp-privd/main.go` (`unitsWith`) prints `daemon-reload` before `systemd-analyze verify`, without `--man=no`, and names only `/var/lib/shell-mcp/backups` (TARGET-SETUP creates `/var/lib/shell-mcp` 0700 as well). Harmless; B replaces the sequence, and the printed text then points at `install`.
- **F-3. `units` writes in place and never removes the broad pair.** It uses `os.WriteFile` on the final path, which truncates an existing unit before writing it, so a failure part-way leaves a mixed set pinned to two hashes; and when a policy stops using the broad unit it prints "remove … if installed" and leaves the old pair (and an enabled socket) in place. Both fail closed (the helper refuses with `helper_policy_mismatch` or `helper_install_insecure`), but B must write each file by temp file and rename, and must disable and remove the broad pair it generated.
- **F-4. The example policies say to run `check-policy` without saying as whom**; TARGET-SETUP §5 runs it as the service account through `runuser`, so the identity checks describe that account. A runs it that way itself (§4.A, without `runuser`).
- **F-5. PRIVILEGED §2 calls the socket group "system group"**; TARGET-SETUP creates it with an explicit gid (`groupadd --gid 60124`, not `--system`), as D-020's pinned ids want. Wording only: PRIVILEGED §2 will say "group with an explicit gid" (decided, §7 Q12; S8-1's docs commit).
- **F-6. The privileged-group list.** The session prompt lists `docker`, `sudo`, `adm`, `wheel` and `root`; D-020 and `internal/gate/install.DeniedGroups` also deny `lxd`, `incus-admin`, `libvirt`, `kvm`, `disk` and `shadow`. A uses `DeniedGroups` itself, never a copy.
- **F-7. `systemctl reload ssh` on Ubuntu.** On all three images the unit is `ssh.service` with `Alias=sshd.service`, and `ssh.socket` exists. TARGET-SETUP §7 says a reload fails when Ubuntu's socket-activated `ssh.service` is not running and the next connection starts it with the new configuration. A reloads `ssh.service` when it is active, reports "no reload needed" when only `ssh.socket` is, and refuses (printing what to run) when neither is.
- **F-8. The forced command passes through the account's shell.** TARGET-SETUP §4 says sshd runs the forced command through `/bin/sh`. So a `--policy` path or `--principal` label holding a space, quote, `;`, `$` or backquote would change what runs. Today nothing checks the hand-written line; A refuses any such value (§4.A).
- **F-9. Enrolment needs a secrets directory that 65532 can write, and nothing creates it.** `deploy/README.md` creates `secrets/` `0700` owned by whoever runs it (root) and hands only the files to 65532; CLIENTS §3.2 says the directory "must be writable by it while you enrol" without a command. `approvers.Add` (`internal/approval/approvers/file.go`) writes a temp file in that directory and renames it, so `approver add` in the container fails until the operator changes the directory's owner by hand. C creates the directory owned by 65532 from the start.
- **F-10. `sshd_config.d` is included near the top on all three images** (`Include /etc/ssh/sshd_config.d/*.conf`, line 12 on Debian 13 and Ubuntu 24.04, line 24 on Ubuntu 26.04), with `StrictModes yes`, `UseDNS no` and the default `AuthorizedKeysFile` in force. A does not parse the main file for the `Include`: it checks the effective configuration with `sshd -T -C` (§4.A), which also catches an earlier drop-in or `Match` block that would win over ours.
- **F-11. `useradd` warns about uid 60123** (above `UID_MAX` 60000) on all three, as TARGET-SETUP §4 says; harmless.
- **F-12. `shell-mcp check` probes only the gate.** `tools.Probe` (`internal/tools/deps.go`) sends `hello`; nothing reaches the helper, so a stopped socket or units left on an old hash show up only on the first privileged call. E adds that.
- **F-13. The S5b container checks are not reproducible from the repository.** ARCHIVE §14 (S5b) ran every *(container)* step as root in throwaway containers, but no script was committed; `scripts/exposure/` is the only committed multi-distribution container harness, and `test/e2e` runs only on the CI runner VM. S8-1 commits `scripts/setup-check/` on `scripts/exposure`'s model (§3.8).

Facts this proposal relies on that are **not verified here** and that the named session verifies first, at the source, before building on them:
- **V-1 (S8-2).** That a stack editor running Compose in its own container cannot resolve `secrets: file:` to a host path while it can pass an absolute bind-mount source to the daemon (the session prompt's statement). Verify in Compose's source or documentation, or by running Compose without a Docker socket mount where possible; if it is false, C's second form is still useful (one mount instead of one entry per file) and nothing else changes.
- **V-2 (S8-1).** Whether stopping or restarting an `Accept=yes` socket ends instances that are serving a connection at that moment (`systemd.socket(5)`, `systemd.unit(5)` for 255, 257 and 259). B restarts a socket only when its own unit text changed (§4.B), and must not end a request in flight if that can be avoided.
- **V-3 (S8-4).** That `docker compose run` of the reference service fails while the server runs, because the service has a fixed `ipv4_address`. That is why `doctor` runs inside the running container with `docker compose exec shell-mcp /shell-mcp doctor`, or `docker exec <container> …` where a stack editor named the container. The reference compose sets no `container_name`, so Compose names it `<project>-shell-mcp-1`, and no doc may assume a fixed container name.
- **V-4 (S8-4).** Caddy's `reverse_proxy` header behaviour (that it replaces a client's `X-Forwarded-For` unless `trusted_proxies` is set, and appends the peer otherwise) and the matcher syntax, from the Caddy documentation of the version in the test's pinned image. Also verify that `caddy validate` runs with `--network none` for the example's site names: it must not try to obtain a certificate. If it cannot run without the network, STOP and ask; do not give the test container a network.

## 3. Rules every subcommand follows

### 3.1 Root, and nothing else
- **A, B and D's writes refuse unless the effective uid is 0**, and refuse when `SSH_ORIGINAL_COMMAND` is set (they are never reachable as a forced command, even by a key line that names them). `serve` is unchanged; a test asserts that the forced command's dispatch reaches only `serve`.
- **No `sudo`, `su`, `pkexec`, `runuser` or setuid binary.** Running a check as the service account (A) means re-executing the running binary as that account's uid, gid and groups, with a scrubbed environment. That drops privileges; it does not gain them. It is started through execx's credential option (decided, §7 Q13; §4.A, "The credential option"), the only process in this work that runs as another user.
- **No shell.** Every external program is run by absolute path, chain-checked like a policy command (`policy.CheckChain`: root-owned, not group/other-writable, every directory above), with a fixed argv in which every value that came from a flag sits after a fixed option and has passed a validator that forbids a leading `-` (names `^[a-z_][a-z0-9_-]{0,31}$`, ids as decimal integers). The programs are exactly: `/usr/sbin/groupadd`, `/usr/sbin/useradd`, `/usr/sbin/usermod`, `/usr/sbin/sshd` (`-t`, `-T -C`), `/usr/bin/systemctl`, `/usr/bin/systemd-analyze`. On Ubuntu 26.04 none of them is a uutils multi-call binary (they are shadow-utils, OpenSSH and systemd). **They are run through `internal/gate/execx`** (decided, §7 Q11), the process path the gate and the helper already share:
  - an exact argv and an environment the installer builds (empty unless a program needs a variable, which is then named in the code);
  - `MaxMemoryMB` set (execx refuses a Spec without it);
  - a timeout per program;
  - capped output, with a cap large enough for `sshd -T`'s output, which is checked to be complete (not truncated);
  - stdin `/dev/null`;
  - the running binary, resolved and chain-checked, as the trampoline.

  execx already runs as root for the helper (it exempts uid 0 from `RLIMIT_NPROC`, as the kernel does), so no change is expected. **If any program cannot run under execx as it is today, S8-1 STOPs and asks.** This covers a needed variable it scrubs, an fd it closes, the trampoline refusing, or a cap or limit too small that only a gate-wide change would lift. S8-1 does not change gate-only behaviour or add an execx option without that answer. The one exception is already decided: Q13's credential option, under its conditions. No installer starts a process outside execx, A's check-as-account step included.
- **No network.** Nothing in A, B, C or D opens a socket other than `/dev/log` and, for B, systemd's own through `systemctl`. E is the only item that makes a request, and only when run.

### 3.2 Files: three idempotency classes
Every file an item writes is in exactly one class, named in its table:

| Class | Absent | Present, identical | Present, different |
|---|---|---|---|
| **Owned** (content is a pure function of the flags) | written | left alone, reported `unchanged` | **refused**, with a unified diff of what is there and what would be written; never overwritten. The operator removes the file (or reverts the edit) and runs again. |
| **Generated** (the helper's units: carry `# Generated by shell-mcp-privd units`) | written | left alone | replaced, only when the existing file carries the marker; a unit without it (hand-written) is refused |
| **Line-keyed** (`authorized_keys.d/<user>`, keyed by the key's SHA-256 fingerprint) | file written with the line | line left alone | the same key with other options: refused unless `--replace-key`, which rewrites that one line; a line A did not write that fails A's checks: refused (§4.A) |
| **Secret** (C's token, key, approvers) | generated | validated and kept; never regenerated, never re-moded | refused if its owner, mode or format is wrong, with the fix to run; never repaired silently |

Writes are temp file in the same directory, `fsync`, `chmod`/`chown` on the descriptor, `rename`, `fsync` of the directory, then **read back and compared by SHA-256** (the project's read-back rule): a mismatch is a failure. **Temp files** (decided within scope, §7 Q10):
- **Name.** `.<target>.shell-mcp-<random>`: the target's own base name after a leading dot, then 12 lowercase base32 characters from `crypto/rand`. They are created with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, in the target's own directory.
- **Ignored by readers.** systemd, sshd and polkit all ignore such a name. sshd's `Include *.conf` does not match a leading dot or the suffix. sshd's `AuthorizedKeysFile` names `%u` exactly. polkit reads `*.rules`, and systemd reads only unit suffixes.
- **Removed on every failure path.** This includes a refusal after the temp file is written, a failed read-back and a rollback.
- **Documented.** The pattern is documented with each command and in TARGET-SETUP's reference part, next to the files it applies to (S8-1's docs commit, H afterwards). That way an operator who finds one knows what it is.
- **Tested.** Every unit test that makes a write fail (the fake `Host` failing at each step in turn), and every failing case in `scripts/setup-check/`, asserts afterwards that no name matching the pattern is left in any directory the run wrote to.
- **After a kill.** A process killed between create and rename can still leave one. The next run of the same item reports it (WARN, path only) and removes it before it writes, but only when it matches the pattern for one of that item's own targets and is a regular root-owned file.

Ownership and mode are checked on every directory on the path the item creates or relies on, with the same chain rule the gate uses (root-owned, not group/other-writable), and a directory that fails is refused, not fixed.

### 3.3 `--dry-run`
Prints, in order, every check it would make, every file with its owner, mode and full content (secrets as `<43 random characters>` and `<new Ed25519 key>`, never a value), every command with its argv, and the result class each would have now (`create`, `unchanged`, `replace`, `refuse`). It writes nothing, runs no command that changes state, and exits 0 only if the real run would succeed as far as can be known without changing anything. Commands that only read (`sshd -T`, `systemctl show`, `systemd-analyze verify` of files already in place) run in dry-run too and say so. A test snapshots the container's filesystem before and after a dry run and requires no difference.

### 3.4 Order and rollback
Each item runs its checks first, then its writes, ordered so that nothing becomes reachable before everything it depends on is in place (A writes the key line last). If a check after a write fails (A's `sshd -T`, B's `systemd-analyze verify`), the item restores every file it changed in this run to its previous bytes (or removes it if it created it), reports the rollback, and exits non-zero. Accounts and groups created in the run are not deleted on rollback (deleting an account is not in TARGET-SETUP's install path); the report says they remain and that a re-run will find them `unchanged`.

### 3.5 Audit
Each item writes one JSON line per change and one per refusal, to stderr and, for A, B and D, to syslog (`/dev/log`, facility authpriv as the gate's audit, tag `shell-mcp-gate` or `shell-mcp-privd`, priority notice for a change and warning for a refusal, the same 250 ms bounded datagram as `internal/gate/audit`):

```json
{"event":"install","component":"gate","action":"create","object":"file","path":"/etc/ssh/sshd_config.d/60-shell-mcp.conf","sha256":"…","mode":"0644","owner":"root:root"}
{"event":"install","component":"gate","action":"create","object":"key","user":"svc-shell","fingerprint":"SHA256:…","principal":"readonly","policy":"/etc/shell-mcp/read-only.yaml"}
{"event":"install","component":"gate","action":"refuse","object":"key","reason":"from_too_wide","detail":"192.0.2.0/16"}
```

Never a key's base64, a token, a seed, a policy's content or a file's content: paths, names, ids, modes, hashes and fingerprints only. The record is a new type next to `audit.Record` (the request record's fields do not fit), with its own `Line` and a golden test. C writes its lines to stderr only, as `approver add` does (`audit(stderr)` in `cmd/shell-mcp/approver.go`); E writes none of its own (the gate and helper log the read requests it makes, under the server key's principal).

### 3.6 Output
Human lines in the existing `check-policy` style (`ok`, `WARN`, `FAIL`, `REVIEW`, `NOTE`), then a one-line result. Exit codes: 0 done (or nothing to do), 1 refused or failed, 2 usage, 3 stopped for review (B without `--accept`). Every refusal names the file or value and what to do.

### 3.7 Where the code lives
- A in `internal/gate/setup` (linux), with a `Host` interface (user and group databases, files, programs, the clock) whose only production implementation is the real host, and a planner that turns the flags plus what `Host` reports into a list of steps: the planner is what the unit tests drive, with fakes; the executor is what the container tests drive. No flag or variable chooses another `Host` (as `ops.ProductionOptions` today).
- B in `internal/privd/setup`, the same shape, reusing `units.Core`, `units.Broad` and `checkPolicyWith`'s checks (moved into a function both `check-policy` and `install` call, so they cannot drift).
- C in `cmd/shell-mcp` and `internal/setup/secrets`, reusing `internal/approval/approvers` for enrolment and `cmd/shell-mcp/approver.go`'s terminal check.
- D in `internal/gate/policy/gen` and `internal/privd/policy/gen`, each emitting its own schema. No gate package imports a privd package, as today. The helper already imports gate packages (`execx`, `fsx`, `policy`, `sandbox`), and B adds no new direction.
- E in `cmd/shell-mcp` and `internal/tools` (a `ProbeHelper` beside `Probe`).

### 3.8 How everything is tested
Three layers, each with tests committed first and run failing against a **stub** subcommand (one that parses its flags, prints nothing and exits 0), the failing run named in the PR:
1. **Unit tests** (`go test -race`, linux build tag where the code has one, `t.TempDir()`): the planner with a fake `Host`, every refusal as a table case, every file's exact content as a golden file, every audit line, and a fuzz target for each parser added (the `from=` list, the key-line parser, the answers file), each run 60 s.
2. **`scripts/setup-check/`** (new, S8-1; F-13): on `scripts/exposure`'s model, one image per supported target (`debian:trixie-slim`, `ubuntu:24.04`, `ubuntu:26.04`, by digest) with `openssh-server`, `passwd`, `systemd` (for `systemd-analyze verify`, no PID 1), `polkitd`, `acl` and `git`; the release binaries built from the commit copied in (`docker cp`, no host mount beyond the repository read-only); labelled with ci-local's run label and removed by it. Inside, as the container's root, **unprivileged, no added capabilities**, it runs the *(container)* steps through the new subcommands: `install` on a fresh image, again (all `unchanged`), with each refusal's input, `--dry-run` with the filesystem snapshot, an `sshd -D` started in the container and a real SSH round trip (`shell-mcp check` from a second container on a labelled network against a `best-effort` test policy, as S5b did, since CI kernels may lack ABI 4). Runs in `scripts/ci-local.sh` and as a new CI job (both approved, §7 Q2). The containers run as their own root, and only these. They stay unprivileged: Docker's default capabilities with none added, `no-new-privileges`, no host mount but the repository read-only, and none of `--privileged`, `--pid=host` or `--network=host`. ci-local's other containers keep running as a non-root user.
3. **e2e-host** (the runner VM, `test/e2e`, behind the runner guard): what needs a running systemd, polkit, journald and a real `ssh.service`: the slice drop-in in force (`systemctl show`), `install`'s reload, `privd install`'s `daemon-reload`, `enable --now`, a policy edit followed by `install` again (no `helper_policy_mismatch` afterwards, and one before it), the broad pair removed when the policy drops it, the syslog audit lines, and `doctor` against the runner's server, gate and helper. It uses a separate test account (`svc-install`, uid 4200005, in setup.sh's documented test range), so the existing e2e account is untouched. **The runner's own sshd** (approved, §7 Q3, limited):
- **What the test may change.** It may write `/etc/ssh/sshd_config.d/60-shell-mcp.conf` and `/etc/ssh/authorized_keys.d/svc-install`, both for `svc-install` only, and reload the runner VM's `ssh.service`.
- **Before.** It refuses to start if either file already exists, so nothing of the runner's is overwritten. It confirms with `sshd -T -C` for another user that the `Match` block reaches only `svc-install`.
- **After.** In a cleanup registered before the first write, so it runs on failure too, it removes both files and reloads again. It then confirms with `sshd -T -C user=svc-install,…` that no value of the block remains.
- **Everything else.** It changes nothing else in the runner's sshd configuration. The dedicated test sshd of `setup.sh` stays as it is for the other e2e tests.

### 3.9 Audience: any deployer
The maintainer's rule, for this handoff and every S8 session: this is a public project, and its defaults, presets, examples and docs must suit any deployer.
- **Compose.** Plain `docker compose` and stack editors that run Compose in their own container both get a working form (C's two forms). No doc assumes a container name (V-3) or a host directory layout beyond the placeholders.
- **Proxies.** Any reverse proxy works. G lists the properties a proxy needs, and the Caddyfile is one example of them, not a requirement (§4.G).
- **Host size.** Small and very large hosts both work. No default is a fixed size that is too big for one or too small for the other: A's slice default follows the policy and is checked against the host (§4.A), and the owner scan can be narrowed on a very large host, with a WARN (§7 Q6). Presets keep the examples' limits unchanged, and any change is the operator's edit.
- **Hosts and addresses.** Nothing in a default names a host, address, user or path other than the placeholders. Where a value cannot be defaulted for everyone, it is a required flag (ids, `from=`, the pin) and never a guess.

Each session's PR states, in its body, that it checked its defaults and docs against this rule.

## 4. The items

### A. `shell-mcp-gate install`

**Flags.** `--policy <file>` (required; absolute, clean, characters `[A-Za-z0-9._/-]` only, F-8; must exist, root-owned and load as `serve` would load it), `--principal <label>` (required; `^[a-z][a-z0-9-]{0,31}$`), `--from <addr>[,<addr>…]` (required; at most 8 entries), `--key <file.pub>` (required), `--user <name>` (default `svc-shell`), `--uid <n>` and `--gid <n>` (required: never a default, D-020), `--home <dir>` (default `/var/lib/<user>`), `--socket-group <name>` and `--socket-gid <n>` (required exactly when the policy has `privileged.enabled: true`), `--memory-max <size>` (a size, or `none` to omit the slice drop-in, with a WARN). The default is `4 × limits.max_memory_mb` of the policy, which is TARGET-SETUP §4's `4G` at the default 1024 MiB. It scales with what the policy allows each process rather than being one fixed size (§3.9). A value above the host's `MemTotal` is a WARN: the bound then never acts, and the WARN says so. `--owner-scan-paths <dir>[,<dir>…]` narrows the owner scan (below; §7 Q6). `--dry-run`, `--no-reload` (write and check everything, print the reload to run; for hosts where the operator reloads sshd themselves, and the container harness), `--replace-key`.

**What it does, in order.**
1. **Checks before any write:** root (§3.1); every binary it will run (§3.1) and its own binary chain (`/usr/local/bin/shell-mcp-gate`, root-owned, as `install.Check` requires); Landlock (`sandbox.KernelABI` against the policy's mode: a FAIL under `required` stops here); the policy loads (`policy.Load` with `ServiceHome` = `--home`); the key file (below); the `from=` list (below); `sshd -T` (no `-C`) reports `strictmodes yes`; the existing account, groups and files (below); and, when the account or a group is to be created in this run, **the owner scan** (below). The scan is TARGET-SETUP §4's free-id check, so it runs before `groupadd` and `useradd`, never after, when it would find the new home directory.
2. **Groups and account:**
   - `groupadd --gid`;
   - `useradd --uid --gid --home-dir --create-home --shell /bin/sh`;
   - `usermod -L` (F-1);
   - `usermod -aG` for `systemd-journal` when the policy has a `journal` section, and for the socket group when it has `privileged.enabled`. These are the only supplementary groups (§7 Q5).
3. **Slice drop-in**, `systemctl daemon-reload`, `systemctl show -p MemoryMax -p MemorySwapMax user-<uid>.slice` must show the values.
4. **`check-policy` as the account** (§3.1): `/usr/local/bin/shell-mcp-gate check-policy --policy <file>` through execx with the credential option (below), set to the account's uid, primary gid and supplementary groups as A has just created or confirmed them. Its output is printed, and a FAIL stops here, before anything sshd reads exists.
5. **polkit rule**, when the policy has `services.control` (TARGET-SETUP §8; added to A because it is a prescribed file and is regenerated by the same edit; the prompt's list did not name it).
6. **sshd drop-in**, then the **keys directory and the key line**, last.
7. **`sshd -t`**, then `sshd -T -C user=<user>,host=client.example.test,addr=<first from address>` must show every value of the `Match` block (`authorizedkeysfile /etc/ssh/authorized_keys.d/%u`, `authenticationmethods publickey`, `passwordauthentication no`, `kbdinteractiveauthentication no`, `permittty no`, `allowtcpforwarding no`, `allowstreamlocalforwarding no`, `allowagentforwarding no`, `x11forwarding no`, `permittunnel no`, `permituserrc no`, `maxsessions 8`), and `sshd -T -C user=<a name that is not an account>,…` must show none of the account's values for `authorizedkeysfile`, `permittty` and `x11forwarding` (the block must not reach other accounts). Any difference: rollback (§3.4). This replaces checking for `Include` (F-10). *As built (S8-1):* a host whose global configuration already sets `PermitTTY no` or `X11Forwarding no` would fail that comparison although the block reaches no one else, so the other name's whole `sshd -T -C` output is compared with the same output taken before the drop-in was written (it must be identical), and its `authorizedkeysfile` must not be the block's; on a run where the drop-in is unchanged, only the latter.
8. **Reload** (F-7), unless `--no-reload`.
9. **Prints** `SHELL_MCP_TARGET_HOST_KEYS=ssh-ed25519 SHA256:…` (from `/etc/ssh/ssh_host_ed25519_key.pub`, read locally and fingerprinted with `x/crypto/ssh`, never `ssh-keyscan`), the other host-key types as extra pins, "keep this session open until a new login works", and the write roots that `check-policy` warned about (TARGET-SETUP §6 stays the operator's).

`shell-mcp-gate host-key` prints step 9's lines alone, as any user (the `.pub` files are world-readable), for re-pinning without re-running install.

**The credential option** (decided, §7 Q13; S8-1 builds it first, in its own commit with its own tests, before step 4 uses it). A new field on `execx.Spec`, for example `Credential *Credential` holding a uid, a gid and the supplementary groups. Nil, the default, means today's behaviour exactly.
- **Off by default.** No existing caller sets it. The existing execx and gate tests pass **untouched**, which is the proof that every existing caller's behaviour is unchanged, alongside a test that a nil `Credential` encodes the same trampoline configuration as today.
- **Root only.** `Run` honours it only when the calling process runs as uid 0, checking both the real and the effective uid. In any other process `Run` refuses with a clear error (a typed error naming the option and the caller's uid) before anything starts: no socketpair, no fork. It is never silently ignored. The trampoline refuses it too, if it ever receives a credential while not running as uid 0.
- **Values, refused before the exec.** The caller resolves the account from `/etc/passwd` and its supplementary groups from `/etc/group`, through A's `Host`. A missing account, a missing group, or a gid that no `/etc/group` entry names is refused before `Run` is called. `Run` itself refuses a uid or gid of 0, a group list containing 0, a duplicate, or more than 64 groups. For A, the groups must also be exactly the set §7 Q5 allows: the socket group, and `systemd-journal` with a journal section.
- **The switch, in the trampoline.**
  - **Checks first.** The trampoline runs every check it runs today first, as root: the argument, AT_SECURE, the empty environment, the main thread, no terminal on fd 0–2, and fd 3's peer being its root parent under its own uid. Then it reads the command and lowers its limits as today.
  - **Then the switch, in this order:** `setgroups(2)` to exactly the given list (possibly empty), then `setgid(2)`, then `setuid(2)`. As root, `setgid` and `setuid` set the real, effective and saved ids; S8-1 verifies that in the man pages.
  - **Every thread.** S8-1 verifies in the installed Go and `x/sys` source that each call applies to every thread of the process (the runtime's all-threads syscalls). If any thread could keep root's ids, STOP.
- **Verified before the exec.** `getresuid`, `getresgid` and `getgroups` must equal the account's uid three times, its gid three times, and exactly its group list. No group 0 may remain. The permitted, effective and ambient capability sets must be empty (`capget`). Any difference refuses: the command is not run, and `Run` reports the trampoline's refusal as a start error.
- **After the switch.** `PR_SET_NO_NEW_PRIVS` is set, if it is not set already, after the verification and before `execve`. The command keeps no capabilities. Its rlimits and descriptor handling are those of every other execx command. Because it now runs as a non-root uid, `RLIMIT_NPROC` is applied as for any non-root command: the account's tasks are counted, plus `ChildExtraTasks`, and not skipped as for root. If that reading of "the same rlimits" is wrong, the session asks.
- **One caller.** The only caller is step 4, which runs the installed `/usr/local/bin/shell-mcp-gate check-policy` as the service account. A call-site test parses every non-test Go file in the module and requires that the field is set in exactly one place, in `internal/gate/setup`. It fails if any file reached from `serve` (`cmd/shell-mcp-gate`'s serve path and `internal/gate/...` other than `setup` and `execx`), the helper (`cmd/shell-mcp-privd`, `internal/privd/...`) or the server (`cmd/shell-mcp`, `internal/...` outside the gate) references it.
- **Tests,** each committed first and shown failing against the pre-change execx:
  - a non-root caller is refused before anything starts (runs in every `go test`);
  - the child's real, effective and saved uid and gid, and its groups, are exactly the account's, with no leftover group 0, and its capability sets are empty (a test command that prints them from `/proc/self/status`);
  - a missing account or group is refused before the exec;
  - existing callers are unchanged (the existing execx and gate tests untouched, plus the nil-encoding test);
  - the call-site test.

  The switch tests need a root test process: they run in `scripts/setup-check/` as the container's root, and on e2e-host. Under ci-local's non-root containers they skip, and they never pass merely by skipping there.
- **STOP** and ask if the option needs anything beyond these conditions: another caller, a capability kept, a different order, a change to the trampoline's existing checks, or a limit that differs from other commands' limits.

**Files.**

| Path | Owner, mode | Class | Notes |
|---|---|---|---|
| `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` | — | — | written only by `groupadd`, `useradd`, `usermod`; never by our code |
| `<home>` (default `/var/lib/svc-shell`) | `svc-shell:svc-shell`, `useradd`'s default mode | — | created by `useradd --create-home`; refused if it exists and is not the account's |
| `/etc/systemd/system/user-<uid>.slice.d/` | `root:root 0755` | owned (directory) | |
| `/etc/systemd/system/user-<uid>.slice.d/50-shell-mcp.conf` | `root:root 0644` | owned | `[Slice]\nMemoryMax=<size>\nMemorySwapMax=0\n`, exactly TARGET-SETUP §4's bytes, with no header comment (decided 2026-11-01 in S8-1: byte identity wins, so a host set up by hand reports `unchanged`) |
| `/etc/polkit-1/rules.d/60-shell-mcp.rules` | `root:root 0644` | owned | `polkit.Rule` output, only with `services.control`; the directory (`root:polkitd 0750`) must exist, it is never created |
| `/etc/ssh/sshd_config.d/60-shell-mcp.conf` | `root:root 0644` | owned | exactly TARGET-SETUP §7's block for `--user`, with no header comment (decided as for the slice drop-in); one service account per host (a file for another user is refused) |
| `/etc/ssh/authorized_keys.d/` | `root:root 0755` | owned (directory) | `/etc/ssh` must be `root:root`, not group/other-writable |
| `/etc/ssh/authorized_keys.d/<user>` | `root:root 0644` | line-keyed | one line per key: `restrict,from="<list>",command="/usr/local/bin/shell-mcp-gate serve --policy <file> --principal <label>" ssh-ed25519 <base64> shell-mcp-<label>` |
| `/etc/shell-mcp/<policy>` | — | read only | must exist; written by D or by hand |
| `/etc/ssh/ssh_host_*_key.pub` | — | read only | |

**Refusals** (each a table test, each a container case where it can be built there):
- `from=` (decided, §7 Q1). Each of these is refused:
  - an empty list;
  - any entry that is not an IP address or a canonical CIDR prefix (`netip.ParsePrefix`, host bits refused, as `SHELL_MCP_TRUSTED_PROXIES` is);
  - wildcards (`*`, `?`) and negations (`!`);
  - host names (they make sshd consult DNS when `UseDNS` is on, which trusts the network);
  - more than 8 entries, and duplicates;
  - **an IPv4 prefix shorter than /24 or an IPv6 prefix shorter than /64.** This is a hard limit with no flag, variable or other override. IPv4-mapped IPv6 (`::ffff:0:0/96` and inside it) is judged by the IPv4 rule on the unmapped prefix, so `/120` is the floor there.

  Any entry wider than one address (shorter than /32 or /128) is accepted with a **WARN**. The WARN names the entry and suggests the server's own address as `/32` or `/128`, and the audit line records it. The same rules apply to every existing line's `from=` (below).
- The key file: not exactly one line; options before the key type; a type other than `ssh-ed25519` (D-012); a body that does not parse; a file that begins with a private-key header (refused without printing any of it, and the message says the `.pub` file is wanted); a key equal to one of the host's own host keys.
- The key line already present: same fingerprint, other options, without `--replace-key`. **Every existing line** of the keys file must parse and pass the same checks (`restrict` present, `from=` within the rules, `command=` exactly `/usr/local/bin/shell-mcp-gate serve --policy <path> [--principal <label>]` with both values in the safe character sets, an Ed25519 key); any line that does not is reported with its number (never its key) and the run is refused, since the file A manages would otherwise hold a line that weakens it. Comments and blank lines are kept.
- `--policy` or `--principal` outside their character sets (F-8); the policy fails to load; `check-policy` as the account reports FAIL.
- Account: `--uid` or `--gid` 0, 65534, in systemd's dynamic range 61184–65519, or below 1000; the uid or gid used by another name; an existing account whose uid, primary gid, home or shell differ from the flags; a member of any group in `install.DeniedGroups` (F-6); a shell that is `nologin` or `false`, or missing.
- **Supplementary groups** (decided, §7 Q5: refuse, never WARN). The account may have only these supplementary groups:
  - the socket group, when `--socket-group` is given;
  - `systemd-journal`, only when the policy has a `journal` section.

  Any other supplementary group of an existing account is refused, and the message names the group. So is `systemd-journal` when the policy has no `journal` section, or a group with the socket group's name or gid when the policy has no `privileged.enabled`. A group in `DeniedGroups` is refused by the bullet above, and the message says it is a privileged group. A never removes a membership; the operator does that and runs again.
- **The owner scan** (decided, §7 Q6). It runs before the account or a group is created in this run (step 1) and refuses on any inode owned by the uid or the gid.
  - **Default.** Mandatory: every local filesystem from `/proc/self/mountinfo` is walked. Pseudo and network filesystems are skipped and listed. The walk stops at the first hit, which is reported.
  - **Narrowed.** `--owner-scan-paths <dir>[,<dir>…]` walks only those directories, each within its own filesystem. Each must be absolute, clean, an existing directory, not a symlink, and listed once, with at most 32 entries. The run prints a **WARN** naming what is not scanned (every local filesystem not covered by a listed path), and the audit line records `owner_scan: narrowed` with the paths.
  - **Never skipped.** An empty list, a `none`, or any other value that would scan nothing is a usage error (exit 2). The flag is refused when no account or group is created in this run, since there is then nothing to scan for. *Decided 2026-11-01 in S8-1:* this disagreed with "a second run with the same flags … reports every item `unchanged`" (Idempotency, below); same-flags idempotency wins: when nothing is created the flag is accepted with a NOTE that nothing is scanned (its own checks still apply).
- `--socket-gid` used by another group; the socket group exists with another gid; `--socket-group` or `--socket-gid` given for a policy without `privileged.enabled`, or missing for one with it.
- sshd: `strictmodes no`; `/etc/ssh`, the keys directory or the keys file not `root:root` or group/other-writable (TARGET-SETUP §7's `stat` check, which `StrictModes` alone does not cover, ARCHIVE S5b F-1); `sshd -t` fails; the effective configuration differs (step 7); a `60-shell-mcp.conf` for another user.
- `SSH_ORIGINAL_COMMAND` set; not root; a binary that fails its chain check.

**Idempotency.** Account and groups: created when absent, `unchanged` when they match, refused when they differ (above). Files per §3.2. A second run with the same flags changes nothing and reports every item `unchanged`; a run with a second `--key`/`--principal` appends one line. The reload runs only when the drop-in or the keys file changed (sshd reads the keys file on every login, so a new key needs no reload; the drop-in does).

**Audit.** §3.5:
- one line per account, group, membership, file and key line created or replaced, and one per refusal;
- the owner scan's scope and result (`"owner_scan":"full"` or `"narrowed"` with `"paths":[…]`);
- each `from=` WARN entry;
- the policy's SHA-256 and the key's fingerprint, never the key.

**Tests** (stub first; each must fail against it):
- Unit:
  - **Refusals.** The refusal table above, one case per bullet.
  - **The `from=` boundaries.** `/24` and `/64` accepted with the WARN, `/23` and `/63` refused. A `/96` inside `::ffff:0:0/96` is refused, and `/32` and `/128` are accepted with no WARN. No flag or variable lowers the floor, which a test proves by grepping the flag set.
  - **Supplementary groups.** Each allowed and refused case, with the group named in the message.
  - **The owner scan.** It runs before `useradd` in the plan, the narrowed scan's WARN and audit field, and the refusal of an empty list.
  - **Golden files.** The drop-in, the slice drop-in (default size from the policy's `limits.max_memory_mb`), and the key line.
  - **Fuzzing.** The key-line parser and the `from=` parser, 60 s each.
  - **Order and rollback.** The planner's order (the key line after everything else); rollback restores the previous bytes when the fake `sshd -T` disagrees, and leaves no temp file (§3.2).
  - **Audit.** The audit lines.
- `scripts/setup-check/` on the three images: a fresh install, then a second run (every item `unchanged`); `--dry-run` with no filesystem difference; each refusal that a container can build (an account in `docker`, a uid in use, a world-writable keys file, `StrictModes no` in an earlier drop-in, a `Match User` in an earlier drop-in that wins, a hand-added key line without `restrict`, a `/16`, a policy path with a space); then the SSH round trip: the gate's `hello` answers, no shell without a command, no PTY, `shell-mcp check` verifies the printed pin and refuses a wrong one.
- e2e-host:
  - the slice drop-in in force;
  - the reload of the runner's `ssh.service` and a login as `svc-install` after it, within §3.8's limits (the block for that account only, removed afterwards and confirmed gone; §7 Q3);
  - the polkit rule allowing exactly the listed verb;
  - the syslog lines (`journalctl -t shell-mcp-gate`).

**Supersedes.** TARGET-SETUP §4 (account, groups, slice), §7 (the drop-in, the keys file, the `StrictModes`/`stat` checks, reload, the host key) and §8 (the polkit rule), which move to the reference part (H); `deploy/README.md`'s "Install `secrets/ssh_key.pub` on the target …" and pinning paragraph (it points at `install`'s printed pin). SECURITY §5 steps 1–3, 6 and 8 stay normative and unchanged: A implements them.

### B. `shell-mcp-privd install`

**Flags.** `--policy <file>` (required), `--accept <sha256>` (the policy's SHA-256), `--gate-policy <file>`. **`--accept` is required on every run that writes or activates anything** (decided, §7 Q4). That includes a re-run with an unchanged policy and a policy with no REVIEW items and no broad unit, so every install binds the operator's review to the bytes installed. `--dry-run` needs no `--accept`: it prints the review and the plan, writes nothing, and exits 3 when the real run would stop for review. (repeatable, optional: cross-checks each), `--dry-run`, `--no-start` (write and verify the units, skip `daemon-reload`, `enable` and restarts; for images and the container harness).

**What it does, in order.**
1. **Checks:** root (§3.1); the running binary is `/usr/local/libexec/shell-mcp-privd` (`units.HelperPath`, resolved), since the units run that file and nothing else; the policy file is `root:root` and not group/other-accessible (today a WARN in `check-policy`; here a refusal, PRIVILEGED §2); the full `check-policy` (the shared function, §3.7) with its output printed; any FAIL stops here.
2. **Review.** Every `REVIEW` line, the broad unit's root-equivalence and the policy's SHA-256 are printed. Without `--accept`, or with a hash other than the policy's, it stops with exit 3 and prints the command to re-run; nothing is written. The policy is read once: the hash accepted, the units generated and the hash in them are of the same bytes.
3. **Cross-checks** (each FAIL stops): the account whose uid is `client_uid` exists locally and has `socket_group` as a supplementary group (else the gate cannot connect); for each `--gate-policy`, `privileged.enabled` is true, `socket` is `/run/shell-mcp/privd.sock`, and `broad_socket` is `/run/shell-mcp/privd-broad.sock` exactly when the broad pair is generated.
4. **Backup store:** `/var/lib/shell-mcp` and `/var/lib/shell-mcp/backups` created `root:root 0700` when absent; when present, refused unless `root:root` with no group or other bits.
5. **Units:** generated in memory (`units.Core`, `units.Broad`), compared with the files in `/etc/systemd/system`; identical files are left alone; changed or new ones written (§3.2, generated class); then `systemd-analyze verify --man=no` on the core pair and, when generated, the broad pair; a failure rolls back to the previous files (§3.4).
6. **Activation** (unless `--no-start`): `systemctl daemon-reload` when any unit changed; `systemctl enable --now` for each generated socket; a socket whose own `.socket` file changed is restarted (V-2), one whose service template alone changed is not (new instances start from the reloaded template); when the policy no longer uses the broad unit and a marked broad pair is installed, `systemctl disable --now shell-mcp-privd-broad.socket`, the pair removed, `daemon-reload` (F-3).
7. **Reports:** `/run/shell-mcp` is `root:root 0711`, each socket `srw-rw---- root <socket_group>` (refused afterwards if not, with the units left as they are); `systemd-analyze security shell-mcp-privd@.service` score, printed with the expected values from PRIVILEGED §5.1 (1.3, 1.4 with a root under `/home`, 1.6 with `CAP_KILL`), WARN above them.

**Files.**

| Path | Owner, mode | Class |
|---|---|---|
| `/etc/shell-mcp/privileged.yaml` | `root:root 0600` | read only (written by D or by hand) |
| `/etc/systemd/system/shell-mcp-privd.socket`, `shell-mcp-privd@.service` | `root:root 0644` | generated |
| `/etc/systemd/system/shell-mcp-privd-broad.socket`, `shell-mcp-privd-broad@.service` | `root:root 0644` | generated, only when the policy uses the broad unit; removed when it stops |
| `/var/lib/shell-mcp/`, `/var/lib/shell-mcp/backups/` | `root:root 0700` | owned (directories) |
| `/run/shell-mcp/` and the sockets | created by systemd | checked only |

**Refusals.** Not root; `SSH_ORIGINAL_COMMAND` set; the running binary is not `units.HelperPath`; the policy file's owner or mode; any `check-policy` FAIL (including `/var/run` not a link to `/run`); `--accept` missing or not the policy's hash (exit 3, not 1); the `client_uid` account missing or not in `socket_group`; a `--gate-policy` that disagrees; a backup directory with the wrong owner or mode; an existing unit file without the generated marker; `systemd-analyze verify` failing; without `--no-start`, systemd not running as PID 1 (`/run/systemd/system` absent); the sockets' modes after activation.

**Idempotency.** Same policy, second run (with `--accept` of the same hash, §7 Q4): nothing written, no reload, sockets confirmed enabled and active, every item `unchanged`. Without `--accept` the second run stops for review like the first. Edited policy: `--accept` with the new hash, then only what changed is written and reloaded. The generated class means a unit file is only ever replaced by `install` (or `units`), never one written by hand.

**What does not change.** Unit generation, the directives, the hash binding and the self-checks are exactly today's (`units.Core`, `units.Broad`, PRIVILEGED §5, §7). B calls them; it does not alter them. Any need to change them is a STOP.

**Audit.** §3.5, tag `shell-mcp-privd`: the accepted hash, every unit written, replaced or removed with its SHA-256, the store directories, each `enable`, restart and disable, and each refusal (the review stop included, at notice).

**Tests** (stub first):
- Unit: the refusal table; the review stop (exit 3, nothing written), also on a re-run of an already installed, unchanged policy and for a policy with no REVIEW items and no broad unit (§7 Q4); and the hash bound to the bytes read (a policy changed between two reads cannot be installed with the first hash: the test swaps the file after the check through the fake `Host`); an unchanged policy writes nothing; a policy that drops the broad unit produces the disable and the removal; a hand-written unit is refused; rollback when the fake `verify` fails, with no temp file left (§3.2).
- `scripts/setup-check/` (`--no-start`, no PID 1): the units written are byte-identical to `units --out`'s for the example policy and the e2e policies; `systemd-analyze verify` runs on the three images; a second run writes nothing.
- e2e-host: `install` from a clean runner (the e2e setup's own units removed first, or a second policy whose units it then restores), the sockets active with the right modes, a privileged read through the real server; then an edit of the policy without `install` gives `helper_policy_mismatch`, and `install --accept <new hash>` clears it; the broad pair removed and its socket gone after the policy drops packages (*as built, decided 2026-11-01:* "gone" is not listening: the socket unit inactive and disabled and a connection refused; systemd keeps the stopped socket's node, `RemoveOnStop=` being off, and install leaves it with a NOTE rather than touch a path the table marks "checked only"); the syslog lines.

**Supersedes.** TARGET-SETUP §9.2, §9.3 and §9.4's procedure (they move to the reference part), §11's "A privileged policy edit" bullet (it becomes "run `install` again"), SECURITY §5 step 9's install sequence (normative content unchanged; it names `install`). `units` stays, for review and for generating units elsewhere; its printed next steps point at `install` (F-2).

### C. `shell-mcp init`

**What it creates** (`deploy/README.md` "Secrets" and CLIENTS §3.2, in one command):

| Path (under `--dir`) | Owner, mode | Class | Content |
|---|---|---|---|
| `<dir>/` | `<uid>:<gid> 0700` | owned (directory) | |
| `mcp_token` | `<uid>:<gid> 0600` | secret | 32 bytes from `crypto/rand`, base64url without padding: 43 characters, one line (as the README's pipeline) |
| `ssh_key` | `<uid>:<gid> 0600` | secret | an unencrypted OpenSSH Ed25519 private key (`crypto/ed25519`, `ssh.MarshalPrivateKey` from `x/crypto/ssh`, comment `shell-mcp`) |
| `ssh_key.pub` | `<uid>:<gid> 0644` | secret (public half, derived) | the matching `ssh-ed25519 … shell-mcp` line; regenerated from `ssh_key` if absent, refused if it does not match it |
| `approvers` | `<uid>:<gid> 0600` | secret | only with `--approver <name>`, through `approvers.Add` and the existing terminal check (QR and `otpauth` URI shown once on the terminal) |

Defaults `--uid 65532 --gid 65532` (the image's user). No new dependency: `crypto/ed25519`, `crypto/rand` and `x/crypto/ssh` are already used.

**Running it.** Two ways, the same code:
- **On the host, as root, with the release's `shell-mcp` binary:** creates `--dir` if absent, writes each file, and `chown`s directory and files to `--uid:--gid` on their descriptors.
- **In the image, as 65532** (the image has no shell and runs as 65532, so it cannot create a host directory owned by 65532 or `chown` anything): the operator creates the directory first with one host command, `install -d -o 65532 -g 65532 -m 0700 /srv/shell-mcp/secrets`, then runs
  `docker run --rm -it --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true -v /srv/shell-mcp/secrets:/secrets ghcr.io/tyler-rich/shell-mcp:<version>@sha256:<digest> init --dir /secrets --approver alice`.
  Files a process with uid 65532 creates are owned by it; nothing needs a capability, the network, or root in the container. `init` refuses when its effective uid is neither 0 nor `--uid`, so it can never leave files the server cannot read. This fixes F-9.

**Output forms** (`init compose`). Printed to stdout only, never written: the reference compose with the target's name, host, user, pin, the MCP and approval host names, the proxy's and the server's fixed addresses and the subnet filled in, and the approval variables when an approver is enrolled. Two forms:
- `--form secrets` (default; `docker compose` on the host): `deploy/docker-compose.yml` exactly, with top-level `secrets:` entries `file: ./secrets/<name>`, run next to the directory (as `deploy/README.md`), plus `approvers` when enrolled.
- `--form bind --dir <absolute host path>` (stack editors that run Compose in their own container, V-1): no `secrets:` blocks; one read-only bind mount `- <dir>:/run/secrets:ro`, so the `*_FILE` paths are the same in both forms. The directory being `0700` and owned by 65532 is what lets the container read it.

The hardening flags (`user`, `read_only`, `cap_drop`, `security_opt`, limits, healthcheck, logging) are not parameters: the template is `deploy/docker-compose.yml` itself, embedded, and a test asserts that rendering with that file's placeholder values reproduces it byte for byte, so the two cannot drift and `deploy/` is not touched. `--image` must carry `@sha256:` and 64 hex digits (no placeholder digest, as S5b decided). `--host-key` is required and is parsed with the server's own pin parser: there is no way to fill the pin from the network (D-012). An environment-store form (`SHELL_MCP_SSH_KEY`, `SHELL_MCP_TOKEN`) is not generated (§5).

**Refusals.** `--dir` not absolute, a symlink, not a directory, not owned by `--uid` (in the image) or by root or `--uid` (on the host), or group/other-accessible; effective uid neither 0 nor `--uid`; an existing secret whose owner or mode is wrong, a token shorter than 43 characters or with a newline inside, a key that is not an unencrypted Ed25519 key, a `.pub` that does not match; `--approver` with stdout not a terminal (checked before anything is generated, as `approver add`), or a name already enrolled; `init compose` without `--host-key`, with a pin that does not parse, with an image without a digest, with host names that are not valid DNS names, with addresses outside `--subnet`, or with the server's and the proxy's addresses equal; `--form bind` without an absolute `--dir`.

**Idempotency.** Secrets class (§3.2): a second run keeps every file and reports `kept`; a missing file is generated; `--approver` adds only a new name. Rotation is not part of `init` (deleting a file and running it again is the rotation, and the deploy docs say what to update).

**Audit.** stderr JSON as `approver add`: `secret created|kept`, with the file name, owner and mode, the key's fingerprint, the approver's name; never the token, the key, the seed or the URI.

**Tests** (stub first): unit tests for each refusal; the token's length and alphabet; the key round-trips through `config`'s own key loader and is accepted by `sshx`; the compose template equality with `deploy/docker-compose.yml`; both forms parsed back with a YAML decoder and checked for every hardening key; a second run changes no byte; nothing secret on stdout or stderr (the test scans both for the token, the key's base64 and the seed). Container (ci-local, the image built from the commit): the in-image path as 65532 with `--network none --read-only --cap-drop ALL`, then `serve` starting from the directory (both forms) and `check` failing closed on the placeholder target only after loading every secret; the refusal for a directory owned by root.

**Supersedes.** `deploy/README.md` "Secrets" (kept as the manual path), CLIENTS §3.2's enrolment command and its "secrets/ must be writable by it" sentence, and the README quick start's secrets lines.

### D. `policy new` (an answers file, in both binaries)

**Shape.** One answers file the operator writes and keeps (`setup.yaml`), strict-decoded (unknown keys are errors), and two commands, each writing only its own schema:
- `shell-mcp-gate policy new --answers setup.yaml --out /etc/shell-mcp/<name>.yaml`
- `shell-mcp-privd policy new --answers setup.yaml --out /etc/shell-mcp/privileged.yaml` (only when the answers enable root actions)

`--out -` prints instead of writing. Both read the same file, so the shared values (the uid as `client_uid`, the socket group, the socket paths, the deny patterns) are the same by construction, and B's `--gate-policy` cross-check confirms it after the fact.

```yaml
# setup.yaml (placeholders)
preset: operator            # read-only | operator | admin
account: { user: svc-shell, uid: 60123 }
read:  [/srv/app, /var/log/example-app]
write: [/srv/app/config]
deny:  ["/srv/app/secrets/**", "**/*.key"]
services: { status: [example-app.service], control: { units: [example-app.service], verbs: [restart] } }
journal: { units: [example-app.service] }
git: { repos: [{ path: /srv/app/deploy, remote: https://git.example.test/app.git }] }
commands:                   # the gate's, run as the service account
  - { id: app-health, path: /usr/local/bin/example-health, tier: read, templates: [["--json"]] }
root:                       # only with preset admin; becomes the privileged policy
  socket_group: { name: svc-shell-priv, gid: 60124 }
  read:  [/etc/example-app]
  write: [/etc/example-app]
  owners: { users: [root, example-app], groups: [root, example-app] }
  packages: { install: [htop, jq], remove: [htop] }
  commands:
    - { id: nginx-test, path: /usr/sbin/nginx, tier: read, templates: [["-t"]] }
```

**Presets.** `read-only` (from `examples/policies/read-only.yaml`), `operator` (`operator.yaml`), `admin` (`admin.yaml`, plus `examples/privileged/privileged.yaml` when `root:` is present). A preset sets `max_tier`, `privileged.max_tier` and which sections may appear: `services.control`, `write` and `git` are refused under `read-only`, `root:` under anything but `admin`. Every limit stays at the example's value; changing one is an edit afterwards.

**Output.** Rendered from the example files as templates, so their header and the worst-case comments ("what would I accept a fully compromised MCP server doing with this key?", each section's comment) are kept verbatim; a test asserts the rendered example answers reproduce `examples/` byte for byte, so the examples and the generator cannot drift. The generated bytes are then loaded with the strict loader (`policy.Load` for the gate's, the privileged loader for the helper's) before anything is written: a policy that does not load is never written. After writing, the gate's command runs `check-policy` as root (with its `NOTE`, F-4) and says that `install` will run it as the account; the helper's runs its own `check-policy`. Neither copies the never or acknowledge lists: an answers entry that needs an `acknowledge` (list B, a script, a package tool) is refused with the name of the key to add (`acknowledge:` on that command), so the operator writes the acknowledgement in their own words.

**Files.**

| Path | Owner, mode | Class |
|---|---|---|
| `/etc/shell-mcp/` | `root:root 0755` | owned (directory), created when absent |
| `/etc/shell-mcp/<name>.yaml` | `root:root 0644` | owned |
| `/etc/shell-mcp/privileged.yaml` | `root:root 0600` | owned |

**Refusals.** Unknown keys; a value the schema refuses (the strict loader's message); an `acknowledge`-requiring entry without one; a section the preset does not allow; a write root inside the protected set or the never set (the loaders' own rules); `root:` with an `account.uid` of 0; `--out` outside `/etc/shell-mcp` (the forced command and the units point there; another path is still possible by hand); an existing file that differs (owned class: refused with a diff). The generator is a starting point, not a configuration manager: after the first write, edits are by hand, followed by `check-policy` and, for the privileged policy, B.

**Audit.** §3.5: the written file and its SHA-256, the preset.

**Tests** (stub first): the examples reproduced byte for byte from their answers; every generated policy loads strictly; a fuzzed answers decoder (60 s); every refusal; the shared values equal across the two outputs; in `scripts/setup-check/`, D then A then B on a fresh image, ending in `check-policy` ok (best-effort Landlock where the kernel lacks ABI 4) and B's cross-check passing.

**Supersedes.** TARGET-SETUP §5's copy-and-edit (kept in the reference part), §9.1, and §9.5's hand-added `privileged:` section.

### E. `shell-mcp doctor`

**Why a new command, and `check` unchanged.** `check` (F-12) has a JSON output that scripts read, and it only connects to targets. `doctor` runs everything `check` does and then checks that make requests `check` should not make silently (the approval URL, the MCP URL through the proxy). It prints `ok`/`WARN`/`FAIL` lines, `--json` gives the same as one object, and it exits 1 on any FAIL. It runs inside the running server's container, so it sees the same environment and mounts. Use `docker compose exec shell-mcp /shell-mcp doctor` with plain Compose (the service name), or the stack editor's own exec on the container it named (V-3: `compose run` would collide on the fixed address; no doc assumes a container name, §3.9).

**Checks.**
- **Configuration:** `config.Load` as `serve` (every startup refusal), its warnings, and each secret file's owner and mode (a group/other-readable file is a FAIL here, a WARN at startup).
- **Per target, from `check`:** the pin verified, SSH authentication, `hello` (version, protocol, principal, policy SHA-256, `max_tier`, sandbox mode, Landlock ABI and whether it is applied).
- **Helper sockets** (a `ProbeHelper` next to `tools.Probe`, every request at ceiling `read`): when `hello` reports privileged forwarding, `priv_policy` through the core socket: the helper's version, its policy SHA-256 and `unit: core`; the codes mapped to remedies: `helper_unavailable` (socket not enabled: run `shell-mcp-privd install`), `helper_refused` (the peer check: `client_uid` or the socket group), `helper_policy_mismatch` (units not regenerated: `install` again), `protocol_mismatch` (upgrade). The broad socket only through a read op that changes nothing: `priv_pkg_update_index_preview` when the summary says `allow_update_index`, else `priv_power_preview` with an allowed action when power is allowed (the broad unit logs everything it serves at WARN, which the output says), else **"broad socket not probed: this policy has no read operation on it"** (decided, §7 Q9: accepted, no protocol change). The line also says the socket's state shows on the first broad call and in `systemctl status shell-mcp-privd-broad.socket` on the target.
- **Trusted proxies, statically** (CLIENTS §1): each `SHELL_MCP_TRUSTED_PROXIES` entry is a single address (a prefix is a WARN); none contains the container's default gateway (read from `/proc/net/route` and `/proc/net/ipv6_route`; containing it is a FAIL, with CLIENTS §1's reason); each is on a directly connected subnet of the container (`net.Interfaces`; otherwise a WARN); and the line that the dynamic check is still the log-line procedure of CLIENTS §1.
- **The approval page**, under `web`: `GET` of `SHELL_MCP_APPROVAL_PUBLIC_URL` from inside the container, no proxy variables, no redirects followed, system roots or `--ca-file`: reachable, the certificate valid for the host and its expiry, and the response carrying the page's own headers (`Content-Security-Policy` with `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Cache-Control: no-store`), which tells our page from another service answering on that name. What it cannot show (that the page is unreachable from outside the LAN or VPN) is said.
- **The MCP endpoint**, with `--mcp-url`: one `POST` without a token must answer `401` with `WWW-Authenticate: Bearer realm="shell-mcp"` (a request without a token does not count toward the lockout, ARCHITECTURE §3), and a `421` says the name is missing from `SHELL_MCP_ALLOWED_HOSTS`.

**Files.** Reads only: the configuration, the mounted secrets (mode and owner, and loading them as `serve` does), `/proc/net/route`, `/proc/net/ipv6_route`, `--ca-file`. Writes nothing.

**Refusals and audit.** None of its own beyond `check`'s; the gate and the helper log its read requests under the server key's principal, which is the evidence it ran.

**Tests** (stub first): unit tests with an in-process SSH server and gate stub (the pattern `cmd/shell-mcp` tests already use) for each helper code and its remedy, the broad probe's three cases, the gateway detection against fixture route tables, the proxy entry rules, the approval page with an `httptest` TLS server (right headers, wrong headers, bad certificate, redirect not followed), the MCP probe (401, 421). Container (ci-local): the image on a labelled network at the reference addresses, with no proxy container: the static checks need only the container's own interfaces and routes. `doctor` is run with `docker exec` on the id the test started, once with the reference `SHELL_MCP_TRUSTED_PROXIES` and then with the network's gateway in it (FAIL). e2e-host: against the runner's server, gate and both helper units (a policy with `allow_update_index`), and after a policy edit without `install` (`helper_policy_mismatch` and its remedy).

**Supersedes.** TARGET-SETUP §10's `shell-mcp check` (doctor first; `check` stays for scripts), and the static half of CLIENTS §1's "Set the value from what the server logs".

### F. `verify-release.sh`

**What it does.** `scripts/verify-release.sh <version> [--dir <dir>] [--sums <file>]`, POSIX `sh`, also in the examples archive, run as any user (never root needed, never `sudo`), downloading nothing itself unless asked: it verifies the files present in `--dir`.
- **With `cosign`** (or `gh`): `sha256sum --strict -c SHA256SUMS` for the files present (every present file other than the bundles must be listed), `cosign verify-blob` of each binary, the archive and `SHA256SUMS` against `--certificate-identity https://github.com/tyler-rich/shell-mcp/.github/workflows/release-build.yml@refs/tags/v<version>` and the GitHub OIDC issuer, and, with `gh`, `gh attestation verify … --signer-workflow … --source-ref refs/tags/v<version>` for the listed files. The same commands as README "Verifying a release" and `scripts/release/verify.sh`, which it shares a test with, so they cannot diverge.
- **Without either** (a target without cosign): `--sums <file>`, a `SHA256SUMS` the operator already verified with cosign elsewhere and copied over; the script checks the files against it and says plainly that the signature was checked elsewhere. With neither cosign, `gh` nor `--sums`, it refuses and prints how to get one.

**Pushback (§5).** The prompt's fallback, "curl + sha256sum against the GitHub attestations API", is not verification: the API returns a Sigstore bundle, and comparing a digest with what it holds without checking the bundle's certificate chain, transparency-log entry and identity only proves that GitHub's API and GitHub's release storage agree, over the same TLS channel the download came through. Doing that check properly in shell means reimplementing Sigstore verification with `openssl`, which is not a script anyone should trust. And a script inside the archive it verifies is circular: the root of trust stays the README's commands, run once, with cosign.

**Files.** Reads the files in `--dir`; writes nothing. **Refusals:** a missing tool and no `--sums`; a file present but not listed; any check failing (exit 1, naming the file). **Audit:** none (a user tool). **Tests** (stub first): a `sh` test (`scripts/verify-release_test.sh`, like `scripts/release/release_test.sh`) with fake `cosign` and `gh` on `PATH` in a temp directory that record their argv and fail on demand: the identity is the tag's, never a branch's; a tampered file fails `sha256sum`; an unlisted file fails; no tool and no `--sums` refuses; shellcheck clean. The real verification runs in the release workflow after signing (`verify.sh` already does; the job gains one run of `verify-release.sh` against the files just signed).

**Supersedes.** TARGET-SETUP §2's commands (kept in the reference part and in README "Verifying a release", which stays the root of trust).

### G. `deploy/caddy/`

Decided (§7 Q7). G is two example files: **no compose file, and no image added to `deploy/`.** Nothing in `deploy/docker-compose.yml` changes, and nothing here ships a container to users. The deployer runs their own proxy, of any kind, and G says what it must do (§3.9).

**Files** (new):
- **`deploy/caddy/Caddyfile`**, an example with placeholders only:
  - **The MCP site.** `mcp.example.test` → `reverse_proxy 172.30.80.10:8080`.
  - **The approval site.** `approve.example.test` uses a `remote_ip` matcher for the LAN and VPN ranges (`192.0.2.0/24`, `198.51.100.0/24` as placeholders). Matching requests go to `reverse_proxy 172.30.80.10:8081`, and everything else gets the fallback `respond 403`.
  - **No `trusted_proxies`** (V-4), so the last `X-Forwarded-For` entry the server sees is the client.
  - **A comment on TLS.** TLS is the deployer's choice: automatic certificates need a public name, and `tls internal` needs the approver's device to trust Caddy's root.
  - **A comment on reloading.** A config mounted as a single file needs a **restart, not a reload**, after an edit. An editor that saves by writing a new file and renaming it leaves the container's mount on the old inode, so `caddy reload` reads the old content. Mounting the directory instead avoids it.
- **`deploy/caddy/README.md`**: the properties **any** reverse proxy needs, written so nginx and Traefik users can follow it without reading the Caddyfile:
  1. It joins the server's dedicated network (`front` in the reference compose) at a fixed address (`172.30.80.5` there), so the server can trust exactly that address.
  2. It passes on the real client IP in `X-Forwarded-For`, and does not trust a client-sent header, so the entry the server reads is the address the proxy saw.
  3. That fixed address, and only it, is `SHELL_MCP_TRUSTED_PROXIES`. Never the network's gateway, and never a prefix (CLIENTS §1 says why).
  4. The approval host is reachable from the LAN or VPN only. Everything else gets 403 or no answer, and it is never published on all interfaces by accident.

  Each property links the CLIENTS §1 text it comes from. The README ends with CLIENTS §1's log-line procedure as the check every deployer runs once: the server's `authentication failed` line must name the client, not the proxy. It also gives the example Caddyfile as one way to meet the properties.

**Refusals, idempotency, audit:** none (example files).

**Tests** (ci-local and CI):
- **`caddy validate` on the Caddyfile**, in a digest-pinned official `caddy` image that exists only inside the test.
  - **Pin.** The image is pinned in `scripts/caddy-check/Dockerfile`, a `FROM` line at the newest stable release's digest (D-013). Dependabot's `docker` ecosystem tracks it once that directory is listed. It is never referenced from `deploy/` or any doc as something to run.
  - **Container.** Labelled with ci-local's run label, `--network none`, `--read-only` with a `tmpfs` for Caddy's data and config directories, `--cap-drop ALL`, `no-new-privileges`, and as a non-root uid. The Caddyfile is copied in, not mounted.
  - **If not.** S8-4 verifies that `validate` runs that way (V-4). If it needs the network or root, STOP and ask.
- **A drift check.** The Caddyfile's upstream address and ports equal `deploy/docker-compose.yml`'s server address and ports. The README's proxy address equals that file's `SHELL_MCP_TRUSTED_PROXIES` value.
- **Not tested here.** No container runs Caddy as a live proxy. An integration run through it (the CLIENTS §1 check automated) is outside Q7's approval and is deferred (§6).

**Supersedes:** nothing; CLIENTS §1 and `deploy/README.md`'s "Attach the proxy" paragraph point at the README.

### H. The quick start

TARGET-SETUP becomes two parts: **Quick start** (below, about ten steps) and **Reference** (today's §0–§11, unchanged in substance, each step marked "done by `install`" where it is). README's quick start points at it. Draft, for the implementing session to finish once A–G exist:

1. **Server host:** `install -d -o 65532 -g 65532 -m 0700 /srv/shell-mcp/secrets`, then `shell-mcp init` in the image (C) with `--approver`; it prints `ssh_key.pub`.
2. **Target:** verify the release (F, or README "Verifying a release").
3. **Target:** `install` the three binaries (TARGET-SETUP §3).
4. **Target:** write `setup.yaml`; `shell-mcp-gate policy new` (and `shell-mcp-privd policy new` for root actions) (D).
5. **Target:** `shell-mcp-gate install … --key ssh_key.pub` (A); it prints the host-key pin.
6. **Target:** give the write roots and repositories to the service account (TARGET-SETUP §6; an application decision, not automated).
7. **Target, root actions only:** `shell-mcp-privd install --policy /etc/shell-mcp/privileged.yaml`, review, then again with `--accept <sha256>` (B).
8. **Server host:** `shell-mcp init compose --host-key '<pin>' …` (C), and a reverse proxy with the properties in `deploy/caddy/README.md` (G; the example Caddyfile is one way).
9. **Server host:** start the server (`docker compose up -d`, or the stack editor), then `docker compose exec shell-mcp /shell-mcp doctor` (E), and the log-line check (G's README).
10. **Client:** configure it (CLIENTS §4).

Inherent and left as steps: the two policies' content (4), the key's transfer (1→5), write roots (6), the privileged review (7), the proxy and its addresses (8), the client (10).

**Tests:** every command in the quick start runs as written in `scripts/setup-check/` (marked *(container)*) or e2e-host (marked *(real host)*), as S5b marked TARGET-SETUP; a docs check that every `§` reference and relative link resolves (the S5b read-through, scripted).

## 5. Pushback and what is not proposed

- **No interactive wizard for D.** A question-and-answer flow cannot be reviewed before it runs, cannot be kept as the record of why a policy is what it is, and cannot be tested except through a terminal emulator. The answers file is the reviewable artefact; `--out -` shows the result before anything is written.
- **One binary per schema.** A single command writing both policies would make the gate binary (the forced command) link the privileged policy's loader, or one of the two be written unvalidated. Two commands over one answers file keep each binary's imports as they are.
- **No dynamic proxy check in `doctor`.** Telling whether the server sees the real client needs either the server's own log (another process) or a route that reports the caller's address, which would be a new unauthenticated surface on the server. Not proposed. CLIENTS §1's log-line procedure stays the check, and G's README ends with it as the step every deployer runs once. No CI test runs a live proxy (§4.G, §7 Q7).
- **No new helper op for `doctor`.** A side-effect-free op on the broad socket would be a protocol change (version 3, ARCHITECTURE §4.0). `doctor` reports "not probed" instead (decided, §7 Q9).
- **No network fallback in F** (above; decided, §7 Q8).
- **No environment-store output from `init`.** It would print the token and the key to a terminal or a file the operator pastes from; the deploy README's base64 instructions stay for those who need it.
- **No account removal, key revocation or uninstall command.** TARGET-SETUP §11's removal stays manual: removal deletes data (`/var/lib/shell-mcp/backups`), which a tool should not do on a flag. A `keys list` / `keys revoke <fingerprint>` pair is a natural follow-up (§6, deferred).
- **No write-root automation.** Whether `/srv/app/deploy` should become the service account's is an application decision with consequences (TARGET-SETUP §6); `install` reports what `check-policy` warns about.
- **Not built at all:** a `.deb` or other package, a `curl | sh` installer, a web setup UI, any change to the approval flow (the session prompt's exclusions).

## 6. Order and sessions

**Dependencies.** A and B are independent of each other in code; A needs a policy on disk (hand-written or the examples until D exists). C is independent. D's output feeds A and B, and its tests run A and B afterwards, so it follows S8-1. E needs A, B and C to be meaningful end to end but not to build; G is needed by E's container test and H's step 8. H documents everything, so it is last.

All sessions: one PR into `dev`; the docs for the session's commands in its first commit; tests failing first against a stub, the failing commit named in the PR; 60 s fuzz for every parser added; Opus 5.5 at High (D-022: each writes root-run installers or secrets), S8-4's F, G and H parts at Medium if split off. **Common STOP conditions:** any change to a policy schema, the protocol, unit generation or directives, the hash binding, the self-checks or the never and acknowledge lists; any file written outside §4's tables; any use of a setuid binary, `sudo`, `runuser` or a shell; a new dependency (none is needed: `x/crypto/ssh`, `crypto/ed25519` and the standard library cover A–E); a change to `deploy/` hardening flags, or any compose file or image in `deploy/` (G adds two example files only, §7 Q7); an override for the `from=` floor (§7 Q1) or a way to skip the owner scan (§7 Q6); anything that would change gate-only behaviour or add an execx option to run the installers' programs, other than Q13's credential option within its conditions (§7 Q11, Q13), and anything that option would need beyond them; a rule that blocks something TARGET-SETUP prescribes. **Every session** also checks its defaults, presets, examples and docs against §3.9 (any deployer) and says so in the PR body.

### S8-1: `shell-mcp-gate install`, `host-key`, `shell-mcp-privd install`, and the container harness (A+B)
- **Includes:** §3's shared rules (the write helper with read-back, the audit record, dry-run, the `Host` interfaces), A and B as specified, `scripts/setup-check/` with its ci-local step and CI job (F-13), e2e-host cases with the `svc-install` account, the `check-policy` function shared by `check-policy` and `install` (no behaviour change, proven by the existing tests passing unchanged), `units`' printed next steps (F-2); the temp-name pattern documented (§3.2, §7 Q10); the wording changes of §7 Q12 (TARGET-SETUP §4 `usermod -L`, PRIVILEGED §2 "group with an explicit gid"); **first, in its own commit with its own failing-first tests, execx's credential option** (§7 Q13; §4.A, "The credential option"), before the step that uses it.
- **Acceptance:** on each of Debian 13, Ubuntu 24.04 and Ubuntu 26.04 in `scripts/setup-check/`, a fresh image goes from nothing to a working SSH round trip with `install` alone after the binaries and a policy are in place; a second run reports only `unchanged`; `--dry-run` leaves the filesystem identical; every refusal in §4.A and §4.B has a failing-first unit test and, where buildable, a container case; on e2e-host, `privd install` takes a policy edit from `helper_policy_mismatch` to serving, and removes the broad pair when it is dropped; the files written are byte-identical to what TARGET-SETUP §4, §7, §8 and §9.2 produce by hand (a test compares them); no failed run leaves a temp file behind (unit and container tests, §3.2); the `from=` floor has no override and `/23` and `/63` are refused (test); every supplementary group outside §7 Q5's two is refused by name; the owner scan runs before `useradd`, cannot be skipped, and a narrowed scan WARNs and is in the audit line; `privd install` stops for review without `--accept` on every run, re-runs included; on e2e-host the runner's `sshd_config.d` and `authorized_keys.d` are as they were before the test (checked after cleanup); the credential option meets every condition of §7 Q13: it is in its own commit before its use; it is refused in a non-root process before anything starts; the trampoline's existing checks run first, as root, and the child's ids, groups and capabilities are verified before the exec; no capability and no group 0 remain; the existing execx and gate tests pass untouched; and the call-site test shows step 4 as its only caller. `serve`'s dispatch is unchanged (test); ci-local and CI green, the new `setup-check` job included.

### S8-2: `shell-mcp init` and `init compose` (C)
- **Includes:** V-1 verified first; C as specified; the compose template embedded from `deploy/docker-compose.yml` with the equality test; the image path tested as 65532 with no network and no capabilities.
- **Acceptance:** the in-image run with the one documented host command produces a directory the reference compose starts from, in both forms; a second run changes no byte; no secret appears on any output (test); every refusal tested failing first; `deploy/docker-compose.yml` unchanged; CLIENTS §3.2 and `deploy/README.md` point at `init`, with the manual path kept.

### S8-3: `policy new` in both binaries (D)
- **Includes:** the answers schema (documented in POLICY.md as an input format, explicitly not a policy schema change) and its strict decoder with a fuzz target; the three presets; rendering from `examples/` with the byte-for-byte test; the strict-load-before-write rule; the acknowledge refusal.
- **Acceptance:** `examples/` reproduced from their answers files byte for byte; D → A → B in `scripts/setup-check/` ends with both `check-policy` runs ok (Landlock best-effort where the kernel lacks ABI 4) and B's `--gate-policy` cross-check passing; no generated policy is ever written without loading strictly (test with an answers file the loader refuses); every refusal tested failing first.

### S8-4: `doctor`, `verify-release.sh`, `deploy/caddy/`, the quick start (E+F+G+H)
- **Includes:** V-3 and V-4 verified first; E, F, G and H as specified; G's `caddy validate` test in a test-only pinned image and its drift check (§4.G); H's restructuring of TARGET-SETUP and README, every command marked and run as S5b did, the scripted link check.
- **Acceptance:** `doctor` reports each helper failure with its remedy in e2e-host and FAILs on a trusted gateway in the container test; `verify-release.sh` passes against a real release's files in the release workflow and refuses each tampered case in its test; `caddy validate` and G's drift check green, with no compose file or image added to `deploy/` and no live-proxy container in any test; G's README states the four proxy properties in terms any proxy can follow; the quick start has at most ten steps, each run as written; TARGET-SETUP's reference part keeps every step it has today.

**Deferred (not scheduled):** `shell-mcp-gate keys list` / `keys revoke`; an uninstall command; an automated live-proxy test (the CLIENTS §1 check through a running proxy), which needs the maintainer's approval beyond §7 Q7; a side-effect-free broad-socket op is **not** deferred but declined (§7 Q9); non-Debian service names (`sshd.service` without the `ssh` alias) for targets beyond D-018's tested distributions.

## 7. Questions for the maintainer: decided 2026-11-01

Each question is kept as asked, and the maintainer's decision follows it. Q13 arose from Q11's decision and was decided the same day.

1. **`from=` floor.** Refuse IPv4 prefixes shorter than /24 and IPv6 shorter than /64 (proposed), or require single addresses (/32, /128) and refuse every prefix? The server on the target itself has a fixed `/32` on the Docker network, so a single address always works with the reference compose.
   **Decided:** a hard limit with no override. IPv4 prefixes no shorter than /24, IPv6 no shorter than /64; no flag, variable or file lowers it. Anything wider than a single address is accepted with a WARN that suggests /32 or /128 (§4.A).
2. **Containers as their own root.** `scripts/setup-check/` runs `useradd`, `sshd` and the installers as the container's root, unprivileged and with Docker's default capabilities, none added, no host mount but the repository read-only (CLAUDE.md's container rule is kept; ci-local's other containers run as a non-root user). Approve, and the new CI job?
   **Decided:** approved, including the new CI job (§3.8).
3. **e2e-host and the runner's sshd.** May the e2e test write `/etc/ssh/sshd_config.d/60-shell-mcp.conf` for the test account and reload the runner VM's own `ssh.service` (disposable, the block reaches only that account), or should A's reload be covered only in containers and the existing dedicated test sshd stay the only one e2e touches?
   **Decided:** approved, limited to the test account's `Match` block (and its keys file), which the test removes afterwards (§3.8, §4.A).
4. **`--accept <sha256>` on every `privd install`** (proposed: the operator's review is bound to the bytes installed, and every edit is reviewed again), or only when the policy has REVIEW items or the broad unit?
   **Decided:** `--accept <sha256>` on every `privd install` (§4.B).
5. **Other supplementary groups:** refuse (D-020 says "nothing else"; proposed) or WARN?
   **Decided:** refuse, naming the group. Allowed: the socket group, plus `systemd-journal` only when the policy has a `journal` section (§4.A).
6. **The owner scan:** mandatory on account creation over every local filesystem (proposed), or bounded (by time, or to filesystems the operator names) for very large hosts?
   **Decided:** mandatory by default. `--owner-scan-paths <list>` narrows it, prints a WARN and is recorded in the audit line. No flag skips the scan (§4.A).
7. **Caddy:** a digest-pinned official `caddy` image as a new image dependency (Dependabot `docker` then tracks it), and the proxy container's hardening (non-root with `NET_BIND_SERVICE`, or a high port inside), since these are new `deploy/` flags.
   **Decided:** `deploy/caddy/` ships no compose file and adds no image to `deploy/`. It holds an example Caddyfile and a README listing the properties any reverse proxy needs. CI may run `caddy validate` in a digest-pinned `caddy` image inside the test only, and nothing ships to users. The proxy-hardening half of the question falls away (§4.G, §6 S8-4).
8. **F's scope:** cosign or `gh` required, `--sums` for an offline target, no network fallback (proposed)?
   **Decided:** as proposed. cosign or `gh` required, `--sums` for offline targets, no network fallback (§4.F).
9. **The broad socket in `doctor`:** accept "not probed" for policies whose only broad use is `unit: broad` commands (proposed), or schedule a side-effect-free op for the next protocol version?
   **Decided:** accept "not probed"; no protocol change. The side-effect-free op is declined, not deferred (§4.E, §6).
10. **Transient temp files** (`.<name>.shell-mcp-<random>`, same directory, removed on failure) next to each prescribed file, for atomic writes: within "the files TARGET-SETUP prescribes"?
    **Decided:** yes, within scope. The temp-name pattern is documented, and tests show that a failed run leaves none behind (§3.2).
11. **Process execution in the installers:** through `internal/gate/execx` as the gate does (its rlimits and trampoline), or a smaller execve wrapper for root-run setup programs in the same package?
    **Decided:** use `internal/gate/execx`. STOP and ask if that would require changing gate-only behaviour (§3.1, §6). Q13 arose from this decision and settles its one exception, the credential option.
12. **Wording:** TARGET-SETUP's reference part to use `usermod -L` instead of `passwd -l` (F-1), and PRIVILEGED §2's "system group" to say "group with an explicit gid" (F-5)?
    **Decided:** yes to both wording changes, made in S8-1's docs commit (F-1, F-5, §6).
13. **(Arose from Q11.) How does A run `check-policy` as the service account?** §3.1 has A re-execute its own binary as the account's uid, gid and groups.
    - **The conflict.** execx starts every program through its trampoline, and the trampoline refuses to run when its control socket's peer runs as another user (`trampolineRefusal`: "fd 3's peer runs as another user"). A root installer that switches the child to the account's uid therefore meets that refusal, and execx has no credential field today.
    - **The options.** (a) An execx option that switches credentials only after the trampoline's checks, which changes execx (shared with the gate). (b) Running this one step outside execx, against Q11. (c) Doing the account's identity checks in-process, as root, by computing what the account can reach from ownership, modes and groups, which duplicates `check-policy`'s logic and can drift from it.
    - **Proposed:** (a). The option would be off for every existing caller, with a test that the gate's and the helper's specs never set it. That is still a change to a gate package, so under Q11 it is the maintainer's call.
    - **Meanwhile.** S8-1 asks before building that step and builds everything else first.

    **Decided:** option (a), with these conditions, which §4.A ("The credential option") states in full:
    - **Off by default.** The switch is an execx option that no existing caller sets. The existing execx and gate tests pass untouched.
    - **Root only.** It is honoured only when the calling process runs as uid 0. In any other process it is refused with a clear error before anything starts, never silently ignored.
    - **Checks first, as root.** The trampoline runs all its current checks before it switches.
    - **The switch, in this order.** `setgroups` to exactly the account's supplementary groups as read from `/etc/group`, then `setgid`, then `setuid`. The trampoline then verifies that the real, effective and saved uid and gid, and the group list, match the account exactly, and refuses to run the command otherwise.
    - **After the switch.** The command keeps no capabilities, `no_new_privs` is set before the exec, and rlimits and descriptor handling are those of every other execx command.
    - **One caller.** The only caller is A's check-policy step, running the installed `shell-mcp-gate` as the service account. Nothing in `serve`, the helper or the server may set the option, and a call-site test enforces it.
    - **Tests, each failing first:** non-root refused; the child's uid, gid and groups exactly the account's, with no leftover root group; a missing account or group refused before the exec; existing callers unchanged.
    - **Built first.** S8-1 builds the option first, in its own commit with its own tests, before the step that uses it. **STOP and ask if it needs anything beyond these conditions.**

## 8. What was read and checked

Read: CLAUDE.md; after the decisions, `internal/gate/execx` (`Spec`, `childLimits`, `trampolineRefusal`) for Q11 and Q13, and `deploy/docker-compose.yml`'s service and container names for V-3; plan.md (D-001 to D-022, F-12, F-13, F-15, O-01, O-02); `docs/ARCHITECTURE.md` in full (D-016, D-017, D-020 through plan.md §2; §2 components, §3, §5); `docs/TARGET-SETUP.md` in full; `docs/PRIVILEGED.md` §2, §3, §4, §5 (5.1 to 5.3), §7, §8; `docs/CLIENTS.md` §1–§3; `docs/SECURITY.md` §5–§6; `deploy/README.md`, `deploy/docker-compose.yml`; `cmd/shell-mcp-gate/main.go`, `cmd/shell-mcp-privd/main.go`, `cmd/shell-mcp/main.go`, `cmd/shell-mcp/approver.go`; `internal/gate/install/install.go` (`DeniedGroups`), `internal/gate/audit/audit.go` (the record and the sink), `internal/privd/units/units.go` (paths, the generated marker), `internal/approval/approvers/file.go` (temp file and rename), `internal/tools/deps.go` (`Probe`); `test/e2e/setup.sh` (accounts, the dedicated sshd, the units), `test/e2e/runner/runner.go`, `scripts/exposure/`, `scripts/probe/systemd.sh`, `scripts/ci-local.sh`'s labelling; ARCHIVE §14 from 2026-10-25 (S5b and its follow-ups, the 0.1.0 release, the post-release scope) and the 0.2.0 entries; `docs/handoff/S4C-PRIVILEGED.md` as the model for this document.

Run: the container probes for F-1, F-7, F-10 and F-11 (§2), on the three images pinned in `scripts/exposure/Dockerfile`, each `--rm`, labelled, unprivileged, with `no-new-privileges` and no host mount; none was left behind (listed by label afterwards).
