# S8 handoff: setup tooling

> Session S8-scope, 2026-11-01. Documentation only: no code, test, workflow or other non-doc file changes in this PR.
> It scopes eight items (A–H) that move what `docs/TARGET-SETUP.md`, `deploy/README.md` and `docs/CLIENTS.md` §3.2 already prescribe into idempotent subcommands, and splits them into four implementation sessions.
> **Status: proposed, awaiting the maintainer.** Nothing here is decided until §7's questions are answered. No locked decision, schema, protocol, unit directive or hash binding changes in this proposal; where an item would need one, it says so and proposes not to build that part (§5).
> Every name below is a placeholder, as in TARGET-SETUP: the service account `svc-shell` (uid/gid 60123), the socket group `svc-shell-priv` (gid 60124), the server at `192.0.2.10`, `target-a.example.test`, `mcp.example.test`, `approve.example.test`, the proxy network `172.30.80.0/24`.

## 0. Summary

**The problem.** The binaries check and generate pieces of an install but never install them, so a deployer transcribes TARGET-SETUP by hand. The steps transcribed most often are also the ones where a typo weakens the install and nothing fails: a key line without `restrict`, a `from=` that is a whole /16, a secret owned by the wrong uid, a privileged policy edited without regenerating its units.

**The rule for every item.** A subcommand writes exactly the files TARGET-SETUP (or `deploy/README.md`, CLIENTS §3.2) already prescribes, with the same owner and mode, and refuses every case that today only a careful reader would catch. No security property changes: same files, same modes, same refusals, plus refusals for the typos. Nothing uses `sudo` or a setuid binary, nothing is piped from the network into a shell, nothing trusts a value read from the network.

**The proposed CLI surface.**

| Item | Command | Runs on | As |
|---|---|---|---|
| A | `shell-mcp-gate install --policy <file> --principal <label> --from <addr>[,<addr>] --key <file.pub> --user <name> --uid <n> --gid <n> [--socket-group <name> --socket-gid <n>] [--memory-max <size>] [--dry-run] [--no-reload] [--replace-key]` | target | root |
| A | `shell-mcp-gate host-key` | target | any |
| B | `shell-mcp-privd install --policy <file> [--accept <sha256>] [--gate-policy <file>]… [--dry-run] [--no-start]` | target | root |
| C | `shell-mcp init --dir <dir> [--uid 65532 --gid 65532] [--approver <name>] [--dry-run]` | server host or the image | root, or the uid itself |
| C | `shell-mcp init compose --dir <dir> --form secrets\|bind --image <ref@sha256:…> --host-key <pin> --target-host … [--approve-host …]` | server host or the image | any |
| D | `shell-mcp-gate policy new --answers <file> --out <file>\|-` and `shell-mcp-privd policy new --answers <file> --out <file>\|-` | target | root |
| E | `shell-mcp doctor [--json] [--mcp-url <url>] [--ca-file <file>]` (`check` unchanged) | inside the server container | 65532 |
| F | `verify-release.sh <version> [--sums <verified SHA256SUMS>]` in the repository and the examples archive | workstation or target | any |
| G | `deploy/caddy/Caddyfile`, `deploy/caddy/docker-compose.yml`, `deploy/caddy/README.md` | server host | — |
| H | A ten-step quick start in `docs/TARGET-SETUP.md` (and README), the current guide kept as its reference part | — | — |

**Pushback, in short (§5).** D is an answers file, not an interactive wizard, and each binary writes its own policy. E's dynamic proxy check (did the server see the real client?) cannot be done without a new unauthenticated route, so `doctor` checks it statically and keeps the log-line procedure; and the broad helper socket cannot be probed for a policy whose only broad use is `unit: broad` commands without a protocol change, which is not proposed. F cannot verify a release without cosign or `gh`: hashing a download against what the attestations API returns over TLS proves only that GitHub served the same bytes twice, so the fallback is `sha256sum` against a `SHA256SUMS` verified elsewhere, never against the network. `init` never prints or stores a secret in an environment-store form.

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

- **F-1. `passwd -l` is a setuid binary; the tools may not run it.** `/usr/bin/passwd` is `4755 root` on all three images. TARGET-SETUP §4 and SECURITY §5 step 1 tell a human to run it, which is fine; CLAUDE.md forbids our code to invoke any setuid binary. `usermod -L` (`0755`, not setuid) gives the same result: after `useradd` the shadow field is already `!` on all three, it stays `!` after `usermod -L`, and `passwd -S` reports `L`. **A uses `usermod -L`**, and H's quick start says so. SECURITY §5 step 1's wording can stay (it describes the locked state); TARGET-SETUP's reference part keeps `passwd -l` for the hand-run path or switches to `usermod -L` (§7 Q12).
- **F-2. `units` prints next steps that differ from TARGET-SETUP §9.2.** `cmd/shell-mcp-privd/main.go` (`unitsWith`) prints `daemon-reload` before `systemd-analyze verify`, without `--man=no`, and names only `/var/lib/shell-mcp/backups` (TARGET-SETUP creates `/var/lib/shell-mcp` 0700 as well). Harmless; B replaces the sequence, and the printed text then points at `install`.
- **F-3. `units` writes in place and never removes the broad pair.** It uses `os.WriteFile` on the final path, which truncates an existing unit before writing it, so a failure part-way leaves a mixed set pinned to two hashes; and when a policy stops using the broad unit it prints "remove … if installed" and leaves the old pair (and an enabled socket) in place. Both fail closed (the helper refuses with `helper_policy_mismatch` or `helper_install_insecure`), but B must write each file by temp file and rename, and must disable and remove the broad pair it generated.
- **F-4. The example policies say to run `check-policy` without saying as whom**; TARGET-SETUP §5 runs it as the service account through `runuser`, so the identity checks describe that account. A runs it that way itself (§4.A, without `runuser`).
- **F-5. PRIVILEGED §2 calls the socket group "system group"**; TARGET-SETUP creates it with an explicit gid (`groupadd --gid 60124`, not `--system`), as D-020's pinned ids want. Wording only (§7 Q12).
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
- **V-3 (S8-4).** That `docker compose run` of the reference service fails while the server runs, because the service has a fixed `ipv4_address` (which is why `doctor` is run with `docker exec`).
- **V-4 (S8-4).** Caddy's `reverse_proxy` header behaviour (that it replaces a client's `X-Forwarded-For` unless `trusted_proxies` is set, and appends the peer otherwise) and the matcher syntax, from the Caddy documentation of the pinned version.

## 3. Rules every subcommand follows

### 3.1 Root, and nothing else
- **A, B and D's writes refuse unless the effective uid is 0**, and refuse when `SSH_ORIGINAL_COMMAND` is set (they are never reachable as a forced command, even by a key line that names them). `serve` is unchanged; a test asserts that the forced command's dispatch reaches only `serve`.
- **No `sudo`, `su`, `pkexec`, `runuser` or setuid binary.** Running a check as the service account (A) is a re-execution of the running binary with `SysProcAttr.Credential` set to that account's uid, gid and groups and a scrubbed environment: dropping privileges, not gaining them.
- **No shell.** Every external program is run by absolute path, chain-checked like a policy command (`policy.CheckChain`: root-owned, not group/other-writable, every directory above), with a fixed argv in which every value that came from a flag sits after a fixed option and has passed a validator that forbids a leading `-` (names `^[a-z_][a-z0-9_-]{0,31}$`, ids as decimal integers). The programs are exactly: `/usr/sbin/groupadd`, `/usr/sbin/useradd`, `/usr/sbin/usermod`, `/usr/sbin/sshd` (`-t`, `-T -C`), `/usr/bin/systemctl`, `/usr/bin/systemd-analyze`. On Ubuntu 26.04 none of them is a uutils multi-call binary (they are shadow-utils, OpenSSH and systemd). They are run through `internal/gate/execx` (the gate binary's only process path) with its limits; whether that suits a root installer, or a smaller execve wrapper in the same package is better, is §7 Q11.
- **No network.** Nothing in A, B, C or D opens a socket other than `/dev/log` and, for B, systemd's own through `systemctl`. E is the only item that makes a request, and only when run.

### 3.2 Files: three idempotency classes
Every file an item writes is in exactly one class, named in its table:

| Class | Absent | Present, identical | Present, different |
|---|---|---|---|
| **Owned** (content is a pure function of the flags) | written | left alone, reported `unchanged` | **refused**, with a unified diff of what is there and what would be written; never overwritten. The operator removes the file (or reverts the edit) and runs again. |
| **Generated** (the helper's units: carry `# Generated by shell-mcp-privd units`) | written | left alone | replaced, only when the existing file carries the marker; a unit without it (hand-written) is refused |
| **Line-keyed** (`authorized_keys.d/<user>`, keyed by the key's SHA-256 fingerprint) | file written with the line | line left alone | the same key with other options: refused unless `--replace-key`, which rewrites that one line; a line A did not write that fails A's checks: refused (§4.A) |
| **Secret** (C's token, key, approvers) | generated | validated and kept; never regenerated, never re-moded | refused if its owner, mode or format is wrong, with the fix to run; never repaired silently |

Writes are temp file in the same directory, `fsync`, `chmod`/`chown` on the descriptor, `rename`, `fsync` of the directory, then **read back and compared by SHA-256** (the project's read-back rule): a mismatch is a failure. Temp files are named `.<target>.shell-mcp-<random>` (a name systemd, sshd and polkit ignore) and removed on any failure. Whether these transient names count as writing outside the prescribed files is §7 Q10.

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
- D in `internal/gate/policy/gen` and `internal/privd/policy/gen`, each emitting its own schema; no gate package imports a privd package or the reverse (as today).
- E in `cmd/shell-mcp` and `internal/tools` (a `ProbeHelper` beside `Probe`).

### 3.8 How everything is tested
Three layers, each with tests committed first and run failing against a **stub** subcommand (one that parses its flags, prints nothing and exits 0), the failing run named in the PR:
1. **Unit tests** (`go test -race`, linux build tag where the code has one, `t.TempDir()`): the planner with a fake `Host`, every refusal as a table case, every file's exact content as a golden file, every audit line, and a fuzz target for each parser added (the `from=` list, the key-line parser, the answers file), each run 60 s.
2. **`scripts/setup-check/`** (new, S8-1; F-13): on `scripts/exposure`'s model, one image per supported target (`debian:trixie-slim`, `ubuntu:24.04`, `ubuntu:26.04`, by digest) with `openssh-server`, `passwd`, `systemd` (for `systemd-analyze verify`, no PID 1), `polkitd`, `acl` and `git`; the release binaries built from the commit copied in (`docker cp`, no host mount beyond the repository read-only); labelled with ci-local's run label and removed by it. Inside, as the container's root, **unprivileged, no added capabilities**, it runs the *(container)* steps through the new subcommands: `install` on a fresh image, again (all `unchanged`), with each refusal's input, `--dry-run` with the filesystem snapshot, an `sshd -D` started in the container and a real SSH round trip (`shell-mcp check` from a second container on a labelled network against a `best-effort` test policy, as S5b did, since CI kernels may lack ABI 4). Runs in `scripts/ci-local.sh` and as a CI job. That containers run as their own root is §7 Q2.
3. **e2e-host** (the runner VM, `test/e2e`, behind the runner guard): what needs a running systemd, polkit, journald and a real `ssh.service`: the slice drop-in in force (`systemctl show`), `install`'s reload, `privd install`'s `daemon-reload`, `enable --now`, a policy edit followed by `install` again (no `helper_policy_mismatch` afterwards, and one before it), the broad pair removed when the policy drops it, the syslog audit lines, and `doctor` against the runner's server, gate and helper. A separate test account (`svc-install`, uid 4200005, in setup.sh's documented test range) so the existing e2e account is untouched; whether the test may write the runner's own `sshd_config.d` and reload its `ssh.service` is §7 Q3.

## 4. The items

### A. `shell-mcp-gate install`

**Flags.** `--policy <file>` (required; absolute, clean, characters `[A-Za-z0-9._/-]` only, F-8; must exist, root-owned and load as `serve` would load it), `--principal <label>` (required; `^[a-z][a-z0-9-]{0,31}$`), `--from <addr>[,<addr>…]` (required; at most 8 entries), `--key <file.pub>` (required), `--user <name>` (default `svc-shell`), `--uid <n>` and `--gid <n>` (required: never a default, D-020), `--home <dir>` (default `/var/lib/<user>`), `--socket-group <name>` and `--socket-gid <n>` (required exactly when the policy has `privileged.enabled: true`), `--memory-max <size>` (default `4G`, as TARGET-SETUP §4; `none` omits the slice drop-in, with a WARN), `--dry-run`, `--no-reload` (write and check everything, print the reload to run; for hosts where the operator reloads sshd themselves, and the container harness), `--replace-key`.

**What it does, in order.**
1. **Checks before any write:** root (§3.1); every binary it will run (§3.1) and its own binary chain (`/usr/local/bin/shell-mcp-gate`, root-owned, as `install.Check` requires); Landlock (`sandbox.KernelABI` against the policy's mode: a FAIL under `required` stops here); the policy loads (`policy.Load` with `ServiceHome` = `--home`); the key file (below); the `from=` list (below); `sshd -T` (no `-C`) reports `strictmodes yes`; the existing account, groups and files (below).
2. **Groups and account** (`groupadd --gid`, `useradd --uid --gid --home-dir --create-home --shell /bin/sh`, `usermod -L` (F-1), `usermod -aG` for `systemd-journal` when the policy has a `journal` section and for the socket group when it has `privileged.enabled`), then the owner scan (below).
3. **Slice drop-in**, `systemctl daemon-reload`, `systemctl show -p MemoryMax -p MemorySwapMax user-<uid>.slice` must show the values.
4. **`check-policy` as the account** (§3.1): its output is printed; a FAIL stops here, before anything sshd reads exists.
5. **polkit rule**, when the policy has `services.control` (TARGET-SETUP §8; added to A because it is a prescribed file and is regenerated by the same edit; the prompt's list did not name it).
6. **sshd drop-in**, then the **keys directory and the key line**, last.
7. **`sshd -t`**, then `sshd -T -C user=<user>,host=client.example.test,addr=<first from address>` must show every value of the `Match` block (`authorizedkeysfile /etc/ssh/authorized_keys.d/%u`, `authenticationmethods publickey`, `passwordauthentication no`, `kbdinteractiveauthentication no`, `permittty no`, `allowtcpforwarding no`, `allowstreamlocalforwarding no`, `allowagentforwarding no`, `x11forwarding no`, `permittunnel no`, `permituserrc no`, `maxsessions 8`), and `sshd -T -C user=<a name that is not an account>,…` must show none of the account's values for `authorizedkeysfile`, `permittty` and `x11forwarding` (the block must not reach other accounts). Any difference: rollback (§3.4). This replaces checking for `Include` (F-10).
8. **Reload** (F-7), unless `--no-reload`.
9. **Prints** `SHELL_MCP_TARGET_HOST_KEYS=ssh-ed25519 SHA256:…` (from `/etc/ssh/ssh_host_ed25519_key.pub`, read locally and fingerprinted with `x/crypto/ssh`, never `ssh-keyscan`), the other host-key types as extra pins, "keep this session open until a new login works", and the write roots that `check-policy` warned about (TARGET-SETUP §6 stays the operator's).

`shell-mcp-gate host-key` prints step 9's lines alone, as any user (the `.pub` files are world-readable), for re-pinning without re-running install.

**Files.**

| Path | Owner, mode | Class | Notes |
|---|---|---|---|
| `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` | — | — | written only by `groupadd`, `useradd`, `usermod`; never by our code |
| `<home>` (default `/var/lib/svc-shell`) | `svc-shell:svc-shell`, `useradd`'s default mode | — | created by `useradd --create-home`; refused if it exists and is not the account's |
| `/etc/systemd/system/user-<uid>.slice.d/` | `root:root 0755` | owned (directory) | |
| `/etc/systemd/system/user-<uid>.slice.d/50-shell-mcp.conf` | `root:root 0644` | owned | `[Slice]\nMemoryMax=<size>\nMemorySwapMax=0\n` after a header comment naming the command |
| `/etc/polkit-1/rules.d/60-shell-mcp.rules` | `root:root 0644` | owned | `polkit.Rule` output, only with `services.control`; the directory (`root:polkitd 0750`) must exist, it is never created |
| `/etc/ssh/sshd_config.d/60-shell-mcp.conf` | `root:root 0644` | owned | exactly TARGET-SETUP §7's block for `--user`, after a header comment; one service account per host (a file for another user is refused) |
| `/etc/ssh/authorized_keys.d/` | `root:root 0755` | owned (directory) | `/etc/ssh` must be `root:root`, not group/other-writable |
| `/etc/ssh/authorized_keys.d/<user>` | `root:root 0644` | line-keyed | one line per key: `restrict,from="<list>",command="/usr/local/bin/shell-mcp-gate serve --policy <file> --principal <label>" ssh-ed25519 <base64> shell-mcp-<label>` |
| `/etc/shell-mcp/<policy>` | — | read only | must exist; written by D or by hand |
| `/etc/ssh/ssh_host_*_key.pub` | — | read only | |

**Refusals** (each a table test, each a container case where it can be built there):
- `from=`: empty; any entry that is not an IP address or a canonical CIDR prefix (`netip.ParsePrefix`, host bits refused, as `SHELL_MCP_TRUSTED_PROXIES` is); wildcards (`*`, `?`); negations (`!`); host names (they make sshd consult DNS when `UseDNS` is on, which trusts the network); an IPv4 prefix shorter than /24 or an IPv6 prefix shorter than /64 (the floor is §7 Q1; the recommendation printed is the server's own /32, which a fixed Docker address gives when the server runs on the target); more than 8 entries; duplicates.
- The key file: not exactly one line; options before the key type; a type other than `ssh-ed25519` (D-012); a body that does not parse; a file that begins with a private-key header (refused without printing any of it, and the message says the `.pub` file is wanted); a key equal to one of the host's own host keys.
- The key line already present: same fingerprint, other options, without `--replace-key`. **Every existing line** of the keys file must parse and pass the same checks (`restrict` present, `from=` within the rules, `command=` exactly `/usr/local/bin/shell-mcp-gate serve --policy <path> [--principal <label>]` with both values in the safe character sets, an Ed25519 key); any line that does not is reported with its number (never its key) and the run is refused, since the file A manages would otherwise hold a line that weakens it. Comments and blank lines are kept.
- `--policy` or `--principal` outside their character sets (F-8); the policy fails to load; `check-policy` as the account reports FAIL.
- Account: `--uid` or `--gid` 0, 65534, in systemd's dynamic range 61184–65519, or below 1000; the uid or gid used by another name; an existing account whose uid, primary gid, home or shell differ from the flags; a member of any group in `install.DeniedGroups` (F-6); a member of any supplementary group other than `systemd-journal` and the socket group (D-020 "nothing else"; refuse or WARN is §7 Q5); a shell that is `nologin` or `false`, or missing.
- The owner scan finds any inode owned by the uid or the gid (when the account is created in this run): every local filesystem from `/proc/self/mountinfo` is walked (pseudo and network filesystems skipped and listed), stopping at the first hit, which is reported; no flag skips it (§7 Q6 asks whether it should be bounded on very large hosts).
- `--socket-gid` used by another group; the socket group exists with another gid; `--socket-group` or `--socket-gid` given for a policy without `privileged.enabled`, or missing for one with it.
- sshd: `strictmodes no`; `/etc/ssh`, the keys directory or the keys file not `root:root` or group/other-writable (TARGET-SETUP §7's `stat` check, which `StrictModes` alone does not cover, ARCHIVE S5b F-1); `sshd -t` fails; the effective configuration differs (step 7); a `60-shell-mcp.conf` for another user.
- `SSH_ORIGINAL_COMMAND` set; not root; a binary that fails its chain check.

**Idempotency.** Account and groups: created when absent, `unchanged` when they match, refused when they differ (above). Files per §3.2. A second run with the same flags changes nothing and reports every item `unchanged`; a run with a second `--key`/`--principal` appends one line. The reload runs only when the drop-in or the keys file changed (sshd reads the keys file on every login, so a new key needs no reload; the drop-in does).

**Audit.** §3.5: one line per account, group, membership, file and key line created or replaced, one per refusal; the policy's SHA-256 and the key's fingerprint, never the key.

**Tests** (stub first; each must fail against it):
- Unit: the refusal table above, one case per bullet; golden files for the drop-in, the slice drop-in and the key line; the key-line parser and the `from=` parser fuzzed (60 s each); the planner's order (the key line after everything else); rollback restores the previous bytes when the fake `sshd -T` disagrees; the audit lines.
- `scripts/setup-check/` on the three images: a fresh install, then a second run (every item `unchanged`); `--dry-run` with no filesystem difference; each refusal that a container can build (an account in `docker`, a uid in use, a world-writable keys file, `StrictModes no` in an earlier drop-in, a `Match User` in an earlier drop-in that wins, a hand-added key line without `restrict`, a `/16`, a policy path with a space); then the SSH round trip: the gate's `hello` answers, no shell without a command, no PTY, `shell-mcp check` verifies the printed pin and refuses a wrong one.
- e2e-host: the slice drop-in in force; the reload of the runner's `ssh.service` and a login after it (§7 Q3); the polkit rule letting exactly the listed verb; the syslog lines (`journalctl -t shell-mcp-gate`).

**Supersedes.** TARGET-SETUP §4 (account, groups, slice), §7 (the drop-in, the keys file, the `StrictModes`/`stat` checks, reload, the host key) and §8 (the polkit rule), which move to the reference part (H); `deploy/README.md`'s "Install `secrets/ssh_key.pub` on the target …" and pinning paragraph (it points at `install`'s printed pin). SECURITY §5 steps 1–3, 6 and 8 stay normative and unchanged: A implements them.

### B. `shell-mcp-privd install`

**Flags.** `--policy <file>` (required), `--accept <sha256>` (the policy's SHA-256, required to write anything: §7 Q4), `--gate-policy <file>` (repeatable, optional: cross-checks each), `--dry-run`, `--no-start` (write and verify the units, skip `daemon-reload`, `enable` and restarts; for images and the container harness).

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

**Idempotency.** Same policy, second run: nothing written, no reload, sockets confirmed enabled and active, every item `unchanged`. Edited policy: `--accept` with the new hash, then only what changed is written and reloaded. The generated class means a unit file is only ever replaced by `install` (or `units`), never one written by hand.

**What does not change.** Unit generation, the directives, the hash binding and the self-checks are exactly today's (`units.Core`, `units.Broad`, PRIVILEGED §5, §7). B calls them; it does not alter them. Any need to change them is a STOP.

**Audit.** §3.5, tag `shell-mcp-privd`: the accepted hash, every unit written, replaced or removed with its SHA-256, the store directories, each `enable`, restart and disable, and each refusal (the review stop included, at notice).

**Tests** (stub first):
- Unit: the refusal table; the review stop (exit 3, nothing written) and the hash bound to the bytes read (a policy changed between two reads cannot be installed with the first hash: the test swaps the file after the check through the fake `Host`); an unchanged policy writes nothing; a policy that drops the broad unit produces the disable and the removal; a hand-written unit is refused; rollback when the fake `verify` fails.
- `scripts/setup-check/` (`--no-start`, no PID 1): the units written are byte-identical to `units --out`'s for the example policy and the e2e policies; `systemd-analyze verify` runs on the three images; a second run writes nothing.
- e2e-host: `install` from a clean runner (the e2e setup's own units removed first, or a second policy whose units it then restores), the sockets active with the right modes, a privileged read through the real server; then an edit of the policy without `install` gives `helper_policy_mismatch`, and `install --accept <new hash>` clears it; the broad pair removed and its socket gone after the policy drops packages; the syslog lines.

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

**Why a new command, and `check` unchanged.** `check` (F-12) has a JSON output that scripts read, and it only connects to targets. `doctor` runs everything `check` does and then checks that make requests `check` should not make silently (the approval URL, the MCP URL through the proxy). It prints `ok`/`WARN`/`FAIL` lines, `--json` gives the same as one object, and it exits 1 on any FAIL. It runs inside the running server's container, `docker exec shell-mcp /shell-mcp doctor`, so it sees the same environment and mounts (V-3: `compose run` would collide on the fixed address).

**Checks.**
- **Configuration:** `config.Load` as `serve` (every startup refusal), its warnings, and each secret file's owner and mode (a group/other-readable file is a FAIL here, a WARN at startup).
- **Per target, from `check`:** the pin verified, SSH authentication, `hello` (version, protocol, principal, policy SHA-256, `max_tier`, sandbox mode, Landlock ABI and whether it is applied).
- **Helper sockets** (a `ProbeHelper` next to `tools.Probe`, every request at ceiling `read`): when `hello` reports privileged forwarding, `priv_policy` through the core socket: the helper's version, its policy SHA-256 and `unit: core`; the codes mapped to remedies: `helper_unavailable` (socket not enabled: run `shell-mcp-privd install`), `helper_refused` (the peer check: `client_uid` or the socket group), `helper_policy_mismatch` (units not regenerated: `install` again), `protocol_mismatch` (upgrade). The broad socket only through a read op that changes nothing: `priv_pkg_update_index_preview` when the summary says `allow_update_index`, else `priv_power_preview` with an allowed action when power is allowed (the broad unit logs everything it serves at WARN, which the output says), else **"broad socket not probed: this policy has no read operation on it"** (§5, §7 Q9).
- **Trusted proxies, statically** (CLIENTS §1): each `SHELL_MCP_TRUSTED_PROXIES` entry is a single address (a prefix is a WARN); none contains the container's default gateway (read from `/proc/net/route` and `/proc/net/ipv6_route`; containing it is a FAIL, with CLIENTS §1's reason); each is on a directly connected subnet of the container (`net.Interfaces`; otherwise a WARN); and the line that the dynamic check is still the log-line procedure of CLIENTS §1.
- **The approval page**, under `web`: `GET` of `SHELL_MCP_APPROVAL_PUBLIC_URL` from inside the container, no proxy variables, no redirects followed, system roots or `--ca-file`: reachable, the certificate valid for the host and its expiry, and the response carrying the page's own headers (`Content-Security-Policy` with `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Cache-Control: no-store`), which tells our page from another service answering on that name. What it cannot show (that the page is unreachable from outside the LAN or VPN) is said.
- **The MCP endpoint**, with `--mcp-url`: one `POST` without a token must answer `401` with `WWW-Authenticate: Bearer realm="shell-mcp"` (a request without a token does not count toward the lockout, ARCHITECTURE §3), and a `421` says the name is missing from `SHELL_MCP_ALLOWED_HOSTS`.

**Files.** Reads only: the configuration, the mounted secrets (mode and owner, and loading them as `serve` does), `/proc/net/route`, `/proc/net/ipv6_route`, `--ca-file`. Writes nothing.

**Refusals and audit.** None of its own beyond `check`'s; the gate and the helper log its read requests under the server key's principal, which is the evidence it ran.

**Tests** (stub first): unit tests with an in-process SSH server and gate stub (the pattern `cmd/shell-mcp` tests already use) for each helper code and its remedy, the broad probe's three cases, the gateway detection against fixture route tables, the proxy entry rules, the approval page with an `httptest` TLS server (right headers, wrong headers, bad certificate, redirect not followed), the MCP probe (401, 421). Container (ci-local): the image on a labelled network with a proxy container (G's Caddy), `doctor` run with `docker exec`, then again with the gateway put in `SHELL_MCP_TRUSTED_PROXIES` (FAIL). e2e-host: against the runner's server, gate and both helper units (a policy with `allow_update_index`), and after a policy edit without `install` (`helper_policy_mismatch` and its remedy).

**Supersedes.** TARGET-SETUP §10's `shell-mcp check` (doctor first; `check` stays for scripts), and the static half of CLIENTS §1's "Set the value from what the server logs".

### F. `verify-release.sh`

**What it does.** `scripts/verify-release.sh <version> [--dir <dir>] [--sums <file>]`, POSIX `sh`, also in the examples archive, run as any user (never root needed, never `sudo`), downloading nothing itself unless asked: it verifies the files present in `--dir`.
- **With `cosign`** (or `gh`): `sha256sum --strict -c SHA256SUMS` for the files present (every present file other than the bundles must be listed), `cosign verify-blob` of each binary, the archive and `SHA256SUMS` against `--certificate-identity https://github.com/tyler-rich/shell-mcp/.github/workflows/release-build.yml@refs/tags/v<version>` and the GitHub OIDC issuer, and, with `gh`, `gh attestation verify … --signer-workflow … --source-ref refs/tags/v<version>` for the listed files. The same commands as README "Verifying a release" and `scripts/release/verify.sh`, which it shares a test with, so they cannot diverge.
- **Without either** (a target without cosign): `--sums <file>`, a `SHA256SUMS` the operator already verified with cosign elsewhere and copied over; the script checks the files against it and says plainly that the signature was checked elsewhere. With neither cosign, `gh` nor `--sums`, it refuses and prints how to get one.

**Pushback (§5).** The prompt's fallback, "curl + sha256sum against the GitHub attestations API", is not verification: the API returns a Sigstore bundle, and comparing a digest with what it holds without checking the bundle's certificate chain, transparency-log entry and identity only proves that GitHub's API and GitHub's release storage agree, over the same TLS channel the download came through. Doing that check properly in shell means reimplementing Sigstore verification with `openssl`, which is not a script anyone should trust. And a script inside the archive it verifies is circular: the root of trust stays the README's commands, run once, with cosign.

**Files.** Reads the files in `--dir`; writes nothing. **Refusals:** a missing tool and no `--sums`; a file present but not listed; any check failing (exit 1, naming the file). **Audit:** none (a user tool). **Tests** (stub first): a `sh` test (`scripts/verify-release_test.sh`, like `scripts/release/release_test.sh`) with fake `cosign` and `gh` on `PATH` in a temp directory that record their argv and fail on demand: the identity is the tag's, never a branch's; a tampered file fails `sha256sum`; an unlisted file fails; no tool and no `--sums` refuses; shellcheck clean. The real verification runs in the release workflow after signing (`verify.sh` already does; the job gains one run of `verify-release.sh` against the files just signed).

**Supersedes.** TARGET-SETUP §2's commands (kept in the reference part and in README "Verifying a release", which stays the root of trust).

### G. `deploy/caddy/`

**Files** (new; nothing in `deploy/docker-compose.yml` changes):
- `deploy/caddy/Caddyfile`: `mcp.example.test` → `reverse_proxy 172.30.80.10:8080`; `approve.example.test` → a `remote_ip` matcher for the LAN and VPN ranges (`192.0.2.0/24`, `198.51.100.0/24` as placeholders) handled by `reverse_proxy 172.30.80.10:8081`, everything else `respond 403` (or `abort`); TLS at the proxy (`tls internal` with the note that the approver's device must trust that root, or the operator's own certificate files); no `trusted_proxies` (V-4), so the server's `X-Forwarded-For` last entry is the client.
- `deploy/caddy/docker-compose.yml`: the Caddy service on the existing `front` network as an external network (`deploy_front`), at `ipv4_address: 172.30.80.5`, the only published ports, bound to a LAN or VPN address (`192.0.2.20:443:443`), never `0.0.0.0` by accident; the image pinned by digest; the Caddyfile and data mounted from a directory, not a single file; its own hardening (§7 Q7: non-root with `cap_add: [NET_BIND_SERVICE]`, or a high port inside, `read_only` with a data volume, `cap_drop: ALL`, `no-new-privileges`, limits).
- `deploy/caddy/README.md`: why two members and fixed addresses (CLIENTS §1), the matcher, and **why the mount is a directory**: an editor that saves a single bind-mounted file by writing a new file and renaming it leaves the container's mount on the old inode, so `caddy reload` reads the old content; with a single-file mount, restart the container instead of reloading.

**Refusals, idempotency, audit:** none (example files). **Tests:** in ci-local and CI, `caddy validate` on the Caddyfile in the pinned image; `docker compose config` of both compose files together; an integration run on labelled networks: the server image behind this proxy, a client container inside the matcher's range reaches the approval page and one outside gets 403, and the server's `authentication failed` line names the client container, not the proxy (the CLIENTS §1 procedure, automated; it is the dynamic check `doctor` cannot do, done once in CI against the example). **Supersedes:** nothing; CLIENTS §1 and `deploy/README.md`'s "Attach the proxy" paragraph point at it.

### H. The quick start

TARGET-SETUP becomes two parts: **Quick start** (below, about ten steps) and **Reference** (today's §0–§11, unchanged in substance, each step marked "done by `install`" where it is). README's quick start points at it. Draft, for the implementing session to finish once A–G exist:

1. **Server host:** `install -d -o 65532 -g 65532 -m 0700 /srv/shell-mcp/secrets`, then `shell-mcp init` in the image (C) with `--approver`; it prints `ssh_key.pub`.
2. **Target:** verify the release (F, or README "Verifying a release").
3. **Target:** `install` the three binaries (TARGET-SETUP §3).
4. **Target:** write `setup.yaml`; `shell-mcp-gate policy new` (and `shell-mcp-privd policy new` for root actions) (D).
5. **Target:** `shell-mcp-gate install … --key ssh_key.pub` (A); it prints the host-key pin.
6. **Target:** give the write roots and repositories to the service account (TARGET-SETUP §6; an application decision, not automated).
7. **Target, root actions only:** `shell-mcp-privd install --policy /etc/shell-mcp/privileged.yaml`, review, then again with `--accept <sha256>` (B).
8. **Server host:** `shell-mcp init compose --host-key '<pin>' …` (C) and the proxy from `deploy/caddy/` (G).
9. **Server host:** `docker compose up -d` for both; `docker exec shell-mcp /shell-mcp doctor` (E).
10. **Client:** configure it (CLIENTS §4).

Inherent and left as steps: the two policies' content (4), the key's transfer (1→5), write roots (6), the privileged review (7), the proxy and its addresses (8), the client (10).

**Tests:** every command in the quick start runs as written in `scripts/setup-check/` (marked *(container)*) or e2e-host (marked *(real host)*), as S5b marked TARGET-SETUP; a docs check that every `§` reference and relative link resolves (the S5b read-through, scripted).

## 5. Pushback and what is not proposed

- **No interactive wizard for D.** A question-and-answer flow cannot be reviewed before it runs, cannot be kept as the record of why a policy is what it is, and cannot be tested except through a terminal emulator. The answers file is the reviewable artefact; `--out -` shows the result before anything is written.
- **One binary per schema.** A single command writing both policies would make the gate binary (the forced command) link the privileged policy's loader, or one of the two be written unvalidated. Two commands over one answers file keep each binary's imports as they are.
- **No dynamic proxy check in `doctor`.** Telling whether the server sees the real client needs either the server's own log (another process) or a route that reports the caller's address, which would be a new unauthenticated surface on the server. Not proposed; G's CI test automates the check once for the example, and CLIENTS §1's procedure stays for real deployments.
- **No new helper op for `doctor`.** A side-effect-free op on the broad socket would be a protocol change (version 3, ARCHITECTURE §4.0). `doctor` reports "not probed" instead (§7 Q9).
- **No network fallback in F** (above).
- **No environment-store output from `init`.** It would print the token and the key to a terminal or a file the operator pastes from; the deploy README's base64 instructions stay for those who need it.
- **No account removal, key revocation or uninstall command.** TARGET-SETUP §11's removal stays manual: removal deletes data (`/var/lib/shell-mcp/backups`), which a tool should not do on a flag. A `keys list` / `keys revoke <fingerprint>` pair is a natural follow-up (§6, deferred).
- **No write-root automation.** Whether `/srv/app/deploy` should become the service account's is an application decision with consequences (TARGET-SETUP §6); `install` reports what `check-policy` warns about.
- **Not built at all:** a `.deb` or other package, a `curl | sh` installer, a web setup UI, any change to the approval flow (the session prompt's exclusions).

## 6. Order and sessions

**Dependencies.** A and B are independent of each other in code; A needs a policy on disk (hand-written or the examples until D exists). C is independent. D's output feeds A and B, and its tests run A and B afterwards, so it follows S8-1. E needs A, B and C to be meaningful end to end but not to build; G is needed by E's container test and H's step 8. H documents everything, so it is last.

All sessions: one PR into `dev`; the docs for the session's commands in its first commit; tests failing first against a stub, the failing commit named in the PR; 60 s fuzz for every parser added; Opus 5.5 at High (D-022: each writes root-run installers or secrets), S8-4's F, G and H parts at Medium if split off. **Common STOP conditions:** any change to a policy schema, the protocol, unit generation or directives, the hash binding, the self-checks or the never and acknowledge lists; any file written outside §4's tables; any use of a setuid binary, `sudo`, `runuser` or a shell; a new dependency (none is needed: `x/crypto/ssh`, `crypto/ed25519` and the standard library cover A–E); a change to `deploy/` hardening flags (G adds files only); a rule that blocks something TARGET-SETUP prescribes.

### S8-1: `shell-mcp-gate install`, `host-key`, `shell-mcp-privd install`, and the container harness (A+B)
- **Includes:** §3's shared rules (the write helper with read-back, the audit record, dry-run, the `Host` interfaces), A and B as specified, `scripts/setup-check/` with its ci-local step and CI job (F-13), e2e-host cases with the `svc-install` account, the `check-policy` function shared by `check-policy` and `install` (no behaviour change, proven by the existing tests passing unchanged), `units`' printed next steps (F-2).
- **Acceptance:** on each of Debian 13, Ubuntu 24.04 and Ubuntu 26.04 in `scripts/setup-check/`, a fresh image goes from nothing to a working SSH round trip with `install` alone after the binaries and a policy are in place; a second run reports only `unchanged`; `--dry-run` leaves the filesystem identical; every refusal in §4.A and §4.B has a failing-first unit test and, where buildable, a container case; on e2e-host, `privd install` takes a policy edit from `helper_policy_mismatch` to serving, and removes the broad pair when it is dropped; the files written are byte-identical to what TARGET-SETUP §4, §7, §8 and §9.2 produce by hand (a test compares them); `serve`'s dispatch is unchanged (test); ci-local and CI green.

### S8-2: `shell-mcp init` and `init compose` (C)
- **Includes:** V-1 verified first; C as specified; the compose template embedded from `deploy/docker-compose.yml` with the equality test; the image path tested as 65532 with no network and no capabilities.
- **Acceptance:** the in-image run with the one documented host command produces a directory the reference compose starts from, in both forms; a second run changes no byte; no secret appears on any output (test); every refusal tested failing first; `deploy/docker-compose.yml` unchanged; CLIENTS §3.2 and `deploy/README.md` point at `init`, with the manual path kept.

### S8-3: `policy new` in both binaries (D)
- **Includes:** the answers schema (documented in POLICY.md as an input format, explicitly not a policy schema change) and its strict decoder with a fuzz target; the three presets; rendering from `examples/` with the byte-for-byte test; the strict-load-before-write rule; the acknowledge refusal.
- **Acceptance:** `examples/` reproduced from their answers files byte for byte; D → A → B in `scripts/setup-check/` ends with both `check-policy` runs ok (Landlock best-effort where the kernel lacks ABI 4) and B's `--gate-policy` cross-check passing; no generated policy is ever written without loading strictly (test with an answers file the loader refuses); every refusal tested failing first.

### S8-4: `doctor`, `verify-release.sh`, `deploy/caddy/`, the quick start (E+F+G+H)
- **Includes:** V-3 and V-4 verified first; E, F, G and H as specified; G's CI integration test; H's restructuring of TARGET-SETUP and README, every command marked and run as S5b did, the scripted link check.
- **Acceptance:** `doctor` reports each helper failure with its remedy in e2e-host and FAILs on a trusted gateway in the container test; `verify-release.sh` passes against a real release's files in the release workflow and refuses each tampered case in its test; `caddy validate` and G's integration test green; the quick start has at most ten steps, each run as written; TARGET-SETUP's reference part keeps every step it has today.

**Deferred (not scheduled):** `shell-mcp-gate keys list` / `keys revoke`; an uninstall command; a side-effect-free broad-socket op (protocol version 3) if Q9 asks for one; non-Debian service names (`sshd.service` without the `ssh` alias) for targets beyond D-018's tested distributions.

## 7. Questions for the maintainer

1. **`from=` floor.** Refuse IPv4 prefixes shorter than /24 and IPv6 shorter than /64 (proposed), or require single addresses (/32, /128) and refuse every prefix? The server on the target itself has a fixed `/32` on the Docker network, so a single address always works with the reference compose.
2. **Containers as their own root.** `scripts/setup-check/` runs `useradd`, `sshd` and the installers as the container's root, unprivileged and with Docker's default capabilities, none added, no host mount but the repository read-only (CLAUDE.md's container rule is kept; ci-local's other containers run as a non-root user). Approve, and the new CI job?
3. **e2e-host and the runner's sshd.** May the e2e test write `/etc/ssh/sshd_config.d/60-shell-mcp.conf` for the test account and reload the runner VM's own `ssh.service` (disposable, the block reaches only that account), or should A's reload be covered only in containers and the existing dedicated test sshd stay the only one e2e touches?
4. **`--accept <sha256>` on every `privd install`** (proposed: the operator's review is bound to the bytes installed, and every edit is reviewed again), or only when the policy has REVIEW items or the broad unit?
5. **Other supplementary groups:** refuse (D-020 says "nothing else"; proposed) or WARN?
6. **The owner scan:** mandatory on account creation over every local filesystem (proposed), or bounded (by time, or to filesystems the operator names) for very large hosts?
7. **Caddy:** a digest-pinned official `caddy` image as a new image dependency (Dependabot `docker` then tracks it), and the proxy container's hardening (non-root with `NET_BIND_SERVICE`, or a high port inside), since these are new `deploy/` flags.
8. **F's scope:** cosign or `gh` required, `--sums` for an offline target, no network fallback (proposed)?
9. **The broad socket in `doctor`:** accept "not probed" for policies whose only broad use is `unit: broad` commands (proposed), or schedule a side-effect-free op for the next protocol version?
10. **Transient temp files** (`.<name>.shell-mcp-<random>`, same directory, removed on failure) next to each prescribed file, for atomic writes: within "the files TARGET-SETUP prescribes"?
11. **Process execution in the installers:** through `internal/gate/execx` as the gate does (its rlimits and trampoline), or a smaller execve wrapper for root-run setup programs in the same package?
12. **Wording:** TARGET-SETUP's reference part to use `usermod -L` instead of `passwd -l` (F-1), and PRIVILEGED §2's "system group" to say "group with an explicit gid" (F-5)?

## 8. What was read and checked

Read: CLAUDE.md; plan.md (D-001 to D-022, F-12, F-13, F-15, O-01, O-02); `docs/ARCHITECTURE.md` in full (D-016, D-017, D-020 through plan.md §2; §2 components, §3, §5); `docs/TARGET-SETUP.md` in full; `docs/PRIVILEGED.md` §2, §3, §4, §5 (5.1 to 5.3), §7, §8; `docs/CLIENTS.md` §1–§3; `docs/SECURITY.md` §5–§6; `deploy/README.md`, `deploy/docker-compose.yml`; `cmd/shell-mcp-gate/main.go`, `cmd/shell-mcp-privd/main.go`, `cmd/shell-mcp/main.go`, `cmd/shell-mcp/approver.go`; `internal/gate/install/install.go` (`DeniedGroups`), `internal/gate/audit/audit.go` (the record and the sink), `internal/privd/units/units.go` (paths, the generated marker), `internal/approval/approvers/file.go` (temp file and rename), `internal/tools/deps.go` (`Probe`); `test/e2e/setup.sh` (accounts, the dedicated sshd, the units), `test/e2e/runner/runner.go`, `scripts/exposure/`, `scripts/probe/systemd.sh`, `scripts/ci-local.sh`'s labelling; ARCHIVE §14 from 2026-10-25 (S5b and its follow-ups, the 0.1.0 release, the post-release scope) and the 0.2.0 entries; `docs/handoff/S4C-PRIVILEGED.md` as the model for this document.

Run: the container probes for F-1, F-7, F-10 and F-11 (§2), on the three images pinned in `scripts/exposure/Dockerfile`, each `--rm`, labelled, unprivileged, with `no-new-privileges` and no host mount; none was left behind (listed by label afterwards).
