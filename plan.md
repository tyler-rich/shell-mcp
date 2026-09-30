# shell-mcp — Project Plan

> Status: **planning complete, no code yet.** Last updated 2026-09-27.
> Read `CLAUDE.md` first, then this file, then `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/POLICY.md` and `docs/PRIVILEGED.md`.

## 1. What this is

A **security-first MCP (Model Context Protocol) server that gives AI clients bounded, audited access to Linux hosts over SSH**. It covers the host-level work that container managers (DockHand, Portainer, Komodo…) cannot — reading **and changing** the host: systemd services, the journal, host configuration files (including root-owned ones), ownership and permissions, packages, disk/memory/process inspection, TLS certificate checks, git-based deployments on the host, and any extra commands the host owner declares, as the service user or as root.

It is **not a remote shell**. There is no shell, no PTY, no interpreter, no free-form argv. Every operation is either a built-in structured operation or a command whose exact argument shapes are declared in a root-owned policy file on the target host.

Design goals, in priority order:

1. **Nothing happens on a host that the host's owner did not declare.** Authorization lives on the target, root-owned, and is enforced there — not in the MCP server, which is an internet-adjacent process holding credentials.
2. **Confinement enforced by the kernel, not only by our code.** Every operation and every child process runs under a Landlock sandbox derived from the policy, with `no_new_privs` set. A bug in our path matcher must not be enough to escape.
3. **Root capability without an escalation path.** No sudo, no setuid, no shell, no interpreter, no free-form argv. Root actions are *requested* from a separate privileged helper that decides against its own root-owned policy inside its own systemd sandbox; restarting declared services uses a generated polkit rule.
4. **A human approves consequential actions.** The model cannot approve on its own: destructive operations and every root-level change require a user answer collected by the client through MCP elicitation, bound cryptographically to the exact operation.
5. **Full capability, explicitly enabled.** Every use case — reads, writes, service control, destructive and root operations — ships in v1. What a deployment can do is set by the server profile and each host's policies; a fresh install starts read-only until the operator turns capability on.
6. **Generic, deployable anywhere Docker runs, connectable by any MCP client**, public from the first commit, every dependency on its newest stable release.

## 1.1 Approach, from requirements

The job is host-level work that container managers (DockHand, Portainer, Komodo…) cannot do: systemd services and the journal, host configuration files, disk/memory/process inspection, certificate expiry, git-based deployments on the host, and a small set of operator-declared extra commands. The server must run in a container and reach one or more hosts.

**Architectures considered**

| Option | Verdict | Why |
|---|---|---|
| **Container MCP server → SSH → forced-command gate on each host** | **Chosen** | SSH is already present, audited and hardened on every Linux host; key options (`restrict`, `from=`, `command=`) bind each key to one policy; no new listening service; the gate runs per request and exits, so there is no daemon to compromise. |
| Long-running agent on each host (HTTP/mTLS/gRPC) | Rejected | A new network listener and credential store per host, a daemon holding privileges between requests, and its own update channel — all things SSH already solves. |
| Docker socket, privileged container, or `nsenter` into the host | Rejected | Root-equivalent by construction. Any bug in the server becomes host root. |
| Configuration-management backends (Ansible, Salt API) as the executor | Rejected | Run as root, execute arbitrary modules and templates, and have a large attack surface; "safe playbook" is not a boundary. |
| Cockpit bridge / generic remote shell | Rejected | Full host access by design; policy would live only in the MCP server. |
| systemd D-Bus over SSH (`systemctl -H`) | Partial | Good for units, nothing else. We use D-Bus + polkit for service control *inside* the gate instead. |
| Root via sudo from the gate (even with generated rules) | Rejected | Sudo needs setuid, which the gate's `no_new_privs` sandbox blocks — so the gate would run unsandboxed; sudoers matches argv text; the command runs as unconfined root. |
| **Root via a socket-activated privileged helper** | **Chosen for root actions** | The gate stays sandboxed and only asks; the helper authenticates the caller by kernel peer credentials, applies its own typed policy, and runs under a systemd sandbox with only the capabilities and write paths the policy needs (docs/PRIVILEGED.md). |
| Local Unix socket + socket-activated service (same host only) | Rejected for v1 | Attractive for the local case, but a second transport doubles the audited surface; SSH covers local and remote uniformly. |

**Execution model inside the gate.** Built-in *native* operations (implemented in Go: file read/write/list/find, system info, disk, processes, certificate parsing) are preferred over running binaries, because a binary brings its own escape hatches — GTFOBins (gtfobins.github.io) catalogues hundreds. Where a binary is unavoidable (`systemctl`, `journalctl`, `git`), the gate builds a fixed argv with hardening flags. Anything else must be declared by the host owner as an **argv template** with typed placeholders; there is no way to pass a free flag. Common "ssh MCP" designs expose `execute_command(string)` through a login shell; that model cannot be made safe and is explicitly not this one.

**Why kernel enforcement as well as policy checks.** Path confinement in userspace (`os.Root`, real-path re-checks) is necessary but is our code. Landlock lets the unprivileged gate restrict its own filesystem, TCP and IPC access *and that of every child it starts*, with rules computed from the same policy, before it reads the untrusted request. A mistake in our matcher, or an escape hatch in a declared binary, then hits a kernel wall.

**Why a helper for root.** Root is sometimes the job: editing a root-owned config, `chown`, installing a package, running a root-only tool. Doing that through sudo would require turning the gate's sandbox off. A separate, one-request-per-connection root process with its own policy and systemd sandbox gives the same capability with a far smaller blast radius, and needs no sudoers file at all.

**Why human approval through the protocol.** A `confirm: true` argument is chosen by the model — a prompt-injected model sets it too. MCP 2026-07-28 lets a server return `input_required` with an elicitation request; the client asks the user and retries with the answer (Multi Round-Trip Requests). Binding that round trip to the exact operation with an HMAC makes approval a property of the human, not the token.

## 2. Locked decisions (change only via a STOP-and-ask + ARCHIVE §14 entry)

| ID | Decision | Rationale |
|---|---|---|
| D-001 | **Language: Go — always the latest stable Go release (1.27 as of 2026-09), official MCP Go SDK (`github.com/modelcontextprotocol/go-sdk`), `golang.org/x/crypto/ssh` for the SSH client, `golang.org/x/sys/unix` for Linux primitives, `github.com/landlock-lsm/go-landlock` for the kernel sandbox.** `go.mod`'s `go` and `toolchain` lines track the latest stable release; there is no backwards-compatibility window. Three static binaries from one module: `shell-mcp` (the MCP server, runs in a container), `shell-mcp-gate` (runs on each target as an SSH forced command) and `shell-mcp-privd` (the privileged helper, socket-activated by systemd on each target that needs root actions). | The gate and helper must run on arbitrary Linux hosts with **no interpreter dependency** — a Python implementation would be tied to each host's system Python and force a compatibility window, which D-013 forbids. Go gives static binaries, `os.Root` (traversal- and symlink-escape-resistant file access in the stdlib), process-wide Landlock and `no_new_privs` from pure Go, a mature SSH client with explicit host-key callbacks, a `distroless/static` image with no shell or interpreter, and `govulncheck` (reachability-aware). The official Go SDK supports MCP 2026-07-28 from v1.7.0. |
| D-002 | **Two-gate architecture.** MCP client → (bearer, HTTPS via reverse proxy) → `shell-mcp` in a container → (SSH, pinned host key, dedicated Ed25519 key) → `shell-mcp-gate` as the key's forced command on the target. The **gate is authoritative**; the server's profile only controls what is advertised. | A prompt-injected model, a stolen MCP bearer token, or a compromised server container can do at most what the target policy allows for that key — the policy is the real boundary, and it lives root-owned on the host. |
| D-003 | **No shell, ever.** No `sh -c`, no PTY, no interpreter, no port/agent/X11 forwarding, no free-form argv. Commands are `execve`'d from absolute, root-owned paths with a scrubbed environment. Shells, interpreters, pagers, editors, privilege changers (including `sudo`) and namespace tools are on a **built-in, non-removable hard-deny list** (docs/POLICY.md §5). | Shell metacharacters, interpreters and GTFOBins escapes are the whole attack surface of a "shell MCP". Removing them structurally beats filtering them. |
| D-004 | **Authentication is required on the MCP endpoint before any response**, including discovery and `tools/list`. `none` exists only for stdio and for loopback-bound HTTP with `SHELL_MCP_ALLOW_UNAUTHENTICATED=true`. | Unauthenticated tool enumeration is a documented, mass-exploited MCP weakness. |
| D-005 | **Tool exposure is governed by a server-side profile: `read-only` (default) < `operator` < `admin`.** Tools outside the profile are not registered (invisible to `tools/list`), not merely rejected. Privileged (`shell_priv_*`) tools are registered only in `admin`. The gate and the helper independently enforce their policies' `max_tier`. | Least privilege at every layer; a client cannot discover or elevate to what the operator did not enable. The default is only a starting point — `admin` is the intended profile for a fully capable deployment. |
| D-006 | **Consequential operations require human approval collected by the client through MCP elicitation** (Multi Round-Trip Requests, MCP 2026-07-28), never a model-supplied argument. Always approval-gated: every destructive operation and every privileged (`priv_*`) operation of tier operator or above. `SHELL_MCP_APPROVAL_TIERS` (default `destructive`) can add ordinary operator writes. The first call returns `input_required` with a computed preview in the elicitation message and an HMAC-bound `requestState` (principal, tool, target, SHA-256 of the canonical arguments and of the preview, expiry ≤ `SHELL_MCP_APPROVAL_TTL`, single-use nonce, per-process key); the retry executes only if the user accepted and the state verifies. Clients that do not declare elicitation support get `approval_unavailable` (fail closed); `SHELL_MCP_APPROVAL_FALLBACK=confirm-argument` is an explicit, logged-at-WARN opt-out for such clients. MCP annotations and `title` are set on every tool. | A `confirm: true` parameter is chosen by the model, so a prompt-injected model approves itself. Elicitation puts the decision in front of the human through the client's own UI, and the binding stops an approval for one operation being replayed for another. Approval defends against a misled model, not a compromised server — that case is bounded by the host policies (docs/PRIVILEGED.md §3). |
| D-007 | **The excluded set is permanent** (`docs/SECURITY.md` §4, `docs/PRIVILEGED.md` §5.3 list A). No profile, policy, flag or fork of this project exposes: interactive shells/PTYs, interpreters, forwarding/tunnels, credential reads (private keys, `shadow`), identity and access administration (users, groups, passwords, sudoers, PAM, SSH server config and keys, polkit rules), or this project's own trust anchors (policies, binaries, units, sockets). Power, kernel, storage, firewall and persistence-area writes are *not* excluded but are helper-only and require an explicit `acknowledge` in the privileged policy. | Credential material, self-escalation and self-modification are how an agent turns bounded access into unbounded access. Everything else a root operator legitimately does is declarable. |
| D-008 | **Tool names are `shell_<verb>_<noun>`; privileged tools are `shell_priv_<verb>_<noun>`, snake_case.** Descriptions are terse, contain no hostnames/IPs/paths/unit names, and never reference other tools. | Namespace safety next to other servers; root actions are unmistakable in client approval prompts; descriptions are injected into model context and are an injection surface. |
| D-009 | **Structured JSON logging; never log file contents, command output, stdin, environment values, tokens or keys.** The gate writes its own audit line per request to syslog/journald on the target. | SIEM-friendly; a second audit trail on the host that the container cannot erase. |
| D-010 | **Branching mirrors the maintainer's other projects: `main` is the default and release branch; all work lands on `dev` via squash-merged PRs; only `dev → main` release PRs (merge commits, so `main` always contains `dev`'s history) touch `main`.** One PR per concern. Sessions never merge. | Standing workflow. |
| D-011 | **Every merged behaviour change gets a dated entry in `docs/ARCHIVE.md` §14.** | Institutional memory for sessions and the public changelog. |
| D-012 | **SSH trust is pinned, never learned.** Every target has a pinned host-key fingerprint (`SHA256:…`) or a `known_hosts` entry; no trust-on-first-use, no `InsecureIgnoreHostKey`, no agent, no password or keyboard-interactive auth. Client keys are Ed25519. | Host-key verification is the difference between "SSH" and "send commands to whoever answers". |
| D-013 | **Latest-everything policy.** The Go toolchain, every module dependency, every base image, every GitHub Action and every CI tool is pinned to the **newest stable release available when the change is made**, and CI fails when anything falls behind: a `deps-current` job fails if `go list -m -u` reports an available update for any `go.mod` requirement or any module that provides a package to `go list -deps -test ./...` (modules present only because a dependency's own `go.mod` requires them are reported but cannot fail the job: `go mod tidy` removes any pin for them), if any direct requirement has a stable next major version on the module proxy (`<path>/vN+1`, or `/v2` for v0/v1 modules; pre-release-only next majors are reported), if the golangci-lint or govulncheck version pinned in CI and `scripts/ci-local.sh` is older than its newest stable release, or if `go.mod`'s `go`/`toolchain` lines are older than the newest stable Go on go.dev; Dependabot runs **daily** for `gomod`, `github-actions` and `docker`; every session starts by refreshing dependencies and records the resulting versions in its ARCHIVE entry; base images are pinned by digest; Actions are pinned to the SHA of their newest release. Pre-releases (alpha/beta/rc) are never used. | The maintainer's standing rule: no outdated packages or dependencies at all. Making it a CI gate means it is enforced rather than remembered. |
| D-014 | **MCP protocol revision 2026-07-28** (stateless: no initialize handshake, no session IDs), via the Go SDK's stateless Streamable HTTP mode. Clients still on 2025-11-25 must keep working through the SDK's negotiation; Session 2 verifies both. | Current revision; stateless fits a server with no per-client state. |
| D-015 | **Apache-2.0, copyright holder `tyler-rich`, public from the first commit.** Root `SECURITY.md` with private vulnerability reporting; no deployment-specific detail may ever enter the repository, commit messages, PR bodies or issues (CLAUDE.md "Public-repo hygiene"). | Public from day one means hygiene is a hard rule, not a launch checklist. |
| D-016 | **The host policies are the security boundary and are out of the service user's reach.** The gate policy, the privileged policy, both binaries, the helper's units and the service user's `authorized_keys` are root-owned and not writable by group/other (gate and helper refuse to run otherwise). No write root — gate or helper — may contain or overlap them. Each SSH key's `command=` selects its own gate policy (`--policy`), so different server instances get different ceilings. | If the confined user, or the helper acting for it, can edit its own confinement, it is not confinement. |
| D-017 | **No sudo, no setuid, no sudoers — anywhere.** Unit start/stop/restart/reload for declared units uses `systemctl` as the service user, authorized by a polkit rule that `shell-mcp-gate polkit` generates (exact units × verbs). Every other root action goes through the privileged helper (D-021). | Sudo on a non-interactive service account is a standing escalation path whose rules match argv strings, and it is incompatible with the gate's `no_new_privs` sandbox. |
| D-018 | **v1 targets are Linux with systemd, amd64 and arm64.** | The gate relies on Linux primitives (`os.Root` semantics, `/proc/self/fd` re-checks, `prctl(PR_SET_NO_NEW_PRIVS)`, process groups, `Pdeathsig`). macOS/BSD targets are a later scoping item. |
| D-019 | **Kernel sandbox is mandatory.** Before reading the request, the gate sets `no_new_privs` and applies a Landlock ruleset computed from the policy to all its threads (inherited by every child): read/execute on system directories needed to run the declared binaries, read on read roots, read/write on write roots, nothing else; TCP connect only to ports the policy lists (git remotes), no TCP bind; signal and abstract-socket scoping where the kernel ABI supports it. Policy `sandbox: required` (default) makes the gate refuse to serve without Landlock; `best-effort` must be set explicitly and is reported by `hello` and `check`. | Userspace confinement is our code; Landlock is the kernel's. Applying it before any untrusted input is parsed means a parser bug or a declared binary's escape hatch still cannot reach outside the policy. |
| D-020 | **The service account is minimal and pinned.** The operator chooses an explicit UID/GID (setup docs never rely on `useradd --system` auto-allocation, and tell the operator to check the chosen UID owns no files on the host). Supplementary groups: `systemd-journal` when journal ops are enabled, and the helper's socket group when privileged ops are enabled — nothing else. The gate refuses to serve (`install_insecure`) if its process has uid 0, or belongs to `root`, `sudo`, `wheel`, `adm`, `docker`, `lxd`, `incus-admin`, `libvirt`, `kvm`, `disk`, or `shadow`. | Auto-allocated system UIDs can collide with UIDs that already own container data on the host. Group membership is invisible privilege — `docker` alone is root-equivalent — so the gate checks it at runtime rather than trusting the setup. |
| D-021 | **Root actions go through `shell-mcp-privd`, a socket-activated privileged helper** (docs/PRIVILEGED.md, normative). The gate forwards `priv_*` requests over a local Unix socket (`root:<socket group> 0660`); systemd starts one helper instance per connection (`Accept=yes`); the helper requires the peer UID to equal its policy's `client_uid` (`SO_PEERCRED`), validates against its own root-owned privileged policy, and runs inside a generated systemd sandbox — the **core** unit (`ProtectSystem=strict`, write access only to declared paths, a four-capability bounding set, no network) or, for package management and commands declared `unit: broad`, the **broad** unit (network, full root, flagged root-equivalent). Units are generated from the policy and pinned to its SHA-256; the helper refuses to serve when they diverge. Overwritten and deleted files are backed up first. | Root capability for every use case without sudo, without a root shell, and without dropping the gate's sandbox. The helper can do only what the privileged policy declares, and systemd enforces its write paths and capabilities independently of our code. |
| D-022 | **Model recommendation: Opus 5.5 at High for every security-critical session; Medium for scaffold and packaging.** Fable 5.1 is not used. | Fable 5.1 is the higher tier but carries additional cybersecurity safeguards; these sessions write sandbox-escape, symlink-race and privilege-boundary tests against the project's own code, which is where those safeguards can interrupt work. Tests-first prompts and High effort on Opus 5.5 cover the risk. |

## 3. Non-goals (v1)

- Being a general remote shell. (If a task needs a shell, the answer is a console.)
- Container management — use a DockHand/Portainer MCP. `docker` is allowed only as a declared command with explicit `root_equivalent: true` acknowledgement, and no built-in tool wraps it.
- Package managers other than apt (dnf, zypper, apk, pacman) — later.
- Multi-tenant principal mapping (one MCP bearer token → one profile per server instance; run another instance with another key and policy for another ceiling).
- Streaming (`journalctl -f`, `tail -f`). Tools return bounded snapshots.
- OAuth / Claude.ai custom connectors (deferred; shell access should not be internet-exposed — see §6).
- Windows or macOS targets.

## 4. Requirements

### 4.1 Functional

| # | Requirement |
|---|---|
| F-01 | Streamable HTTP transport at `POST /mcp` (stateless, JSON responses), plus `serve --transport stdio`. |
| F-02 | Unauthenticated `GET /healthz` returning exactly `200 {"status":"ok"}` — no version, no target reachability, no config. `shell-mcp healthcheck` subcommand for the container `HEALTHCHECK` (distroless has no shell or curl). |
| F-03 | Configuration via environment variables (with `*_FILE` variants for secrets) and an optional targets file. Validated at startup with actionable one-line errors; the process refuses to start on an insecure combination (SECURITY §6). |
| F-04 | Server profiles `read-only` / `operator` / `admin` (D-005), plus `SHELL_MCP_DISABLE_TOOLS` to remove individual tools. No allow-list can add a tool above the profile. |
| F-05 | Targets: one or more named SSH targets, each with host, port, user, pinned host key(s) and key file. Every tool takes `target` (optional when exactly one target exists or a default is configured). |
| F-06 | Gate protocol: one versioned JSON request per SSH session on stdin, one JSON response on stdout (ARCHITECTURE §4). The server checks the gate's protocol version and refuses mismatches with an actionable error. |
| F-07 | Built-in read operations implemented natively in the gate where possible (system info, disk, memory, processes, directory listing, stat, bounded file read, find, certificate inspection) and via fixed argv for `systemctl`/`journalctl`/`git` reads. |
| F-08 | Built-in operator operations: service start/stop/restart/reload (unit × verb allow-list, authorized by the generated polkit rule — no sudo), atomic file write with **read-back verification**, mkdir, copy, move, chmod (no setuid/setgid/world-writable), `git pull --ff-only` on allow-listed repos. |
| F-09 | Built-in destructive operations (admin profile + human approval through elicitation (D-006) + policy `max_tier: destructive`): delete path (recursive only with `recursive=true`), discard git working-tree changes. |
| F-10 | Policy commands (`shell_run_command`): argv templates with typed placeholders (docs/POLICY.md §4), per-command tier, `cwd`, bounded `stdin`, bounded `timeout_seconds`; always unprivileged. Tier `read` commands are callable in `read-only`; `operator` in `operator`; `destructive` in `admin` with human approval. |
| F-11 | All results use the uniform envelope (ARCHITECTURE §6): `structuredContent` + compact text; `outputSchema` on every tool; truncation flagged; non-zero exits reported with `exit_code`, never hidden. |
| F-12 | CLI: `shell-mcp serve | check | tools | healthcheck | version`; `check` connects to each target, verifies the host key, calls the gate's `hello` and prints gate version, protocol, principal, policy hash, `max_tier` and effective tool list per target. `tools` prints the deterministic catalogue (name, tier, description, input/output schema SHA-256) for rug-pull diffing. |
| F-13 | Gate CLI (run locally by the host admin): `shell-mcp-gate serve --policy <file> [--principal <label>]` (the forced command), `check-policy --policy <file>` (lint, ownership checks, GTFOBins warnings, effective policy), `polkit --policy <file> --user <name>` (the exact polkit rule for the policy's unit × verb list, ready for `/etc/polkit-1/rules.d/`), `version`. |
| F-14 | Privileged operations through the helper (docs/PRIVILEGED.md §6): read/list/stat of root-only files; atomic write with backup and read-back verification; mkdir, chown/chgrp (allow-listed owners), chmod (within the mode mask), copy, move; backup listing and restore; delete (destructive); declared commands run as root; apt index update, install/remove of allow-listed packages, full upgrade when allowed. |
| F-15 | Helper CLI (run locally by the host admin): `shell-mcp-privd serve` (started by systemd only), `check-policy --policy <file>` (lint, never-list and acknowledge report, capability and broad-unit report), `units --policy <file>` (generate the socket and service units pinned to the policy hash), `version`. |

### 4.2 Security (summary — full treatment in `docs/SECURITY.md`)

| # | Requirement |
|---|---|
| S-01 | MCP auth: `bearer` (constant-time compare, token ≥ 43 chars from `SHELL_MCP_TOKEN_FILE`/`SHELL_MCP_TOKEN`) or guarded `none` (D-004). |
| S-02 | DNS-rebinding protection: our own `Host`/`Origin` allow-list middleware, regardless of SDK defaults (the Go SDK has shipped at least one advisory about rebinding protection defaults). |
| S-03 | Rate limits: 10 auth failures/5 min/IP → 429 for 5 min; global per-IP token bucket; request body ≤ 1 MiB. |
| S-04 | SSH: pinned host keys (D-012), Ed25519 client key, no agent/forwarding/PTY requests, connect timeout, keepalives, per-target connection reuse with bounded concurrent sessions. |
| S-05 | Gate: refuses to run as root or with a privileged supplementary group (D-020); refuses a policy/binary/authorized_keys that is not root-owned or is group/other-writable; strict policy parsing (unknown keys are errors); hard-deny list; protected-path set; placeholder values may never start with `-`; commands resolved to absolute, root-owned, non-writable binaries at policy load. |
| S-06 | Gate exec: `execve` only, scrubbed environment (fixed `PATH`, `LANG=C.UTF-8`, `PAGER=cat`, `SYSTEMD_PAGER=`, `GIT_TERMINAL_PROMPT=0`…), new process group, `Pdeathsig`, `RLIMIT_CORE=0`, SIGTERM→SIGKILL on timeout, per-stream output caps, stdin cap — all inside the process-wide `no_new_privs` + Landlock domain (D-019). |
| S-07 | Gate filesystem: every path op goes through `os.Root` for the matching root; after open, the real path from `/proc/self/fd/N` is re-checked against roots and the deny list; final-component symlinks are refused; writes are temp-file + fsync + rename in the same directory, preserve mode/owner, refuse setuid/setgid bits, and are verified by re-reading. |
| S-08 | Output hygiene: PEM private-key blocks and configured secret patterns are redacted in every output (gate and server); files whose content begins with a private-key header are refused; process command lines are redacted of values after known secret flags; sizes are capped. |
| S-09 | Container image: `distroless/static` (nonroot) final stage pinned by digest, no shell, read-only root FS, `cap_drop: ALL`, `no-new-privileges`, pids/memory/CPU limits in the reference compose. |
| S-10 | Supply chain: `go.sum` committed; `govulncheck`; Trivy **and** Grype image scans (fail on HIGH/CRITICAL, documented ignore files only); CodeQL (Go) + `golangci-lint` with `gosec`; gitleaks; Dependabot daily; `deps-current` gate (D-013); CycloneDX SBOM; cosign keyless signatures on the image **and** the gate binaries; build provenance attestations. |
| S-11 | Audit: server logs one JSON line per tool call (time, principal, target, tool, sanitized args — ids/paths/units only, never content — outcome, exit code, duration). Gate logs one line per request to syslog with the principal label and the SSH client address. |
| S-12 | Human approval (D-006): `requestState` = versioned, HMAC-SHA-256 over {principal, tool, target, canonical-args SHA-256, preview SHA-256, expiry, nonce} with a per-process random key; verified in constant time; expired, mismatched or foreign state → `approval_invalid`; nonces recorded in a bounded in-memory set until expiry so an accepted approval executes once. Approval decisions are audit-logged. |
| S-13 | Helper: peer-UID authentication, strict privileged policy, never-list enforcement, generated core/broad units with the systemd sandbox in docs/PRIVILEGED.md §5, Landlock inside the core unit, self-checks (§7), backups before overwrite/delete, journald audit. |

### 4.3 Operability

| # | Requirement |
|---|---|
| O-01 | Reference `deploy/docker-compose.yml` (hardened), `deploy/stack-editor.yml` (for DockHand/Portainer env stores), `deploy/.env.example`, `deploy/docker-run.md`. |
| O-02 | `docs/TARGET-SETUP.md`: numbered steps to create the service user with an explicitly chosen UID/GID and a check that it owns no existing files (D-020), verify Landlock is enabled (`/sys/kernel/security/lsm`), install and verify the gate (checksum + cosign), write the policy, add the root-owned `authorized_keys` line with `restrict,from=,command=`, the sshd `Match User` block, filesystem ACLs for write roots, the generated polkit rule (only when service control is enabled), and — when root actions are wanted — the privileged helper: binary, socket group, privileged policy, generated units, `systemd-analyze security` check. |
| O-03 | `docs/CLIENTS.md`: Claude Code, Claude Desktop (via a remote-MCP bridge with the token in the config's `env` block), generic clients, MCP Inspector for verification. |
| O-04 | Example policies in `examples/policies/` (`read-only.yaml`, `operator.yaml`, `admin.yaml`) and `examples/privileged/privileged.yaml`, using only generic paths (`/srv/...`, `/etc/<app>` placeholders). |
| O-05 | Semantic versioning; `CHANGELOG.md` generated from ARCHIVE §14 at release. |

## 5. Phased delivery (each session = one PR into `dev`)

Every use case ships in `v0.1.0`; the order below only builds the foundations first.

| Phase | Session | Outcome | Model / effort |
|---|---|---|---|
| 0 — Scaffold | **S0** | Go module, three `cmd/` binaries that build, tooling (golangci-lint, govulncheck), `scripts/ci-local.sh` (the CI gate in digest-pinned Linux containers, for Windows workstations), CI (lint, test with `-race`, vuln, gitleaks, CodeQL, image build + Trivy + Grype, `deps-current`), hardened Dockerfile, config loader + fail-closed validation, `/healthz`, zero tools, PR template, Dependabot daily. | Opus 5.5 · medium |
| 1 — Gate security core | **S1** | Gate: wire protocol, strict policy loader (including the `privileged` forwarding section), hard-deny + protected sets, install and group checks, Landlock + `no_new_privs` sandbox, path confinement (`os.Root` + fd re-check) for read **and** write primitives, exec engine, redaction, `hello`/`policy` ops, fuzz tests. | Opus 5.5 · high |
| 1b — Gate operations | **S1b** | Remaining gate ops (sysinfo, disk, processes, systemd, journal, git, cert), `polkit` rule generator, syslog audit, `check-policy` UX, example gate policies. | Opus 5.5 · high |
| 1c — Helper core | **S1c** | `shell-mcp-privd`: peer-UID auth, strict privileged policy with the never/acknowledge lists, core-unit generator pinned to the policy hash, self-checks, Landlock, privileged file ops with backups and read-back, root exec, journald audit; gate forwarding of `priv_*`; e2e with a systemd-enabled test container. | Opus 5.5 · high |
| 1d — Helper broad unit | **S1d** | Broad-unit generator, apt operations (update index, install/remove allow-listed, upgrade with simulated preview), `unit: broad` commands, example privileged policy. | Opus 5.5 · high |
| 2 — Server core | **S2** | Bearer auth, Host/Origin allow-list, rate limits, body cap, SSH client with pinned host keys, target registry, gate client, envelope, `check`/`tools` CLI, `shell_list_targets`, `shell_get_policy`; stdio; 2026-07-28 + 2025-11-25 client compatibility; **verification of which target clients (Claude Code, Claude Desktop through its remote-MCP bridge) declare and render elicitation** — recorded in ARCHIVE, because D-006 fails closed without it. | Opus 5.5 · high |
| 3 — Read tools + E2E | **S3** | Read tier from `docs/TOOLS.md`; end-to-end harness (sshd + gate + helper containers on a CI-only network); catalogue snapshot. | Opus 5.5 · medium |
| 4 — Write, approval, root | **S4a**, **S4b**, **S4c** | S4a operator tools with read-back verification; S4b the elicitation approval binding (D-006, S-12) and destructive tools; S4c privileged tools (`shell_priv_*`). | Opus 5.5 · high |
| 4b — Multi-call binaries | **S-MC** (design session, before S5) | Decide whether the binary identity check (POLICY §5) may allow a declared name of an argv[0]-dispatched multi-call binary (e.g. Rust coreutils on Ubuntu 26.04, where every coreutils command is refused today): only for a known implementation verified at the source to dispatch strictly on argv[0]'s base name, only when the declared name is not itself denied, and only if the gate (and helper) always set argv[0] to the declared path — with two-sided tests on both CI images. Not implemented before that session (S1c finding). | Opus 5.5 · high |
| 5 — Ship | **S5** | Release workflow (multi-arch image + gate and helper binaries, cosign, SBOM, provenance), `TARGET-SETUP.md` (gate and helper), `CLIENTS.md`, README, CHANGELOG, `v0.1.0` release PR. | Opus 5.5 · medium |

## 6. Deferred decisions

- **Other package managers** for the helper (dnf, zypper, apk, pacman).
- **Seccomp filtering** for gate children, on top of Landlock — evaluate once the command set is known.
- **OAuth resource-server mode.** Deliberately parked. Remote shell capability should sit behind a VPN or LAN, not a public connector URL; revisit only on demand, with the same scoping-first approach used elsewhere.
- **Multi-principal servers** (several bearer tokens → several profiles in one instance).
- **Non-Linux targets.**

## 7. Definition of done (per PR)

- [ ] `gofmt`/`golangci-lint run` clean; `go vet ./...` clean; `go test -race ./...` green; `govulncheck ./...` clean
- [ ] New behaviour has tests that were **verified to fail** against the pre-change code (the PR body names the commit or shows the failing run)
- [ ] Gate and helper parsers and path handling covered by Go native fuzz tests where touched
- [ ] No new tool without: input/output schema, annotations, `title`, tier + profile registration, gate op (and helper op for `shell_priv_*`) + policy tier, approval classification, a `docs/TOOLS.md` row, a catalogue-snapshot update, and tests
- [ ] `docs/ARCHIVE.md` §14 entry, dated, with the decision, the reasoning and the dependency versions in use
- [ ] Public-repo hygiene: no hostnames, IPs, domains, usernames, unit/service/stack names or paths from any real deployment in the diff, fixtures, commit messages or PR body; the local pre-push hook passed and the session reviewed the diff itself
- [ ] PR opened against `dev`, not merged, link posted; attribution footer stripped from the PR body and the live body re-read to confirm

## 8. Repository layout (target after Phase 2)

```
shell-mcp/
├── CLAUDE.md, plan.md, README.md, SECURITY.md, LICENSE, NOTICE
├── go.mod, go.sum
├── cmd/
│   ├── shell-mcp/            # server main
│   ├── shell-mcp-gate/       # gate main
│   └── shell-mcp-privd/      # privileged helper main
├── internal/
│   ├── config/               # env + targets file, startup validation
│   ├── auth/                 # bearer, principal
│   ├── approval/             # elicitation round trip, HMAC-bound requestState, nonce set
│   ├── transport/            # HTTP app, host/origin, rate limit, body cap, /healthz
│   ├── sshx/                 # SSH client, host-key pinning, connection pool
│   ├── gateclient/           # request/response over an SSH session
│   ├── envelope/             # uniform results, error codes
│   ├── tools/                # registry (tiers/profiles) + one file per domain
│   ├── redact/               # shared redaction (server, gate, helper)
│   ├── protocol/             # shared wire types + version (server, gate, helper)
│   ├── template/             # shared argv-template engine (gate, helper)
│   ├── gate/
│   │   ├── policy/           # strict loader, hard-deny, protected paths
│   │   ├── fsx/              # os.Root confinement, fd re-check, atomic write
│   │   ├── execx/            # execve engine, env scrub, limits, caps
│   │   ├── ops/              # one file per op; priv_* forwarding
│   │   ├── audit/            # syslog
│   │   ├── sandbox/          # no_new_privs + Landlock ruleset from policy
│   │   └── polkit/           # unit × verb rule generator
│   └── privd/
│       ├── policy/           # privileged policy, never / acknowledge lists
│       ├── peercred/         # SO_PEERCRED authentication
│       ├── units/            # core/broad systemd unit generator, policy-hash pinning
│       ├── selfcheck/        # uid, NoNewPrivs, capability set, ownership, hash
│       ├── ops/              # privileged file ops, backups, root exec
│       └── pkg/              # apt operations (broad unit)
├── examples/policies/, examples/privileged/
├── deploy/                   # compose, stack-editor variant, .env.example, docker-run.md
├── test/e2e/                 # sshd + gate + systemd/helper harness (CI only)
├── docs/                     # ARCHITECTURE, SECURITY, POLICY, PRIVILEGED, TOOLS, ARCHIVE, TARGET-SETUP, CLIENTS
├── Dockerfile, .dockerignore, .gitattributes, .gitignore
└── .github/                  # workflows, dependabot.yml, PR template, CODEOWNERS
```
