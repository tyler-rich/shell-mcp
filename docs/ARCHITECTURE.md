# Architecture

## 1. Shape of the system

```
┌─────────────┐ Streamable HTTP  ┌──────────────────────────┐  SSH (pinned host key,  ┌──────────────────────────────────────────────────┐
│ MCP client  │ ── Bearer ─────▶ │ shell-mcp (container)    │── Ed25519 client key) ─▶│ target host                                      │
│ Claude Code │ ◀─ JSON ──────── │ /mcp: auth → profile →   │                         │  sshd → forced command:                          │
│ Desktop …   │  (approval_      │ approval → tool → gate   │ ◀── one JSON response ──│  shell-mcp-gate  (service user, no_new_privs,    │
└─────────────┘   pending + URL) │ client → envelope        │                         │                   Landlock, gate policy)         │
                                 │                          │                         │      │ priv_* only, local Unix socket            │
┌─────────────┐ HTTPS (own       │ approval listener:       │                         │      ▼  (peer-UID checked by the kernel)          │
│ approver's  │ ── listener, ──▶ │ page, TOTP code, no      │                         │  shell-mcp-privd (root, one instance per request, │
│ browser     │    no bearer)    │ bearer, no cookies       │                         │   systemd sandbox, privileged policy, backups)    │
└─────────────┘                  └──────────────────────────┘                         └──────────────────────────────────────────────────┘
```

Properties that follow from this shape:

- **Three gates, the host ones authoritative.** The server decides what is *advertised* (profile, D-005) and collects human approval (D-006). The gate decides what the service user may do (gate policy, D-016). The helper decides what root may do (privileged policy, D-021). Neither host component trusts the component that called it. Every request also carries the calling tool's tier as its `ceiling` (§4.1), which the gate and the helper apply in the same check as their `max_tier`; that makes the server's profile a second enforcement point on the host against server mistakes and races, but not against a compromised server, which can send any ceiling.
- **The container holds no host access.** No Docker socket, no host mounts, no capabilities. Its only secrets are the MCP bearer token and the SSH private key(s). Its only egress is SSH to configured targets.
- **No long-running privileged process anywhere.** sshd starts the gate per request; systemd starts a helper instance per connection. Both serve one request and exit.
- **Stateless server.** No MCP sessions (D-014). In-memory state is limited to rate limiters, the SSH connection pool, the approval store and the approvers' TOTP state (last accepted step, wrong-code counts, lockouts), all bounded and all lost on restart.
- **Two listeners.** `/mcp` (bearer-authenticated) and, with `SHELL_MCP_APPROVAL_METHOD=web`, the approval listener on its own bind and port (loopback by default), which never accepts the bearer token. Neither serves the other's routes.

### 1.1 Why Go (D-001)

| | Go | Python |
|---|---|---|
| Gate and helper on arbitrary hosts | Static binaries, no runtime; `os.Root` for confinement; `x/sys/unix` for `prctl`, rlimits | Bound to each host's system Python; stdlib-only to avoid installs; forces a compatibility window (conflicts with D-013) |
| Server image | `distroless/static:nonroot`, a few MB, no interpreter or shell | `python:<latest>-slim` or distroless-python, larger surface |
| SSH client | `golang.org/x/crypto/ssh` (+ `knownhosts`), host-key callback is explicit | `asyncssh`/`paramiko`, fine but another large dependency |
| MCP SDK | Official Go SDK; 2026-07-28 from v1.7.0 | Official Python SDK |
| Vulnerability tooling | `govulncheck` (call-graph reachability) | `pip-audit` (package-level) |
| Maintainer familiarity | Lower (sessions write the code; the maintainer reviews) | Higher (sibling project is Python) |

Python remains viable for the server alone, but one language for all three binaries (shared protocol types, template engine and redaction, one CI) outweighs familiarity. Switching is allowed only before Session 1.

## 2. Components

### Server (`cmd/shell-mcp`)

| Package | Responsibility |
|---|---|
| `internal/config` | Parse env + optional targets file → `Config`; `*_FILE` secrets; fail-closed validation (SECURITY §6). |
| `internal/approval` | D-006: approval records bound to principal, tool, target, canonical-args, preview and policy SHA-256; the bounded in-memory store (pending limit, deduplication, expiry sweep); the execution check (`approval_pending` / `approval_declined` / `approval_invalid`). Subpackages: `totp` (RFC 6238 verifier, last accepted step, lockouts), `approvers` (the secret file and enrolment), `qr` (the enrolment QR encoder), `page` (the approval listener and page: origin banner, POST-only decisions with a CSRF token and a TOTP code, CSP and headers, exposure rules), `notify` (optional ntfy push). |
| `internal/auth` | Bearer middleware (constant-time compare over a list, one entry in v1), `Principal{Name, Profile}`. 401 with `WWW-Authenticate: Bearer realm="shell-mcp"` and body `{"error":"unauthorized"}`. |
| `internal/transport` | HTTP server: body cap → global rate limit → Host/Origin allow-list → auth → SDK handler (stateless Streamable HTTP, JSON responses). `/healthz` outside the chain. Timeouts set on `http.Server` (read header, read, write, idle). |
| `internal/sshx` | SSH client per target: pinned host keys (typed `<key-type> SHA256:` pins; no known_hosts in v1), Ed25519 signer from file, `HostKeyAlgorithms` derived from the pinned key types only, connect timeout, keepalive, max concurrent sessions per target (default 4), reconnect with backoff. No agent, no forwarding, no PTY, no `Setenv`. |
| `internal/gateclient` | Open a session, request exec `shell-mcp-gate/1`, write one request (≤ 2 MiB), read one response (≤ 4 MiB), enforce the tool's time budget, map gate errors to envelope codes. |
| `internal/tools` | Registry: `Register(tool, tier)`; at startup registers tiers allowed by the profile minus `SHELL_MCP_DISABLE_TOOLS`. One file per domain. Tools validate inputs, call the gate, shape results — no host logic. |
| `internal/envelope` | Uniform result builders; the closed error-code set. |
| `internal/redact` | Shared with the gate: PEM private-key blocks, bearer/`Authorization`, configured secrets, `key=value` secret patterns. |
| `internal/protocol` | Shared wire types, protocol version constant, size limits. |

### Gate (`cmd/shell-mcp-gate`)

| Package | Responsibility |
|---|---|
| `internal/gate/policy` | Strict YAML load (unknown keys are errors), schema validation, hard-deny list, protected-path set, template compilation, binary resolution and ownership checks, policy SHA-256. |
| `internal/gate/fsx` | Root selection (longest matching root), `os.Root` operations, `/proc/self/fd/N` real-path re-check, O_NOFOLLOW final component, deny matching, bounded reads, atomic writes with read-back, mode/owner preservation, setuid/setgid refusal. |
| `internal/gate/execx` | Template matching, argv construction, scrubbed env, `SysProcAttr{Setpgid, Pdeathsig}`, rlimits in force before the command's first instruction (the running binary re-executes itself as a trampoline: it reads the command from an inherited socketpair, lowers its own limits with `setrlimit(2)`, marks every descriptor above stderr close-on-exec and `execve(2)`s the command; it refuses any other way of being started), output capture with per-stream caps, timeout SIGTERM→SIGKILL on the process group, exit-code/signal reporting. Used by the gate and the helper. |
| `internal/gate/ops` | One file per op (§4.3). Each op declares its tier; the dispatcher refuses ops above min(`max_tier`, the request's `ceiling`) before doing anything else. |
| `internal/gate/audit` | One syslog line per request (authpriv; info on success, notice on refusal): request id, the request's tier `ceiling` (empty when the request was refused before it was read), principal, client address (`SSH_CONNECTION`), op, sanitized args (paths, units, ids, flags; an argument list only as its count), outcome, duration, as one JSON object. Never content, stdin, output or environment. One datagram to `/dev/log` with a 250 ms dial and write deadline: a missing socket or full queue never blocks the request. |
| `internal/gate/procfs`, `systemd`, `gitx`, `certs` | Bounded, fuzzed parsers for `/proc` and os-release, systemctl/journalctl arguments and output, git output and repository configuration, and certificates. |
| `internal/gate/sandbox` | Compute the Landlock ruleset from the policy (system read/execute paths, read roots, write roots, allowed TCP connect ports, IPC scoping) and apply it with `no_new_privs` to all threads before the request is read; report the effective ABI level. |
| `internal/template` | The argv-template engine shared by the gate and the helper (POLICY §4). |
| `internal/gate/polkit` | Generate the polkit rule for `services.control` (exact units × verbs, `subject.user` match, no wildcards); refuse if any unit name is not exact. |

### Helper (`cmd/shell-mcp-privd`) — normative detail in `docs/PRIVILEGED.md`

| Package | Responsibility |
|---|---|
| `internal/privd/peercred` | Read `SO_PEERCRED` on the systemd-provided socket; require the uid to equal the unit's `SHELL_MCP_PRIVD_CLIENT_UID`. |
| `internal/privd/policy` | Strict privileged policy; never list (A) and acknowledge list (B); owners, mode mask, backups, commands, packages. |
| `internal/privd/units` | Generate the core socket/service units, and the broad pair when the policy uses it, embedding the policy SHA-256, `client_uid` and which unit they are. |
| `internal/privd/selfcheck` | Before the peer check: stdin is a socket, the unit's client uid is valid. After it: uid 0, `NoNewPrivs: 1`, ownership, policy hash and `client_uid` equal to the unit's, capability bounding set ⊆ the generated unit's. |
| `internal/privd/ops` | Privileged read/write/mkdir/chown/chmod/copy/move/delete with backups and read-back; backup list/restore; root exec through `internal/template` and the gate's exec engine. |
| `internal/privd/pkg` | apt (broad unit): the fixed apt-get argv per operation, Debian package-name validation, the `-s` simulation parser behind the previews, and a bounded wait for a held dpkg or lists lock. |
| `internal/privd/dbus` | The smallest D-Bus client `priv_power` needs (broad unit): EXTERNAL authentication, Hello, one method call with string arguments, strict bounded decoding; standard library only. |

## 3. Request lifecycle

1. **HTTP:** body ≤ 1 MiB (413; a declared length over the cap is refused before anything else, and every body is bounded while it is read) → global rate limit (429 with `Retry-After`, per client: an IPv4 address or an IPv6 /64) → Host/Origin allow-list (421 for a `Host` not on the list, 403 for an `Origin` not on it) → bearer auth (401 with `WWW-Authenticate`; 10 failures in 5 min per client → 429 for 5 min, and while locked every request is refused before its credential is looked at) → SDK dispatch. Only a presented credential that does not authenticate counts toward that lockout: an `Authorization` header that is not a matching bearer token, another scheme, a malformed value, or more than one `Authorization` header. A request with no `Authorization` header gets the same 401 and is still subject to the global rate limit, but it does not count. The lockout exists to stop token guessing, and such a request guesses nothing. Clients probe OAuth discovery without credentials before connecting, and counting those probes locked clients out of a freshly started server. Each failure is logged at WARN with its `reason` and `counts_toward_lockout`. The global limiter logs the first refusal of each run as `request refused` with `reason: rate_limited`, so its 429 can be told apart from the lockout's. Every path except `/healthz` is behind the chain, so an unauthenticated request learns nothing, not even which paths exist. Refusals are `{"error":"<code>"}` with `request_too_large`, `rate_limited`, `host_not_allowed`, `origin_not_allowed` or `unauthorized`. Only registered tools exist.
2. **Tool:** strict argument decoding → semantic validation (target exists, path absolute and clean, sizes) → the tool's registered tier becomes the `ceiling` of every gate request it makes → for an approval-gated tool (destructive, privileged operator+, or a tier in `SHELL_MCP_APPROVAL_TIERS`), per `SHELL_MCP_APPROVAL_METHOD`:
   - `none`: refuse with `approval_unavailable`; nothing is sent.
   - **First call (no `approval_id`):** compute the preview through the gate's read operations → create an approval record {pending} bound to principal, tool, target, canonical-args SHA-256, preview SHA-256 and the gate's policy SHA-256 (an identical pending request returns the same record; at most 5 pending per principal) → push a notification (optional) → return `approval_pending` with `{id, status, url, expires_at, summary}` and the instruction to show the URL unchanged.
   - **Approver:** opens the bookmarked page (enters the id) or taps the push → POST approve or decline with a TOTP code and the record's CSRF token → record {approved | declined by <name>}.
   - **Re-call (`approval_id`):** a pending record waits up to 20 s (never past expiry) and returns `approval_pending` again; declined → `approval_declined`; otherwise the record must be approved, unexpired, unused and match every bound field → mark used → fresh preview, whose hash and policy hash must equal the record's → gate request with the tool's ceiling and, where the operation supports it, the preview's precondition (`expected_sha256` of the content it saw, or `expect_absent` when it saw no file). Anything else is `approval_invalid`.
   - `confirm-argument`: the same record; the re-call with `approval_id` and `confirm: true` approves it as `model (confirm-argument)` (WARN).
3. **SSH:** reuse or open the target connection (host key verified on every new connection) → new session → exec `shell-mcp-gate/1` (sshd ignores it and runs the forced command; the gate reads it from `SSH_ORIGINAL_COMMAND` as a protocol hello) → write request → read response → close session.
4. **Gate:** check own install (not root, no privileged groups, policy/binary ownership) → load policy → **set `no_new_privs` and apply Landlock** → only now read and parse the request (bounded; a missing or unknown `ceiling` is `bad_request`) → tier ≤ min(`max_tier`, `ceiling`) (for `exec`, the command's own tier) → op-specific validation against policy → execute → redact → respond → audit → exit. For `priv_*` ops: check `privileged.enabled` and tier ≤ min(`privileged.max_tier`, `ceiling`) → pick the socket: `privileged.broad_socket` for `priv_pkg_*` (and their previews), `priv_power`, and `priv_exec` whose `unit` argument is `broad` (a label the server supplies, since the gate cannot read the privileged policy); `privileged.socket` for everything else; a broad route without `broad_socket` is `privileged_disabled`; a malformed `unit` is `bad_request` → connect to the helper socket → forward the request unchanged (the same `v`, `id`, `ceiling`, `op`, `timeout_ms`, and the `args` bytes as received) → read one response (≤ 4 MiB, strictly decoded, within the request's timeout plus 15 s) → return the helper's `ok`, `data`, `error` and `warnings` under the gate's own `gate` block. An unreachable socket or an unreadable response is `helper_unavailable`; a connection closed without a byte (only a peer that failed the helper's peer check gets that) is `helper_refused`; no answer in time is `timeout`; a helper error passes through with its code, including the `helper_*` self-check codes, which the helper may answer before the request is even sent.
5. **Helper** (privileged ops only): systemd accepts the connection and starts an instance → peer check from the connection and the unit alone: stdin, the unit's client uid, `SO_PEERCRED` (any failure: close without a byte, WARN journal line) → self-checks (uid, NoNewPrivs, binary) → load privileged policy → policy hash, `client_uid` and bounding set against the unit (any failure: a `helper_*` response without an id, WARN journal line) → which unit it runs in (`SHELL_MCP_PRIVD_UNIT`) → Landlock (core unit only; a failure is a `helper_sandbox_unavailable` response without an id) → read request → the op belongs to this unit, else `helper_wrong_unit` (the helper is authoritative for routing: nothing meant for the other unit runs here) → tier ≤ min(`max_tier`, `ceiling`) (for `priv_exec`, the command's own tier) → validation against the privileged policy → backup → execute → verify → redact → respond → journald audit → exit.
6. **Server:** map response → envelope → audit line.

Every failure at steps 2–6 becomes a tool error in the envelope, never a transport error.

## 4. Gate wire protocol (version 1)

One request per SSH session, UTF-8 JSON, newline-terminated, on stdin. One response, same encoding, on stdout. The gate writes nothing else to stdout. Stderr is unused (the gate logs to syslog).

### 4.1 Request

```json
{
  "v": 1,
  "id": "0b5c…(uuid v4)",
  "ceiling": "read",
  "op": "read_file",
  "args": { "path": "/srv/app/config.yaml", "max_bytes": 262144 },
  "timeout_ms": 30000
}
```

- `v` must equal the gate's protocol version, else `{"ok":false,"error":{"code":"protocol_mismatch"}}`.
- `id` must be a UUID v4 in lowercase canonical form (`xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx`, exactly 36 characters); anything else is `bad_request`. It is echoed in the response and written into the gate's and the helper's audit lines, which join on it.
- `ceiling` is required: `read`, `operator` or `destructive`, the tier of the tool that made the request. A request without it, or with any other value, is `bad_request` before anything else about it is looked at (the response has no id). The gate refuses any op, and any `exec` command, whose tier is above min(`max_tier`, `ceiling`) with `tier_denied`, as its first check on the request; a `priv_*` op is checked against min(`privileged.max_tier`, `ceiling`) and forwarded with the ceiling unchanged, and the helper applies min(its own `max_tier`, `ceiling`) to the operation or the `priv_exec` command. The refusal's message names the limit that applied (the policy's `max_tier`, `privileged.max_tier`, or the request's ceiling). The ceiling is defence in depth against server mistakes and races (a policy edited between two requests), not against a compromised server, which can send any ceiling; the policies remain the boundary for that (POLICY §2, PRIVILEGED §6). Protocol v1 was amended in place to add it before any release (ARCHIVE §14, 2026-10-16).
- `op` must be a known op; `args` are op-specific and strictly decoded (unknown fields are errors).
- `timeout_ms` is clamped to the policy's `limits.max_timeout_s`.
- Request size ≤ 2 MiB (write content is carried as base64 in `args.content_b64`, ≤ `limits.max_write_bytes` after decoding).
- `write_file` and `priv_write_file` take at most one precondition: `expected_sha256` (the current content must have that SHA-256; otherwise `exists`, or `not_found` without a file) or `expect_absent: true` (the file must not exist, up to and including the commit; otherwise `exists`). Both together is `bad_request`. `expect_absent` is optional and defaults to false; it was added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-17), and an older gate refuses it as an unknown field (`bad_request`), never ignores it.

### 4.2 Response

```json
{
  "v": 1,
  "id": "0b5c…",
  "ok": true,
  "data": { … op-specific … },
  "warnings": [],
  "gate": { "version": "0.1.0", "principal": "readonly-key", "policy_sha256": "…", "max_tier": "read", "duration_ms": 12 }
}
```

Failure: `"ok": false, "error": {"code": "<closed set>", "message": "<one line, no content>"}`. Exec ops report process results in `data` (`exit_code`, `signal`, `stdout`, `stderr`, `stdout_truncated`, `stderr_truncated`, `timed_out`) and use `ok: true` whenever the process was started — a non-zero exit is data, not a gate error.

Gate error codes: `protocol_mismatch`, `bad_request`, `unknown_op`, `tier_denied`, `policy_denied`, `path_denied`, `not_found`, `not_a_directory`, `is_a_directory`, `too_large`, `exists`, `template_mismatch`, `not_authorized` (polkit denied), `sandbox_unavailable`, `privileged_disabled`, `helper_unavailable`, `helper_refused`, `backup_failed`, `exec_failed`, `timeout`, `verify_failed`, `install_insecure`, `internal`.

Helper self-check codes (PRIVILEGED §7), answered by the privileged helper to an authenticated gate before the request is read (so without an id) and passed through by the gate unchanged: `helper_install_insecure` (not root under its unit, no NoNewPrivs, its binary or policy file missing, not root-owned or group/other-writable, or a unit that does not say which sandbox it is), `helper_policy_invalid` (the policy does not parse or fails validation), `helper_policy_mismatch` (the policy's SHA-256 is not the units'), `helper_client_uid_mismatch` (the policy's `client_uid` is not the unit's), `helper_capabilities_broad` (the bounding set is broader than the unit declares), `helper_sandbox_unavailable` (the core unit could not apply its Landlock sandbox under `sandbox.landlock: required`; the gate's own refusal stays `sandbox_unavailable`). Answered with the request's id, after it is read: `helper_wrong_unit` (the operation belongs to the other unit's helper instance, core or broad; it was not executed).

### 4.3 Operations

| Op | Tier | Implementation |
|---|---|---|
| `hello` | read | Gate version, protocol, principal, policy hash, `max_tier`, op list. |
| `policy` | read | Effective policy summary: roots, limits, services, repos, command ids with templates and tiers. Never raw file bytes. |
| `sysinfo` | read | Native: `/etc/os-release`, `uname(2)`, `/proc/uptime`, `/proc/loadavg`, `/proc/meminfo`, CPU count (`/proc/stat`). |
| `disk` | read | Native: `/proc/self/mountinfo` + `statfs(2)` (2 s per mount, so a hung network mount is reported, not waited on); pseudo filesystems filtered unless `include_pseudo`. |
| `processes` | read | Native `/proc` walk bounded by `limits.max_processes`: pid, ppid, user, state, rss, cpu time, start time, comm, cmdline with values after secret-looking flags (`--password`, `--token`, `--secret`, `-p` …) and URL userinfo redacted, then the redaction patterns, then cut to 512 characters. Reports `hidepid` on `/proc` (the list is then partial). |
| `service_status` | read | `systemctl show --no-pager -p <fixed property list> -- <unit>`; exact unit name matching `services.status`; `KEY=VALUE` output parsed strictly (unrequested or repeated keys are `exec_failed`). |
| `service_list` | read | `systemctl list-units --no-pager --plain --output=json --type=service [--state=failed]`; only units matching `services.status`. `-o json` for `list-units` is not in the man pages but is implemented in systemd 257 and 259 (verified at the source; keys `unit`, `load`, `active`, `sub`, `description`, and `job` only when a job is pending). |
| `journal` | read | `journalctl --no-pager -o short-iso -n <N> [--since @<t>] [--until @<t>] [-p <prio>] -u <unit>`; exact unit name (journalctl would expand a glob) matching `journal.units`; N ≤ `journal.max_lines`; `since`/`until` accepted as RFC 3339 or `-N<s\|m\|h\|d\|w>` (≤ 10 years) and passed only as epoch seconds computed by the gate. |
| `list_dir`, `stat`, `read_file`, `find` | read | Native via `fsx` within `paths.read` (write roots are implicitly readable). `find` = bounded walk (depth, results, name glob, type) — never the `find` binary. |
| `cert_inspect` | read | Native: parse PEM/DER certificates from a file within read roots; subject, issuer, SANs, validity, key type, SHA-256 fingerprint. Refuses files containing private keys. |
| `git_status`, `git_log`, `git_diff` | read | `git` with fixed hardening flags and environment (POLICY §7) on a repo listed in `git.repos`, after the repository-local configuration passes the allowlist. |
| `service_control` | operator | `systemctl --no-ask-password <verb> -- <unit>` as the service user; `verb ∈ services.control.verbs`; unit ∈ `services.control.units`; authorized by the generated polkit rule; no sudo. A polkit denial (exit 4, or exit 1 "interactive authentication required") is `not_authorized`; the unit's status is re-read after the action. |
| `write_file`, `mkdir`, `copy`, `move`, `chmod` | operator | Native via `fsx` within `paths.write`; atomic; read-back verified. Create-only commits (`write_file` with `expect_absent`, `copy` and `move` without `overwrite`) refuse a destination that exists at the moment of the commit (POLICY §3). |
| `git_pull` | operator | `git pull --ff-only --no-rebase --no-recurse-submodules` with hardening flags; the repo must be inside a write root; `remote.origin.url` and the URL git would use must equal the policy's (https) remote; refused on uncommitted tracked changes or a non-fast-forward. |
| `delete` | destructive | Native; files and empty dirs, or recursive with `recursive: true` bounded by `limits.max_delete_entries`; preview variant `delete_preview` is read tier. |
| `git_discard` | destructive | `git reset --hard` + `git clean -fd` (hardened); preview variant `git_discard_preview` is read tier. |
| `exec` | per command | Policy command by `id` + argv matched against its templates; tier from the command entry. |
| `priv_*` | per op | Forwarded to the helper when the gate policy enables it; the helper's op table is `docs/PRIVILEGED.md` §6. |

## 5. Configuration (server)

All variables are read at startup; `*_FILE` reads the value from a file (Docker secrets / mounted secret files) and wins over the plain variable.

| Variable | Default | Notes |
|---|---|---|
| `SHELL_MCP_PROFILE` | `read-only` | `read-only` / `operator` / `admin`. |
| `SHELL_MCP_DISABLE_TOOLS` | — | Comma list of tool names to remove. |
| `SHELL_MCP_TRANSPORT` | `http` | `http` / `stdio`. |
| `SHELL_MCP_BIND` / `SHELL_MCP_PORT` / `SHELL_MCP_PATH` | `127.0.0.1` / `8080` / `/mcp` | The reference compose binds `0.0.0.0` *inside* the container and limits exposure with the port mapping. |
| `SHELL_MCP_AUTH_MODE` | `bearer` | `bearer` / `none` (guarded, SECURITY §3). |
| `SHELL_MCP_TOKEN` / `_FILE` | *(required for bearer)* | ≥ 43 characters (≥ 32 bytes base64url). |
| `SHELL_MCP_ALLOW_UNAUTHENTICATED` | `false` | Required for `none` over HTTP, together with a loopback bind. |
| `SHELL_MCP_ALLOWED_HOSTS` | `localhost,127.0.0.1` | `Host` allow-list. Add the name clients use. |
| `SHELL_MCP_ALLOWED_ORIGINS` | *(empty)* | Browser `Origin` allow-list; empty = requests carrying `Origin` are refused. |
| `SHELL_MCP_TRUSTED_PROXIES` | *(empty)* | Comma list of the reverse proxies' IP addresses or CIDR prefixes (canonical form; `/0` and host bits refused). Empty: `X-Forwarded-For` is never used. Only a request whose **peer address** is in the list has its client taken from `X-Forwarded-For`, and then only from the last entry of the last header (the one that proxy appended); leftmost entries are written by the client and never used, and an unparsable entry falls back to the peer. A request from any other address is rate-limited and locked out by its own peer address, whatever headers it carries. An invalid entry fails startup with a one-line reason. Replaces the boolean `SHELL_MCP_TRUST_PROXY`, which is now refused at startup. |
| `SHELL_MCP_RATE_LIMIT_PER_MIN` | `120` | Per client IP. |
| `SHELL_MCP_TARGETS_FILE` | — | YAML list of targets (below). Mutually exclusive with the single-target variables. |
| `SHELL_MCP_TARGET_NAME` / `_HOST` / `_PORT` / `_USER` | — / — / `22` / — | Single-target shorthand for stack-editor deployments. |
| `SHELL_MCP_TARGET_HOST_KEYS` | *(required)* | Comma list of typed host-key pins, each `<key-type> SHA256:<base64>` (for example `ssh-ed25519 SHA256:…`); several pins of any mix of types allow rotation. Key types: `ssh-ed25519`, `ecdsa-sha2-nistp256`/`384`/`521`, `ssh-rsa`. The SSH client offers only the pinned types (`ssh-rsa` as `rsa-sha2-512`/`rsa-sha2-256`, never SHA-1); DSA and certificates are never accepted. An untyped or unknown-type pin fails startup. On the target the type is the first word of the host key's `.pub` file and `ssh-keygen -lf <host key>.pub` prints the fingerprint; `ssh-keyscan -t <type> <host>` piped to `ssh-keygen -lf -` works too when the result is verified out of band. |
| `SHELL_MCP_SSH_KEY` / `_FILE` | *(required)* | OpenSSH-format Ed25519 private key, unencrypted. `_FILE` (a mounted secret) is recommended and wins. The plain variable also accepts the single-line standard base64 of the whole key file (recognised by the absence of a `-----BEGIN` header; it must decode to an OpenSSH private key), for environment stores that cannot hold multi-line values. |
| `SHELL_MCP_DEFAULT_TARGET` | — | Makes `target` optional when several targets exist. |
| `SHELL_MCP_SSH_CONNECT_TIMEOUT` | `10` | Seconds. |
| `SHELL_MCP_SSH_MAX_SESSIONS` | `4` | Concurrent sessions per target. |
| `SHELL_MCP_DEFAULT_TIMEOUT` / `_MAX_TIMEOUT` | `30` / `300` | Seconds for gate operations; the gate clamps further. |
| `SHELL_MCP_MAX_OUTPUT_BYTES` | `262144` | Per stream returned to the client (the gate cap may be higher): each free-text field is cut to it, and a list is trimmed until the data fits it, with truncation flagged (docs/TOOLS.md, read tier). |
| `SHELL_MCP_APPROVAL_TIERS` | `destructive` | `destructive` or `operator,destructive`. Destructive operations and privileged operations of tier operator or above always need approval; adding `operator` also gates ordinary (unprivileged) writes. `destructive` cannot be removed. |
| `SHELL_MCP_APPROVAL_METHOD` | `none` | `none` \| `web` \| `confirm-argument`. `none`: approval-gated tools refuse with `approval_unavailable`. `web`: the out-of-band approval page (D-006). `confirm-argument`: the model approves with `confirm: true` on the re-call; WARN at startup and on every use. Replaces `SHELL_MCP_APPROVAL_FALLBACK`, which is refused at startup if set. |
| `SHELL_MCP_APPROVAL_TTL` | `300` | Seconds an approval request stays valid (60..900). |
| `SHELL_MCP_APPROVAL_BIND` / `_PORT` | `127.0.0.1` / `8081` | `web` only. The approval listener; the port must differ from `SHELL_MCP_PORT`. A non-loopback bind requires native TLS or `SHELL_MCP_TRUSTED_PROXIES`, and with only the latter the listener serves only peers inside it. |
| `SHELL_MCP_APPROVAL_TLS_CERT_FILE` / `_KEY_FILE` | — | Optional native TLS (1.2 or later) for the approval listener. Both or neither. |
| `SHELL_MCP_APPROVAL_PUBLIC_URL` | — | Required for `web`. Fixes the page's origin: absolute `https://` URL (`http://` only with a loopback host and a loopback bind), no userinfo, query or fragment. Every link the server emits uses it; requests with another `Host`, or an `Origin` other than it, are refused. |
| `SHELL_MCP_APPROVERS_FILE` | — | Required for `web`. A mounted secret file only; the plain variable `SHELL_MCP_APPROVERS` is refused. One `<name> <base32 seed>` per line (created with `shell-mcp approver add`). Names match `^[a-z][a-z0-9-]{0,31}$`; at least one approver, no duplicates, seeds ≥ 160 bits. Group/other-accessible fails startup. |
| `SHELL_MCP_APPROVAL_MAX_APPROVERS` | `1` | 1..8. A file with more approvers than this fails startup. |
| `SHELL_MCP_APPROVAL_NOTIFY_URL` | — | Optional ntfy topic URL (`https://…/<topic>`); JSON publish of the tool title, target, summary, expiry and a `view` link, and of approver lockouts. Never an approve or decline action. |
| `SHELL_MCP_APPROVAL_NOTIFY_TOKEN` / `_FILE` | — | Bearer token for the notify URL. Required when the URL is set. |
| `SHELL_MCP_REDACT_PATTERNS` / `_FILE` | — | Extra regexes for output redaction (RE2 syntax), one per line. `_FILE` wins, for environment stores that cannot hold multi-line values. |
| `SHELL_MCP_LOG_LEVEL` / `_LOG_FORMAT` | `info` / `json` | stdio transport logs to stderr only. |

Targets file:

```yaml
targets:
  - name: app-host
    host: target-a.example.test
    port: 22
    user: svc-shell
    host_keys: ["ssh-ed25519 SHA256:AAAA…placeholder…"]
    key_file: /run/secrets/ssh_key_app_host
```

## 6. Result envelope

```json
{
  "ok": true,
  "target": "app-host",
  "data": { … },
  "exec": { "exit_code": 0, "signal": null, "timed_out": false, "stdout_truncated": false, "stderr_truncated": false },
  "verified": true,
  "warnings": [],
  "gate": { "version": "0.1.0", "principal": "operator-key", "max_tier": "operator", "policy_sha256": "…" }
}
```

```json
{ "ok": false, "target": "app-host", "error": { "code": "path_denied", "message": "…" } }
```

Server error codes (closed set, defined in Session 2): `validation_error`, `unknown_target`, `target_unreachable`, `host_key_mismatch`, `auth_failed_ssh`, `gate_unavailable`, `protocol_mismatch`, `approval_pending`, `approval_declined`, `approval_invalid`, `approval_unavailable`, `timeout`, plus every gate code passed through unchanged. `profile_denied` exists for defence in depth only — tools outside the profile are not registered.

**Approval.** `approval_pending` has `ok: false`, since nothing ran. Envelopes of approval-gated tools may carry an `approval` object, `{id, status, url, expires_at, summary}`, with status `pending`, `approved`, `declined`, `expired` or `used` (`url` only under `SHELL_MCP_APPROVAL_METHOD=web`):

```json
{ "ok": false, "target": "app-host",
  "error": { "code": "approval_pending", "message": "Approval required. Show the user this URL exactly as written, without changing or shortening it: https://approve.example.test/approvals/<id>. …" },
  "approval": { "id": "<26 base32 characters>", "status": "pending", "url": "https://approve.example.test/approvals/<id>", "expires_at": "2026-10-16T12:05:00Z", "summary": "…" } }
```

Under `web`, the `approval_pending` message is, in server-generated words: "Approval required. Show the user this URL exactly as written, without changing or shortening it: `<url>`. The approver opens it from their bookmark or the server's notification, checks the operation, and approves with a code. Then call this tool again with the same arguments and `approval_id` `<id>`." The URL is built from `SHELL_MCP_APPROVAL_PUBLIC_URL` and the record id only, so it carries no string from the host or the caller.
