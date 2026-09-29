# Architecture

## 1. Shape of the system

```
┌─────────────┐ Streamable HTTP  ┌──────────────────────────┐  SSH (pinned host key,  ┌──────────────────────────────────────────────────┐
│ MCP client  │ ── Bearer ─────▶ │ shell-mcp (container)    │── Ed25519 client key) ─▶│ target host                                      │
│ Claude Code │ ◀─ JSON ──────── │ auth → profile → approval│                         │  sshd → forced command:                          │
│ Desktop …   │  (+ elicitation  │ → tool → gate client →   │ ◀── one JSON response ──│  shell-mcp-gate  (service user, no_new_privs,    │
└─────────────┘   round trips)   │ envelope                 │                         │                   Landlock, gate policy)         │
                                 └──────────────────────────┘                         │      │ priv_* only, local Unix socket            │
                                                                                      │      ▼  (peer-UID checked by the kernel)          │
                                                                                      │  shell-mcp-privd (root, one instance per request, │
                                                                                      │   systemd sandbox, privileged policy, backups)    │
                                                                                      └──────────────────────────────────────────────────┘
```

Properties that follow from this shape:

- **Three gates, the host ones authoritative.** The server decides what is *advertised* (profile, D-005) and collects human approval (D-006). The gate decides what the service user may do (gate policy, D-016). The helper decides what root may do (privileged policy, D-021). Neither host component trusts the component that called it.
- **The container holds no host access.** No Docker socket, no host mounts, no capabilities. Its only secrets are the MCP bearer token and the SSH private key(s). Its only egress is SSH to configured targets.
- **No long-running privileged process anywhere.** sshd starts the gate per request; systemd starts a helper instance per connection. Both serve one request and exit.
- **Stateless server.** No MCP sessions (D-014). In-memory state is limited to rate limiters, the SSH connection pool and the approval nonce set, all bounded.

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
| `internal/approval` | D-006: builds the `input_required` result with the elicitation (preview in the message), mints and verifies the HMAC-bound `requestState`, keeps the bounded single-use nonce set, decides whether a tool call needs approval (tier, `priv_*`, `SHELL_MCP_APPROVAL_TIERS`, client capability, fallback). |
| `internal/auth` | Bearer middleware (constant-time compare over a list, one entry in v1), `Principal{Name, Profile}`. 401 with `WWW-Authenticate: Bearer realm="shell-mcp"` and body `{"error":"unauthorized"}`. |
| `internal/transport` | HTTP server: body cap → global rate limit → Host/Origin allow-list → auth → SDK handler (stateless Streamable HTTP, JSON responses). `/healthz` outside the chain. Timeouts set on `http.Server` (read header, read, write, idle). |
| `internal/sshx` | SSH client per target: pinned host keys (fingerprint list and/or known_hosts), Ed25519 signer from file, `HostKeyAlgorithms` restricted to what is pinned, connect timeout, keepalive, max concurrent sessions per target (default 4), reconnect with backoff. No agent, no forwarding, no PTY, no `Setenv`. |
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
| `internal/gate/execx` | Template matching, argv construction, scrubbed env, `SysProcAttr{Setpgid, Pdeathsig}`, rlimits, output capture with per-stream caps, timeout SIGTERM→SIGKILL on the process group, exit-code/signal reporting. |
| `internal/gate/ops` | One file per op (§4.3). Each op declares its tier; the dispatcher refuses ops above `max_tier` before doing anything else. |
| `internal/gate/audit` | One syslog line per request (authpriv; info on success, notice on refusal): principal, client address (`SSH_CONNECTION`), op, sanitized args (paths, units, ids, flags; an argument list only as its count), outcome, duration, as one JSON object. Never content, stdin, output or environment. One datagram to `/dev/log` with a 250 ms dial and write deadline: a missing socket or full queue never blocks the request. |
| `internal/gate/procfs`, `systemd`, `gitx`, `certs` | Bounded, fuzzed parsers for `/proc` and os-release, systemctl/journalctl arguments and output, git output and repository configuration, and certificates. |
| `internal/gate/sandbox` | Compute the Landlock ruleset from the policy (system read/execute paths, read roots, write roots, allowed TCP connect ports, IPC scoping) and apply it with `no_new_privs` to all threads before the request is read; report the effective ABI level. |
| `internal/template` | The argv-template engine shared by the gate and the helper (POLICY §4). |
| `internal/gate/polkit` | Generate the polkit rule for `services.control` (exact units × verbs, `subject.user` match, no wildcards); refuse if any unit name is not exact. |

### Helper (`cmd/shell-mcp-privd`) — normative detail in `docs/PRIVILEGED.md`

| Package | Responsibility |
|---|---|
| `internal/privd/peercred` | Read `SO_PEERCRED` on the systemd-provided socket; require `uid == client_uid`. |
| `internal/privd/policy` | Strict privileged policy; never list (A) and acknowledge list (B); owners, mode mask, backups, commands, packages. |
| `internal/privd/units` | Generate the core and broad socket/service units from the policy, embedding the policy SHA-256. |
| `internal/privd/selfcheck` | uid 0, `NoNewPrivs: 1`, capability bounding set ⊆ the generated unit's, ownership, policy hash, stdin is a socket. |
| `internal/privd/ops` | Privileged read/write/mkdir/chown/chmod/copy/move/delete with backups and read-back; backup list/restore; root exec through `internal/template` and the gate's exec engine. |
| `internal/privd/pkg` | apt: update index, install/remove allow-listed names, upgrade with `-s` simulation as the preview. |

## 3. Request lifecycle

1. **HTTP:** body ≤ 1 MiB (413) → global rate limit (429) → Host/Origin allow-list (403/421) → bearer auth (401; failures counted, 10/5 min/IP → 429 for 5 min) → SDK dispatch. Only registered tools exist.
2. **Tool:** schema validation (SDK) → semantic validation (target exists, path absolute and clean, sizes) → for tiers in `SHELL_MCP_APPROVAL_TIERS`: no valid approval → fetch the gate preview and return `input_required` with an elicitation (preview in the message) and a bound `requestState`; valid accepted approval → continue → gate request.
3. **SSH:** reuse or open the target connection (host key verified on every new connection) → new session → exec `shell-mcp-gate/1` (sshd ignores it and runs the forced command; the gate reads it from `SSH_ORIGINAL_COMMAND` as a protocol hello) → write request → read response → close session.
4. **Gate:** check own install (not root, no privileged groups, policy/binary ownership) → load policy → **set `no_new_privs` and apply Landlock** → only now read and parse the request (bounded) → tier ≤ `max_tier` → op-specific validation against policy → execute → redact → respond → audit → exit. For `priv_*` ops: check `privileged.enabled` and `privileged.max_tier` → connect to the helper socket → forward the request unchanged → return the helper's response.
5. **Helper** (privileged ops only): systemd accepts the connection and starts an instance → self-checks → peer-UID check → load privileged policy → Landlock (core unit) → read request → tier ≤ `max_tier` → validation against the privileged policy → backup → execute → verify → redact → respond → journald audit → exit.
6. **Server:** map response → envelope → audit line.

Every failure at steps 2–6 becomes a tool error in the envelope, never a transport error.

## 4. Gate wire protocol (version 1)

One request per SSH session, UTF-8 JSON, newline-terminated, on stdin. One response, same encoding, on stdout. The gate writes nothing else to stdout. Stderr is unused (the gate logs to syslog).

### 4.1 Request

```json
{
  "v": 1,
  "id": "0b5c…(uuid v4)",
  "op": "read_file",
  "args": { "path": "/srv/app/config.yaml", "max_bytes": 262144 },
  "timeout_ms": 30000
}
```

- `v` must equal the gate's protocol version, else `{"ok":false,"error":{"code":"protocol_mismatch"}}`.
- `op` must be a known op; `args` are op-specific and strictly decoded (unknown fields are errors).
- `timeout_ms` is clamped to the policy's `limits.max_timeout_s`.
- Request size ≤ 2 MiB (write content is carried as base64 in `args.content_b64`, ≤ `limits.max_write_bytes` after decoding).

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
| `write_file`, `mkdir`, `copy`, `move`, `chmod` | operator | Native via `fsx` within `paths.write`; atomic; read-back verified. |
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
| `SHELL_MCP_TRUST_PROXY` | `false` | Honour the first `X-Forwarded-For` hop for rate limiting. |
| `SHELL_MCP_RATE_LIMIT_PER_MIN` | `120` | Per client IP. |
| `SHELL_MCP_TARGETS_FILE` | — | YAML list of targets (below). Mutually exclusive with the single-target variables. |
| `SHELL_MCP_TARGET_NAME` / `_HOST` / `_PORT` / `_USER` | — / — / `22` / — | Single-target shorthand for stack-editor deployments. |
| `SHELL_MCP_TARGET_HOST_KEYS` | *(required)* | Comma list of pinned `SHA256:` fingerprints (list allows rotation). |
| `SHELL_MCP_SSH_KEY` / `_FILE` | *(required)* | OpenSSH-format Ed25519 private key, unencrypted. `_FILE` (a mounted secret) is recommended and wins. The plain variable also accepts the single-line standard base64 of the whole key file (recognised by the absence of a `-----BEGIN` header; it must decode to an OpenSSH private key), for environment stores that cannot hold multi-line values. |
| `SHELL_MCP_DEFAULT_TARGET` | — | Makes `target` optional when several targets exist. |
| `SHELL_MCP_SSH_CONNECT_TIMEOUT` | `10` | Seconds. |
| `SHELL_MCP_SSH_MAX_SESSIONS` | `4` | Concurrent sessions per target. |
| `SHELL_MCP_DEFAULT_TIMEOUT` / `_MAX_TIMEOUT` | `30` / `300` | Seconds for gate operations; the gate clamps further. |
| `SHELL_MCP_MAX_OUTPUT_BYTES` | `262144` | Per stream returned to the client (the gate cap may be higher). |
| `SHELL_MCP_APPROVAL_TIERS` | `destructive` | `destructive` or `operator,destructive`. Destructive operations and privileged operations of tier operator or above always need approval; adding `operator` also gates ordinary (unprivileged) writes. `destructive` cannot be removed. |
| `SHELL_MCP_APPROVAL_FALLBACK` | `deny` | For clients that do not declare elicitation: `deny` (refuse with `approval_unavailable`) or `confirm-argument` (explicit opt-out: a `confirm: true` argument is accepted; WARN at startup and on every use). |
| `SHELL_MCP_APPROVAL_TTL` | `120` | Seconds an approval request stays valid (30..600). |
| `SHELL_MCP_REDACT_PATTERNS` / `_FILE` | — | Extra regexes for output redaction (RE2 syntax), one per line. `_FILE` wins, for environment stores that cannot hold multi-line values. |
| `SHELL_MCP_LOG_LEVEL` / `_LOG_FORMAT` | `info` / `json` | stdio transport logs to stderr only. |

Targets file:

```yaml
targets:
  - name: app-host
    host: target-a.example.test
    port: 22
    user: svc-shell
    host_keys: ["SHA256:AAAA…placeholder…"]
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

Server error codes (closed set, defined in Session 2): `validation_error`, `unknown_target`, `target_unreachable`, `host_key_mismatch`, `auth_failed_ssh`, `gate_unavailable`, `protocol_mismatch`, `approval_declined`, `approval_invalid`, `approval_unavailable`, `timeout`, plus every gate code passed through unchanged. `profile_denied` exists for defence in depth only — tools outside the profile are not registered.
