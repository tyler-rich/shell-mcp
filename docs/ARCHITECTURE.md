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
- **The container holds no host access.** No Docker socket, no host mounts, no capabilities. Its secrets are the MCP bearer token and the SSH private key(s) and, with web approvals, the approvers file (TOTP seeds) and the optional notify token. Its only egress is SSH to configured targets, plus the notify URL when one is set.
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
| `internal/gate/execx` | Template matching, argv construction, scrubbed env, `SysProcAttr{Setpgid, Pdeathsig}`, rlimits in force before the command's first instruction (`RLIMIT_CORE=0`, `RLIMIT_NOFILE`, `RLIMIT_NPROC` and `RLIMIT_DATA` at the policy's `limits.max_memory_mb`, soft and hard, without which nothing runs; POLICY §4a) (the running binary re-executes itself as a trampoline: it reads the command from an inherited socketpair, lowers its own limits with `setrlimit(2)`, marks every descriptor above stderr close-on-exec and `execve(2)`s the command; it refuses any other way of being started), output capture with per-stream caps, timeout SIGTERM→SIGKILL on the process group, exit-code/signal reporting. Used by the gate and the helper. |
| `internal/gate/ops` | One file per op (§4.3). Each op declares its tier; the dispatcher refuses ops above min(`max_tier`, the request's `ceiling`) before doing anything else. |
| `internal/gate/audit` | One syslog line per request (authpriv; info on success, notice on refusal): request id, the request's tier `ceiling` (empty when the request was refused before it was read), principal, client address (`SSH_CONNECTION`), op, sanitized args (paths, units, ids, flags; an argument list only as its count), outcome, duration and, for a delete or a discard that set an entry aside and could not put it back, that entry's temporary path (`set_aside`), as one JSON object. Never content, stdin, output or environment. One datagram to `/dev/log` with a 250 ms dial and write deadline: a missing socket or full queue never blocks the request. |
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
| `internal/privd/pkg` | apt (broad unit): the fixed apt-get argv per operation (unpinned for previews, pinned to the approved transaction for the run), Debian package-name validation, the `-s` simulation parser behind the previews and its hash, the bounded dpkg status reader, its diff and the unfinished-state check, the dpkg lock holder, and a bounded wait for a held dpkg or lists lock. |
| `internal/privd/dbus` | The smallest D-Bus client the power operations need (broad unit): EXTERNAL authentication, Hello, one method call at a time with string and `uint64` arguments, strict bounded decoding of basic types, structs, arrays and variants; standard library only. |

## 3. Request lifecycle

1. **HTTP:** body ≤ 1 MiB (413; a declared length over the cap is refused before anything else, and every body is bounded while it is read) → global rate limit (429 with `Retry-After`, per client: an IPv4 address or an IPv6 /64) → Host/Origin allow-list (421 for a `Host` not on the list, 403 for an `Origin` not on it) → bearer auth (401 with `WWW-Authenticate`; 10 failures in 5 min per client → 429 for 5 min, and while locked every request is refused before its credential is looked at) → SDK dispatch. Only a presented credential that does not authenticate counts toward that lockout: an `Authorization` header that is not a matching bearer token, another scheme, a malformed value, or more than one `Authorization` header. A request with no `Authorization` header gets the same 401 and is still subject to the global rate limit, but it does not count. The lockout exists to stop token guessing, and such a request guesses nothing. Clients probe OAuth discovery without credentials before connecting, and counting those probes locked clients out of a freshly started server. Each failure is logged at WARN with its `reason` and `counts_toward_lockout`. The global limiter logs the first refusal of each run as `request refused` with `reason: rate_limited`, so its 429 can be told apart from the lockout's. Every path except `/healthz` is behind the chain, so an unauthenticated request learns nothing, not even which paths exist. Refusals are `{"error":"<code>"}` with `request_too_large`, `rate_limited`, `host_not_allowed`, `origin_not_allowed` or `unauthorized`. Only registered tools exist.
2. **Tool:** strict argument decoding → semantic validation (target exists, path absolute and clean, sizes) → the tool's registered tier becomes the `ceiling` of every gate request it makes → for an approval-gated tool (destructive, privileged operator+, or a tier in `SHELL_MCP_APPROVAL_TIERS`; for `shell_run_command`, the tier of the command its `exec_preview` resolves, decided after that preview, with an unapproved `exec` sent at the highest tier that needs no approval: TOOLS.md, Destructive tier; for `shell_priv_run_command`, likewise after `priv_exec_preview`, with an unapproved `priv_exec` sent at ceiling `read`: TOOLS.md, Privileged tier), per `SHELL_MCP_APPROVAL_METHOD`:
   - `none`: refuse with `approval_unavailable`; nothing is sent.
   - **First call (no `approval_id`):** compute the preview through the gate's read operations → create an approval record {pending} bound to principal, tool, target, canonical-args SHA-256, preview SHA-256 and the gate's policy SHA-256 (for a privileged operation, the SHA-256 of `gate:<gate policy SHA-256>\nhelper:<privileged policy SHA-256>`, from the responses' `gate` and `helper` blocks; a privileged answer without both is refused with `internal`) (an identical pending request returns the same record; at most 5 pending per principal) → push a notification (optional) → return `approval_pending` with `{id, status, url, expires_at, summary}` and the instruction to show the URL unchanged.
   - **Approver:** opens the bookmarked page (enters the id) or taps the push → POST approve or decline with a TOTP code and the record's CSRF token → record {approved | declined by <name>}.
   - **Re-call (`approval_id`):** a pending record waits up to 20 s (never past expiry) and returns `approval_pending` again; declined → `approval_declined`; otherwise the record must be approved, unexpired, unused and match every bound field → mark used → fresh preview, whose hash and policy hash must equal the record's → gate request with the tool's ceiling and, where the operation supports it, the preview's precondition (`expected_sha256` of the content it saw, or `expect_absent` when it saw no file; for `copy`, `move`, `priv_copy` and `priv_move` with `overwrite`, `expected_destination_sha256` of the destination it saw, or `overwrite` false when it saw none; for `delete`, `git_discard`, `exec`, `priv_chown`, `priv_chmod`, `priv_delete`, `priv_restore_backup`, `priv_exec` and the `priv_pkg_*` operations, the fresh preview's `preview_sha256` (from `delete_preview`, `git_discard_preview`, `exec_preview`, `priv_chown_preview`, `priv_chmod_preview`, `priv_delete_preview`, `priv_restore_preview`, `priv_exec_preview` or the matching `priv_pkg_*_preview`) as `expected_preview_sha256`, and for `priv_exec` the unit `priv_exec_preview` reported as its routing label `unit`). Anything else is `approval_invalid`.
   - `confirm-argument`: the same record; the re-call with `approval_id` and `confirm: true` approves it as `model (confirm-argument)` (WARN).
3. **SSH:** reuse or open the target connection (host key verified on every new connection) → new session → exec `shell-mcp-gate/1` (sshd ignores it and runs the forced command; the gate reads it from `SSH_ORIGINAL_COMMAND` as a protocol hello) → write request → read response → close session.
4. **Gate:** check own install (not root, no privileged groups, policy/binary ownership) → load policy → **set `no_new_privs` and apply Landlock** → only now read and parse the request (bounded; a missing or unknown `ceiling` is `bad_request`) → tier ≤ min(`max_tier`, `ceiling`) (for `exec`, the command's own tier) → op-specific validation against policy → execute → redact → respond → audit → exit. For `priv_*` ops: check `privileged.enabled` and tier ≤ min(`privileged.max_tier`, `ceiling`) → pick the socket: `privileged.broad_socket` for `priv_pkg_*` (and their previews), `priv_power`, `priv_power_preview`, `priv_power_cancel`, and `priv_exec` whose `unit` argument is `broad` (a label the server supplies, since the gate cannot read the privileged policy); `privileged.socket` for everything else; a broad route without `broad_socket` is `privileged_disabled`; a malformed `unit` is `bad_request` → connect to the helper socket → forward the request (the same `v`, `id`, `ceiling`, `op` and `args` bytes as received; `timeout_ms` set to the timeout the gate waits for: the request's, clamped to `limits.max_timeout_s`, or `limits.default_timeout_s` when it has none, so the helper's deadline is never later than the gate's) → read one response (≤ 4 MiB, strictly decoded, within that timeout plus 15 s; 7 s before that deadline the gate shuts down its sending side, which tells the helper it stopped waiting, and keeps reading: PRIVILEGED §6, "Timeouts, and a gate that goes away") → return the helper's `ok`, `data`, `error` and `warnings` under the gate's own `gate` block, with the helper's own block as `helper` (§4.2). An unreachable socket is `helper_unavailable`; a helper error passes through with its code, including the `helper_*` self-check codes, which the helper may answer before the request is even sent. When no answer comes back after the request was sent: for a request that can change the host (an operation above read tier, or `priv_exec` above ceiling `read`: `protocol.PrivMayChange`), no answer in time, a connection closed without a byte and an unreadable answer are each `outcome_unknown`: the operation may have run on the host (handoff must-fix (b), S4c-6); for any other request, an unreadable response is `helper_unavailable`, a connection closed without a byte (a peer that failed the helper's peer check gets that) `helper_refused`, and no answer in time `timeout`.
5. **Helper** (privileged ops only): systemd accepts the connection and starts an instance → peer check from the connection and the unit alone: stdin, the unit's client uid, `SO_PEERCRED` (any failure: close without a byte, WARN journal line) → self-checks (uid, NoNewPrivs, binary) → load privileged policy → policy hash, `client_uid` and bounding set against the unit (any failure: a `helper_*` response without an id, WARN journal line) → which unit it runs in (`SHELL_MCP_PRIVD_UNIT`) → Landlock (core unit only; a failure is a `helper_sandbox_unavailable` response without an id) → read request → the op belongs to this unit, else `helper_wrong_unit` (the helper is authoritative for routing: nothing meant for the other unit runs here) → tier ≤ min(`max_tier`, `ceiling`) (for `priv_exec`, the command's own tier) → validation against the privileged policy → backup → execute (for `priv_exec` and `priv_pkg_update_index`, watching the connection: a hang-up stops the command, and everything it started is killed before the answer; for `priv_pkg_install`, `_upgrade` and `_remove`, the one exception: a hang-up or the request's deadline gets an early `outcome_unknown` answer while apt-get is left to finish, stopped with `SIGINT` before `limits.max_timeout_s` and killed only at it, and the journal line is written when it ends; PRIVILEGED §6) → verify → redact → respond → journald audit → exit.
6. **Server:** map response → envelope (an answer lost after the request was sent, on a privileged request that can change the host, is `outcome_unknown`, §6) → audit line.

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
- `timeout_ms` is clamped to the policy's `limits.max_timeout_s` (absent or 0: `limits.default_timeout_s`). For a `priv_*` op the gate forwards that value as the request's `timeout_ms`, and the helper clamps it again to its own `limits.max_timeout_s` (PRIVILEGED §6). This was amended in place before any release (ARCHIVE §14, 2026-10-18 S4c-1); before, the gate forwarded the request's value unchanged.
- Request size ≤ 2 MiB (write content is carried as base64 in `args.content_b64`, ≤ `limits.max_write_bytes` after decoding).
- `write_file` and `priv_write_file` take at most one precondition: `expected_sha256` (the current content must have that SHA-256; otherwise `exists`, or `not_found` without a file) or `expect_absent: true` (the file must not exist, up to and including the commit; otherwise `exists`). Both together is `bad_request`. `expect_absent` is optional and defaults to false; it was added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-17), and an older gate refuses it as an unknown field (`bad_request`), never ignores it.
- `copy`, `move`, `priv_copy` and `priv_move` take an optional `expected_destination_sha256` (64 lowercase hex digits), valid only with `overwrite: true` (otherwise, or malformed, `bad_request`): the destination must be a regular file with that content when the commit is prepared, otherwise `exists` (`not_found` when it is gone), and nothing changes. `priv_backup_check {path}` is a read-tier core op. `priv_write_file`, `priv_copy` and `priv_mkdir` results gain `uid`, `gid` and, for names on the privileged policy's `owners`, `owner` and `group`. These were added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-18 S4c-2; handoff P-9, P-11, P-12); an older helper refuses the field or op as unknown (`bad_request`, `unknown_op`). The gate's `copy` and `move` gained the field the same way (ARCHIVE §14, 2026-10-19, the gate's verified replaces; approved by the maintainer as P-9 for the gate); an older gate refuses it as an unknown field (`bad_request`), never ignores it. A gate `write_file` with `expected_sha256`, and a `copy` or `move` with the field, commits as a verified replace (POLICY §3).
- `delete` requires `expected_preview_sha256`: the `preview_sha256` that `delete_preview` returned for the same `path` and `recursive`, 64 lowercase hex digits (missing or malformed is `bad_request`). The gate walks the tree again and refuses with `exists`, deleting nothing, unless its hash is the same (POLICY §3). `delete_preview` does not take it. It was added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-18); a gate without it refuses the field as unknown (`bad_request`).
- `git_discard` requires `expected_preview_sha256`, the `preview_sha256` that `git_discard_preview` returned for the same `repo` and `include_untracked` (missing or malformed is `bad_request`; another hash is `exists`, and nothing is changed). Both ops take an optional `include_untracked` (default false). `exec` takes an optional `expected_preview_sha256`, the `preview_sha256` that `exec_preview` returned for the same `command_id`, `args` and `cwd`: when given, malformed is `bad_request` and another hash is `exists`, and nothing runs. `exec_preview` takes `command_id`, `args` and `cwd` only. These fields and the `exec_preview` op were added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-18 S4b-2b); an older gate refuses them as unknown fields or an unknown op.
- `priv_chown` and `priv_chmod` require `expected_preview_sha256`: the `preview_sha256` that `priv_chown_preview` or `priv_chmod_preview` returned for the same arguments (missing or malformed is `bad_request`; another hash is `exists`, and nothing is changed). All four take an optional `recursive` (default false). The previews take the same arguments without the hash, and return `{path, type, entries, changes, first, truncated, policy_sha256, preview_sha256}` (PRIVILEGED §6). These were added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-19 S4c-3; handoff P-2b, P-3, P-4); an older helper refuses them as unknown fields or an unknown op (`bad_request`, `unknown_op`).
- `priv_delete` requires `expected_preview_sha256`: the `preview_sha256` that `priv_delete_preview` returned for the same `path` and `recursive` (missing or malformed is `bad_request`; another hash is `exists`, and nothing is deleted or backed up). `priv_delete_preview` takes `{path, recursive}` without the hash, and returns `{path, type, entries, bytes, first, truncated, backup: {written, kind, bytes}, policy_sha256, preview_sha256}`; its hash also covers the privileged policy's (PRIVILEGED §6, "Delete"). Both were added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-19 S4c-4; handoff P-2a, P-3); an older helper refuses them as an unknown field or op. `priv_delete`'s result is unchanged: `{path, type, entries, bytes, first, deleted, backup_ids}`.
- `priv_restore_backup` requires `expected_preview_sha256`: the `preview_sha256` that `priv_restore_preview` returned for the same `id` (missing or malformed is `bad_request`; another hash is `exists`, and nothing is restored or backed up). `priv_restore_preview` takes `{id}` and returns `{id, kind, path, backup, current, restore, current_backup, policy_sha256, preview_sha256}`; `restore` carries the mode that will be set beside the recorded one (and for a tree the first 50 entries' modes), and `priv_restore_backup`'s result gains `mode`, `recorded_mode`, `narrowed`, `first` and `truncated` (PRIVILEGED §6, "Restore"). These were added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-19 S4c-5; handoff P-2c, P-3, P-10); an older helper refuses them as an unknown field or op (`bad_request`, `unknown_op`).
- `priv_exec` takes `expected_preview_sha256`: the `preview_sha256` that `priv_exec_preview` returned for the same `command_id`, `args` and `cwd`, required for an operator or destructive command and optional for a read command (missing where required, or malformed, is `bad_request`; another hash is `exists`, and nothing runs). `priv_exec_preview` takes `{command_id, args, cwd}` (no `unit` label: it always goes to the core socket, for commands of either unit) and returns `{command_id, tier, unit, description, root_equivalent, capabilities, template, argv, cwd, policy_sha256, preview_sha256}` (PRIVILEGED §6, "Commands"). These were added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-20 S4c-6; handoff P-2d, P-3); an older helper refuses them as an unknown field or op (`bad_request`, `unknown_op`).
- `priv_pkg_update_index`, `priv_pkg_install`, `priv_pkg_upgrade` and `priv_pkg_remove` require `expected_preview_sha256`: the `preview_sha256` that `priv_pkg_update_index_preview`, `priv_pkg_install_preview`, `priv_pkg_upgrade_preview` or `priv_pkg_remove_preview` returned for the same arguments (missing or malformed is `bad_request`; another hash, or a pinned simulation whose transaction differs from the approved one, is `exists`, and nothing runs). `priv_pkg_update_index_preview` takes `{}` and returns `{argv, policy_sha256, preview_sha256}`; the three other previews gain `argv`, `policy_sha256` and `preview_sha256`; the install, upgrade and remove results gain `applied` (`{install[], upgrade[], remove[]}`, what dpkg's status shows changed) (PRIVILEGED §6, "Package operations"). These were added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-21 S4c-7; handoff P-2e, P-3, P-5, P-6); an older helper refuses them as an unknown field or op (`bad_request`, `unknown_op`).
- `priv_power` requires `expected_preview_sha256`: the `preview_sha256` that `priv_power_preview` returned for the same `action` (missing or malformed is `bad_request`; another hash is `exists`, and nothing is scheduled). `priv_power_preview` takes `{action}` and returns `{action, target, delay_s, policy_sha256, preview_sha256}`; `priv_power` returns `{action, target, scheduled_at, delay_s, cancel}`, answered before the action is requested; `priv_power_cancel` takes `{}` and returns `{cancelled, request_id, action, scheduled_at}` (PRIVILEGED §6, "Power"). These were added to protocol v1 in place, before any release, replacing the S1d `priv_power` result `{action, target, job}` (ARCHIVE §14, 2026-10-22 S4c-8; handoff P-2f, P-3, P-13); an older helper refuses them as an unknown field or op (`bad_request`, `unknown_op`).
- `priv_policy` takes `{}` and returns the privileged policy summary (PRIVILEGED §6, "The policy summary"): what the helper enforces, with the operations it allows by tier and unit, its commands, and the N-13 findings; never a `paths.deny` value or `acknowledge` text. A read-tier core op, added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-22 S4c-9; handoff P-8, amended with `ops`, `findings`, `deny_patterns` and `roots.persistence`); an older helper or gate refuses it as `unknown_op`.

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

A response the gate forwarded from the privileged helper also carries `helper`, the helper's own block as the helper sent it: `version`, `principal` (`shell-mcp-privd`), `policy_sha256` (the privileged policy's), `max_tier`, `unit` (`core` or `broad`: the unit whose instance answered; empty only when it refused before knowing) and `duration_ms`. `gate` stays the gate's own. A response the gate answered itself, including a `priv_*` op it refused before connecting, has no `helper`; nor has a helper refusal that carried no block. `unit` appears only in a helper's block. The server binds `helper.policy_sha256` into approvals of privileged operations (§3 step 2). `helper` and `unit` were added to protocol v1 in place, before any release (ARCHIVE §14, 2026-10-18 S4c-1); an older server refuses `helper` as an unknown field (`protocol_mismatch`), never ignores it.

```json
{ "v": 1, "id": "0b5c…", "ok": true, "data": { … }, "warnings": [],
  "gate":   { "version": "0.1.0", "principal": "admin-key", "policy_sha256": "…", "max_tier": "destructive", "duration_ms": 31 },
  "helper": { "version": "0.1.0", "principal": "shell-mcp-privd", "policy_sha256": "…", "max_tier": "operator", "unit": "core", "duration_ms": 9 } }
```

Failure: `"ok": false, "error": {"code": "<closed set>", "message": "<one line, no content>"}`. Exec ops report process results in `data` (`exit_code`, `signal`, `stdout`, `stderr`, `stdout_truncated`, `stderr_truncated`, `timed_out`) and use `ok: true` whenever the process was started — a non-zero exit is data, not a gate error.

Gate error codes: `protocol_mismatch`, `bad_request`, `unknown_op`, `tier_denied`, `policy_denied`, `path_denied`, `not_found`, `not_a_directory`, `is_a_directory`, `too_large`, `exists`, `template_mismatch`, `not_authorized` (polkit denied), `sandbox_unavailable`, `privileged_disabled`, `helper_unavailable`, `helper_refused`, `backup_failed`, `exec_failed`, `timeout`, `verify_failed`, `install_insecure`, `internal`, `outcome_unknown` (a privileged request that can change the host may or may not have run: its answer was lost after it was sent, or its command was stopped by a hang-up; added to protocol v1 in place, before any release, ARCHIVE §14, 2026-10-20 S4c-6).

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
| `write_file`, `mkdir`, `copy`, `move`, `chmod` | operator | Native via `fsx` within `paths.write`; atomic; read-back verified. Create-only commits (`write_file` with `expect_absent`, `copy` and `move` without `overwrite`) refuse a destination that exists at the moment of the commit; bound replaces (`write_file` with `expected_sha256`, `copy` and `move` with `expected_destination_sha256`) replace only the file they checked, by `RENAME_EXCHANGE` checked afterwards (POLICY §3). |
| `git_pull` | operator | `git pull --ff-only --no-rebase --no-recurse-submodules` with hardening flags; the repo must be inside a write root; `remote.origin.url` and the URL git would use must equal the policy's (https) remote; refused on uncommitted tracked changes or a non-fast-forward. |
| `delete` | destructive | Native via `fsx` within `paths.write`; files and empty dirs, or recursive with `recursive: true` bounded by `limits.max_delete_entries`. The read-tier `delete_preview` returns type, entries, bytes, the first 50 entries and `preview_sha256` over the complete list; `delete` requires that hash as `expected_preview_sha256` and removes exactly the listed entries, or stops (POLICY §3). Never a root, a mount point, `.git` or the protected set; symlinks are removed, never followed. |
| `git_discard` | destructive | On a repo inside a write root, with git's index lock held: recompute `git_discard_preview` (read tier: tracked paths differing from HEAD with their work-tree identity and content hash, untracked paths as delete previews with `include_untracked`, and `preview_sha256`) and require `expected_preview_sha256`; set each listed file aside and check it; remove untracked paths through the delete; git builds HEAD's index in a temporary index and writes the restored files create-only (`checkout-index` without `-f`); verify with `status`; rename the temporary index onto `.git/index`. Never `reset --hard` or `clean -f`; no hook runs (POLICY §7). |
| `exec` | per command | Policy command by `id` + argv matched against its templates; tier from the command entry. With `expected_preview_sha256`, refused (`exists`) unless `exec_preview` would return that hash now. |
| `exec_preview` | read (the command's own tier is checked as for `exec`) | The same resolution as `exec` (tier, template, path placeholders, `cwd`), nothing run: command id, tier, description, `root_equivalent`, matched template, resolved argv and `cwd`, policy hash and `preview_sha256` (POLICY §4). |
| `priv_*` | per op | Forwarded to the helper when the gate policy enables it; the helper's op table is `docs/PRIVILEGED.md` §6, including the read-tier `priv_backup_check` the write tools' previews use, the read-tier `priv_chown_preview` and `priv_chmod_preview`, the read-tier `priv_delete_preview`, the read-tier `priv_restore_preview`, the read-tier `priv_exec_preview` (core socket; for commands of either unit), the read-tier `priv_policy` (core socket: the privileged policy summary, handoff P-8), the read-tier `priv_pkg_update_index_preview` (broad socket), and the read-tier `priv_power_preview` and `priv_power_cancel` (broad socket; the cancel is read tier only so that it is never approval-gated, and is not one of the operations that change nothing). |

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

Server error codes (closed set, defined in Session 2): `validation_error`, `unknown_target`, `target_unreachable`, `host_key_mismatch`, `auth_failed_ssh`, `gate_unavailable`, `protocol_mismatch`, `approval_pending`, `approval_declined`, `approval_invalid`, `approval_unavailable`, `timeout`, `outcome_unknown` (also a gate code; S4c-6), plus every gate code passed through unchanged. `profile_denied` exists for defence in depth only — tools outside the profile are not registered.

**Outcome unknown (`outcome_unknown`).** For a privileged request that can change the host (`protocol.PrivMayChange`: an operation above read tier, or `priv_exec` above ceiling `read`), the result is `outcome_unknown` whenever the operation may or may not have run: the gate's answer to a helper answer lost after the request was written (none by its deadline, a close without a byte, an unreadable or mismatched answer), the helper's answer for an operator or destructive command stopped by the gate's hang-up or whose leftover processes it could not confirm ended, and the server's own for a failure after the session started (its time budget, a session closed without an answer, an unreadable answer). It is never a refusal code. The message is human-readable: what to check on the host before retrying, that the approval was used, and the cause. `timeout` stays for read requests and for a privileged command the helper never started ("nothing was run"). It was added to the closed set in place, before any release (handoff must-fix (b), approved by the maintainer).

**Approval.** `approval_pending` has `ok: false`, since nothing ran. Envelopes of approval-gated tools may carry an `approval` object, `{id, status, url, expires_at, summary}`, with status `pending`, `approved`, `declined`, `expired` or `used` (`url` only under `SHELL_MCP_APPROVAL_METHOD=web`):

```json
{ "ok": false, "target": "app-host",
  "error": { "code": "approval_pending", "message": "Approval required. Show the user this URL exactly as written, without changing or shortening it: https://approve.example.test/approvals/<id>. …" },
  "approval": { "id": "<26 base32 characters>", "status": "pending", "url": "https://approve.example.test/approvals/<id>", "expires_at": "2026-10-16T12:05:00Z", "summary": "…" } }
```

Under `web`, the `approval_pending` message is, in server-generated words: "Approval required. Show the user this URL exactly as written, without changing or shortening it: `<url>`. The approver opens it from their bookmark or the server's notification, checks the operation, and approves with a code. Then call this tool again with the same arguments and `approval_id` `<id>`." The URL is built from `SHELL_MCP_APPROVAL_PUBLIC_URL` and the record id only, so it carries no string from the host or the caller.

## 7. Build, release and supply chain

**CI** (`.github/workflows/ci.yml`, required check `ci`; `codeql.yml`, `analyze (go)` and `analyze (actions)`): gofmt, `go vet` and golangci-lint (with every test-only build tag), `go test -race` on two pinned runner images (one per all-thread Landlock path, D-019), the test-only builds' own steps, the e2e runner-only guards, govulncheck, linux/amd64 and linux/arm64 builds checked by `scripts/release-binary-check.sh`, `deps-current` (D-013) and the scripts' self-tests, gitleaks, the image (build, release check of its binary, Trivy and Grype), and `e2e-host`. `scripts/ci-local.sh` runs the same gate in digest-pinned Linux containers, plus the release build twice (its files must be byte-identical).

**Releases** (`.github/workflows/release.yml`, `release-build.yml`; plan D-010, S-10). A release is a tag `vX.Y.Z` (SemVer, no suffix) on `main`; the tag is the only source of the version (`-X main.version`, `-X main.commit`).

1. **preflight** (`release.yml`): the tag's format; the tagged commit is on `main`; `ci` and `analyze (go)` succeeded on that exact commit (the dev → main merge commit; both workflows run on push to `main`); `CHANGELOG.md` has a `## [X.Y.Z]` section with text; the `release` environment exists with a required reviewer and admits only `v*.*.*` tags.
2. **build** (`release-build.yml`, reusable; contents: read): `scripts/release/build.sh` builds `shell-mcp`, `shell-mcp-gate` and `shell-mcp-privd` for linux/amd64 and linux/arm64 (`CGO_ENABLED=0 -trimpath -buildvcs=false`, each through the release check) and `shell-mcp_X.Y.Z_examples.tar.gz` (examples, `deploy/`, LICENSE, NOTICE; reproducible); the Dockerfile builds one image per platform (cross-compiled, no emulation), pushed only to a loopback registry inside the job, joined into one index and saved as an OCI layout with `cosign save`; syft writes a CycloneDX SBOM per binary and per platform image; `SHA256SUMS` covers every file. The helper's systemd units are not released: they are generated per policy (`shell-mcp-privd units`).
3. **verify** (contents: read): every file matches the digests `build` reported; the release check on all six binaries and on each image's binary, which must be byte-identical to the released `shell-mcp` of its platform; version stamps; SBOM contents; Trivy and Grype on each platform image; govulncheck on the source (not `-mode=binary`: the stripped release binaries have no symbol table, so it reports every vulnerability of every module they use); `deps-current`.
4. **approve** (a tag only): the `release` environment, the owner's approval, before anything is pushed, signed or attested.
5. **sign**: `cosign load` pushes the index and both images unchanged (same digests) as `ghcr.io/<owner>/shell-mcp:X.Y.Z`, the only tag; cosign keyless signs the index and both images, and each binary, the examples archive and `SHA256SUMS` (`<file>.sigstore.json`); `actions/attest` (with `subject-checksums: dist/SHA256SUMS`) records SLSA build provenance for every file `SHA256SUMS` lists and for the image index, but none for `SHA256SUMS` itself, which its cosign signature covers, and CycloneDX SBOM attestations for every binary and platform image; `scripts/release/verify.sh` verifies all of it as a user would, pinned to `https://github.com/<owner>/shell-mcp/.github/workflows/release-build.yml@refs/tags/vX.Y.Z` and the GitHub OIDC issuer, and checks that another ref's identity is refused.
6. **publish** (a tag only): a draft GitHub Release with every file, the bundles and notes (the CHANGELOG section and the verification commands), then published.

The signing workflow is the reusable `release-build.yml`, which also builds, so the provenance is SLSA v1.0 Build Level 3 as GitHub describes it for reusable workflows. Jobs that build hold no write permission and no OIDC token; approve, sign and publish inherit the caller's grant, and a dry run's caller grants no contents or packages write.

**Dry runs.** `workflow_dispatch` (with the version about to be tagged) and pull requests that touch the release files run the same workflow with `publish: false`: the build is stamped `X.Y.Z-dryrun.<commit>` (`0.0.0-dryrun.<commit>` for a pull request), the image goes to a loopback registry, signatures and attestations are real (they appear in the public transparency log and on the repository's attestations page, bound to the dry run's ref, which a release's verification refuses), and nothing is pushed to GHCR or released. Workflow artifacts between jobs are kept one day.
