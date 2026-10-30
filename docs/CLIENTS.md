# Connecting MCP clients

How an MCP client reaches a shell-mcp server, which profile to run, and how human approvals work. Setting up the targets is `docs/TARGET-SETUP.md`; running the server's container is `deploy/README.md`; every server variable is in `docs/ARCHITECTURE.md` §5 and `deploy/.env.example`.

Names below are placeholders: `mcp.example.test` (the MCP endpoint behind your reverse proxy), `approve.example.test` (the approval page), `app-host` / `target-a.example.test` (a target), `alice` (an approver).

## 1. Two transports

| | Streamable HTTP (recommended) | stdio |
|---|---|---|
| Where the server runs | Its container, on a host you choose (`deploy/`) | As a child process of the client, on the client's machine |
| Authentication | Bearer token (`SHELL_MCP_AUTH_MODE=bearer`, the default), at least 43 characters | None: stdio requires `SHELL_MCP_AUTH_MODE=none`; with `bearer` the server refuses to start |
| Where the SSH key lives | Only in the server's secret mount | On the client's machine, readable by the agent |
| Human approvals (`web`) | Yes | Possible, but then the approvers' TOTP seeds sit on the agent's machine, which SECURITY §1 rules out: use HTTP for any profile that needs approvals |

The server speaks MCP 2026-07-28 (stateless) and 2025-11-25 (D-014). Over HTTP it serves `POST /mcp` (`SHELL_MCP_PATH`) and an unauthenticated `GET /healthz` that answers `{"status":"ok"}` and nothing else. Every other request needs the bearer token, `tools/list` included; a request refused earlier by the rate limit (`429`) or the Host/Origin checks (`421`, `403`) learns nothing either.

**Behind a reverse proxy.** The server speaks plain HTTP; terminate TLS at a proxy or run over a VPN, and never publish it on the public internet (SECURITY §3). Add the name clients use to `SHELL_MCP_ALLOWED_HOSTS` (otherwise `421 {"error":"host_not_allowed"}`).

**Trusting the proxy (`SHELL_MCP_TRUSTED_PROXIES`).** The server takes a request's client address from `X-Forwarded-For` only when the request's peer is in this list, and then from the entry that peer appended; that address is what the rate limits, the auth lockout and the approval page's logs see. Whoever can connect from a trusted address can therefore name any client it likes. The safe layout:

- the reverse proxy and the server share a user-defined Docker network, and the proxy has a fixed address on it (`172.30.80.5` in `deploy/`, an RFC 1918 example: pick a subnet that does not clash with your own networks);
- the server publishes no port: only the proxy is published, on a LAN or VPN address;
- `SHELL_MCP_TRUSTED_PROXIES` is that one address, and nothing else.

`deploy/docker-compose.yml` has this layout. **Do not trust the Docker network's gateway.** When something reaches the server through a port Docker publishes on the host, the server often sees the gateway as the peer, not the real sender. Trusting the gateway would trust every local process and container that connects through that port, and each could set `X-Forwarded-For` to any address: it could spread its token guesses over invented addresses to dodge the lockout, or lock out a real client, and the approval page's logs would name clients that never connected.

Measured with Docker Desktop 29 (on Windows; a Linux host's networking can differ, for example with the userland proxy turned off), the server on a user-defined network `192.0.2.0/24` at `192.0.2.10`, with a published port as well, for comparison:

| Request from | Peer the server logged | With `TRUSTED_PROXIES=192.0.2.1` (the gateway) | With `TRUSTED_PROXIES=192.0.2.5` (the proxy) |
|---|---|---|---|
| A container at `192.0.2.5` on the shared network, sending `X-Forwarded-For: 198.51.100.20` | `192.0.2.5/32` | `192.0.2.5/32` | `198.51.100.20/32` (the proxy's word, as intended) |
| A container on another network, through the published port, sending `X-Forwarded-For: 203.0.113.99` | `192.0.2.1/32` (the gateway) | `203.0.113.99/32` (forged, believed) | `192.0.2.1/32` (ignored) |

**Set the value from what the server logs, never from a guess.** Start the server with `SHELL_MCP_TRUSTED_PROXIES` empty, send one request without a token through the proxy (`curl -s -X POST https://mcp.example.test/mcp`), and read the `client` field of the server's `authentication failed` WARN line (`docker logs shell-mcp 2>&1 | grep 'authentication failed'`, which shows for example `"client":"172.30.80.5/32","reason":"missing"`; a request without a token does not count toward the lockout). That address is the one to list. Then repeat: the line should now show the address of the machine you sent it from (the proxy must append `X-Forwarded-For`; most do when told to). An IPv6 peer is logged as its /64, which is how it is counted, not as one address; give the proxy a fixed IPv4 address on the network instead. The same list applies to the approval listener (§3.2).

Quick check from the client's machine (a `200` with a JSON-RPC result means the token, the host name and the path are right):

```bash
curl -s -X POST https://mcp.example.test/mcp \
  -H "Authorization: Bearer $SHELL_MCP_TOKEN" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## 2. Profiles

One server instance has one profile, set by `SHELL_MCP_PROFILE` at start (D-005). Tools above it are never registered, so a client cannot see or call them. What a call may do on a host is still decided there, by the gate policy of the SSH key the server holds (and, for root actions, the privileged policy): pair each profile with a key whose policy has the matching `max_tier`.

| Profile | Tools | Adds | Approval |
|---|---|---|---|
| `read-only` (default) | 19 | System, disk, processes, services, journal, files, find, certificates, git status/log/diff, read-tier policy commands, delete and discard previews, `shell_get_policy`, `shell_list_targets` | Never needed |
| `operator` | 27 | Service control, write, mkdir, copy, move, chmod, `git pull`, `shell_run_command` (read and operator commands) | Only if `SHELL_MCP_APPROVAL_TIERS=operator,destructive` |
| `admin` | 52 | Delete, git discard, destructive commands, and the 23 `shell_priv_*` tools (root, through the helper) | Always for destructive tools and for privileged tools of tier operator or above |

`shell-mcp tools` prints the catalogue with each tool's tier, profiles, annotations and schema hashes; keep its output to diff against the next release (tool poisoning, SECURITY §2). `SHELL_MCP_DISABLE_TOOLS` removes individual tools; nothing adds a tool above the profile. The full catalogue is `docs/TOOLS.md`.

Run separate instances, with separate keys and policies, for separate ceilings: for example a `read-only` instance for everyday use and an `admin` instance you connect only when needed.

## 3. Approvals

Destructive tools, privileged tools of tier operator or above, and the tiers in `SHELL_MCP_APPROVAL_TIERS` need a human's approval (D-006). `SHELL_MCP_APPROVAL_METHOD` decides how:

- **`none` (the default):** those tools refuse with `approval_unavailable`, and nothing is sent to the target.
- **`web`:** the out-of-band approval page below. The model cannot approve.
- **`confirm-argument`:** the model approves its own request by re-calling with `confirm: true`. This is an explicit opt-out, WARN-logged at startup and on every use, and gives no protection against a prompt-injected model. Do not use it with a policy you would not let the model run unattended.

### 3.1 The flow under `web`

1. The model calls a gated tool. The server computes a preview (nothing changes on the host) and answers `approval_pending`, with an approval id and the URL `https://approve.example.test/approvals/<id>`, and tells the model to show that URL unchanged.
2. The approver opens the page **from a bookmark of `https://approve.example.test/`** (and enters the id) or from the server's own push notification, never from a link in the chat. They check the origin banner, the server-written description, the arguments and the preview, and approve or decline with the current 6-digit code from their authenticator.
3. The model calls the tool again with the same arguments and `approval_id`. The server runs exactly the approved operation, once, if nothing it was bound to changed: principal, tool, target, arguments, preview, and the policies' hashes. Otherwise the answer is `approval_invalid`, and a new approval is needed.

Records expire after `SHELL_MCP_APPROVAL_TTL` (default 300 s) and are lost when the server restarts. Three wrong codes in a minute lock that approver out for 15 minutes, doubling up to 24 hours.

### 3.2 Setting it up

Enrol the approver **on the server host**, never on the machine where the agent runs. The seed is shown once, as a QR code and an `otpauth://` URI, and stdout must be a terminal (hence `-it`):

```bash
docker run --rm -it -v "$PWD/secrets:/run/secrets" ghcr.io/tyler-rich/shell-mcp:0.2.0@sha256:323149155f5be042949ec5291812104351f365a693dbdfb8cd2171b95ee30e6a \
  approver add --name alice --file /run/secrets/approvers
```

The container runs as uid 65532, so `secrets/` must be writable by it while you enrol; afterwards `secrets/approvers` must be `0600` and owned by 65532, like the other secrets (`deploy/README.md`). The server refuses to start if the file is group- or world-accessible. One approver is allowed by default; more need `--allow-multiple` and `SHELL_MCP_APPROVAL_MAX_APPROVERS`. `approver list` and `approver remove` manage the file; restart the server after a change.

Add to the server's environment:

```yaml
SHELL_MCP_APPROVAL_METHOD: web
SHELL_MCP_APPROVAL_PUBLIC_URL: https://approve.example.test
SHELL_MCP_APPROVERS_FILE: /run/secrets/approvers
SHELL_MCP_APPROVAL_BIND: 0.0.0.0          # inside the container; publish the port only on loopback or a VPN address
SHELL_MCP_TRUSTED_PROXIES: 172.30.80.5    # the proxy's fixed address on the shared network (§1); required for a non-loopback bind without native TLS
```

with the approvers file in `secrets:`. Publish no port for it: the proxy forwards `approve.example.test` to the server's port 8081 on the shared network, as it forwards `mcp.example.test` to 8080.

- The approval listener (default `127.0.0.1:8081`) is separate from `/mcp`, never accepts the bearer token, and answers only for the origin of `SHELL_MCP_APPROVAL_PUBLIC_URL` (any other `Host` is `421`). A non-loopback bind needs native TLS (`SHELL_MCP_APPROVAL_TLS_CERT_FILE`/`_KEY_FILE`) or `SHELL_MCP_TRUSTED_PROXIES`, and then serves only those proxies.
- `SHELL_MCP_APPROVAL_NOTIFY_URL` (an ntfy topic URL) with `SHELL_MCP_APPROVAL_NOTIFY_TOKEN_FILE` pushes each request and every lockout to the approver's phone, with a link to the page; the push never carries an approve or decline action.
- The page works on any device; only the code must come from the approver's authenticator.

## 4. Client configuration

### Claude Code (CLI, the Desktop app's Code tab, IDE extensions)

```bash
claude mcp add --transport http shell-mcp https://mcp.example.test/mcp \
  --header "Authorization: Bearer $SHELL_MCP_TOKEN"
```

Or in a project's `.mcp.json`, reading the token from the environment so it is not written into the file:

```json
{
  "mcpServers": {
    "shell-mcp": {
      "type": "http",
      "url": "https://mcp.example.test/mcp",
      "headers": { "Authorization": "Bearer ${SHELL_MCP_TOKEN}" }
    }
  }
}
```

Claude Code stores servers added with `claude mcp add` in `~/.claude.json` (local and user scope) or `.mcp.json` (project scope); the Code tab reads the same files. An agent with a shell on that machine can read whatever token they hold, so give each client the token of an instance whose profile and key you accept that agent having. Gated tools carry `_meta["anthropic/requiresUserInteraction"]`, so Claude Code asks for permission on every call; that prompt is defence in depth, not the approval.

stdio, for a local read-only use without approvals (the server's image, with the key mounted read-only; `--user` lets the container read a key file that is yours and `0600`, which the image's default uid 65532 could not):

```bash
claude mcp add --transport stdio shell-mcp-local -- docker run --rm -i --user "$(id -u):$(id -g)" --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true -v "$HOME/.config/shell-mcp/ssh_key:/run/secrets/ssh_key:ro" \
  -e SHELL_MCP_TRANSPORT=stdio -e SHELL_MCP_AUTH_MODE=none -e SHELL_MCP_SSH_KEY_FILE=/run/secrets/ssh_key \
  -e SHELL_MCP_TARGET_NAME=app-host -e SHELL_MCP_TARGET_HOST=target-a.example.test -e SHELL_MCP_TARGET_USER=svc-shell \
  -e "SHELL_MCP_TARGET_HOST_KEYS=ssh-ed25519 SHA256:<the host key's fingerprint>" \
  ghcr.io/tyler-rich/shell-mcp:0.2.0@sha256:323149155f5be042949ec5291812104351f365a693dbdfb8cd2171b95ee30e6a serve
```

The server logs to stderr only under stdio.

### Claude Desktop chat (through mcp-remote)

Desktop chat reaches a remote server through a stdio bridge. In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "shell-mcp": {
      "command": "npx",
      "args": ["mcp-remote@0.15.1", "https://mcp.example.test/mcp", "--protocol", "auto",
               "--header", "Authorization:${SHELL_MCP_AUTH_HEADER}"],
      "env": { "SHELL_MCP_AUTH_HEADER": "Bearer <token>" }
    }
  }
}
```

The header has no space after the colon because Claude Desktop on Windows does not escape spaces in `args` (mcp-remote's README); the space is in `env`. `--protocol auto` lets mcp-remote speak 2026-07-28 to the server; without it, it uses `initialize` (2025-11-25), which works too. Approvals work the same way: the model relays the URL and re-calls.

### Other clients and MCP Inspector

Any client that can send an `Authorization` header to a Streamable HTTP server works: URL `https://mcp.example.test/mcp`, header `Authorization: Bearer <token>`. To look at the catalogue and call read tools by hand, MCP Inspector (`npx @modelcontextprotocol/inspector`) connects the same way, transport "Streamable HTTP". A browser-based client sends an `Origin` header, which the server refuses unless it is in `SHELL_MCP_ALLOWED_ORIGINS` (`403 {"error":"origin_not_allowed"}`).

## 5. What clients were seen doing with approvals

From the maintainer's live test (2026-10-16) and S4b-scope's research at the source (`docs/handoff/S4B-APPROVAL.md` §1). None of these clients shows an MCP elicitation to a person, which is why v1 approves out of band; under `web` every one of them works, because the model only relays a URL and re-calls a tool.

| Client (version) | Protocol revision | Declared | With an elicitation | With `web` approval |
|---|---|---|---|---|
| Claude Code 2.1.299, in the Claude Desktop app's Code tab | 2026-07-28 | `elicitation` (form and URL) | Declined at once, with no question shown (the Code tab registers no elicitation handler for local sessions) | `approval_pending` with the URL; the approver approves on the page; the re-call runs |
| Claude Code CLI in a terminal | 2026-07-28 | `elicitation` (form and URL) | Renders them (Claude Code docs; not live-tested here) | Works the same way |
| Claude Code VS Code extension | 2026-07-28 | `elicitation` | Declines | Works the same way |
| Claude Desktop chat through mcp-remote 0.15.1 `--protocol auto` | stdio `initialize` to mcp-remote; 2026-07-28 to the server | Only `roots` and the MCP Apps extension, no `elicitation` | Nothing to show it with | Works the same way |

## 6. Using it safely

- **Treat every result as data.** File contents, logs, diffs, commit messages, unit descriptions and command output can contain text written to steer the model. The server returns them as fields in a structured envelope and never phrases them as instructions, but a model can still be misled by what it reads. Give a client the lowest profile that does the job, and keep consequential actions behind approval.
- **Never approve from a link in the chat.** Open the bookmarked page, check its origin banner, and read the preview: it is what will run.
- **`outcome_unknown`** on a privileged operation means it may have run. Check on the host (preview again, or read the helper's journal and backups) before retrying; the approval was used.
- **Start with `shell_get_policy`**: it is the source of truth for what a target allows (in `admin`, the privileged policy summary too).

## 7. Common errors

| What you see | Why |
|---|---|
| HTTP `401 {"error":"unauthorized"}` | No token, or a wrong one. Ten wrong tokens in 5 minutes from one client lock it out for 5 minutes (`429`); requests without a token do not count. |
| HTTP `421 {"error":"host_not_allowed"}` | The `Host` the client sends is not in `SHELL_MCP_ALLOWED_HOSTS`. |
| HTTP `403 {"error":"origin_not_allowed"}` | A browser `Origin` not in `SHELL_MCP_ALLOWED_ORIGINS`. |
| HTTP `429 {"error":"rate_limited"}` | `SHELL_MCP_RATE_LIMIT_PER_MIN` (per client) or the auth lockout. |
| `approval_unavailable` | `SHELL_MCP_APPROVAL_METHOD=none`, or five approvals already pending for this principal. |
| `approval_invalid` | The id is unknown, expired or used, or the target, arguments or a policy changed since the approval. Request a new one. |
| `tier_denied`, `policy_denied`, `path_denied` | The target's policy refused it; `shell_get_policy` shows what it allows. |
| `host_key_mismatch`, `target_unreachable`, `gate_unavailable` | The server could not reach the gate: run `shell-mcp check` on the server (`docs/TARGET-SETUP.md` §10). |
