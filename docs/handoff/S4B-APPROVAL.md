# S4b handoff: how approvals reach a human

> Session S4b-scope, 2026-10-16. Documentation only: no approval code exists or is proposed in this PR.
> It answers plan §5 (S4b-scope) and feeds S4b, S4c and S5's `docs/CLIENTS.md`.
> **Nothing here changes a locked decision by itself.** §7 gives exact new wording for D-006, S-12 and the other documents; it takes effect only when the maintainer accepts it (§11 lists the decisions).

## 0. Summary

- **Why the Code tab declines (§1).** The Desktop app's Code tab runs Claude Code as an Agent SDK host. When Claude Code receives an elicitation in that mode, it runs `Elicitation` hooks and then forwards the request to the host as an SDK control request. The SDK answers `decline` by itself when the host registered no `onElicitation` callback, and the Desktop app (2.42304.0, SDK 0.3.299) registers none for local Code-tab sessions. That is the immediate decline the maintainer saw. Verified in the installed binaries and in the SDK docs; three open upstream issues report the same. No setting, permission mode or documented hook makes the Code tab show the question to a person.
- **Recommendation (§5).** Out-of-band approval (option c). The first call returns `approval_pending` with an approval id and the URL of an approval page served by shell-mcp on its own listener. The human opens the page from the link or from an optional push notification. The page shows the server's own description of the operation. The human approves by entering a **current TOTP code from an authenticator on their phone**. The model then re-calls the tool with the approval id, and the server executes only that exact operation, once, within its TTL.
  - This works with every client, because the model only re-calls a tool.
  - The model cannot produce the code, and cannot change what the page shows.
  - `confirm-argument` stays as the explicit, logged, weaker opt-in.
  - Approval-gated tools also set Claude Code's `anthropic/requiresUserInteraction`, as client-side defence in depth.
  - Form elicitation, URL elicitation and MCP Apps are deferred. Each could later deliver the same approval record more conveniently, but none of them reaches a person through the maintainer's clients today.
- **The STOP condition does not apply.** D-006's goal can be met with both of the maintainer's clients.

## 1. Why the Code tab auto-declines

### 1.1 What was observed (ARCHIVE §14, 2026-10-16)

Claude Code 2.1.299 in the Desktop Code tab, protocol 2026-07-28, declared `elicitation: {form, url}`. Round 2 of `shell_diag_elicit` arrived with the request state echoed unchanged and the action `decline`, 0 ms after round 1. No question was shown; the only dialog was the tool-permission prompt.

### 1.2 The path an elicitation takes in the Code tab

| Step | What happens | Evidence |
|---|---|---|
| 1 | The Code tab runs its own copy of Claude Code (here 2.1.299), separately versioned from any CLI on `PATH`. | code.claude.com/docs/en/desktop ("runs its own copy of Claude Code"). Installed under `%APPDATA%\Claude\claude-code\<version>\<build-id>\claude.exe`. |
| 2 | It is hosted through the Claude Agent SDK. The Desktop app bundles SDK 0.3.299 and drives Claude Code over stream-json. | Desktop 2.42304.0's `app.asar` sets `CLAUDE_AGENT_SDK_VERSION="0.3.299"` and contains the SDK's `query()` and control-request handler. The CHANGELOG (2.1.282) speaks of "SDK-hosted sessions such as Claude Desktop". Issue #89858 reports the launch flags `--input-format stream-json --output-format stream-json`. |
| 3 | Inside Claude Code, a non-interactive session logs "Elicitation request received in print mode", runs `Elicitation` hooks first, and, if no hook answers, sends a control request `subtype: "elicitation"` to the host. | Strings and code in the installed 2.1.299 executable. A separate flag, `--permission-prompts none`, marks the host as not answering elicitations; Claude Code then returns `cancel` (not what was observed). |
| 4 | The SDK's control handler calls the host's `onElicitation` callback if one was registered; otherwise it returns `{action: "decline"}` at once. | The same handler in the SDK copy inside `app.asar` and inside the CLI executable. The SDK reference documents it: when `onElicitation` is not provided, "unhandled elicitation requests are declined automatically" (code.claude.com/docs/en/agent-sdk/typescript, Options). |
| 5 | Desktop registers no `onElicitation` for local Code-tab sessions. | In Desktop 2.42304.0, `onElicitation` occurs in `app.asar` only inside the SDK itself (its option destructuring, class field, constructor and handler); no caller passes it. The only caller that does is in the claude.ai web bundle for remote (cloud) Code sessions, behind a feature flag (`epitaxy_disable_mcp_elicitation`); that path does not serve local sessions. Issues #96043 ("`onElicitation` is never wired") and #89858 report the same from earlier builds. |

**Conclusion (verified at the installed source, consistent with the docs):** an elicitation from a local Code-tab session is answered `decline` by the SDK inside the Desktop app, within milliseconds, without any UI. It is a gap in the Desktop host, not a setting. The docs still say Claude Code "displays an interactive dialog" with "no configuration required" (code.claude.com/docs/en/mcp), and Anthropic consolidates the VS Code variant as a bug (#98256), so it may be fixed later. No fix date or statement was found.

**Upstream issues** (anthropics/claude-code, all open on 2026-10-16, no substantive staff reply):
- #89858: "MCP elicitation is answered `decline` by a controlling client that never drew a prompt (desktop app, --input-format stream-json, SDK 0.3.234)".
- #96043: "Desktop: MCP elicitation is declared but never presented — `onElicitation` is never wired…".
- #98256: the same in the VS Code extension ("auto-declined ("print mode") in interactive VSCode sessions", reports through 2.1.301).

### 1.3 Can anything make the Code tab show it?

| Lever | Effect | Source |
|---|---|---|
| Permission modes (Ask, Auto, Accept edits, Bypass) | None. Elicitation is not part of the permission system; issue reports show the same decline in manual and auto modes. | code.claude.com/docs/en/permission-modes (no mention); #89858 |
| settings.json keys | None renders elicitation. The only related key, `bareElicitationCapability` (2.1.287), is a per-server compatibility switch. | CHANGELOG 2.1.287 |
| `Elicitation` hook | Runs before the request reaches the host, and can answer `accept`/`decline`/`cancel` with content, so "no dialog appears". With no output it passes the request on, to the same automatic decline. | code.claude.com/docs/en/hooks#elicitation; the hook-first order in the 2.1.299 code |
| A hook that opens its own OS dialog | Would put a question in front of a person, but it is an undocumented use. The answer comes from a script in a settings file on the same machine and account the model's shell runs in (§3, option a). | Inference |

**Other Claude Code surfaces:**
- **The CLI in a terminal** renders form and URL elicitations: the docs say so, and third-party reports confirm it for 2.1.296 and 2.1.301. The maintainer's terminal `claude` is older (2.1.156), so live test T-1 (§10) checks this with the Code tab's own 2.1.299 build.
- **The VS Code extension** declines (#98256).
- **`claude -p`** cancels or declines unless a hook answers (code.claude.com/docs/en/headless).

**Claude Desktop chat.**
- **No elicitation, but MCP Apps.** Its `initialize` declared no elicitation, only the MCP Apps extension. No Anthropic document says chat supports elicitation. anthropics/claude-ai-mcp#153 ("Elicitation Support", open since 2026-04-06) has a user report that claude.ai declares only the `io.modelcontextprotocol/ui` extension.
- **mcp-remote can't help.** mcp-remote turns 2026-07-28 elicitations into legacy `elicitation/create` only if the stdio client declared elicitation, and it refuses URL mode outright. This is from its `main` source (`src/lib/protocol-era.ts`); the 0.15.1 tag was not diffed.

### 1.4 What this means

- **Form or URL elicitation can't approve on the maintainer's clients.** They reach a person through neither the Code tab nor Desktop chat. Of the Claude surfaces, only a terminal CLI shows one.
- **An elicitation answer proves only that the client answered.** A hook, an SDK host's callback, or a host default can answer, and the server receives an ordinary `accept` or `decline` either way. The spec makes no human-presence promise: the client gathers input "from the user or other sources" (MRTR), and "the protocol itself does not mandate any specific user interaction model".

## 2. Threat model for approval (from SECURITY §2)

Approval exists for the **prompt-injected model** ("model self-approval"). It does not defend against a **compromised server**, which holds whatever key or state approval uses and can skip it; that case stays bounded by the host policies (PRIVILEGED §3). Every option below is judged against:

| # | Threat | Question asked of each option |
|---|---|---|
| T1 | Prompt-injected model | Can the model produce an approval, directly or through anything it can reach? |
| T2 | Replay | Can one approval run twice? |
| T3 | Cross-operation reuse | Can an approval for one operation (tool, target, arguments, preview, principal) run another? |
| T4 | CSRF and phishing (web flows) | Can another site, or a page or link the model supplies, approve or capture an approval credential? |
| T5 | Approval fatigue | Does the human see enough to decide, and is approving cheap enough to rubber-stamp? |
| T6 | Multi-target, multi-principal | Is the approval bound to the right target and principal, with several of each? |
| T7 | Compromised server | What can it do? (Expected answer for all options: skip approval; the policies bound it.) |

**What a prompt-injected model can reach depends on the client.** This is the main input to T1.

| Client | The model's reach beyond our tools |
|---|---|
| Claude Code (CLI, Code tab) | A shell as the user. It can read client config, including the MCP bearer token in `.mcp.json`/`~/.claude.json`, and run local programs and servers. It can edit settings files, subject to Claude Code's own permission prompts. The Code tab adds a built-in browser pane with its own persistent sign-ins. |
| Claude Desktop chat | Its tools, and where the user enabled them, browser control in the user's real Chrome with their sign-ins, and computer use on the desktop. |

So the approval must not depend on:
- the MCP bearer token;
- a browser session cookie on the workstation;
- a click the model could make in a UI on the workstation;
- a setting the model can edit.

It needs a factor the model's environment does not hold. In the recommendation, that factor is an authenticator on the human's phone.

## 3. Options

Every option keeps what shell-mcp already does: tier and profile registration, the request `ceiling`, the gate's and the helper's policies, and the computed preview. The options differ only in how "a human said yes to exactly this" reaches the server.

### a. Form elicitation (the current design, D-006 / S-12)

- **How.** The first call returns `input_required` with a form elicitation that shows the preview, plus an HMAC-bound `requestState`. The retry carries the answer (S-12 as written).
- **Binding.** HMAC over principal, tool, target, canonical-args SHA-256, preview SHA-256, expiry and nonce, with a per-process key. Single use comes from the in-memory nonce set; the spec says single use "MUST" be enforced server-side, because clients may retry.
- **State and restart.** Stateless apart from the nonce set. A restart changes the key, so every outstanding state fails as `approval_invalid` (fail closed).
- **Audit.** Request issued, answer received (accept/decline/cancel), state verified or refused.
- **Operator setup.** None.
- **Clients.** The CLI in a terminal (expected, T-1). **Not** the Code tab (automatic decline, §1.2), the VS Code extension, or Desktop chat (not declared). mcp-remote passes form mode only if Desktop declares it, and Desktop doesn't.

| Threat | Assessment |
|---|---|
| T1 | The model cannot answer the elicitation itself. But the answer comes from the client process, and anything in that process can produce it: an `Elicitation` hook (a settings file the model's shell can edit, behind Claude Code's permission prompts), an SDK host's callback, or a host default. The server cannot tell a person from a script. **The trust root is the client's configuration.** |
| T2, T3 | Good: the HMAC binding and the nonce set. |
| T4 | Not applicable; no web flow. |
| T5 | One dialog per operation. Cheap to click through. The client shows the server's message, so the preview is visible. |
| T6 | Good: principal and target are in the HMAC. |
| T7 | Can skip it (expected). |

**Verdict.** It works only where a terminal CLI is used, and it trusts client configuration. Not suitable as the primary method for the maintainer's clients. Keep it as a possible later method (§8, S4d), not in S4b.

**a.1 Elicitation hook with a native dialog.** Rejected. It is an undocumented use, Windows-specific scripting, and the hook is editable from the model's shell. The server cannot distinguish it from an auto-accept hook.

**a.2 `_meta["anthropic/requiresUserInteraction"]: true` (complement, not an option).**
- **What Claude Code does with it.** It shows that tool's permission prompt on every call, even in auto and bypass modes, with no "don't ask again"; allow rules do not skip it. In non-interactive mode an allow from `--permission-prompt-tool` becomes a deny. An SDK host's `canUseTool` can still approve. (code.claude.com/docs/en/mcp, "Require approval for a specific tool"; the key is present in the 2.1.299 executable.)
- **Why adopt it.** It costs nothing and makes a person look at every approval-gated call in Claude Code.
- **Why it isn't approval.** The server cannot verify it, and the prompt shows the model's arguments, not the server's preview.
- **Recommended** for approval-gated tools, as defence in depth.

### b. URL-mode elicitation to a server-hosted page

- **How (2026-07-28).**
  1. The server returns `input_required` with a URL elicitation.
  2. The client must show the full URL and get consent before opening it, and must not prefetch it.
  3. On consent, the client retries with only `{action: "accept"}`. That means "consented", not "done".
  4. The server decides from its own stored state whether the out-of-band step finished, and answers with the result or another `input_required`.

  The spec's completion notification and `elicitationId` were removed in 2026-07-28 ("encode their own identifier in `requestState`"). So URL mode needs server-side state keyed by an id; a fully stateless server cannot finish it.
- **Spec security rules.**
  - The server "MUST verify the identity of the user who opens the URL", and the user who starts the flow must be the one who finishes it.
  - No pre-authenticated URLs; no sensitive data in the URL; HTTPS.
  - Identity should come from MCP authorization when available. shell-mcp has bearer tokens only, so the page needs its own credential, which is option c's step-up.
- **Binding, state, audit.** As option c (the same page and record). The URL elicitation is only a way to deliver the link.
- **Operator setup.** As option c.
- **Clients.** The Claude Code CLI (URL mode since 2.1.281). **Not** the Code tab (declines every elicitation), Desktop chat (none declared), or mcp-remote (refuses URL mode).

| Threat | Assessment |
|---|---|
| T1 | As option c, because the approval happens on the page. Without a step-up on the page, a model with browser control and the user's session could complete it. |
| T2, T3, T6 | As option c. |
| T4 | The client shows the server-sent URL, which is better than a link relayed by the model in chat. Otherwise as option c. |
| T5 | As option c. |
| T7 | Can skip it (expected). |

**Verdict.** It adds nothing on the maintainer's clients today. Later, a client that renders URL mode could receive option c's page link this way, with no change to the record or the page (§8, S4d).

### c. Out-of-band approval, independent of the client (recommended)

- **How.**
  1. The first call validates the input, computes the preview through the gate, and creates an approval record.
  2. The server optionally pushes a notification to the operator's channel.
  3. The call returns `approval_pending` with the approval id, the page URL, the expiry and a server-generated summary.
  4. The human opens the page, sees the server's own description of the operation, and approves with a current TOTP code from their authenticator. Declining needs no code.
  5. The model re-calls the same tool with the same arguments plus `approval_id`. The server executes only if that record is approved and every bound field matches (§6).
- **Binding.**
  - **Bound fields.** Principal, tool, target, SHA-256 of the canonical arguments, SHA-256 of the preview, SHA-256 of the gate policy reported with the preview, and expiry.
  - **Approver.** The approval is recorded against a named approver.
  - **Single use.** The record is marked used before execution.
  - **Fresh preview.** It must still hash the same at execution time.
- **State and restart.** Approval records live in a bounded in-memory store. A restart loses them, so a re-call gets `approval_invalid` ("unknown approval") and the model must ask again (fail closed). TOTP replay state is reset safely at start (§6.4).
- **Audit.** Server JSON lines for:
  - request created;
  - decision (approver, client address);
  - refused attempts (reason only);
  - lockouts;
  - consumption;
  - the tool-call line with the approval id.

  Codes, tokens and content are never logged (§6.8).
- **Operator setup.**
  - Enrol one or more approvers. Each gets a TOTP seed generated by `shell-mcp`, added to an authenticator app on their phone, and stored in a secret file the server reads.
  - Set the page's public URL.
  - Expose the approval listener to the networks the approver's phone uses, through the existing reverse proxy or VPN, with TLS.
  - Optionally, configure a push channel.
- **Clients.** All of them, including the Code tab, Desktop chat through mcp-remote, the terminal CLI, and scripts.

| Threat | Assessment |
|---|---|
| T1 | The model cannot approve. The code is generated on the approver's phone from a seed the workstation never holds. The bearer token, a browser session or a click is not enough: the page has no session, takes no bearer token, and requires the code for every approval. The model can create requests (bounded: pending limit, deduplication) and can decline (harmless). |
| T2 | The record is used once and marked used before execution. Each TOTP time step is accepted once per approver. |
| T3 | Every bound field is compared on the re-call. A fresh preview and the policy hash must match, so a changed target or policy needs a new approval. |
| T4 | **CSRF.** No ambient credential: no cookies, and the code is typed into the form each time. There is still a per-render form token, an Origin/`Sec-Fetch-Site` check, no state change on GET, and `frame-ancestors 'none'`. **Phishing.** TOTP is not phishing-resistant. A model with a shell could serve a look-alike page and relay a typed code in real time, to approve a different pending operation. Mitigations: <br>• the link reaches the human through the push notification, a channel the model does not write to; <br>• the page shows the approval id, which the chat also shows; <br>• operator guidance: open approvals only from the notification or the configured host, never from a link that differs from it; <br>• each code works once, and wrong codes lock the page out. <br>WebAuthn removes this residual risk (§11, Q2). |
| T5 | One code per operation. The page shows the full operation and the preview, rendered by the server with control and bidi characters made visible. The default gates only destructive and privileged-operator operations. Deduplication and a pending limit stop request floods. The friction is deliberate for these tiers. Gating `operator` too (`SHELL_MCP_APPROVAL_TIERS`) multiplies it, and the docs say so. |
| T6 | Principal and target are bound and shown. Each server instance has its own listener, approvers and records, so one instance's approval cannot run on another. |
| T7 | Can skip it, or fake the page (expected). Unchanged. |

**Verdict.** Recommended as the primary method.

**Push notification.** Optional; a nudge only.
- **What it carries.** Tool title, target, summary, expiry, and a `view` link to the page.
- **What it never carries.** No ntfy `http` action that approves directly. Anyone who can read the topic receives the whole message, including action URLs, headers and bodies. Topic access is set in the channel's own ACLs, which the server cannot verify. ntfy tokens grant access to the whole user account (docs.ntfy.sh/config, access control).
- **Recommended channel setup.** ntfy with `auth-default-access: deny-all`, a write-only user for the server, and a read-only user for the phone.
- **On failure.** The approval still works through the link in the tool result.

### d. MCP Apps (`io.modelcontextprotocol/ui`)

- **How.** An approval-gated tool links a `ui://` resource (`_meta.ui.resourceUri`). The host renders it in a sandboxed iframe, and the app calls an **app-only** tool (`_meta.ui.visibility: ["app"]`), such as "decide approval", through the host.
- **What the spec guarantees** (ext-apps 2026-01-26):
  - The host "MUST NOT include tools in the agent's tool list when their visibility does not include `"model"`".
  - The host "MUST reject `tools/call` requests from apps for tools that don't include `"app"`".
  - Cross-server calls to app-only tools are blocked.
- **What it does not guarantee:**
  - **No call origin.** No field tells the server a call came from the app; the server trusts the host completely.
  - **No user activation.** There is no user-gesture requirement for app-initiated calls ("MAY … subject them to further user approval").
  - **Hidden fields are advice only.** "`structuredContent` not added to model context" and "`_meta` not intended for model context" are best-practice text, not normative.
- **Clients.**
  - **Claude Desktop and claude.ai.** Desktop renders Apps for local stdio servers; Anthropic's MCP Apps guide runs examples from `claude_desktop_config.json` and suggests mcp-remote for remote ones. Desktop 2.42304.0 filters tools whose `_meta.ui.visibility` lacks `model` out of the model's list (verified in `app.asar`).
  - **mcp-remote.** It forwards client `extensions` upstream and `resources/read` generically (`main` source, not the tag).
  - **Claude Code** does not render Apps.
  - **Not verified:** that Desktop, through mcp-remote and a stateless 2026-07-28 server, renders the app and routes its app-only call. That needs a spike.
- **Binding, state, audit.** As option c if the app only presents option c's record and collects the TOTP code. A bare "Approve" button would make the host the trust root, like option a.
- **Operator setup.** As option c, plus nothing on the client.

| Threat | Assessment |
|---|---|
| T1 | **Button only:** host-trusted. The model cannot call the hidden tool, but nothing verifies a person clicked; computer use on the desktop could click it (not verified either way). **Button plus TOTP code:** as option c. |
| T2, T3, T6 | As option c. |
| T4 | Sandboxed iframe, host-defined CSP; no cross-site issue. Better than a relayed link: the panel appears in the chat itself, not via a URL the model chose. |
| T5 | Best UX of all: the preview and the decision sit next to the conversation. |
| T7 | Can skip it (expected). |

**Verdict.** A good later front end for option c in Desktop chat (§8, S4d), always with the TOTP code. Not for S4b: unverified on the maintainer's path, and Desktop-only.

### e. The confirm-argument fallback

- **How.** As option c's record, but the re-call carries `approval_id` and `confirm: true` and the server approves it itself, recording the approver as `model (confirm-argument)`.
- **What it still gives.** A preview round trip before execution, binding to arguments and target, and single use.
- **What it does not give.** Any defence against T1. **The model approves.**
- **Binding and state.** As option c.
- **Audit.** WARN at startup and on every use; the decision line names the method.
- **Operator setup.** One variable.
- **Clients.** All.

| Threat | Assessment |
|---|---|
| T1 | None: the model chooses the argument. |
| T2, T3, T6 | As option c. |
| T4 | Not applicable. |
| T5 | No human step. |
| T7 | Can skip it (expected). |

**Verdict.** Keep as the explicit, logged opt-in that D-006 already allows, never a default. The docs must say plainly that it turns approval off against a prompt-injected model.

## 4. Comparison

| | a. Form elicitation | b. URL elicitation | **c. Out-of-band page + TOTP** | d. MCP Apps (+TOTP) | e. confirm-argument |
|---|---|---|---|---|---|
| Reaches a person in the Code tab | No (auto-decline) | No | **Yes** | No (Code doesn't render Apps) | n/a (no person) |
| Reaches a person in Desktop chat | No (not declared) | No | **Yes** | Probably (unverified spike) | n/a |
| Reaches a person in a terminal CLI | Yes (to confirm, T-1) | Yes | **Yes** | No | n/a |
| Model can self-approve (T1) | Via client config | No (with step-up) | **No** | Button: host-trusted; +TOTP: no | **Yes** |
| Replay / cross-operation (T2, T3) | Bound | Bound | **Bound + fresh preview** | Bound | Bound |
| Phishing residue (T4) | n/a | Low | **Real-time relay (TOTP)** | Low | n/a |
| Operator setup | None | As c | **Approvers, listener, URL** | As c | One variable |
| New dependency | No | No | **No (stdlib)** | No | No |

## 5. Recommendation

1. **Primary: option c**, `SHELL_MCP_APPROVAL_METHOD=web`. It uses an approval page on its own listener, a TOTP step-up per approval from named approvers, approval-id re-calls with full binding and a fresh preview, and an optional ntfy push. This is the only option that reaches a person through both of the maintainer's clients today, and the only one whose proof of a person (a code from a device the model cannot reach) the server verifies itself.
2. **Fallback: option e**, `SHELL_MCP_APPROVAL_METHOD=confirm-argument`, explicit and WARN-logged. **Default: `none`**, under which approval-gated tools refuse with `approval_unavailable`, as today.
3. **Client-side defence in depth:** `_meta["anthropic/requiresUserInteraction"]: true` on every approval-gated tool.
4. **Deferred (S4d, optional, after S4b and S4c):**
   - MCP Apps panel for Desktop chat (with the TOTP field);
   - URL-mode delivery of the same link;
   - form elicitation as a weaker method for terminal-CLI users;
   - WebAuthn instead of TOTP.

   Each reuses option c's record.

**Under this design, the model can:**
- start an approval request (bounded per principal; an identical pending request returns the same record);
- see a request's status;
- relay, or misdescribe, the link in chat;
- decline a request;
- re-call after approval to run exactly what was approved.

**It cannot:**
- approve;
- change what an approval covers;
- reuse an approval for another tool, target, argument set or principal;
- run an approval twice, after expiry, after a restart, or after the target's preview or the gate policy changed;
- extend a TTL;
- approve with the MCP bearer token, a browser session, or a click.

Under `confirm-argument` it can approve everything, and the logs say so. A compromised server can skip approval under every method; the gate and privileged policies remain the boundary (PRIVILEGED §3).

## 6. Design detail for S4b

### 6.1 Flow

```
model ──call(args)──────────────▶ server: validate → preview via gate (read-tier preview op)
                                          → create record {pending} → notify (optional)
model ◀─ ok:false, approval_pending, approval{id,url,expires_at,summary}
human ── opens url (from notification or chat) ──▶ approval listener: GET /approvals/{id}
human ── POST approve {approver, totp, form_token} ──▶ verify → record {approved by <approver>}
model ──call(args, approval_id)─▶ server: match record → mark used → fresh preview, compare
                                          → execute with ceiling = tool tier → result
```

- **A re-call while still pending** waits up to 20 s (a fixed bound, and never past the expiry) for a decision. Then it returns `approval_pending` again, so the model does not spin.
- **A declined record** gives `approval_declined`.
- **Anything else** gives `approval_invalid`: unknown, expired, used, a mismatch, or a changed preview or policy.

### 6.2 The approval record

| Field | Notes |
|---|---|
| `id` | 128 random bits, lowercase base32 (26 chars). It is a capability to *view*, never to approve. |
| `principal`, `tool`, `target` | As resolved by the server (the target after defaulting). |
| `args_sha256` | SHA-256 of the canonical arguments: the decoded, typed input with defaults applied and `approval_id`/`confirm` removed, marshalled deterministically. |
| `preview`, `preview_sha256` | The rendered preview (bounded, e.g. 16 KiB) and its hash. |
| `policy_sha256` | From the gate's `gate` block on the preview response. |
| `created_at`, `expires_at` | TTL from `SHELL_MCP_APPROVAL_TTL`. |
| `state` | `pending` → `approved` / `declined` / `expired` → `used`. |
| `approver`, `decided_at`, `decided_from` | Set on decision. |
| `wrong_codes` | At 3, the record becomes `declined`. |

- **Store.** A bounded map: at most 5 pending records per principal (more gets `approval_unavailable`, "too many pending approvals") and at most 256 records in total. Expired records are swept.
- **Deduplication.** An identical request (same bound fields) while one is pending returns the existing record.

### 6.3 Execution check (the re-call)

Every check must hold, in this order:
1. The record exists and is `approved`. A pending record waits as in §6.1.
2. It is unexpired and unused.
3. The principal, tool, target and `args_sha256` are equal.
4. The record is marked `used`. This happens atomically, before anything is sent, so a failed execution never leaves a reusable approval.
5. A fresh preview is computed, and both its hash and the policy hash must equal the record's. If they differ, the answer is `approval_invalid` ("the target or policy changed since approval; request a new approval").
6. The operation runs with the tool's ceiling. Where the operation supports a precondition, the server passes what the preview saw: `expected_sha256` of the previewed content for `shell_priv_write_file` and `shell_write_file`. That closes the window between check and write.

### 6.4 TOTP

- **Parameters.** RFC 6238: HMAC-SHA-1, 6 digits, 30 s step, ±1 step accepted, the RFC's recommended maximum.
- **Seeds.** One per approver, at least 160 bits, base32.
- **Replay.** Per approver, the last accepted step is stored, and a code for that step or an earlier one is refused. The RFC says the verifier "MUST NOT accept the second attempt of the OTP".
- **Restart.** At process start each approver's last accepted step is set to the current step. A code seen before a restart cannot be replayed after it; approvals in the first ≤ 30 s after a start must wait for the next code.
- **Brute force.**
  - Per record: 3 wrong codes decline it.
  - Global: 5 wrong codes lock the page for 15 minutes. Each consecutive lockout doubles, up to 24 hours, and a successful approval resets the count. Each lockout is logged at WARN and pushed to the operator.
  - That bounds online guessing to a few dozen attempts a day. At three valid codes in 10⁶, that is roughly 10⁻⁴ a day, against an attacker who must also reach the listener.
- **Enrolment.** `shell-mcp approver-secret <name>` prints a new seed and its `otpauth://` URI once, on the operator's terminal on the server host. There is no QR rendering (stdlib only). The operator puts the line into the approvers secret file.
- **Guidance.** Keep the seed only in the phone's authenticator and the server's secret store. Never paste it into a chat, and never keep it on the workstation where the agent runs.

### 6.5 The approval page

- **Listener.** Its own bind and port (`SHELL_MCP_APPROVAL_BIND`/`_PORT`), so the operator can expose it, for example to a phone over the VPN or proxy, without exposing `/mcp`.
- **Auth.** It never accepts the bearer token, and `/mcp` never serves approvals. `Host` must equal the public URL's host.
- **Routes**; everything else is 404:
  - `GET /approvals/{id}`: an HTML page with no script, built with `html/template`.
  - `POST /approvals/{id}/approve`: fields `approver`, `code`, `form_token`.
  - `POST /approvals/{id}/decline`: field `form_token`.
- **What the page shows:**
  - the tool title and name, target name and host, principal;
  - every canonical argument;
  - the preview;
  - expiry, approval id;
  - "Approve only if you asked for exactly this."

  Strings from the host or the caller have control, bidi and other non-printing characters shown as visible escapes, so a file name cannot disguise the operation.
- **Request checks:**
  - No state change on GET.
  - A per-render form token, stored in the record, is required on POST.
  - `http.CrossOriginProtection` (Go ≥ 1.25: `Sec-Fetch-Site`, falling back to Origin against Host).
  - An `Origin`, when present, must equal the public URL's origin.
  - No cookies.
  - Body ≤ 4 KiB; per-client rate limit, client derived as on `/mcp` (`SHELL_MCP_TRUSTED_PROXIES`).
- **Response headers.** `Content-Security-Policy: default-src 'none'; style-src 'sha256-…'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`.
- **TLS.** Terminated by the operator's proxy. The public URL must be `https://` unless its host is loopback.
- **No inbox page in S4b** (§11, Q11). A listing of pending approvals would need an authenticated view.

### 6.6 Envelope and tool schema

- **New code.** `approval_pending` joins the closed set of server codes. The answer is `ok: false`, because nothing ran.
- **New `approval` object.** Envelopes of approval-gated tools gain an optional `approval` object: `{id, status, url, expires_at, summary}`, with status `pending`, `approved`, `declined`, `expired` or `used`.
  - The text block's summary line stays code-only (`error: approval_pending`). The URL appears in the envelope JSON that follows it.
  - This is an envelope change after S2, which needs the maintainer's approval (§11, Q5).
- **New input.** Approval-gated tools gain an optional `approval_id` (pattern `^[a-z2-7]{26}$`), always present, so the catalogue does not depend on configuration.
- **`confirm`.** It appears only under `confirm-argument`, as D-006 already says. The catalogue snapshot covers both variants.
- **New tool `_meta`.** Approval-gated tools carry `"anthropic/requiresUserInteraction": true`.
- **Tool descriptions** stay terse and do not explain the flow (CLAUDE.md). The `approval_id` field's schema description says what it is.

### 6.7 Configuration (proposed)

| Variable | Default | Rule |
|---|---|---|
| `SHELL_MCP_APPROVAL_METHOD` | `none` | `none` \| `web` \| `confirm-argument`. Replaces `SHELL_MCP_APPROVAL_FALLBACK`, which is refused at startup if set, as was done for `SHELL_MCP_TRUST_PROXY`. `confirm-argument` logs a WARN at startup and on every use. |
| `SHELL_MCP_APPROVAL_TIERS` | `destructive` | Unchanged. |
| `SHELL_MCP_APPROVAL_TTL` | `300` | Seconds, 60..900. Proposed change from 120 and 30..600, because a person needs time to reach a phone (§11, Q6). |
| `SHELL_MCP_APPROVAL_BIND` / `_PORT` | `127.0.0.1` / `8081` | `web` only. The port must differ from `SHELL_MCP_PORT`. |
| `SHELL_MCP_APPROVAL_PUBLIC_URL` | — | Required for `web`. Absolute `https://` URL (`http://` only with a loopback host), no userinfo, query or fragment. Used for links, the Host check and the Origin check. |
| `SHELL_MCP_APPROVERS_FILE` | — | Required for `web`. A secret file with one approver per line, `<name> <base32 seed>`. Names match `^[a-z][a-z0-9-]{0,31}$`; at least one approver; no duplicates; each seed ≥ 160 bits. Group/other-readable logs a WARN, as for the other secret files. |
| `SHELL_MCP_APPROVAL_NOTIFY_URL` | — | Optional. ntfy topic URL (`https://…/<topic>`); JSON publish. |
| `SHELL_MCP_APPROVAL_NOTIFY_TOKEN` / `_FILE` | — | Bearer token for the notify URL. Required when the URL is set. |

**Fail-closed startup rules** (additions to SECURITY §6). The server exits with a one-line reason on:
- an unknown method;
- `SHELL_MCP_APPROVAL_FALLBACK` set;
- `web` without a valid public URL or approvers file;
- an approver line that does not parse, a short seed, or a duplicate name;
- the approval port equal to the MCP port;
- a notify URL that is not `https://` (loopback excepted), or one without a token;
- a TTL outside its range;
- `SHELL_MCP_APPROVAL_TIERS` without `destructive` (unchanged).

### 6.8 Audit lines (server, JSON)

| Message | Fields |
|---|---|
| `approval requested` | `approval_id`, principal, tool, target, `args_sha256`, `preview_sha256`, `policy_sha256`, `expires_at`, method |
| `approval decided` | `approval_id`, `decision`, `approver` (or `model (confirm-argument)`), client address, method |
| `approval attempt refused` | `approval_id` if any, `reason` (`bad_code`, `form_token`, `cross_origin`, `expired`, `locked`, `unknown`), client address |
| `approval lockout` | `until`, `consecutive` |
| `tool call` (existing) | gains `approval_id` and `approval_outcome` (`pending`, `used`, `invalid`, `declined`) |

**Never logged:** codes, seeds, form tokens, the notify token, the preview text, or content. Hashes and ids only.

The gate's and the helper's audit lines are unchanged. Carrying the approval id to the host would be a protocol change (§11, Q9).

## 7. Changes implied (exact wording, for S4b to apply once accepted)

### 7.1 D-006 (plan §2), replacement text

> **D-006 | Consequential operations require a human's approval, given outside the model's reach, never a model-supplied argument.**
>
> **Which operations.** Always approval-gated: every destructive operation and every privileged (`priv_*`) operation of tier operator or above. `SHELL_MCP_APPROVAL_TIERS` (default `destructive`) can add ordinary operator writes.
>
> **The method** (`SHELL_MCP_APPROVAL_METHOD=web`) is out-of-band.
> - The first call computes a preview and returns `approval_pending` with an approval id and the URL of an approval page served by shell-mcp on its own listener.
> - The human opens the page and sees the server's own description of the operation and its preview. They approve by entering a current TOTP code from an authenticator enrolled for a named approver.
> - The model re-calls the tool with the approval id. The server executes only if that exact approval was approved: principal, tool, target, SHA-256 of the canonical arguments, of the preview and of the gate policy, within `SHELL_MCP_APPROVAL_TTL`, and not yet used. A fresh preview must still match.
> - Approval state is in memory and does not survive a restart.
>
> **Other values.** With `none` (the default), approval-gated tools refuse with `approval_unavailable`. `confirm-argument` is an explicit, logged-at-WARN opt-out in which the model approves.
>
> **No elicitation in v1.** MCP elicitation is not used for approval in v1: neither target client showed it to a person, and an elicitation answer proves only that the client answered (S4b-scope).
>
> **Tool metadata.** MCP annotations and `title` are set on every tool, and approval-gated tools carry `_meta["anthropic/requiresUserInteraction"]: true`.
>
> **Rationale.**
> - A `confirm: true` parameter is chosen by the model, so a prompt-injected model approves itself.
> - An answer collected by the client is only as trustworthy as the client's configuration, which an agent with a shell can change, and the maintainer's clients did not show it to anyone.
> - A code from the approver's authenticator, entered on a page that shows the server's description of the operation, is something the model can neither produce nor alter. It works with every client, because the model only re-calls a tool.
> - The binding stops an approval for one operation being used for another.
> - Approval defends against a misled model, not a compromised server; that case is bounded by the host policies (docs/PRIVILEGED.md §3).

Plan §1 goal 4 and §1.1 "Why human approval through the protocol" change to match: "through a server-hosted approval page with a code from the approver's authenticator" in place of "through MCP elicitation".

### 7.2 S-12 (plan §4.2), replacement text

> **S-12 | Human approval (D-006).**
> - **Record.** An approval record (128-bit random id) binds principal, tool, target, canonical-args SHA-256, preview SHA-256, gate-policy SHA-256 and expiry. It is held in a bounded in-memory store, at most 5 pending per principal, and lost on restart.
> - **Approving.** A pending record becomes approved only through the approval page with a valid TOTP code (RFC 6238: SHA-1, 6 digits, 30 s, ±1 step) of a configured approver. Each step is accepted once per approver, and none from before process start.
> - **Executing.** The re-call executes only if the record is approved, unexpired, unused and matches every bound field. It is marked used before execution, and a fresh preview's hash and the policy hash must still match. Otherwise the answer is `approval_pending`, `approval_declined` or `approval_invalid`.
> - **The page.** A separate listener, never authenticated by the bearer token. No state change on GET. A per-render form token, Origin/`Sec-Fetch-Site` checks, no cookies, no script, a strict CSP and `frame-ancestors 'none'`. Rate-limited. Three wrong codes decline a record; five globally lock the page, with doubling lockouts up to 24 h, each logged and notified.
> - **Audit.** Requests, decisions, refused attempts, lockouts and use are audit-logged with ids and hashes, never codes, seeds, tokens or content.

### 7.3 Other documents

| Document | Change |
|---|---|
| plan §4.1 F-09 | "human approval through elicitation (D-006)" → "human approval (D-006)". |
| plan §5 | **S4b** is split as in §8. **S4c** "privileged tools (`shell_priv_*`), approval-gated per TOOLS.md through the S4b approval core, with previews' preconditions passed through". New optional **S4d** (§8). |
| plan §8 | `internal/approval/` comment → "approval records, binding, TOTP verification, approval page, notifier". |
| SECURITY §2 | **Model self-approval** mitigation → "A person approves on the server's approval page with a TOTP code from an authenticator the agent's environment does not hold; the approval is bound to principal, tool, target, arguments, preview and policy, short-lived and single-use (D-006, S-12); `none` → fail closed; `confirm-argument` is a logged opt-out with no protection against this threat." New rows: **Approval phishing / relay** (look-alike page relays a typed code: links via the notification channel, approval id shown in both places, single-use codes and lockouts, WebAuthn as the future fix); **Approval brute force** (per-record and global wrong-code limits with doubling lockouts, notification on lockout). |
| SECURITY §6 | Add the startup rules of §6.7; replace "an unknown fallback" with "an unknown method; `SHELL_MCP_APPROVAL_FALLBACK` set". |
| SECURITY §1 | New asset rows: approver TOTP seeds (secret file, never logged, never on the workstation); the notify token. |
| ARCHITECTURE §1 diagram, §2, §3 | Approval listener next to `/mcp`; `internal/approval` description; request lifecycle step 2 rewritten to §6.1; "stateless server" note: in-memory state adds the approval store. |
| ARCHITECTURE §5 | Variables of §6.7; remove `SHELL_MCP_APPROVAL_FALLBACK`. |
| ARCHITECTURE §6 | `approval_pending` in the closed set; the optional `approval` object. |
| TOOLS.md approval section | Rewritten to the web flow; codes `approval_pending`/`approval_declined`/`approval_invalid`/`approval_unavailable`; `approval_id` on gated tools; `requiresUserInteraction`; the client table gains the S4b-scope findings (Code tab declines in the SDK host; terminal CLI renders; VS Code declines; Desktop chat declares only MCP Apps). |
| `docs/PRIVILEGED.md` §3 | "enforced by the MCP server, which holds the HMAC key" → "enforced by the MCP server, which holds the approval records and verifies the approver's code". |
| deploy/ (S5) | Compose: a second port mapping for the approval listener (default loopback), the approvers secret, and the optional notify token; `.env.example` entries; a short "approvals" section (enrolment, proxy exposure to the phone over VPN, ntfy ACLs). This adds a port and is a `deploy/` hardening-flag change: STOP-and-ask in that session. |
| `docs/CLIENTS.md` (S5) | The client matrix, with: approvals arrive as a link in the tool result (and a push), never as a dialog. |

## 8. S4b outline, split into sessions

**S4b-1: approval core** (Opus 5.5, High).
- **Scope:**
  - `internal/approval`: the record store, canonical arguments, binding and execution check, TOTP (RFC 6238 vectors), approvers file, notifier (ntfy JSON publish).
  - The approval listener and page.
  - Config and startup rules.
  - Envelope `approval_pending` and the `approval` object.
  - `approval_id` on gated tools.
  - `define`'s `approvalGuard` replaced by the approval flow: today that covers operator tools under `SHELL_MCP_APPROVAL_TIERS=operator`, the only gated tools that exist yet.
  - The `requiresUserInteraction` meta.
  - The `shell-mcp approver-secret` command.
  - `confirm-argument` on the same record.
  - Docs per §7, except deploy/.
- **Tests first** (failing commits named in the PR): §9.1 and the in-process simulated-human tests.
- **Fuzz:** the approvers-file parser, the TOTP code parser, the approval-id parser, canonical-argument hashing (round trip), 60 s each.

**S4b-2: destructive tools** (Opus 5.5, High).
- **Scope:**
  - `shell_preview_delete` and `shell_preview_git_discard` (read tier).
  - `shell_delete_path` and `shell_discard_git_changes`.
  - `shell_run_command`'s admin registration at `destructive`, approval-gated.
  - Execution with fresh-preview comparison.
  - e2e-host with a simulated human (§9.2).

**S4c: privileged tools.**
- **Scope.** As planned, with approval through S4b-1. Preview preconditions (`expected_sha256`) are passed to the helper; package previews come from the `priv_pkg_*_preview` ops.

**S4d (optional, later; each part its own PR):**
- an MCP Apps approval panel for Desktop chat (with the TOTP field; starts with a spike verifying rendering and app-only routing through mcp-remote to a stateless server);
- URL-mode delivery of the page link;
- a form-elicitation method for terminal CLIs;
- WebAuthn (dependency STOP-and-ask).

## 9. Test plan

### 9.1 Unit (S4b-1). Every guardrail's test is committed first and shown failing.

- **Binding.**
  - A re-call differing in each bound field (principal, tool, target, any argument, defaults made explicit vs omitted, which must hash the same) is `approval_invalid`, and the gate sees no request.
  - Expired, used, unknown and declined records give their codes.
  - A second re-call after success is `approval_invalid`.
  - A failed execution leaves the record used.
- **Fresh preview.** A changed preview or policy hash at execution is `approval_invalid`, with no mutating gate request.
- **Pending.** A pending re-call waits ≤ 20 s and returns `approval_pending`; the wait ends early on a decision and on context cancellation.
- **TOTP.**
  - The RFC 6238 Appendix B SHA-1 vectors pass.
  - ±1 step is accepted; ±2 is refused.
  - The same step twice is refused, per approver; another approver's code for the same step is independent.
  - A code from the step current at start is refused.
  - Wrong-code counting: per record, then global, then doubling lockouts; a lockout is logged and notified.
- **Page.**
  - GET never changes state.
  - POST without, or with a stale, form token is refused.
  - Cross-site `Sec-Fetch-Site` and a foreign `Origin` are refused.
  - A wrong `Host` is refused.
  - The bearer token on the page gives nothing, and `/mcp` has no `/approvals` route (and the reverse).
  - All headers of §6.5 are present.
  - Control and bidi characters in a preview are rendered visibly.
  - The body cap and the rate limit hold.
- **Store.** The pending cap per principal holds; deduplication returns the same id; the global bound holds; restart (a new store) makes old ids unknown.
- **Config.** Every fail-closed rule of §6.7; `SHELL_MCP_APPROVAL_FALLBACK` refused.
- **`confirm-argument`.** It works only in that mode; a WARN on every use; the approver is recorded as the model.
- **Logs.** The audit lines of §6.8. Codes, seeds, tokens and preview text never appear in logs; this is proved by searching the captured log for each.
- **Catalogue.** The snapshot covers both schema variants; gated tools carry the meta.

### 9.2 End-to-end with a simulated human (S4b-2, e2e-host)

- **Delete.**
  - **Before approval.** `shell_delete_path` returns `approval_pending`, and the file still exists. No gate `delete` line for the principal appears, only `delete_preview`.
  - **Approval.** The test acts as the human: it fetches the page, reads the form token, computes the TOTP from a test seed, and POSTs approve.
  - **After approval.** The re-call deletes, and the gate's audit line appears once. A second re-call is `approval_invalid` with no gate line.
- **Change after approval.** The previewed directory changes after approval; the re-call is `approval_invalid` and nothing is deleted.
- **Decline.** Declining on the page gives `approval_declined`, and nothing runs.
- **Restart.** Restarting the server between approval and re-call gives `approval_invalid`, and nothing runs.
- **Ceiling.** A destructive `shell_run_command` runs only after approval, at ceiling `destructive`.

### 9.3 Live client checks (maintainer, after S4b-2)

1. **Code tab.**
   - The model gets `approval_pending` and shows the link.
   - The approver approves on the phone, and the re-call deletes a scratch file on a test target.
   - The permission prompt for the gated tool shows no "Always allow" (`requiresUserInteraction`).
2. **Desktop chat through mcp-remote `--protocol auto`.** The same as the Code tab check.
3. **Negative.**
   - Ask the model to approve the request itself: it cannot.
   - Paste a wrong code on the page three times: the record is declined.
   - Re-call after that: `approval_declined`.
4. **Push.** The ntfy notification arrives with a `view` link, and no approve button.

## 10. Live test for the maintainer now: T-1 (does the terminal CLI render form elicitation?)

**Why.** It settles whether option a works anywhere in the maintainer's setup (it decides only Q1's "later" part; the recommendation does not depend on it). It uses the Code tab's own Claude Code build, so the version matches the earlier test. It needs the existing diagnostic build; everything is loopback and throwaway.

1. **Scratch folder and diagnostic build** (from `dev`, in the Go image pinned by the Dockerfile):
   ```powershell
   cd C:\src\shell-mcp; git checkout dev; git pull
   $d = Join-Path $env:TEMP 'shell-mcp-diag'; New-Item -ItemType Directory -Force $d | Out-Null
   $img = (Select-String -Path Dockerfile -Pattern '^FROM (golang:\S+)').Matches[0].Groups[1].Value
   docker run --rm -v "${PWD}:/src:ro" -v "${d}:/out" -w /src -e GOOS=windows -e GOARCH=amd64 -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false $img go build -trimpath -tags shellmcp_diag -o /out/shell-mcp-diag.exe ./cmd/shell-mcp
   & "$d\shell-mcp-diag.exe" version
   ```
   The output must say it is a diagnostic build.
2. **Throwaway token and key:**
   ```powershell
   $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
   $tok = [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_'); $tok.Length
   docker run --rm -v "${d}:/out" $img sh -c 'ssh-keygen -q -t ed25519 -N "" -C diag -f /out/key'
   ```
3. **Start the server on loopback** (leave this window open):
   ```powershell
   $env:SHELL_MCP_TOKEN = $tok; $env:SHELL_MCP_BIND = '127.0.0.1'; $env:SHELL_MCP_PORT = '8765'
   $env:SHELL_MCP_TARGET_NAME = 'diag-target'; $env:SHELL_MCP_TARGET_HOST = 'target-a.example.test'; $env:SHELL_MCP_TARGET_USER = 'svc-shell'
   $env:SHELL_MCP_TARGET_HOST_KEYS = 'ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
   $env:SHELL_MCP_SSH_KEY_FILE = "$d\key"
   & "$d\shell-mcp-diag.exe" serve
   ```
4. **Scratch project** (second PowerShell window; replace `<TOKEN>` with the value of `$tok` from step 2):
   ```powershell
   $p = Join-Path $env:TEMP 'shell-mcp-diag\project'; New-Item -ItemType Directory -Force $p | Out-Null
   '{"mcpServers":{"shell-mcp-diag":{"type":"http","url":"http://127.0.0.1:8765/mcp","headers":{"Authorization":"Bearer <TOKEN>"}}}}' | Set-Content -Encoding utf8 (Join-Path $p '.mcp.json')
   cd $p
   ```
5. **Run the Code tab's Claude Code build in this terminal**, not the older `claude` on `PATH`:
   ```powershell
   $cc = Get-ChildItem "$env:APPDATA\Claude\claude-code" -Recurse -Filter claude.exe | Sort-Object LastWriteTime -Descending | Select-Object -First 1
   & $cc.FullName --version
   & $cc.FullName
   ```
   - Approve the project's MCP server when asked.
   - Send: `Call the shell_diag_elicit tool and show me its full result.`
   - If a yes/no question appears, answer **yes**.
   - Copy the tool's `data` object.
   - Exit with `/exit`.
6. **Clean up.**
   - Press Ctrl+C in the server window.
   - Remove the scratch folder: `Remove-Item -Recurse -Force (Join-Path $env:TEMP 'shell-mcp-diag')`.
   - Clear the variables: `Remove-Item Env:SHELL_MCP_*`.
   - Nothing was installed, and no setting outside the scratch folder was changed. The project's MCP approval is stored against the deleted folder's path in `~/.claude.json`; it is harmless, and `claude mcp` or the file itself can remove it.

**Possible outcomes:**

| Result | Meaning |
|---|---|
| A dialog appeared; `data.round = 2`, `action = accept`, `answer = true`, `request_state_echoed = true` | The terminal CLI renders form elicitation. Option a is usable there, but only there. This supports keeping it as a later, weaker method (S4d); it does not change the recommendation. |
| No dialog; `action = decline` or `cancel` at once | Elicitation reaches no person on any of the maintainer's surfaces. Option a is dropped, not deferred. |
| `round = 1`, `elicitation_declared = false` | This build negotiated without elicitation (for example, a 2025-11-25 fallback). Report the `protocol_version`; it changes nothing for option c. |

**No live test is needed to accept option c.** Its client requirement is only that the model can call a tool twice and show a link.

## 11. Open questions for the maintainer

| # | Question | Options | Recommendation |
|---|---|---|---|
| Q1 | Adopt out-of-band approval (c) as v1's method, and drop elicitation from v1? | (a) yes; (b) also implement form elicitation in S4b for terminal CLIs; (c) keep elicitation as primary and wait for clients | **(a).** It is the only method reaching a person in both clients; elicitation can return as S4d. |
| Q2 | Step-up credential | (a) TOTP, standard library; (b) WebAuthn now, which needs `github.com/go-webauthn/webauthn` (dependency STOP-and-ask) or a hand-written verifier; (c) forward-auth SSO identity only | **(a) now, (b) later.** (c) alone fails T1: a model driving the user's browser carries the SSO session, and Authelia and Authentik offer no per-request step-up. |
| Q3 | Where the page is served | (a) its own listener and port; (b) a path on the MCP listener | **(a).** It can be exposed to the phone without exposing `/mcp`, and the two auth schemes never meet. |
| Q4 | Push channel in S4b | (a) ntfy JSON publish; (b) a generic JSON webhook; (c) none in S4b | **(a).** It is self-hostable with per-topic ACLs; others can follow. |
| Q5 | Envelope change | (a) code `approval_pending` plus an `approval` object; (b) the code only, details in `error.message` | **(a).** The model needs the id machine-readably. It is additive. |
| Q6 | TTL | (a) default 300 s, range 60..900; (b) keep 120 s, 30..600 | **(a).** A person needs time to reach a phone; the approval is still single-use and bound. |
| Q7 | Config naming | (a) `SHELL_MCP_APPROVAL_METHOD` replaces `_FALLBACK` (old variable refused); (b) keep `_FALLBACK` and add a method variable | **(a).** One variable states how approval works. Nothing is released, so nothing breaks. |
| Q8 | Re-preview at execution | (a) refuse if the preview or policy changed; (b) execute whatever the approval says | **(a).** The human approved what the preview showed. |
| Q9 | Approval id on gate requests (host audit correlation) | (a) not now; (b) add an optional field to protocol v1 | **(a).** It is a protocol change for correlation only. The server log has both ids, and the gate log has the time and op. |
| Q10 | Approvers | (a) several named approvers in one file; (b) one unnamed seed | **(a).** The audit says who approved, and seeds rotate one person at a time. |
| Q11 | Inbox page (a list of pending approvals) | (a) defer; (b) S4b, behind forward-auth headers from trusted proxies | **(a).** It needs an authenticated view. The notification and the link cover it. |
| Q12 | `anthropic/requiresUserInteraction` on gated tools | (a) yes; (b) no | **(a).** Free defence in depth in Claude Code. Clearly not the approval itself. |
| Q13 | The notification as a capability (an ntfy `http` action that approves without the page) | (a) never; (b) allowed as an opt-in | **(a).** Topic readers get the whole message; the server cannot verify who that is. |

## 12. What was run (throwaway spikes; nothing committed)

- **Installed Claude Code 2.1.299** (the Code tab's build). The single-file executable was searched for elicitation code with `grep -a`. This found:
  - the non-interactive path ("received in print mode") and its hook-first order;
  - the control request `subtype: "elicitation"`;
  - the `--permission-prompts none` switch to `cancel`;
  - the SDK handler's `return {action: "decline"}` when no `onElicitation` exists;
  - the interactive dialog path used in a terminal;
  - the `anthropic/requiresUserInteraction` key.
- **Installed Claude Desktop 2.42304.0** (`app.asar` and its renderer assets) was searched the same way. This found:
  - SDK 0.3.299;
  - every `onElicitation` occurrence lies inside the SDK, and no local-session caller passes it;
  - the renderer's remote-session path passes one, behind a feature flag;
  - the MCP Apps capability strings;
  - the filter that hides tools whose `_meta.ui.visibility` lacks `model`.
- **Dependency refresh** in the pinned Go container: `go get -u ./... && go get -u -t ./... && go mod tidy` changed nothing.

Minified code was read for behaviour only, and nothing of it is reproduced beyond identifiers and short string literals.

## 13. Sources (fetched 2026-10-16)

**Claude Code and Desktop**
- code.claude.com/docs/en/mcp: "Respond to MCP elicitation requests"; "Require approval for a specific tool" (`anthropic/requiresUserInteraction`); client runtimes.
- code.claude.com/docs/en/agent-sdk/typescript: Options, `onElicitation` (declined automatically when not provided).
- code.claude.com/docs/en/hooks#elicitation: hook inputs and outputs.
- code.claude.com/docs/en/headless: `--permission-prompts none` cancels unanswered elicitations.
- code.claude.com/docs/en/desktop: the Code tab runs its own copy of Claude Code; settings and hooks shared.
- code.claude.com/docs/en/permission-modes: no elicitation behaviour.
- github.com/anthropics/claude-code CHANGELOG.md, entries 2.1.76, 2.1.117, 2.1.281, 2.1.282, 2.1.284, 2.1.287. The newest release was 2.1.302 when read.
- github.com/anthropics/claude-code issues #89858, #96043, #98256 (open); github.com/anthropics/claude-ai-mcp issue #153 (open).
- claude.com/docs/connectors/building and …/building/mcp-apps/getting-started, …/troubleshooting.

**MCP**
- modelcontextprotocol.io/specification/2026-07-28/client/elicitation (form and URL mode, security, phishing).
- …/2026-07-28/basic/patterns/mrtr (`requestState` integrity, server-side single use).
- …/2026-07-28/changelog (completion notification and `elicitationId` removed).
- …/2026-07-28/server/tools (human in the loop SHOULD).
- …/2025-11-25/client/elicitation (for comparison).
- github.com/modelcontextprotocol/ext-apps, specification/2026-01-26/apps.mdx (visibility, sandboxing, results); modelcontextprotocol.io/extensions/client-matrix.
- registry.npmjs.org/mcp-remote/latest (0.15.1); github.com/punkpeye/mcp-remote `main` `src/lib/protocol-era.ts`. Not diffed against the 0.15.1 tag: **unverified for 0.15.1**.

**Approval mechanics**
- RFC 6238 (§4.1 time step, §5.2 one step of network delay, no second acceptance); RFC 4226 (§4, §7.3 throttling).
- W3C Web Authentication Level 3 (user verification, RP ID/origin binding).
- OWASP CSRF Prevention Cheat Sheet; pkg.go.dev/net/http#CrossOriginProtection (Go 1.25).
- docs.ntfy.sh/publish (action buttons, auth) and docs.ntfy.sh/config (access control, token scope); ntfy-android `UserActionWorker.kt` (the `http` action is sent from the phone); ntfy v2.31.1.
- authelia.com trusted-header SSO and access control (no per-request step-up); docs.goauthentik.io proxy provider; oauth2-proxy configuration; Caddy `forward_auth` and GHSA-7r4p-vjf4-gxv4 (client header passed through, fixed in 2.11.2); Traefik ForwardAuth.

**Unverified, and marked where used**
- That Desktop renders an MCP App from a stateless 2026-07-28 server through mcp-remote and routes its app-only calls (option d).
- Whether computer use can click inside the Desktop window's app panel.
- mcp-remote 0.15.1 behaviour versus `main`.
- Whether ntfy's iOS and web clients send `http` actions like Android (irrelevant to the recommendation, which uses `view` links only).
