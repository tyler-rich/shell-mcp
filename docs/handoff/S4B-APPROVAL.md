# S4b handoff: how approvals reach a human

> Session S4b-scope, 2026-10-16. Documentation only: no approval code exists in this PR.
> It answers plan §5 (S4b-scope) and feeds S4b, S4c and S5's `docs/CLIENTS.md`.
> **Status: accepted by the maintainer on 2026-10-16** (option c with TOTP; the answers and added requirements are in §11).
> S4b applies §7's wording to D-006, S-12 and the other documents in its first commit. This PR changes no locked document.

## 0. Summary

- **Why the Code tab declines (§1).** The Desktop app's Code tab runs Claude Code as an Agent SDK host. When Claude Code receives an elicitation in that mode, it runs `Elicitation` hooks and then forwards the request to the host as an SDK control request. The SDK answers `decline` by itself when the host registered no `onElicitation` callback, and the Desktop app (2.42304.0, SDK 0.3.299) registers none for local Code-tab sessions. That is the immediate decline the maintainer saw. Verified in the installed binaries and in the SDK docs; three open upstream issues report the same. No setting, permission mode or documented hook makes the Code tab show the question to a person.
- **Decision (§5).** Out-of-band approval (option c).
  - The first call returns `approval_pending` with an approval id and the URL of an approval page that shell-mcp serves on its own listener, whose origin is fixed by configuration.
  - The human opens the page from a bookmark or from the server's own optional push notification, never from a link the model presents. The page shows its own origin prominently, and the server's own description of the operation, generated from the canonical arguments.
  - The approver approves or declines by entering a **current TOTP code from an authenticator on their phone**. By default there is exactly one approver, enrolled with a CLI command that shows the `otpauth` QR code in the terminal once.
  - The model then re-calls the tool with the approval id, and the server executes only that exact operation, once, within its TTL.
  - This works with every client, because the model only re-calls a tool.
  - The model cannot produce the code, and cannot change what the page shows.
  - The page works with no push channel at all; ntfy is optional.
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
- **The CLI in a terminal** renders form and URL elicitations: the docs say so, and third-party reports confirm it for 2.1.296 and 2.1.301. The maintainer's terminal `claude` is older (2.1.156), and the maintainer chose not to run live test T-1 (§10), so this rests on the docs and those reports.
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

It needs a factor the model's environment does not hold. In the accepted design, that factor is an authenticator on the human's phone.

## 3. Options

Every option keeps what shell-mcp already does: tier and profile registration, the request `ceiling`, the gate's and the helper's policies, and the computed preview. The options differ only in how "a human said yes to exactly this" reaches the server.

### a. Form elicitation (the current design, D-006 / S-12)

- **How.** The first call returns `input_required` with a form elicitation that shows the preview, plus an HMAC-bound `requestState`. The retry carries the answer (S-12 as written).
- **Binding.** HMAC over principal, tool, target, canonical-args SHA-256, preview SHA-256, expiry and nonce, with a per-process key. Single use comes from the in-memory nonce set; the spec says single use "MUST" be enforced server-side, because clients may retry.
- **State and restart.** Stateless apart from the nonce set. A restart changes the key, so every outstanding state fails as `approval_invalid` (fail closed).
- **Audit.** Request issued, answer received (accept/decline/cancel), state verified or refused.
- **Operator setup.** None.
- **Clients.** The CLI in a terminal (per the docs and third-party reports; T-1 was skipped). **Not** the Code tab (automatic decline, §1.2), the VS Code extension, or Desktop chat (not declared). mcp-remote passes form mode only if Desktop declares it, and Desktop doesn't.

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

### c. Out-of-band approval, independent of the client (accepted)

- **How.**
  1. The first call validates the input, computes the preview through the gate, and creates an approval record. The record's description is generated by the server from the canonical arguments.
  2. The server optionally pushes a notification to the operator's channel.
  3. The call returns `approval_pending` with the approval id, the page URL (its origin fixed by configuration), the expiry and a server-generated summary. The result text tells the model to show that URL unchanged.
  4. The approver opens the page from a bookmark (and enters the id) or from the push, never from a link the model presents. They check the origin banner and the server's description of the operation, and approve or decline with a current TOTP code from their authenticator.
  5. The model re-calls the same tool with the same arguments plus `approval_id`. The server executes only if that record is approved and every bound field matches (§6).
- **Binding.**
  - **Bound fields.** Principal, tool, target, SHA-256 of the canonical arguments, SHA-256 of the preview, SHA-256 of the gate policy reported with the preview, and expiry.
  - **Approver.** The decision is recorded against the verified approver's name.
  - **Single use.** The record is marked used before execution.
  - **Fresh preview.** It must still hash the same at execution time.
- **State and restart.** Approval records live in a bounded in-memory store. A restart loses them, so a re-call gets `approval_invalid` ("unknown approval") and the model must ask again (fail closed). TOTP replay state is reset safely at start (§6.4).
- **Audit.** Server JSON lines for:
  - request created;
  - decision (verified approver name, client address);
  - refused attempts;
  - lockouts;
  - expiry;
  - use;
  - the tool-call line with the approval id.

  Codes, seeds, tokens and content are never logged (§6.8).
- **Operator setup.**
  - Enrol the approver with `shell-mcp approver add`, which shows the `otpauth` QR code in the terminal once and writes a `0600` secret file. Mount that file into the server.
  - Set the page's public URL.
  - Either keep the listener on loopback, or expose it to the networks the approver's phone uses, through native TLS or the existing TLS-terminating reverse proxy.
  - Bookmark the page on the phone.
  - Optionally, configure a push channel.
- **Clients.** All of them, including the Code tab, Desktop chat through mcp-remote, the terminal CLI, and scripts.

| Threat | Assessment |
|---|---|
| T1 | The model cannot approve or decline. The code is generated on the approver's phone from a seed the workstation never holds. The bearer token, a browser session or a click is not enough: the page has no session, takes no bearer token, and requires a code for every decision. The model can create requests, bounded by a pending limit and deduplication. |
| T2 | The record is used once and marked used before execution. Each TOTP step is accepted once per approver (last accepted step). |
| T3 | Every bound field is compared on the re-call. A fresh preview and the policy hash must match, so a changed target or policy needs a new approval. |
| T4 | **CSRF.** No ambient credential: no cookies, and the code is typed into the form each time. Even so: POST-only decisions with a CSRF token, an Origin/`Sec-Fetch-Site` check and `frame-ancestors 'none'`. <br>**Phishing.** TOTP is not phishing-resistant: a model with a shell could serve a look-alike page and relay a typed code in real time. Mitigations: <br>• the origin is fixed by configuration and shown prominently on the page; <br>• approvers open approvals only from a bookmark or the server's own push, never from a chat link; <br>• the model is told to show the URL unchanged, so a different URL in the chat is a warning sign; <br>• codes are single-use, with per-approver lockouts. <br>WebAuthn removes this residual risk (§11, Q2). |
| T5 | One code per decision. The page shows the full operation and preview, generated by the server, with control and bidi characters shown as escapes. The default gates only destructive and privileged-operator operations. Deduplication and a pending limit stop request floods. The friction is deliberate for these tiers. Gating `operator` too (`SHELL_MCP_APPROVAL_TIERS`) multiplies it, and the docs say so. |
| T6 | Principal and target are bound and shown. Each server instance has its own listener, approvers and records, so one instance's approval cannot run on another. |
| T7 | Can skip it, or fake the page (expected). Unchanged. |

**Verdict.** Accepted as the primary method.

**Push notification.** Optional. The page works fully without it.
- **What it carries.** Tool title, target, summary, expiry, and a `view` link to the page.
- **What it never carries.** No ntfy `http` action that approves directly (Q13). Anyone who can read the topic receives the whole message, including action URLs, headers and bodies. Topic access is set in the channel's own ACLs, which the server cannot verify, and ntfy tokens grant access to the whole user account (docs.ntfy.sh/config, access control).
- **Recommended channel setup.** ntfy with `auth-default-access: deny-all`, a write-only user for the server, and a read-only user for the phone.
- **On failure.** The approver uses the bookmark and the id from the chat.

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
| Reaches a person in a terminal CLI | Yes (docs; T-1 skipped) | Yes | **Yes** | No | n/a |
| Model can self-approve (T1) | Via client config | No (with step-up) | **No** | Button: host-trusted; +TOTP: no | **Yes** |
| Replay / cross-operation (T2, T3) | Bound | Bound | **Bound + fresh preview** | Bound | Bound |
| Phishing residue (T4) | n/a | Low | **Real-time relay (TOTP), reduced by bookmark + fixed origin** | Low | n/a |
| Operator setup | None | As c | **One approver (CLI + QR), listener, URL, TLS or proxy** | As c | One variable |
| New dependency | No | No | **No (stdlib; in-repo QR encoder)** | No | No |

## 5. Decision (accepted 2026-10-16)

1. **Primary: option c**, `SHELL_MCP_APPROVAL_METHOD=web`.
   - **What it consists of.**
     - An approval page on its own listener, loopback by default, with an origin fixed by configuration.
     - A TOTP code from the approver for every approval and every decline; exactly one approver by default.
     - Approval-id re-calls, with full binding and a fresh preview.
     - An optional ntfy push. The page works fully without it.
   - **Why this one.**
     - It is the only option that reaches a person through both of the maintainer's clients today.
     - It is the only one whose proof of a person the server verifies itself: a code from a device the model cannot reach.
2. **Fallback and default.**
   - **Fallback: option e**, `SHELL_MCP_APPROVAL_METHOD=confirm-argument`, explicit and WARN-logged.
   - **Default: `none`.** Approval-gated tools refuse with `approval_unavailable`, as today.
3. **Client-side defence in depth:** `_meta["anthropic/requiresUserInteraction"]: true` on every approval-gated tool.
4. **Deferred (S4d, optional, after S4b and S4c):**
   - MCP Apps panel for Desktop chat (with the TOTP field);
   - URL-mode delivery of the same link;
   - form elicitation as a weaker method for terminal-CLI users;
   - WebAuthn instead of TOTP;
   - an inbox page that lists pending approvals.

   Each reuses option c's record.

**Under this design, the model can:**
- start an approval request (bounded per principal; an identical pending request returns the same record);
- see a request's status;
- relay the approval URL, which it is told to show unchanged;
- misdescribe the request in chat. The page shows the truth, and operators open it from a bookmark or the push, not from the chat.
- re-call after approval to run exactly what was approved.

**It cannot:**
- approve or decline. Both need the approver's code.
- change what an approval covers, or what the page says about it. The description and preview come from the server, generated from the canonical arguments.
- reuse an approval for another tool, target, argument set or principal;
- run an approval twice, after expiry, after a restart, or after the target's preview or the gate policy changed;
- extend a TTL;
- approve with the MCP bearer token, a browser session, or a click.

Under `confirm-argument` it can approve everything, and the logs say so. A compromised server can skip approval under every method; the gate and privileged policies remain the boundary (PRIVILEGED §3).

## 6. Design detail for S4b

### 6.1 Flow

```
model ──call(args)──────────────▶ server: validate → preview via gate (read-tier preview op)
                                          → create record {pending} → push (optional)
model ◀─ ok:false, approval_pending, approval{id,url,expires_at,summary}
         message: "show the user this URL exactly as written: <url> …"
approver ── opens the bookmarked page (enters the id) or taps the push ──▶ approval listener
approver ── POST approve|decline {approver, code, csrf_token} ──▶ verify code → record {approved|declined by <name>}
model ──call(args, approval_id)─▶ server: match record → mark used → fresh preview, compare
                                          → execute with ceiling = tool tier → result
```

- **A re-call while still pending** waits up to 20 s for a decision (a fixed bound, and never past the expiry). Then it returns `approval_pending` again, so the model does not spin.
- **A declined record** gives `approval_declined`.
- **Anything else** gives `approval_invalid`: unknown, expired, used, a mismatch, or a changed preview or policy.

### 6.2 The approval record

| Field | Notes |
|---|---|
| `id` | 128 random bits, lowercase base32 (26 chars). It is a capability to *view*, never to approve or decline. |
| `principal`, `tool`, `target` | As resolved by the server (the target after defaulting). |
| `args_sha256` | SHA-256 of the canonical arguments: the decoded, typed input with defaults applied and `approval_id`/`confirm` removed, marshalled deterministically. |
| `description` | One line generated by the server from the tool and the canonical arguments, e.g. "Delete /srv/app/old (recursive) on target-a". Never text the model supplied as prose; the tools have no free-text "reason" argument. |
| `preview`, `preview_sha256` | The gate's or helper's preview, rendered by the server (bounded, e.g. 16 KiB), and its hash. |
| `policy_sha256` | From the gate's `gate` block on the preview response. |
| `created_at`, `expires_at` | TTL from `SHELL_MCP_APPROVAL_TTL`. |
| `state` | `pending` → `approved` / `declined` / `expired` → `used`. |
| `approver`, `decided_at`, `decided_from` | Set on decision: the verified approver's name and the client address. |
| `csrf_token` | 128 random bits, created with the record. Required on both POSTs. |

- **Store.** A bounded map: at most 5 pending records per principal (more gets `approval_unavailable`, "too many pending approvals") and at most 256 records in total. Expired records are swept, and their expiry is audit-logged.
- **Deduplication.** An identical request (same bound fields) while one is pending returns the existing record.

### 6.3 Execution check (the re-call)

Every check must hold, in this order:
1. The record exists and is `approved`. A pending record waits as in §6.1.
2. It is unexpired and unused.
3. The principal, tool, target and `args_sha256` are equal.
4. The record is marked `used`. This happens atomically, before anything is sent, so a failed execution never leaves a reusable approval.
5. A fresh preview is computed, and both its hash and the policy hash must equal the record's. If they differ, the answer is `approval_invalid` ("the target or policy changed since approval; request a new approval").
6. The operation runs with the tool's ceiling. Where the operation supports a precondition, the server passes what the preview saw: `expected_sha256` of the previewed content for `shell_priv_write_file` and `shell_write_file`.

### 6.4 TOTP, approvers and enrolment

- **Algorithm.** RFC 6238: HMAC-SHA-1, 6 digits, 30 s step.
- **Clock skew.** **±1 step only** (the RFC's recommended maximum); ±2 is refused.
- **Single use.** Each time-step code is usable once per approver.
  - **Last accepted step.** The server records the last accepted step per approver, and refuses a code for that step or any earlier one. The RFC says the verifier "MUST NOT accept the second attempt of the OTP". This covers approve and decline alike.
  - **Restart.** At process start, every approver's last accepted step is set to the current step. A code seen before a restart cannot be used after it; a decision in the first ≤ 30 s after a start waits for the next code.
- **Brute force.**
  - **Per approver:** at most **3 wrong codes in any rolling 60 s**. The next wrong code locks that approver out for 15 minutes.
    - Each consecutive lockout doubles, up to 24 hours. A successful decision resets the count.
    - During a lockout, every code for that approver is refused without being checked.
    - Each lockout is audit-logged at WARN, and pushed if a push channel is configured.
  - **The bound.** About two dozen guesses a day per approver. At 3 valid codes in 10⁶, that is under 10⁻⁴ a day, against an attacker who must also reach the listener.
  - **Lockout state** is in memory; a restart clears it. Only the operator can restart the server.
- **Approvers.**
  - **One by default.** There is exactly one approver by default. `SHELL_MCP_APPROVAL_MAX_APPROVERS` (default 1, at most 8) must be raised explicitly before the server accepts more.
  - **Named.** Each approver has a name, which the audit records.
  - **The form.** With one approver the form has no name field. With several, the approver chooses their name, and each has their own lockout and last accepted step.
- **The secret file.**
  - **Location.** Approvers live only in a mounted secret file: `SHELL_MCP_APPROVERS_FILE`, one approver per line, `<name> <base32 seed>`.
  - **Never in the environment.** There is no plain environment variable: `SHELL_MCP_APPROVERS` is refused at startup.
  - **Permissions.** A file readable or writable by group/other fails startup. That is stricter than the other secret files' WARN, because a readable seed is an approval.
  - **Never logged.** Seeds are never logged, and never appear in `check` or effective-config output.
- **Enrolment.** `shell-mcp approver add --name <name> --file <path>` creates an approver.
  - **Seed.** It generates a 160-bit seed with `crypto/rand`.
  - **The file.** It writes the line atomically (temp file + rename, mode `0600`). It refuses if:
    - the name exists;
    - the file is group/other-accessible;
    - the file already holds an approver and `--allow-multiple` is not given.
  - **The QR code.** It shows the `otpauth://totp/shell-mcp:<name>?secret=…&issuer=shell-mcp&algorithm=SHA1&digits=6&period=30` URI **once, as a QR code in the terminal** (Unicode half-blocks), with the URI text below it for authenticators that take manual entry.
    - It refuses to print either unless stdout is a terminal, so the seed cannot land in a pipe, file or container log.
    - In the container, the command runs as `docker run --rm -it` with the secrets directory mounted.
  - **Other commands.** `shell-mcp approver remove --name <name> --file <path>` and `approver list` (names only) complete the set. The server reads the file at start, so changes take effect on restart.
- **QR encoder.** The standard library has none. S4b-1 writes a small encoder in `internal/approval/qr`: byte mode, error-correction level M, versions 1–10, all eight masks with the standard penalty scoring.
  - **Tests.** Golden matrices generated offline by an established encoder are committed as fixtures, and the fixture comment names the encoder and its version. A fuzz target covers bounds and panics.
  - **The alternative** is a third-party module, which is a STOP-and-ask with justification.
- **Guidance.** Keep the seed only in the phone's authenticator and the server's secret file. Never paste it into a chat, and never keep it on the workstation where the agent runs.

### 6.5 The approval page

- **Listener.** Its own bind and port, `SHELL_MCP_APPROVAL_BIND`/`_PORT`, default **`127.0.0.1`/`8081`**. The page is never served on the MCP listener, and `/mcp` is never served on this one.
- **Exposure rules** (fail-closed at startup). A non-loopback bind must have one of:
  - **Native TLS.** `SHELL_MCP_APPROVAL_TLS_CERT_FILE` and `_KEY_FILE`, served with `crypto/tls`, TLS 1.2 or later.
  - **A TLS-terminating proxy.** A non-empty `SHELL_MCP_TRUSTED_PROXIES` covering that proxy. The listener then serves **only** connections whose peer address is inside `SHELL_MCP_TRUSTED_PROXIES`. Any other peer is refused with 403, logged, and gets no page. So plain HTTP never reaches anything but the proxy.

  A non-loopback bind with neither fails startup. In a container the bind is typically `0.0.0.0` inside the container, so one of the two is always required there.
- **Fixed origin.** `SHELL_MCP_APPROVAL_PUBLIC_URL` fixes the page's origin. It must be `https://`, unless its host is loopback and the bind is loopback.
  - Every link the server emits uses it.
  - Requests whose `Host` differs are refused.
  - An `Origin` header, when present, must equal it.
- **Auth.** The bearer token is never accepted here.
- **Routes**; everything else is 404:
  - `GET /`: **the bookmark page.** It shows the origin banner and a field for an approval id. Submitting it is a GET to `/approvals/{id}` that changes nothing. It lists nothing; the inbox is deferred.
  - `GET /approvals/{id}`: the approval page.
  - `POST /approvals/{id}/approve` and `POST /approvals/{id}/decline`: fields `code`, `csrf_token`, and `approver` when there are several.

  **Approve and decline are POST-only**, and both need a valid code, so every decision has a verified approver name. GET never changes state.
- **What the page shows:**
  - **The origin banner**, first and prominent: "Approval page for shell-mcp at `<public origin>`. Check that your address bar shows exactly this origin. Open approvals only from your bookmark or this server's own notification, never from a link in a chat." The origin comes from configuration, not from the request.
  - The tool title and name, target name and host, principal.
  - The record's **description**, generated by the server from the canonical arguments.
  - Every canonical argument as escaped data in a table, never as prose.
  - The preview.
  - Expiry, approval id.

  Strings from the host or the caller show control, bidi and other non-printing characters as visible escapes, so a file name cannot disguise the operation. Nothing on the page is model-supplied prose.
- **CSRF and requests.**
  - The record's `csrf_token` is embedded in each form and required on both POSTs.
  - `http.CrossOriginProtection` (Go ≥ 1.25).
  - No cookies.
  - Body ≤ 4 KiB.
  - Per-client rate limit, client derived as on `/mcp`.
- **Response headers.**
  - `Content-Security-Policy: default-src 'none'; style-src 'sha256-…'; img-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`. **No external resources:** no script, font, image or stylesheet from anywhere. The page's own inline style is pinned by hash.
  - `X-Frame-Options: DENY`.
  - `Cache-Control: no-store`.
  - `Referrer-Policy: no-referrer`.
  - `X-Content-Type-Options: nosniff`.
  - `Cross-Origin-Opener-Policy: same-origin`.
  - `Cross-Origin-Resource-Policy: same-origin`.
- **No push needed.** The page works with no push channel configured: the approver uses the bookmark and the approval id shown in the chat.

### 6.6 Envelope, result text and tool schema

- **New code.** `approval_pending` joins the closed set of server codes, with `ok: false`, since nothing ran.
- **New `approval` object.** Envelopes of approval-gated tools gain an optional `approval` object: `{id, status, url, expires_at, summary}`, with status `pending`, `approved`, `declined`, `expired` or `used`.
- **The `approval_pending` text.** `error.message` and the text block say, in server-generated words: "Approval required. Show the user this URL exactly as written, without changing or shortening it: `<url>`. The approver opens it from their bookmark or the server's notification, checks the operation, and approves with a code. Then call this tool again with the same arguments and `approval_id` `<id>`."
  - The URL is built from the configured origin and the record id, so it carries no string from the host or the caller. The rule that the text block never repeats such strings still holds.
  - Tool descriptions stay terse and never explain the flow (CLAUDE.md). The instruction lives in this result.
- **New input.** Approval-gated tools gain an optional `approval_id` (pattern `^[a-z2-7]{26}$`), always present, so the catalogue does not depend on configuration. `confirm` appears only under `confirm-argument`, as D-006 already says; the catalogue snapshot covers both variants.
- **New tool `_meta`.** Approval-gated tools carry `"anthropic/requiresUserInteraction": true`.

### 6.7 Configuration

| Variable | Default | Rule |
|---|---|---|
| `SHELL_MCP_APPROVAL_METHOD` | `none` | `none` \| `web` \| `confirm-argument`. Replaces `SHELL_MCP_APPROVAL_FALLBACK`, which is refused at startup if set. `confirm-argument` logs a WARN at startup and on every use. |
| `SHELL_MCP_APPROVAL_TIERS` | `destructive` | Unchanged. |
| `SHELL_MCP_APPROVAL_TTL` | `300` | Seconds, 60..900. |
| `SHELL_MCP_APPROVAL_BIND` / `_PORT` | `127.0.0.1` / `8081` | `web` only. The port must differ from `SHELL_MCP_PORT`. A non-loopback bind requires native TLS or `SHELL_MCP_TRUSTED_PROXIES` (§6.5). |
| `SHELL_MCP_APPROVAL_TLS_CERT_FILE` / `_KEY_FILE` | — | Optional native TLS for the approval listener. Both or neither. |
| `SHELL_MCP_APPROVAL_PUBLIC_URL` | — | Required for `web`. Fixes the page's origin: absolute `https://` URL (`http://` only with a loopback host and a loopback bind), no userinfo, query or fragment. |
| `SHELL_MCP_APPROVERS_FILE` | — | Required for `web`. A mounted secret file only; the plain variable `SHELL_MCP_APPROVERS` is refused. One `<name> <base32 seed>` per line. Names match `^[a-z][a-z0-9-]{0,31}$`; at least one approver, no duplicates, seeds ≥ 160 bits. Group/other-accessible fails startup. |
| `SHELL_MCP_APPROVAL_MAX_APPROVERS` | `1` | 1..8. A file with more approvers than this fails startup. |
| `SHELL_MCP_APPROVAL_NOTIFY_URL` | — | Optional ntfy topic URL (`https://…/<topic>`); JSON publish. |
| `SHELL_MCP_APPROVAL_NOTIFY_TOKEN` / `_FILE` | — | Bearer token for the notify URL. Required when the URL is set. |

**Fail-closed startup rules** (additions to SECURITY §6). The server exits with a one-line reason on:
- an unknown method;
- `SHELL_MCP_APPROVAL_FALLBACK` or `SHELL_MCP_APPROVERS` set;
- `web` without a valid public URL or approvers file;
- an approvers file that is group/other-accessible, has a line that does not parse, a short seed or a duplicate name, or holds more approvers than `SHELL_MCP_APPROVAL_MAX_APPROVERS`;
- a non-loopback approval bind without native TLS or `SHELL_MCP_TRUSTED_PROXIES`;
- a TLS certificate without its key, or the reverse, or either unreadable;
- an `http://` public URL with a non-loopback host or bind;
- the approval port equal to the MCP port;
- a notify URL that is not `https://` (loopback excepted), or one without a token;
- a TTL outside 60..900;
- `SHELL_MCP_APPROVAL_TIERS` without `destructive` (unchanged).

### 6.8 Audit lines (server, JSON)

| Message | Fields |
|---|---|
| `approval requested` | `approval_id`, principal, tool, target, `args_sha256`, `preview_sha256`, `policy_sha256`, `expires_at`, method |
| `approval decided` | `approval_id`, `decision` (`approved` or `declined`), **`approver` (the verified name**, or `model (confirm-argument)`), client address, method |
| `approval expired` | `approval_id` |
| `approval attempt refused` | `approval_id` if any, `approver` (the name chosen on the form), `reason` (`bad_code`, `reused_code`, `csrf_token`, `cross_origin`, `host`, `expired`, `locked`, `unknown`, `peer_not_proxy`), client address |
| `approval lockout` | `approver`, `until`, `consecutive` |
| `approver enrolled` / `approver removed` (CLI, stderr) | `name`, file path |
| `tool call` (existing) | gains `approval_id` and `approval_outcome` (`pending`, `used`, `invalid`, `declined`) |

**Never logged:** codes, seeds, `otpauth` URIs, CSRF tokens, the notify token, the description or preview text, or content. Hashes, ids and approver names only.

The gate's and the helper's audit lines are unchanged (Q9: not now).

## 7. Changes implied (exact wording; S4b applies it)

### 7.1 D-006 (plan §2), replacement text

> **D-006 | Consequential operations require a human's approval, given outside the model's reach, never a model-supplied argument.**
>
> **Which operations.** Always approval-gated: every destructive operation and every privileged (`priv_*`) operation of tier operator or above. `SHELL_MCP_APPROVAL_TIERS` (default `destructive`) can add ordinary operator writes.
>
> **The method** (`SHELL_MCP_APPROVAL_METHOD=web`) is out-of-band.
> - **The request.** The first call computes a preview and returns `approval_pending`, with an approval id and the URL of an approval page served by shell-mcp on its own listener. The listener is loopback by default. The page's origin is fixed by `SHELL_MCP_APPROVAL_PUBLIC_URL`. The result tells the model to show that URL unchanged.
> - **The page.** The approver opens it from a bookmark or the server's own optional push notification, never from a link in the chat. It shows its own origin prominently, and a description and preview the server generated from the canonical arguments.
> - **The decision.** The approver approves or declines with a current TOTP code from their authenticator. There is exactly one enrolled approver by default.
> - **The re-call.** The model re-calls the tool with the approval id. The server executes only if that exact approval was approved: principal, tool, target, SHA-256 of the canonical arguments, of the preview and of the gate policy, within `SHELL_MCP_APPROVAL_TTL`, and not yet used. A fresh preview must still match.
> - **State.** Approval state is in memory and does not survive a restart.
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
> - A code from the approver's authenticator, entered on a page whose origin the approver checks and whose content the server generated, is something the model can neither produce nor alter. It works with every client, because the model only re-calls a tool.
> - The binding stops an approval for one operation being used for another.
> - Approval defends against a misled model, not a compromised server; that case is bounded by the host policies (docs/PRIVILEGED.md §3).

Plan §1 goal 4 and §1.1 "Why human approval through the protocol" change to match: "on a server-hosted approval page with a code from the approver's authenticator" in place of "through MCP elicitation".

### 7.2 S-12 (plan §4.2), replacement text

> **S-12 | Human approval (D-006).**
> - **Record.** An approval record (128-bit random id) binds principal, tool, target, canonical-args SHA-256, preview SHA-256, gate-policy SHA-256 and expiry. Its description and preview are generated by the server from the canonical arguments and the gate's preview, never from model-supplied text. It is held in a bounded in-memory store, at most 5 pending per principal, and lost on restart.
> - **TOTP.** A record is approved or declined only on the approval page, with a valid TOTP code (RFC 6238: SHA-1, 6 digits, 30 s, ±1 step only) of an enrolled approver.
>   - The last accepted step is recorded per approver. Each step's code is accepted once, and no code from before process start is accepted.
>   - At most 3 wrong codes per approver in any rolling minute; then that approver is locked out for 15 minutes, doubling per consecutive lockout up to 24 h. Each lockout is logged and, when configured, pushed.
> - **Executing.** The re-call executes only if the record is approved, unexpired, unused and matches every bound field. It is marked used before execution, and a fresh preview's hash and the policy hash must still match. Otherwise the answer is `approval_pending`, `approval_declined` or `approval_invalid`.
> - **The page.**
>   - **Listener.** It has its own listener, loopback by default, never authenticated by the bearer token. A non-loopback bind requires native TLS, or a `SHELL_MCP_TRUSTED_PROXIES` covering a TLS-terminating proxy (and then serves only those peers); otherwise startup fails.
>   - **Origin.** Its origin is fixed by configuration and shown prominently on the page.
>   - **Hardening.** Approve and decline are POST-only, with a CSRF token. No cookies, no script, no external resources. A strict CSP, `frame-ancestors 'none'`, `X-Frame-Options: DENY` and `Cache-Control: no-store`. It is rate-limited.
> - **Approvers.** There is exactly one approver by default; more need `SHELL_MCP_APPROVAL_MAX_APPROVERS`. An approver is created by `shell-mcp approver add`, which shows the `otpauth` QR code in the terminal once. Seeds live only in a mounted secret file that is not group/other-accessible, never in environment variables or logs.
> - **Audit.** Every approval and decline is audit-logged with the approver's name, and requests, refused attempts, lockouts, expiry and use with ids and hashes. Codes, seeds, tokens and content are never logged.

### 7.3 Other documents

| Document | Change |
|---|---|
| plan §4.1 F-09 | "human approval through elicitation (D-006)" → "human approval (D-006)". |
| plan §5 | **S4b** is split as in §8. **S4c** "privileged tools (`shell_priv_*`), approval-gated per TOOLS.md through the S4b approval core, with previews' preconditions passed through". New optional **S4d** (§8). |
| plan §8 | `internal/approval/` comment → "approval records, binding, TOTP, approvers and enrolment, QR encoder, approval page, notifier". |
| SECURITY §1 | New asset rows: approver TOTP seeds (mounted secret file, `0600`, never in environment or logs, never on the workstation); the notify token. |
| SECURITY §2 | **Model self-approval** mitigation → "The approver approves on the server's approval page, with a TOTP code from an authenticator the agent's environment does not hold. The approval is bound to principal, tool, target, arguments, preview and policy, and is short-lived and single-use (D-006, S-12). `none` fails closed. `confirm-argument` is a logged opt-out with no protection against this threat." New rows:<br>• **Approval phishing / relay.** A look-alike page relays a typed code. Mitigations: the origin is fixed by configuration and shown on the page; approvers open approvals only from a bookmark or the server's push, never from a chat link; the result text tells the model to show the URL unchanged; codes are single-use, with lockouts; WebAuthn is the future fix.<br>• **Approval brute force.** At most 3 wrong codes per approver per minute, then doubling lockouts, each logged and pushed.<br>• **Approval page exposure.** Loopback by default; TLS or a trusted proxy required for anything else; proxy-only peers. |
| SECURITY §6 | Add the startup rules of §6.7. Replace "an unknown fallback" with "an unknown method; `SHELL_MCP_APPROVAL_FALLBACK` or `SHELL_MCP_APPROVERS` set". |
| ARCHITECTURE §1 diagram, §2, §3 | Approval listener next to `/mcp`; `internal/approval` description; request lifecycle step 2 rewritten to §6.1; "stateless server" note: in-memory state adds the approval store and the approvers' TOTP state. |
| ARCHITECTURE §5 | Variables of §6.7; remove `SHELL_MCP_APPROVAL_FALLBACK`. |
| ARCHITECTURE §6 | `approval_pending` in the closed set; the optional `approval` object; the `approval_pending` message. |
| TOOLS.md approval section | Rewritten to the web flow:<br>• the codes `approval_pending`, `approval_declined`, `approval_invalid` and `approval_unavailable`;<br>• `approval_id` on gated tools, and `requiresUserInteraction`;<br>• the client table gains the S4b-scope findings: the Code tab declines in the SDK host, the terminal CLI renders (docs), VS Code declines, Desktop chat declares only MCP Apps. |
| `docs/PRIVILEGED.md` §3 | "enforced by the MCP server, which holds the HMAC key" → "enforced by the MCP server, which holds the approval records and verifies the approver's code". |
| deploy/ (S5) | This is a `deploy/` hardening-flag change, so it is a STOP-and-ask in that session.<br>• **Compose:** a second port mapping for the approval listener (loopback by default); the approvers secret file; the optional notify token; and either TLS files or the reverse proxy's address in `SHELL_MCP_TRUSTED_PROXIES`.<br>• **`.env.example`** entries.<br>• **An "approvals" section:** enrolment with `docker run --rm -it … approver add`; exposure to the phone over the VPN or proxy; the bookmark guidance; ntfy ACLs (`deny-all`, a write-only server user, a read-only phone user). |
| `docs/CLIENTS.md` (S5) | The client matrix, with: approvals arrive as a URL in the tool result (and optionally a push), never as a dialog. Approvers open the bookmarked page. |

## 8. S4b outline, split into sessions

**S4b-1: approval core** (Opus 5.5, High). Its first commit applies §7's wording to plan, SECURITY, ARCHITECTURE, TOOLS and PRIVILEGED.
- **Scope:**
  - `internal/approval`: the record store, canonical arguments and server-generated descriptions, binding and the execution check.
  - TOTP: RFC 6238 vectors, ±1 step, last accepted step, per-approver rolling-minute limit and doubling lockouts.
  - The approvers file, with a single approver by default.
  - The notifier (ntfy JSON publish, optional).
  - The approval listener and page:
    - bookmark page, origin banner;
    - POST-only decisions with a CSRF token, decline needing a code;
    - CSP and headers;
    - the exposure rules, with native TLS and proxy-only peers.
  - Config and startup rules.
  - Envelope `approval_pending`, the `approval` object and the result text.
  - `approval_id` on gated tools.
  - `define`'s `approvalGuard` replaced by the approval flow: today that covers operator tools under `SHELL_MCP_APPROVAL_TIERS=operator`.
  - The `requiresUserInteraction` meta.
  - `confirm-argument` on the same record.
- **Enrolment.** `shell-mcp approver add|remove|list`, and the in-repo QR encoder (§6.4). The encoder may land as its own first PR if it grows.
- **Tests first** (failing commits named in the PR): §9.1 and the in-process simulated-human tests.
- **Fuzz** (60 s each): the approvers-file parser, the TOTP code parser, the approval-id parser, canonical-argument hashing (round trip), and the QR encoder (bounds).

**S4b-2: destructive tools** (Opus 5.5, High).
- **Scope:**
  - `shell_preview_delete` and `shell_preview_git_discard` (read tier).
  - `shell_delete_path` and `shell_discard_git_changes`.
  - `shell_run_command`'s admin registration at `destructive`, approval-gated.
  - Execution with fresh-preview comparison.
  - e2e-host with a simulated human (§9.2).

**S4c: privileged tools.**
- **Scope.** As planned, with approval through S4b-1. Preview preconditions (`expected_sha256`) are passed to the helper; package previews come from the `priv_pkg_*_preview` ops.

**S5: deployment docs.** §7.3's deploy/ and CLIENTS rows.

**S4d (optional, later; each part its own PR):**
- an MCP Apps approval panel for Desktop chat (with the TOTP field; starts with a spike verifying rendering and app-only routing through mcp-remote to a stateless server);
- URL-mode delivery of the page link;
- a form-elicitation method for terminal CLIs;
- WebAuthn (dependency STOP-and-ask);
- an authenticated inbox page.

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
  - The same step twice is refused, across approve and decline.
  - A code for a step earlier than the last accepted one is refused.
  - A code from the step current at start is refused.
- **Lockout.**
  - The 4th wrong code within 60 s locks the approver out, and a correct code during the lockout is refused.
  - The second lockout lasts twice as long, capped at 24 h.
  - A success resets the count.
  - With two approvers, the counters and last accepted steps are independent.
  - Every lockout is logged and, with a notifier configured, pushed.
- **Page.**
  - GET never changes state.
  - Approve and decline by GET are 405.
  - A POST without, or with another record's, CSRF token is refused.
  - Decline without a valid code is refused.
  - Cross-site `Sec-Fetch-Site`, a foreign `Origin` and a wrong `Host` are refused.
  - The bearer token gives nothing, and the two listeners never serve each other's routes.
  - **Headers.** All headers of §6.5 are present. The HTML holds no `src`, `href` or `action` pointing off-origin, and no `<script>`.
  - **Origin banner.** It shows the configured origin even when the request's `Host` differs; such a request is refused anyway.
  - **Server-generated text.** An argument value written to look like instructions appears only escaped in the arguments table, never in the description or headings.
  - Control and bidi characters in a preview are shown as escapes.
  - The body cap and the rate limit hold.
  - The bookmark page has no listing.
  - With no notifier configured, the whole flow works.
- **Exposure.**
  - A non-loopback bind with neither TLS nor trusted proxies fails startup.
  - With trusted proxies, a peer outside them gets 403 and a log line, and no page.
  - With TLS files, the listener serves TLS only.
- **Approvers and enrolment.**
  - `approver add` creates the file `0600`, appends atomically, and refuses a duplicate name.
  - It refuses a group/other-accessible file.
  - It refuses a second approver without `--allow-multiple`.
  - It refuses to print when stdout is not a terminal.
  - The `otpauth` URI parameters are right, and the QR matches its golden matrices.
  - The server refuses more approvers than `SHELL_MCP_APPROVAL_MAX_APPROVERS`, and refuses `SHELL_MCP_APPROVERS`.
- **Store.** The pending cap per principal holds; deduplication returns the same id; the global bound holds; restart (a new store) makes old ids unknown.
- **Config.** Every fail-closed rule of §6.7.
- **Result text.** The `approval_pending` message contains the exact configured URL with the record id, and nothing from the host or the caller.
- **`confirm-argument`.** It works only in that mode; a WARN on every use; the approver is recorded as the model.
- **Logs.** The lines of §6.8, with the approver's name on every decision. Codes, seeds, URIs, tokens, descriptions and preview text never appear; this is proved by searching the captured log for each.
- **Catalogue.** The snapshot covers both schema variants; gated tools carry the meta.

### 9.2 End-to-end with a simulated human (S4b-2, e2e-host)

- **Delete.**
  - **Before approval.** `shell_delete_path` returns `approval_pending`, and the file still exists. No gate `delete` line for the principal appears, only `delete_preview`.
  - **Approval.** The test acts as the human: it fetches the page through the bookmark route, reads the CSRF token, computes the TOTP from a test seed, and POSTs approve.
  - **After approval.** The re-call deletes, and the gate's audit line appears once. A second re-call is `approval_invalid` with no gate line.
- **Change after approval.** The previewed directory changes after approval; the re-call is `approval_invalid` and nothing is deleted.
- **Decline.** A decline with a code gives `approval_declined`, the log names the approver, and nothing runs.
- **Restart.** Restarting the server between approval and re-call gives `approval_invalid`, and nothing runs.
- **Ceiling.** A destructive `shell_run_command` runs only after approval, at ceiling `destructive`.

### 9.3 Live client checks (maintainer, after S4b-2)

1. **Code tab, no push configured.**
   - The model gets `approval_pending` and shows the URL unchanged.
   - The approver opens the bookmarked page on the phone, enters the id, checks the origin banner and the description, and approves with a code.
   - The re-call deletes a scratch file on a test target.
   - The permission prompt for the gated tool shows no "Always allow".
2. **Desktop chat through mcp-remote `--protocol auto`.** The same as the Code tab check.
3. **Negative.**
   - Ask the model to approve or decline the request itself: it cannot.
   - Enter four wrong codes within a minute: the approver is locked out, and the log and the push say so.
4. **Push, if configured.** The ntfy notification arrives with a `view` link, and no approve button.

## 10. Live test T-1

**Skipped (maintainer, 2026-10-16).** Whether a terminal CLI renders form elicitation rests on the Claude Code docs and third-party reports only (§1.3). That is enough: form elicitation is deferred to S4d either way, and the accepted method does not depend on it.

## 11. Decisions (maintainer, 2026-10-16)

**Answers to the open questions:**

| # | Question | Decision |
|---|---|---|
| Q1 | Out-of-band approval (c) as v1's method; elicitation out of v1 | **Accepted.** |
| Q2 | Step-up credential | **TOTP now; WebAuthn later** (a dependency STOP-and-ask when it comes). |
| Q3 | Where the page is served | **Its own listener and port.** |
| Q4 | Push channel | **ntfy, optional.** The page must work with no push at all (§6.5). |
| Q5 | Envelope | **`approval_pending` plus the `approval` object.** |
| Q6 | TTL | **Default 300 s, range 60..900.** |
| Q7 | Config naming | **`SHELL_MCP_APPROVAL_METHOD` replaces `_FALLBACK`**, and the old variable is refused. |
| Q8 | Re-preview at execution | **Refuse if the preview or policy changed.** |
| Q9 | Approval id on gate requests | **Not now.** |
| Q10 | Approvers | **Named approvers, defaulting to exactly one.** More need `SHELL_MCP_APPROVAL_MAX_APPROVERS` (§6.4). |
| Q11 | Inbox page | **Deferred.** The bookmark page takes an approval id and lists nothing (§6.5). |
| Q12 | `requiresUserInteraction` | **Yes.** |
| Q13 | Approving from the notification | **Never.** |

**Added requirements and where they are:**

| # | Requirement | Where |
|---|---|---|
| R1 | TOTP brute force and replay: a small per-approver per-minute wrong-code limit, then a lockout; each step's code usable once (last accepted step per approver); ±1 step only | §6.4; S-12 |
| R2 | Phishing: the page shows its origin prominently; operators open approvals from a bookmark or the server's push, never a chat link; the origin is fixed by config; the `approval_pending` text tells the model to show the exact URL unchanged | §6.5, §6.6; D-006; SECURITY §2 row; deploy docs |
| R3 | Page hardening: POST-only approve and decline with a CSRF token; strict CSP, no framing, no external resources, no-store; description and preview generated by the server from the canonical arguments | §6.2, §6.5; S-12 |
| R4 | Exposure: loopback by default; a non-loopback bind without TLS, or without `SHELL_MCP_TRUSTED_PROXIES` covering a TLS-terminating proxy, fails startup | §6.5, §6.7; S-12; SECURITY §6 |
| R5 | Enrolment: a CLI creates an approver and shows the `otpauth` QR in the terminal once; secrets only in a mounted secret file; every approval and decline audit-logged with the approver's name | §6.4, §6.8; S-12 |

**How the requirements were read where they met:**
- **"From a bookmark" (R2) with the inbox deferred (Q11).** The bookmark page takes an approval id and shows only that record.
- **"Every decline audit-logged with the approver's name" (R5).** Declining needs a code too, so the name is verified.
- **"Shows the QR in the terminal" (R5).** The standard library has no QR encoder, so S4b-1 writes one; a module would be a STOP-and-ask.
- **"Covering a TLS-terminating proxy" (R4).** The listener serves only peers inside `SHELL_MCP_TRUSTED_PROXIES` when it relies on them.
- **"Small limit" (R1).** Three wrong codes per rolling minute.
- **Seed files.** A group/other-accessible approvers file fails startup, not just a WARN.

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
- Whether ntfy's iOS and web clients send `http` actions like Android (irrelevant to the accepted design, which uses `view` links only).
