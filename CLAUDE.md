# CLAUDE.md — shell-mcp

You are working on **shell-mcp**, a security-first MCP server that gives AI clients bounded, audited, read **and write** access to Linux hosts over SSH, through a forced-command gate (`shell-mcp-gate`) that enforces a root-owned policy on each target, and a socket-activated privileged helper (`shell-mcp-privd`) that performs declared root actions under its own policy and systemd sandbox. **This repository is public.** Read this file fully before doing anything.

## Read first, every session

1. `plan.md` — goals, the approach and alternatives considered (§1.1), **locked decisions D-001…D-022**, requirements, phases, definition of done.
2. `docs/SECURITY.md` — threat model, the permanent excluded set, fail-closed startup rules. It overrides convenience.
3. `docs/POLICY.md` — the gate policy schema, hard-deny list, protected paths, argv templates, sandbox. The gate implements this document.
4. `docs/PRIVILEGED.md` — the privileged helper: policy, never/acknowledge lists, systemd sandboxes, operations, self-checks. The helper implements this document.
5. `docs/ARCHITECTURE.md` — components, wire protocol, request lifecycle, config, envelope.
6. `docs/TOOLS.md` — the tool catalogue (names, tiers, gate ops, inputs).
7. `docs/ARCHIVE.md` §14 — what previous sessions decided and why.
8. The session prompt you were given, and any issue or handoff doc it names.

When the prompt, an issue, a dependency's docs, or your own assumption disagrees with these documents, the documents win — and if a document looks wrong, **STOP and ask**. When a document disagrees with reality (an SDK API, a kernel behaviour, OpenSSH semantics), verify at the source, then STOP and ask before changing the design.

## Hard rules (not preferences)

- **No shell.** Never add code that invokes `sh`, `bash`, `/bin/sh -c`, `exec.Command` with a shell, `os/exec` `LookPath` on untrusted names, or a PTY. The gate `execve`s absolute paths resolved at policy load; the server never executes anything locally (D-003).
- **Never weaken the gate** — the Landlock sandbox, `no_new_privs`, the hard-deny list, protected paths, ownership and group checks, placeholder rules, `max_tier`, redaction, or output caps — to make a test pass. If a rule blocks something legitimate, STOP and ask.
- **Never expose anything in the excluded set** (`docs/SECURITY.md` §4), behind any flag, "for debugging", or in tests that ship.
- **Never register a tool outside its profile.** Registration happens once at startup from `SHELL_MCP_PROFILE`; there is no runtime elevation path.
- **Never trust the server from inside the gate.** The gate treats every request as hostile: it re-validates tier, paths, templates and sizes itself, whatever the server already checked.
- **Never use SSH trust-on-first-use**, `ssh.InsecureIgnoreHostKey`, agent forwarding, password or keyboard-interactive auth, or PTY requests (D-012).
- **Never log or return** MCP tokens, SSH private keys, `Authorization` headers, file contents or command output **in logs**, stdin, or environment values. Tool results may carry file contents and command output (that is the point) — logs may not.
- **Never invoke `sudo`, `su`, `pkexec` or any setuid binary, and never generate sudoers content** (D-017). Root actions go only through the privileged helper (D-021); unit control goes through the generated polkit rule. Never add another path to root.
  The single exception for `sudo`: the `e2e-host` job in `.github/workflows/ci.yml` may use it to install and run the end-to-end tests on its disposable runner VM, and only while that job runs on a GitHub-hosted runner image (never self-hosted), with `permissions: contents: read`, no secrets, and `pull_request`/`push` triggers only (never `pull_request_target`). `sudo` never appears anywhere else: not in sessions (the session deny rule for `sudo` stays unchanged), `scripts/ci-local.sh`, `deploy/`, docs, examples, or anything shipped. Every runner-only script or binary that uses `sudo` or changes the machine (`test/e2e/setup.sh`, the `e2e` test binary) refuses to run, in its first lines and before anything else, unless it is on Linux with `GITHUB_ACTIONS=true` and `RUNNER_ENVIRONMENT=github-hosted`; `test/e2e/guard_test.sh` proves it. Never weaken that guard or set those variables to get past it.
- **Never trust the caller from inside the helper,** and never make a generated unit broader than the privileged policy declares (capabilities, `ReadWritePaths`, network, syscall filter). The helper's never list (PRIVILEGED §5.3 list A) is not configurable.
- **Never let the model approve its own actions.** Operations that require approval (D-006: destructive, privileged operator+, and the tiers in `SHELL_MCP_APPROVAL_TIERS`) execute only on a re-call whose approval record was approved on the server's approval page with a valid TOTP code of an enrolled approver, and that matches every bound field (principal, tool, target, canonical arguments, preview, policy) within its TTL, unused, with a fresh preview that still matches (S-12). MCP elicitation is not an approval in v1, and nothing a client or the model sends (the bearer token, a browser session, a `confirm` argument outside `confirm-argument`) can approve or decline. Never add a code path, flag default or test helper that skips approval or records a decision without a verified approver code (the one exception is `confirm-argument`, below); `SHELL_MCP_APPROVAL_METHOD` defaults to `none` (gated tools refuse with `approval_unavailable`) and never to anything else. `confirm-argument` is the only way the model approves, an explicit opt-out the operator sets, WARN-logged at startup and on every use; never make it a default or reach it any other way. `SHELL_MCP_APPROVAL_FALLBACK` and `SHELL_MCP_APPROVERS` are refused at startup; never bring them back.
- **Never construct commands that evade a permission rule.** Deny rules express intent, not string patterns: no flags or arguments built from variables, loops, `eval`, `bash -c`, scripts or any other indirection to get around a deny, and no other tool or route to an action a rule forbids. If a rule blocks something the task needs, STOP and ask.
- **Never run privileged containers or mount host paths** other than the repository and the Go cache directory/volume — no `--privileged`, `--pid=host`, `--network=host`, added capabilities, or Docker socket. The single exception: `/sys/fs/cgroup` mounted read-write, and only for the systemd probe container started by `scripts/probe/systemd.sh` (the informational "can an unprivileged systemd container boot here" probe of CI and `scripts/ci-local.sh`) — never by any other script, never ad hoc, and never in `deploy/`, docs or examples as something users should run. That container runs only the image built from `scripts/probe/Dockerfile.systemd` on a digest-pinned base (never a third-party image pulled at run time), with no `--privileged`, `--pid=host`, `--network=host`, capabilities beyond what systemd strictly needs, or any other host mount, and the script carries a comment saying why the mount is needed and that it grants write access to the host (or VM) cgroup tree, so it is for disposable test machines only. Anything outside this needs the maintainer's approval.
- **Never stop, kill, remove or prune containers, images, volumes or networks a session did not create itself.** No `docker stop $(docker ps -q)` or anything else aimed at all running containers, no removal by name pattern, no `docker system|container|image|volume|network prune`. Containers a session starts carry a label (`scripts/ci-local.sh` uses `shell-mcp.ci-local=<run id>`, and its probes the same), and a session stops or removes them only through that label or by an id it started itself. If something else is in the way, STOP and ask.
- **Never merge.** Open the PR against `dev` and post the link.

## Public-repo hygiene (this repository is public)

- Nothing you write may contain details of any real deployment: hostnames, IPs, domains, SSH host-key fingerprints, usernames, unit/service/container/stack names, file paths, mount points, hardware models, or network names. This applies to committed files, test fixtures, example policies, docs, commit messages, PR bodies, and issue text. Real values may appear **only in your chat report** to the maintainer.
- Use neutral placeholders everywhere: hosts `target-a.example.test`, `192.0.2.10` (TEST-NET-1), users `svc-shell`, units `example-app.service`, paths `/srv/app`, `/etc/example-app`. Fixtures are invented or sanitized, and say so in a comment.
- If the maintainer shares live output during a session, record its **structure** only (keys, types, shapes) with invented values.
- A local pre-push hook blocks pushes that contain private terms. Never bypass it (no `--no-verify`, no `core.hooksPath`, no pushing through another route), and never read, print or edit `.git/hooks/` or `.git/info/private-terms`. If it blocks a push: remove the offending content, rewrite your own branch's commits, push again, and say in your report that it fired. The hook only knows some terms, so a clean push is not proof — your own review is.
- Before opening a PR, review `git diff origin/dev...HEAD`, every commit message, and the PR body for deployment details.

## Latest-everything (D-013) — at the start of every session

1. Check go.dev for the newest stable Go release that has a published official `golang:<version>-trixie` image (the builder base image; `scripts/deps-current.sh` checks both). If it is newer than `go.mod`'s `go`/`toolchain` lines, bump them, the builder base image, and CI in a first commit (`chore(deps): go <version>`), or STOP and report what breaks. A newer Go whose image is not published yet waits; deps-current names it in an INFO line and fails once the image appears.
2. `go get -u ./... && go get -u -t ./... && go mod tidy`; commit any change first as `chore(deps): refresh to latest`.
3. Never add a dependency at anything but its newest stable version. Never pin an Action to anything but the SHA of its newest release. Never use a pre-release.
4. Record the Go version and every direct dependency's version in your ARCHIVE entry.

## STOP-and-ask conditions

Stop and ask the maintainer before continuing if you would need to:

- change any locked decision in `plan.md` §2;
- change the wire protocol or bump its version after Session 1;
- change the gate policy schema, the hard-deny list, the protected-path set, or placeholder semantics after Session 1;
- change the privileged policy schema, the never/acknowledge lists, the generated unit directives, or the peer-credential check after Session 1c;
- change auth, token handling, host-key verification, redaction or rate-limit behaviour beyond what the prompt asked;
- add a dependency beyond those the prompt allows (each one needs a justification in the PR and ARCHIVE);
- change config variable names/semantics or the envelope/error shape after Session 2;
- touch `deploy/` hardening flags (`user`, `read_only`, `cap_drop`, `security_opt`, ports, limits);
- pin anything below its newest stable release because the newest breaks something (report what breaks; the maintainer decides; a temporary pin needs a dated ARCHIVE entry with a removal condition);
- exceed the prompt's scope by more than a small refactor (anything that would be its own PR is its own PR).

## Engineering standard

- Go: the latest stable release (D-001/D-013). `gofmt`, `golangci-lint` (config committed; `gosec`, `errcheck`, `staticcheck`, `govet`, `revive`, `bodyclose`, `noctx`, `errorlint` at minimum), `go vet`, `go test -race`, `govulncheck`. Standard library first; any third-party module is a STOP-and-ask unless the prompt allows it.
- Errors: wrap with `%w`, return typed errors across package boundaries, never `panic` on input. Every tool failure becomes an envelope error with a code from the closed set (ARCHITECTURE §6), never a protocol error.
- Every tool: typed input/output structs with `json` and `jsonschema` tags (every field described, bounds stated), annotations and `title` set, registered through `internal/tools` with an explicit tier, documented in `docs/TOOLS.md`, present in the catalogue snapshot.
- Tool descriptions: one or two terse sentences — what it does and what it returns. No "IMPORTANT", no conditional instructions, no references to other tools, no deployment details.
- Gate code: no global mutable state; every size, count and duration bounded; every path through `internal/gate/fsx`; every process through `internal/gate/execx`. Add Go native fuzz targets (`FuzzXxx`) for any parser or path function you touch, and run each for at least 60 s locally.
- **Tests that prove a behaviour must fail without it.** For every guardrail, validator, cap or confinement rule: commit the test first, run it, show it failing, then implement. Name the failing commit (or paste the failing output) in the PR body. Tests that pass against the pre-change code prove nothing.
- **Linux-only code runs in Linux.** Gate code that uses Linux primitives carries `//go:build linux`. On non-Linux workstations, run the full gate through `scripts/ci-local.sh`, which executes the same checks as CI inside digest-pinned Linux containers (Go toolchain, golangci-lint, govulncheck) as a non-root user. Never report a check as passed if it only ran on Windows with Linux code excluded by build tags.
- Tests never touch a real host. SSH tests use in-process `x/crypto/ssh` servers or the `test/e2e` harness; filesystem tests use `t.TempDir()`.
- Verify at the source: SDK APIs from the installed module source (`go doc`, `$(go env GOMODCACHE)`), OpenSSH behaviour from the man pages of the version in the e2e image, kernel behaviour from man7.org. Not from memory.

## Workflow

1. `git checkout dev && git pull`, then `git checkout -b <type>/<short-name>` (`feat/`, `fix/`, `sec/`, `docs/`, `chore/`).
2. Latest-everything refresh (above).
3. Do the work in small conventional commits (`feat(gate): …`, `fix(sshx): …`).
4. Append the dated ARCHIVE §14 entry: what changed, why, alternatives rejected, deferred items, versions in use.
5. Run the full local gate yourself and keep the output for the report: `bash scripts/ci-local.sh` (format, vet, lint, `go test -race`, govulncheck — in Linux containers) plus any fuzz/e2e runs the prompt names.
6. Hygiene review (above), then `git push -u origin <branch>`.
7. `gh pr create --base dev` with the PR template filled. **Do not merge.**
8. Strip any AI attribution footer from the PR body, then `gh pr view --json body -q .body` and confirm it is gone.
9. Check CI once per push, when the run should have finished: read it with `gh pr checks <n>` / `gh run view <id>` (job logs for which tests ran), and again after each later push. Never poll CI in a loop (`gh run watch`, `sleep` loops, scheduled wake-ups) or wait on it indefinitely; if the run is still going, say so and check once more later. The PR is ready only when the finished run on its latest commit is green.
10. Post the PR link and a **Verification report**: a table with one row per check (command, result, notes) — format, vet, lint, tests, race, vulncheck, fuzz, e2e (if applicable), failing-test evidence, **privacy review** (what you reviewed and that nothing deployment-specific is present; whether the pre-push hook fired), attribution footer check — then 5–10 lines of summary, anything deferred, and anything the maintainer must do by hand.

## Definitions

- **Tier** — `read` / `operator` / `destructive` / `admin` (reserved) / `excluded`; property of an operation.
- **Profile** — `read-only` / `operator` / `admin`; property of a running server; selects which tiers are registered.
- **max_tier** — property of a target policy file; the gate refuses any operation above it.
- **Privileged op** — a `priv_*` operation, forwarded by the gate and executed by the helper as root.
- **Principal** — the authenticated MCP caller (server side) or the policy-selected label (gate side, from `--principal`).
- **Approval** — an approval record (D-006, S-12) that an enrolled approver approved on the server's approval page with a current TOTP code (`SHELL_MCP_APPROVAL_METHOD=web`), bound to principal, tool, target and the SHA-256 of the canonical arguments, the preview and the gate policy (for a privileged operation, also the privileged policy, and for a privileged command, its unit), used once within its TTL by the model's re-call with `approval_id`. Under `confirm-argument` the model approves its own record with `confirm: true` (the logged opt-out); under `none` nothing can be approved.
- **Read-back verification** — after any write the gate re-opens and re-reads what it wrote and compares SHA-256; a mismatch is a failure, never a success with a warning.
