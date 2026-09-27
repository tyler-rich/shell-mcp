# shell-mcp

A security-first [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI clients **bounded, audited access to Linux hosts over SSH** — reading and changing what container managers can't: systemd services, the journal, host and root-owned configuration files, ownership and permissions, packages, disk and process inspection, TLS certificate checks, and git-based deployments.

It is **not a remote shell**. There is no shell, no PTY, no interpreter, and no free-form command line.

> **Status: pre-alpha — scaffold only: the server exposes no tools yet. Not usable.** See [`plan.md`](plan.md).

## Security posture

- **Two independent gates.** The MCP server decides what the model can see; a small forced-command binary on each host (`shell-mcp-gate`) decides what actually runs, from a root-owned policy the server cannot change.
- **No shell, ever.** Built-in native operations for files and system state; fixed argv for systemd, journal and git; everything else through argv templates with typed placeholders. Shells, interpreters, pagers and editors are hard-denied.
- **Kernel-enforced confinement.** Every operation and every child process runs under a Landlock sandbox computed from the host policy, with `no_new_privs` set — before the request is even parsed.
- **Root without sudo.** Root actions are requested from a separate, socket-activated privileged helper that authenticates the caller by kernel peer credentials, applies its own root-owned policy, runs under a generated systemd sandbox, and backs up what it changes. Service restarts use a generated polkit rule. No sudoers file, no setuid.
- **A human approves consequential actions.** Destructive and root-level changes need the user's approval, collected by the client (MCP elicitation) and bound to the exact operation; the model cannot approve on its own.
- **Everything is supported; nothing is on by accident.** Read, write, destructive and root capabilities all ship; each is enabled explicitly on the server and in each host's policies.
- **Pinned SSH trust.** Host keys are pinned, never learned; per-key policies give each server instance its own ceiling.
- **Hardened delivery.** Distroless non-root image, read-only filesystem, no capabilities, no Docker socket; signed images and binaries with SBOMs; every dependency on its newest stable release, enforced in CI.

Design documents: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · [`docs/SECURITY.md`](docs/SECURITY.md) · [`docs/POLICY.md`](docs/POLICY.md) · [`docs/PRIVILEGED.md`](docs/PRIVILEGED.md) · [`docs/TOOLS.md`](docs/TOOLS.md)

Reporting a vulnerability: see [`SECURITY.md`](SECURITY.md).

## Development

The maintainer's workstation is Windows, but the gate and the privileged helper are Linux-only (Landlock, `prctl`, `SO_PEERCRED`, systemd). A check that ran on Windows with that code excluded by build tags would prove nothing, so every check runs on Linux:

```sh
bash scripts/ci-local.sh
```

`scripts/ci-local.sh` runs the same gate as CI (gofmt, `go vet`, golangci-lint, `go test -race`, govulncheck, linux/amd64 and linux/arm64 builds of all three binaries, and the `deps-current` freshness check with its self-test) inside digest-pinned Linux containers, as a non-root user, with Go caches in a named Docker volume. It needs only Docker, and works from Git Bash on Windows and from bash on Linux. It also reports whether Landlock is available inside the test container and whether an unprivileged systemd container can boot, which the gate sandbox tests and the helper end-to-end tests rely on.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
