# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting). Include the affected version or commit, a description, reproduction steps, and the impact you expect.

You can expect an acknowledgement within 7 days and a status update at least every 14 days until resolution. The default coordinated-disclosure window is 90 days from the report, shortened when a fix ships earlier and extended by mutual agreement when needed. Reporters are credited in the release notes unless they prefer otherwise.

## Scope

In scope: the `shell-mcp` server, the `shell-mcp-gate` and `shell-mcp-privd` binaries and the helper units they generate, the published container image, release artefacts, and the example policies and deployment files in this repository.

Especially interesting: anything that lets a caller execute a command, read or write a path, or reach a privilege that the gate or privileged policy does not allow; bypasses of MCP authentication, human approval, host-key verification, the helper's peer-credential check, or redaction; and supply-chain issues in the release pipeline.

Out of scope: weaknesses that require a policy the documentation tells operators not to write (for example a `{path:write}` placeholder passed to a binary flagged by `check-policy`), and findings in third-party dependencies that are already publicly tracked upstream.

## Supported versions

Until 1.0, only the latest release receives fixes.

## Design

The threat model and security design are documented in [`docs/SECURITY.md`](docs/SECURITY.md).
