# shell-mcp

A security-first [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI clients **bounded, audited access to Linux hosts over SSH**: reading and changing what container managers can't reach, such as systemd services, the journal, host and root-owned configuration files, ownership and permissions, packages, disk and process inspection, TLS certificates and git-based deployments.

It is **not a remote shell**. There is no shell, no PTY, no interpreter and no free-form command line. Every operation is either built in or a command whose exact argument shapes the host's owner declared.

## How it is built

- **A gate on every host decides.** The MCP server only decides which tools a client can see (its profile: `read-only`, `operator` or `admin`). What actually runs is decided on the target by `shell-mcp-gate`, the SSH key's forced command, from a root-owned policy the server cannot change. Each SSH key selects its own policy, so each server instance has its own ceiling.
- **Kernel confinement.** Before the gate reads a request it sets `no_new_privs` and applies a Landlock sandbox computed from the policy, which every child inherits. A bug in the gate's own path checks still hits a kernel wall.
- **Things it never runs.** Shells, interpreters, program launchers and wrappers, debuggers, pagers and editors, privilege changers, tunnels and session tools are refused under any name: by path, by hard link or renamed copy, as a multi-call binary's program, or as a script's interpreter. Credentials (private keys, shadow files), identity and access administration, and this project's own policies, binaries and units are out of reach for every profile and policy (`docs/SECURITY.md` §4).
- **Root without sudo.** Root actions go to `shell-mcp-privd`, a socket-activated helper started per request that checks the caller by kernel peer credentials, applies its own root-owned policy, runs in a systemd sandbox generated from that policy, and backs up what it changes. Service control uses a generated polkit rule. There is no sudoers file and no setuid binary.
- **A human approves consequential actions.** Destructive and root-level changes need approval on the server's own approval page, with a code from the approver's authenticator, bound to the exact operation and its preview. The model cannot approve; by default such tools refuse until approvals are set up.
- **Pinned trust.** SSH host keys are pinned, never learned. Releases are signed and attested (below).

## What it does not protect against

- **A compromised server or a stolen SSH key** can skip the approval page: it can do whatever the target's policies allow that key. Write the policies for that case.
- **A misled model within its allowance.** Reads return host content to the model, and anything below the approval threshold runs without asking. Give each client the lowest profile and the narrowest policy that does the job.
- **The commands you declare.** The gate runs exactly the argv you allow, but a declared program does what it does; `check-policy` warns about programs with known escapes. A `#!` script is judged by its interpreter, not by what it runs.
- **The broad unit and package operations** are root-equivalent by design (maintainer scripts run as root).
- **Exposure.** There is no OAuth; keep the server on a LAN or VPN, never on the public internet.

The open items are listed in [`CHANGELOG.md`](CHANGELOG.md).

## Documentation

- [`docs/TARGET-SETUP.md`](docs/TARGET-SETUP.md) — setting up a target host: binaries, service account, SSH, policy, polkit, the helper
- [`docs/CLIENTS.md`](docs/CLIENTS.md) — connecting MCP clients, profiles, approvals
- [`deploy/README.md`](deploy/README.md) — running the server's container
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model and fail-closed rules (normative)
- [`docs/POLICY.md`](docs/POLICY.md) — the gate policy (normative)
- [`docs/PRIVILEGED.md`](docs/PRIVILEGED.md) — the privileged helper (normative)
- [`docs/TOOLS.md`](docs/TOOLS.md) — the tool catalogue
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, wire protocol, configuration, releases
- [`docs/ARCHIVE.md`](docs/ARCHIVE.md) — the decision record; [`plan.md`](plan.md) — goals and locked decisions
- [`CHANGELOG.md`](CHANGELOG.md) — releases, known limitations
- Reporting a vulnerability: [`SECURITY.md`](SECURITY.md)

## Verifying a release

Each GitHub release has the binaries (`shell-mcp`, `shell-mcp-gate`, `shell-mcp-privd`, as `<name>_X.Y.Z_linux_<arch>`), `shell-mcp_X.Y.Z_examples.tar.gz`, SBOMs, `SHA256SUMS` and a Sigstore bundle `<file>.sigstore.json` for every binary, the archive and `SHA256SUMS`. The image is `ghcr.io/tyler-rich/shell-mcp:X.Y.Z`; its digest is in the release notes. Everything is signed by the release workflow at the release's tag, and only that identity is a release: a dry run or a branch build has another one and fails these checks. For 0.1.0:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

```bash
cosign verify-blob --bundle shell-mcp-gate_0.1.0_linux_amd64.sigstore.json \
  --certificate-identity https://github.com/tyler-rich/shell-mcp/.github/workflows/release-build.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  shell-mcp-gate_0.1.0_linux_amd64
```

```bash
gh attestation verify shell-mcp-gate_0.1.0_linux_amd64 --repo tyler-rich/shell-mcp \
  --signer-workflow tyler-rich/shell-mcp/.github/workflows/release-build.yml --source-ref refs/tags/v0.1.0
```

```bash
cosign verify ghcr.io/tyler-rich/shell-mcp@sha256:<digest from the release notes> \
  --certificate-identity https://github.com/tyler-rich/shell-mcp/.github/workflows/release-build.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```bash
gh attestation verify oci://ghcr.io/tyler-rich/shell-mcp@sha256:<digest from the release notes> --repo tyler-rich/shell-mcp \
  --signer-workflow tyler-rich/shell-mcp/.github/workflows/release-build.yml --source-ref refs/tags/v0.1.0
```

Run the `cosign verify-blob` and `gh attestation verify` lines for each file you use, and pull the image by digest, never by tag alone.

## Supported platforms

- **Server:** the container image for linux/amd64 and linux/arm64, or the static binary on Linux.
- **Targets:** Linux with systemd on amd64 or arm64, with Landlock ABI 4 or newer (Linux 6.7+). Tested on Debian 13, Ubuntu 24.04 LTS and Ubuntu 26.04 LTS. No macOS, BSD or Windows targets.
- **Clients:** any MCP client that speaks Streamable HTTP with a bearer header (MCP 2026-07-28 or 2025-11-25), or stdio (`docs/CLIENTS.md`).

## Development

The gate and the helper are Linux-only (Landlock, `prctl`, `SO_PEERCRED`, systemd), so every check runs on Linux. From bash on Linux, or Git Bash on Windows, with only Docker:

```bash
bash scripts/ci-local.sh
```

It runs CI's gate (gofmt, `go vet`, golangci-lint, `go test -race`, govulncheck, the linux/amd64 and linux/arm64 release builds, built twice and compared, the Landlock forced-psx test build, `deps-current` and the scripts' self-tests) in digest-pinned Linux containers, as a non-root user. The end-to-end tests run only on CI's GitHub-hosted runner (`e2e-host`).

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
