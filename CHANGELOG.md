# Changelog

All notable changes to shell-mcp. Versions follow [Semantic Versioning](https://semver.org); a release is the tag `vX.Y.Z` on `main`. The design record behind each change is `docs/ARCHIVE.md` §14.

## [Unreleased]

**Added**

- **`{path:read:fd}`** (handoff N-22): an opt-in placeholder for gate commands that passes the file as the gate's open descriptor (`/dev/fd/4` and up) instead of a path, so a command that reads its argument reads the file the gate checked, whatever happens to its name afterwards. It closes the owner-matched `{path:read}` redirect for such commands. Regular files only, at most 8 per template; the privileged policy refuses it. `exec_preview`, `exec`, `shell_run_read_command` and `shell_run_command` report the descriptors (`fds`), and an approved command is bound to the file's identity. `check-policy` warns about programs measured to give wrong results with a descriptor (`stat`, `du`, `file`, `ls` and `find` without following links; `cp -a`/`-P`/`-r`; `tar` adding a member; `findmnt`; `nginx`; `docker compose`) and checks `/dev/fd`. POLICY §4.

**Changed**

- **Protocol version 2** (ARCHITECTURE §4.0). A server, gate or helper of another version refuses with `protocol_mismatch`, naming both versions and which side to upgrade; a 0.1.0 server or gate gets that message in its own version's frame. A refusal of the version is never reported as `outcome_unknown`. The session hello is unchanged.

**Upgrade notes**

- **Upgrade the server, the gate and the helper together.** A 0.1.0 server and a gate of this release, or the reverse, refuse each other with `protocol_mismatch` (the message says which to upgrade); so do a gate and a helper of different releases.
- A gate policy that uses `{path:read:fd}` is refused by a 0.1.0 gate (unknown placeholder).

## [0.1.0]

The first release: an MCP server that gives AI clients bounded, audited read and write access to Linux hosts over SSH, without a shell.

**What it contains**

- **Three binaries**, static, for linux/amd64 and linux/arm64: `shell-mcp` (the MCP server, also shipped as a distroless, non-root container image), `shell-mcp-gate` (the SSH forced command on each target) and `shell-mcp-privd` (the optional privileged helper for root actions).
- **The server.** Streamable HTTP with a bearer token (MCP 2026-07-28 and 2025-11-25), or stdio. Host and Origin allow-lists, per-client rate limits and an auth-failure lockout, trusted proxies by address. Pinned SSH host keys only, Ed25519 client keys, no agent, forwarding or PTY. Three profiles: `read-only` (19 tools, the default), `operator` (27) and `admin` (50). `shell-mcp check` verifies every target; `shell-mcp tools` prints the catalogue with schema hashes.
- **The gate.** One request per SSH session, checked against a root-owned policy on the target: read and write roots, a built-in deny list and protected set, exact unit and verb lists, pinned git repositories, and declared commands as exact argv templates with typed placeholders. Before it reads a request it sets `no_new_privs` and a Landlock sandbox computed from the policy, inherited by everything it runs. Shells, interpreters, wrappers, pagers, editors and privilege changers are refused under any name, including through hard links, renamed copies, multi-call binaries and `#!` interpreters. Writes are atomic and read back; deletes and git discards remove exactly what their preview listed, or stop. Service control is authorized by a generated polkit rule. `check-policy` reports what the gate would refuse before it is asked.
- **The privileged helper.** Root actions without sudo, setuid or a root shell: a socket-activated process per request that authenticates the gate's account by kernel peer credentials, applies its own root-owned policy, and runs in a systemd sandbox generated from that policy and pinned to its hash. File operations as root with backups and restore, chown and chmod, declared root commands, apt package operations bound to an approved transaction of exact versions, and a delayed, cancellable reboot or power-off through logind.
- **Human approval.** Destructive operations and every privileged change need a person's approval on the server's own approval page, with a TOTP code from an enrolled approver's authenticator, bound to the exact operation, its preview and both policies, single-use and short-lived. The model cannot approve. Approvals are off by default (gated tools refuse), and a logged `confirm-argument` opt-out exists for those who accept the model approving.
- **Supply chain.** Every file in a signed `SHA256SUMS`; cosign keyless signatures, SLSA build provenance and CycloneDX SBOM attestations for the binaries and the image, all bound to the release workflow at the release tag. Every dependency, image and tool at its newest stable release, enforced in CI.
- **Documentation.** `docs/TARGET-SETUP.md` (target hosts), `docs/CLIENTS.md` (clients, profiles, approvals), the normative design documents, example policies and a hardened reference deployment.

**Known limitations**

- Targets must be Linux with systemd and a kernel with Landlock ABI 4 or newer (Linux 6.7+); tested on Debian 13, Ubuntu 24.04 and Ubuntu 26.04. The helper's sandbox is exercised end to end on Ubuntu 26.04 only.
- Package operations use apt only. Git LFS repositories, repositories on case-folding filesystems, and git repositories that an account other than root or the service account owns or can write are not supported by the git tools; submodules are never entered.
- Deletes and moves are refused on filesystems without `RENAME_NOREPLACE` (for example NFS), and verified replaces on those without `RENAME_EXCHANGE`.
- UDP is not restricted by the gate's sandbox (the target kernels cannot govern it).
- Approvals live in memory and are lost when the server restarts. MCP elicitation is not used for approval; clients relay the approval page's URL instead.
- OAuth is not supported: keep the server on a LAN or VPN, behind a TLS-terminating proxy, never on the public internet.
- One profile per server instance; run several instances for several ceilings.

**Open items after this release**

- **N-5:** an approved copy or move over an existing file cannot be approved when that file is larger than 256 MiB or starts with a private key, because the preview hashes it through the read operation. Workaround: delete the destination first (its own approval), then copy or move without overwriting.
- **N-22:** a declared command's `{path:read}` is passed as a path, not as the descriptor the gate checked, so an application account that owns a directory on that path can redirect what the command reads to another file the service account can read. Planned as an opt-in per template.
- **N-25:** an account that can write a git submodule's directory in a listed repository can make git status, diff, pull and discard wait until their timeout (a FIFO in the submodule's git files). Nothing runs; the request times out.
- **N-26:** a declared command that is a `#!` script is judged by its interpreter; what the script itself runs is not inspected. Review every script you declare, above all in the privileged policy.
