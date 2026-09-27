# Security design & threat model

This document is normative. Where it conflicts with convenience, it wins. Changing anything here is a STOP-and-ask. (Vulnerability *reporting* is in the root `SECURITY.md`.)

## 1. Assets and trust boundaries

| Asset | Where | Who can touch it |
|---|---|---|
| MCP bearer token | Secret file / env store / server memory | `internal/auth` only. Constant-time compare; never logged or returned. |
| SSH private key(s) | Secret file / env store / server memory | `internal/sshx` only. Never logged, never in `check` output (show the public-key fingerprint instead). |
| Gate policy, privileged policy, gate and helper binaries, helper units, `authorized_keys` | Target, root-owned | Root only (D-016). Gate and helper refuse to run if any is writable by group/other or not owned by root; the helper also refuses when its units were generated for a different policy. |
| Host files, service state, journal, process list | Target | Through gate operations only, within the policy. |
| Tool results (file contents, command output, logs) | In transit to the client | Returned to the model on request, redacted and size-capped; **never logged**. |

Trust boundaries:

- **(a) MCP client ↔ server.** Untrusted until authenticated. The *model* stays untrusted after authentication — it can be prompt-injected by anything it reads, including our own tool output.
- **(b) Server ↔ gate.** The gate treats the server as hostile (a compromised container is in the threat model). SSH provides transport security and client authentication; the policy provides authorization.
- **(c) Gate ↔ host.** The gate runs as an unprivileged service user inside a `no_new_privs` + Landlock domain. Its only direct privilege is polkit authorization for exact units and verbs.
- **(e) Gate ↔ helper.** The helper treats the gate as hostile: it authenticates the caller by kernel peer credentials, re-validates everything against its own privileged policy, and runs in a systemd sandbox that limits its capabilities and write paths regardless of what the request says.
- **(d) Container ↔ host running it.** Hardened image, no privileges, no socket, no mounts.

## 2. Threats and mitigations

| Threat | Vector here | Mitigation |
|---|---|---|
| **Command / argument injection** | Shell metacharacters; option injection (`--output=/etc/…`, `-exec`); GTFOBins escapes in allowed binaries | No shell (D-003); argv templates with typed placeholders; placeholder values may not start with `-`; interpreters/shells/pagers/editors hard-denied; `check-policy` warns on GTFOBins binaries; built-in native file ops instead of `cat`/`cp`/`find`. |
| **Path traversal / symlink escape** | `../`, symlink inside a root pointing outside, symlink to a denied file inside a root, TOCTOU swaps | `os.Root` per root; final-component `O_NOFOLLOW`; real path from `/proc/self/fd/N` re-checked against roots and deny list after open; writes via temp + rename inside the opened root. |
| **Credential disclosure** | Reading private keys, `shadow`, tokens in configs, `/proc/*/environ`, command lines with passwords | Built-in read deny list (POLICY §3); private-key content sniffing; output redaction; cmdline redaction; `environ` never readable. |
| **Persistence / privilege escalation** | Writing systemd units, cron, sudoers, SSH keys, PAM, shell rc files, the gate's policy | Protected-path set cannot be a write root or inside one; the gate refuses a policy that overlaps it; setuid/setgid bits refused; `no_new_privs` on every process; no sudo anywhere (D-017); polkit rule limited to exact units × verbs; privileged groups refused at runtime (D-020). |
| **Prompt injection via tool output** (LLM01) | Log lines, file contents, commit messages, unit descriptions containing instructions | Structured JSON results; descriptions never instruct the model to act on content; size caps; client guidance in `docs/CLIENTS.md` to treat results as data. |
| **Excessive agency** (LLM08) | Model calls a write/destructive tool | Profiles (D-005); policy `max_tier` (D-016); computed previews; annotations so clients prompt. |
| **Model self-approval** | A prompt-injected model supplies whatever confirmation argument a tool asks for | Destructive approval is a user answer collected by the client through elicitation, bound by HMAC to principal, tool, target, arguments and preview, short-lived and single-use (D-006, S-12); no elicitation → fail closed. |
| **Escape via a declared binary or a gate bug** | A policy command with a file-write or exec feature; a flaw in our path matcher | Landlock ruleset computed from the policy and applied before the request is read; children inherit it; TCP bind denied and connect limited to listed ports (D-019). |
| **Compromised MCP server** | Stolen bearer token, container compromise, SDK bug | Gate and helper are authoritative; per-key policies — a read-only server instance holds a key whose policy has `max_tier: read`; `from=` restricts where the key is usable. A compromised server can skip human approval, so the privileged policy must be written for that case (PRIVILEGED §3). |
| **Compromised gate / service account** | Code execution as the service user | The helper accepts only declared `priv_*` operations, re-validated against the root-owned privileged policy; the core unit's `ProtectSystem=strict`, write-path list and four-capability bounding set bound what even a correct-looking request can do; the broad unit is only present if the owner enabled packages or broad commands. |
| **Compromised helper instance** | A bug in privileged code | One instance per request, no persistence, systemd sandbox (core: no network, write paths and capabilities fixed by the generated unit), Landlock inside, backups of anything overwritten or deleted, journald audit. The broad unit is root-equivalent by design and is documented as such. |
| **Confused deputy** | One service user serving several callers | One principal per server instance; separate keys + policies per trust level; gate audits the policy-selected principal label. |
| **Host impersonation / MITM** | DNS or ARP spoofing of the target | Pinned host keys, no TOFU (D-012); host key algorithms restricted to the pinned types; `check` prints what it verified. |
| **Unauthenticated enumeration** | `tools/list` without auth | Auth before any response (D-004); `/healthz` returns nothing informational. |
| **DNS rebinding** | Browser on the LAN reaches a loopback-bound server | Host/Origin allow-list in our own middleware; loopback bind by default outside Docker. |
| **Brute force** | Guessing the bearer token | ≥ 256-bit tokens enforced; constant-time compare; auth-failure limiter; global limiter. |
| **Denial of service** | Huge outputs, deep walks, fork bombs, slow commands | Caps on output, stdin, file size, walk depth/results, delete entries, request/response size; timeouts with process-group kill; `RLIMIT_NPROC`/`RLIMIT_CORE`; per-target session limit; sshd `MaxSessions`/`MaxStartups`. |
| **Tool poisoning / rug pull** | Our descriptions change between versions | `shell-mcp tools` catalogue with schema hashes; snapshot test; signed images pinned by digest. |
| **Supply chain** | Malicious module, base image, or Action | `go.sum`, `govulncheck`, Trivy + Grype, CodeQL, gitleaks, Dependabot daily, `deps-current`, SHA-pinned Actions, digest-pinned bases, cosign signatures and provenance for image and gate binaries. |
| **Container breakout** | Bug in the server | Distroless static, non-root, `cap_drop: ALL`, `no-new-privileges`, read-only FS, limits, no socket or mounts. Blast radius = the SSH key's policy. |
| **Log injection** | Newlines/ANSI in paths, units, output | JSON logging; free-text fields truncated to 512 chars; content never logged. |
| **Repository leakage** | Deployment details committed to a public repo | CLAUDE.md hygiene rules; placeholder conventions; local pre-push private-term hook; gitleaks for secrets; session self-review. |

## 3. Authentication modes (MCP side)

| Mode | When | Rules |
|---|---|---|
| `bearer` (default) | Any client that can send a header (Claude Code, Claude Desktop via a bridge, scripts) | Token from `SHELL_MCP_TOKEN_FILE` (preferred) or `SHELL_MCP_TOKEN`; ≥ 43 chars; startup fails otherwise. |
| `none` | stdio, or loopback-only HTTP for development | HTTP requires **both** `SHELL_MCP_ALLOW_UNAUTHENTICATED=true` and bind ∈ {`127.0.0.1`, `::1`}. |

OAuth resource-server mode is deferred (plan §6). Remote shell capability should sit behind a VPN or LAN; do not publish this server on the public internet.

## 4. The excluded set — permanent (D-007)

Everything a root operator legitimately does can be declared in a host policy. What stays out, for every profile, policy and fork, is what lets an agent read credentials, escalate its own access, or modify its own confinement.

| Family | Examples | Reason |
|---|---|---|
| Shells, PTYs, interpreters | `sh`, `bash`, `zsh`, `busybox`, `python*`, `perl`, `ruby`, `node`, `php`, `lua`, `awk`, `expect`, `script` | Arbitrary code execution; the whole point of the design is that there is none. |
| Command launchers / wrappers | `env`, `xargs`, `nohup`, `setsid`, `timeout`, `nice`, `ionice`, `stdbuf`, `flock`, `watch`, `strace`, `ltrace`, `gdb` | Run arbitrary argv. |
| Pagers and editors | `less`, `more`, `man`, `vi`, `vim`, `nano`, `ed`, `emacs` | Shell escapes. |
| Privilege changers | `sudo`, `su`, `doas`, `pkexec`, `runuser`, `setpriv`, `chroot`, `nsenter`, `unshare`, `capsh` | Escalation. Root actions go only through the helper. |
| Network tools that proxy or transfer | `ssh`, `scp`, `sftp`, `nc`, `ncat`, `socat`, `telnet`, `rsync`, `curl`/`wget` with output-to-file or upload | Tunnels, exfiltration, fetch-and-write. (Read-only network diagnostics are allowed as policy templates.) |
| Credential material | Private keys (`*/.ssh/*`, host private keys), `shadow`/`gshadow`, sudoers, `/proc/*/environ`, `/proc/*/mem`, `/root` | Disclosure. |
| This project's trust anchors | Policy directory, gate and helper binaries, helper units and sockets, `authorized_keys` | Self-modification of confinement — not even through the helper. |
| Identity and access administration | Users, groups, passwords, sudoers, PAM, SSH server config and keys, polkit rules — by command or by file write, including through the helper | Self-escalation: the agent granting itself more access. |
| Boot, kernel, storage, firewall, persistence areas | `reboot`, `mount`, `nft`, `modprobe`, `sysctl -w`, disk tools; systemd unit and cron directories, `/etc/profile.d`, `/usr/local/bin` | **Not permanently excluded.** Never through the gate; through the helper only when the privileged policy declares them with an `acknowledge` string (PRIVILEGED §5.3 list B). |

## 5. Target hardening (normative; `docs/TARGET-SETUP.md` turns this into steps)

1. **Dedicated system user** (placeholder name `svc-shell`): password locked (`passwd -l`), minimal groups (e.g. `systemd-journal` for journal reads). Its login shell must be a real POSIX shell such as `/bin/sh`, because sshd runs the forced command through it — `nologin` would refuse. That is safe here: the forced command is root-authored in a root-owned file, and the client's requested command never reaches the shell.
2. **Root-owned keys file** via an sshd `Match` block, so the user cannot edit its own key options:
   ```
   Match User svc-shell
       AuthorizedKeysFile /etc/ssh/authorized_keys.d/%u
       AuthenticationMethods publickey
       PasswordAuthentication no
       KbdInteractiveAuthentication no
       PermitTTY no
       AllowTcpForwarding no
       AllowStreamLocalForwarding no
       AllowAgentForwarding no
       X11Forwarding no
       PermitTunnel no
       PermitUserRC no
       MaxSessions 8
   ```
   (Verify every directive against `man sshd_config` for the target's OpenSSH version.)
3. **One line per key**, always with `restrict`, a `from=` source restriction, and its own policy:
   ```
   restrict,from="192.0.2.0/24",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/read-only.yaml --principal readonly" ssh-ed25519 AAAA… shell-mcp-readonly
   restrict,from="192.0.2.0/24",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/operator.yaml --principal operator" ssh-ed25519 AAAA… shell-mcp-operator
   ```
4. **Gate and policy root-owned**: `/usr/local/bin/shell-mcp-gate` `root:root 0755`; `/etc/shell-mcp/` `root:root 0755`; policies `root:root 0644` (or `root:svc-shell 0640`).
5. **Writes via ACLs**: grant the service user write access only to the write roots (`setfacl -R -m u:svc-shell:rwX` and default ACLs), never to anything in the protected set.
6. **No sudoers entry at all.** If service control is enabled: install `polkitd`, then `shell-mcp-gate polkit …` → review → install as `/etc/polkit-1/rules.d/60-shell-mcp.rules` `root:root 0644`.
7. **Landlock enabled:** `landlock` appears in `/sys/kernel/security/lsm` (enabled by default on current Debian and Ubuntu kernels; verify).
8. **Explicit UID/GID, minimal groups (D-020):** choose an unused UID/GID, confirm no files on the host are owned by it (`find / -xdev -uid <UID>` on each filesystem that holds application or container data), create the account with that UID, add only `systemd-journal` (if journal ops are enabled) and the helper's socket group (if root actions are enabled), and never `docker`, `sudo`, `adm`, `disk` or similar.
9. **Privileged helper (only if root actions are wanted):** create the socket group and add only the service account to it; install `shell-mcp-privd` `root:root 0755` in `/usr/local/libexec`; write `/etc/shell-mcp/privileged.yaml` `root:root 0600` with `client_uid` = the pinned UID; `shell-mcp-privd check-policy` → review every acknowledge and root-equivalent item → `shell-mcp-privd units` → install the units → `systemd-analyze verify` and `systemd-analyze security shell-mcp-privd@.service` → enable the socket(s); set `privileged.enabled: true` in the gate policy of the key(s) that may use it.

## 6. Fail-closed startup rules

**Server** — exits non-zero with a one-line reason when:

- `bearer` mode and no token, or token < 43 chars;
- `none` mode over HTTP without `SHELL_MCP_ALLOW_UNAUTHENTICATED=true`, or with a non-loopback bind;
- no targets, or both the targets file and single-target variables are set;
- any target lacks a pinned host key, has an unparsable fingerprint, or has no usable key;
- an SSH private key is not Ed25519, is passphrase-protected without a passphrase source, or cannot be parsed;
- `SHELL_MCP_DEFAULT_TARGET` names an unknown target;
- a redaction pattern fails to compile;
- `stdio` transport with `bearer` mode (meaningless — stdio is `none`);
- an invalid approval setting (`SHELL_MCP_APPROVAL_TIERS` without `destructive`, an unknown fallback, a TTL outside 30..600).

A secret file readable by group/other logs a WARN on every start (container secret mounts vary; not fatal).

**Helper** — refuses to serve under the conditions in `docs/PRIVILEGED.md` §7.

**Gate** — refuses to serve (`install_insecure`) when:

- running as uid 0, or with any supplementary group in the D-020 deny list;
- Landlock is unavailable (or below the ABI the policy needs) while `sandbox.landlock: required`;
- the policy file, any parent directory, or its own binary is not owned by root or is group/other-writable;
- the policy fails strict parsing or validation (unknown keys, overlapping protected paths, a write root inside a protected path, a hard-denied command, a glob in `services.control.units`, an unresolvable or non-root-owned command binary, placeholder regexes that are not anchored);
- `SSH_ORIGINAL_COMMAND` is present and is not the protocol hello `shell-mcp-gate/<version>`.

## 7. Deployment hardening (reference compose, normative flags)

```yaml
services:
  shell-mcp:
    image: ghcr.io/OWNER/shell-mcp:X.Y.Z@sha256:<digest>
    restart: unless-stopped
    user: "65532:65532"
    read_only: true
    ports:
      - "127.0.0.1:8080:8080"           # or a specific LAN/VPN interface address; never all interfaces by accident
    environment:
      SHELL_MCP_BIND: 0.0.0.0           # inside the container; exposure is controlled by `ports`
      SHELL_MCP_PROFILE: read-only
      SHELL_MCP_TOKEN_FILE: /run/secrets/mcp_token
      SHELL_MCP_SSH_KEY_FILE: /run/secrets/ssh_key
      SHELL_MCP_TARGET_NAME: app-host
      SHELL_MCP_TARGET_HOST: target-a.example.test
      SHELL_MCP_TARGET_USER: svc-shell
      SHELL_MCP_TARGET_HOST_KEYS: "SHA256:placeholder"
      SHELL_MCP_ALLOWED_HOSTS: localhost,127.0.0.1,mcp.example.test
    secrets: [mcp_token, ssh_key]
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    pids_limit: 64
    deploy:
      resources:
        limits: { cpus: "0.50", memory: 128M, pids: 64 }   # pids repeated: Compose rejects pids_limit next to a limits block without it
    healthcheck:
      test: ["CMD", "/shell-mcp", "healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "3" }
secrets:
  mcp_token: { file: ./secrets/mcp_token }
  ssh_key: { file: ./secrets/ssh_key }
```

When the container runs on the target itself, it reaches the host's sshd through the Docker host gateway (`extra_hosts: ["host.docker.internal:host-gateway"]`) — the `from=` restriction then names the Docker network's subnet. In DockHand/Portainer, keep secrets in the tool's encrypted env store (`SHELL_MCP_TOKEN`, `SHELL_MCP_SSH_KEY`), never in the YAML.

TLS: terminate at a reverse proxy or run over a VPN; the server speaks plain HTTP on an internal network only. Set `SHELL_MCP_TRUST_PROXY=true` only behind that proxy.
