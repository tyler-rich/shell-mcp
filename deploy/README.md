# Deploying shell-mcp

> **Pin the image by digest.** The commands below and the reference compose use the 0.2.0 image index by digest, `ghcr.io/tyler-rich/shell-mcp:0.2.0@sha256:323149155f5be042949ec5291812104351f365a693dbdfb8cd2171b95ee30e6a`, as its release notes give it and as
> `docker buildx imagetools inspect ghcr.io/tyler-rich/shell-mcp:0.2.0 --format '{{.Manifest.Digest}}'` prints it.
> Verify it before you deploy it (README, "Verifying a release"). For a later release, use that release's digest.

The server needs only two secrets, the MCP bearer token and the SSH private key, plus each target's pinned host-key fingerprint. It needs no Docker socket, host mounts or capabilities. See [`../docs/SECURITY.md`](../docs/SECURITY.md) §3 and §7, and [`.env.example`](.env.example) for every variable.

## Secrets

`shell-mcp init` creates them: the bearer token, the SSH key pair and, with `--approver`, the approvers file, each `0600` (the `.pub` file `0644`) and owned by the server's uid, in a directory `0700` owned by that uid. It never overwrites a secret and never prints one. [`shell-mcp init`](#shell-mcp-init) below is its reference. The image has no shell and runs as uid 65532, so create the directory with one host command, as root, then run `init` in the image. It needs no network, no capability and no root inside the container:

```sh
install -d -o 65532 -g 65532 -m 0700 secrets
docker run --rm -it --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$PWD/secrets:/secrets" ghcr.io/tyler-rich/shell-mcp:<version>@sha256:<digest> \
  init --dir /secrets --approver alice
```

Run it in this directory, next to `docker-compose.yml`, because Compose resolves `./secrets/…` relative to the compose file. `<version>` is a release that has `init` (any after 0.2.0), with its digest from the release notes. Leave out `--approver alice` when you run without approvals. With it, the approver's code is shown once, as a QR code and an `otpauth://` URI, which is why it needs `-it` ([`../docs/CLIENTS.md`](../docs/CLIENTS.md) §3.2). `init` prints `ssh_key.pub`: install it on the target with `shell-mcp-gate install --key` ([`../docs/TARGET-SETUP.md`](../docs/TARGET-SETUP.md) §12.1), which also prints the target's host-key pin. On the host, as root, the release's `shell-mcp` binary does the same: `shell-mcp init --dir /srv/shell-mcp/secrets` creates the directory if it is absent and gives every file to uid 65532.

### By hand

The same result without `init`:

```sh
mkdir -p secrets && chmod 700 secrets
# 32 random bytes, base64url: 43 characters
head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > secrets/mcp_token
ssh-keygen -t ed25519 -N '' -C shell-mcp -f secrets/ssh_key
chmod 600 secrets/*
# The container runs as UID 65532 and bind-mounts these files: hand the two
# it reads to that UID (as root). The .pub file stays yours.
chown 65532:65532 secrets/mcp_token secrets/ssh_key
```

Install `secrets/ssh_key.pub` on the target as described in [`../docs/TARGET-SETUP.md`](../docs/TARGET-SETUP.md) §7, and pin the target's host key: `ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -` prints the `SHA256:` fingerprint. Check it against the host's own `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` over a trusted channel. Never trust a key on first use.

## Plain docker

For a client on the same machine, without a reverse proxy: the port is published on loopback only, and `SHELL_MCP_TRUSTED_PROXIES` stays unset, so `X-Forwarded-For` is never believed.

```sh
docker run -d --name shell-mcp \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 64 --memory 128m --cpus 0.5 \
  -p 127.0.0.1:8080:8080 \
  -e SHELL_MCP_BIND=0.0.0.0 \
  -e SHELL_MCP_TOKEN_FILE=/run/secrets/mcp_token \
  -e SHELL_MCP_SSH_KEY_FILE=/run/secrets/ssh_key \
  -e SHELL_MCP_TARGET_NAME=app-host \
  -e SHELL_MCP_TARGET_HOST=target-a.example.test \
  -e SHELL_MCP_TARGET_USER=svc-shell \
  -e "SHELL_MCP_TARGET_HOST_KEYS=ssh-ed25519 SHA256:placeholder" \
  -v "$PWD/secrets/mcp_token:/run/secrets/mcp_token:ro" \
  -v "$PWD/secrets/ssh_key:/run/secrets/ssh_key:ro" \
  ghcr.io/tyler-rich/shell-mcp:0.2.0@sha256:323149155f5be042949ec5291812104351f365a693dbdfb8cd2171b95ee30e6a
```

`docker run --rm ghcr.io/tyler-rich/shell-mcp:0.2.0@sha256:323149155f5be042949ec5291812104351f365a693dbdfb8cd2171b95ee30e6a check` (with the same environment and mounts) validates the configuration, connects to every target, verifies its host key and calls the gate's `hello`, and prints the result: the configuration with the token shown only as a length and the key only as its fingerprint, then per target the verified host-key pin, gate version, protocol, principal, policy hash, `max_tier`, sandbox status and the profile's tools that target can serve. It exits non-zero if any target fails.

## Docker Compose

[`docker-compose.yml`](docker-compose.yml) is the reference deployment. Its hardening flags (`user`, `read_only`, `cap_drop`, `security_opt`, limits) are normative. Keep them. It is laid out for a reverse proxy: the server publishes no port and sits on a user-defined network, `front`, which your proxy joins at the fixed address `172.30.80.5`, the only entry in `SHELL_MCP_TRUSTED_PROXIES`. The subnet (`172.30.80.0/24`, RFC 1918) is an example: pick one that does not clash with your own networks and change the addresses to match.

`shell-mcp init compose` prints this file with your values in place: the image, the target and its pin, the MCP host name, the subnet and the two fixed addresses, the profile and, with `--approve-host`, the approval page ([below](#shell-mcp-init-compose)). The hardening flags are not parameters: the output is this file with only those values changed.

```sh
docker compose up -d
```

Attach the proxy in its own compose file or service, for example:

```yaml
    networks:
      front:
        ipv4_address: 172.30.80.5
```

(with `front` declared as `external: true, name: deploy_front` when the proxy lives in another compose project). The proxy forwards `mcp.example.test` to `http://172.30.80.10:8080` and appends `X-Forwarded-For`; only the proxy publishes a port, on a LAN or VPN address. Never put the Docker network's gateway in `SHELL_MCP_TRUSTED_PROXIES`, and confirm the proxy's address from the server's own `authentication failed` log line before you set it: [`../docs/CLIENTS.md`](../docs/CLIENTS.md) §1 says why and how. Terminate TLS at the proxy or run over a VPN, and do not expose this server to the public internet.

The compose runs the `read-only` profile with approvals off. For the `operator` or `admin` profile, and for the approval page (its own port, an approvers file in `secrets:`, `SHELL_MCP_APPROVAL_*`), see [`../docs/CLIENTS.md`](../docs/CLIENTS.md) §2 and §3.

## Stack editors (DockHand, Portainer, …)

In a stack editor such as DockHand or Portainer, never put secrets in the YAML, and keep every hardening flag from the reference compose.

- **Secrets — recommended:** `init compose --form bind --dir /srv/shell-mcp/secrets` prints the reference compose with one read-only bind mount of `init`'s directory on `/run/secrets` in place of the `secrets:` blocks, so the `*_FILE` paths stay the same. An editor runs Compose in its own container, where a relative path such as `./secrets/mcp_token` is resolved inside that container, not on the host. The bind form names the directory by its absolute host path, which the Docker daemon resolves, in one entry instead of one per file. The container can read the directory because `init` made it `0700` and owned by uid 65532.

- **SSH key — recommended:** keep it a mounted file and set `SHELL_MCP_SSH_KEY_FILE`, as in the reference compose, if your tool can provide one (Docker secrets, or a bind-mounted file readable only by the container user, UID 65532).
- **SSH key — fallback:** put it in the tool's encrypted environment store as `SHELL_MCP_SSH_KEY`. Environment stores usually cannot hold the key's multi-line PEM, so store the single-line base64 of the whole key file instead:

  ```sh
  base64 -w0 secrets/ssh_key            # Linux
  ```

  ```powershell
  [Convert]::ToBase64String([IO.File]::ReadAllBytes("secrets\ssh_key"))   # Windows PowerShell
  ```

  `shell-mcp check` shows only the key's fingerprint, never the value.
- **Bearer token:** `SHELL_MCP_TOKEN` in the encrypted environment store. It is a single line.
- **What to drop:** the `secrets:` blocks and any `*_FILE` variable you are not using.
- **Several redaction patterns:** mount a file with one pattern per line and point `SHELL_MCP_REDACT_PATTERNS_FILE` at it, because environment stores cannot hold the multi-line value.

## `shell-mcp init`

```text
shell-mcp init --dir <dir> [--uid <n>] [--gid <n>] [--approver <name>] [--dry-run]
```

| File (under `--dir`) | Owner, mode | Content |
|---|---|---|
| `<dir>/` | `<uid>:<gid> 0700` | created when absent (its parent must exist) |
| `mcp_token` | `<uid>:<gid> 0600` | 32 bytes from the system's random source, base64url without padding: 43 characters on one line |
| `ssh_key` | `<uid>:<gid> 0600` | an unencrypted OpenSSH Ed25519 private key, comment `shell-mcp` |
| `ssh_key.pub` | `<uid>:<gid> 0644` | its public half, `ssh-ed25519 <base64> shell-mcp`; written again from `ssh_key` when absent |
| `approvers` | `<uid>:<gid> 0600` | with `--approver <name>` only: the name and a new seed, in `shell-mcp approver`'s format |

- **Who runs it.** `--uid` and `--gid` default to 65532, the image's user. It runs as root (on the host) or as `--uid` itself (in the image, after the host command above), and refuses any other effective uid, so it can never leave files the server cannot read. `--uid` or `--gid` 0 is refused: the server never runs as root.
- **The directory.** `--dir` must be absolute and clean, and neither it nor any directory above it may be a symbolic link. No directory above it may be writable by group or other, except a sticky one such as `/tmp`, whose entry on the path must then belong to root, `--uid` or the user running `init` (and `--dir` itself is never created directly in one). When it exists, it must be a directory with no group or other access, owned by `--uid` or, on the host, by root. A root-owned directory works for the `secrets` form, where Docker mounts each file, but not for the `bind` form, and `init` says so.
- **Existing files are kept, never overwritten.** Each existing file must have the table's owner, no group or other access (for the `.pub` file, no group or other write), and valid content: a token of at least 43 characters with no line break inside, an unencrypted Ed25519 key, a `.pub` file holding that key's public half, and an approvers file the server would load. Anything else is refused, with the command that fixes it; nothing is repaired. A second run with the same flags changes nothing and reports each file `kept`. To rotate a secret, delete its file and run `init` again, then update the target's key line or the client's token.
- **`--approver <name>`** enrols that approver when the name is new. The seed, its QR code and URI go to a terminal only, shown once. When stdout is not a terminal, `--approver` for a new name is refused before anything is generated or written (a `--dry-run` refuses the same way): run `init` interactively (in the image, `docker run --rm -it`), or run it without `--approver` and enrol later with `shell-mcp approver add`. A name already enrolled is `kept` and nothing is shown. A second approver needs `shell-mcp approver add --allow-multiple` ([`../docs/CLIENTS.md`](../docs/CLIENTS.md) §3.2).
- **What it prints.** `ok`, `NOTE` and `FAIL` lines, the `ssh_key.pub` line and its fingerprint (for `shell-mcp-gate install --key`), then a one-line result. It never prints the token, the private key or a seed; the one exception is the approver's QR code and URI, shown once. Stderr gets one JSON audit line per file created or kept: the file name, owner, mode and, for the key, its fingerprint, never a value.
- **`--dry-run`** prints every check and every file with its owner, mode and result (`create`, `kept`, `refuse`), with values shown as `<43 random characters>` and `<new Ed25519 key>`. It writes nothing and shows no seed.
- **Writes and failures.** Each file is written the way the install commands write theirs ([`../docs/TARGET-SETUP.md`](../docs/TARGET-SETUP.md) §12.4): a temporary file `.<name>.shell-mcp-<12 random lowercase letters and digits>` in `--dir`, created `0600`, given its owner and mode on its descriptor, renamed over the target, and read back by SHA-256. A run that fails part-way removes the files it created (and the directory, if it created it) and leaves no temporary file. The next run removes any temporary file a killed run left.
- **Exit codes.** 0 done or nothing to do, 1 refused or failed, 2 usage.

### `shell-mcp init compose`

```text
shell-mcp init compose --image <repository>[:<tag>]@sha256:<digest> --host-key '<type> SHA256:<fingerprint>' [--host-key …]
    --target-name <name> --target-host <host> [--target-user <user>] --mcp-host <name>
    --subnet <IPv4 prefix> --server-addr <address> --proxy-addr <address>
    [--profile read-only|operator|admin] [--approve-host <name>] [--form secrets|bind] [--dir <absolute host path>]
```

It prints [`docker-compose.yml`](docker-compose.yml) to stdout with these values in place, and writes nothing. Redirect it to a file (`> docker-compose.yml` in a copy of this directory), or paste it into your stack editor. It reads no secret and prints none: the output names files only. Notes go to stderr.

- **`--form secrets`** (the default, for `docker compose` on the host): this file exactly, with its `secrets:` entries `file: ./secrets/<name>`, so run it next to `init`'s directory as above.
- **`--form bind --dir <absolute host path>`** (for stack editors): no `secrets:` blocks, and one read-only bind mount `<dir>:/run/secrets:ro`. `--dir` is the host path of `init`'s directory and may contain only `A-Z a-z 0-9 . _ / -`.
- **`--image`** must carry `@sha256:` and 64 hex digits. A tag alone is refused, so the deployment stays pinned to what you verified.
- **`--host-key`** is the pin that `shell-mcp-gate install` or `host-key` printed on the target, parsed by the server's own parser. Nothing fills it in from the network. `--target-user` defaults to `svc-shell`, as `install`'s `--user` does.
- **`--profile`** (default `read-only`) sets `SHELL_MCP_PROFILE`. **`--approve-host <name>`** adds the approval page ([`../docs/CLIENTS.md`](../docs/CLIENTS.md) §3.2): `SHELL_MCP_APPROVAL_METHOD=web`, `SHELL_MCP_APPROVAL_PUBLIC_URL=https://<name>`, `SHELL_MCP_APPROVERS_FILE=/run/secrets/approvers`, `SHELL_MCP_APPROVAL_BIND=0.0.0.0` and, in the `secrets` form, the `approvers` secret. Enrol the approver with `init --approver` first.
  - `--profile admin` without `--approve-host` is refused. Every destructive and privileged tool needs an approval, so `admin` without the approval page would only refuse those calls.
  - `--profile operator` without it prints a NOTE: operator tools then run without approval under the default `SHELL_MCP_APPROVAL_TIERS`.
- **Addresses.** `--subnet` is an IPv4 prefix in canonical form, between /16 and /28. `--server-addr` (the server's `ipv4_address`) and `--proxy-addr` (your proxy's fixed address, the only entry in `SHELL_MCP_TRUSTED_PROXIES`) must be two different hosts inside it. Neither may be the subnet's network or broadcast address or its first host, which Docker gives the network's gateway: the trusted proxy must never be the gateway ([`../docs/CLIENTS.md`](../docs/CLIENTS.md) §1).
- **Refused** (exit 1): a malformed value for any flag above, and a host name that is not a DNS name (`--target-host` may also be an IP address). A missing required flag, an unknown flag and `--dir` without `--form bind` are usage errors (exit 2). A value that YAML would read as something other than the string given (`00000000`, `true`, `null`) is printed quoted, so the server gets exactly what you typed.
- **Never generated:** an environment-store form (`SHELL_MCP_TOKEN`, `SHELL_MCP_SSH_KEY`). It would put the secrets in the YAML or the editor's store. [Stack editors](#stack-editors-dockhand-portainer-) describes doing that by hand when there is no other way.
