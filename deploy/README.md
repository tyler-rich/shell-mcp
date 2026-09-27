# Deploying shell-mcp

> Pre-alpha. Until Session 2 lands, `serve` refuses to start in `bearer` mode ("bearer auth arrives in Session 2"), so none of these deployments serve traffic yet. The files show the intended, hardened shape.

The server needs only two secrets, the MCP bearer token and the SSH private key, plus each target's pinned host-key fingerprint. It needs no Docker socket, host mounts or capabilities. See [`../docs/SECURITY.md`](../docs/SECURITY.md) §3 and §7, and [`.env.example`](.env.example) for every variable.

## Secrets

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

Install `secrets/ssh_key.pub` on the target as described in the target setup guide, and pin the target's host key: `ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -` prints the `SHA256:` fingerprint. Check it against the host's own `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` over a trusted channel. Never trust a key on first use.

## Plain docker

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
  -e SHELL_MCP_TARGET_HOST_KEYS=SHA256:placeholder \
  -v "$PWD/secrets/mcp_token:/run/secrets/mcp_token:ro" \
  -v "$PWD/secrets/ssh_key:/run/secrets/ssh_key:ro" \
  ghcr.io/tyler-rich/shell-mcp:0.0.1
```

`docker run --rm ghcr.io/tyler-rich/shell-mcp:0.0.1 check` (with the same environment and mounts) validates the configuration and prints it with the token shown only as a length and the key only as its fingerprint.

## Docker Compose

[`docker-compose.yml`](docker-compose.yml) is the reference deployment. Its hardening flags (`user`, `read_only`, `cap_drop`, `security_opt`, the loopback-only `ports`, limits) are normative. Keep them.

```sh
docker compose -f deploy/docker-compose.yml up -d
```

Publish the port only on loopback, or on a specific LAN/VPN interface address. Terminate TLS at a reverse proxy or run over a VPN, and do not expose this server to the public internet.

## Stack editors (DockHand, Portainer, …)

In a stack editor such as DockHand or Portainer, never put secrets in the YAML, and keep every hardening flag from the reference compose.

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
