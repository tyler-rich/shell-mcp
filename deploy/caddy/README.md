# A reverse proxy in front of shell-mcp

The server speaks plain HTTP and never publishes a port of its own (`../docker-compose.yml`). Clients reach it through a reverse proxy that you run: Caddy, nginx, Traefik or any other. This page lists what that proxy must do, in terms any of them can follow, and why each property matters. [`Caddyfile`](Caddyfile) and [`nginx.conf`](nginx.conf) here are two examples that meet them; neither is a requirement, and nothing in this directory runs a container for you.

The names below are the reference compose's placeholders: the server at `172.30.80.10` on the user-defined network `front` (`172.30.80.0/24`), the proxy at `172.30.80.5`, the MCP name `mcp.example.test` and the approval page's name `approve.example.test`, a LAN `192.0.2.0/24` and a VPN `198.51.100.0/24`. Use your own; `shell-mcp init compose` prints the compose file with them ([`../README.md`](../README.md#shell-mcp-init-compose)).

## What every proxy needs

### 1. It joins the server's network at a fixed address

The proxy is a member of the network the server sits on (`front` in the reference compose) with a fixed address on it (`172.30.80.5`), and reaches the server directly at `172.30.80.10`: port `8080` for MCP (`SHELL_MCP_PORT`) and port `8081` for the approval page (`SHELL_MCP_APPROVAL_PORT`). A fixed address is what lets the server trust exactly one peer, and nothing else on the host.

- **In a compose file:** give the proxy's service `networks: { front: { ipv4_address: 172.30.80.5 } }`. When the proxy lives in another compose project, declare the network there as `external: true` with the name Compose gave it (`<project>_front`, for example `deploy_front`).
- **Only the proxy publishes a port**, and only on a LAN or VPN address of the host, never on all interfaces by accident.
- **The proxy is a container on that network.** A proxy installed on the host itself (nginx or Caddy from the distribution's packages, for example) is not supported by this layout. The host reaches a container on a user-defined network from that network's gateway (`172.30.80.1` here), so the server would see every request arrive from the gateway, and the only way to make that work would be to trust the gateway, which this page forbids (property 3): every local process and every container that reaches the server through the host would then share that address and could name any client it liked. Run the proxy as a container on the server's network instead, with its fixed address.

Why ([`../../docs/CLIENTS.md`](../../docs/CLIENTS.md#1-two-transports) §1): the server believes `X-Forwarded-For` only from the addresses in `SHELL_MCP_TRUSTED_PROXIES`, and whoever can connect from a trusted address can name any client it likes.

### 2. It passes on the address it saw, not one a client sent

The proxy sets `X-Forwarded-For` to the address of the client that connected to it. The server reads only the last entry, the one its trusted peer added. A client-sent `X-Forwarded-For` must never reach the server as that last entry.

- **Caddy:** `reverse_proxy` does this by default. Without `trusted_proxies` (neither in the global options nor in `reverse_proxy`), Caddy replaces a client's `X-Forwarded-For` with the peer address. With it, Caddy appends the peer to what a trusted client sent. Checked in Caddy 2.11.7's source (`modules/caddyhttp/reverseproxy/reverseproxy.go`, `addForwardedHeaders`). The example sets no `trusted_proxies`.
- **nginx:** `proxy_set_header X-Forwarded-For $remote_addr;` replaces the header, as [`nginx.conf`](nginx.conf) does. `$proxy_add_x_forwarded_for` keeps a client's header and appends `$remote_addr` after a comma, which also leaves the proxy's own observation last. Also pass the name the client used, `proxy_set_header Host $host;`: nginx sends the upstream's own name (`$proxy_host`) by default, and the server answers only for the names in `SHELL_MCP_ALLOWED_HOSTS` (and the approval page only for its public URL's host).
- **Traefik:** leave the entry point's `forwardedHeaders.insecure` off, and do not list client networks in `forwardedHeaders.trustedIPs`. Traefik's documentation says `insecure` trusts every `X-Forwarded-*` header and recommends it for tests only.

### 3. That address, and only it, is `SHELL_MCP_TRUSTED_PROXIES`

Set `SHELL_MCP_TRUSTED_PROXIES` to the proxy's single fixed address (`172.30.80.5`), not a prefix, and **never the network's gateway**. When something reaches the server through a port Docker publishes on the host, the server often sees the gateway (the network's first address, `172.30.80.1` here) as the peer. Trusting the gateway would trust every local process and container that connects that way, and each could invent its own client address: spread its token guesses over invented addresses to dodge the lockout, lock out a real client, or put false names in the approval page's logs. [CLIENTS §1](../../docs/CLIENTS.md#1-two-transports) has the measurement.

The same list governs the approval listener: with `SHELL_MCP_APPROVAL_BIND` on a non-loopback address and no native TLS, the approval page serves only the proxies in this list ([CLIENTS §3.2](../../docs/CLIENTS.md#32-setting-it-up)).

`shell-mcp doctor` checks this statically inside the server's container: an entry that is or holds one of the container's gateways (read from its routing table) is a FAIL, a prefix or an address on no network the container is attached to is a WARN ([`../../docs/TARGET-SETUP.md`](../../docs/TARGET-SETUP.md#126-shell-mcp-doctor-container) §12.6).

### 4. The approval page is reachable from the LAN or VPN only

The approval host (`approve.example.test`) answers only clients on your LAN or VPN. Everything else gets `403` or no answer. The page is where a person approves what the model may not do alone; it must not be reachable from the internet. The MCP endpoint should be limited the same way: there is no OAuth, and the server is not meant for the public internet ([`../../docs/SECURITY.md`](../../docs/SECURITY.md#3-authentication-modes-mcp-side) §3).

**Never put the proxy, the MCP endpoint or the approval page behind a tunnel or an internet-facing relay** (Cloudflare Tunnel, ngrok, Tailscale Funnel or similar). This is a rule, not a preference, because nothing below can enforce it: a source-address filter decides by the address of the connection that reaches the proxy, and behind a tunnel that is the tunnel's connector, a process on your own machine or network (often a container on a Docker network), never the internet client it relays. The filter would let the whole internet through as that one local address.

- **The ranges are explicit LAN and VPN prefixes, as placeholders you replace.** Never a catch-all such as Caddy's `private_ranges`, and never a range that holds a Docker network: `172.16.0.0/12` holds Docker's default bridge networks, and the server's own subnet (`172.30.80.0/24` here) is one. A tunnel connector in a container on such a network would pass. The examples' tests refuse such a range.
- **Caddy:** a `remote_ip` matcher with your LAN and VPN ranges, the `reverse_proxy` inside `handle @private`, and `respond 403` inside a separate `handle {}` fallback, as in the example. `remote_ip` matches the address of the direct connection to Caddy, never a forwarded header.
- **nginx:** `allow 192.0.2.0/24; allow 198.51.100.0/24; deny all;` in each server block (a refused request gets `403`), as in [`nginx.conf`](nginx.conf). nginx's `allow` matches the connection's address unless the `realip` module rewrites it; leave `set_real_ip_from` unset.
- **Traefik:** an `ipAllowList` middleware whose `sourceRange` lists the LAN and VPN ranges. It matches the connection's remote address by default and answers `403` to everything else.
- **Behind Docker's port publishing, check what the proxy sees.** If every request gets `403`, the proxy sees the Docker gateway rather than the client (CLIENTS §1). Fix how the port reaches the proxy; never add the gateway or the whole Docker network to the allowed ranges, which would admit every local process.

`shell-mcp doctor` requests the approval page's public URL from inside the server's container. With a LAN/VPN-only proxy, that request may arrive from an address the proxy refuses; doctor then reports a WARN that the proxy, not the page, answered `403`. Check the page from a LAN or VPN machine instead. It cannot show that the page is unreachable from outside; check that from outside.

### 5. After an edit, restart a proxy whose configuration is mounted as a single file

When the proxy's configuration file is bind-mounted into its container as a single file, an edit needs a container restart, not a reload. Most editors save by writing a new file and renaming it over the old one. The container's mount stays on the old file, so a reload (`caddy reload`, `nginx -s reload`) reads the old content. Mount the directory that holds the file instead, and a reload sees the edit.

## Check it once: does the server see each client's own address?

The properties above are what a proxy must do; whether yours does is a measurement, which `doctor` cannot make: it would need a route that reports the caller's address, and the server has none. `init compose` already set `SHELL_MCP_TRUSTED_PROXIES` to your proxy's fixed address (`--proxy-addr`); this check confirms that value, once, as [CLIENTS §1](../../docs/CLIENTS.md#1-two-transports) says:

1. From a client machine on your LAN or VPN, send one request without a token through the proxy:

   ```bash
   curl -s -X POST https://mcp.example.test/mcp
   ```

2. On the server host, in the deployment's directory, read the `client` field of the server's `authentication failed` WARN line (or use your stack editor's log view). A request without a token does not count toward the lockout.

   ```bash
   docker compose logs shell-mcp 2>&1 | grep 'authentication failed'
   ```

3. **It must show the client machine's own address**, for example `"client":"192.0.2.20/32"`. Then the preset value is right, and you are done.
   - **It shows the proxy's address** (`172.30.80.5/32`): the server trusts the proxy, but the proxy does not set `X-Forwarded-For` (property 2).
   - **It shows another address on the server's network:** the proxy is not at the address you listed. Give it its fixed address (property 1), or, if that is where it is meant to be, run `init compose` again with that `--proxy-addr` (never the gateway, property 3), and recreate the server's container.
   - **It shows the network's gateway** (`172.30.80.1/32`): the request did not come through a proxy container on the network, but through the host (a published port, or a proxy installed on the host, property 1). Fix the path; never trust the gateway.

## The example

[`Caddyfile`](Caddyfile) has both sites, each limited to the LAN and VPN placeholders, with no `trusted_proxies`, and comments on TLS and reloading. TLS is yours to choose: Caddy's automatic certificates need a public DNS name it can prove it serves, `tls internal` needs every client's and approver's device to trust Caddy's local root, or TLS can end in front of Caddy or the whole path can run over a VPN. To run it, give Caddy's container the `front` network at `172.30.80.5`, publish its ports on a LAN or VPN address only, and mount the directory that holds the Caddyfile (property 5).

[`nginx.conf`](nginx.conf) is the same for nginx: server blocks for nginx's `http` context, one per site, with placeholder certificate paths, the same LAN and VPN ranges with `deny all`, `Host $host` and `X-Forwarded-For $remote_addr`, `proxy_http_version 1.1`, `proxy_buffering off` (MCP answers can be event streams), a `proxy_read_timeout` above `SHELL_MCP_MAX_TIMEOUT`'s default of 300 seconds (raise both together) and `client_max_body_size 2m` (the server reads at most 1 MiB). Put it where your nginx includes server blocks (the official image includes `/etc/nginx/conf.d/*.conf`), and mount that directory (property 5).

CI checks both examples on every change: their upstreams against `../docker-compose.yml`'s server address and ports, the shape above, that every allowed range is an explicit one holding no Docker network, and `caddy validate` and `nginx -t`, each in a test-only image pinned by digest, run with no network, a read-only root, no capabilities and a non-root user (`scripts/caddy-check/`, `scripts/nginx-check/`). Each check also has negative controls that must be refused. A third check runs both examples live, in the same test-only images, in front of a server started from `init compose`'s file, with clients on a network that reaches only the proxy: the token, the client address the server logs (a forged `X-Forwarded-For` included), the approval page's `Host` rule, the allowed ranges and `doctor`'s rows, with a proxy that passes a client's `X-Forwarded-For` through, a gateway-sourced proxy and the gateway in `SHELL_MCP_TRUSTED_PROXIES` as negative controls (`scripts/proxy-live-check/`). It replaces only the placeholders, so it is no substitute for "Check it once" on your own network.
