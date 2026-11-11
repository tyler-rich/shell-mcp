# Test-only image for scripts/caddy-check/run.sh (handoff §4.G): `caddy
# validate` of deploy/caddy/Caddyfile, copied in at build time. Nothing in
# deploy/ or any document runs this image; it ships to no one. Pinned by
# digest to the newest stable Caddy (D-013); Dependabot's docker ecosystem
# tracks this directory.
FROM caddy:2.11.9@sha256:0c2243efcf437ab7f7a978f1027fcf0d4f9be8a75df27b1b3fbc5dbe0ffa8cf0
# The official image gives /usr/bin/caddy the file capability
# cap_net_bind_service=ep, to bind ports below 1024. The check runs with
# --cap-drop ALL and no-new-privileges, under which the kernel refuses to
# execute a binary whose file capabilities it cannot grant (EPERM,
# capabilities(7)); validate binds nothing, so the capability is removed.
RUN ["setcap", "-r", "/usr/bin/caddy"]
COPY Caddyfile /etc/caddy/Caddyfile
