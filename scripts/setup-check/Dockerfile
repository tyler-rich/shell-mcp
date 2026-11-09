# Images for the setup check (scripts/setup-check/run.sh): one per supported
# target, on the digest-pinned bases scripts/exposure pins, with what
# TARGET-SETUP's container steps need: OpenSSH (server and client), passwd,
# systemd (for systemd-analyze verify; it never runs as PID 1 here),
# polkitd, acl and git. The release binaries built from the commit are
# copied in by run.sh; nothing else of this repository is baked in. Used by
# scripts/ci-local.sh and CI only, never shipped.

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS debian13
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client passwd systemd polkitd acl git \
 && rm -rf /var/lib/apt/lists/*

FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852 AS ubuntu2404
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client passwd systemd polkitd acl git \
 && rm -rf /var/lib/apt/lists/*

FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c AS ubuntu2604
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client passwd systemd polkitd acl git \
 && rm -rf /var/lib/apt/lists/*
