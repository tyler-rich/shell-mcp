# Images for the setup check (scripts/setup-check/run.sh): one per supported
# target, on the digest-pinned bases scripts/exposure pins, with what
# TARGET-SETUP's container steps need: OpenSSH (server and client), passwd,
# systemd (for systemd-analyze verify; it never runs as PID 1 here),
# polkitd, acl and git. The release binaries built from the commit are
# copied in by run.sh; nothing else of this repository is baked in. Used by
# scripts/ci-local.sh and CI only, never shipped.

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS debian13
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client passwd systemd polkitd acl git \
 && rm -rf /var/lib/apt/lists/*

FROM ubuntu:24.04@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c AS ubuntu2404
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client passwd systemd polkitd acl git \
 && rm -rf /var/lib/apt/lists/*

FROM ubuntu:26.04@sha256:19fcd1bf268f02b60aca3bd30bd8a6d9a11759a430e32921833e65f16d87348a AS ubuntu2604
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client passwd systemd polkitd acl git \
 && rm -rf /var/lib/apt/lists/*
