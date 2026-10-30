# Images for the offline exposure check (scripts/exposure/run.sh): one per
# systemd version of a supported target, each the distribution's own systemd
# package on a digest-pinned base. Nothing runs here: systemd-analyze
# security --offline reads unit files and needs no PID 1. Used by
# scripts/ci-local.sh and CI only.

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS debian13
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd \
 && rm -rf /var/lib/apt/lists/*

FROM ubuntu:25.10@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092 AS ubuntu2404
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd \
 && rm -rf /var/lib/apt/lists/*

FROM ubuntu:26.04@sha256:19fcd1bf268f02b60aca3bd30bd8a6d9a11759a430e32921833e65f16d87348a AS ubuntu2604
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd \
 && rm -rf /var/lib/apt/lists/*
