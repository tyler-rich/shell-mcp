# Images for the offline exposure check (scripts/exposure/run.sh): one per
# systemd version of a supported target, each the distribution's own systemd
# package on a digest-pinned base. Nothing runs here: systemd-analyze
# security --offline reads unit files and needs no PID 1. Used by
# scripts/ci-local.sh and CI only.

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS debian13
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd \
 && rm -rf /var/lib/apt/lists/*

FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852 AS ubuntu2404
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd \
 && rm -rf /var/lib/apt/lists/*

FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c AS ubuntu2604
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd \
 && rm -rf /var/lib/apt/lists/*
