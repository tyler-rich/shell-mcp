# shell-mcp server image. The gate and helper binaries are not in the image;
# they ship as release assets. Base images are pinned by digest (D-013);
# Dependabot keeps them current.

# The builder runs on the build machine's platform and cross-compiles for the
# target (TARGETOS/TARGETARCH, set by BuildKit), so the arm64 image needs no
# emulation: the final stage only copies the binary.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS builder

ARG VERSION=dev
ARG REVISION=dev
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal

# The same flags as scripts/release/build.sh, so that the image's binary is
# byte-identical to the released shell-mcp binary of its platform (the
# release workflow checks it). The revision is injected through ldflags and
# the OCI revision label; no VCS data is stamped (.dockerignore excludes .git).
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${REVISION}" \
      -o /out/shell-mcp ./cmd/shell-mcp

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

ARG VERSION=dev
ARG REVISION=dev

LABEL org.opencontainers.image.source="https://github.com/tyler-rich/shell-mcp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Security-first MCP server for bounded, audited access to Linux hosts over SSH" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=builder /out/shell-mcp /shell-mcp

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/shell-mcp", "healthcheck"]
ENTRYPOINT ["/shell-mcp"]
CMD ["serve"]
