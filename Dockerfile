# shell-mcp server image. The gate and helper binaries are not in the image;
# they ship as release assets. Base images are pinned by digest (D-013);
# Dependabot keeps them current.

FROM golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS builder

ARG VERSION=dev
ARG REVISION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal

# .dockerignore excludes .git, so -buildvcs=true stamps no VCS data here; the
# revision is injected through ldflags and the OCI revision label.
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=true \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${REVISION}" \
      -o /out/shell-mcp ./cmd/shell-mcp

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

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
