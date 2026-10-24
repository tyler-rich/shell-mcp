# shell-mcp server image. The gate and helper binaries are not in the image;
# they ship as release assets. Base images are pinned by digest (D-013);
# Dependabot keeps them current.

FROM golang:1.27.3-trixie@sha256:1896654cfc5c2b5ad74c07f29cb36f5d2d1cbed42e3054070fbfe444e521e83c AS builder

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

FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087

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
