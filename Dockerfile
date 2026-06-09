# syntax=docker/dockerfile:1.6
#
# Multi-stage build for the Tool Guard Core binaries. Produces a small
# distroless image with `tg-proxy` as the default entrypoint and `tg`
# also on the PATH for one-shot CLI use.
#
# Default build: pure Go, statically linked, distroless/static-nonroot,
#                ~15 MB image (an ~11 MB static binary on distroless).
#                SQL classifier uses the tokenizer-based
#                lite package (pkg/sqlguard/lite + pkg/sqlguard/mssql).
#
# Strict build:  set BUILD_TAGS=pg_strict,mysql_strict,sqlite_strict and
#                CGO_ENABLED=1 to link the heavy parsers. Result is ~25 MB,
#                dynamically linked, distroless/base-debian12 runtime.
#
# Tagged release builds inject the version via -ldflags:
#
#   docker build --build-arg VERSION=v0.1.0 -t tool-guard-core:v0.1.0 .
#
# To build the strict variant explicitly:
#
#   docker build \
#     --build-arg BUILD_TAGS=pg_strict,mysql_strict,sqlite_strict \
#     --build-arg CGO=1 \
#     --build-arg RUNTIME=gcr.io/distroless/base-debian12:nonroot \
#     -t tool-guard-core:strict .

ARG RUNTIME=gcr.io/distroless/static-debian12:nonroot

FROM golang:1.25-bookworm AS build
WORKDIR /src

# Cache modules separately from source so a code-only change doesn't
# re-download deps every build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=""
ARG BUILD_TAGS=""
ARG CGO=0
ENV CGO_ENABLED=${CGO} \
    GOFLAGS="-trimpath"

RUN if [ -n "$VERSION" ]; then \
        LDFLAGS="-s -w -X main.Version=${VERSION}"; \
    else \
        LDFLAGS="-s -w"; \
    fi && \
    TAGS=""; \
    if [ -n "$BUILD_TAGS" ]; then TAGS="-tags=${BUILD_TAGS}"; fi && \
    go build $TAGS -ldflags "$LDFLAGS" -o /out/tg-proxy ./cmd/tg-proxy && \
    go build $TAGS -ldflags "$LDFLAGS" -o /out/tg       ./cmd/tg

FROM ${RUNTIME}
LABEL org.opencontainers.image.title="tool-guard-core"
LABEL org.opencontainers.image.description="Runtime policy firewall for AI agents — Apache 2.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/dimaggi-ai/tool-guard-core"
COPY --from=build /out/tg       /usr/local/bin/tg
COPY --from=build /out/tg-proxy /usr/local/bin/tg-proxy
USER nonroot:nonroot
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/tg-proxy"]
CMD ["-listen=:9090"]
