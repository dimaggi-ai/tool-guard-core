# syntax=docker/dockerfile:1.6
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
    -o /out/content-gen-tools ./examples/content-gen/tools

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="content-gen-tools (mock)"
LABEL org.opencontainers.image.description="Mock generative-AI tools for the content-gen demo bundle"
COPY --from=build /out/content-gen-tools /usr/local/bin/content-gen-tools
USER nonroot:nonroot
EXPOSE 18091
ENTRYPOINT ["/usr/local/bin/content-gen-tools"]
CMD ["-listen=:18091"]
