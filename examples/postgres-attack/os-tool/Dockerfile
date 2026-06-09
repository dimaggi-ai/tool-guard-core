FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ENV CGO_ENABLED=0 GOFLAGS="-trimpath"
RUN go build -ldflags "-s -w" -o /out/os-tool .

# We DO need a shell here because os_exec runs `sh -c <cmd>`. Switch
# from distroless static (no shell) to alpine. The shell is the
# attack-surface point being protected by tg-proxy.
FROM alpine:3.20
RUN adduser -D -u 65532 osuser
COPY --from=build /out/os-tool /usr/local/bin/os-tool
USER osuser
EXPOSE 18090
ENTRYPOINT ["/usr/local/bin/os-tool"]
