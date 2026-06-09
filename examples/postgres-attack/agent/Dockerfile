FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ENV CGO_ENABLED=0 GOFLAGS="-trimpath"
RUN go build -ldflags "-s -w" -o /out/agent .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/agent /usr/local/bin/agent
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/agent"]
