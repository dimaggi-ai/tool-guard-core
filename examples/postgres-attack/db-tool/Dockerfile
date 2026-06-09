FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0 GOFLAGS="-trimpath"
RUN go build -ldflags "-s -w" -o /out/db-tool .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/db-tool /usr/local/bin/db-tool
USER nonroot:nonroot
EXPOSE 18080
ENTRYPOINT ["/usr/local/bin/db-tool"]
