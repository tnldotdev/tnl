# syntax=docker.io/docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
FROM docker.io/library/golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/development/dns ./internal/development/dns
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -o /dnsdev ./internal/development/dns/cmd/dnsdev
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /dnsdev /usr/local/bin/dnsdev
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.txt /licenses/tnl/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/dnsdev"]
