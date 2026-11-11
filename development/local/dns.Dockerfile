# syntax=docker.io/docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM docker.io/library/golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/development/dns ./internal/development/dns
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -o /dnsdev ./internal/development/dns/cmd/dnsdev
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /dnsdev /usr/local/bin/dnsdev
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.txt /licenses/tnl/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/dnsdev"]
