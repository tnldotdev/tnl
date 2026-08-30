# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

ARG VERSION=devel
ARG COMMIT=

FROM --platform=$BUILDPLATFORM golang:1.27.0-bookworm@sha256:ded31c68586d2e49e760acc2e65a884b23d032e9bbbed0ae0c55abd3fcaf4452 AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG COMMIT

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOFLAGS=-tags=ts_omit_ssh \
    go build -mod=readonly -trimpath \
    -ldflags="-s -w -X github.com/0xcadams/tnl/internal/buildinfo.Version=${VERSION} -X github.com/0xcadams/tnl/internal/buildinfo.Commit=${COMMIT}" \
    -o /out/tnld ./cmd/tnld && \
    install -d -m 0750 /out/state

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

ARG VERSION
ARG COMMIT

LABEL org.opencontainers.image.source="https://github.com/0xcadams/tnl" \
      org.opencontainers.image.description="TNL standalone core daemon" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$COMMIT

COPY --from=build --chown=65532:65532 /out/tnld /usr/local/bin/tnld
COPY --from=build --chown=65532:65532 /out/state/ /var/lib/tnl/
COPY --chown=65532:65532 LICENSE NOTICE /licenses/tnl/

USER 65532:65532
WORKDIR /var/lib/tnl
EXPOSE 8443 9090

ENTRYPOINT ["/usr/local/bin/tnld"]
