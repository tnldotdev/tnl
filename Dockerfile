# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

ARG VERSION=devel
ARG COMMIT=

FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG COMMIT

WORKDIR /src
RUN apt-get update && \
    apt-get install --yes --no-install-recommends libcap2-bin && \
    rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -mod=readonly -trimpath \
    -ldflags="-s -w -X github.com/tnldotdev/tnl/internal/buildinfo.Version=${VERSION} -X github.com/tnldotdev/tnl/internal/buildinfo.Commit=${COMMIT}" \
    -o /out/tnld ./cmd/tnld && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -mod=readonly -trimpath \
    -ldflags="-s -w -X github.com/tnldotdev/tnl/internal/buildinfo.Version=${VERSION} -X github.com/tnldotdev/tnl/internal/buildinfo.Commit=${COMMIT}" \
    -o /out/tnl ./cmd/tnl && \
    setcap cap_net_bind_service=+ep /out/tnld
RUN install -d -m 0700 /out/client-state

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

ARG VERSION
ARG COMMIT

LABEL org.opencontainers.image.source="https://github.com/tnldotdev/tnl" \
      org.opencontainers.image.description="tnl client and self-hosted server daemon" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$COMMIT

# Changing ownership during COPY would clear the file capability.
COPY --from=build /out/tnld /usr/local/bin/tnld
COPY --from=build --chown=65532:65532 /out/tnl /usr/local/bin/tnl
COPY --from=build --chown=65532:65532 --chmod=0700 /out/client-state /state
COPY --chown=65532:65532 LICENSE NOTICE THIRD_PARTY_LICENSES.txt /licenses/tnl/

USER 65532:65532
ENV TNL_STATE_DIR=/state
WORKDIR /
EXPOSE 8443/tcp 8443/udp 9090/tcp 9443/tcp 9444/tcp

ENTRYPOINT ["/usr/local/bin/tnld"]
