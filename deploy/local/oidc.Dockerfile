# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM mirror.gcr.io/library/golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -o /oidcdev ./internal/devoidc/cmd/oidcdev
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /oidcdev /usr/local/bin/oidcdev
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.txt /licenses/tnl/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/oidcdev"]
