# syntax=docker.io/docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
FROM docker.io/library/golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS toolchain
FROM docker.io/library/ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
RUN apt-get update && apt-get install --yes --no-install-recommends \
    systemd systemd-sysv dbus sudo ca-certificates git docker.io docker-compose-v2 gcc libc6-dev \
    && systemctl mask docker.service docker.socket containerd.service \
    && rm -rf /var/lib/apt/lists/*
COPY --from=toolchain /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV GOTOOLCHAIN=local
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
