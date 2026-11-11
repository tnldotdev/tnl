FROM docker.io/library/golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea
RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 && rm -rf /var/lib/apt/lists/*
