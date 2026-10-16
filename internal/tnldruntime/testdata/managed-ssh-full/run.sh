#!/bin/sh
set -eu

# run from the repository root through mise exec.
fixture="$(pwd)/internal/tnldruntime/testdata/managed-ssh-full"
test -f "$fixture/compose.yaml"
temporary="$(mktemp -d)"
project="tnl-managed-ssh-full-$$"
export TNL_MANAGED_SSH_FULL_BIN_DIR="$temporary"
cleanup() {
  docker compose --project-name "$project" --file "$fixture/compose.yaml" down --volumes --remove-orphans
  rm -rf "$temporary"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export GOOS=linux
GOARCH="$(go env GOHOSTARCH)"
export GOARCH CGO_ENABLED=0
go test -p=2 -c -o "$temporary/tnldruntime.test" ./internal/tnldruntime
go build -p=2 -o "$temporary/tnl" ./cmd/tnl
go mod download github.com/letsencrypt/pebble/v2@v2.10.1
go -C "$(go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@v2.10.1" build -p=2 -o "$temporary/pebble" ./cmd/pebble
docker compose --project-name "$project" --file "$fixture/compose.yaml" up --build --abort-on-container-exit --exit-code-from test
