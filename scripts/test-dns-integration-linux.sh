#!/bin/sh

set -eu

repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
suffix="$(date +%s)-$$"
network="tnl-dns-integration-$suffix"
postgres="tnl-dns-integration-postgres-$suffix"

cleanup() {
	docker rm --force "$postgres" >/dev/null 2>&1 || true
	docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

docker network create "$network" >/dev/null
docker run --detach --name "$postgres" --network "$network" --network-alias postgres \
	--env POSTGRES_DB=postgres --env POSTGRES_PASSWORD=postgres --env POSTGRES_USER=postgres \
	postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94 >/dev/null

attempt=0
until docker exec "$postgres" pg_isready --username postgres --dbname postgres >/dev/null 2>&1; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 30 ]; then
		docker logs "$postgres"
		exit 1
	fi
	sleep 1
done

docker run --rm --network "$network" \
	--volume "$repository_root:/workspace:ro" --workdir /workspace \
	--env GOFLAGS=-tags=ts_omit_ssh \
	--env TNL_TEST_INTEGRATION=1 \
	--env 'TNL_TEST_POSTGRES_URL=postgres://postgres:postgres@postgres:5432/postgres?sslmode=disable' \
	golang:1.27.0-bookworm@sha256:ded31c68586d2e49e760acc2e65a884b23d032e9bbbed0ae0c55abd3fcaf4452 \
	sh -ec '
		go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
		go test -race -v ./internal/tnldruntime \
			-run="^TestIntegrationSplitAutomaticRelayDNSCertificates$" \
			-count=1 -timeout=5m
	'
