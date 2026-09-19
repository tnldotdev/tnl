#!/usr/bin/env bash
set -euo pipefail

compose() {
  docker compose --ansi never --progress plain --file internal/tnldruntime/testdata/separated-load.compose.yaml "$@"
}

mkdir -p "$RESULTS"
log_pid=""
cleanup() {
  # Preserve exit/OOM evidence even when a component dies before a phase snapshot.
  compose ps --all --format json >"$RESULTS/containers-before-cleanup.json" 2>/dev/null || true
  compose stop visitor-1 visitor-2 visitor-3 visitor-4 >/dev/null 2>&1 || true
  compose stop app publishers >/dev/null 2>&1 || true
  compose stop ingress relay-a relay-b >/dev/null 2>&1 || true
  compose stop control pebble coordinator >/dev/null 2>&1 || true
  compose stop postgres >/dev/null 2>&1 || true
  compose ps --all --format json >"$RESULTS/containers.json" 2>/dev/null || true
  for container in $(compose ps --all --quiet); do
    docker inspect --format '{{.Name}} oom_killed={{.State.OOMKilled}} exit={{.State.ExitCode}} cpus={{.HostConfig.NanoCpus}} memory={{.HostConfig.Memory}}' "$container"
  done
  if [[ -n "$log_pid" ]]; then
    kill "$log_pid" 2>/dev/null || true
    wait "$log_pid" 2>/dev/null || true
  fi
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
compose down --volumes --remove-orphans >/dev/null 2>&1
trap cleanup EXIT HUP INT TERM
compose config --quiet
compose run --rm build
compose up --wait postgres
compose run --rm setup
compose up --detach \
  control ingress relay-a relay-b publishers visitor-1 visitor-2 visitor-3 visitor-4 app pebble coordinator
compose logs --follow --no-color &
log_pid=$!
# Detect any failed component after startup has finished. Compose's attached
# abort-on-exit can race still-starting containers and leave the attachment hung.
containers=$(compose ps --all --quiet)
while true; do
  states=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}} {{.State.Running}} {{.State.ExitCode}}' $containers)
  while read -r service running status; do
    if [[ "$running" == false ]]; then
      if [[ "$service" == coordinator ]]; then exit "$status"; fi
      exit 1
    fi
  done <<<"$states"
  sleep 1
done
