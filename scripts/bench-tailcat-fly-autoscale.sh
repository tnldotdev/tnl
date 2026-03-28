#!/usr/bin/env bash

set -euo pipefail

org="${ORG:-tnl}"
region="${REGION:-sjc}"
worker_size="${WORKER_SIZE:-performance-2x}"
client_size="${CLIENT_SIZE:-performance-2x}"
worker_memory_limit="${WORKER_GOMEMLIMIT:-3GiB}"
if [[ ! "${worker_memory_limit}" =~ ^([1-9][0-9]*)(MiB|GiB)$ ]]; then
  printf 'WORKER_GOMEMLIMIT must be a whole number of MiB or GiB\n' >&2
  exit 2
fi
worker_memory_limit_bytes="${BASH_REMATCH[1]}"
if [[ "${BASH_REMATCH[2]}" == "GiB" ]]; then
  worker_memory_limit_bytes=$((worker_memory_limit_bytes * 1024))
fi
worker_memory_limit_bytes=$((worker_memory_limit_bytes * 1024 * 1024))
shard_target="${SHARD_TARGET:-400}"
shard_limit="${SHARD_LIMIT:-500}"
routes="${ROUTES:-5000}"
parallel="${PARALLEL:-8}"
local_port="${LOCAL_PORT:-18080}"
run_id="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)"
prefix="tnl-tailbench-${run_id}"
worker_app="${prefix}-workers"
client_app="${prefix}-clients"
controller_app="${prefix}-controller"
autoscaler_app="${prefix}-autoscaler"
worker_image="registry.fly.io/${worker_app}:${run_id}"
client_image="registry.fly.io/${client_app}:${run_id}"
controller_image="registry.fly.io/${controller_app}:${run_id}"
token="$(openssl rand -hex 32)"
metrics_config='{"metrics":{"port":8080,"path":"/metrics"}}'
temp_dir="$(mktemp -d)"
proxy_pid=""
phase="setup"

cleanup() {
  set +e
  if [[ -n "${proxy_pid}" ]]; then
    kill "${proxy_pid}" 2>/dev/null
    wait "${proxy_pid}" 2>/dev/null
  fi
  fly apps destroy "${autoscaler_app}" --yes >/dev/null 2>&1
  fly apps destroy "${client_app}" --yes >/dev/null 2>&1
  fly apps destroy "${controller_app}" --yes >/dev/null 2>&1
  fly apps destroy "${worker_app}" --yes >/dev/null 2>&1
  while read -r token_id _ token_name _; do
    if [[ "${token_name}" == "${prefix}" ]]; then
      fly tokens revoke "${token_id}" >/dev/null 2>&1
    fi
  done < <(fly tokens list --org "${org}" --scope org 2>/dev/null)
  rm -r "${temp_dir}" 2>/dev/null
}

finish() {
  local status=$?
  trap - EXIT
  if ((status != 0)); then
    printf 'Fly autoscaling benchmark failed during %s (exit %d).\n' "${phase}" "${status}" >&2
  fi
  cleanup
  exit "${status}"
}
trap finish EXIT
trap 'exit 130' INT TERM

run_machine() {
  for _ in $(seq 1 5); do
    if fly machine run "$@"; then
      return 0
    fi
    sleep 5
  done
  return 1
}

wait_for_count() {
  local app="$1"
  local wanted="$2"
  local require_started="$3"
  local deadline=$((SECONDS + 600))
  while ((SECONDS < deadline)); do
    fly machine list --app "${app}" --json >"${temp_dir}/machines.json"
    local created
    local started
    created="$(jq 'length' "${temp_dir}/machines.json")"
    started="$(jq '[.[] | select(.state == "started")] | length' "${temp_dir}/machines.json")"
    if [[ "${created}" == "${wanted}" && ("${require_started}" != "yes" || "${started}" == "${wanted}") ]]; then
      return 0
    fi
    sleep 5
  done
  printf 'timed out waiting for %s Machines in %s\n' "${wanted}" "${app}" >&2
  fly machine list --app "${app}" >&2 || true
  fly logs --app "${autoscaler_app}" --no-tail >&2 || true
  return 1
}

set_demand() {
  local count="$1"
  curl --fail --silent --show-error \
    -X PUT \
    -H "Authorization: Bearer ${token}" \
    -H 'Content-Type: application/json' \
    --data "{\"routes\":${count}}" \
    "http://127.0.0.1:${local_port}/v1/demand" >/dev/null
}

wait_for_prometheus() {
  local query="max(tnl_routes{app=\"${controller_app}\",state=\"active\"})"
  local deadline=$((SECONDS + 600))
  while ((SECONDS < deadline)); do
    local value
    value="$(curl --fail --silent --get \
      -H "Authorization: ${prometheus_token}" \
      --data-urlencode "query=${query}" \
      "https://api.fly.io/prometheus/${org}/api/v1/query" | jq -r '.data.result[0].value[1] // empty')"
    if [[ -n "${value}" ]]; then
      printf 'Prometheus active route metric: %s\n' "${value}"
      return 0
    fi
    sleep 5
  done
  printf 'controller metric did not reach Fly Prometheus\n' >&2
  fly machine list --app "${controller_app}" --json | jq '.[0].config.metrics' >&2
  return 1
}

destroy_clients() {
  local ids=()
  while IFS= read -r id; do
    [[ -n "${id}" ]] && ids+=("${id}")
  done < <(fly machine list --app "${client_app}" --json | jq -r '.[].id')
  if ((${#ids[@]} > 0)); then
    fly machine destroy --force --app "${client_app}" "${ids[@]}" >/dev/null
  fi
}

validate_result() {
  local label="$1"
  local machine_id="$2"
  local result="$3"
  if ! jq -e --argjson limit "${worker_memory_limit_bytes}" \
    '.worker_metrics_ok and .worker_memory_limit == $limit and .worker_forced_closes == 0 and (.worker_drain_error // "") == ""' \
    <<<"${result}" >/dev/null; then
    printf '%s Machine %s failed validation:\n%s\n' "${label}" "${machine_id}" "${result}" >&2
    return 1
  fi
}

summarize_results() {
  local total="$1"
  local results="$2"
  jq -s -e --argjson routes "${total}" 'map(.route_count) | add == $routes' "${results}" >/dev/null
  jq -s '{
    routes: (map(.route_count) | add),
    transferred_bytes: (map(.transfer_bytes) | add),
    throughput_mib_per_second: (map(.throughput_mib_per_second) | add),
    startup_p95_ms: (map(.startup_p95_ms) | max),
    first_byte_p95_ms: (map(.first_byte_p95_ms) | max),
    shutdown_p95_ms: (map(.shutdown_p95_ms) | max),
    max_worker_rss: (map(.worker_ready.rss) | max),
    max_client_rss: (map(.client_ready.rss) | max),
    forced_closes: (map(.worker_forced_closes) | add),
    started_at: (map(.started_at) | min),
    finished_at: (map(.finished_at) | max)
  }' "${results}"
}

run_sharded() {
  local label="$1"
  local total="$2"
  local worker_count="$3"
  local per_worker="$4"
  local worker_ids=()
  local worker_ips=()
  local client_ids=()
  local remaining="${total}"
  local start_unix=$(( $(date +%s) + 180 ))
  local results="${temp_dir}/${label}-results.jsonl"
  phase="${label}"

  fly machine list --app "${worker_app}" --json >"${temp_dir}/workers.json"
  while IFS=$'\t' read -r id ip; do
    worker_ids+=("${id}")
    worker_ips+=("${ip}")
  done < <(jq -r '.[] | select(.state == "started") | [.id, .private_ip] | @tsv' "${temp_dir}/workers.json")
  if ((${#worker_ids[@]} < worker_count)); then
    printf '%s has %d started workers; want %d\n' "${label}" "${#worker_ids[@]}" "${worker_count}" >&2
    return 1
  fi

  printf '\nRunning %s: %d routes across %d workers\n' "${label}" "${total}" "${worker_count}"
  for ((index = 0; index < worker_count; index++)); do
    local shard="${per_worker}"
    if ((remaining < shard)); then
      shard="${remaining}"
    fi
    remaining=$((remaining - shard))
    run_machine "${client_image}" client \
      --app "${client_app}" \
      --config fly.tailbench.toml \
      --name "${label}-${index}" \
      --region "${region}" \
      --vm-size "${client_size}" \
      --restart no \
      --detach \
      --env "GOMEMLIMIT=${worker_memory_limit}" \
      --env "TS_DEBUG_NEVER_DIRECT_UDP=1" \
      --env "TNL_TAILBENCH_TOKEN=${token}" \
      --env "TNL_TAILBENCH_SERVER_URL=http://[${worker_ips[index]}]:8080" \
      --env "TNL_TAILBENCH_ROUTES=${shard}" \
      --env "TNL_TAILBENCH_PARALLEL=${parallel}" \
      --env "TNL_TAILBENCH_START_UNIX=${start_unix}" \
      --env "TNL_TAILBENCH_MAX_RUNTIME=2h" >/dev/null
  done
  if ((remaining != 0)); then
    printf '%s left %d routes unassigned\n' "${label}" "${remaining}" >&2
    return 1
  fi

  while IFS= read -r id; do
    [[ -n "${id}" ]] && client_ids+=("${id}")
  done < <(fly machine list --app "${client_app}" --json | jq -r '.[].id')
  if ((${#client_ids[@]} != worker_count)); then
    printf '%s launched %d clients; want %d\n' "${label}" "${#client_ids[@]}" "${worker_count}" >&2
    return 1
  fi

  local deadline=$((SECONDS + 3600))
  while ((SECONDS < deadline)); do
    fly machine list --app "${client_app}" --json >"${temp_dir}/clients.json"
    local stopped
    stopped="$(jq '[.[] | select(.state == "stopped")] | length' "${temp_dir}/clients.json")"
    [[ "${stopped}" == "${worker_count}" ]] && break
    sleep 10
  done
  if ((SECONDS >= deadline)); then
    printf '%s clients did not stop within one hour\n' "${label}" >&2
    return 1
  fi

  for id in "${client_ids[@]}"; do
    local result
    result="$(fly logs --app "${client_app}" --machine "${id}" --no-tail --json | jq -rs '[.[] | .message? | select(contains("TAILBENCH_RESULT ")) | split("TAILBENCH_RESULT ")[1]] | last // empty')"
    if [[ -z "${result}" ]]; then
      printf '%s client %s did not report a result\n' "${label}" "${id}" >&2
      fly logs --app "${client_app}" --machine "${id}" --no-tail >&2 || true
      return 1
    fi
    validate_result "${label}" "${id}" "${result}"
    printf '%s\n' "${result}" >>"${results}"
  done

  summarize_results "${total}" "${results}"
  destroy_clients
}

run_self_sharded() {
  local label="$1"
  local total="$2"
  local worker_count="$3"
  local per_worker="$4"
  local worker_ids=()
  local remaining="${total}"
  local start_unix=$(( $(date +%s) + 180 ))
  local results="${temp_dir}/${label}-results.jsonl"
  phase="${label}"

  while IFS= read -r id; do
    [[ -n "${id}" ]] && worker_ids+=("${id}")
  done < <(fly machine list --app "${worker_app}" --json | jq -r '.[] | select(.state == "started") | .id')
  if ((${#worker_ids[@]} != worker_count)); then
    printf '%s has %d started workers; want %d\n' "${label}" "${#worker_ids[@]}" "${worker_count}" >&2
    return 1
  fi

  printf '\nRunning %s: %d routes across %d workers\n' "${label}" "${total}" "${worker_count}"
  for id in "${worker_ids[@]}"; do
    local shard="${per_worker}"
    if ((remaining < shard)); then
      shard="${remaining}"
    fi
    remaining=$((remaining - shard))
    fly machine update "${id}" \
      --app "${worker_app}" \
      --command self \
      --restart no \
      --detach \
      --yes \
      --env "TNL_TAILBENCH_ROUTES=${shard}" \
      --env "TNL_TAILBENCH_PARALLEL=${parallel}" \
      --env "TNL_TAILBENCH_START_UNIX=${start_unix}" >/dev/null
  done
  if ((remaining != 0)); then
    printf '%s left %d routes unassigned\n' "${label}" "${remaining}" >&2
    return 1
  fi

  local deadline=$((SECONDS + 3600))
  while ((SECONDS < deadline)); do
    local reported=0
    for id in "${worker_ids[@]}"; do
      local result_file="${temp_dir}/${label}-${id}.json"
      if [[ ! -s "${result_file}" ]]; then
        local result
        result="$(fly logs --app "${worker_app}" --machine "${id}" --no-tail --json 2>/dev/null | jq -rs '[.[] | .message? | select(contains("TAILBENCH_RESULT ")) | split("TAILBENCH_RESULT ")[1]] | last // empty')" || true
        if [[ -n "${result}" ]]; then
          validate_result "${label}" "${id}" "${result}"
          printf '%s\n' "${result}" >"${result_file}"
        fi
      fi
      [[ -s "${result_file}" ]] && reported=$((reported + 1))
    done
    ((reported == worker_count)) && break
    sleep 10
  done
  if ((SECONDS >= deadline)); then
    printf '%s workers did not all report results within one hour\n' "${label}" >&2
    fly logs --app "${worker_app}" --no-tail >&2 || true
    return 1
  fi

  for id in "${worker_ids[@]}"; do
    jq -c . "${temp_dir}/${label}-${id}.json" >>"${results}"
  done
  summarize_results "${total}" "${results}"
}

create_fly_token() {
  local kind="$1"
  local output
  if [[ "${kind}" == "deploy" ]]; then
    output="$(fly tokens create deploy --app "${worker_app}" --expiry 4h --name "${prefix}" --json)"
  else
    output="$(fly tokens create readonly --org "${org}" --expiry 4h --name "${prefix}" --json)"
  fi
  created_fly_token="$(jq -r '.token' <<<"${output}")"
}

for app in "${worker_app}" "${client_app}" "${controller_app}" "${autoscaler_app}"; do
  fly apps create "${app}" --org "${org}" --yes >/dev/null
done

phase="image build"
for app in "${worker_app}" "${client_app}" "${controller_app}"; do
  fly deploy . \
    --app "${app}" \
    --config fly.tailbench.toml \
    --build-only \
    --push \
    --image-label "${run_id}" \
    --no-public-ips >/dev/null
done
sleep 10

phase="controller launch"
run_machine "${controller_image}" controller \
  --app "${controller_app}" \
  --machine-config "${metrics_config}" \
  --name controller \
  --region "${region}" \
  --vm-size shared-cpu-1x \
  --restart no \
  --detach \
  --env "TNL_TAILBENCH_TOKEN=${token}" \
  --env "TNL_TAILBENCH_MAX_RUNTIME=2h" >/dev/null
wait_for_count "${controller_app}" 1 yes
fly machine list --app "${controller_app}" --json | jq -e '.[0].config.metrics.port == 8080' >/dev/null

controller_ip="$(fly machine list --app "${controller_app}" --json | jq -r '.[0].private_ip')"
fly proxy "${local_port}:8080" "${controller_ip}" --app "${controller_app}" --quiet >"${temp_dir}/proxy.log" 2>&1 &
proxy_pid=$!
for _ in $(seq 1 60); do
  curl --fail --silent "http://127.0.0.1:${local_port}/healthz" >/dev/null && break
  sleep 1
done
curl --fail --silent "http://127.0.0.1:${local_port}/healthz" >/dev/null

phase="worker launch"
fly deploy . \
  --app "${worker_app}" \
  --config fly.tailbench.toml \
  --image "${worker_image}" \
  --ha=false \
  --vm-size "${worker_size}" \
  --no-public-ips \
  --yes \
  --env "GOMEMLIMIT=${worker_memory_limit}" \
  --env "TS_DEBUG_NEVER_DIRECT_UDP=1" \
  --env "TNL_TAILBENCH_TOKEN=${token}" \
  --env "TNL_TAILBENCH_MAX_ROUTES=${shard_limit}" \
  --env "TNL_TAILBENCH_MAX_RUNTIME=2h" >/dev/null
wait_for_count "${worker_app}" 1 yes

if [[ "${SKIP_CAPACITY:-0}" != "1" ]]; then
  run_sharded calibration-400 400 1 400
  run_sharded calibration-500 500 1 500

  seed_id="$(fly machine list --app "${worker_app}" --json | jq -r '.[0].id')"
  for index in 1 2 3; do
    fly machine clone "${seed_id}" \
      --app "${worker_app}" \
      --name "static-${index}" \
      --region "${region}" \
      --vm-size "${worker_size}" \
      --detach >/dev/null
  done
  wait_for_count "${worker_app}" 4 yes
  run_sharded static-2000 2000 4 500
fi

create_fly_token deploy
deploy_token="${created_fly_token}"
create_fly_token readonly
prometheus_token="${created_fly_token}"
fly secrets set --app "${autoscaler_app}" --stage \
  "FAS_API_TOKEN=${deploy_token}" \
  "FAS_PROMETHEUS_TOKEN=${prometheus_token}" >/dev/null

set_demand 0
phase="Prometheus ingestion"
wait_for_prometheus
phase="autoscaler launch"
run_machine flyio/fly-autoscaler:0.3.2 \
  --app "${autoscaler_app}" \
  --name autoscaler \
  --region "${region}" \
  --vm-size shared-cpu-1x \
  --restart no \
  --detach \
  --env "FAS_APP_NAME=${worker_app}" \
  --env "FAS_PROMETHEUS_ADDRESS=https://api.fly.io/prometheus/${org}" \
  --env "FAS_PROMETHEUS_METRIC_NAME=active_routes" \
  --env "FAS_PROMETHEUS_QUERY=max(tnl_routes{app=\"${controller_app}\",state=\"active\"})" \
  --env "FAS_CREATED_MACHINE_COUNT=max(1, min(13, ceil(active_routes / ${shard_target})))" \
  --env "FAS_STARTED_MACHINE_COUNT=max(1, min(13, ceil(active_routes / ${shard_target})))" >/dev/null
wait_for_count "${autoscaler_app}" 1 yes
wait_for_count "${worker_app}" 1 yes

for tier in 500 1000 2000 3000 4000 5000; do
  phase="scale to ${tier}"
  expected=$(((tier + shard_target - 1) / shard_target))
  printf 'Scaling to %d routes (%d workers)\n' "${tier}" "${expected}"
  set_demand "${tier}"
  wait_for_count "${worker_app}" "${expected}" yes
done

final_workers=$(((routes + shard_target - 1) / shard_target))
if ((final_workers > 13)); then
  printf '%d routes require %d workers; autoscaler is capped at 13\n' "${routes}" "${final_workers}" >&2
  exit 2
fi
run_self_sharded autoscaled-5000 "${routes}" "${final_workers}" "${shard_target}"
set_demand 0
wait_for_count "${worker_app}" 1 yes

printf '\nAutoscaling run passed; destroying temporary Fly resources.\n'
phase="cleanup"
cleanup
trap - EXIT INT TERM

remaining="$(fly apps list --org "${org}" --json | jq --arg prefix "${prefix}" '[.[] | select((.Name // .name) | startswith($prefix))] | length')"
if [[ "${remaining}" != "0" ]]; then
  printf '%s temporary Fly apps remain\n' "${remaining}" >&2
  exit 1
fi
printf 'Cleanup verified: no apps remain for %s.\n' "${prefix}"
