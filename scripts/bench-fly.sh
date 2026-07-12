#!/usr/bin/env bash

set -euo pipefail

org="${ORG:-tnl}"
region="${REGION:-sjc}"
modes="${MODES:-single-node,ha}"
single_routes="${SINGLE_ROUTES:-1,100,250,400,500}"
ha_routes="${HA_ROUTES:-1,250,500,800,1000}"
workers="${WORKERS:-2}"
drivers="${DRIVERS:-1}"
parallel="${PARALLEL:-8}"
payload_bytes="${PAYLOAD_BYTES:-65536}"
benchmark_timeout="${TIMEOUT:-5m}"
attempts="${ATTEMPTS:-3}"
driver_wait_seconds="${DRIVER_WAIT_SECONDS:-480}"
worker_capacity="${WORKER_CAPACITY:-500}"
nofile_limit="${NOFILE_LIMIT:-65536}"
single_size="${SINGLE_SIZE:-performance-6x}"
edge_size="${EDGE_SIZE:-performance-2x}"
worker_size="${WORKER_SIZE:-performance-6x}"
driver_size="${DRIVER_SIZE:-performance-8x}"
local_control_port="${LOCAL_CONTROL_PORT:-18443}"
derp_region="${DERP_REGION:-302}"
run_id="$(date -u +%m%d%H%M)-$(openssl rand -hex 2)"
barrier_token="$(openssl rand -hex 32)"
app="tnl-bench-${run_id}"
image="registry.fly.io/${app}:${run_id}"
temp_dir="$(mktemp -d)"
results_dir="${RESULTS_DIR:-bench-results}"
results_file="${results_dir}/${run_id}.jsonl"
proxy_pid=""
edge_metrics_url=""

stop_proxy() {
  if [[ -n "${proxy_pid}" ]]; then
    kill "${proxy_pid}" >/dev/null 2>&1 || true
    wait "${proxy_pid}" >/dev/null 2>&1 || true
    proxy_pid=""
  fi
}

destroy_machines() {
  local ids=()
  while IFS= read -r id; do
    [[ -n "${id}" ]] && ids+=("${id}")
  done < <(fly machine list --app "${app}" --json 2>/dev/null | jq -r '.[].id' 2>/dev/null || true)
  if ((${#ids[@]} > 0)); then
    fly machine destroy --force --app "${app}" "${ids[@]}" >/dev/null 2>&1 || true
    sleep 5
  fi
}

cleanup() {
  set +e
  stop_proxy
  destroy_machines
  fly apps destroy "${app}" --yes >/dev/null 2>&1
  rm -rf "${temp_dir}"
}
trap cleanup EXIT INT TERM

run_machine() {
  local machine_name=""
  local previous=""
  for argument in "$@"; do
    if [[ "${previous}" == "--name" ]]; then
      machine_name="${argument}"
      break
    fi
    previous="${argument}"
  done
  for _ in $(seq 1 5); do
    if fly machine run "$@"; then
      return 0
    fi
    if [[ -n "${machine_name}" ]]; then
      local ids=()
      while IFS= read -r id; do
        [[ -n "${id}" ]] && ids+=("${id}")
      done < <(fly machine list --app "${app}" --json 2>/dev/null | jq -r --arg name "${machine_name}" '.[] | select(.name == $name) | .id' 2>/dev/null || true)
      if ((${#ids[@]} > 0)); then
        fly machine destroy --force --app "${app}" "${ids[@]}" >/dev/null 2>&1 || true
      fi
    fi
    sleep 5
  done
  return 1
}

machine_value() {
  local name="$1"
  local field="$2"
  local deadline=$((SECONDS + 120))
  while ((SECONDS < deadline)); do
    local value
    value="$(fly machine list --app "${app}" --json | jq -r --arg name "${name}" --arg field "${field}" '.[] | select(.name == $name) | .[$field] // empty')"
    if [[ -n "${value}" ]]; then
      printf '%s\n' "${value}"
      return 0
    fi
    sleep 2
  done
  return 1
}

wait_for_drivers() {
  local machine_ids=("$@")
  local deadline=$((SECONDS + driver_wait_seconds))
  while ((SECONDS < deadline)); do
    local machines
    if ! machines="$(fly machine list --app "${app}" --json 2>/dev/null)"; then
      sleep 5
      continue
    fi
    local all_stopped=1
    for machine_id in "${machine_ids[@]}"; do
      local state
      state="$(jq -r --arg id "${machine_id}" '.[] | select(.id == $id) | .state // empty' <<<"${machines}")"
      if [[ "${state}" != "stopped" ]]; then
        all_stopped=0
        continue
      fi
      local exit_code
      exit_code="$(jq -r --arg id "${machine_id}" '[.[] | select(.id == $id) | .events[]? | select(.type == "exit")][0].request.exit_event.exit_code // empty' <<<"${machines}")"
      if [[ -n "${exit_code}" && "${exit_code}" != "0" ]]; then
        return 1
      fi
    done
    if ((all_stopped != 0)); then
      return 0
    fi
    sleep 5
  done
  return 1
}

capture_failure_diagnostics() {
  local topology="$1"
  local routes="$2"
  local attempt="$3"
  local directory="${results_dir}/${run_id}-failures/${topology}-${routes}-attempt-${attempt}"
  mkdir -p "${directory}"
  fly machine list --app "${app}" --json 2>"${directory}/machines.err" | jq '[.[] | {
    id, name, state, region, instance_id, created_at, updated_at,
    guest: .config.guest, events, host_status, cordoned
  }]' >"${directory}/machines.json" || true
  while IFS=$'\t' read -r machine_id machine_name; do
    [[ -n "${machine_id}" ]] || continue
    fly logs --app "${app}" --machine "${machine_id}" --no-tail \
      >"${directory}/${machine_name:-${machine_id}}.log" 2>&1 || true
  done < <(jq -r '.[] | [.id, .name] | @tsv' "${directory}/machines.json" 2>/dev/null || true)
  printf 'failure diagnostics: %s\n' "${directory}" >&2
}

wait_for_core() {
  stop_proxy
  fly proxy "${local_control_port}:4443" --app "${app}" --quiet >"${temp_dir}/proxy.log" 2>&1 &
  proxy_pid=$!
  local deadline=$((SECONDS + 180))
  while ((SECONDS < deadline)); do
    if curl --fail --silent --show-error \
      --cacert "${temp_dir}/control-ca.crt" \
      --resolve "${app}.fly.dev:${local_control_port}:127.0.0.1" \
      "https://${app}.fly.dev:${local_control_port}/v1/capabilities" >/dev/null; then
      stop_proxy
      return 0
    fi
    sleep 2
  done
  stop_proxy
  printf 'core did not become ready\n' >&2
  return 1
}

launch_single_node() {
  local total_routes="$1"
  local active_claim_limit=$((total_routes > 128 ? total_routes : 128))
  local claim_request_limit=$((total_routes > 1024 ? total_routes : 1024))
  run_machine "${image}" /tnld \
    --app "${app}" --name single-node --region "${region}" --vm-size "${single_size}" \
    --detach --restart no \
    --port 443:4443/tcp \
    --file-local "/etc/tnl/control.crt=${temp_dir}/control.crt" \
    --file-local "/etc/tnl/control.key=${temp_dir}/control.key" \
    --file-local "/etc/tnl/relay.json=${temp_dir}/relay.json" \
    --env TNLD_MODE=standalone \
    --env TNLD_STATE_DIR=/tmp/tnl-state \
    --env 'TNLD_METRICS_LISTEN=[::]:9090' \
    --env 'TNLD_PUBLIC_LISTEN=[::]:4443' \
    --env "TNLD_CONTROL_HOSTNAME=${app}.fly.dev" \
    --env "TNLD_ROUTE_SUFFIX=${run_id}.bench.test" \
    --env "TNLD_MAX_ACTIVE_HOSTNAME_CLAIMS=${active_claim_limit}" \
    --env "TNLD_MAX_HOSTNAME_CLAIM_REQUESTS=${claim_request_limit}" \
    --env TNLD_CONTROL_CERT_FILE=/etc/tnl/control.crt \
    --env TNLD_CONTROL_KEY_FILE=/etc/tnl/control.key \
    --env "TNLD_BOOTSTRAP_TOKEN=${bootstrap_token}" \
    --env TNLD_RELAY_MAP_FILE=/etc/tnl/relay.json \
    --env "TNLD_RELAY_PROFILE=${relay_profile}" \
    --env "TNLD_WORKER_CAPACITY=${worker_capacity}" \
    --env "TNL_NOFILE_LIMIT=${nofile_limit}" \
    --env TS_DEBUG_NEVER_DIRECT_UDP=1
}

launch_edge() {
  local total_routes="$1"
  local active_claim_limit=$((total_routes > 128 ? total_routes : 128))
  local claim_request_limit=$((total_routes > 1024 ? total_routes : 1024))
  run_machine "${image}" /tnld \
    --app "${app}" --name edge --region "${region}" --vm-size "${edge_size}" \
    --detach --restart no \
    --port 443:4443/tcp \
    --file-local "/etc/tnl/control.crt=${temp_dir}/control.crt" \
    --file-local "/etc/tnl/control.key=${temp_dir}/control.key" \
    --env TNLD_MODE=edge \
    --env TNLD_STATE_DIR=/tmp/tnl-state \
    --env 'TNLD_METRICS_LISTEN=[::]:9090' \
    --env 'TNLD_PUBLIC_LISTEN=[::]:4443' \
    --env "TNLD_CONTROL_HOSTNAME=${app}.fly.dev" \
    --env "TNLD_ROUTE_SUFFIX=${run_id}.bench.test" \
    --env "TNLD_MAX_ACTIVE_HOSTNAME_CLAIMS=${active_claim_limit}" \
    --env "TNLD_MAX_HOSTNAME_CLAIM_REQUESTS=${claim_request_limit}" \
    --env TNLD_CONTROL_CERT_FILE=/etc/tnl/control.crt \
    --env TNLD_CONTROL_KEY_FILE=/etc/tnl/control.key \
    --env "TNLD_BOOTSTRAP_TOKEN=${bootstrap_token}" \
    --env "TNLD_RELAY_PROFILE=${relay_profile}" \
    --env "TNLD_WORKER_TOKEN=${worker_token}" \
    --env "TNL_NOFILE_LIMIT=${nofile_limit}"
}

launch_workers() {
  worker_metrics=()
  for ((index = 0; index < workers; index++)); do
    local name="worker-${index}"
    run_machine "${image}" /tnld \
      --app "${app}" --name "${name}" --region "${region}" --vm-size "${worker_size}" \
      --detach --restart no \
      --file-local "/etc/tnl/control-ca.crt=${temp_dir}/control-ca.crt" \
      --file-local "/etc/tnl/relay.json=${temp_dir}/relay.json" \
      --env TNLD_MODE=worker \
      --env 'TNLD_METRICS_LISTEN=[::]:9090' \
      --env "TNLD_WORKER_URL=wss://${app}.fly.dev/internal/v1/worker" \
      --env "TNLD_WORKER_TOKEN=${worker_token}" \
      --env TNLD_RELAY_MAP_FILE=/etc/tnl/relay.json \
      --env "TNLD_WORKER_CAPACITY=${worker_capacity}" \
      --env SSL_CERT_FILE=/etc/tnl/control-ca.crt \
      --env "TNL_NOFILE_LIMIT=${nofile_limit}" \
      --env TS_DEBUG_NEVER_DIRECT_UDP=1
    local ip
    ip="$(machine_value "${name}" private_ip)"
    worker_metrics+=("http://[${ip}]:9090/metrics")
  done
}

run_tier() {
  local topology="$1"
  local total_routes="$2"
  local server_size="$3"
  shift 3
  local metrics=("$@")
  if ((drivers <= 0 || drivers > total_routes)); then
    printf 'DRIVERS must be between 1 and the tier route count\n' >&2
    return 1
  fi
  local metrics_csv
  metrics_csv="$(IFS=,; printf '%s' "${metrics[*]}")"
  local tier_results="${temp_dir}/${topology}-${total_routes}.results.jsonl"
  printf '' >"${tier_results}"
  local driver_ids=()
  local base=$((total_routes / drivers))
  local remainder=$((total_routes % drivers))
  local barrier_url=""
  printf '\nRunning %s with %s routes across %s drivers\n' "${topology}" "${total_routes}" "${drivers}"
  for ((index = 0; index < drivers; index++)); do
    local count="${base}"
    if ((index < remainder)); then
      count=$((count + 1))
    fi
    local driver_name="driver-${topology}-${total_routes}-${index}"
    local barrier_args=(
      --env "TNL_BENCH_DRIVER_INDEX=${index}"
      --env "TNL_BENCH_DRIVER_COUNT=${drivers}"
    )
    if ((drivers > 1)); then
      if ((index == 0)); then
        barrier_args+=(
          --env 'TNL_BENCH_BARRIER_LISTEN=[::]:9191'
          --env TNL_BENCH_BARRIER_URL=http://127.0.0.1:9191
        )
      else
        barrier_args+=(--env "TNL_BENCH_BARRIER_URL=${barrier_url}")
      fi
      barrier_args+=(--env "TNL_BENCH_BARRIER_TOKEN=${barrier_token}")
    fi
    if ! run_machine "${image}" /tnlbench \
      --app "${app}" --name "${driver_name}" --region "${region}" --vm-size "${driver_size}" \
      --detach --restart no \
      --file-local "/etc/tnl/control-ca.crt=${temp_dir}/control-ca.crt" \
      --file-local "/etc/tnl/relay.json=${temp_dir}/relay.json" \
      --env "TNL_BENCH_TOPOLOGY=${topology}" \
      --env "TNL_BENCH_CORE_URL=https://${app}.fly.dev" \
      --env "TNL_BENCH_BOOTSTRAP_TOKEN=${bootstrap_token}" \
      --env TNL_BENCH_CONTROL_CA_FILE=/etc/tnl/control-ca.crt \
      --env "TNL_BENCH_PUBLIC_ADDRESS=${app}.fly.dev:443" \
      --env TNL_BENCH_RELAY_MAP_FILE=/etc/tnl/relay.json \
      --env "TNL_BENCH_HOSTNAME_SUFFIX=${run_id}.bench.test" \
      --env "TNL_BENCH_METRICS_URLS=${metrics_csv}" \
      --env "TNL_BENCH_EDGE_METRICS_URL=${edge_metrics_url}" \
      --env "TNL_BENCH_ROUTES=${count}" \
      --env "TNL_BENCH_EXPECTED_ROUTES=${total_routes}" \
      "${barrier_args[@]}" \
      --env "TNL_BENCH_PARALLEL=${parallel}" \
      --env "TNL_BENCH_PAYLOAD_BYTES=${payload_bytes}" \
      --env "TNL_BENCH_TIMEOUT=${benchmark_timeout}" \
      --env "TNL_NOFILE_LIMIT=${nofile_limit}" \
      --env TS_DEBUG_NEVER_DIRECT_UDP=1; then
      return 1
    fi
    local driver_id
    if ! driver_id="$(machine_value "${driver_name}" id)"; then
      return 1
    fi
    driver_ids+=("${driver_id}")
    if ((drivers > 1 && index == 0)); then
      local barrier_ip
      if ! barrier_ip="$(machine_value "${driver_name}" private_ip)"; then
        return 1
      fi
      barrier_url="http://[${barrier_ip}]:9191"
    fi
  done

  local failed=0
  if ! wait_for_drivers "${driver_ids[@]}"; then
    failed=1
  fi

  for index in "${!driver_ids[@]}"; do
    local log_file="${temp_dir}/${topology}-${total_routes}-${index}.log"
    local result=""
    for _ in $(seq 1 15); do
      if fly logs --app "${app}" --machine "${driver_ids[index]}" --json --no-tail >"${log_file}.json" 2>/dev/null; then
        jq -r '.message // .msg // empty' "${log_file}.json" >"${log_file}"
        result="$(jq -Rrc 'fromjson? | select(.schema_version == 1)' "${log_file}")"
        [[ -n "${result}" ]] && break
      fi
      sleep 2
    done
    if [[ -f "${log_file}.json" ]]; then
      jq -r '.message // .msg // empty' "${log_file}.json" | tee "${log_file}"
    fi
    if [[ -z "${result}" ]]; then
      printf 'driver %s produced no result JSON\n' "${index}" >&2
      failed=1
      continue
    fi
    if ! jq -c \
      --arg run_id "${run_id}" \
      --arg region "${region}" \
      --arg server_size "${server_size}" \
      --arg driver_size "${driver_size}" \
      --argjson total_routes "${total_routes}" \
      --argjson driver_index "${index}" \
      --argjson driver_count "${drivers}" \
      '. + {
        run_id: $run_id, region: $region, server_size: $server_size,
        driver_size: $driver_size, forced_derp: true, total_routes: $total_routes,
        driver_index: $driver_index, driver_count: $driver_count
      }' <<<"${result}" >>"${tier_results}"; then
      failed=1
    fi
  done
  if ((failed != 0)); then
    return 1
  fi
  if ! fly machine destroy --force --app "${app}" "${driver_ids[@]}" >/dev/null; then
    return 1
  fi
  tee -a "${results_file}" <"${tier_results}"
}

mkdir -p "${results_dir}"
bootstrap_token="$(go run ./cmd/tnl token bootstrap)"
worker_token="$(go run ./cmd/tnl token worker)"

curl --fail --silent --show-error https://tailcat.dev/derpmap.json >"${temp_dir}/relay.json"
relay_profile="$(jq -r --arg region "${derp_region}" '.Regions[$region].RegionCode // empty' "${temp_dir}/relay.json")"
if [[ -z "${relay_profile}" ]]; then
  printf 'DERP region %s is absent from the relay map\n' "${derp_region}" >&2
  exit 2
fi

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout "${temp_dir}/control-ca.key" -out "${temp_dir}/control-ca.crt" \
  -days 1 -subj '/CN=tnl benchmark control CA' >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "${temp_dir}/control.key" -out "${temp_dir}/control.csr" \
  -subj "/CN=${app}.fly.dev" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s.fly.dev\nextendedKeyUsage=serverAuth\n' "${app}" >"${temp_dir}/control.ext"
openssl x509 -req -sha256 -in "${temp_dir}/control.csr" \
  -CA "${temp_dir}/control-ca.crt" -CAkey "${temp_dir}/control-ca.key" -CAcreateserial \
  -out "${temp_dir}/control.crt" -days 1 -extfile "${temp_dir}/control.ext" >/dev/null 2>&1

fly apps create "${app}" --org "${org}" --yes
fly ips allocate-v6 --app "${app}" >/dev/null
fly deploy . --app "${app}" --config fly.bench.toml --build-only --push \
  --image-label "${run_id}" --no-public-ips

IFS=',' read -r -a mode_list <<<"${modes}"
for mode in "${mode_list[@]}"; do
  mode="${mode//[[:space:]]/}"
  case "${mode}" in
    single-node)
      IFS=',' read -r -a route_list <<<"${single_routes}"
      for routes in "${route_list[@]}"; do
        routes="${routes//[[:space:]]/}"
        completed=0
        for ((attempt = 1; attempt <= attempts; attempt++)); do
          destroy_machines
          launch_single_node "${routes}"
          wait_for_core
          single_ip="$(machine_value single-node private_ip)"
          edge_metrics_url="http://[${single_ip}]:9090/metrics"
          if run_tier single-node "${routes}" "${single_size}" "http://[${single_ip}]:9090/metrics"; then
            completed=1
            break
          fi
          capture_failure_diagnostics single-node "${routes}" "${attempt}"
          if ((attempt < attempts)); then
            printf 'retrying single-node %s routes after failed attempt %s\n' "${routes}" "${attempt}" >&2
          fi
        done
        if ((completed == 0)); then
          exit 1
        fi
      done
      ;;
    ha)
      IFS=',' read -r -a route_list <<<"${ha_routes}"
      for routes in "${route_list[@]}"; do
        routes="${routes//[[:space:]]/}"
        completed=0
        for ((attempt = 1; attempt <= attempts; attempt++)); do
          destroy_machines
          launch_edge "${routes}"
          wait_for_core
          edge_ip="$(machine_value edge private_ip)"
          edge_metrics_url="http://[${edge_ip}]:9090/metrics"
          launch_workers
          sleep 5
          if run_tier ha "${routes}" "${edge_size}+${workers}x${worker_size}" "${worker_metrics[@]}"; then
            completed=1
            break
          fi
          capture_failure_diagnostics ha "${routes}" "${attempt}"
          if ((attempt < attempts)); then
            printf 'retrying ha %s routes after failed attempt %s\n' "${routes}" "${attempt}" >&2
          fi
        done
        if ((completed == 0)); then
          exit 1
        fi
      done
      ;;
    *)
      printf 'invalid mode: %s\n' "${mode}" >&2
      exit 2
      ;;
  esac
done

destroy_machines
printf '\nResults: %s\n' "${results_file}"
