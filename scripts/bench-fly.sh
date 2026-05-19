#!/usr/bin/env bash

set -euo pipefail

org="${ORG:-tnl}"
region="${REGION:-sjc}"
bench_suite="${BENCH_SUITE:?set BENCH_SUITE to a planned suite}"
bench_approved="${BENCH_APPROVED:-0}"
workers=0
drivers=0
parallel="${PARALLEL:-8}"
payload_bytes="${PAYLOAD_BYTES:-65536}"
driver_wait_seconds="${DRIVER_WAIT_SECONDS:-480}"
benchmark_timeout=""
worker_capacity=0
nofile_limit="${NOFILE_LIMIT:-65536}"
edge_size=""
worker_size=""
driver_size=""
local_control_port="${LOCAL_CONTROL_PORT:-18443}"
derp_region="${DERP_REGION:-302}"
domain="${DOMAIN:?set DOMAIN to the benchmark base domain}"
dns_hook="${DNS_HOOK:?set DNS_HOOK to an executable that updates benchmark DNS}"
acme_directory_url="${ACME_DIRECTORY_URL:?set ACME_DIRECTORY_URL to the benchmark ACME directory}"
acme_email="${ACME_EMAIL:?set ACME_EMAIL to the benchmark ACME account contact}"
control_ca_file="${CONTROL_CA_FILE:?set CONTROL_CA_FILE to the ACME issuer root bundle}"
server_hostname="tnl.${domain}"
hostname_suffix="${domain}"
run_id="$(date -u +%m%d%H%M)-$(openssl rand -hex 2)"
barrier_token="$(openssl rand -hex 32)"
app="tnl-bench-${run_id}"
image="registry.fly.io/${app}:${run_id}"
temp_dir="$(mktemp -d)"
results_dir="${RESULTS_DIR:-bench-results}"
run_dir="${results_dir}/${run_id}"
results_file="${run_dir}/results.jsonl"
proxy_pid=""
edge_metrics_url=""
login_token=""
current_cell_id=""
current_repetition=1

if [[ ! -x "${dns_hook}" ]]; then
  printf 'DNS_HOOK must be executable: %s\n' "${dns_hook}" >&2
  exit 2
fi

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
  local directory="${run_dir}/failures/${topology}-${routes}-attempt-${attempt}"
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

wait_for_server() {
  stop_proxy
  fly proxy "${local_control_port}:4443" --app "${app}" --quiet >"${temp_dir}/proxy.log" 2>&1 &
  proxy_pid=$!
  local deadline=$((SECONDS + 180))
  while ((SECONDS < deadline)); do
    if curl --fail --silent --show-error \
      --cacert "${temp_dir}/control-ca.crt" \
      --resolve "${server_hostname}:${local_control_port}:127.0.0.1" \
      "https://${server_hostname}:${local_control_port}/v1/ready" >/dev/null; then
      stop_proxy
      return 0
    fi
    sleep 2
  done
  stop_proxy
  printf 'server did not become ready\n' >&2
  return 1
}

read_login_token() {
  local machine_name="$1"
  local machine_id
  machine_id="$(machine_value "${machine_name}" id)"
  local deadline=$((SECONDS + 120))
  while ((SECONDS < deadline)); do
    local output
    output="$(fly ssh console --app "${app}" --machine "${machine_id}" \
      --command '/usr/local/bin/tnl admin server login-token --state-dir /tmp/tnl-state' 2>/dev/null || true)"
    while IFS= read -r line; do
      line="${line//$'\r'/}"
      if [[ "${line}" =~ ^tnl_login_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
        printf '%s\n' "${line}"
        return 0
      fi
    done <<<"${output}"
    sleep 2
  done
  printf 'could not retrieve login token from %s\n' "${machine_name}" >&2
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
    --file-local "/etc/tnl/control-ca.crt=${temp_dir}/control-ca.crt" \
    --file-local "/etc/tnl/relay.json=${temp_dir}/relay.json" \
    --env TNLD_MODE=standalone \
    --env TNLD_STATE_DIR=/tmp/tnl-state \
    --env 'TNLD_METRICS_LISTEN=[::]:9090' \
    --env 'TNLD_PUBLIC_LISTEN=[::]:4443' \
    --env "TNLD_DOMAIN=${domain}" \
    --env "TNLD_MAX_ACTIVE_HOSTNAMES=${active_claim_limit}" \
    --env "TNLD_MAX_HOSTNAME_REQUESTS=${claim_request_limit}" \
    --env "TNLD_ACME_DIRECTORY_URL=${acme_directory_url}" \
    --env "TNLD_ACME_EMAIL=${acme_email}" \
    --env TNLD_ACME_ACCEPT_TERMS=true \
    --env TNLD_RELAY_MAP_FILE=/etc/tnl/relay.json \
    --env "TNLD_RELAY_REGION=${relay_region}" \
    --env "TNLD_WORKER_CAPACITY=${worker_capacity}" \
    --env SSL_CERT_FILE=/etc/tnl/control-ca.crt \
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
    --file-local "/etc/tnl/control-ca.crt=${temp_dir}/control-ca.crt" \
    --file-local "/etc/tnl/relay.json=${temp_dir}/relay.json" \
    --env TNLD_MODE=edge \
    --env TNLD_STATE_DIR=/tmp/tnl-state \
    --env 'TNLD_METRICS_LISTEN=[::]:9090' \
    --env 'TNLD_PUBLIC_LISTEN=[::]:4443' \
    --env "TNLD_DOMAIN=${domain}" \
    --env "TNLD_MAX_ACTIVE_HOSTNAMES=${active_claim_limit}" \
    --env "TNLD_MAX_HOSTNAME_REQUESTS=${claim_request_limit}" \
    --env "TNLD_ACME_DIRECTORY_URL=${acme_directory_url}" \
    --env "TNLD_ACME_EMAIL=${acme_email}" \
    --env TNLD_ACME_ACCEPT_TERMS=true \
    --env TNLD_RELAY_MAP_FILE=/etc/tnl/relay.json \
    --env "TNLD_RELAY_REGION=${relay_region}" \
    --env "TNLD_WORKER_TOKEN=${worker_token}" \
    --env SSL_CERT_FILE=/etc/tnl/control-ca.crt \
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
      --env TNLD_MODE=worker \
      --env 'TNLD_METRICS_LISTEN=[::]:9090' \
      --env "TNLD_WORKER_URL=wss://${server_hostname}/internal/v1/worker" \
      --env "TNLD_WORKER_TOKEN=${worker_token}" \
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
    if ! run_machine "${image}" /tnlbench driver \
      --app "${app}" --name "${driver_name}" --region "${region}" --vm-size "${driver_size}" \
      --detach --restart no \
      --file-local "/etc/tnl/control-ca.crt=${temp_dir}/control-ca.crt" \
      --file-local "/etc/tnl/relay.json=${temp_dir}/relay.json" \
      --env "TNL_BENCH_TOPOLOGY=${topology}" \
      --env "TNL_BENCH_CELL_ID=${current_cell_id}" \
      --env "TNL_BENCH_SUITE=${bench_suite}" \
      --env TNL_BENCH_WORKLOAD=agent-worktrees-assumed-v1 \
      --env "TNL_BENCH_REPETITION=${current_repetition}" \
      --env "TNL_BENCH_SERVER=https://${server_hostname}" \
      --env "TNL_BENCH_LOGIN_TOKEN=${login_token}" \
      --env TNL_BENCH_CONTROL_CA_FILE=/etc/tnl/control-ca.crt \
      --env "TNL_BENCH_PUBLIC_ADDRESS=${app}.fly.dev:443" \
      --env "TNL_BENCH_HOSTNAME_SUFFIX=${hostname_suffix}" \
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
        result="$(jq -Rrc 'fromjson? | select(.schema_version == 2)' "${log_file}")"
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
  tee -a "${results_file}" <"${tier_results}"
  if ! fly machine destroy --force --app "${app}" "${driver_ids[@]}" >/dev/null; then
    failed=1
  fi
  ((failed == 0))
}

if [[ "${bench_approved}" != "1" ]]; then
  printf 'BENCH_APPROVED=1 is required before creating Fly or DNS resources\n' >&2
  exit 2
fi

plan_json="$(go run ./cmd/tnlbench plan --suite "${bench_suite}" --format json)"
if [[ "$(jq -r '.read_only' <<<"${plan_json}")" != "true" ]]; then
  printf 'benchmark plan is not marked read-only\n' >&2
  exit 2
fi
if [[ "$(jq -r '.transport' <<<"${plan_json}")" != "forced-derp" ]]; then
  printf 'capacity runner currently requires forced-derp transport\n' >&2
  exit 2
fi
region="$(jq -r '.region' <<<"${plan_json}")"
edge_size="$(jq -r '.machines.edge.size' <<<"${plan_json}")"
worker_size="$(jq -r '.machines.worker.size' <<<"${plan_json}")"
driver_size="$(jq -r '.machines.driver.size' <<<"${plan_json}")"
worker_capacity="$(jq -r '.machines.worker.capacity' <<<"${plan_json}")"

mkdir -p "${run_dir}/failures"
: >"${results_file}"
git_sha="$(git rev-parse HEAD)"
git_dirty=false
if [[ -n "$(git status --porcelain)" ]]; then
  git_dirty=true
fi
jq -n \
  --arg run_id "${run_id}" \
  --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg git_sha "${git_sha}" \
  --arg image "${image}" \
  --argjson git_dirty "${git_dirty}" \
  --argjson plan "${plan_json}" \
  '{
    manifest_schema_version: 1,
    run_id: $run_id,
    created_at: $created_at,
    git_sha: $git_sha,
    git_dirty: $git_dirty,
    image: $image,
    plan: $plan
  }' >"${run_dir}/manifest.json"

printf '%s\n' "${plan_json}" | jq '{
  suite, region, transport, cells, expected_result_rows,
  expected_duration_seconds, maximum_duration_seconds,
  expected_spend, maximum_spend
}'

worker_token="$(go run ./cmd/tnl admin server token worker)"
cp "${control_ca_file}" "${temp_dir}/control-ca.crt"

curl --fail --silent --show-error https://tailcat.dev/derpmap.json >"${temp_dir}/relay.json"
relay_region="$(jq -r --arg region "${derp_region}" '.Regions[$region].RegionCode // empty' "${temp_dir}/relay.json")"
if [[ -z "${relay_region}" ]]; then
  printf 'DERP region %s is absent from the relay map\n' "${derp_region}" >&2
  exit 2
fi

fly apps create "${app}" --org "${org}" --yes
fly ips allocate-v6 --app "${app}" >/dev/null
"${dns_hook}" "${domain}" "${app}.fly.dev"
fly deploy . --app "${app}" --config fly.bench.toml --build-only --push \
  --image-label "${run_id}" --no-public-ips

while IFS=$'\t' read -r current_cell_id workers routes current_repetition drivers maximum_seconds; do
  destroy_machines
  benchmark_timeout="${maximum_seconds}s"
  driver_wait_seconds=$((maximum_seconds + 180))
  launch_edge "${routes}"
  wait_for_server
  login_token="$(read_login_token edge)"
  edge_ip="$(machine_value edge private_ip)"
  edge_metrics_url="http://[${edge_ip}]:9090/metrics"
  launch_workers
  sleep 5
  if ! run_tier ha "${routes}" "${edge_size}+${workers}x${worker_size}" "${worker_metrics[@]}"; then
    capture_failure_diagnostics ha "${routes}" 1
    BENCH_RUN="${run_dir}" go run ./cmd/tnlbench report || true
    printf 'benchmark cell failed; stopping suite without retry: %s\n' "${current_cell_id}" >&2
    exit 1
  fi
done < <(jq -r '.cells[] | [.id, .workers, .routes, .repetition, .drivers, .maximum_duration_seconds] | @tsv' <<<"${plan_json}")

destroy_machines
actual_rows="$(jq -s 'length' "${results_file}")"
expected_rows="$(jq -r '.expected_result_rows' <<<"${plan_json}")"
if [[ "${actual_rows}" != "${expected_rows}" ]]; then
  printf 'result row mismatch: got %s, want %s\n' "${actual_rows}" "${expected_rows}" >&2
  exit 1
fi
BENCH_RUN="${run_dir}" go run ./cmd/tnlbench report
printf '\nResults: %s\n' "${run_dir}"
