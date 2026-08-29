#!/usr/bin/env bash

set -euo pipefail

org="${ORG:-tnl}"
region="${REGION:-sjc}"
size="${AGENT_SIZE:-performance-8x}"
routes="${ROUTES:-1,10,100,250,500,1000,1500}"
modes="${MODES:-direct,derp}"
parallel="${PARALLEL:-8}"
local_port="${LOCAL_PORT:-18080}"
agent_gomemlimit="${AGENT_GOMEMLIMIT:-}"
run_id="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)"
app="tnl-tailbench-${run_id}"
image="registry.fly.io/${app}:${run_id}"
token="$(openssl rand -hex 32)"
proxy_pid=""
machine_id=""

cleanup_machine() {
  if [[ -n "${proxy_pid}" ]]; then
    kill "${proxy_pid}" 2>/dev/null || true
    wait "${proxy_pid}" 2>/dev/null || true
    proxy_pid=""
  fi
  if [[ -n "${machine_id}" ]]; then
    fly machine destroy --force --app "${app}" "${machine_id}" >/dev/null 2>&1 || true
    machine_id=""
  fi
}

cleanup() {
  cleanup_machine
  fly apps destroy "${app}" --yes >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

fly apps create "${app}" --org "${org}" --yes
fly deploy . --app "${app}" --config fly.tailbench.toml --build-only --push --image-label "${run_id}" --no-public-ips

status=0
IFS=',' read -r -a mode_list <<<"${modes}"
for mode in "${mode_list[@]}"; do
  mode="${mode//[[:space:]]/}"
  if [[ "${mode}" != "direct" && "${mode}" != "derp" ]]; then
    printf 'invalid mode: %s\n' "${mode}" >&2
    exit 2
  fi

  printf '\nRunning %s ramp on %s (%s in %s)\n' "${mode}" "${app}" "${size}" "${region}"
  machine_args=(
    "${image}"
    --app "${app}"
    --name "agent-${mode}"
    --region "${region}"
    --vm-size "${size}"
    --detach
    --restart no
    --env "TNL_TAILBENCH_TOKEN=${token}"
  )
  if [[ -n "${agent_gomemlimit}" ]]; then
    machine_args+=(--env "GOMEMLIMIT=${agent_gomemlimit}")
  fi
  if [[ "${mode}" == "derp" ]]; then
    machine_args+=(--env TS_DEBUG_NEVER_DIRECT_UDP=1)
  fi
  launched=0
  for _ in $(seq 1 5); do
    if fly machine run "${machine_args[@]}"; then
      launched=1
      break
    fi
    sleep 5
  done
  if [[ "${launched}" != "1" ]]; then
    printf 'agent Machine did not launch\n' >&2
    status=1
    continue
  fi
  machine_id="$(fly machine list --quiet --app "${app}")"

  fly proxy "${local_port}:8080" --app "${app}" --quiet >"/tmp/${app}-proxy.log" 2>&1 &
  proxy_pid=$!
  ready=0
  for _ in $(seq 1 60); do
    if curl --fail --silent "http://127.0.0.1:${local_port}/healthz" >/dev/null; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "${ready}" != "1" ]]; then
    fly logs --app "${app}" --machine "${machine_id}" --no-tail || true
    printf 'agent did not become ready\n' >&2
    status=1
    cleanup_machine
    continue
  fi

  benchmark_env=(
    GOFLAGS=-tags=ts_omit_ssh
    TNL_TEST_TAILCAT_FLY=1
    "TNL_TEST_TAILCAT_AGENT_URL=http://127.0.0.1:${local_port}"
    "TNL_TAILBENCH_TOKEN=${token}"
    "TNL_TEST_TAILCAT_ROUTES=${routes}"
    "TNL_TEST_TAILCAT_PATH=${mode}"
    "TNL_TEST_TAILCAT_PARALLEL=${parallel}"
    TNL_TEST_TAILCAT_DERP_REGION=302
  )
  if [[ "${mode}" == "derp" ]]; then
    benchmark_env+=(TS_DEBUG_NEVER_DIRECT_UDP=1)
  fi

  if ! env "${benchmark_env[@]}" go test -v ./internal/tailtransport -run='^$' -bench='^BenchmarkTailcatFly$' -benchtime=1x -count=1 -timeout=90m; then
    status=1
    fly logs --app "${app}" --machine "${machine_id}" --no-tail || true
    cleanup_machine
    break
  fi
  cleanup_machine
done

exit "${status}"
