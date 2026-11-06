import type { Fixture } from "./run.ts";
import type { SocketHost } from "./host.ts";
import { parseTCPAddress } from "./host.ts";

// private version-1 input is owned by fixture/config.go, not the SDK.
export interface LocalFixture {
  control_url: string;
  control_dial_address: string;
  control_root_pem: string;
  relay_root_pem: string;
  service_root_pem: string;
  team_id: string;
  project: string;
  source_fingerprint: string;
  workload_policy: string;
  services: { db: string };
  relays: Array<{ relay_address: string; dial_address: string }>;
  assertion_url: string;
  fault_url: string;
  fixture_api_token: string;
  native_connector_address: string;
  postgres: {
    user: string;
    password: string;
    database: string;
    direct_url: string;
    tls_server_name: string;
    target_tls: false;
    write_table: "public.connector_wasm_writes";
    write_id_column: "id";
  };
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("invalid private connector fixture object");
  }
  return value as Record<string, unknown>;
}

function text(value: Record<string, unknown>, key: string): string {
  const result = value[key];
  if (typeof result !== "string" || result.length === 0) {
    throw new Error(`private connector fixture requires ${key}`);
  }
  return result;
}

function loopbackURL(value: string): string {
  const url = new URL(value);
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.username ||
    url.password
  ) {
    throw new Error("fixture API must use a loopback HTTP URL");
  }
  return value;
}

function loopbackAddress(value: string): string {
  const { hostname } = parseTCPAddress(value);
  if (!["127.0.0.1", "localhost", "::1"].includes(hostname)) {
    throw new Error("fixture TCP destination must be loopback");
  }
  return value;
}

export function parseLocalFixture(value: unknown): LocalFixture {
  const input = record(value);
  if (input.version !== 1 || input.outer_transport !== "tls-tcp") {
    throw new Error("expected version-1 fixture with outer TLS/TCP transport");
  }
  const controlURL = new URL(text(input, "control_url"));
  if (
    controlURL.protocol !== "https:" ||
    controlURL.username ||
    controlURL.password ||
    controlURL.origin !== controlURL.href.replace(/\/$/, "")
  ) {
    throw new Error("fixture control_url must be an HTTPS origin");
  }
  const services = record(input.services);
  if (!Array.isArray(input.relays) || input.relays.length !== 2) {
    throw new Error("fixture requires two relay addresses");
  }
  const relays = input.relays.map((value: unknown) => {
    const relay = record(value);
    const address = text(relay, "relay_address");
    parseTCPAddress(address);
    return { relay_address: address, dial_address: loopbackAddress(text(relay, "dial_address")) };
  });
  const postgres = record(input.postgres);
  if (
    Object.keys(postgres).some(
      (key) =>
        ![
          "user",
          "password",
          "database",
          "direct_url",
          "tls_server_name",
          "target_tls",
          "write_table",
          "write_id_column",
        ].includes(key),
    )
  ) {
    throw new Error("unsupported PostgreSQL fixture setting");
  }
  if (
    postgres.target_tls !== false ||
    postgres.write_table !== "public.connector_wasm_writes" ||
    postgres.write_id_column !== "id"
  ) {
    throw new Error("fixture requires its fixed PostgreSQL write table and plaintext target leg");
  }
  const directURL = new URL(text(postgres, "direct_url"));
  if (
    !["postgres:", "postgresql:"].includes(directURL.protocol) ||
    !["127.0.0.1", "localhost", "[::1]"].includes(directURL.hostname)
  ) {
    throw new Error("fixture PostgreSQL observer must use a loopback URL");
  }
  return {
    control_url: controlURL.origin,
    control_dial_address: loopbackAddress(text(input, "control_dial_address")),
    control_root_pem: text(input, "control_root_pem"),
    relay_root_pem: text(input, "relay_root_pem"),
    service_root_pem: text(input, "service_root_pem"),
    team_id: text(input, "team_id"),
    project: text(input, "project"),
    source_fingerprint: text(input, "source_fingerprint"),
    workload_policy: text(input, "workload_policy"),
    services: { db: text(services, "db") },
    relays,
    assertion_url: loopbackURL(text(input, "assertion_url")),
    fault_url: loopbackURL(text(input, "fault_url")),
    fixture_api_token: text(input, "fixture_api_token"),
    native_connector_address: loopbackAddress(text(input, "native_connector_address")),
    postgres: {
      user: text(postgres, "user"),
      password: text(postgres, "password"),
      database: text(postgres, "database"),
      direct_url: directURL.href,
      tls_server_name: text(postgres, "tls_server_name"),
      target_tls: false,
      write_table: "public.connector_wasm_writes",
      write_id_column: "id",
    },
  };
}

export function mapFixtureHost(host: SocketHost, fixture: LocalFixture): SocketHost {
  const control = new URL(fixture.control_url);
  const controlAddress = `${control.hostname}:${control.port || "443"}`;
  const destinations = new Map([
    [controlAddress, fixture.control_dial_address],
    ...fixture.relays.map((relay) => [relay.relay_address, relay.dial_address] as const),
  ]);
  return {
    dialTCP(address, signal) {
      const destination = destinations.get(address);
      if (!destination) return Promise.reject(new Error("unexpected fixture TCP destination"));
      return host.dialTCP(destination, signal);
    },
    close: () => host.close(),
  };
}

export async function prepareFixture(
  fixture: LocalFixture,
  execution: string,
  signal: AbortSignal,
  queries = 10,
): Promise<Fixture> {
  const url = new URL(fixture.assertion_url);
  url.searchParams.set("execution", execution);
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${fixture.fixture_api_token}` },
    signal,
    redirect: "manual",
  });
  if (!response.ok) throw new Error("fixture assertion request failed");
  const assertion = text(record(await response.json()), "token");
  return {
    options: {
      control_url: fixture.control_url,
      team_id: fixture.team_id,
      project_key: fixture.project,
      source_fingerprint: fixture.source_fingerprint,
      workload: fixture.workload_policy,
      assertion,
      service_id: fixture.services.db,
      ca_pem: fixture.control_root_pem,
      relay_ca_pem: fixture.relay_root_pem,
      service_ca_pem: fixture.service_root_pem,
    },
    postgres: {
      user: fixture.postgres.user,
      password: fixture.postgres.password,
      database: fixture.postgres.database,
    },
    queries,
    local: fixture,
  };
}

export async function setRelayBlocked(
  fixture: LocalFixture,
  relayAddress: string,
  blocked: boolean,
  signal: AbortSignal,
): Promise<number> {
  if (!fixture.relays.some((relay) => relay.relay_address === relayAddress)) {
    throw new Error("selected relay is not part of this fixture");
  }
  const response = await fetch(fixture.fault_url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${fixture.fixture_api_token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ relay_address: relayAddress, blocked }),
    redirect: "manual",
    signal,
  });
  if (!response.ok) throw new Error("fixture relay fault request failed");
  const result = record(await response.json());
  const closed = result.closed_connections;
  if (
    typeof closed !== "number" ||
    !Number.isSafeInteger(closed) ||
    closed < 0 ||
    (blocked && closed === 0)
  ) {
    throw new Error("fixture fault did not close an actual outer carrier");
  }
  return closed;
}
