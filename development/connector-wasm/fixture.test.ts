import { describe, expect, it, vi } from "vitest";
import { mapFixtureHost, parseLocalFixture, prepareFixture, setRelayBlocked } from "./fixture.ts";
import { PG_TLS_COMPATIBILITY } from "./run.ts";
import { nativePostgresClient, observerPostgresClient } from "./postgres.ts";

import { fixtureInput as input } from "./test-fixture.ts";

describe("private version-1 fixture boundary (not PostgreSQL integration)", () => {
  it("accepts the Go fixture schema without confusing visitor and target TLS", () => {
    const fixture = parseLocalFixture(input);
    expect(fixture.postgres.target_tls).toBe(false);
    expect(fixture.services.db).toBe("service");
    expect(fixture.postgres.tls_server_name).toBe("service.fixture.invalid");
    expect(PG_TLS_COMPATIBILITY).toEqual({
      tlsOwner: "go",
      pgSsl: false,
      scramChannelBinding: false,
      peerCertificateApi: false,
    });
  });

  it("verifies native visitor TLS while keeping only the direct observer plaintext", () => {
    const fixture = parseLocalFixture(input);
    const native = nativePostgresClient(fixture);
    const observer = observerPostgresClient(fixture);
    expect(native.ssl).toMatchObject({
      ca: fixture.service_root_pem,
      servername: fixture.postgres.tls_server_name,
      expectedServerHostname: fixture.postgres.tls_server_name,
      rejectUnauthorized: true,
    });
    expect(observer.ssl).toBe(false);
    expect(native.host).toBe("127.0.0.1");
    expect(observer.host).toBe("127.0.0.1");
    expect(() =>
      parseLocalFixture({ ...input, postgres: { ...input.postgres, tls_server_name: "" } }),
    ).toThrow("requires tls_server_name");
  });

  it("authenticates actual carrier faults and rejects zero closed connections", async () => {
    const fetcher = vi.fn(async (_url: string, _init: RequestInit) =>
      Response.json({ closed_connections: 2 }),
    );
    vi.stubGlobal("fetch", fetcher);
    const fixture = parseLocalFixture(input);
    const relay = fixture.relays[0]?.relay_address;
    if (!relay) throw new Error("missing test relay");
    const signal = new AbortController().signal;
    await expect(setRelayBlocked(fixture, relay, true, signal)).resolves.toBe(2);
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({
      headers: { Authorization: "Bearer private-api-token", "Content-Type": "application/json" },
      body: JSON.stringify({ relay_address: relay, blocked: true }),
      signal,
      redirect: "manual",
    });
    fetcher.mockImplementation(async () => Response.json({ closed_connections: 0 }));
    await expect(setRelayBlocked(fixture, relay, true, signal)).rejects.toThrow(
      "did not close an actual outer carrier",
    );
    await expect(setRelayBlocked(fixture, relay, false, signal)).resolves.toBe(0);
  });

  it("cannot override the custom stream, go TLS, or channel binding policy", () => {
    for (const setting of [
      { ssl: false },
      { ssl: { rejectUnauthorized: false } },
      { stream: {} },
      { connectionString: "private" },
      { enableChannelBinding: true },
    ]) {
      expect(() =>
        parseLocalFixture({ ...input, postgres: { ...input.postgres, ...setting } }),
      ).toThrow("unsupported PostgreSQL fixture setting");
    }
  });

  it("maps only canonical fixture destinations to loopback while keeping original TLS identities in Go", async () => {
    const dialTCP = vi.fn(async () => ({
      read: async () => null,
      write: async () => {},
      close: async () => {},
    }));
    const close = vi.fn(async () => {});
    const host = mapFixtureHost({ dialTCP, close }, parseLocalFixture(input));
    await host.dialTCP("control.fixture.invalid:443");
    await host.dialTCP("relay-a.fixture.invalid:443");
    expect(dialTCP.mock.calls).toEqual([
      ["127.0.0.1:10001", undefined],
      ["127.0.0.1:10002", undefined],
    ]);
    await expect(host.dialTCP("outside.invalid:443")).rejects.toThrow(
      "unexpected fixture TCP destination",
    );
    await host.close();
    expect(close).toHaveBeenCalledOnce();
  });

  it("fetches an actual issuer assertion with a stable execution label and exact Go option names", async () => {
    const fetcher = vi.fn(async (_url: URL, _init: RequestInit) =>
      Response.json({ token: "actual-signed-token", expires_at: "2026-11-06T17:00:00Z" }),
    );
    vi.stubGlobal("fetch", fetcher);
    const signal = new AbortController().signal;
    const prepared = await prepareFixture(parseLocalFixture(input), "wasm-node-execution", signal);
    expect(fetcher).toHaveBeenCalledOnce();
    expect(prepared.options).toEqual({
      control_url: input.control_url,
      team_id: "team",
      project_key: "project",
      source_fingerprint: "source",
      workload: "workload",
      assertion: "actual-signed-token",
      service_id: "service",
      ca_pem: "control root",
      relay_ca_pem: "relay root",
      service_ca_pem: "service root",
    });
    expect(fetcher.mock.calls[0]?.[0]).toEqual(
      new URL("http://127.0.0.1:10004/assertion?execution=wasm-node-execution"),
    );
  });

  it("rejects nonlocal dials and fixture API URLs", () => {
    expect(() =>
      parseLocalFixture({ ...input, control_dial_address: "outside.invalid:443" }),
    ).toThrow("loopback");
    expect(() =>
      parseLocalFixture({ ...input, assertion_url: "https://outside.invalid/assertion" }),
    ).toThrow("loopback");
    expect(() => parseLocalFixture({ ...input, version: 2 })).toThrow("version-1");
  });

  it("rejects redirects without forwarding fixture credentials", async () => {
    const fetcher = vi.fn(
      async (_url: URL | string, _init: RequestInit) =>
        new Response(null, { status: 302, headers: { Location: "https://outside.invalid" } }),
    );
    vi.stubGlobal("fetch", fetcher);
    const local = parseLocalFixture(input);
    const signal = new AbortController().signal;
    await expect(prepareFixture(local, "execution", signal)).rejects.toThrow(
      "fixture assertion request failed",
    );
    await expect(
      setRelayBlocked(local, local.relays[0]?.relay_address ?? "", true, signal),
    ).rejects.toThrow();
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const [, options] of fetcher.mock.calls) expect(options.redirect).toBe("manual");
  });
});
