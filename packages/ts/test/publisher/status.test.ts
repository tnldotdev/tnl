import { inspect } from "node:util";
import { describe, expect, test } from "vitest";
import { parseStatus } from "../../src/internal/publisher/status.js";

const registrationID = `reg_${"a".repeat(32)}`;
const target = "http://127.0.0.1:3000";
const service = {
  service: "web",
  directory: ".",
  registration_id: registrationID,
  target,
  registered: true,
  routable: true,
  ready: true,
  public_url: "https://web.example",
  run_number: 2,
  readiness: { path: "/ready" },
  observation: {
    registration_id: registrationID,
    run_number: 2,
    checked_at: "2026-11-03T00:00:00Z",
    ready: true,
    status: 200,
    readiness: { path: "/ready" },
  },
};
const snapshot = {
  schema_version: 1,
  project: "/project",
  cursor: "cursor",
  observed_at: "2026-11-03T00:00:00Z",
  services: [service],
};

describe("publisher status replies", () => {
  test("retains the exact public HTTP port", () => {
    const publicURL = "https://web.example:25443";
    expect(
      parseStatus(
        { ...snapshot, services: [{ ...service, public_url: publicURL }] },
        "web",
        registrationID,
        target,
      )?.publicURL,
    ).toBe(publicURL);
  });

  test("reports readiness only for the registered target and observed publish run", () => {
    expect(parseStatus(snapshot, "web", registrationID, target)).toEqual({
      registered: true,
      routable: true,
      ready: true,
      publicURL: service.public_url,
      publishRunNumber: 2,
    });
    expect(parseStatus(snapshot, "web", registrationID, "http://127.0.0.1:4000")).toBeUndefined();
    expect(
      parseStatus({ ...snapshot, services: [] }, "web", registrationID, target),
    ).toBeUndefined();
  });

  test.each([
    { ...service, observation: undefined },
    { ...service, observation: { ...service.observation, ready: false } },
    { ...service, observation: { ...service.observation, run_number: 1 } },
    {
      ...service,
      observation: { ...service.observation, registration_id: `reg_${"b".repeat(32)}` },
    },
    { ...service, registered: false },
    { ...service, public_url: "https://web.example/path" },
    { ...service, public_url: "https://web.example:0" },
    { ...service, public_url: "https://web.example:65536" },
    { ...service, public_url: "https://user@web.example:25443" },
    { ...service, service_protocol: "tcp" },
  ])("rejects stale readiness and malformed service facts %#", (item) => {
    expect(() =>
      parseStatus({ ...snapshot, services: [item] }, "web", registrationID, target),
    ).toThrow(expect.objectContaining({ code: "sdk.response_invalid" }));
  });

  test("rejects extra capabilities without exposing schema input in errors", () => {
    const secret = "private-capability-never-display";
    let failure: unknown;
    try {
      parseStatus({ ...snapshot, [secret]: secret }, "web", registrationID, target);
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({ code: "sdk.response_invalid" });
    expect(inspect(failure, { depth: 10 })).not.toContain(secret);
    expect(JSON.stringify(failure)).not.toContain(secret);
  });

  test("invocation publications use their exact tunnel, not a configured service", () => {
    const invocation = `ivk_${"A".repeat(22)}`;
    const publication = {
      tunnel_id: "tunnel",
      command: "publish",
      state: "ready",
      process_id: 1,
      server: "https://control.example",
      project: "/project",
      publish_run_number: 2,
      started_at: snapshot.observed_at,
      updated_at: snapshot.observed_at,
      heartbeat_at: snapshot.observed_at,
      lease_expires_at: snapshot.observed_at,
    };
    const value = {
      ...snapshot,
      services: [{ ...service, service: invocation, tunnel_id: publication.tunnel_id }],
      publications: [publication],
    };
    expect(parseStatus(value, invocation, registrationID, target)?.routable).toBe(true);
    for (const changed of [
      { ...publication, tunnel_id: "another-tunnel" },
      { ...publication, service: "another-service" },
    ])
      expect(() =>
        parseStatus({ ...value, publications: [changed] }, invocation, registrationID, target),
      ).toThrow(expect.objectContaining({ code: "sdk.response_invalid" }));
    expect(() =>
      parseStatus({ ...snapshot, publications: [publication] }, "web", registrationID, target),
    ).toThrow(expect.objectContaining({ code: "sdk.response_invalid" }));
  });

  test("local registration records reject the non-contract counter field", () => {
    const { run_number, ...item } = service;
    expect(() =>
      parseStatus(
        {
          ...snapshot,
          services: [{ ...item, publish_run_number: run_number }],
        },
        "web",
        registrationID,
        target,
      ),
    ).toThrow(expect.objectContaining({ code: "sdk.response_invalid" }));
  });
});
