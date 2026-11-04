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
  publish_run_number: 2,
  readiness: { path: "/ready" },
  observation: {
    registration_id: registrationID,
    publish_run_number: 2,
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
    { ...service, observation: { ...service.observation, publish_run_number: 1 } },
    {
      ...service,
      observation: { ...service.observation, registration_id: `reg_${"b".repeat(32)}` },
    },
    { ...service, registered: false },
    { ...service, public_url: "https://web.example/path" },
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
});
