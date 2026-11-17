import { expect, test } from "vitest";
import { TnlError } from "../../src/errors.js";
import { NativeRegistration } from "../../src/internal/publisher/registration.js";
import { invocationIDSchema } from "../../src/internal/values.js";
import type { RuntimeEndpoint } from "../../src/internal/publisher/local.js";

const endpoint: RuntimeEndpoint = {
  version: 1,
  url: "http://127.0.0.1:12345",
  capability: "b".repeat(64),
  owner_id: "a".repeat(32),
  scope: "invocation",
  invocation_id: invocationIDSchema.parse(`ivk_${"A".repeat(22)}`),
};
const registrationID = `reg_${"a".repeat(32)}`;
const budget = () => ({
  deadline: new Date(Date.now() + 10_000).toISOString(),
  signal: new AbortController().signal,
});

test("uncertain invocation cleanup replays captured nested intent and discovery selection", async () => {
  const request = {
    version: 1,
    invocation_id: endpoint.invocation_id,
    owner: "owner",
    target: "http://127.0.0.1:3000",
    deployment: { credential: "original", service: "web" },
    limits: { rate: { count: 7, per: "1s" } },
  };
  const original = structuredClone(request);
  const environment: NodeJS.ProcessEnv = { NODE_ENV: "test", TNL_NO_TELEMETRY: "1" };
  const acquisitions: unknown[] = [];
  const cleanups: unknown[] = [];
  const discoveries: unknown[] = [];
  const native = new NativeRegistration(
    {
      start: async (_directory, _binary, selection) => {
        discoveries.push(structuredClone(selection));
        return endpoint;
      },
      request: async (_endpoint, operation, body) => {
        if (operation === "publications/register") {
          acquisitions.push(structuredClone(body));
          if (acquisitions.length <= 2) throw new TnlError("sdk.dev_unavailable");
          return {
            version: 1,
            registration_id: registrationID,
            owner: "owner",
            target: request.target,
          };
        }
        cleanups.push(body);
        return undefined;
      },
    },
    "/project",
    { invocationID: endpoint.invocation_id, environment },
    { kind: "invocation", request },
  );
  request.deployment.credential = "changed";
  request.limits.rate.count = 99;
  environment.TNL_NO_TELEMETRY = "changed";
  await native.discover();
  await expect(native.acquire()).rejects.toMatchObject({ code: "sdk.dev_unavailable" });
  const shutdown = budget();
  await native.unregister(shutdown, { pause: async () => {} });
  expect(acquisitions).toEqual([original, original, original]);
  expect(discoveries).toEqual([
    {
      invocationID: endpoint.invocation_id,
      environment: { NODE_ENV: "test", TNL_NO_TELEMETRY: "1" },
    },
    {
      invocationID: endpoint.invocation_id,
      environment: { NODE_ENV: "test", TNL_NO_TELEMETRY: "1" },
    },
  ]);
  expect(cleanups).toEqual([
    {
      version: 1,
      registration_id: registrationID,
      owner: "owner",
      target: original.target,
      shutdown_deadline: shutdown.deadline,
    },
  ]);
});

test("configured acquisition retains acknowledgment before the caller requires a hostname", async () => {
  const cleanups: unknown[] = [];
  const native = new NativeRegistration(
    {
      start: async () => ({
        version: 1,
        url: endpoint.url,
        capability: endpoint.capability,
        owner_id: endpoint.owner_id,
        scope: "app",
        service: "web",
      }),
      request: async (_endpoint, operation, body) => {
        if (operation === "prepare")
          return {
            version: 1,
            registration_id: registrationID,
            service: "web",
            hostname: "",
            public_url: "",
            project: { namespace: "", services: {}, dev: true },
          };
        cleanups.push(body);
        return undefined;
      },
    },
    "/project",
    { service: "web" },
    { kind: "configured", request: { owner: "owner" } },
  );
  await native.discover();
  expect((await native.acquire())?.hostname).toBeUndefined();
  await native.unregister(budget());
  expect(cleanups).toHaveLength(1);
  expect(cleanups[0]).toMatchObject({ registration_id: registrationID, owner: "owner" });
});

test("unknown configured preparation is not replayed as proof of cleanup", async () => {
  let requests = 0;
  const native = new NativeRegistration(
    {
      start: async () => endpoint,
      request: async () => {
        requests++;
        throw new TnlError("sdk.dev_unavailable");
      },
    },
    "/project",
    { service: "web" },
    { kind: "configured", request: { owner: "owner" } },
  );
  await native.discover();
  await expect(native.acquire()).rejects.toMatchObject({ code: "sdk.dev_unavailable" });
  await expect(native.unregister(budget())).rejects.toMatchObject({ code: "sdk.dev_unavailable" });
  expect(requests).toBe(1);
});
