import { createServer, type Server } from "node:http";
import { afterEach, expect, test, vi } from "vitest";
import * as z from "zod";
import { TnlError } from "../../src/errors.js";
import { prepareApplicationPublication } from "../../src/internal/publisher/app_credential.js";
import type { RuntimeEndpoint } from "../../src/internal/publisher/local.js";
import { invocationIDSchema } from "../../src/internal/values.js";
import type { ApplicationPublication } from "../../src/internal/publisher/publish.js";

const resource = `url_${"A".repeat(22)}` as const;
const source = {
  document: "private application document",
  server: "https://control.example",
  resource,
};
const bodySchema = z.looseObject({ owner: z.string() });
const registrationSchema = z.strictObject({
  version: z.literal(1),
  registration_id: z.string(),
  owner: z.string(),
  target: z.string().optional(),
});
afterEach(() => vi.useRealTimers());

function fixture(selected: ApplicationPublication = source) {
  const calls: { operation: string; body: unknown }[] = [];
  const state = {
    id: `reg_${"a".repeat(32)}`,
    invocation: "",
    owner: "",
    target: "",
    failRenew: false,
    failCleanup: false,
    wrongResource: false,
    starts: 0,
    hostname: "app.example",
    publicURL: "https://app.example",
    preparation: undefined as Promise<void> | undefined,
  };
  const runtime = {
    start: vi.fn(
      async (
        _directory: string,
        _binary?: string,
        selection?: { invocationID?: string },
      ): Promise<RuntimeEndpoint> => {
        state.starts++;
        state.invocation = selection?.invocationID ?? "";
        return {
          version: 1,
          url: "http://127.0.0.1:12345",
          capability: "b".repeat(64),
          owner_id: "a".repeat(32),
          scope: "invocation",
          invocation_id: invocationIDSchema.parse(state.invocation),
        };
      },
    ),
    request: vi.fn(
      async (_endpoint: RuntimeEndpoint, operation: string, body?: unknown): Promise<unknown> => {
        calls.push({ operation, body });
        if (operation === "publications/prepare") {
          await state.preparation;
          state.owner = bodySchema.parse(body).owner;
          expect(body).toMatchObject({
            application_credential: selected.document,
            resource_id: selected.resource,
            server_url: selected.server,
          });
          expect(z.record(z.string(), z.unknown()).parse(body).target).toBeUndefined();
          return {
            version: 1,
            registration_id: state.id,
            resource_id: state.wrongResource ? `url_${"X".repeat(22)}` : selected.resource,
            hostname: state.hostname,
            public_url: state.publicURL,
          };
        }
        if (operation === "publications/register")
          state.target = registrationSchema.parse(body).target ?? "";
        if (operation === "status")
          return {
            schema_version: 1,
            project: "/project",
            cursor: "cursor",
            observed_at: new Date().toISOString(),
            services: [
              {
                service: state.invocation,
                directory: ".",
                registration_id: state.id,
                target: state.target,
                ...(state.publicURL === "" ? {} : { public_url: state.publicURL }),
                registered: true,
                routable: false,
                ready: false,
                readiness: { path: "/" },
              },
            ],
          };
        if (operation === "renew" && state.failRenew) {
          state.failRenew = false;
          state.id = `reg_${"c".repeat(32)}`;
          throw new TnlError("sdk.dev_unavailable");
        }
        if (operation === "unregister" && state.failCleanup)
          throw new TnlError("sdk.dev_unavailable");
        return undefined;
      },
    ),
  };
  return { calls, state, runtime };
}

async function listener(): Promise<Server> {
  const server = createServer((_request, response) => response.end("app"));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server;
}
async function stop(server: Server) {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

test("application preparation registers a port-zero listener without waiting for public readiness", async () => {
  const { calls, runtime } = fixture();
  const prepared = await prepareApplicationPublication(
    source,
    "/project",
    undefined,
    { resource },
    runtime,
  );
  const server = await listener();
  try {
    expect(prepared.publicURL).toBe("https://app.example");
    expect(JSON.stringify(prepared)).not.toContain(source.document);
    expect(calls.map((call) => call.operation)).toEqual(["publications/prepare"]);
    const publication = await prepared.register(server);
    expect(calls.map((call) => call.operation)).toEqual([
      "publications/prepare",
      "publications/register",
    ]);
    expect(await publication.status()).toMatchObject({
      registered: true,
      routable: false,
      ready: false,
    });
    await publication.close();
    expect(server.listening).toBe(true);
    expect(
      calls
        .filter((call) => JSON.stringify(call.body)?.includes(source.document))
        .map((call) => call.operation),
    ).toEqual(["publications/prepare"]);
  } finally {
    await prepared.close();
    await stop(server);
  }
});

test("source authority loss fences preparation and finishes its publication without releasing unconfirmed cleanup", async () => {
  vi.useFakeTimers();
  let denied = false;
  const failure = new TnlError("sdk.workload_denied");
  const selected = {
    ...source,
    authorize: async () => {
      if (denied) throw failure;
    },
  };
  const { calls, state, runtime } = fixture(selected);
  const prepared = await prepareApplicationPublication(
    selected,
    "/project",
    undefined,
    {},
    runtime,
  );
  const server = await listener();
  try {
    const publication = await prepared.register(server);
    const finished = publication.finished();
    void finished.catch(() => {});
    denied = true;
    state.failCleanup = true;
    await vi.advanceTimersByTimeAsync(5_000);
    await expect(finished).rejects.toBe(failure);
    await expect(prepared.register(server)).rejects.toBe(failure);
    await expect(prepared.close()).rejects.toHaveProperty("code", "sdk.dev_unavailable");
    expect(server.listening).toBe(true);
    state.failCleanup = false;
    await prepared.close();
    expect(calls.filter((call) => call.operation === "unregister")).toHaveLength(3);
  } finally {
    state.failCleanup = false;
    await prepared.close();
    await stop(server);
  }
});

test("application listener replacement fences old handles without letting old cleanup stop the new target", async () => {
  const { calls, runtime } = fixture();
  const prepared = await prepareApplicationPublication(source, "/project", undefined, {}, runtime);
  const first = await listener(),
    second = await listener();
  try {
    const old = await prepared.register(first);
    const current = await prepared.register(second);
    await expect(old.status()).rejects.toHaveProperty("code", "sdk.registration_stale");
    await old.close();
    expect(calls.filter((call) => call.operation === "unregister")).toHaveLength(0);
    expect(await current.status()).toHaveProperty("registered", true);
    await current.close();
    expect(calls.filter((call) => call.operation === "unregister")).toHaveLength(1);
    expect(first.listening && second.listening).toBe(true);
  } finally {
    await prepared.close();
    await Promise.all([stop(first), stop(second)]);
  }
});

test("application owner recovery reuses the pinned identity and resource, then registers the existing listener", async () => {
  vi.useFakeTimers();
  const { calls, state, runtime } = fixture();
  const prepared = await prepareApplicationPublication(source, "/project", undefined, {}, runtime);
  const server = await listener();
  try {
    const publication = await prepared.register(server);
    state.failRenew = true;
    await vi.advanceTimersByTimeAsync(5_000);
    expect(state.starts).toBe(2);
    expect(calls.filter((call) => call.operation === "publications/prepare")).toHaveLength(2);
    expect(calls.filter((call) => call.operation === "publications/register")).toHaveLength(2);
    expect(await publication.status()).toHaveProperty("registered", true);
  } finally {
    await prepared.close();
    await stop(server);
  }
});

test("unconfirmed prepared-publication cleanup is retained for isolated retry", async () => {
  const { state, runtime } = fixture();
  const prepared = await prepareApplicationPublication(source, "/project", undefined, {}, runtime);
  const server = await listener();
  await prepared.register(server);
  try {
    state.failCleanup = true;
    await expect(prepared.close()).rejects.toHaveProperty("code", "sdk.dev_unavailable");
    expect(server.listening).toBe(true);
    state.failCleanup = false;
    await prepared.close();
    await expect(prepared.register(server)).rejects.toHaveProperty(
      "code",
      "sdk.registration_stale",
    );
  } finally {
    state.failCleanup = false;
    await prepared.close();
    await stop(server);
  }
});

test("application preparation rejects another resource in the native reply", async () => {
  const { state, runtime } = fixture();
  state.wrongResource = true;
  await expect(
    prepareApplicationPublication(source, "/project", undefined, {}, runtime),
  ).rejects.toHaveProperty("code", "sdk.response_invalid");
});

test.each(["", "https://app.example:15443"])(
  "saved public URL preparation rejects a service-only endpoint form %s",
  async (endpoint) => {
    const { state, runtime } = fixture();
    state.publicURL = endpoint;
    await expect(
      prepareApplicationPublication(source, "/project", undefined, {}, runtime),
    ).rejects.toHaveProperty("code", "sdk.response_invalid");
  },
);

test.each([false, true])(
  "HTTP service preparation preserves public reachability %s without inventing a public URL",
  async (publicEndpoint) => {
    const selected: ApplicationPublication = { ...source, resource: `svc_${"S".repeat(22)}` };
    const { state, runtime } = fixture(selected);
    state.hostname = "service.example";
    state.publicURL = publicEndpoint ? "https://service.example:15443" : "";
    const prepared = await prepareApplicationPublication(
      selected,
      "/project",
      undefined,
      { resource: selected.resource },
      runtime,
    );
    const server = await listener();
    try {
      expect(prepared.hostname).toBe(state.hostname);
      expect(prepared.publicURL).toBe(publicEndpoint ? state.publicURL : undefined);
      const publication = await prepared.register(server);
      expect(publication.url).toBe(publicEndpoint ? state.publicURL : undefined);
      expect((await publication.status()).publicURL).toBe(
        publicEndpoint ? state.publicURL : undefined,
      );
    } finally {
      await prepared.close();
      await stop(server);
    }
  },
);

test("closing during owner recovery joins and releases the late replacement without registering it", async () => {
  vi.useFakeTimers();
  const { calls, state, runtime } = fixture();
  const prepared = await prepareApplicationPublication(source, "/project", undefined, {}, runtime);
  const server = await listener();
  const gate = Promise.withResolvers<void>();
  try {
    const publication = await prepared.register(server);
    state.preparation = gate.promise;
    state.failRenew = true;
    await vi.advanceTimersByTimeAsync(5_000);
    expect(state.starts).toBe(2);
    expect(calls.filter((call) => call.operation === "publications/prepare")).toHaveLength(2);
    let closed = false;
    const closing = prepared.close().then(() => {
      closed = true;
    });
    await Promise.resolve();
    expect(closed).toBe(false);
    await expect(publication.status()).rejects.toHaveProperty("code", "sdk.registration_stale");
    gate.resolve();
    await closing;
    expect(calls.filter((call) => call.operation === "publications/register")).toHaveLength(1);
    expect(calls.filter((call) => call.operation === "unregister")).toEqual([
      { operation: "unregister", body: expect.objectContaining({ registration_id: state.id }) },
    ]);
    expect(server.listening).toBe(true);
  } finally {
    gate.resolve();
    await prepared.close();
    await stop(server);
  }
});

test("an unbound preparation can close without registering, independently of a sibling", async () => {
  const first = fixture(),
    sibling = fixture();
  const prepared = await prepareApplicationPublication(
    source,
    "/project",
    undefined,
    {},
    first.runtime,
  );
  const other = await prepareApplicationPublication(
    source,
    "/project",
    undefined,
    {},
    sibling.runtime,
  );
  const server = await listener();
  try {
    await prepared.close();
    await expect(prepared.register(server)).rejects.toHaveProperty(
      "code",
      "sdk.registration_stale",
    );
    const publication = await other.register(server);
    expect(await publication.status()).toHaveProperty("registered", true);
    expect(first.calls.map((call) => call.operation)).toEqual([
      "publications/prepare",
      "unregister",
    ]);
    expect(sibling.calls.map((call) => call.operation)).not.toContain("unregister");
  } finally {
    await Promise.all([prepared.close(), other.close()]);
    await stop(server);
  }
});
