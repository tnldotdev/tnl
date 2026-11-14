import { createServer, request as httpRequest, type Server } from "node:http";
import { afterEach, expect, test, vi } from "vitest";
import * as z from "zod";
import { createClient } from "../../src/internal/connector/client.js";
import { TnlError } from "../../src/errors.js";
import type { EndpointSelection, RuntimeEndpoint } from "../../src/internal/publisher/local.js";
import type { BunHTTPServer } from "../../src/internal/publisher/register.js";

const native = vi.hoisted(() => ({ start: vi.fn(), request: vi.fn() }));
vi.mock("../../src/internal/publisher/local.js", async (original) => ({
  ...(await original<typeof import("../../src/internal/publisher/local.js")>()),
  startRuntime: native.start,
  runtimeRequest: native.request,
}));
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/fixture/tnl",
}));
const payload = z.looseObject({ owner: z.string(), target: z.string() });
const servers: Server[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  for (const server of servers.splice(0))
    await new Promise<void>((resolve) => server.close(() => resolve()));
  native.start.mockReset();
  native.request.mockReset();
});
async function listener() {
  const server = createServer((_request, response) => response.end("application owned"));
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server;
}
async function visit(target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(target, { headers: { Host: "app.example.test" } }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("error", reject);
      response.on("end", () => {
        if (response.statusCode !== 200) reject(new Error("unexpected response"));
        else resolve(Buffer.concat(chunks).toString());
      });
    });
    request.on("error", reject);
    request.end();
  });
}
function fixture({ unrealized = false, publicEndpoint = true, runNumber = 1 } = {}) {
  const sessions = new Map<
    string,
    {
      selection: EndpointSelection;
      body?: z.output<typeof payload>;
      registration: string;
      publicURL: string;
      runNumber: number;
      stopped: boolean;
    }
  >();
  const calls: { operation: string; body: unknown }[] = [];
  native.start.mockImplementation(
    async (_directory: string, _binary: string | undefined, selection: EndpointSelection) => {
      const key = String(sessions.size + 1).padStart(32, "0");
      sessions.set(key, {
        selection,
        registration: `reg_${key}`,
        publicURL: `https://app-${key}.example.test`,
        runNumber,
        stopped: false,
      });
      return {
        version: 1,
        url: "http://127.0.0.1:1234",
        capability: key,
        owner_id: key,
        ...(selection.service === undefined
          ? { scope: "invocation", invocation_id: selection.invocationID }
          : { scope: "app", service: selection.service }),
      };
    },
  );
  const request = async (
    endpoint: RuntimeEndpoint,
    operation: string,
    body?: unknown,
  ): Promise<unknown> => {
    calls.push({ operation, body });
    const session = sessions.get(endpoint.capability);
    if (session === undefined) throw new Error("missing session");
    if (operation === "prepare")
      return {
        version: 1,
        registration_id: session.registration,
        service: session.selection.service,
        hostname: unrealized ? "" : new URL(session.publicURL).hostname,
        public_url: unrealized ? "" : session.publicURL,
        project: {
          namespace: "example.test",
          dev: true,
          services: unrealized
            ? {}
            : {
                web: {
                  protocol: "http",
                  namespace: "example.test",
                  hostname: new URL(session.publicURL).hostname,
                  port: 443,
                  public: true,
                  url: session.publicURL,
                },
              },
        },
      };
    if (operation === "publications/register" || operation === "register") {
      session.body = payload.parse(body);
      return {
        version: 1,
        registration_id: session.registration,
        owner: session.body.owner,
        target: session.body.target,
      };
    }
    if (operation === "unregister") {
      session.stopped = true;
      return;
    }
    if (operation === "status")
      return {
        schema_version: 1,
        project: "/project",
        cursor: "cursor",
        observed_at: new Date().toISOString(),
        services: [
          {
            service: session.selection.service ?? session.selection.invocationID,
            directory: ".",
            registration_id: session.registration,
            target: session.body?.target,
            registered: true,
            routable: true,
            ready: false,
            readiness: { path: "/" },
            ...(publicEndpoint ? { public_url: session.publicURL } : {}),
            run_number: session.runNumber,
          },
        ],
      };
    return undefined;
  };
  native.request.mockImplementation(request);
  return { sessions, calls, request };
}

test("remote handles capture private authority, default policy, and independent ownership", async () => {
  const { calls, sessions } = fixture();
  vi.stubEnv("TNL_TOKEN", "captured-private");
  vi.stubEnv("TNL_STATE_DIR", "/private/original");
  const client = createClient({ project: "acme/shop" });
  const first = client.deployment("production"),
    sibling = client.deployment("customer");
  vi.stubEnv("TNL_TOKEN", "other-tenant");
  vi.stubEnv("TNL_STATE_DIR", "/private/other");
  vi.stubEnv("TNL_PUBLISHER_CREDENTIAL_FILE", "/wrong/file");
  const server = await listener();
  const named = await first.publish("web", server),
    temporary = await sibling.publish(server);
  const registrations = calls.filter((call) => call.operation === "publications/register");
  expect(registrations[0]?.body).toMatchObject({
    deployment: {
      project: "acme/shop",
      name: "production",
      service: "web",
      credential: "captured-private",
    },
  });
  expect(registrations[1]?.body).not.toHaveProperty("deployment.service");
  for (const call of registrations) {
    expect(call.body).not.toHaveProperty("access_mode");
    expect(call.body).not.toHaveProperty("publisher_credential_file");
  }
  for (const session of sessions.values())
    expect(session.selection).toMatchObject({
      publications: true,
      stateDir: "/private/original",
      environment: { TNL_TOKEN: "captured-private" },
    });
  expect(JSON.stringify(named)).not.toContain("captured-private");
  await first.close();
  expect([...sessions.values()].map((session) => session.stopped)).toEqual([true, false]);
  expect(temporary.url).toMatch(/^https:/);
  await sibling.close();
  expect(server.listening).toBe(true);
});

test("local named publication uses framework registration and rejects policy overrides", async () => {
  const { calls } = fixture();
  const local = createClient({
    services: { web: { protocol: "http" }, db: { protocol: "postgres" } },
  }).deployment("local");
  const server = await listener();
  await expect(local.publish("db" as "web", server)).rejects.toMatchObject({
    code: "sdk.configuration_invalid",
  });
  await expect(
    local.publish("web", server, { access: "anonymous" } as never),
  ).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
  await local.publish("web", server);
  expect(calls.map((call) => call.operation)).toEqual(
    expect.arrayContaining(["prepare", "register"]),
  );
  expect(calls.map((call) => call.operation)).not.toContain("publications/register");
  await local.close();
  expect(server.listening).toBe(true);
});

test.each(["node", "fetch"])(
  "named publication waits for its first endpoint and preserves %s listener ownership",
  async (kind) => {
    const { request, calls, sessions } = fixture({ unrealized: true });
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    native.request.mockImplementation(async (endpoint, operation, body) => {
      if (operation === "status") {
        entered.resolve();
        await release.promise;
      }
      return request(endpoint, operation, body);
    });
    const local = createClient({ services: { web: { protocol: "http" } } }).deployment("local");
    const server = kind === "node" ? await listener() : undefined;
    let returned = false;
    const pending = local.publish("web", server ?? (() => new Response("owned"))).then((value) => {
      returned = true;
      return value;
    });
    try {
      await entered.promise;
      expect(returned).toBe(false);
      expect(calls.filter((call) => call.operation === "prepare")).toHaveLength(1);
      expect(calls.filter((call) => call.operation === "register")).toHaveLength(1);
      const target = payload.parse(
        calls.find((call) => call.operation === "register")?.body,
      ).target;
      expect(await visit(target)).toBe(server === undefined ? "owned" : "application owned");
      release.resolve();
      const publication = await pending;
      expect(publication.url).toBe([...sessions.values()][0]?.publicURL);
      await publication.close();
      expect(calls.filter((call) => call.operation === "unregister")).toHaveLength(1);
      if (server !== undefined) expect(server.listening).toBe(true);
      else await expect(fetch(target)).rejects.toThrow();
    } finally {
      release.resolve();
      await local.close();
    }
  },
);

test.each(["url", "run"])("late named endpoint retains its %s fence", async (changed) => {
  const { sessions, calls } = fixture({ unrealized: true, runNumber: 2 });
  const local = createClient({ services: { web: { protocol: "http" } } }).deployment("local");
  const server = await listener();
  const publication = await local.publish("web", server);
  try {
    const session = [...sessions.values()][0];
    if (session === undefined) throw new Error("missing publication session");
    if (changed === "url") session.publicURL = "https://another.example.test";
    else session.runNumber = 1;
    const failure = await publication.wait().catch((cause: unknown) => cause);
    expect(failure).toMatchObject({ code: "sdk.response_invalid" });
    await expect(publication.close()).rejects.toBe(failure);
  } finally {
    await local.close();
  }
  expect(server.listening).toBe(true);
  expect(calls.filter((call) => call.operation === "unregister")).toHaveLength(1);
});

test.each(["node", "fetch"])(
  "connector-only HTTP releases its registration and leaves %s listener ownership intact",
  async (kind) => {
    const { calls, sessions } = fixture({ unrealized: true, publicEndpoint: false });
    const local = createClient({ services: { web: { protocol: "http" } } }).deployment("local");
    const server = kind === "node" ? await listener() : undefined;
    await expect(
      local.publish("web", server ?? (() => new Response("owned"))),
    ).rejects.toMatchObject({ code: "sdk.response_invalid" });
    expect(calls.filter((call) => call.operation === "prepare")).toHaveLength(1);
    expect(calls.filter((call) => call.operation === "register")).toHaveLength(1);
    const unregistered = calls.filter((call) => call.operation === "unregister");
    expect(unregistered).toHaveLength(1);
    expect([...sessions.values()][0]?.stopped).toBe(true);
    const target = payload.parse(unregistered[0]?.body).target;
    if (server !== undefined) expect(server.listening).toBe(true);
    else await expect(fetch(target)).rejects.toThrow();
    await local.close();
    expect(calls.filter((call) => call.operation === "prepare")).toHaveLength(1);
  },
);

test("permanent cleanup during startup closes Fetch without replaying the allocation", async () => {
  const { request, calls, sessions } = fixture();
  const cleanup = new TnlError("sdk.publication_cleanup_failed");
  native.request.mockImplementation(async (endpoint, operation, body) => {
    const result = await request(endpoint, operation, body);
    if (operation === "publications/register") {
      const session = sessions.get(endpoint.capability);
      if (session !== undefined) session.stopped = true;
      throw cleanup;
    }
    return result;
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  await expect(deployment.publish(() => new Response("owned"))).rejects.toBe(cleanup);
  const registered = calls.filter((call) => call.operation === "publications/register");
  expect(registered).toHaveLength(1);
  await expect(fetch(payload.parse(registered[0]?.body).target)).rejects.toThrow();
  await deployment.close();
  expect(calls.filter((call) => call.operation === "unregister")).toHaveLength(0);
});

test("lost reply and permanent cleanup retain both failures while closing Fetch", async () => {
  const { request, calls } = fixture();
  const operation = new TnlError("sdk.dev_unavailable");
  const cleanup = new TnlError("sdk.publication_cleanup_failed");
  let lost = false;
  native.request.mockImplementation(async (endpoint, name, body) => {
    const value = await request(endpoint, name, body);
    if (name === "publications/register" && !lost) {
      lost = true;
      throw operation;
    }
    if (name === "unregister") throw cleanup;
    return value;
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  await expect(deployment.publish(() => new Response("owned"))).rejects.toMatchObject({
    code: "sdk.cleanup_failed",
    errors: [operation, cleanup],
  });
  const registered = calls.filter((call) => call.operation === "publications/register");
  expect(registered).toHaveLength(2);
  expect(registered[0]?.body).toEqual(registered[1]?.body);
  await expect(fetch(payload.parse(registered[0]?.body).target)).rejects.toThrow();
  await deployment.close();
});

test.each(["node", "fetch"])(
  "permanent native cleanup failure retires %s locally without claiming remote success",
  async (kind) => {
    const { request, calls, sessions } = fixture();
    const cleanup = new TnlError("sdk.publication_cleanup_failed");
    native.request.mockImplementation(async (endpoint, operation, body) => {
      const result = await request(endpoint, operation, body);
      if (operation === "unregister") throw cleanup;
      return result;
    });
    const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
      "production",
    );
    const server = kind === "node" ? await listener() : undefined;
    const handle = await deployment.publish(server ?? (() => new Response("owned")));
    const target = payload.parse(
      calls.find((call) => call.operation === "publications/register")?.body,
    ).target;
    await expect(handle.close()).rejects.toBe(cleanup);
    await expect(handle.wait()).rejects.toBe(cleanup);
    expect([...sessions.values()][0]?.stopped).toBe(true);
    if (server !== undefined) expect(server.listening).toBe(true);
    else await expect(fetch(target)).rejects.toThrow();
    await deployment.close();
    expect(calls.filter((call) => call.operation === "unregister")).toHaveLength(1);
  },
);

test("Fetch returns only when routable and joins its owned adapter", async () => {
  const { request, calls } = fixture();
  const entered = Promise.withResolvers<void>(),
    ready = Promise.withResolvers<void>();
  native.request.mockImplementation(async (endpoint, operation, body) => {
    if (operation === "status") {
      entered.resolve();
      await ready.promise;
    }
    return request(endpoint, operation, body);
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  let returned = false;
  const pending = deployment
    .publish(() => new Response("fetch app"))
    .then((handle) => {
      returned = true;
      return handle;
    });
  await entered.promise;
  expect(returned).toBe(false);
  ready.resolve();
  const handle = await pending;
  const target = payload.parse(
    calls.find((call) => call.operation === "publications/register")?.body,
  ).target;
  expect(await visit(target)).toBe("fetch app");
  await handle.close();
  await expect(fetch(target)).rejects.toThrow();
  await deployment.close();
});

test("close joins a committed late reply and its native drain", async () => {
  const { request, calls } = fixture();
  const committed = Promise.withResolvers<void>(),
    reply = Promise.withResolvers<void>();
  const draining = Promise.withResolvers<void>(),
    drained = Promise.withResolvers<void>();
  native.request.mockImplementation(async (endpoint, operation, body) => {
    const value = await request(endpoint, operation, body);
    if (operation === "publications/register") {
      committed.resolve();
      await reply.promise;
    }
    if (operation === "unregister") {
      draining.resolve();
      await drained.promise;
    }
    return value;
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  const pending = deployment.publish(await listener());
  const rejected = expect(pending).rejects.toMatchObject({ code: "sdk.client_closed" });
  await committed.promise;
  let closed = false;
  const closing = deployment.close().then(() => {
    closed = true;
  });
  reply.resolve();
  await draining.promise;
  expect(closed).toBe(false);
  drained.resolve();
  await Promise.all([closing, rejected]);
  expect(calls.filter((call) => call.operation === "unregister")).toHaveLength(1);
});

test("lost initial reply recovers exact intent; failed startup cleanup remains retryable", async () => {
  const { request, calls } = fixture();
  let lost = false,
    failing = true;
  native.request.mockImplementation(async (endpoint, operation, body) => {
    if (operation === "unregister" && failing) throw new TnlError("sdk.request_rejected");
    const value = await request(endpoint, operation, body);
    if (operation === "publications/register" && !lost) {
      lost = true;
      throw new TnlError("sdk.dev_unavailable");
    }
    return value;
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  await expect(deployment.publish(() => new Response("retained"))).rejects.toMatchObject({
    code: "sdk.cleanup_failed",
  });
  const registered = calls.filter((call) => call.operation === "publications/register");
  expect(registered).toHaveLength(2);
  expect(registered[0]?.body).toEqual(registered[1]?.body);
  const target = payload.parse(registered[0]?.body).target;
  expect(await visit(target)).toBe("retained");
  failing = false;
  await deployment.close();
  await expect(fetch(target)).rejects.toThrow();
});

test("retained startup cleanup retires Fetch when transient deletion becomes permanently denied", async () => {
  const { request, calls } = fixture();
  let lost = false;
  let permanent = false;
  const terminal = new TnlError("sdk.publication_cleanup_failed");
  native.request.mockImplementation(async (endpoint, operation, body) => {
    if (operation === "unregister" && !permanent) throw new TnlError("sdk.request_rejected");
    const value = await request(endpoint, operation, body);
    if (operation === "publications/register" && !lost) {
      lost = true;
      throw new TnlError("sdk.dev_unavailable");
    }
    if (operation === "unregister") throw terminal;
    return value;
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  await expect(deployment.publish(() => new Response("retained"))).rejects.toMatchObject({
    code: "sdk.cleanup_failed",
  });
  const registered = calls.filter((call) => call.operation === "publications/register");
  const target = payload.parse(registered[0]?.body).target;
  expect(registered).toHaveLength(2);
  expect(registered[0]?.body).toEqual(registered[1]?.body);
  expect(await visit(target)).toBe("retained");
  permanent = true;
  await expect(deployment.close()).rejects.toBe(terminal);
  await expect(fetch(target)).rejects.toThrow();
  await deployment.close();
  expect(calls.filter((call) => call.operation === "unregister")).toHaveLength(1);
});

test("permanent cleanup leaves a supplied Bun server app-owned and restores stop", async () => {
  const { request } = fixture();
  native.request.mockImplementation(async (endpoint, operation, body) => {
    const value = await request(endpoint, operation, body);
    if (operation === "unregister") throw new TnlError("sdk.publication_cleanup_failed");
    return value;
  });
  const stop = vi.fn(async () => {});
  const server: BunHTTPServer = { url: new URL("http://127.0.0.1:3000"), port: 3000, stop };
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  const publication = await deployment.publish(server);
  await expect(publication.close()).rejects.toMatchObject({
    code: "sdk.publication_cleanup_failed",
  });
  expect(server.stop).toBe(stop);
  expect(stop).not.toHaveBeenCalled();
  await deployment.close();
});

test("Bun stop is shared and restored without closing application-owned listeners", async () => {
  fixture();
  const stop = vi.fn(async () => {});
  const server: BunHTTPServer = { url: new URL("http://127.0.0.1:3000"), port: 3000, stop };
  const client = createClient({ project: "acme/shop", token: "private" });
  const a = client.deployment("first"),
    b = client.deployment("second");
  const first = await a.publish(server),
    second = await b.publish(server);
  expect(server.stop).not.toBe(stop);
  await first.close();
  expect(server.stop).not.toBe(stop);
  await second.close();
  expect(server.stop).toBe(stop);
  expect(stop).not.toHaveBeenCalled();
  await Promise.all([a.close(), b.close()]);
});

test("ready cleanup retry retains Fetch and preserves the first failure", async () => {
  const { request, calls } = fixture();
  let failing = true;
  native.request.mockImplementation(async (endpoint, operation, body) => {
    if (operation === "unregister" && failing) throw new TnlError("sdk.request_rejected");
    return request(endpoint, operation, body);
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  const handle = await deployment.publish(() => new Response("retained"));
  const target = payload.parse(
    calls.find((call) => call.operation === "publications/register")?.body,
  ).target;
  await expect(deployment.close()).rejects.toThrow();
  expect(await visit(target)).toBe("retained");
  failing = false;
  await expect(deployment.close()).rejects.toThrow();
  await expect(fetch(target)).rejects.toThrow();
  await deployment.close();
  expect(handle.url).toMatch(/^https:/);
});
