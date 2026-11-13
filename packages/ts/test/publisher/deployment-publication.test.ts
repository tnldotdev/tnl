import { createServer, request as httpRequest, type Server } from "node:http";
import { afterEach, expect, test, vi } from "vitest";
import * as z from "zod";
import { createClient } from "../../src/internal/connector/client.js";
import { TnlError } from "../../src/errors.js";
import type { EndpointSelection, RuntimeEndpoint } from "../../src/internal/publisher/local.js";
import type { BunHTTPServer } from "../../src/internal/publisher/register.js";

const native = vi.hoisted(() => ({ start: vi.fn(), request: vi.fn() }));
vi.mock("../../src/internal/publisher/local.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/internal/publisher/local.js")>()),
  startRuntime: native.start,
  runtimeRequest: native.request,
}));
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/fixture/tnl",
}));

const payloadSchema = z.looseObject({ owner: z.string(), target: z.string() });
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

async function visit(target: string, publicURL: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      target,
      { headers: { Host: new URL(publicURL).hostname } },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("error", reject);
        response.on("end", () => {
          if (response.statusCode !== 200)
            reject(new Error(`unexpected status ${response.statusCode}`));
          else resolve(Buffer.concat(chunks).toString());
        });
      },
    );
    request.on("error", reject);
    request.end();
  });
}

function fixture() {
  const sessions = new Map<
    string,
    {
      selection: EndpointSelection;
      body?: z.output<typeof payloadSchema>;
      registration: string;
      publicURL: string;
      stopped: boolean;
    }
  >();
  const calls: { operation: string; body: unknown }[] = [];
  native.start.mockImplementation(
    async (_directory: string, _binary: string | undefined, selection: EndpointSelection) => {
      const capability = String(sessions.size + 1).padStart(64, "0");
      const registration = `reg_${String(sessions.size + 1).padStart(32, "0")}`;
      const publicURL =
        selection.service === undefined
          ? `https://temporary-${sessions.size}.example.test`
          : "https://web.example.test";
      sessions.set(capability, { selection, registration, publicURL, stopped: false });
      return {
        version: 1,
        url: "http://127.0.0.1:1234",
        capability,
        owner_id: "a".repeat(32),
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
    if (session === undefined) throw new Error("unknown fixture session");
    if (operation === "prepare")
      return {
        version: 1,
        registration_id: session.registration,
        service: session.selection.service,
        hostname: "web.example.test",
        public_url: session.publicURL,
        project: {
          namespace: "example.test",
          dev: true,
          services: {
            web: {
              protocol: "http",
              namespace: "example.test",
              hostname: "web.example.test",
              port: 443,
              public: true,
              url: session.publicURL,
            },
          },
        },
      };
    if (operation === "ad-hoc/register" || operation === "register") {
      session.body = payloadSchema.parse(body);
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
            public_url: session.publicURL,
            publish_run_number: 1,
          },
        ],
      };
    return undefined;
  };
  native.request.mockImplementation(request);
  return { sessions, calls, request };
}

test("named and unnamed handles capture remote selection without facts and preserve the app listener", async () => {
  const { sessions, calls } = fixture();
  vi.stubEnv("TNL_TOKEN", "captured-private");
  vi.stubEnv("TNL_STATE_DIR", "/private/original-state");
  const app = createClient({ project: "acme/shop" });
  const production = app.deployment("production");
  const sibling = app.deployment("customer");
  vi.stubEnv("TNL_TOKEN", "wrong-tenant");
  vi.stubEnv("TNL_STATE_DIR", "/private/changed-state");
  vi.stubEnv("TNL_PUBLISHER_CREDENTIAL_FILE", "/wrong/publisher.json");
  const server = await listener();
  const named = await production.publish("web", server);
  const temporary = await sibling.publish(server);
  const registered = calls.filter((call) => call.operation === "ad-hoc/register");
  expect(registered[0]?.body).toMatchObject({
    deployment: {
      project: "acme/shop",
      name: "production",
      service: "web",
      credential: "captured-private",
    },
  });
  expect(registered[1]?.body).toMatchObject({
    deployment: { project: "acme/shop", name: "customer", credential: "captured-private" },
  });
  expect(registered[1]?.body).not.toHaveProperty("deployment.service");
  for (const call of registered) {
    expect(call.body).not.toHaveProperty("publisher_credential_file");
    expect(call.body).not.toHaveProperty("access_mode");
  }
  for (const session of sessions.values()) {
    expect(session.selection).toMatchObject({
      publications: true,
      stateDir: "/private/original-state",
    });
    expect(session.selection.environment?.TNL_TOKEN).toBe("captured-private");
  }
  expect(JSON.stringify(named)).not.toContain("captured-private");
  await production.close();
  expect([...sessions.values()].map((value) => value.stopped)).toEqual([true, false]);
  expect(server.listening).toBe(true);
  expect(temporary.url).toMatch(/^https:/);
  await sibling.close();
  expect(server.listening).toBe(true);
});

test("local named publication uses framework prepare/register and strict saved policy", async () => {
  const { calls, sessions } = fixture();
  const local = createClient({
    project: "acme/shop",
    services: { web: { protocol: "http" }, db: { protocol: "postgres" } },
  }).deployment("local");
  const server = await listener();
  await expect(local.publish("db" as "web", server)).rejects.toMatchObject({
    code: "sdk.configuration_invalid",
  });
  await expect(
    local.publish("web", server, { access: "anonymous" } as never),
  ).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
  const publication = await local.publish("web", server);
  expect(publication.url).toBe("https://web.example.test");
  expect(calls.map((call) => call.operation)).toContain("prepare");
  expect(calls.map((call) => call.operation)).toContain("register");
  expect(calls.map((call) => call.operation)).not.toContain("ad-hoc/register");
  expect([...sessions.values()][0]?.selection).not.toHaveProperty("publications");
  await local.close();
  expect(server.listening).toBe(true);
});

test("Fetch publication waits for routability and closes its owned adapter", async () => {
  const { request, calls } = fixture();
  const waiting = Promise.withResolvers<void>();
  const routable = Promise.withResolvers<void>();
  native.request.mockImplementation(async (endpoint, operation, body) => {
    if (operation === "status") {
      waiting.resolve();
      await routable.promise;
    }
    return request(endpoint, operation, body);
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  let ready = false;
  const publishing = deployment
    .publish(() => new Response("fetch app"), { access: "anonymous" })
    .then((value) => {
      ready = true;
      return value;
    });
  await waiting.promise;
  expect(ready).toBe(false);
  routable.resolve();
  const publication = await publishing;
  const target = payloadSchema.parse(
    calls.find((call) => call.operation === "ad-hoc/register")?.body,
  ).target;
  expect(await visit(target, publication.url)).toBe("fetch app");
  await publication.close();
  await expect(fetch(target)).rejects.toThrow();
  await deployment.close();
});

test("deployment close joins a registration that committed before cancellation", async () => {
  const { request, calls } = fixture();
  const committed = Promise.withResolvers<void>();
  const reply = Promise.withResolvers<void>();
  const draining = Promise.withResolvers<void>();
  const drained = Promise.withResolvers<void>();
  native.request.mockImplementation(async (endpoint, operation, body) => {
    const result = await request(endpoint, operation, body);
    if (operation === "ad-hoc/register") {
      committed.resolve();
      await reply.promise;
    }
    if (operation === "unregister") {
      draining.resolve();
      await drained.promise;
    }
    return result;
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  const server = await listener();
  const publishing = deployment.publish(server);
  const rejected = expect(publishing).rejects.toMatchObject({ code: "sdk.client_closed" });
  await committed.promise;
  let closed = false;
  const closing = deployment.close().then(() => {
    closed = true;
  });
  reply.resolve();
  await draining.promise;
  expect(closed).toBe(false);
  expect(server.listening).toBe(true);
  drained.resolve();
  await Promise.all([closing, rejected]);
  expect(calls.filter((call) => call.operation === "unregister")).toHaveLength(1);
});

test("lost initial acknowledgement recovers exact invocation before cleanup", async () => {
  const { request, calls } = fixture();
  let lost = false;
  native.request.mockImplementation(async (endpoint, operation, body) => {
    const result = await request(endpoint, operation, body);
    if (operation === "ad-hoc/register" && !lost) {
      lost = true;
      throw new TnlError("sdk.dev_unavailable");
    }
    return result;
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  await expect(deployment.publish(await listener())).rejects.toMatchObject({
    code: "sdk.dev_unavailable",
  });
  const registered = calls.filter((call) => call.operation === "ad-hoc/register");
  expect(registered).toHaveLength(2);
  expect(registered[0]?.body).toEqual(registered[1]?.body);
  expect(calls.at(-1)?.operation).toBe("unregister");
  await deployment.close();
});

test("two publications restore Bun stop only after their final observer closes", async () => {
  fixture();
  const stop = vi.fn(async () => {});
  const server: BunHTTPServer = { url: new URL("http://127.0.0.1:3000"), port: 3000, stop };
  const client = createClient({ project: "acme/shop", token: "private" });
  const first = client.deployment("first"),
    second = client.deployment("second");
  const a = await first.publish(server),
    b = await second.publish(server);
  expect(server.stop).not.toBe(stop);
  await a.close();
  expect(server.stop).not.toBe(stop);
  await b.close();
  expect(server.stop).toBe(stop);
  expect(stop).not.toHaveBeenCalled();
  await Promise.all([first.close(), second.close()]);
});

test("failed native cleanup retains the Fetch listener for a joined retry", async () => {
  const { request, calls } = fixture();
  const failure = new TnlError("sdk.request_rejected");
  let failing = true;
  native.request.mockImplementation(async (endpoint, operation, body) => {
    if (operation === "unregister" && failing) throw failure;
    return request(endpoint, operation, body);
  });
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  const publication = await deployment.publish(() => new Response("still serving"));
  const target = payloadSchema.parse(
    calls.find((call) => call.operation === "ad-hoc/register")?.body,
  ).target;
  await expect(deployment.close()).rejects.toThrow();
  expect(await visit(target, publication.url)).toBe("still serving");
  failing = false;
  // the first cleanup failure remains observable, even after retry joins.
  await expect(deployment.close()).rejects.toThrow();
  await expect(fetch(target)).rejects.toThrow();
  await deployment.close();
});
