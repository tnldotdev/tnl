import { createServer } from "node:http";
import { expect, test } from "vitest";
import { TnlError } from "../../src/errors.js";
import { openServer, openFetch } from "../../src/internal/publisher/open.js";
import { parseStatus } from "../../src/internal/publisher/status.js";
import { runtimeRequest, type RuntimeEndpoint } from "../../src/internal/publisher/local.js";
import { record } from "../../src/internal/project/runtime.js";

const id = `reg_${"a".repeat(32)}`;
const publicURL = "https://temporary.member.example";
function snapshot(service: string, target: string, registration = id, routable = true, run = 2) {
  return {
    schema_version: 1,
    project: "/project",
    cursor: "cursor",
    observed_at: new Date().toISOString(),
    services: [
      {
        service,
        directory: ".",
        registration_id: registration,
        target,
        registered: true,
        routable,
        ready: false,
        readiness: { path: "/" },
        public_url: publicURL,
        publish_run_number: run,
      },
    ],
  };
}

test("status fences scope, registration, target, and publish run without public GET probes", () => {
  const value = snapshot("invocation", "http://127.0.0.1:1234");
  expect(parseStatus(value, "invocation", id, "http://127.0.0.1:1234")?.routable).toBe(true);
  expect(
    parseStatus(value, "invocation", `reg_${"b".repeat(32)}`, "http://127.0.0.1:1234"),
  ).toBeUndefined();
  expect(parseStatus(value, "invocation", id, "http://127.0.0.1:4321")).toBeUndefined();
  expect(() => parseStatus(value, "other", id, "http://127.0.0.1:1234")).toThrow(TnlError);
  expect(() =>
    parseStatus({ ...value, capability: "secret" }, "invocation", id, "http://127.0.0.1:1234"),
  ).toThrow(TnlError);
  const item = value.services[0];
  if (item === undefined) throw new Error("missing service");
  item.publish_run_number = 0;
  expect(() => parseStatus(value, "invocation", id, "http://127.0.0.1:1234")).toThrow(TnlError);
});

test("real Node port-0 wildcard listener waits for exact native status and joins target-fenced cleanup", async () => {
  const app = createServer((_request, response) => response.end("app"));
  await new Promise<void>((resolve) => app.listen(0, "0.0.0.0", resolve));
  const calls: { path: string | undefined; body: unknown }[] = [];
  let service = "";
  let owner = "";
  let target = "";
  let statuses = 0;
  const api = createServer((request, response) => {
    expect(request.headers.authorization).toBe(`Bearer ${"b".repeat(64)}`);
    expect(request.headers.origin).toBeUndefined();
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const body: unknown =
        chunks.length === 0 ? undefined : JSON.parse(Buffer.concat(chunks).toString());
      calls.push({ path: request.url, body });
      response.setHeader("Content-Type", "application/json");
      if (request.url === "/v1/ad-hoc/register") {
        const payload = record(body, "invocation");
        service = String(payload.invocation_id);
        owner = String(payload.owner);
        target = String(payload.target);
        expect(payload.publisher_id).toBe(`pub_${"A".repeat(22)}`);
        expect(payload.credential).toBeUndefined();
        response.end(JSON.stringify({ version: 1, registration_id: id, owner, target }));
      } else if (request.url === "/v1/status") {
        expect(request.method).toBe("GET");
        statuses++;
        response.end(
          JSON.stringify(
            snapshot(service, target, statuses === 1 ? `reg_${"c".repeat(32)}` : id, statuses > 2),
          ),
        );
      } else {
        expect(body).toEqual({ version: 1, registration_id: id, owner, target });
        response.writeHead(204).end();
      }
    });
  });
  await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
  const address = api.address();
  if (address === null || typeof address === "string") throw new Error("missing listener");
  try {
    const handle = await openServer(
      app,
      { publisherID: `pub_${"A".repeat(22)}` },
      {
        start: async (_directory, _binary, selection) => ({
          version: 1,
          url: `http://127.0.0.1:${address.port}`,
          capability: "b".repeat(64),
          owner_id: "a".repeat(32),
          scope: "invocation",
          invocation_id: selection?.invocationID ?? "",
        }),
        request: runtimeRequest,
        pause: async () => new Promise((resolve) => setTimeout(resolve, 1)),
      },
    );
    expect(handle.url).toBe(publicURL);
    expect(statuses).toBeGreaterThanOrEqual(3);
    await handle.close();
    await handle.wait();
    expect(app.listening).toBe(true);
    expect(calls.at(-1)?.path).toBe("/v1/unregister");
  } finally {
    await Promise.all(
      [app, api].map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
    );
  }
});

test("default invocation rediscovery retains automatic publisher selection after owner replacement", async () => {
  let starts = 0;
  let service = "";
  let target = "";
  let failed = false;
  const ids: string[] = [];
  const handle = await openFetch(
    () => new Response("app"),
    {},
    {
      start: async (_directory, _binary, selection): Promise<RuntimeEndpoint> => {
        starts++;
        service = selection?.invocationID ?? "";
        return {
          version: 1,
          url: "http://127.0.0.1:12345",
          capability: String(starts).repeat(64),
          owner_id: "a".repeat(32),
          scope: "invocation",
          invocation_id: service,
        };
      },
      request: async (_endpoint, operation, body) => {
        if (operation === "ad-hoc/register") {
          const payload = record(body, "invocation");
          target = String(payload.target);
          ids.push(String(payload.invocation_id));
          expect(payload).not.toHaveProperty("publisher_id");
          expect(payload).not.toHaveProperty("publisher_file");
          expect(payload).not.toHaveProperty("enrollment_key");
          return {
            version: 1,
            registration_id: `reg_${String(starts).repeat(32)}`,
            owner: payload.owner,
            target,
          };
        }
        if (operation === "status") {
          if (!failed) {
            failed = true;
            throw new TnlError("sdk.registration_stale");
          }
          return snapshot(service, target, `reg_${String(starts).repeat(32)}`);
        }
        return undefined;
      },
      pause: async () => new Promise((resolve) => setTimeout(resolve, 1)),
    },
  );
  expect(starts).toBe(2);
  expect(ids[0]).toBe(ids[1]);
  await handle.close();
});

test("close interrupts status polling and joins unregister without waiting for its next timer", async () => {
  let service = "";
  let target = "";
  let unregistered = false;
  const handle = await openFetch(
    () => new Response("app"),
    { publisherID: `pub_${"A".repeat(22)}` },
    {
      start: async (_directory, _binary, selection): Promise<RuntimeEndpoint> => {
        service = selection?.invocationID ?? "";
        return {
          version: 1,
          url: "http://127.0.0.1:12345",
          capability: "b".repeat(64),
          owner_id: "a".repeat(32),
          scope: "invocation",
          invocation_id: service,
        };
      },
      request: async (_endpoint, operation, body) => {
        if (operation === "ad-hoc/register") {
          const payload = record(body, "invocation");
          target = String(payload.target);
          return { version: 1, registration_id: id, owner: payload.owner, target };
        }
        if (operation === "status") return snapshot(service, target);
        if (operation === "unregister") unregistered = true;
        return undefined;
      },
      pause: () => new Promise<void>(() => {}),
    },
  );
  await handle.close();
  await handle.wait();
  expect(unregistered).toBe(true);
});

test("explicit publisher file is passed only to native and never enters status", async () => {
  let service = "";
  let target = "";
  const handle = await openFetch(
    () => new Response("app"),
    { publisherFile: "/private/publisher.json" },
    {
      start: async (_directory, _binary, selection): Promise<RuntimeEndpoint> => {
        service = selection?.invocationID ?? "";
        return {
          version: 1,
          url: "http://127.0.0.1:12345",
          capability: "b".repeat(64),
          owner_id: "a".repeat(32),
          scope: "invocation",
          invocation_id: service,
        };
      },
      request: async (_endpoint, operation, body) => {
        if (operation === "ad-hoc/register") {
          const payload = record(body, "invocation");
          target = String(payload.target);
          expect(payload.publisher_file).toBe("/private/publisher.json");
          expect(payload.publisher_id).toBeUndefined();
          return { version: 1, registration_id: id, owner: payload.owner, target };
        }
        if (operation === "status") return snapshot(service, target);
        return undefined;
      },
      pause: () => new Promise<void>(() => {}),
    },
  );
  expect(JSON.stringify(handle)).not.toContain("publisher.json");
  await handle.close();
});

test("publisher file configured after the owner starts reaches the native invocation", async () => {
  const prior = process.env.TNL_PUBLISHER_FILE;
  process.env.TNL_PUBLISHER_FILE = "/private/production-publisher.json";
  let service = "";
  let target = "";
  try {
    const handle = await openFetch(
      () => new Response("app"),
      {},
      {
        start: async (_directory, _binary, selection): Promise<RuntimeEndpoint> => {
          service = selection?.invocationID ?? "";
          return {
            version: 1,
            url: "http://127.0.0.1:12345",
            capability: "b".repeat(64),
            owner_id: "a".repeat(32),
            scope: "invocation",
            invocation_id: service,
          };
        },
        request: async (_endpoint, operation, body) => {
          if (operation === "ad-hoc/register") {
            const payload = record(body, "invocation");
            target = String(payload.target);
            expect(payload.publisher_file).toBe("/private/production-publisher.json");
            return { version: 1, registration_id: id, owner: payload.owner, target };
          }
          if (operation === "status") return snapshot(service, target);
          return undefined;
        },
        pause: () => new Promise<void>(() => {}),
      },
    );
    expect(JSON.stringify(handle)).not.toContain("production-publisher.json");
    await handle.close();
  } finally {
    if (prior === undefined) delete process.env.TNL_PUBLISHER_FILE;
    else process.env.TNL_PUBLISHER_FILE = prior;
  }
});

test("invalid explicit publisher selection fails before contacting native", async () => {
  const app = createServer();
  await new Promise<void>((resolve) => app.listen(0, "127.0.0.1", resolve));
  try {
    const start = async (): Promise<RuntimeEndpoint> => {
      throw new Error("native should not be called");
    };
    await expect(
      openServer(
        app,
        { publisherFile: "relative/file" },
        { start, request: async () => undefined, pause: async () => {} },
      ),
    ).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
    await expect(
      openServer(
        app,
        { publisherFile: "/private/file", publisherID: `pub_${"A".repeat(22)}` } as never,
        { start, request: async () => undefined, pause: async () => {} },
      ),
    ).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
  } finally {
    await new Promise<void>((resolve) => app.close(() => resolve()));
  }
});
