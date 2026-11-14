import { createServer, request as httpRequest } from "node:http";
import { assert, expect, test } from "vitest";
import * as z from "zod";
import { TnlError } from "../../src/errors.js";
import { publishServer, publishFetch } from "../../src/internal/publisher/publication.js";
import { parseStatus } from "../../src/internal/publisher/status.js";
import { runtimeRequest, type RuntimeEndpoint } from "../../src/internal/publisher/local.js";
import { invocationIDSchema } from "../../src/internal/values.js";

const invocationSchema = z.looseObject({
  invocation_id: z.string(),
  owner: z.string(),
  target: z.string(),
});

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
        run_number: run,
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
  assert(item !== undefined);
  item.run_number = 0;
  expect(() => parseStatus(value, "invocation", id, "http://127.0.0.1:1234")).toThrow(TnlError);
});

test.each(["unregister", "publications/register", "status"])(
  "stopped cleanup outcome is validated for %s without exposing remote details",
  async (operation) => {
    const api = createServer((_request, response) => {
      response.writeHead(409, { "Content-Type": "application/json" }).end(
        JSON.stringify({
          code: "runtime.publication_cleanup_failed",
          message: "private remote failure",
        }),
      );
    });
    await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
    const address = api.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    try {
      const endpoint: RuntimeEndpoint = {
        version: 1,
        url: `http://127.0.0.1:${address.port}`,
        capability: "b".repeat(64),
        owner_id: "a".repeat(32),
        scope: "invocation",
        invocation_id: invocationIDSchema.parse(`ivk_${"A".repeat(22)}`),
      };
      await expect(runtimeRequest(endpoint, operation)).rejects.toMatchObject({
        code: operation === "status" ? "sdk.response_invalid" : "sdk.publication_cleanup_failed",
        message: expect.not.stringContaining("private remote failure"),
      });
    } finally {
      await new Promise<void>((resolve) => api.close(() => resolve()));
    }
  },
);

test.each(["terminal", "transient", "forgotten"])(
  "Fetch recovers a lost %s unregister reply over real IPC before closing its listener",
  async (outcome) => {
    let service = "";
    let target = "";
    let restored = false;
    const unregisters: string[] = [];
    const api = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        const encoded = Buffer.concat(chunks).toString("utf8");
        response.setHeader("Content-Type", "application/json");
        if (request.url === "/v1/publications/register") {
          const body = invocationSchema.parse(JSON.parse(encoded));
          service = body.invocation_id;
          target = body.target;
          response.end(
            JSON.stringify({ version: 1, registration_id: id, owner: body.owner, target }),
          );
        } else if (request.url === "/v1/status") {
          response.end(JSON.stringify(snapshot(service, target)));
        } else if (request.url === "/v1/unregister") {
          unregisters.push(encoded);
          if (unregisters.length === 1) {
            // native already joined the worker; lose only its outer reply.
            request.socket.destroy();
          } else if (outcome === "forgotten" && !restored) {
            response.writeHead(401).end(
              JSON.stringify({
                code: "runtime.unauthorized",
                message: "a replacement owner does not recognize the old capability",
              }),
            );
          } else if (outcome === "terminal" || restored) {
            response.writeHead(409).end(
              JSON.stringify({
                code: "runtime.publication_cleanup_failed",
                message: "the exact registration stopped with failed remote cleanup",
              }),
            );
          } else response.writeHead(204).end();
        } else response.writeHead(204).end();
      });
    });
    await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
    const address = api.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    let publication: Awaited<ReturnType<typeof publishFetch>> | undefined;
    try {
      publication = await publishFetch(
        () => new Response("owned"),
        {},
        {
          start: async (_directory, _binary, selection): Promise<RuntimeEndpoint> => ({
            version: 1,
            url: `http://127.0.0.1:${address.port}`,
            capability: "b".repeat(64),
            owner_id: "a".repeat(32),
            scope: "invocation",
            invocation_id: invocationIDSchema.parse(selection?.invocationID),
          }),
          request: runtimeRequest,
          pause: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
        },
      );
      if (outcome === "forgotten") {
        await expect(publication.close()).rejects.toMatchObject({ code: "sdk.dev_unavailable" });
        await expect(publication.wait()).rejects.toMatchObject({
          code: "sdk.cleanup_failed",
          errors: [{ code: "sdk.dev_unavailable" }, { code: "sdk.dev_unavailable" }],
        });
        const body = await new Promise<string>((resolve, reject) => {
          const request = httpRequest(
            target,
            { headers: { Host: "app.example.test" } },
            (response) => {
              const chunks: Buffer[] = [];
              response.on("data", (chunk: Buffer) => chunks.push(chunk));
              response.on("error", reject);
              response.on("end", () => resolve(Buffer.concat(chunks).toString()));
            },
          );
          request.on("error", reject);
          request.end();
        });
        expect(body).toBe("owned");
        // withdraw the simulated restart so the fixture can return its original
        // exact stopped outcome. no production fallback changes the capability.
        restored = true;
        await expect(publication.close()).rejects.toMatchObject({
          code: "sdk.publication_cleanup_failed",
        });
      } else if (outcome === "terminal") {
        await expect(publication.close()).rejects.toMatchObject({
          code: "sdk.publication_cleanup_failed",
        });
        await expect(publication.wait()).rejects.toMatchObject({
          code: "sdk.publication_cleanup_failed",
        });
      } else {
        await publication.close();
        await publication.wait();
      }
      if (outcome !== "forgotten") expect(unregisters).toHaveLength(2);
      expect(unregisters.every((value) => value === unregisters[0])).toBe(true);
      await expect(fetch(target)).rejects.toThrow();
    } finally {
      restored = true;
      await publication?.close().catch(() => {});
      await new Promise<void>((resolve) => api.close(() => resolve()));
    }
  },
);

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
      if (request.url === "/v1/publications/register") {
        const payload = invocationSchema.parse(body);
        service = payload.invocation_id;
        owner = payload.owner;
        target = payload.target;
        expect(payload.publisher_identity_id).toBe(`pub_${"A".repeat(22)}`);
        expect(payload.require_post_quantum).toBe(true);
        expect(payload.telemetry_disabled).toBe(true);
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
    const handle = await publishServer(
      app,
      { publisherIdentityID: `pub_${"A".repeat(22)}`, requirePostQuantum: true, telemetry: false },
      {
        start: async (_directory, _binary, selection) => ({
          version: 1,
          url: `http://127.0.0.1:${address.port}`,
          capability: "b".repeat(64),
          owner_id: "a".repeat(32),
          scope: "invocation",
          invocation_id: invocationIDSchema.parse(selection?.invocationID),
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
  const handle = await publishFetch(
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
          invocation_id: invocationIDSchema.parse(service),
        };
      },
      request: async (_endpoint, operation, body) => {
        if (operation === "publications/register") {
          const payload = invocationSchema.parse(body);
          target = payload.target;
          ids.push(payload.invocation_id);
          expect(payload).not.toHaveProperty("publisher_identity_id");
          expect(payload).not.toHaveProperty("publisher_credential_file");
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
  const handle = await publishFetch(
    () => new Response("app"),
    { publisherIdentityID: `pub_${"A".repeat(22)}` },
    {
      start: async (_directory, _binary, selection): Promise<RuntimeEndpoint> => {
        service = selection?.invocationID ?? "";
        return {
          version: 1,
          url: "http://127.0.0.1:12345",
          capability: "b".repeat(64),
          owner_id: "a".repeat(32),
          scope: "invocation",
          invocation_id: invocationIDSchema.parse(service),
        };
      },
      request: async (_endpoint, operation, body) => {
        if (operation === "publications/register") {
          const payload = invocationSchema.parse(body);
          target = payload.target;
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
  const handle = await publishFetch(
    () => new Response("app"),
    { publisherCredentialFile: "/private/publisher.json" },
    {
      start: async (_directory, _binary, selection): Promise<RuntimeEndpoint> => {
        service = selection?.invocationID ?? "";
        return {
          version: 1,
          url: "http://127.0.0.1:12345",
          capability: "b".repeat(64),
          owner_id: "a".repeat(32),
          scope: "invocation",
          invocation_id: invocationIDSchema.parse(service),
        };
      },
      request: async (_endpoint, operation, body) => {
        if (operation === "publications/register") {
          const payload = invocationSchema.parse(body);
          target = payload.target;
          expect(payload.publisher_credential_file).toBe("/private/publisher.json");
          expect(payload.publisher_identity_id).toBeUndefined();
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
  const prior = process.env.TNL_PUBLISHER_CREDENTIAL_FILE;
  process.env.TNL_PUBLISHER_CREDENTIAL_FILE = "/private/production-publisher.json";
  let service = "";
  let target = "";
  try {
    const handle = await publishFetch(
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
            invocation_id: invocationIDSchema.parse(service),
          };
        },
        request: async (_endpoint, operation, body) => {
          if (operation === "publications/register") {
            const payload = invocationSchema.parse(body);
            target = payload.target;
            expect(payload.publisher_credential_file).toBe("/private/production-publisher.json");
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
    if (prior === undefined) delete process.env.TNL_PUBLISHER_CREDENTIAL_FILE;
    else process.env.TNL_PUBLISHER_CREDENTIAL_FILE = prior;
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
      publishServer(
        app,
        { publisherCredentialFile: "relative/file" },
        { start, request: async () => undefined, pause: async () => {} },
      ),
    ).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
    await expect(
      publishServer(
        app,
        {
          publisherCredentialFile: "/private/file",
          publisherIdentityID: `pub_${"A".repeat(22)}`,
        } as never,
        { start, request: async () => undefined, pause: async () => {} },
      ),
    ).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
  } finally {
    await new Promise<void>((resolve) => app.close(() => resolve()));
  }
});
