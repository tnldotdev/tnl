import { mkdtemp, realpath, writeFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { createServer as createTLSServer } from "node:https";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import * as z from "zod";
import { createClient } from "../../src/internal/connector/client.js";
import { key, cert } from "../fixtures/workload_tls.js";

vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => process.execPath,
}));

afterEach(() => vi.unstubAllEnvs());

const requestSchema = z.strictObject({
  schema: z.literal(1),
  directory: z.string(),
  config_digest: z.string(),
  service: z.literal("api"),
  selection: z.strictObject({ project: z.string(), name: z.string() }),
});

async function fixture() {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), "tnl-deployment-borrowed-")));
  const visits: string[] = [];
  const servernames: string[] = [];
  const tls = createTLSServer({ key, cert }, (request, response) => {
    visits.push(request.headers.host ?? "");
    response.end("verified deployment traffic");
  });
  tls.on("secureConnection", (socket) => {
    if ("servername" in socket && typeof socket.servername === "string")
      servernames.push(socket.servername);
  });
  await new Promise<void>((resolve) => tls.listen(0, "127.0.0.1", resolve));
  const target = tls.address();
  if (target === null || typeof target === "string") throw new Error("missing target");
  const requests: z.output<typeof requestSchema>[] = [];
  const entered = Promise.withResolvers<void>();
  let gate: Promise<void> = Promise.resolve();
  const ipc = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      void (async () => {
        const value = requestSchema.parse(JSON.parse(Buffer.concat(chunks).toString()));
        requests.push(value);
        if (
          request.url !== "/v1/connections/prepare" ||
          request.headers.authorization !== `Bearer ${"a".repeat(64)}` ||
          value.directory !== directory ||
          value.config_digest !== "c".repeat(64) ||
          !["acme/project", "tm_selected/project"].includes(value.selection.project) ||
          value.selection.name !== "production"
        ) {
          response
            .writeHead(401, { "content-type": "application/json" })
            .end('{"code":"connections.unauthorized"}');
          return;
        }
        entered.resolve();
        await gate;
        response.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            schema: 1,
            project_runtime: {
              dev: false,
              namespace: "team.example",
              services: {
                api: {
                  protocol: "http",
                  namespace: "team.example",
                  hostname: "localhost",
                  port: 8443,
                  public: false,
                  url: "https://localhost:8443",
                },
              },
            },
            connection: {
              schema: 1,
              protocol: "http",
              host: "127.0.0.1",
              port: target.port,
              url: "https://localhost:8443",
              ssl: { servername: "localhost", rejectUnauthorized: true, ca: cert },
              expires_at: new Date(Date.now() + 60_000).toISOString(),
              transport_id: `ctg_${"a".repeat(22)}`,
            },
          }),
        );
      })().catch(() => response.writeHead(500).end());
    });
  });
  await new Promise<void>((resolve) => ipc.listen(0, "127.0.0.1", resolve));
  const local = ipc.address();
  if (local === null || typeof local === "string") throw new Error("missing owner");
  const file = path.join(directory, "handle.json");
  await writeFile(
    file,
    JSON.stringify({
      schema: 1,
      url: `http://127.0.0.1:${local.port}`,
      key: "a".repeat(64),
      directory,
      config_digest: "c".repeat(64),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      executable: process.execPath,
    }),
    { mode: 0o600 },
  );
  vi.stubEnv("TNL_TOKEN", undefined);
  vi.stubEnv("TNL_CONNECTION_HANDLE", file);
  return {
    file,
    requests,
    visits,
    servernames,
    entered: entered.promise,
    block(work: Promise<void>) {
      gate = work;
    },
    async close() {
      tls.closeAllConnections();
      ipc.closeAllConnections();
      await Promise.all([
        new Promise<void>((resolve) => tls.close(() => resolve())),
        new Promise<void>((resolve) => ipc.close(() => resolve())),
      ]);
      await rm(directory, { recursive: true, force: true });
    },
  };
}

const services = { api: { protocol: "http" } } as const;

test("borrowed deployments capture exact selection and own independent verified HTTP transports", async () => {
  const owner = await fixture();
  const client = createClient({ project: "acme/project", services });
  const first = client.deployment("production");
  const sibling = client.deployment("production");
  const closedClients: string[] = [];
  try {
    vi.stubEnv("TNL_CONNECTION_HANDLE", "/wrong/job/handle.json");
    vi.stubEnv("TNL_TOKEN", "wrong-tenant");
    const connection = await first.connect("api");
    const other = await sibling.connect("api");
    expect(await (await connection.fetch("/")).text()).toBe("verified deployment traffic");
    const factory = first.client("api", {
      create: () => ({ name: "first driver" }),
      close: (value) => {
        closedClients.push(value.name);
      },
    });
    expect((await factory()).name).toBe("first driver");
    await first.close();
    expect(closedClients).toEqual(["first driver"]);
    await expect(connection.fetch("/")).rejects.toMatchObject({
      code: "sdk.client_closed",
    });
    expect(await (await other.fetch("/")).text()).toBe("verified deployment traffic");
    expect(
      owner.requests.every(
        (value) =>
          value.selection.project === "acme/project" && value.selection.name === "production",
      ),
    ).toBe(true);
    expect(owner.visits).toEqual(["localhost:8443", "localhost:8443"]);
    expect(owner.servernames).toEqual(["localhost", "localhost"]);
    await expect(first.connect("api")).rejects.toMatchObject({ code: "sdk.client_closed" });
  } finally {
    await Promise.all([first.close(), sibling.close()]);
    await owner.close();
  }
});

test("borrowed authority rejects another team, project, or deployment before visitor traffic", async () => {
  const owner = await fixture();
  try {
    for (const [project, name] of [
      ["other/project", "production"],
      ["acme/other", "production"],
      ["acme/project", "staging"],
    ] as const) {
      const deployment = createClient({ project, services }).deployment(name);
      try {
        await expect(deployment.connect("api")).rejects.toMatchObject({
          code: "sdk.connection_unavailable",
        });
      } finally {
        await deployment.close();
      }
    }
    expect(owner.visits).toEqual([]);
    const matchingID = createClient({ project: "tm_selected/project", services }).deployment(
      "production",
    );
    try {
      expect((await matchingID.connect("api")).url).toBe("https://localhost:8443");
    } finally {
      await matchingID.close();
    }
  } finally {
    await owner.close();
  }
});

test("borrowed visitor capability cannot administer deployments", async () => {
  const owner = await fixture();
  const client = createClient({ project: "acme/project", services });
  const deployment = client.deployment("production");
  try {
    await expect(client.deployments.list()).rejects.toMatchObject({
      code: "sdk.configuration_invalid",
    });
    expect(owner.requests).toEqual([]);
  } finally {
    await deployment.close();
    await owner.close();
  }
});

test("an invalid supplied credential never falls back to the borrowed job capability", async () => {
  const owner = await fixture();
  const deployment = createClient({
    project: "acme/project",
    services,
    token: "invalid-private",
  }).deployment("production");
  try {
    await expect(deployment.connect("api")).rejects.toThrow();
    expect(owner.requests).toEqual([]);
  } finally {
    await deployment.close().catch(() => {});
    await owner.close();
  }
});

test("closing a borrowed deployment joins an in-flight preparation without stopping the owner", async () => {
  const owner = await fixture();
  const release = Promise.withResolvers<void>();
  owner.block(release.promise);
  const deployment = createClient({ project: "acme/project", services }).deployment("production");
  try {
    const connecting = deployment.connect("api");
    const rejected = expect(connecting).rejects.toMatchObject({ code: "sdk.client_closed" });
    await owner.entered;
    let closed = false;
    const closing = deployment.close().then(() => {
      closed = true;
    });
    await Promise.resolve();
    expect(closed).toBe(false);
    release.resolve();
    await Promise.all([closing, rejected]);
    const sibling = createClient({ project: "acme/project", services }).deployment("production");
    try {
      await sibling.connect("api");
    } finally {
      await sibling.close();
    }
  } finally {
    release.resolve();
    await deployment.close();
    await owner.close();
  }
});
