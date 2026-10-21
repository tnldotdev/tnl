import { createServer } from "node:http";
import { chmod, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { inspect } from "node:util";
import { test, expect } from "vitest";
import { ownerIPC } from "./src/internal/connection_ipc.js";

test("direct async IPC reuses one authenticated socket and rejects unsafe handles before requests", async () => {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), "tnl-private-ipc-")));
  const key = "a".repeat(64);
  let requests = 0,
    connections = 0;
  const server = createServer((request, response) => {
    requests++;
    expect(request.method).toBe("POST");
    expect(request.url).toBe("/v1/connections/prepare");
    expect(request.headers.authorization).toBe(`Bearer ${key}`);
    expect(request.headers.origin).toBeUndefined();
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const body: unknown = JSON.parse(Buffer.concat(chunks).toString());
      expect(body).toMatchObject({
        schema: 1,
        directory,
        config_digest: "c".repeat(64),
        service: "db",
        assertion: "private-assertion",
      });
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ schema: 1, state: "prepared" }));
    });
  });
  server.on("connection", () => connections++);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  let client: Awaited<ReturnType<typeof ownerIPC>> | undefined;
  try {
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    const file = path.join(directory, "handle.json");
    const handle = {
      schema: 1,
      url: `http://127.0.0.1:${address.port}`,
      key,
      directory,
      config_digest: "c".repeat(64),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      executable: "/installed/tnl",
    };
    await writeFile(file, JSON.stringify(handle), { mode: 0o600 });
    client = await ownerIPC(file);
    for (let i = 0; i < 10; i++)
      expect(await client.prepare("db", "private-assertion")).toEqual({
        schema: 1,
        state: "prepared",
      });
    expect(requests).toBe(10);
    expect(connections).toBe(1);
    await chmod(file, 0o644);
    await expect(ownerIPC(file)).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
    await chmod(file, 0o600);
    const alias = path.join(directory, "alias.json");
    await symlink(file, alias);
    await expect(ownerIPC(alias)).rejects.toThrow();
    await writeFile(file, JSON.stringify({ ...handle, url: "https://external.example.test/" }));
    await expect(ownerIPC(file)).rejects.toThrow();
    expect(requests).toBe(10);
    expect(inspect(client)).not.toContain(key);
  } finally {
    client?.close();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});
