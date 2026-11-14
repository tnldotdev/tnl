import { createServer, type RequestListener } from "node:http";
import { chmod, mkdtemp, realpath, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { inspect } from "node:util";
import { test, expect, vi } from "vitest";
import { ownerIPC } from "../../src/internal/connector/connection_ipc.js";

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
    server.removeAllListeners("request");
    for (const body of ["{private-invalid", "x".repeat(128 * 1024 + 1)]) {
      server.once("request", (request, response) => {
        request.resume();
        response.writeHead(200, { "content-type": "application/json" }).end(body);
      });
      await expect(client.prepare("db")).rejects.toMatchObject({ code: "sdk.response_invalid" });
    }
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

test("closing sequential IPC clients preserves another client's active request", async () => {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), "tnl-ipc-retire-")));
  let release: (() => void) | undefined;
  const sockets = new Set<object>();
  const server = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      const reply = () =>
        response.writeHead(200, { "content-type": "application/json" }).end('{"schema":1}');
      if (request.headers.authorization === `Bearer ${"b".repeat(64)}`) release = reply;
      else reply();
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    const handle = {
      schema: 1,
      url: `http://127.0.0.1:${address.port}`,
      key: "a".repeat(64),
      directory,
      config_digest: "c".repeat(64),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      executable: "/installed/tnl",
    };
    const activeFile = path.join(directory, "active.json");
    await writeFile(activeFile, JSON.stringify({ ...handle, key: "b".repeat(64) }), {
      mode: 0o600,
    });
    const activeClient = await ownerIPC(activeFile);
    const active = activeClient.prepare("db");
    for (let i = 0; i < 40; i++) {
      const file = path.join(directory, `${i}.json`);
      await writeFile(file, JSON.stringify(handle), { mode: 0o600 });
      const client = await ownerIPC(file);
      await expect(client.prepare("db")).resolves.toEqual({ schema: 1 });
      client.close();
    }
    expect(release).toBeTypeOf("function");
    await expect.poll(() => sockets.size).toBe(1);
    release?.();
    await expect(active).resolves.toEqual({ schema: 1 });
    activeClient.close();
    release = undefined;
  } finally {
    release?.();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test.each([
  "renewed",
  "unchanged",
  "missing",
  "key",
  "url",
  "directory",
  "config_digest",
  "executable",
  "workload",
  "team_id",
  "unsafe",
  "symlink",
  "oversized",
  "closed",
] as const)("expired borrowed IPC accepts only an exact renewed capability: %s", async (change) => {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), "tnl-ipc-renewal-")));
  let requests = 0;
  const reply: RequestListener = (request, response) => {
    requests++;
    expect(request.url).toBe("/v1/connections/prepare");
    request.resume();
    response.writeHead(200, { "content-type": "application/json" }).end('{"schema":1}');
  };
  const server = createServer(reply),
    replacement = createServer(reply);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  await new Promise<void>((resolve) => replacement.listen(0, "127.0.0.1", resolve));
  const clock = vi.spyOn(Date, "now");
  let client: Awaited<ReturnType<typeof ownerIPC>> | undefined;
  try {
    const address = server.address(),
      other = replacement.address();
    if (
      address === null ||
      typeof address === "string" ||
      other === null ||
      typeof other === "string"
    )
      throw new Error("missing listener");
    const expires = Date.now() + 3600_000;
    const handle = {
      schema: 1,
      url: `http://127.0.0.1:${address.port}`,
      key: "a".repeat(64),
      directory,
      config_digest: "c".repeat(64),
      expires_at: new Date(expires).toISOString(),
      executable: "/installed/tnl",
      workload: "job",
      team_id: `tm_${"a".repeat(22)}`,
    };
    const file = path.join(directory, "handle.json");
    await writeFile(file, JSON.stringify(handle), { mode: 0o600 });
    client = await ownerIPC(file);
    await expect(client.prepare("db")).resolves.toEqual({ schema: 1 });
    const next = { ...handle, expires_at: new Date(expires + 3600_000).toISOString() };
    switch (change) {
      case "key":
        next.key = "b".repeat(64);
        break;
      case "url":
        next.url = `http://127.0.0.1:${other.port}`;
        break;
      case "directory":
        next.directory = path.join(directory, "other");
        break;
      case "config_digest":
        next.config_digest = "d".repeat(64);
        break;
      case "executable":
        next.executable = "/installed/other-tnl";
        break;
      case "workload":
        next.workload = "other";
        break;
      case "team_id":
        next.team_id = `tm_${"b".repeat(22)}`;
        break;
    }
    if (change === "missing") await rm(file);
    else if (change !== "unchanged") {
      await writeFile(
        `${file}.next`,
        JSON.stringify(next) + (change === "oversized" ? " ".repeat(128 * 1024) : ""),
        { mode: 0o600 },
      );
      if (change === "unsafe") await chmod(`${file}.next`, 0o644);
      if (change === "symlink") {
        await rm(file);
        await symlink(`${file}.next`, file);
      } else await rename(`${file}.next`, file);
    }
    if (change === "closed") client.close();
    clock.mockReturnValue(expires + 1);
    if (change === "renewed") {
      await expect(client.prepare("db")).resolves.toEqual({ schema: 1 });
      expect(client.expiresAt).toBe(expires + 3600_000);
      clock.mockReturnValue(expires + 3600_001);
    }
    await expect(client.prepare("db")).rejects.toMatchObject({
      code: "sdk.connection_unavailable",
    });
    expect(requests).toBe(change === "renewed" ? 2 : 1);
  } finally {
    clock.mockRestore();
    client?.close();
    for (const listener of [server, replacement]) {
      listener.closeAllConnections();
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
    await rm(directory, { recursive: true, force: true });
  }
});
