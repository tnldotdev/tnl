import { createServer } from "node:http";
import { once } from "node:events";
import { afterEach, expect, test, vi } from "vitest";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { startTestBootstrap } from "./test-helper/bootstrap.js";
import { withProcessEnvironment } from "./test-helper/environment.js";

afterEach(() => vi.resetModules());

test("registers the port actually bound by a Node server", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment(bootstrap.environment, async () => {
    const { tnl } = await import("@tnldotdev/tnl");
    expect(tnl.port).toBe(0);
    const server = createServer((_, response) => response.end("ready"));
    try {
      server.listen(tnl.port, "127.0.0.1");
      await tnl.register(server);
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("server did not listen");
      expect(bootstrap.requests.map((request) => request.path)).toEqual([
        "/v1/configure",
        "/v1/target",
      ]);
      expect(bootstrap.requests[0]?.body).toEqual({ protocol: 1, framework: "node" });
      expect(bootstrap.requests[1]?.body).toEqual({
        protocol: 1,
        framework: "node",
        target: `http://127.0.0.1:${address.port}`,
      });
    } finally {
      if (server.listening && "closeAllConnections" in server) server.closeAllConnections();
      if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test("closes a Node listener when registration is refused", async () => {
  const bootstrap = await startTestBootstrap({ status: 503 });
  await withProcessEnvironment(bootstrap.environment, async () => {
    const { tnl } = await import("@tnldotdev/tnl");
    const server = createServer((_, response) => response.end("ready"));
    server.listen(tnl.port, "127.0.0.1");
    const closed = once(server, "close");
    await expect(tnl.register(server)).rejects.toThrow();
    await closed;
    expect(server.listening).toBe(false);
  });
});

test("stops waiting when a Node listener closes before listening", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment(bootstrap.environment, async () => {
    const { tnl } = await import("@tnldotdev/tnl");
    const server = createServer();
    const registration = tnl.register(server);
    server.close(() => {});
    await expect(
      Promise.race([
        registration,
        new Promise((_, reject) => setTimeout(() => reject(new Error("registration hung")), 250)),
      ]),
    ).rejects.toMatchObject({ code: "sdk.listener_failed" });
    expect(bootstrap.requests).toHaveLength(0);
  });
});

test("keeps Hono's Node server in control of its own HTTP listener", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment(bootstrap.environment, async () => {
    const { tnl } = await import("@tnldotdev/tnl");
    const app = new Hono();
    app.get("/", (context) => context.text("hono"));
    const server = serve({ fetch: app.fetch, hostname: "127.0.0.1", port: tnl.port });
    try {
      await tnl.register(server);
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("Hono did not listen");
      const response = await fetch(`http://127.0.0.1:${address.port}`);
      expect(await response.text()).toBe("hono");
      expect(bootstrap.requests[1]?.body).toMatchObject({
        framework: "node",
        target: `http://127.0.0.1:${address.port}`,
      });
    } finally {
      if (server.listening && "closeAllConnections" in server) server.closeAllConnections();
      if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test("registers Bun's resolved port without replacing its server", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment(bootstrap.environment, async () => {
    const { tnl } = await import("@tnldotdev/tnl");
    const stop = vi.fn(async () => {});
    await tnl.register({
      port: 5173,
      hostname: "127.0.0.1",
      url: new URL("http://127.0.0.1:5173"),
      stop,
    });
    expect(stop).not.toHaveBeenCalled();
    expect(bootstrap.requests[1]?.body).toEqual({
      protocol: 1,
      framework: "bun",
      target: "http://127.0.0.1:5173",
    });
  });
});

test("rejects a Bun TLS listener and stops it", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment(bootstrap.environment, async () => {
    const { tnl } = await import("@tnldotdev/tnl");
    const stop = vi.fn(async () => {});
    await expect(
      tnl.register({
        port: 5173,
        hostname: "127.0.0.1",
        url: new URL("https://127.0.0.1:5173"),
        stop,
      }),
    ).rejects.toMatchObject({ code: "sdk.target_invalid" });
    expect(stop).toHaveBeenCalledWith(true);
    expect(bootstrap.requests).toHaveLength(0);
  });
});
