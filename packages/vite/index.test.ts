import { fileURLToPath } from "node:url";
import type { ConfigEnv, Plugin, UserConfig } from "vite";
import { describe, expect, onTestFinished, test } from "vitest";
import {
  errorMessage,
  nonLoopbackIPv4Addresses,
  occupyLoopbackPort,
  openTestWebSocket,
  requestOnce,
  requestTestServer,
  reserveLoopbackPort,
  startTestBootstrap,
  startTestProcess,
  waitForBootstrapRequest,
  waitForProcessExit,
  waitForWebSocketMessage,
  withProcessEnvironment,
} from "../dev/test-helper.js";
import tnl from "./dist/index.js";

const serveEnvironment: ConfigEnv = {
  command: "serve",
  isPreview: false,
  isSsrBuild: false,
  mode: "development",
};

describe("tnl", () => {
  test("takes no arguments and is inert outside tnl dev", async () => {
    expect(tnl).toHaveLength(0);
    await expect(runConfigHook(tnl(), { server: { port: 4173 } })).resolves.toBeUndefined();
  });

  test("is inert during preview", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());

    await withProcessEnvironment(bootstrap.environment, async () => {
      await expect(
        runConfigHook(tnl(), {}, { ...serveEnvironment, isPreview: true }),
      ).resolves.toBeUndefined();
    });
    expect(bootstrap.requests).toHaveLength(0);
  });

  test("pins loopback, strict port, and the assigned host", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());

    await withProcessEnvironment(bootstrap.environment, async () => {
      await expect(
        runConfigHook(tnl(), {
          server: {
            allowedHosts: ["existing.example", "demo.tnl.dev"],
            host: "0.0.0.0",
            port: 5200,
            strictPort: false,
          },
        }),
      ).resolves.toEqual({
        server: {
          allowedHosts: ["existing.example", "demo.tnl.dev"],
          host: "127.0.0.1",
          port: 5200,
          strictPort: true,
        },
      });
    });
    expect(bootstrap.requests[0]?.body).toEqual({
      protocol: 1,
      framework: "vite",
      port: 5200,
    });
  });

  test("prefers the port selected by tnl dev", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());

    await withProcessEnvironment({ ...bootstrap.environment, TNL_DEV_PORT: "5300" }, async () => {
      await expect(runConfigHook(tnl(), { server: { port: 5200 } })).resolves.toMatchObject({
        server: { port: 5300 },
      });
    });
    expect(bootstrap.requests[0]?.body).toEqual({
      protocol: 1,
      framework: "vite",
      port: 5300,
    });
  });
});

test(
  "runs Vite with host filtering, loopback binding, and real HMR",
  { timeout: 60_000 },
  async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    const port = await reserveLoopbackPort();
    const process_ = startViteFixture(port, bootstrap.environment);
    onTestFinished(() => process_.close());

    try {
      const registration = await waitForBootstrapRequest(bootstrap);
      expect(registration.body).toEqual({ protocol: 1, framework: "vite", port });

      const page = await requestTestServer(port);
      expect(page.status).toBe(200);
      expect(page.body).toContain("Vite fixture");
      expect(page.headers["x-tnl-fixture"]).toBe("vite");
      await expect(requestTestServer(port, { host: "existing.example" })).resolves.toMatchObject({
        status: 200,
      });
      await expect(requestTestServer(port, { host: "attacker.example" })).resolves.toMatchObject({
        status: 403,
      });

      const nonLoopbackAddress = nonLoopbackIPv4Addresses()[0];
      if (nonLoopbackAddress !== undefined) {
        await expect(
          requestOnce(port, { address: nonLoopbackAddress, timeout: 1000 }),
        ).rejects.toThrow();
      }

      const client = await requestTestServer(port, { path: "/@vite/client" });
      expect(client.status).toBe(200);
      const token = extractViteWebSocketToken(client.body);
      const socket = await openTestWebSocket(port, `/?token=${encodeURIComponent(token)}`, {
        origin: "https://demo.tnl.dev",
        protocol: "vite-hmr",
      });
      onTestFinished(() => socket.close());
      const message = JSON.parse(await waitForWebSocketMessage(socket)) as { type?: string };
      expect(message.type).toBe("connected");
    } catch (error) {
      throw new Error(`${errorMessage(error)}\n${process_.output()}`, { cause: error });
    }
  },
);

test("fails instead of incrementing an occupied port", { timeout: 60_000 }, async () => {
  const bootstrap = await startTestBootstrap();
  onTestFinished(() => bootstrap.close());
  const port = await reserveLoopbackPort();
  const releasePort = await occupyLoopbackPort(port);
  onTestFinished(releasePort);
  const process_ = startViteFixture(port, bootstrap.environment);
  onTestFinished(() => process_.close());

  const registration = await waitForBootstrapRequest(bootstrap);
  expect(registration.body).toEqual({ protocol: 1, framework: "vite", port });
  const exit = await waitForProcessExit(process_);
  expect(exit.code).not.toBe(0);
  expect(process_.output()).toContain(`Port ${port} is already in use`);
  expect(process_.output()).not.toContain("trying another one");
});

async function runConfigHook(
  plugin: Plugin,
  config: UserConfig,
  environment: ConfigEnv = serveEnvironment,
): Promise<unknown> {
  const hook = plugin.config;
  if (typeof hook !== "function") {
    throw new Error("tnl plugin does not have a configuration hook");
  }
  return await hook.call({} as never, config, environment);
}

function startViteFixture(port: number, environment: Record<string, string>) {
  const fixture = fileURLToPath(new URL("fixtures/app", import.meta.url));
  const viteCLI = fileURLToPath(new URL("node_modules/vite/bin/vite.js", import.meta.url));
  return startTestProcess(process.execPath, [viteCLI], {
    cwd: fixture,
    env: { ...process.env, ...environment, TNL_FIXTURE_PORT: String(port) },
  });
}

function extractViteWebSocketToken(client: string): string {
  const match = client.match(/const wsToken = "([^"]+)"/);
  if (match?.[1] === undefined) {
    throw new Error("Vite client did not include a WebSocket token");
  }
  return match[1];
}
