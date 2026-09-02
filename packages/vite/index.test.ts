import { fileURLToPath } from "node:url";
import type { ConfigEnv, Plugin, UserConfig } from "vite";
import { describe, expect, onTestFinished, test } from "vitest";
import {
  errorMessage,
  nonLoopbackIPv4Addresses,
  occupyLoopbackPort,
  openTestWebSocketWithMessage,
  requestOnce,
  requestTestServer,
  reserveLoopbackPort,
  startTestBootstrap,
  startTestProcess,
  waitForBootstrapRequest,
  withProcessEnvironment,
} from "../dev/test-helper.js";
import tnl from "./dist/index.js";

const serveEnvironment: ConfigEnv = {
  command: "serve",
  isPreview: false,
  isSsrBuild: false,
  mode: "development",
};
const expectedTnlDefine = {
  "import.meta.env.VITE_TNL_HOSTNAME": JSON.stringify("demo.tnl.dev"),
  "import.meta.env.VITE_TNL_TUNNEL_ID": JSON.stringify(`tunnel_${"b".repeat(32)}`),
  "import.meta.env.VITE_TNL_URL": JSON.stringify("https://demo.tnl.dev"),
};

describe("tnl", () => {
  test("takes no arguments and is inert outside tnl dev", async () => {
    expect(tnl).toHaveLength(0);
    expect(tnl()).toMatchObject({ apply: "serve", enforce: "post", name: "tnl" });
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

  test("pins loopback and the assigned host while preserving Vite port selection", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());

    await withProcessEnvironment(bootstrap.environment, async () => {
      await expect(
        runConfigHook(
          tnl(async ({ cwd, env, worktree }) => {
            expect(cwd).toBe(process.cwd());
            expect(env.TNL_DEV_PROTOCOL).toBe("1");
            expect(worktree.root).toBe(process.cwd());
            expect(worktree.label).not.toHaveLength(0);
            return {
              controlURL: "https://tnl.example.com",
              host: "agent.example.com",
              allowCurrentIP: true,
            };
          }),
          {
            server: {
              allowedHosts: ["existing.example", "demo.tnl.dev"],
              host: "0.0.0.0",
              port: 5200,
              strictPort: false,
            },
          },
        ),
      ).resolves.toEqual({
        define: expectedTnlDefine,
        server: {
          allowedHosts: ["existing.example", "demo.tnl.dev"],
          host: "127.0.0.1",
        },
      });
    });
    expect(bootstrap.requests[0]?.body).toEqual({
      protocol: 1,
      framework: "vite",
      options: {
        controlURL: "https://tnl.example.com",
        host: "agent.example.com",
        allowCurrentIP: true,
      },
    });
  });

  test("prefers the port selected by tnl dev", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());

    await withProcessEnvironment({ ...bootstrap.environment, TNL_DEV_PORT: "5300" }, async () => {
      await expect(runConfigHook(tnl(), { server: { port: 5200 } })).resolves.toMatchObject({
        define: expectedTnlDefine,
        server: { port: 5300 },
      });
    });
    expect(bootstrap.requests[0]?.body).toEqual({
      protocol: 1,
      framework: "vite",
      options: {},
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
      const assignment = await waitForBootstrapRequest(bootstrap);
      expect(assignment).toMatchObject({
        body: { protocol: 1, framework: "vite", options: {} },
        path: "/v1/configure",
      });
      const target = await waitForBootstrapRequest(bootstrap, 1);
      expect(target).toMatchObject({
        body: { protocol: 1, framework: "vite", port },
        path: "/v1/target",
      });

      const page = await requestTestServer(port);
      expect(page.status).toBe(200);
      expect(page.body).toContain("Vite fixture");
      expect(page.headers["x-tnl-fixture"]).toBe("vite");
      const appModule = await requestTestServer(port, { path: "/src/main.ts" });
      expect(appModule.status).toBe(200);
      expect(appModule.body).toContain('"VITE_TNL_URL": "https://demo.tnl.dev"');
      expect(appModule.body).toContain('"VITE_TNL_HOSTNAME": "demo.tnl.dev"');
      expect(appModule.body).toContain(`"VITE_TNL_TUNNEL_ID": "tunnel_${"b".repeat(32)}"`);
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
      const { message: socketMessage, socket } = await openTestWebSocketWithMessage(
        port,
        `/?token=${encodeURIComponent(token)}`,
        {
          origin: "https://demo.tnl.dev",
          protocol: "vite-hmr",
        },
      );
      onTestFinished(() => socket.close());
      const message = JSON.parse(socketMessage) as { type?: string };
      expect(message.type).toBe("connected");
    } catch (error) {
      throw new Error(`${errorMessage(error)}\n${process_.output()}`, { cause: error });
    }
  },
);

test("registers the next port selected by Vite when the preferred port is occupied", async () => {
  const bootstrap = await startTestBootstrap();
  onTestFinished(() => bootstrap.close());
  const port = await reserveLoopbackPort();
  const releasePort = await occupyLoopbackPort(port);
  onTestFinished(releasePort);
  const process_ = startViteFixture(port, bootstrap.environment);
  onTestFinished(() => process_.close());

  const assignment = await waitForBootstrapRequest(bootstrap);
  expect(assignment).toMatchObject({
    body: { protocol: 1, framework: "vite", options: {} },
    path: "/v1/configure",
  });
  const target = await waitForBootstrapRequest(bootstrap, 1);
  expect(target.path).toBe("/v1/target");
  expect(target.body).toMatchObject({ protocol: 1, framework: "vite" });
  const selectedPort = (target.body as { port: number }).port;
  expect(selectedPort).toBeGreaterThan(port);
  await expect(requestTestServer(selectedPort)).resolves.toMatchObject({ status: 200 });
  expect(process_.output()).toContain(`Port ${port} is in use, trying another one`);
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
