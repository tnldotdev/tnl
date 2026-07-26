import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import type { ConfigEnv, Plugin, UserConfig } from "vite";
import { describe, expect, onTestFinished, test } from "vitest";
import {
  createProjectFixture,
  errorMessage,
  occupyLoopbackPort,
  openTestWebSocketWithMessage,
  requestTestServer,
  reserveLoopbackPort,
  startTestBootstrap,
  startTestProcess,
  temporaryDirectory,
  testPublicProject,
  waitForBootstrapRequest,
  waitForWebSocketMessage,
  withCurrentDirectory,
  withProcessEnvironment,
} from "./test-helper.js";
import tnl from "@tnldotdev/tnl/vite";

const serveEnvironment: ConfigEnv = {
  command: "serve",
  isPreview: false,
  isSsrBuild: false,
  mode: "development",
};
const buildEnvironment: ConfigEnv = {
  command: "build",
  isPreview: false,
  isSsrBuild: false,
  mode: "production",
};

describe("tnl", () => {
  test("takes no arguments and is inert without generated metadata", async () => {
    expect(tnl).toHaveLength(0);
    expect(tnl()).toMatchObject({ apply: "serve", enforce: "post", name: "tnl" });
    expect(() => tnl({} as never)).toThrow(/does not accept tunnel options/);
    const directory = await temporaryDirectory("tnl-vite-empty-");
    await withCurrentDirectory(directory, async () => {
      await expect(runConfigHook(tnl(), { server: { port: 4173 } })).resolves.toBeUndefined();
    });
  });

  test.each([
    ["build", buildEnvironment],
    ["preview", { ...serveEnvironment, isPreview: true }],
  ])("is inert during %s", async (_name, environment) => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    await withProcessEnvironment(bootstrap.environment, async () => {
      await expect(runConfigHook(tnl(), {}, environment)).resolves.toBeUndefined();
    });
    expect(bootstrap.requests).toHaveLength(0);
  });

  test("injects generated metadata without networking during plain development", async () => {
    const project = await createProjectFixture("tnl-vite-project-");
    await withCurrentDirectory(project.serviceDirectory, async () => {
      const result = await runConfigHook(tnl(), { server: { host: "0.0.0.0", port: 5200 } });
      expect(result).toEqual(runtimeDefine(false));
    });
  });

  test("uses an invocation hostname override for Vite coordination only", async () => {
    const project = testPublicProject(true);
    const bootstrap = await startTestBootstrap({
      responseBody: JSON.stringify({
        hostname: "override.example",
        memberNamespace: "member.example",
        project: {
          ...project,
          services: {
            ...project.services,
            api: {
              ...project.services.api,
              hostname: "override.example",
              url: "https://override.example",
            },
          },
        },
        protocol: 1,
        publicURL: "https://override.example",
        service: "api",
        tunnelID: `tunnel_${"b".repeat(32)}`,
      }),
    });
    onTestFinished(() => bootstrap.close());
    await withProcessEnvironment(bootstrap.environment, async () => {
      await expect(
        runConfigHook(tnl(), {
          server: {
            allowedHosts: ["existing.example", "api.member.example"],
            host: "0.0.0.0",
            port: 5200,
            strictPort: false,
          },
        }),
      ).resolves.toEqual({
        ...runtimeDefine(true, "override.example"),
        server: {
          allowedHosts: ["existing.example", "api.member.example", "override.example"],
        },
      });
    });
    expect(bootstrap.requests[0]?.body).toEqual({ protocol: 1, framework: "vite" });
  });

  test("uses a port forced by tnl dev", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    await withProcessEnvironment({ ...bootstrap.environment, TNL_DEV_PORT: "5300" }, async () => {
      await expect(runConfigHook(tnl(), { server: { port: 5200 } })).resolves.toMatchObject({
        define: runtimeDefine(true).define,
        server: { port: 5300, strictPort: false },
      });
    });
  });
});

test(
  "runs Vite with host filtering, a preserved wildcard binding, runtime metadata, and real HMR",
  { timeout: 60_000 },
  async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    const port = await reserveLoopbackPort();
    const source = fileURLToPath(new URL("fixtures/vite/app/src/main.ts", import.meta.url));
    const originalSource = await readFile(source, "utf8");
    onTestFinished(() => writeFile(source, originalSource));
    const process_ = startViteFixture(port, bootstrap.environment);
    onTestFinished(() => process_.close());

    try {
      expect(await waitForBootstrapRequest(bootstrap)).toMatchObject({
        body: { protocol: 1, framework: "vite" },
        path: "/v1/configure",
      });
      expect(await waitForBootstrapRequest(bootstrap, 1)).toMatchObject({
        body: { protocol: 1, framework: "vite", target: `http://127.0.0.1:${port}` },
        path: "/v1/target",
      });

      const page = await requestTestServer(port);
      expect(page.status).toBe(200);
      expect(page.body).toContain("Vite fixture");
      expect(page.headers["x-tnl-fixture"]).toBe("vite");
      const appModule = await requestTestServer(port, { path: "/src/main.ts" });
      expect(appModule.status).toBe(200);
      expect(appModule.body).toContain("/dist/index.js");
      await expect(requestTestServer(port, { host: "existing.example" })).resolves.toMatchObject({
        status: 200,
      });
      await expect(requestTestServer(port, { host: "attacker.example" })).resolves.toMatchObject({
        status: 403,
      });

      const client = await requestTestServer(port, { path: "/@vite/client" });
      expect(client.status).toBe(200);
      const environmentImport = client.body.match(
        /\bimport\s*(["'])(\/[^"']*\/env\.mjs(?:\?[^"']*)?)\1/,
      );
      if (environmentImport?.[2] === undefined) {
        throw new Error("Vite client did not import its environment module");
      }
      const environment = await requestTestServer(port, { path: environmentImport[2] });
      expect(environment.status).toBe(200);
      // Execute the browser defines without depending on Vite's serialization or host globals.
      const payload = runInNewContext(
        `${environment.body}\nprocess.env.TNL_PROJECT_RUNTIME`,
        {},
        { timeout: 1000 },
      );
      expect(JSON.parse(payload)).toEqual(testPublicProject(true));

      const token = extractViteWebSocketToken(client.body);
      const { message: socketMessage, socket } = await openTestWebSocketWithMessage(
        port,
        `/?token=${encodeURIComponent(token)}`,
        { origin: "https://api.member.example", protocol: "vite-hmr" },
      );
      onTestFinished(() => socket.close());
      const message = JSON.parse(socketMessage) as { type?: string };
      expect(message.type).toBe("connected");
      const updateMessage = waitForWebSocketMessage(socket, 30_000);
      await writeFile(source, originalSource.replace("Vite fixture", "Vite fixture HMR"));
      const update = JSON.parse(await updateMessage) as {
        type?: string;
        updates?: { acceptedPath?: string; path?: string }[];
      };
      expect(update).toMatchObject({
        type: "update",
        updates: [expect.objectContaining({ acceptedPath: "/src/main.ts", path: "/src/main.ts" })],
      });
      const updatedModule = await requestTestServer(port, {
        path: `/src/main.ts?t=${Date.now()}`,
      });
      expect(updatedModule.status).toBe(200);
      expect(updatedModule.body).toContain("Vite fixture HMR");
    } catch (error) {
      throw new Error(`${errorMessage(error)}\n${process_.output()}`, { cause: error });
    }
  },
);

test("registers the actual next port selected by Vite", async () => {
  const bootstrap = await startTestBootstrap();
  onTestFinished(() => bootstrap.close());
  const port = await reserveLoopbackPort();
  const releasePort = await occupyLoopbackPort(port);
  onTestFinished(releasePort);
  const process_ = startViteFixture(port, bootstrap.environment, "127.0.0.1");
  onTestFinished(() => process_.close());

  expect(await waitForBootstrapRequest(bootstrap)).toMatchObject({
    body: { protocol: 1, framework: "vite" },
    path: "/v1/configure",
  });
  const target = await waitForBootstrapRequest(bootstrap, 1);
  expect(target.path).toBe("/v1/target");
  const selectedTarget = (target.body as { target: string }).target;
  expect(selectedTarget).toMatch(/^http:\/\/127\.0\.0\.1:[0-9]+$/);
  const selectedPort = Number(new URL(selectedTarget).port);
  expect(selectedPort).toBeGreaterThan(port);
  await expect(requestTestServer(selectedPort)).resolves.toMatchObject({ status: 200 });
  expect(process_.output()).toContain(`Port ${port} is in use, trying another one`);
});

test("reports a fallback listener for server-side forced-port validation", async () => {
  const bootstrap = await startTestBootstrap();
  onTestFinished(() => bootstrap.close());
  const port = await reserveLoopbackPort();
  const releasePort = await occupyLoopbackPort(port);
  onTestFinished(releasePort);
  const process_ = startViteFixture(
    port,
    {
      ...bootstrap.environment,
      TNL_DEV_PORT: String(port),
    },
    "127.0.0.1",
  );
  onTestFinished(() => process_.close());

  expect(await waitForBootstrapRequest(bootstrap)).toMatchObject({
    body: { protocol: 1, framework: "vite" },
    path: "/v1/configure",
  });
  const registration = await waitForBootstrapRequest(bootstrap, 1);
  expect(registration.path).toBe("/v1/target");
  const selectedPort = Number(new URL((registration.body as { target: string }).target).port);
  expect(selectedPort).toBeGreaterThan(port);
  expect(process_.output()).toContain(`Port ${port} is in use, trying another one`);
});

test("registers and serves an IPv6 loopback target", async () => {
  const port = await reserveLoopbackPort("::1");
  const bootstrap = await startTestBootstrap();
  onTestFinished(() => bootstrap.close());
  const process_ = startViteFixture(port, bootstrap.environment, "::1");
  onTestFinished(() => process_.close());

  try {
    expect(await waitForBootstrapRequest(bootstrap, 1)).toMatchObject({
      body: { protocol: 1, framework: "vite", target: `http://[::1]:${port}` },
      path: "/v1/target",
    });
    await expect(requestTestServer(port, { address: "::1" })).resolves.toMatchObject({
      status: 200,
    });
  } catch (error) {
    throw new Error(`${errorMessage(error)}\n${process_.output()}`, { cause: error });
  }
});

function runtimeDefine(runningUnderTnlDev: boolean, apiHostname = "api.member.example") {
  const payload = JSON.stringify({
    memberNamespace: "member.example",
    runningUnderTnlDev,
    services: {
      api: {
        memberNamespace: "member.example",
        hostname: apiHostname,
        url: `https://${apiHostname}`,
      },
      web: {
        memberNamespace: "member.example",
        hostname: "web.member.example",
        url: "https://web.member.example",
      },
    },
  });
  return {
    define: {
      "process.env.TNL_PROJECT_RUNTIME": JSON.stringify(payload),
    },
  };
}

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

function startViteFixture(port: number, environment: Record<string, string>, host?: string) {
  const fixture = fileURLToPath(new URL("fixtures/vite/app", import.meta.url));
  const viteCLI = fileURLToPath(new URL("node_modules/vite/bin/vite.js", import.meta.url));
  return startTestProcess(process.execPath, [viteCLI], {
    cwd: fixture,
    env: {
      ...process.env,
      ...environment,
      TNL_FIXTURE_HOST: host,
      TNL_FIXTURE_PORT: String(port),
    },
  });
}

function extractViteWebSocketToken(client: string): string {
  const match = client.match(/const wsToken = "([^"]+)"/);
  if (match?.[1] === undefined) {
    throw new Error("Vite client did not include a WebSocket token");
  }
  return match[1];
}
