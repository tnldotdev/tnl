import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import type { ConfigEnv, Plugin, UserConfig } from "vite";
import { describe, expect, test } from "vitest";
import {
  createProjectFixture,
  temporaryDirectory,
  testPublicProject,
  withCurrentDirectory,
} from "./test-helper/project.js";
import {
  holdLoopbackPort,
  openTestWebSocketWithMessage,
  requestTestServer,
  findAvailableLoopbackPort,
  waitForWebSocketMessage,
} from "./test-helper/http-websocket.js";
import { startTestBootstrap } from "./test-helper/bootstrap.js";
import { withProcessEnvironment } from "./test-helper/environment.js";
import { startFrameworkFixture } from "./test-helper/framework.js";
import { viteClientConnection } from "./test-helper/vite-client.js";
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
    const port = await findAvailableLoopbackPort();
    const fixture = await startViteFixture(port);
    const source = join(fixture.directory, "src", "main.ts");
    const originalSource = await readFile(source, "utf8");

    await fixture.diagnose(async () => {
      expect(await fixture.request()).toMatchObject({
        body: { protocol: 1, framework: "vite" },
        path: "/v1/configure",
      });
      expect(await fixture.request(1)).toMatchObject({
        body: { protocol: 1, framework: "vite", target: `http://127.0.0.1:${port}` },
        path: "/v1/target",
      });

      const page = await requestTestServer(port);
      expect(page.status).toBe(200);
      expect(page.body).toContain("Vite fixture");
      expect(page.headers["x-tnl-fixture"]).toBe("vite");
      const appModule = await requestTestServer(port, { path: "/src/main.ts" });
      expect(appModule.status).toBe(200);
      await expect(requestTestServer(port, { host: "existing.example" })).resolves.toMatchObject({
        status: 200,
      });
      await expect(requestTestServer(port, { host: "attacker.example" })).resolves.toMatchObject({
        status: 403,
      });

      const client = await requestTestServer(port, { path: "/@vite/client" });
      expect(client.status).toBe(200);
      const { environmentPath, token } = viteClientConnection(client.body);
      const environment = await requestTestServer(port, { path: environmentPath });
      expect(environment.status).toBe(200);
      // Execute the browser defines without depending on Vite's serialization or host globals.
      const payload = runInNewContext(
        `${environment.body}\nprocess.env.TNL_PROJECT_RUNTIME`,
        {},
        { timeout: 1000 },
      );
      expect(JSON.parse(payload)).toEqual(testPublicProject(true));

      const { message: socketMessage, socket } = await openTestWebSocketWithMessage(
        port,
        `/?token=${encodeURIComponent(token)}`,
        { origin: "https://api.member.example", protocol: "vite-hmr" },
      );
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
    });
  },
);

test("registers the actual next port selected by Vite", async () => {
  const { port } = await holdLoopbackPort();
  const fixture = await startViteFixture(port, {}, "127.0.0.1");

  await fixture.diagnose(async () => {
    expect(await fixture.request()).toMatchObject({
      body: { protocol: 1, framework: "vite" },
      path: "/v1/configure",
    });
    const target = await fixture.request(1);
    expect(target.path).toBe("/v1/target");
    const selectedTarget = (target.body as { target: string }).target;
    expect(selectedTarget).toMatch(/^http:\/\/127\.0\.0\.1:[0-9]+$/);
    const selectedPort = Number(new URL(selectedTarget).port);
    expect(selectedPort).toBeGreaterThan(port);
    await expect(requestTestServer(selectedPort)).resolves.toMatchObject({ status: 200 });
    expect(fixture.output()).toContain(`Port ${port} is in use, trying another one`);
  });
});

test("reports a fallback listener for server-side forced-port validation", async () => {
  const { port } = await holdLoopbackPort();
  const fixture = await startViteFixture(
    port,
    {
      TNL_DEV_PORT: String(port),
    },
    "127.0.0.1",
  );

  await fixture.diagnose(async () => {
    expect(await fixture.request()).toMatchObject({
      body: { protocol: 1, framework: "vite" },
      path: "/v1/configure",
    });
    const registration = await fixture.request(1);
    expect(registration.path).toBe("/v1/target");
    const selectedPort = Number(new URL((registration.body as { target: string }).target).port);
    expect(selectedPort).toBeGreaterThan(port);
    expect(fixture.output()).toContain(`Port ${port} is in use, trying another one`);
  });
});

test("registers and serves an IPv6 loopback target", async () => {
  const port = await findAvailableLoopbackPort("::1");
  const fixture = await startViteFixture(port, {}, "::1");

  await fixture.diagnose(async () => {
    expect(await fixture.request(1)).toMatchObject({
      body: { protocol: 1, framework: "vite", target: `http://[::1]:${port}` },
      path: "/v1/target",
    });
    await expect(requestTestServer(port, { address: "::1" })).resolves.toMatchObject({
      status: 200,
    });
  });
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

function startViteFixture(
  port: number,
  environment: Readonly<Record<string, string | undefined>> = {},
  host?: string,
) {
  return startFrameworkFixture("vite", [], {
    ...environment,
    TNL_FIXTURE_HOST: host,
    TNL_FIXTURE_PORT: String(port),
  });
}
