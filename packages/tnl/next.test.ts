import { readFile, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, onTestFinished, test } from "vitest";
import {
  createProjectFixture,
  errorMessage,
  occupyPort,
  openTestWebSocket,
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
import { withTnl, type NextConfigContext } from "@tnldotdev/tnl/next";

const productionPhase = "phase-production-build";
const developmentPhase = "phase-development-server";
const context: NextConfigContext = { defaultConfig: {} };

describe("withTnl", () => {
  test("preserves builds and development without generated metadata", async () => {
    const config = { reactStrictMode: true };
    const wrapped = withTnl(config);
    expect(() => withTnl({}, {} as never)).toThrow(/does not accept tunnel options/);
    await expect(wrapped(productionPhase, context)).resolves.toBe(config);

    const directory = await temporaryDirectory("tnl-next-empty-");
    await withCurrentDirectory(directory, async () => {
      await expect(wrapped(developmentPhase, context)).resolves.toBe(config);
    });
  });

  test("injects generated project metadata only during plain development", async () => {
    const project = await createProjectFixture("tnl-next-project-");
    const config = { reactStrictMode: true };
    await withCurrentDirectory(project.serviceDirectory, async () => {
      const local = await withTnl(config)(developmentPhase, context);
      expect(local).toMatchObject({ reactStrictMode: true });
      expect(JSON.parse(local.env?.TNL_PROJECT_RUNTIME ?? "null")).toEqual({
        memberNamespace: "member.example",
        runningUnderTnlDev: false,
        services: {
          api: {
            hostname: "api.member.example",
            memberNamespace: "member.example",
            url: "https://api.member.example",
          },
          web: {
            hostname: "web.member.example",
            memberNamespace: "member.example",
            url: "https://web.member.example",
          },
        },
      });
      await expect(withTnl(config)(productionPhase, context)).resolves.toBe(config);
    });
  });

  test("uses an invocation hostname override for Next.js coordination only", async () => {
    const project = testPublicProject(true);
    const runtimeProject = {
      ...project,
      services: {
        ...project.services,
        api: {
          ...project.services.api,
          hostname: "override.example",
          url: "https://override.example",
        },
      },
    };
    const bootstrap = await startTestBootstrap({
      responseBody: JSON.stringify({
        hostname: "override.example",
        memberNamespace: "member.example",
        project: runtimeProject,
        protocol: 1,
        publicURL: "https://override.example",
        service: "api",
        tunnelID: `tunnel_${"b".repeat(32)}`,
      }),
    });
    onTestFinished(() => bootstrap.close());
    const originalContext: NextConfigContext = { defaultConfig: { reactStrictMode: false } };
    let receivedPhase: string | undefined;
    let receivedContext: NextConfigContext | undefined;

    const result = await withProcessEnvironment(
      {
        ...bootstrap.environment,
        __NEXT_PRIVATE_ORIGIN: "http://127.0.0.1:3200",
        PORT: "3200",
        TNL_DEV_PORT: "3200",
      },
      async () => {
        const wrapped = withTnl(async (phase, factoryContext) => {
          receivedPhase = phase;
          receivedContext = factoryContext;
          return {
            allowedDevOrigins: ["existing.example", "api.member.example"],
            env: { EXISTING_PUBLIC_VALUE: "existing" },
            reactStrictMode: true,
          };
        });
        return await wrapped(developmentPhase, originalContext);
      },
    );

    expect(result.allowedDevOrigins).toEqual([
      "existing.example",
      "api.member.example",
      "override.example",
    ]);
    expect(result.env?.EXISTING_PUBLIC_VALUE).toBe("existing");
    expect(JSON.parse(result.env?.TNL_PROJECT_RUNTIME ?? "null")).toEqual(runtimeProject);
    expect(receivedPhase).toBe(developmentPhase);
    expect(receivedContext).toBe(originalContext);
    expect(
      bootstrap.requests.map(({ body, path: requestPath }) => ({ body, path: requestPath })),
    ).toEqual([
      { body: { protocol: 1, framework: "next" }, path: "/v1/configure" },
      {
        body: { protocol: 1, framework: "next", target: "http://127.0.0.1:3200" },
        path: "/v1/target",
      },
    ]);
  });

  test.each([
    {
      expected: "http://127.0.0.1:3100",
      origin: "http://localhost:3100",
      source: "default hostname",
    },
    {
      expected: "http://127.0.0.2:3200",
      origin: "http://127.0.0.2:3200",
      source: "custom IPv4 hostname",
    },
    {
      expected: "http://127.0.0.1:3300",
      origin: "http://0.0.0.0:3300",
      source: "IPv4 wildcard hostname",
    },
    {
      expected: "http://[::1]:3400",
      origin: "http://[::1]:3400",
      source: "IPv6 loopback hostname",
    },
    {
      expected: "http://[::1]:3500",
      origin: "http://[::]:3500",
      source: "IPv6 wildcard hostname",
    },
  ])("registers the post-bind $source target", async ({ origin, expected }) => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    const port = new URL(origin).port;
    await withProcessEnvironment(
      {
        ...bootstrap.environment,
        __NEXT_PRIVATE_ORIGIN: origin,
        PORT: port,
        TNL_DEV_PORT: undefined,
      },
      async () => await withTnl()(developmentPhase, context),
    );
    expect(bootstrap.requests[1]?.body).toEqual({
      protocol: 1,
      framework: "next",
      target: expected,
    });
  });

  test.each([
    {
      environment: { __NEXT_PRIVATE_ORIGIN: undefined, PORT: undefined },
      expected: /did not report its bound development listener/,
      name: "missing post-bind origin",
    },
    {
      environment: { __NEXT_PRIVATE_ORIGIN: "http://192.0.2.1:3000", PORT: "3000" },
      expected: /loopback listener/,
      name: "non-loopback target",
    },
    {
      environment: { __NEXT_PRIVATE_ORIGIN: "http://127.0.0.1:3000", PORT: "3001" },
      expected: /inconsistent development listener ports/,
      name: "inconsistent PORT",
    },
  ])("rejects $name before networking", async ({ environment, expected }) => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    await withProcessEnvironment(
      { ...bootstrap.environment, TNL_DEV_PORT: undefined, ...environment },
      async () => await expect(withTnl()(developmentPhase, context)).rejects.toThrow(expected),
    );
    expect(bootstrap.requests).toHaveLength(0);
  });

  test("preserves a loopback host when tnl dev forces only the port", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    await withProcessEnvironment(
      {
        ...bootstrap.environment,
        __NEXT_PRIVATE_ORIGIN: "http://[::1]:3200",
        PORT: "3200",
        TNL_DEV_PORT: "3200",
      },
      async () => await withTnl()(developmentPhase, context),
    );
    expect(bootstrap.requests[1]?.body).toEqual({
      protocol: 1,
      framework: "next",
      target: "http://[::1]:3200",
    });
  });
});

test(
  "runs Next.js with protected development assets, runtime metadata, and HMR",
  { timeout: 60_000 },
  async () => {
    const fixture = fileURLToPath(new URL("fixtures/next/app", import.meta.url));
    const pageSource = fileURLToPath(new URL("fixtures/next/app/app/page.tsx", import.meta.url));
    const originalPageSource = await readFile(pageSource, "utf8");
    const nextOutput = fileURLToPath(new URL("fixtures/next/app/.next", import.meta.url));
    const generatedFixtureFiles = [
      nextOutput,
      fileURLToPath(new URL("fixtures/next/app/next-env.d.ts", import.meta.url)),
      fileURLToPath(new URL("fixtures/next/app/tsconfig.json", import.meta.url)),
    ];
    await Promise.all(
      generatedFixtureFiles.map((file) => rm(file, { force: true, recursive: true })),
    );

    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    const nextCLI = fileURLToPath(new URL("node_modules/next/dist/bin/next", import.meta.url));
    const port = await reserveLoopbackPort();
    const process_ = startTestProcess(process.execPath, [nextCLI, "dev", "--port", String(port)], {
      cwd: fixture,
      env: { ...process.env, ...bootstrap.environment },
    });
    onTestFinished(async () => {
      await process_.close();
      await writeFile(pageSource, originalPageSource);
      await Promise.all(
        generatedFixtureFiles.map((file) => rm(file, { force: true, recursive: true })),
      );
    });

    try {
      expect(await waitForBootstrapRequest(bootstrap)).toMatchObject({
        body: { protocol: 1, framework: "next" },
        path: "/v1/configure",
      });
      expect(await waitForBootstrapRequest(bootstrap, 1)).toMatchObject({
        body: { protocol: 1, framework: "next", target: `http://127.0.0.1:${port}` },
        path: "/v1/target",
      });

      const page = await requestTestServer(port);
      expect(page.status).toBe(200);
      expect(page.body).toContain("Next.js fixture");
      expect(page.body).toContain("url:https://api.member.example");
      expect(page.body).toContain("hostname:api.member.example");
      expect(page.body).toContain("namespace:member.example");
      expect(page.body).toContain("under-dev:true");
      expect(page.headers["x-tnl-fixture"]).toBe("next");

      const assetPath = extractNextAssetPath(page.body);
      await expect(
        requestTestServer(port, {
          headers: { Origin: "https://api.member.example" },
          path: assetPath,
        }),
      ).resolves.toMatchObject({ status: 200 });
      await expect(
        requestTestServer(port, {
          headers: { Origin: "https://attacker.example" },
          path: assetPath,
        }),
      ).resolves.toMatchObject({ status: 403 });

      const { message: socketMessage, socket } = await openTestWebSocketWithMessage(
        port,
        "/_next/hmr?id=tnl-test",
        { origin: "https://api.member.example" },
      );
      onTestFinished(() => socket.close());
      const message = JSON.parse(socketMessage) as { type?: string };
      expect(["isrManifest", "turbopack-connected"]).toContain(message.type);
      let connected = message.type === "turbopack-connected";
      while (!connected) {
        const nextMessage = JSON.parse(await waitForWebSocketMessage(socket, 30_000)) as {
          type?: string;
        };
        connected = nextMessage.type === "turbopack-connected";
      }
      let updateMessage = waitForWebSocketMessage(socket, 30_000);
      await writeFile(
        pageSource,
        originalPageSource.replace("Next.js fixture", "Next.js fixture refreshed"),
      );
      let updateType = "";
      while (updateType !== "built") {
        const update = JSON.parse(await updateMessage) as { type?: string };
        updateType = update.type ?? "";
        if (updateType !== "built") {
          updateMessage = waitForWebSocketMessage(socket, 30_000);
        }
      }
      await expect
        .poll(
          async () => {
            const updatedPage = await requestTestServer(port);
            return updatedPage.status === 200 ? updatedPage.body : "";
          },
          { timeout: 30_000 },
        )
        .toContain("Next.js fixture refreshed");
      await expect(
        openTestWebSocket(port, "/_next/hmr?id=tnl-attacker", {
          origin: "https://attacker.example",
        }),
      ).rejects.toThrow();
    } catch (error) {
      throw new Error(`${errorMessage(error)}\n${process_.output()}`, { cause: error });
    }
  },
);

test("registers the actual fallback port selected by Next.js", { timeout: 60_000 }, async () => {
  const fixture = fileURLToPath(new URL("fixtures/next/app", import.meta.url));
  const nextOutput = fileURLToPath(new URL("fixtures/next/app/.next", import.meta.url));
  const generatedFixtureFiles = [
    nextOutput,
    fileURLToPath(new URL("fixtures/next/app/next-env.d.ts", import.meta.url)),
    fileURLToPath(new URL("fixtures/next/app/tsconfig.json", import.meta.url)),
  ];
  await Promise.all(
    generatedFixtureFiles.map((file) => rm(file, { force: true, recursive: true })),
  );

  let releasePort: (() => Promise<void>) | undefined;
  try {
    releasePort = await occupyPort(3000);
    onTestFinished(releasePort);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EADDRINUSE") {
      throw error;
    }
  }
  const bootstrap = await startTestBootstrap();
  onTestFinished(() => bootstrap.close());
  const nextCLI = fileURLToPath(new URL("node_modules/next/dist/bin/next", import.meta.url));
  const process_ = startTestProcess(process.execPath, [nextCLI, "dev"], {
    cwd: fixture,
    env: {
      ...process.env,
      ...bootstrap.environment,
      PORT: undefined,
      TNL_DEV_PORT: undefined,
    },
  });
  onTestFinished(async () => {
    await process_.close();
    await Promise.all(
      generatedFixtureFiles.map((file) => rm(file, { force: true, recursive: true })),
    );
  });

  try {
    expect(await waitForBootstrapRequest(bootstrap)).toMatchObject({
      body: { protocol: 1, framework: "next" },
      path: "/v1/configure",
    });
    const registration = await waitForBootstrapRequest(bootstrap, 1);
    expect(registration.path).toBe("/v1/target");
    const target = (registration.body as { target: string }).target;
    expect(target).toMatch(/^http:\/\/127\.0\.0\.1:[0-9]+$/);
    const selectedPort = Number(new URL(target).port);
    expect(selectedPort).toBeGreaterThan(3000);
    await expect(requestTestServer(selectedPort)).resolves.toMatchObject({ status: 200 });
    expect(process_.output()).toContain("Port 3000 is in use");
  } catch (error) {
    throw new Error(`${errorMessage(error)}\n${process_.output()}`, { cause: error });
  }
});

function extractNextAssetPath(html: string): string {
  const match = html.match(/src="([^"]*\/_next\/static\/[^"]+\.js[^"]*)"/);
  if (match?.[1] === undefined) {
    throw new Error("Next.js page did not include a JavaScript asset");
  }
  return match[1].replaceAll("&amp;", "&");
}
