import { rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, onTestFinished, test } from "vitest";
import {
  errorMessage,
  openTestWebSocket,
  openTestWebSocketWithMessage,
  requestTestServer,
  startTestBootstrap,
  startTestProcess,
  waitForBootstrapRequest,
  withProcessEnvironment,
} from "../dev/test-helper.js";
import { withTnl, type NextConfigContext } from "./dist/index.js";

const productionPhase = "phase-production-build";
const developmentPhase = "phase-development-server";
const context: NextConfigContext = { defaultConfig: {} };

describe("withTnl", () => {
  test("leaves production and local development unchanged", async () => {
    const config = { reactStrictMode: true };
    const wrapped = withTnl(config);

    await expect(wrapped(productionPhase, context)).resolves.toBe(config);
    await expect(wrapped(developmentPhase, context)).resolves.toBe(config);
  });

  test("preserves async configuration and adds the assigned origin once", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    const originalContext: NextConfigContext = { defaultConfig: { reactStrictMode: false } };
    let receivedPhase: string | undefined;
    let receivedContext: NextConfigContext | undefined;
    let requestedName: string | undefined;

    await withProcessEnvironment(
      {
        ...bootstrap.environment,
        PORT: "3200",
        TNL_DEV_PORT: "3200",
      },
      async () => {
        const wrapped = withTnl(
          async (phase, factoryContext) => {
            receivedPhase = phase;
            receivedContext = factoryContext;
            return {
              allowedDevOrigins: ["existing.example", "demo.tnl.dev"],
              reactStrictMode: true,
            };
          },
          ({ cwd, env, worktree }) => {
            expect(cwd).toBe(process.cwd());
            expect(env.TNL_DEV_PORT).toBe("3200");
            requestedName = `${worktree.label}.example.com`;
            return { name: requestedName, allowCurrentIP: true };
          },
        );

        await expect(wrapped(developmentPhase, originalContext)).resolves.toMatchObject({
          allowedDevOrigins: ["existing.example", "demo.tnl.dev"],
          reactStrictMode: true,
        });
      },
    );

    expect(receivedPhase).toBe(developmentPhase);
    expect(receivedContext).toBe(originalContext);
    expect(bootstrap.requests[0]).toMatchObject({
      path: "/v1/configure",
      body: {
        protocol: 1,
        framework: "next",
        options: { name: requestedName, allowCurrentIP: true },
      },
    });
    expect(bootstrap.requests[1]).toMatchObject({
      path: "/v1/target",
      body: {
        protocol: 1,
        framework: "next",
        port: 3200,
      },
    });
  });

  test.each([
    { port: 3200, forcedPort: "3200" },
    { port: 3100, forcedPort: undefined },
  ])("registers Next.js final port $port", async ({ port, forcedPort }) => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());

    await withProcessEnvironment(
      {
        ...bootstrap.environment,
        PORT: String(port),
        TNL_DEV_PORT: forcedPort,
      },
      async () => withTnl()(developmentPhase, context),
    );

    expect(bootstrap.requests[0]?.body).toEqual({
      protocol: 1,
      framework: "next",
      options: {},
    });
    expect(bootstrap.requests[1]?.body).toEqual({
      protocol: 1,
      framework: "next",
      port,
    });
  });

  test("rejects a tnl dev --port mismatch", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    await withProcessEnvironment(
      { ...bootstrap.environment, PORT: "3200", TNL_DEV_PORT: "3300" },
      async () => {
        await expect(withTnl()(developmentPhase, context)).rejects.toThrow(
          /tnl dev --port requires 3300/,
        );
      },
    );
    expect(bootstrap.requests).toHaveLength(0);
  });
});

test("runs Next.js with protected development assets and HMR", { timeout: 60_000 }, async () => {
  const fixture = fileURLToPath(new URL("fixtures/app", import.meta.url));
  const nextOutput = fileURLToPath(new URL("fixtures/app/.next", import.meta.url));
  const generatedFixtureFiles = [
    nextOutput,
    fileURLToPath(new URL("fixtures/app/next-env.d.ts", import.meta.url)),
    fileURLToPath(new URL("fixtures/app/tsconfig.json", import.meta.url)),
  ];
  await Promise.all(
    generatedFixtureFiles.map((file) => rm(file, { force: true, recursive: true })),
  );

  const bootstrap = await startTestBootstrap();
  onTestFinished(() => bootstrap.close());
  const nextCLI = fileURLToPath(new URL("node_modules/next/dist/bin/next", import.meta.url));
  const process_ = startTestProcess(
    process.execPath,
    [nextCLI, "dev", "--hostname", "127.0.0.1", "--port", "0"],
    { cwd: fixture, env: { ...process.env, ...bootstrap.environment } },
  );
  onTestFinished(async () => {
    await process_.close();
    await Promise.all(
      generatedFixtureFiles.map((file) => rm(file, { force: true, recursive: true })),
    );
  });

  try {
    const assignment = await waitForBootstrapRequest(bootstrap);
    expect(assignment).toMatchObject({
      body: { protocol: 1, framework: "next", options: {} },
      path: "/v1/configure",
    });
    const target = await waitForBootstrapRequest(bootstrap, 1);
    expect(target.path).toBe("/v1/target");
    expect(target.body).toMatchObject({ protocol: 1, framework: "next" });
    const port = (target.body as { port: number }).port;
    expect(port).toBeGreaterThan(0);

    const page = await requestTestServer(port);
    expect(page.status).toBe(200);
    expect(page.body).toContain("Next.js fixture");
    expect(page.headers["x-tnl-fixture"]).toBe("next");

    const assetPath = extractNextAssetPath(page.body);
    const assignedAsset = await requestTestServer(port, {
      headers: { Origin: "https://demo.tnl.dev" },
      path: assetPath,
    });
    expect(assignedAsset.status).toBe(200);

    const attackerAsset = await requestTestServer(port, {
      headers: { Origin: "https://attacker.example" },
      path: assetPath,
    });
    expect(attackerAsset.status).toBe(403);

    const { message: socketMessage, socket } = await openTestWebSocketWithMessage(
      port,
      "/_next/hmr?id=tnl-test",
      { origin: "https://demo.tnl.dev" },
    );
    onTestFinished(() => socket.close());
    const message = JSON.parse(socketMessage) as { type?: string };
    expect(["isrManifest", "turbopack-connected"]).toContain(message.type);

    const attackerHmr = await requestTestServer(port, {
      headers: { Origin: "https://attacker.example" },
      path: "/_next/hmr?id=tnl-attacker",
    });
    expect(attackerHmr.status).toBe(403);
    await expect(
      openTestWebSocket(port, "/_next/hmr?id=tnl-attacker", {
        origin: "https://attacker.example",
      }),
    ).rejects.toThrow();
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
