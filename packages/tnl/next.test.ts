import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import * as z from "zod";
import {
  createProjectFixture,
  temporaryDirectory,
  testPublicProject,
  withCurrentDirectory,
} from "./test-helper/project.js";
import {
  occupyPort,
  openTestWebSocket,
  openTestWebSocketWithMessage,
  requestTestServer,
  findAvailableLoopbackPort,
  waitForWebSocketMessage,
} from "./test-helper/http-websocket.js";
import { startTestBootstrap } from "./test-helper/bootstrap.js";
import { withProcessEnvironment } from "./test-helper/environment.js";
import { startFrameworkFixture } from "./test-helper/framework.js";
import { withTnl, type NextConfigContext } from "@tnldotdev/tnl/next";
import { testAliasAssignment } from "./test-helper/project.js";

const productionPhase = "phase-production-build";
const developmentPhase = "phase-development-server";
const context: NextConfigContext = { defaultConfig: {} };

describe("withTnl", () => {
  test("allows entry and mounted service aliases in development", async () => {
    const bootstrap = await startTestBootstrap({
      responseBody: JSON.stringify(testAliasAssignment()),
    });
    await withProcessEnvironment(
      { ...bootstrap.environment, __NEXT_PRIVATE_ORIGIN: "http://127.0.0.1:3200" },
      async () => {
        const result = await withTnl({ allowedDevOrigins: ["existing.example"] })(
          developmentPhase,
          context,
        );
        expect(result.allowedDevOrigins).toEqual([
          "existing.example",
          "api.member.example",
          "review-api.member.example",
          "review-web.member.example",
        ]);
      },
    );
  });
  test("rejects non-string development origins before requesting an assignment", async () => {
    const bootstrap = await startTestBootstrap();
    await withProcessEnvironment(
      { ...bootstrap.environment, __NEXT_PRIVATE_ORIGIN: "http://127.0.0.1:3200" },
      async () => {
        await expect(
          withTnl({ allowedDevOrigins: ["existing.example", 42] as unknown as string[] })(
            developmentPhase,
            context,
          ),
        ).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
      },
    );
    expect(bootstrap.requests).toHaveLength(0);
  });
  test("preserves builds and development without generated metadata", async () => {
    const config = { reactStrictMode: true };
    const wrapped = withTnl(config);
    expect(() => withTnl({}, {} as never)).toThrow(/framework configuration is invalid/);
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
        namespace: "member.example",
        dev: false,
        services: {
          api: {
            hostname: "api.member.example",
            namespace: "member.example",
            url: "https://api.member.example",
          },
          web: {
            hostname: "web.member.example",
            namespace: "member.example",
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
        namespace: "member.example",
        project: runtimeProject,
        protocol: 1,
        publicURL: "https://override.example",
        service: "api",
        tunnelID: `tun_${"b".repeat(22)}`,
      }),
    });
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
      source: "IPv6 localhost address",
    },
    {
      expected: "http://[::1]:3500",
      origin: "http://[::]:3500",
      source: "IPv6 wildcard hostname",
    },
    {
      expected: "http://192.0.2.1:3000",
      origin: "http://192.0.2.1:3000",
      source: "non-loopback hostname",
    },
  ])("registers the post-bind $source target", async ({ origin, expected }) => {
    const bootstrap = await startTestBootstrap();
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
      environment: { __NEXT_PRIVATE_ORIGIN: "http://127.0.0.1:3000", PORT: "3001" },
      expected: /inconsistent development listener ports/,
      name: "inconsistent PORT",
    },
  ])("rejects $name before networking", async ({ environment }) => {
    const bootstrap = await startTestBootstrap();
    await withProcessEnvironment(
      { ...bootstrap.environment, TNL_DEV_PORT: undefined, ...environment },
      async () =>
        await expect(withTnl()(developmentPhase, context)).rejects.toMatchObject({
          code: "sdk.target_invalid",
        }),
    );
    expect(bootstrap.requests).toHaveLength(0);
  });

  test("preserves a local host when tnl dev forces only the port", async () => {
    const bootstrap = await startTestBootstrap();
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
    const port = await findAvailableLoopbackPort();
    const fixture = await startFrameworkFixture("next", ["dev", "--port", String(port)]);
    const pageSource = join(fixture.directory, "app", "page.tsx");
    const originalPageSource = await readFile(pageSource, "utf8");

    await fixture.diagnose(async () => {
      expect(await fixture.request()).toMatchObject({
        body: { protocol: 1, framework: "next" },
        path: "/v1/configure",
      });
      expect(await fixture.request(1)).toMatchObject({
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
      const message = z.object({ type: z.optional(z.string()) }).parse(JSON.parse(socketMessage));
      expect(["isrManifest", "turbopack-connected"]).toContain(message.type);
      // startup frames can arrive together; either accepted frame confirms the connection.
      let updateMessage = waitForWebSocketMessage(socket, 30_000);
      await writeFile(
        pageSource,
        originalPageSource.replace("Next.js fixture", "Next.js fixture refreshed"),
      );
      let updateType = "";
      while (updateType !== "built") {
        const update = z
          .object({ type: z.optional(z.string()) })
          .parse(JSON.parse(await updateMessage));
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
    });
  },
);

test("registers the actual fallback port selected by Next.js", { timeout: 60_000 }, async () => {
  try {
    await occupyPort(3000);
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "EADDRINUSE")) {
      throw error;
    }
  }
  const fixture = await startFrameworkFixture("next", ["dev"]);

  await fixture.diagnose(async () => {
    expect(await fixture.request()).toMatchObject({
      body: { protocol: 1, framework: "next" },
      path: "/v1/configure",
    });
    const registration = await fixture.request(1);
    expect(registration.path).toBe("/v1/target");
    const target = z.object({ target: z.string() }).parse(registration.body).target;
    expect(target).toMatch(/^http:\/\/127\.0\.0\.1:[0-9]+$/);
    const selectedPort = Number(new URL(target).port);
    expect(selectedPort).toBeGreaterThan(3000);
    await expect(requestTestServer(selectedPort)).resolves.toMatchObject({ status: 200 });
    expect(fixture.output()).toContain("Port 3000 is in use");
  });
});

function extractNextAssetPath(html: string): string {
  const match = html.match(/src="([^"]*\/_next\/static\/[^"]+\.js[^"]*)"/);
  if (match?.[1] === undefined) {
    throw new Error("Next.js page did not include a JavaScript asset");
  }
  return match[1].replaceAll("&amp;", "&");
}
