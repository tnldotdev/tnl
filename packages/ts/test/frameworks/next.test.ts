import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, onTestFinished, test, vi } from "vitest";
import * as z from "zod";
import {
  createProjectFixture,
  temporaryDirectory,
  testPublicProject,
  withCurrentDirectory,
} from "../helpers/project.js";
import {
  occupyPort,
  openTestWebSocket,
  openTestWebSocketWithMessage,
  requestTestServer,
  findAvailableLoopbackPort,
  waitForWebSocketMessage,
} from "../helpers/http-websocket.js";
import { startTestBootstrap } from "../helpers/bootstrap.js";
import { withProcessEnvironment } from "../helpers/environment.js";
import { startFrameworkFixture } from "../helpers/framework.js";
import { withTnl, type NextConfigContext } from "@tnldotdev/tnl/next";
import { testAliasAssignment } from "../helpers/project.js";

vi.mock("../../dist/internal/publisher/app.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../dist/internal/publisher/app.js")>();
  return {
    ...actual,
    prepareService: async (
      options: import("../../dist/internal/publisher/app.js").PrepareOptions,
      framework: Parameters<typeof actual.createPreparedService>[1],
      signal?: AbortSignal,
    ) => {
      const prepared = await actual.createPreparedService(
        options,
        framework,
        {
          start: async () => JSON.parse(process.env.APP_TEST_ENDPOINT ?? "null"),
          request: actual.runtimeRequest,
        },
        () => {},
        signal,
      );
      onTestFinished(() => prepared.close());
      return prepared;
    },
  };
});

test.each([
  [401, "runtime.authentication_required"],
  [400, "TNL_CLIENT_SERVER_UNAVAILABLE"],
  [503, "runtime.unavailable"],
] as const)("keeps Next local when preparation returns %s/%s", async (status, code) => {
  const bootstrap = await startTestBootstrap({
    status,
    responseBody: JSON.stringify({ code, message: "private diagnostic must not be logged" }),
  });
  const config = { reactStrictMode: true, allowedDevOrigins: ["existing.example"] };
  const warning = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  await withProcessEnvironment(
    { ...bootstrap.environment, __NEXT_PRIVATE_ORIGIN: "http://127.0.0.1:3200" },
    async () => {
      const result = await withTnl(config)(developmentPhase, context);
      expect(result).toMatchObject(config);
      expect(JSON.parse(result.env?.TNL_PROJECT_RUNTIME ?? "null")).toEqual({
        namespace: "",
        services: {},
        dev: true,
      });
      await expect(
        withTnl(config, { preview: "required" })(developmentPhase, context),
      ).rejects.toBeInstanceOf(Error);
    },
  );
  expect(warning).toHaveBeenCalled();
  expect(warning.mock.calls.flat().join("")).not.toContain("private diagnostic");
});

test("disabled Next preserves origins without preparing or requiring a bound target", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment(bootstrap.environment, async () => {
    const result = await withTnl({ allowedDevOrigins: ["existing.example"] }, { preview: false })(
      developmentPhase,
      context,
    );
    expect(result.allowedDevOrigins).toEqual(["existing.example"]);
    expect(JSON.parse(result.env?.TNL_PROJECT_RUNTIME ?? "null")).toEqual({
      namespace: "",
      services: {},
      dev: true,
    });
  });
  expect(bootstrap.requests).toHaveLength(0);
});

test("local preview override can disable required Next publication without a bound target", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment({ ...bootstrap.environment, TNL_PREVIEW: "off" }, async () => {
    const result = await withTnl({}, { preview: "required" })(developmentPhase, context);
    expect(JSON.parse(result.env?.TNL_PROJECT_RUNTIME ?? "null")).toEqual({
      namespace: "",
      services: {},
      dev: true,
    });
  });
  expect(bootstrap.requests).toHaveLength(0);
});

test("invalid Next preview mode fails before networking", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment({ ...bootstrap.environment, TNL_PREVIEW: "invalid" }, async () => {
    await expect(withTnl()(developmentPhase, context)).rejects.toMatchObject({
      code: "sdk.configuration_invalid",
    });
  });
  expect(bootstrap.requests).toHaveLength(0);
});

test("optional Next registration failure releases preparation and preserves local config", async () => {
  const bootstrap = await startTestBootstrap({
    status: 503,
    failurePath: "/v1/register",
    responseBody: JSON.stringify({ code: "runtime.unavailable", message: "unavailable" }),
  });
  const beforeExitListeners = process.listenerCount("beforeExit");
  await withProcessEnvironment(
    { ...bootstrap.environment, __NEXT_PRIVATE_ORIGIN: "http://127.0.0.1:3200" },
    async () => {
      const result = await withTnl({ allowedDevOrigins: ["existing.example"] })(
        developmentPhase,
        context,
      );
      expect(result.allowedDevOrigins).toEqual(["existing.example"]);
      expect(JSON.parse(result.env?.TNL_PROJECT_RUNTIME ?? "null")).toEqual({
        namespace: "",
        services: {},
        dev: true,
      });
    },
  );
  expect(bootstrap.requests.at(-1)?.path).toBe("/v1/unregister");
  expect(process.listenerCount("beforeExit")).toBe(beforeExitListeners);
});

test.each([
  [
    "without preview access",
    {
      status: 401,
      responseBody: JSON.stringify({ code: "runtime.authentication_required", message: "sign in" }),
    },
  ],
  [
    "when control is unavailable",
    {
      status: 503,
      responseBody: JSON.stringify({
        code: "TNL_CLIENT_SERVER_UNAVAILABLE",
        message: "control is offline",
      }),
    },
  ],
] as const)(
  "runs real Next %s without publishing",
  { timeout: 60_000 },
  async (_case, bootstrapOptions) => {
    const port = await findAvailableLoopbackPort();
    const fixture = await startFrameworkFixture(
      "next",
      ["dev", "--port", String(port)],
      {},
      bootstrapOptions,
    );
    await fixture.diagnose(async () => {
      const page = await requestTestServer(port, { host: "localhost" });
      expect(page.status).toBe(200);
      expect(page.body).toContain("Next.js fixture");
      expect(page.body).toContain("under-dev:true");
      expect(fixture.requests.length).toBeGreaterThanOrEqual(1);
      expect(fixture.requests.every(({ path }) => path === "/v1/prepare")).toBe(true);
      expect(fixture.output()).toContain("continuing local development");
      expect(fixture.output()).not.toContain(bootstrapOptions.responseBody);
    });
  },
);

test("runs real Next with tnl disabled and no login", { timeout: 60_000 }, async () => {
  const port = await findAvailableLoopbackPort();
  const fixture = await startFrameworkFixture("next", ["dev", "--port", String(port)], {
    TNL_PREVIEW: "off",
    TNL_APP_ENDPOINT: undefined,
  });
  await fixture.diagnose(async () => {
    const page = await requestTestServer(port, { host: "localhost" });
    expect(page.status).toBe(200);
    expect(page.body).toContain("Next.js fixture");
    expect(page.body).toContain("under-dev:true");
    expect(fixture.requests).toEqual([]);
  });
});

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
    await expect(wrapped(productionPhase, context)).resolves.toBe(config);

    const directory = await temporaryDirectory("tnl-next-empty-");
    await withCurrentDirectory(directory, async () => {
      await expect(wrapped(developmentPhase, context)).rejects.toMatchObject({
        code: "sdk.target_invalid",
      });
    });
  });

  test("injects generated project metadata only during plain development", async () => {
    const project = await createProjectFixture("tnl-next-project-");
    const config = { reactStrictMode: true };
    const bootstrap = await startTestBootstrap();
    await withProcessEnvironment(
      { ...bootstrap.environment, __NEXT_PRIVATE_ORIGIN: "http://127.0.0.1:3200" },
      async () =>
        withCurrentDirectory(project.serviceDirectory, async () => {
          const local = await withTnl(config)(developmentPhase, context);
          expect(local).toMatchObject({ reactStrictMode: true });
          expect(JSON.parse(local.env?.TNL_PROJECT_RUNTIME ?? "null")).toEqual({
            namespace: "member.example",
            dev: true,
            services: {
              api: {
                protocol: "http",
                port: 443,
                public: true,
                hostname: "api.member.example",
                namespace: "member.example",
                url: "https://api.member.example",
              },
              web: {
                protocol: "http",
                port: 443,
                public: true,
                hostname: "web.member.example",
                namespace: "member.example",
                url: "https://web.member.example",
              },
            },
          });
          expect(bootstrap.requests[0]?.body).not.toHaveProperty("service");
          await expect(withTnl(config)(productionPhase, context)).resolves.toBe(config);
        }),
    );
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
        project: runtimeProject,
        version: 1,
        publicURL: "https://override.example",
        service: "api",
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
    ).toMatchObject([
      { body: { version: 1, framework: "next" }, path: "/v1/prepare" },
      {
        body: { version: 1, target: "http://127.0.0.1:3200" },
        path: "/v1/register",
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
      },
      async () => await withTnl()(developmentPhase, context),
    );
    expect(bootstrap.requests[1]?.body).toMatchObject({
      version: 1,
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
      { ...bootstrap.environment, ...environment },
      async () =>
        await expect(withTnl()(developmentPhase, context)).rejects.toMatchObject({
          code: "sdk.target_invalid",
        }),
    );
    expect(bootstrap.requests).toHaveLength(0);
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
        body: { version: 1, framework: "next" },
        path: "/v1/prepare",
      });
      expect(await fixture.request(1)).toMatchObject({
        body: { version: 1, target: `http://127.0.0.1:${port}` },
        path: "/v1/register",
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
      // keep one listener across progress and completion frames from the same read.
      const updateMessage = waitForWebSocketMessage(socket, 30_000, (value) => {
        const update = z.object({ type: z.optional(z.string()) }).parse(JSON.parse(value));
        return update.type === "built";
      });
      await writeFile(
        pageSource,
        originalPageSource.replace("Next.js fixture", "Next.js fixture refreshed"),
      );
      const update = z
        .object({ type: z.optional(z.string()) })
        .parse(JSON.parse(await updateMessage));
      expect(update.type).toBe("built");
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
      body: { version: 1, framework: "next" },
      path: "/v1/prepare",
    });
    const registration = await fixture.request(1);
    expect(registration.path).toBe("/v1/register");
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
