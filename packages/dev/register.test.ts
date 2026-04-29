import { describe, expect, onTestFinished, test } from "vitest";
import { readDevEnvironment, registerTarget } from "./dist/index.js";
import { startTestBootstrap } from "./test-helper.js";

describe("tnl dev environment", () => {
  test("is inert outside tnl dev", async () => {
    expect(readDevEnvironment({})).toBeNull();
    await expect(registerTarget("INVALID", 0, {})).resolves.toBeNull();
  });

  test("rejects unsupported protocols", () => {
    expect(() => readDevEnvironment({ TNL_DEV_PROTOCOL: "2" })).toThrow(
      /unsupported tnl dev protocol/,
    );
  });

  test("rejects incomplete environments locally", () => {
    const environment: Record<string, string> = {
      TNL_DEV_PROTOCOL: "1",
      TNL_DEV_SOCKET: "/tmp/tnl-test.sock",
      TNL_DEV_TOKEN: "a".repeat(64),
      TNL_PUBLIC_HOSTNAME: "demo.tnl.dev",
      TNL_PUBLIC_URL: "https://demo.tnl.dev",
    };
    for (const name of [
      "TNL_DEV_SOCKET",
      "TNL_DEV_TOKEN",
      "TNL_PUBLIC_HOSTNAME",
      "TNL_PUBLIC_URL",
    ]) {
      const incomplete = { ...environment };
      delete incomplete[name];
      expect(() => readDevEnvironment(incomplete), name).toThrow(new RegExp(`${name} is required`));
    }
  });
});

describe("target registration", () => {
  test("sends the exact authenticated registration request", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());

    const session = await registerTarget("vite", 5173, bootstrap.environment);

    expect(session).toMatchObject({
      hostname: "demo.tnl.dev",
      port: 5173,
      publicURL: "https://demo.tnl.dev",
    });
    expect(bootstrap.requests).toEqual([
      {
        authorization: `Bearer ${"a".repeat(64)}`,
        body: { protocol: 1, framework: "vite", port: 5173 },
        contentType: "application/json",
        method: "POST",
        path: "/v1/target",
      },
    ]);
  });

  test("includes bounded rejection details", async () => {
    const bootstrap = await startTestBootstrap({
      responseBody: "target already registered",
      status: 409,
    });
    onTestFinished(() => bootstrap.close());

    await expect(registerTarget("next", 3000, bootstrap.environment)).rejects.toThrow(
      /status 409: target already registered/,
    );
  });

  test("rejects oversized responses", async () => {
    const bootstrap = await startTestBootstrap({ responseBody: "x".repeat(5000), status: 409 });
    onTestFinished(() => bootstrap.close());

    await expect(registerTarget("next", 3000, bootstrap.environment)).rejects.toThrow(
      /oversized response/,
    );
  });

  test.each([
    ["framework", "Next.js", 3000],
    ["port", "next", 0],
  ])("validates the %s before sending", async (_name, framework, port) => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());

    await expect(registerTarget(framework, port, bootstrap.environment)).rejects.toThrow();
    expect(bootstrap.requests).toHaveLength(0);
  });
});
