import { describe, expect, onTestFinished, test } from "vitest";
import {
  publicTunnelEnvironment,
  readDevEnvironment,
  registerLocalPort,
  requestTunnelAssignment,
  type TnlTunnelAssignment,
} from "./dist/index.js";
import { startTestBootstrap } from "./test-helper.js";

describe("tnl dev environment", () => {
  test("is inert outside tnl dev", async () => {
    expect(readDevEnvironment({})).toBeNull();
    let configured = false;
    await expect(
      requestTunnelAssignment(
        {
          framework: "INVALID",
          options: () => {
            configured = true;
            return {};
          },
        },
        {},
      ),
    ).resolves.toBeNull();
    expect(configured).toBe(false);
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
    };
    for (const name of ["TNL_DEV_SOCKET", "TNL_DEV_TOKEN"]) {
      const incomplete = { ...environment };
      delete incomplete[name];
      expect(() => readDevEnvironment(incomplete), name).toThrow(new RegExp(`${name} is required`));
    }
  });

  test("rejects invalid tokens", () => {
    expect(() =>
      readDevEnvironment({
        TNL_DEV_PROTOCOL: "1",
        TNL_DEV_SOCKET: "/tmp/tnl-test.sock",
        TNL_DEV_TOKEN: "invalid",
      }),
    ).toThrow(/TNL_DEV_TOKEN is invalid/);
  });

  test.each(["0", "65536", "1.5"])("rejects invalid port %s", (port) => {
    expect(() =>
      readDevEnvironment({
        TNL_DEV_PORT: port,
        TNL_DEV_PROTOCOL: "1",
        TNL_DEV_SOCKET: "/tmp/tnl-test.sock",
        TNL_DEV_TOKEN: "a".repeat(64),
      }),
    ).toThrow(/TNL_DEV_PORT must be a port/);
  });
});

describe("tunnel assignment and local port registration", () => {
  test("sends exact authenticated requests and provides worktree context", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    let worktreeLabel = "";

    const assignment = await requestTunnelAssignment(
      {
        framework: "vite",
        options: ({ cwd, env, worktree }) => {
          expect(cwd).toBe(process.cwd());
          expect(env.DEPLOYMENT_SLOT).toBe("review-3");
          expect(worktree).toMatchObject({
            isGit: true,
            name: path.basename(process.cwd()),
            root: process.cwd(),
          });
          expect(worktree.label).not.toHaveLength(0);
          worktreeLabel = worktree.label;
          return {
            controlURL: "https://tnl.example.com",
            host: `${worktree.label}.example.com`,
            allowIP: ["198.51.100.0/24"],
            allowCurrentIP: true,
          };
        },
      },
      { ...bootstrap.environment, DEPLOYMENT_SLOT: "review-3" },
    );
    expect(assignment).not.toBeNull();
    if (assignment === null) {
      return;
    }
    expect(assignment).toMatchObject({
      framework: "vite",
      hostname: "demo.tnl.dev",
      publicURL: "https://demo.tnl.dev",
      tunnelID: `tunnel_${"b".repeat(32)}`,
    });
    expect(publicTunnelEnvironment(assignment, "NEXT_PUBLIC_")).toEqual({
      NEXT_PUBLIC_TNL_HOSTNAME: "demo.tnl.dev",
      NEXT_PUBLIC_TNL_TUNNEL_ID: `tunnel_${"b".repeat(32)}`,
      NEXT_PUBLIC_TNL_URL: "https://demo.tnl.dev",
    });
    await registerLocalPort(assignment, 5174);

    expect(bootstrap.requests).toEqual([
      {
        authorization: `Bearer ${"a".repeat(64)}`,
        body: {
          protocol: 1,
          framework: "vite",
          options: {
            controlURL: "https://tnl.example.com",
            host: `${worktreeLabel}.example.com`,
            allowIP: ["198.51.100.0/24"],
            allowCurrentIP: true,
          },
        },
        contentType: "application/json",
        method: "POST",
        path: "/v1/configure",
      },
      {
        authorization: `Bearer ${"a".repeat(64)}`,
        body: { protocol: 1, framework: "vite", port: 5174 },
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

    await expect(
      requestTunnelAssignment({ framework: "next" }, bootstrap.environment),
    ).rejects.toThrow(/status 409: target already registered/);
  });

  test("rejects oversized responses", async () => {
    const bootstrap = await startTestBootstrap({ responseBody: "x".repeat(5000), status: 409 });
    onTestFinished(() => bootstrap.close());

    await expect(
      requestTunnelAssignment({ framework: "next" }, bootstrap.environment),
    ).rejects.toThrow(/oversized response/);
  });

  test("validates framework and port before sending", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());

    await expect(
      requestTunnelAssignment({ framework: "Next.js" }, bootstrap.environment),
    ).rejects.toThrow(/framework name/);
    await expect(registerLocalPort(fakeAssignment(bootstrap.environment), 0)).rejects.toThrow(
      /local port/,
    );
    expect(bootstrap.requests).toHaveLength(0);
  });

  test.each([
    [[], /tnl options must be an object/],
    [{ host: "" }, /tnl host must be a non-empty string/],
    [{ host: "a".repeat(254) }, /tnl host must be a non-empty string/],
    [{ allowIP: "198.51.100.1" }, /tnl allowIP must be an array/],
    [{ allowIP: Array.from({ length: 65 }, () => "198.51.100.1") }, /at most 64 entries/],
    [{ allowCurrentIP: "yes" }, /tnl allowCurrentIP must be a boolean/],
  ])("rejects invalid options %# before sending", async (options, expected) => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());

    await expect(
      requestTunnelAssignment(
        { framework: "vite", options: options as never },
        bootstrap.environment,
      ),
    ).rejects.toThrow(expected);
    expect(bootstrap.requests).toHaveLength(0);
  });

  test.each([
    ["protocol", { ...validAssignmentResponse, protocol: 2 }, /inconsistent tunnel assignment/],
    ["tunnel ID", { ...validAssignmentResponse, tunnelID: "invalid" }, /invalid tunnel ID/],
    [
      "hostname",
      { ...validAssignmentResponse, hostname: "Demo.tnl.dev" },
      /invalid public hostname/,
    ],
    [
      "absolute hostname",
      { ...validAssignmentResponse, hostname: "demo.tnl.dev." },
      /invalid public hostname/,
    ],
    [
      "public URL",
      { ...validAssignmentResponse, publicURL: "http://demo.tnl.dev" },
      /invalid public URL/,
    ],
  ])("rejects an invalid assignment $0", async (_name, response, expected) => {
    const bootstrap = await startTestBootstrap({ responseBody: JSON.stringify(response) });
    onTestFinished(() => bootstrap.close());

    await expect(
      requestTunnelAssignment({ framework: "vite" }, bootstrap.environment),
    ).rejects.toThrow(expected);
  });
});

const validAssignmentResponse = {
  hostname: "demo.tnl.dev",
  protocol: 1,
  publicURL: "https://demo.tnl.dev",
  tunnelID: `tunnel_${"b".repeat(32)}`,
};

function fakeAssignment(environment: Record<string, string>): TnlTunnelAssignment {
  return {
    framework: "vite",
    hostname: "demo.tnl.dev",
    publicURL: "https://demo.tnl.dev",
    tunnelID: `tunnel_${"b".repeat(32)}`,
    socket: environment.TNL_DEV_SOCKET ?? "",
    token: environment.TNL_DEV_TOKEN ?? "",
  } as unknown as TnlTunnelAssignment;
}
