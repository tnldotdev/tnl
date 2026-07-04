import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, onTestFinished, test } from "vitest";
import {
  canonicalLoopbackTarget,
  discoverProject,
  readDevelopmentContext,
  registerLocalTarget,
  requestTunnelAssignment,
  runtimePayload,
  socketIdentity,
} from "./dist/internal/dev.js";
import { startTestBootstrap, testProjectDocument, testPublicProject } from "./test-helper.js";

describe("development context", () => {
  test("is inert without a project or tnl dev", async () => {
    const directory = await temporaryDirectory("tnl-empty-");
    expect(readDevelopmentContext({}, directory)).toEqual({
      bootstrap: null,
      localProject: null,
    });
  });

  test("accepts only the complete final protocol environment", () => {
    expect(() => readDevelopmentContext({ TNL_DEV_PROTOCOL: "2" })).toThrow(
      /unsupported tnl dev protocol/,
    );
    expect(() => readDevelopmentContext({ TNL_DEV_SOCKET: "/tmp/tnl.sock" })).toThrow(
      /TNL_DEV_PROTOCOL=1 is required/,
    );
    expect(() => readDevelopmentContext({ TNL_DEV_PROTOCOL: "1" })).toThrow(
      /TNL_DEV_SOCKET is required/,
    );
    expect(() =>
      readDevelopmentContext({
        TNL_DEV_PORT: "0",
        TNL_DEV_PROTOCOL: "1",
        TNL_DEV_SOCKET: "/tmp/tnl.sock",
      }),
    ).toThrow(/TNL_DEV_PORT must be a port/);
  });

  test("discovers strict generated metadata and its service socket", async () => {
    if (process.getuid === undefined) {
      return;
    }
    const projectRoot = await temporaryDirectory("tnl-project-");
    const serviceDirectory = path.join(projectRoot, "apps", "api");
    await mkdir(path.join(projectRoot, ".tnl"), { recursive: true });
    await mkdir(serviceDirectory, { recursive: true });
    await writeFile(
      path.join(projectRoot, ".tnl", "project.json"),
      `${JSON.stringify(testProjectDocument())}\n`,
    );
    const runtimeRoot = await temporaryDirectory("tnl-runtime-");
    const runtimeDirectory = path.join(runtimeRoot, `tnl-${process.getuid()}`);
    await mkdir(runtimeDirectory, { mode: 0o700 });
    const socket = path.join(runtimeDirectory, `dev-${socketIdentity(projectRoot, "api")}.sock`);
    const bootstrap = await startTestBootstrap({ socket });
    onTestFinished(() => bootstrap.close());

    const context = readDevelopmentContext({ XDG_RUNTIME_DIR: runtimeRoot }, serviceDirectory);
    expect(context.bootstrap).toEqual({ socket });
    expect(context.localProject).toEqual({
      memberNamespace: "member.example",
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
    expect(discoverProject(serviceDirectory)?.service).toBe("api");
  });

  test.each([
    ["malformed JSON", "{"],
    ["unknown field", JSON.stringify({ ...testProjectDocument(), unknown: true })],
  ])("rejects %s project metadata", async (_name, contents) => {
    const root = await temporaryDirectory("tnl-invalid-project-");
    await mkdir(path.join(root, ".tnl"));
    await writeFile(path.join(root, ".tnl", "project.json"), contents);
    expect(() => discoverProject(root)).toThrow();
  });

  test("rejects oversized projects and service sets", async () => {
    const root = await temporaryDirectory("tnl-bounded-project-");
    await mkdir(path.join(root, ".tnl"));
    const file = path.join(root, ".tnl", "project.json");
    await writeFile(file, "x".repeat(64 * 1024 + 1));
    expect(() => discoverProject(root)).toThrow(/exceeds 65536 bytes/);

    const document = testProjectDocument();
    const service = document.services.api;
    const services = Object.fromEntries(
      Array.from({ length: 33 }, (_, index) => [`s${index}`, service]),
    );
    await writeFile(file, JSON.stringify({ ...document, services }));
    expect(() => discoverProject(root)).toThrow(/at most 32 services/);

    await writeFile(file, JSON.stringify({ ...testProjectDocument(), runningUnderTnlDev: true }));
    expect(() => discoverProject(root)).toThrow(/cannot be marked as running under tnl dev/);
  });
});

describe("protocol v1", () => {
  test("accepts an invocation hostname override reflected in project metadata", async () => {
    const project = testPublicProject(true);
    const bootstrap = await startTestBootstrap({
      responseBody: JSON.stringify({
        ...validAssignmentResponse(),
        hostname: "override.example",
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
        publicURL: "https://override.example",
      }),
    });
    onTestFinished(() => bootstrap.close());
    const context = readDevelopmentContext(bootstrap.environment);
    expect(context.bootstrap).not.toBeNull();
    if (context.bootstrap === null) {
      return;
    }

    const assignment = await requestTunnelAssignment("vite", context.bootstrap);
    expect(assignment).toMatchObject({
      framework: "vite",
      hostname: "override.example",
      memberNamespace: "member.example",
      publicURL: "https://override.example",
      service: "api",
      tunnelID: `tunnel_${"b".repeat(32)}`,
    });
    expect(JSON.parse(runtimePayload(assignment.project, true))).toEqual({
      memberNamespace: "member.example",
      runningUnderTnlDev: true,
      services: {
        api: {
          hostname: "override.example",
          memberNamespace: "member.example",
          url: "https://override.example",
        },
        web: {
          hostname: "web.member.example",
          memberNamespace: "member.example",
          url: "https://web.member.example",
        },
      },
    });
    await registerLocalTarget(assignment, canonicalLoopbackTarget("127.0.0.2", 5174));
    expect(bootstrap.requests).toEqual([
      {
        authorization: undefined,
        body: { protocol: 1, framework: "vite" },
        contentType: "application/json",
        method: "POST",
        path: "/v1/configure",
      },
      {
        authorization: undefined,
        body: { protocol: 1, framework: "vite", target: "http://127.0.0.2:5174" },
        contentType: "application/json",
        method: "POST",
        path: "/v1/target",
      },
    ]);
  });

  test("rejects malformed and oversized responses", async () => {
    const malformed = await startTestBootstrap({
      responseBody: JSON.stringify({ ...validAssignmentResponse(), unexpected: true }),
    });
    onTestFinished(() => malformed.close());
    const malformedContext = readDevelopmentContext(malformed.environment);
    await expect(
      requestTunnelAssignment("next", requiredBootstrap(malformedContext.bootstrap)),
    ).rejects.toThrow(/invalid shape/);

    const oversized = await startTestBootstrap({
      responseBody: "x".repeat(64 * 1024 + 1),
      status: 409,
    });
    onTestFinished(() => oversized.close());
    const oversizedContext = readDevelopmentContext(oversized.environment);
    await expect(
      requestTunnelAssignment("next", requiredBootstrap(oversizedContext.bootstrap)),
    ).rejects.toThrow(/oversized response/);
  });

  test.each([
    ["protocol", { protocol: 2 }, /inconsistent tunnel assignment/],
    ["tunnel ID", { tunnelID: "invalid" }, /invalid tunnel ID/],
    ["service", { service: "API" }, /invalid service/],
    ["unknown project service", { service: "worker" }, /inconsistent project metadata/],
    ["member namespace", { memberNamespace: "Member.example" }, /member namespace is invalid/],
    ["hostname", { hostname: "API.member.example" }, /public hostname is invalid/],
    ["public URL", { publicURL: "http://api.member.example" }, /invalid public URL/],
    ["project", { project: { ...testPublicProject(true), unexpected: true } }, /invalid shape/],
    [
      "project member namespace",
      {
        project: {
          ...testPublicProject(true),
          services: {
            ...testPublicProject(true).services,
            api: {
              ...testPublicProject(true).services.api,
              memberNamespace: "other.example",
            },
          },
        },
      },
      /inconsistent project metadata/,
    ],
  ])("rejects an invalid assignment $0", async (_name, replacement, expected) => {
    const bootstrap = await startTestBootstrap({
      responseBody: JSON.stringify({ ...validAssignmentResponse(), ...replacement }),
    });
    onTestFinished(() => bootstrap.close());
    const context = readDevelopmentContext(bootstrap.environment);
    await expect(
      requestTunnelAssignment("vite", requiredBootstrap(context.bootstrap)),
    ).rejects.toThrow(expected);
  });

  test("validates framework and listener targets before sending", async () => {
    const bootstrap = await startTestBootstrap();
    onTestFinished(() => bootstrap.close());
    const context = readDevelopmentContext(bootstrap.environment);
    const connection = requiredBootstrap(context.bootstrap);
    await expect(requestTunnelAssignment("Next.js", connection)).rejects.toThrow(/framework name/);
    expect(() => canonicalLoopbackTarget("127.0.0.1", 0)).toThrow(/listener port/);
    expect(() => canonicalLoopbackTarget("192.0.2.1", 3000)).toThrow(/loopback listener/);
    expect(bootstrap.requests).toHaveLength(0);
  });

  test.each([
    ["localhost", 3000, "http://127.0.0.1:3000"],
    ["LOCALHOST", 3001, "http://127.0.0.1:3001"],
    ["0.0.0.0", 3002, "http://127.0.0.1:3002"],
    ["127.0.0.42", 3003, "http://127.0.0.42:3003"],
    ["::", 3004, "http://[::1]:3004"],
    ["::1", 3005, "http://[::1]:3005"],
    ["[::1]", 3006, "http://[::1]:3006"],
  ])("constructs a canonical target for %s", (host, port, expected) => {
    expect(canonicalLoopbackTarget(host, port)).toBe(expected);
  });
});

test("socket identity matches the shared Go fixture", async () => {
  const vectors = JSON.parse(
    await readFile(
      new URL("../../cmd/tnl/testdata/dev-socket-vectors.json", import.meta.url),
      "utf8",
    ),
  ) as Array<{ projectRoot: string; service: string; digest: string }>;
  expect(vectors).not.toHaveLength(0);
  for (const vector of vectors) {
    expect(socketIdentity(vector.projectRoot, vector.service)).toBe(vector.digest);
  }
});

function validAssignmentResponse() {
  return {
    hostname: "api.member.example",
    memberNamespace: "member.example",
    project: testPublicProject(true),
    protocol: 1,
    publicURL: "https://api.member.example",
    service: "api",
    tunnelID: `tunnel_${"b".repeat(32)}`,
  };
}

function requiredBootstrap<T>(value: T | null): T {
  if (value === null) {
    throw new Error("test bootstrap was not available");
  }
  return value;
}

async function temporaryDirectory(prefix: string): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), prefix));
  onTestFinished(() => rm(directory, { force: true, recursive: true }));
  return directory;
}
