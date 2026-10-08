import { once } from "node:events";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import * as http from "node:http";
import * as path from "node:path";
import { describe, expect, onTestFinished, test } from "vitest";
import * as z from "zod";
import {
  canonicalLoopbackTarget,
  discoverProject,
  parseListenerPort,
  readDevelopmentContext,
  registerLocalTarget,
  requestTunnelAssignment,
  runtimePayload,
  socketIdentity,
} from "./dist/internal/dev.js";
import { parseRuntimePayload } from "./dist/internal/runtime.js";
import { TnlError } from "./dist/errors.js";
import {
  createProjectFixture,
  temporaryDirectory,
  testProjectDocument,
  testPublicProject,
} from "./test-helper/project.js";
import { startTestBootstrap } from "./test-helper/bootstrap.js";

describe("development context", () => {
  test.each(["", "0", "65536", " 80", "+80", "8.0", "8e1", "80\n"])(
    "rejects invalid string listener port %j",
    (value) =>
      expect(() => parseListenerPort(value, "test")).toThrow(new TnlError("sdk.target_invalid")),
  );

  test.each([
    ["1", 1],
    ["65535", 65535],
    ["00080", 80],
  ] as const)("accepts string listener port %s", (value, expected) =>
    expect(parseListenerPort(value, "test")).toBe(expected),
  );

  test.each([
    [
      "duplicate hostname",
      { api: testProjectDocument().services.api, web: testProjectDocument().services.api },
      false,
    ],
    [
      "unknown service field",
      { api: { ...testProjectDocument().services.api, secret: "not-public" } },
      false,
    ],
    [
      "URL mismatch",
      { api: { ...testProjectDocument().services.api, url: "https://other.example" } },
      false,
    ],
    ["invalid name", { "api-": testProjectDocument().services.api }, false],
    ["32-byte name", { ["a".repeat(32)]: testProjectDocument().services.api }, true],
    ["33-byte name", { ["a".repeat(33)]: testProjectDocument().services.api }, false],
    [
      "different namespace",
      { api: { ...testProjectDocument().services.api, namespace: "other.example" } },
      true,
    ],
    ...[32, 33].map(
      (count) =>
        [
          `${count} services`,
          Object.fromEntries(
            Array.from({ length: count }, (_, index) => [
              `s${index}`,
              {
                namespace: "member.example",
                hostname: `s${index}.member.example`,
                url: `https://s${index}.member.example`,
              },
            ]),
          ),
          count === 32,
        ] as const,
    ),
  ] as const)("uses the same metadata contract for %s", async (_name, services, valid) => {
    const root = await temporaryDirectory("tnl-metadata-contract-");
    await mkdir(path.join(root, ".tnl"));
    const project = { namespace: "member.example", services, dev: false };
    await writeFile(
      path.join(root, ".tnl", "project.json"),
      JSON.stringify({
        ...project,
        version: 2,
        serviceDirectories: Object.fromEntries(Object.keys(services).map((name) => [name, name])),
      }),
    );
    if (!valid) {
      expect(() => parseRuntimePayload(JSON.stringify(project))).toThrow();
      expect(() => discoverProject(root)).toThrow();
      return;
    }
    const runtime = parseRuntimePayload(JSON.stringify(project));
    const discovery = discoverProject(root);
    expect(discovery?.project.services).toEqual(runtime?.services);
    expect(Object.keys(discovery?.project ?? {}).sort()).toEqual(["namespace", "services"]);
    expect(Object.isFrozen(discovery?.project)).toBe(true);
    expect(Object.isFrozen(discovery?.project.services)).toBe(true);
    expect(Object.values(discovery?.project.services ?? {}).every(Object.isFrozen)).toBe(true);
  });

  test("is inert without a project or tnl dev", async () => {
    const directory = await temporaryDirectory("tnl-empty-");
    expect(readDevelopmentContext({}, directory)).toEqual({
      bootstrap: null,
      localProject: null,
    });
  });

  test("does not borrow project metadata across a nested Git worktree boundary", async () => {
    const root = await temporaryDirectory("tnl-ancestor-project-");
    await mkdir(path.join(root, ".tnl"));
    await writeFile(path.join(root, ".tnl", "project.json"), JSON.stringify(testProjectDocument()));
    const nested = path.join(root, "nested");
    await mkdir(nested);
    await writeFile(path.join(nested, ".git"), "gitdir: /tmp/nested-worktree\n");
    expect(discoverProject(nested)).toBeNull();
  });

  test("accepts only the complete final protocol environment", () => {
    expect(() => readDevelopmentContext({ TNL_DEV_PROTOCOL: "2" })).toThrow(
      /unsupported tnl dev protocol/,
    );
    expect(() => readDevelopmentContext({ TNL_DEV_SOCKET: "/tmp/tnl.sock" })).toThrow(
      new TnlError("sdk.configuration_invalid"),
    );
    expect(() => readDevelopmentContext({ TNL_DEV_PROTOCOL: "1" })).toThrow(
      new TnlError("sdk.configuration_invalid"),
    );
    expect(() =>
      readDevelopmentContext({
        TNL_DEV_PORT: "0",
        TNL_DEV_PROTOCOL: "1",
        TNL_DEV_SOCKET: "/tmp/tnl.sock",
      }),
    ).toThrow(new TnlError("sdk.target_invalid"));
  });

  test("discovers strict generated metadata and its service socket", async () => {
    if (process.getuid === undefined) {
      return;
    }
    const { root: projectRoot, serviceDirectory } = await createProjectFixture("tnl-project-");
    const runtimeRoot = await temporaryDirectory("tnl-runtime-");
    const runtimeDirectory = path.join(runtimeRoot, `tnl-${process.getuid()}`);
    await mkdir(runtimeDirectory, { mode: 0o700 });
    const socket = path.join(runtimeDirectory, `dev-${socketIdentity(projectRoot, "api")}.sock`);
    await startTestBootstrap({ socket });

    const context = readDevelopmentContext({ XDG_RUNTIME_DIR: runtimeRoot }, serviceDirectory);
    expect(context.bootstrap).toEqual({ socket });
    expect(context.localProject).toEqual({
      namespace: "member.example",
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
    expect(() => discoverProject(root)).toThrow(new TnlError("sdk.runtime_invalid"));

    const document = testProjectDocument();
    const service = document.services.api;
    const services = Object.fromEntries(
      Array.from({ length: 33 }, (_, index) => [`s${index}`, service]),
    );
    await writeFile(file, JSON.stringify({ ...document, services }));
    expect(() => discoverProject(root)).toThrow(new TnlError("sdk.runtime_invalid"));

    await writeFile(file, JSON.stringify({ ...testProjectDocument(), dev: true }));
    expect(() => discoverProject(root)).toThrow(new TnlError("sdk.runtime_invalid"));
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
    const context = readDevelopmentContext(bootstrap.environment);
    expect(context.bootstrap).not.toBeNull();
    if (context.bootstrap === null) {
      return;
    }

    const assignment = await requestTunnelAssignment("vite", context.bootstrap);
    expect(assignment).toMatchObject({
      framework: "vite",
      hostname: "override.example",
      namespace: "member.example",
      publicURL: "https://override.example",
      service: "api",
      tunnelID: `tun_${"b".repeat(22)}`,
    });
    expect(JSON.parse(runtimePayload(assignment.project, true))).toEqual({
      namespace: "member.example",
      dev: true,
      services: {
        api: {
          hostname: "override.example",
          namespace: "member.example",
          url: "https://override.example",
        },
        web: {
          hostname: "web.member.example",
          namespace: "member.example",
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
    const malformedContext = readDevelopmentContext(malformed.environment);
    await expect(
      requestTunnelAssignment("next", requiredBootstrap(malformedContext.bootstrap)),
    ).rejects.toMatchObject({ code: "sdk.response_invalid", class: "internal" });

    const oversized = await startTestBootstrap({
      responseBody: "x".repeat(64 * 1024 + 1),
      status: 409,
    });
    const oversizedContext = readDevelopmentContext(oversized.environment);
    await expect(
      requestTunnelAssignment("next", requiredBootstrap(oversizedContext.bootstrap)),
    ).rejects.toMatchObject({ code: "sdk.response_invalid" });
  });

  test("wraps socket connection failures with configuration request context", async () => {
    const directory = await temporaryDirectory("tnl-missing-socket-");
    const failure = await rejection(
      requestTunnelAssignment("vite", { socket: path.join(directory, "missing.sock") }),
    );
    expect(failure).toMatchObject({
      code: "sdk.dev_unavailable",
      class: "unavailable",
      retry: "later",
    });
    expect(failure.cause).toMatchObject({ code: "ENOENT" });
  });

  test("rejects a response that closes after a partial body", async () => {
    const directory = await temporaryDirectory("tnl-partial-response-");
    const socket = path.join(directory, "control.sock");
    const server = http.createServer((_request, response) => {
      response.writeHead(200, {
        "Content-Length": "100",
        "Content-Type": "application/json",
      });
      response.write("{");
      setImmediate(() => response.destroy());
    });
    server.listen(socket);
    await once(server, "listening");
    onTestFinished(async () => {
      const closed = new Promise<void>((resolve) => server.close(() => resolve()));
      server.closeAllConnections();
      await closed;
    });

    const failure = await rejection(requestTunnelAssignment("vite", { socket }));
    expect(failure).toMatchObject({ code: "sdk.dev_unavailable" });
    expect(failure.cause).toMatchObject({ code: "ECONNRESET" });
  });

  test.each([
    ["protocol", { protocol: 2 }, /inconsistent tunnel assignment/],
    ["tunnel ID", { tunnelID: "invalid" }, /invalid tunnel ID/],
    ["service", { service: "API" }, /invalid service/],
    ["unknown project service", { service: "worker" }, /inconsistent project metadata/],
    ["namespace", { namespace: "Member.example" }, /namespace is invalid/],
    ["hostname", { hostname: "API.member.example" }, /public hostname is invalid/],
    ["public URL", { publicURL: "http://api.member.example" }, /invalid public URL/],
    ["project", { project: { ...testPublicProject(true), unexpected: true } }, /invalid shape/],
    [
      "project namespace",
      {
        project: {
          ...testPublicProject(true),
          services: {
            ...testPublicProject(true).services,
            api: {
              ...testPublicProject(true).services.api,
              namespace: "other.example",
            },
          },
        },
      },
      /inconsistent project metadata/,
    ],
  ])("rejects an invalid assignment $0", async (_name, replacement, _expected) => {
    const bootstrap = await startTestBootstrap({
      responseBody: JSON.stringify({ ...validAssignmentResponse(), ...replacement }),
    });
    const context = readDevelopmentContext(bootstrap.environment);
    await expect(
      requestTunnelAssignment("vite", requiredBootstrap(context.bootstrap)),
    ).rejects.toMatchObject({ code: "sdk.response_invalid" });
  });

  test("validates framework and listener targets before sending", async () => {
    const bootstrap = await startTestBootstrap();
    const context = readDevelopmentContext(bootstrap.environment);
    const connection = requiredBootstrap(context.bootstrap);
    await expect(requestTunnelAssignment("Next.js", connection)).rejects.toMatchObject({
      code: "sdk.configuration_invalid",
    });
    expect(() => canonicalLoopbackTarget("127.0.0.1", 0)).toThrow(
      new TnlError("sdk.target_invalid"),
    );
    expect(() => canonicalLoopbackTarget("192.0.2.1", 3000)).toThrow(
      new TnlError("sdk.target_invalid"),
    );
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
  const vectors = z
    .array(z.object({ projectRoot: z.string(), service: z.string(), digest: z.string() }))
    .parse(
      JSON.parse(
        await readFile(
          new URL("../../cmd/tnl/testdata/dev-socket-vectors.json", import.meta.url),
          "utf8",
        ),
      ),
    );
  expect(vectors).not.toHaveLength(0);
  for (const vector of vectors) {
    expect(socketIdentity(vector.projectRoot, vector.service)).toBe(vector.digest);
  }
});

test("project metadata agrees with the Go validation fixture", async () => {
  const fixture = z
    .object({
      version: z.literal(2),
      cases: z.array(
        z.object({
          name: z.string(),
          valid: z.boolean(),
          runtimeValid: z.boolean().optional(),
          metadata: z.object({
            namespace: z.string(),
            dev: z.boolean(),
            version: z.number(),
            worktree: z.unknown().optional(),
            oauth: z.object({ hostname: z.string(), url: z.string() }).optional(),
            webhooks: z
              .record(
                z.string(),
                z.object({
                  hostname: z.string(),
                  url: z.string(),
                  service: z.string(),
                  path: z.string(),
                  methods: z.array(z.string()),
                }),
              )
              .optional(),
            serviceDirectories: z.record(z.string(), z.string()),
            services: z.record(
              z.string(),
              z.object({
                namespace: z.string(),
                hostname: z.string(),
                url: z.string(),
              }),
            ),
          }),
        }),
      ),
    })
    .parse(
      JSON.parse(
        await readFile(
          new URL("../../api/fixtures/project-metadata-v2.json", import.meta.url),
          "utf8",
        ),
      ) as unknown,
    );
  expect(fixture.cases.length).toBeGreaterThan(0);
  for (const entry of fixture.cases) {
    const root = await temporaryDirectory("tnl-project-contract-");
    await mkdir(path.join(root, ".tnl"));
    await writeFile(path.join(root, ".tnl", "project.json"), JSON.stringify(entry.metadata));
    if (entry.valid) {
      expect(discoverProject(root)?.project.namespace, entry.name).toBe(entry.metadata.namespace);
    } else {
      expect(() => discoverProject(root), entry.name).toThrow();
    }
    const { namespace, services, dev, oauth, webhooks, worktree } = entry.metadata;
    const runtime = JSON.stringify({
      namespace,
      services,
      dev,
      ...(worktree === undefined ? {} : { worktree }),
      ...(oauth === undefined ? {} : { oauth }),
      ...(webhooks === undefined ? {} : { webhooks }),
    });
    if (entry.runtimeValid ?? entry.valid) {
      expect(parseRuntimePayload(runtime)?.namespace, entry.name).toBe(namespace);
    } else {
      expect(() => parseRuntimePayload(runtime), entry.name).toThrow();
    }
  }
});

test("tnl dev requests and assignment agree with the Go wire fixture", async () => {
  const fixture = z
    .object({
      version: z.literal(1),
      configuration: z.object({ protocol: z.literal(1), framework: z.string() }),
      invalidConfiguration: z.object({ protocol: z.literal(1), framework: z.string() }),
      target: z.object({ protocol: z.literal(1), framework: z.string(), target: z.string() }),
      invalidTarget: z.object({
        protocol: z.literal(1),
        framework: z.string(),
        target: z.string(),
      }),
      invalidAssignmentOverride: z.object({ unexpected: z.literal(true) }),
      assignment: z.object({
        protocol: z.literal(1),
        tunnelID: z.string(),
        service: z.string(),
        namespace: z.string(),
        hostname: z.string(),
        publicURL: z.string(),
        project: z.object({
          namespace: z.string(),
          dev: z.boolean(),
          oauth: z.object({ hostname: z.string(), url: z.string() }).optional(),
          webhooks: z
            .record(
              z.string(),
              z.object({
                hostname: z.string(),
                url: z.string(),
                service: z.string(),
                path: z.string(),
                methods: z.array(z.string()),
              }),
            )
            .optional(),
          services: z.record(
            z.string(),
            z.object({ namespace: z.string(), hostname: z.string(), url: z.string() }),
          ),
        }),
      }),
    })
    .parse(
      JSON.parse(
        await readFile(new URL("../../api/fixtures/dev-protocol-v1.json", import.meta.url), "utf8"),
      ) as unknown,
    );
  const bootstrap = await startTestBootstrap({ responseBody: JSON.stringify(fixture.assignment) });
  const assignment = await requestTunnelAssignment(fixture.configuration.framework, {
    socket: bootstrap.environment.TNL_DEV_SOCKET ?? "",
  });
  const { protocol, ...expectedAssignment } = fixture.assignment;
  expect(protocol).toBe(1);
  expect(assignment).toMatchObject(expectedAssignment);
  const target = new URL(fixture.target.target);
  await registerLocalTarget(
    assignment,
    canonicalLoopbackTarget(target.hostname, Number(target.port)),
  );
  expect(bootstrap.requests.map((request) => request.body)).toEqual([
    fixture.configuration,
    fixture.target,
  ]);
  await expect(
    requestTunnelAssignment(fixture.invalidConfiguration.framework, {
      socket: bootstrap.environment.TNL_DEV_SOCKET ?? "",
    }),
  ).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
  const invalidTarget = new URL(fixture.invalidTarget.target);
  expect(() =>
    canonicalLoopbackTarget(invalidTarget.hostname, Number(invalidTarget.port)),
  ).toThrow();
  const invalidBootstrap = await startTestBootstrap({
    responseBody: JSON.stringify({ ...fixture.assignment, ...fixture.invalidAssignmentOverride }),
  });
  await expect(
    requestTunnelAssignment(fixture.configuration.framework, {
      socket: invalidBootstrap.environment.TNL_DEV_SOCKET ?? "",
    }),
  ).rejects.toMatchObject({ code: "sdk.response_invalid" });
});

function validAssignmentResponse() {
  return {
    hostname: "api.member.example",
    namespace: "member.example",
    project: testPublicProject(true),
    protocol: 1,
    publicURL: "https://api.member.example",
    service: "api",
    tunnelID: `tun_${"b".repeat(22)}`,
  };
}

function requiredBootstrap<T>(value: T | null): T {
  if (value === null) {
    throw new Error("test bootstrap was not available");
  }
  return value;
}

async function rejection(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof Error) return error;
    throw new Error("promise rejected with a non-Error value", { cause: error });
  }
  throw new Error("promise unexpectedly resolved");
}
