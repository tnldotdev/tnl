import { afterEach, describe, expect, test, vi } from "vitest";
import { readFile } from "node:fs/promises";
import * as z from "zod";
import { parseRuntimePayload, serializeRuntimePayload } from "./dist/internal/runtime.js";
import { startTestProcess } from "./test-helper/process.js";

const project = {
  namespace: "member.example",
  services: {
    api: {
      protocol: "http",
      hostname: "api.member.example",
      namespace: "member.example",
      url: "https://api.member.example",
    },
  },
};

afterEach(() => {
  vi.resetModules();
  vi.unstubAllEnvs();
});

describe("root runtime", () => {
  test("exposes the configured port and optional metadata", async () => {
    vi.stubEnv("TNL_PROJECT_RUNTIME", undefined);
    vi.stubEnv("PORT", undefined);
    vi.resetModules();
    const runtime = await import("@tnldotdev/tnl");
    expect(runtime.tnl).toMatchObject({ port: 3000, dev: false });
    expect(runtime.tnl.services).toBeUndefined();
    expect(runtime.tnl.namespace).toBeUndefined();
  });

  test.each([false, true])("exposes validated metadata with dev=%s", async (running) => {
    vi.stubEnv("TNL_PROJECT_RUNTIME", JSON.stringify({ ...project, dev: running }));
    vi.resetModules();
    const runtime = await import("@tnldotdev/tnl");
    expect(runtime.tnl).toMatchObject({ ...project, dev: running });
    expect(runtime.tnl.prepare).toBeTypeOf("function");
  });

  test("imports the built root runtime with no process global", async () => {
    const child = startTestProcess(process.execPath, [
      "--input-type=module",
      "-e",
      `const host = process;
       delete globalThis.process;
       const { tnl } = await import(${JSON.stringify(new URL("./dist/index.js", import.meta.url).href)});
       host.stdout.write(JSON.stringify({ processAbsent: typeof process === "undefined", metadataAbsent: tnl.services === undefined }));`,
    ]);
    await child.ready();
    await expect.poll(() => child.child.exitCode).toBe(0);
    expect(JSON.parse(child.output())).toEqual({ processAbsent: true, metadataAbsent: true });
  });

  test("deep-freezes the complete runtime value", () => {
    const runtime = parseRuntimePayload(JSON.stringify({ ...project, dev: true }));
    expect(Object.isFrozen(runtime)).toBe(true);
    expect(Object.isFrozen(runtime?.services)).toBe(true);
    expect(Object.isFrozen(runtime?.services.api)).toBe(true);
  });

  test("validates mounted service URLs and freezes their paths", () => {
    const web = {
      protocol: "http",
      hostname: "web.member.example",
      namespace: "member.example",
      url: "https://web.member.example",
      paths: {
        "/api": { service: "api", url: "https://web.member.example/api", stripPrefix: true },
      },
    };
    const payload = { ...project, services: { ...project.services, web }, dev: true };
    const runtime = parseRuntimePayload(JSON.stringify(payload));
    expect(runtime?.services.web?.paths?.["/api"]?.url).toBe("https://web.member.example/api");
    expect(Object.isFrozen(runtime?.services.web?.paths)).toBe(true);
    expect(Object.isFrozen(runtime?.services.web?.paths?.["/api"])).toBe(true);
    for (const invalid of [
      { "/api": { ...web.paths["/api"], service: "Invalid" } },
      { "/api": { ...web.paths["/api"], url: "https://api.member.example/api" } },
      { "/__tnl/share": web.paths["/api"] },
    ]) {
      expect(() =>
        parseRuntimePayload(
          JSON.stringify({
            ...payload,
            services: { ...payload.services, web: { ...web, paths: invalid } },
          }),
        ),
      ).toThrow();
    }
  });

  test("does not expose inherited properties as project services", () => {
    const runtime = parseRuntimePayload(JSON.stringify({ ...project, dev: true }));
    expect(Object.getPrototypeOf(runtime?.services)).toBeNull();
    expect(runtime?.services.constructor).toBeUndefined();
  });

  test("respects Node and Bun port settings", async () => {
    vi.stubEnv("PORT", "4300");
    vi.resetModules();
    expect((await import("@tnldotdev/tnl")).tnl.port).toBe(4300);
    vi.stubEnv("BUN_PORT", "4400");
    vi.stubGlobal("Bun", {});
    vi.resetModules();
    expect((await import("@tnldotdev/tnl")).tnl.port).toBe(4400);
  });

  test.each([
    ["invalid JSON", "{"],
    ["unknown fields", JSON.stringify({ ...project, dev: false, extra: true })],
    [
      "invalid service URL",
      JSON.stringify({
        ...project,
        dev: false,
        services: { api: { ...project.services.api, url: "http://api.member.example" } },
      }),
    ],
    [
      "too many services",
      JSON.stringify({
        namespace: "member.example",
        dev: false,
        services: Object.fromEntries(
          Array.from({ length: 33 }, (_, index) => [
            `s${index}`,
            {
              protocol: "http",
              hostname: `s${index}.member.example`,
              namespace: "member.example",
              url: `https://s${index}.member.example`,
            },
          ]),
        ),
      }),
    ],
  ])("rejects %s", (_name, payload) => {
    expect(() => parseRuntimePayload(payload)).toThrow();
  });

  test("rejects an oversized payload before parsing", () => {
    expect(() => parseRuntimePayload("x".repeat(64 * 1024 + 1))).toThrow(
      /project metadata is invalid/,
    );
  });

  test("serialization validates nested metadata before exposing it to a browser", () => {
    const valid = parseRuntimePayload(JSON.stringify({ ...project, dev: false }));
    const api = valid?.services.api;
    if (!valid || !api) throw new Error("missing runtime");
    expect(JSON.parse(serializeRuntimePayload(valid, true)) as unknown).toEqual({
      ...project,
      dev: true,
    });
    const unsafe = { ...valid, services: { api: { ...api, target: "private.internal:3000" } } };
    expect(() => serializeRuntimePayload(unsafe, true)).toThrow();
  });

  test("uses the shared HTTP and saved TCP metadata contract", async () => {
    const fixture = z
      .object({
        cases: z.array(
          z.object({
            name: z.string(),
            valid: z.boolean(),
            runtimeValid: z.boolean().optional(),
            metadata: z.object({ namespace: z.string(), services: z.unknown() }).passthrough(),
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
    for (const entry of fixture.cases) {
      const { version: _version, serviceDirectories: _directories, ...payload } = entry.metadata;
      if (entry.runtimeValid ?? entry.valid) {
        expect(() => parseRuntimePayload(JSON.stringify(payload)), entry.name).not.toThrow();
      } else {
        expect(() => parseRuntimePayload(JSON.stringify(payload)), entry.name).toThrow();
      }
    }
  });

  test.each(["tcp", "postgres", "mysql", "redis", "ssh"])(
    "rejects private or removed %s addresses in browser metadata",
    (protocol) => {
      const db = {
        protocol,
        namespace: "member.example",
        hostname: "db.member.example",
        port: 15432,
        address: "db.member.example:15432",
      };
      const payload = { ...project, services: { ...project.services, db }, dev: true };
      expect(() => parseRuntimePayload(JSON.stringify(payload))).toThrow();
      for (const extra of [
        { target: "db.internal:5432" },
        { accessToken: "secret" },
        { paths: {} },
        { port: 15432.5 },
        { port: 65536 },
      ]) {
        expect(() =>
          parseRuntimePayload(
            JSON.stringify({ ...payload, services: { db: { ...db, ...extra } } }),
          ),
        ).toThrow();
      }
      expect(() =>
        parseRuntimePayload(
          JSON.stringify({
            ...payload,
            aliases: {
              review: {
                service: "db",
                hostname: "review.member.example",
                url: "https://review.member.example",
              },
            },
          }),
        ),
      ).toThrow();
    },
  );

  test("uses the canonical Go hostname cases for project metadata", async () => {
    const fixture = z
      .object({
        version: z.literal(1),
        cases: z.array(
          z.object({
            context: z.string(),
            input: z.string(),
            canonical: z.string().optional(),
          }),
        ),
      })
      .parse(
        JSON.parse(
          await readFile(new URL("../../api/fixtures/hostname/v1.json", import.meta.url), "utf8"),
        ) as unknown,
      );
    expect(fixture.cases.length).toBeGreaterThan(0);
    for (const entry of fixture.cases.filter((item) => item.context === "hostname")) {
      const payload = JSON.stringify({ namespace: entry.input, services: {}, dev: false });
      if (entry.canonical === entry.input || entry.input === "") {
        expect(parseRuntimePayload(payload)?.namespace, entry.input).toBe(entry.input);
      } else {
        expect(() => parseRuntimePayload(payload), entry.input).toThrow();
      }
    }
  });
});
