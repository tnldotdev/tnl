import { afterEach, describe, expect, test, vi } from "vitest";
import { parseRuntimePayload } from "./dist/internal/runtime.js";
import { startTestProcess } from "./test-helper/process.js";

const project = {
  namespace: "member.example",
  services: {
    api: {
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
  test("exposes a normal port and optional metadata outside tnl dev", async () => {
    vi.stubEnv("TNL_PROJECT_RUNTIME", undefined);
    vi.stubEnv("TNL_DEV_PROTOCOL", undefined);
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
    expect(runtime.tnl.register).toBeTypeOf("function");
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

  test("uses an ephemeral listener under tnl dev and honors a forced port", async () => {
    vi.stubEnv("TNL_DEV_PROTOCOL", "1");
    vi.stubEnv("TNL_DEV_PORT", undefined);
    vi.resetModules();
    expect((await import("@tnldotdev/tnl")).tnl.port).toBe(0);
    vi.stubEnv("TNL_DEV_PORT", "5173");
    vi.resetModules();
    expect((await import("@tnldotdev/tnl")).tnl.port).toBe(5173);
  });

  test("respects normal Node and Bun port settings outside tnl dev", async () => {
    vi.stubEnv("TNL_DEV_PROTOCOL", undefined);
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
    expect(() => parseRuntimePayload("x".repeat(64 * 1024 + 1))).toThrow(/exceeds 65536 bytes/);
  });
});
