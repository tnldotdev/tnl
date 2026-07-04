import { afterEach, describe, expect, test, vi } from "vitest";
import { parseRuntimePayload } from "./dist/internal/runtime.js";

const project = {
  memberNamespace: "member.example",
  services: {
    api: {
      hostname: "api.member.example",
      memberNamespace: "member.example",
      url: "https://api.member.example",
    },
  },
};

afterEach(() => {
  delete process.env.TNL_PROJECT_RUNTIME;
  vi.resetModules();
});

describe("root runtime", () => {
  test("is undefined without injected metadata", async () => {
    delete process.env.TNL_PROJECT_RUNTIME;
    vi.resetModules();
    const runtime = await import("@tnldotdev/tnl");
    expect(runtime.tnl).toBeUndefined();
  });

  test.each([false, true])(
    "exposes validated metadata with runningUnderTnlDev=%s",
    async (running) => {
      process.env.TNL_PROJECT_RUNTIME = JSON.stringify({ ...project, runningUnderTnlDev: running });
      vi.resetModules();
      const runtime = await import("@tnldotdev/tnl");
      expect(runtime.tnl).toEqual({ ...project, runningUnderTnlDev: running });
    },
  );

  test("deep-freezes the complete runtime value", () => {
    const runtime = parseRuntimePayload(JSON.stringify({ ...project, runningUnderTnlDev: true }));
    expect(Object.isFrozen(runtime)).toBe(true);
    expect(Object.isFrozen(runtime?.services)).toBe(true);
    expect(Object.isFrozen(runtime?.services.api)).toBe(true);
  });

  test.each([
    ["invalid JSON", "{"],
    ["unknown fields", JSON.stringify({ ...project, runningUnderTnlDev: false, extra: true })],
    [
      "invalid service URL",
      JSON.stringify({
        ...project,
        runningUnderTnlDev: false,
        services: { api: { ...project.services.api, url: "http://api.member.example" } },
      }),
    ],
    [
      "too many services",
      JSON.stringify({
        memberNamespace: "member.example",
        runningUnderTnlDev: false,
        services: Object.fromEntries(
          Array.from({ length: 33 }, (_, index) => [
            `s${index}`,
            {
              hostname: `s${index}.member.example`,
              memberNamespace: "member.example",
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
