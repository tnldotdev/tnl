import { createServer } from "node:http";
import { expect, test, vi } from "vitest";
import {
  createPreparedService,
  prepareService,
  runtimeRequest,
} from "../../dist/internal/publisher/app.js";
import { openFetch, openServer } from "../../dist/internal/publisher/open.js";
import { readTelemetryDisabled } from "../../dist/internal/publisher/telemetry.js";
import { TnlError } from "../../dist/errors.js";
import { startTestBootstrap } from "../helpers/bootstrap.js";
import { withProcessEnvironment } from "../helpers/environment.js";

test.each([
  [undefined, false],
  ["1", true],
  ["true", true],
  ["True", true],
  ["TRUE", true],
  ["TrUe", true],
  ["yes", true],
  ["YES", true],
  ["YeS", true],
  ["0", false],
  ["false", false],
  ["False", false],
  ["FALSE", false],
  ["FaLsE", false],
  ["no", false],
  ["NO", false],
  ["nO", false],
] as const)("Kong telemetry setting %j normalizes to %s", (value, disabled) => {
  expect(readTelemetryDisabled(value)).toBe(disabled);
});

test("equivalent telemetry opt-outs reuse the same cached preparation", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment({ ...bootstrap.environment, TNL_NO_TELEMETRY: "1" }, async () => {
    const first = prepareService();
    process.env.TNL_NO_TELEMETRY = "false";
    const handle = await first;
    process.env.TNL_NO_TELEMETRY = "true";
    const second = prepareService();
    try {
      // observe either outcome before asserting so red cannot leave native work running.
      const result = await second.catch((error: unknown) => error);
      expect(second).toBe(first);
      expect(result).toBe(handle);
      expect(bootstrap.requests[0]?.body).toMatchObject({ telemetry_disabled: true });
      process.env.TNL_NO_TELEMETRY = "private-invalid-setting";
      await expect(Promise.resolve().then(() => prepareService())).rejects.toMatchObject({
        code: "sdk.configuration_invalid",
        message: expect.not.stringContaining("private-invalid-setting"),
      });
      expect(bootstrap.requests.filter((request) => request.path === "/v1/prepare")).toHaveLength(
        1,
      );
    } finally {
      const other = await second.catch(() => undefined);
      if (other !== undefined && other !== handle) await other.close();
      await handle.close();
    }
  });
});

test("enabled and disabled telemetry never share a cached owner", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment(
    { ...bootstrap.environment, TNL_NO_TELEMETRY: "false" },
    async () => {
      const first = prepareService();
      const handle = await first;
      process.env.TNL_NO_TELEMETRY = "true";
      const second = prepareService();
      try {
        const result = await second.catch((error: unknown) => error);
        expect(second).not.toBe(first);
        // the real IPC fixture fences a second owner rather than silently reusing the first.
        expect(result).toMatchObject({ code: "sdk.owner_conflict" });
        expect(
          bootstrap.requests.filter((request) => request.path === "/v1/prepare"),
        ).toMatchObject([
          { body: { telemetry_disabled: false } },
          { body: { telemetry_disabled: true } },
        ]);
      } finally {
        const other = await second.catch(() => undefined);
        if (other !== undefined && other !== handle) await other.close();
        await handle.close();
      }
    },
  );
});

test.each(["vite", "next"] as const)(
  "%s prepare captures telemetry before asynchronous owner startup",
  async (framework) => {
    const bootstrap = await startTestBootstrap();
    await withProcessEnvironment({ TNL_NO_TELEMETRY: "true" }, async () => {
      const handle = await createPreparedService({}, framework, {
        start: async () => {
          await Promise.resolve();
          process.env.TNL_NO_TELEMETRY = "false";
          return bootstrap.endpoint;
        },
        request: runtimeRequest,
      });
      try {
        expect(bootstrap.requests[0]?.body).toMatchObject({ framework, telemetry_disabled: true });
      } finally {
        await handle.close();
      }
    });
  },
);

test.each(["", "t", "T", "f", "F", "private-invalid-setting", " true", "true "])(
  "invalid telemetry setting %j is safely rejected before prepare or open starts native",
  async (value) => {
    const bootstrap = await startTestBootstrap();
    await withProcessEnvironment(
      { ...bootstrap.environment, TNL_NO_TELEMETRY: value },
      async () => {
        expect(() => readTelemetryDisabled(value)).toThrow(TnlError);
        const start = vi.fn(async (): Promise<never> => {
          throw new TnlError("sdk.dev_unavailable");
        });
        const runtime = { start, request: async () => undefined, pause: async () => {} };
        const app = createServer();
        await new Promise<void>((resolve) => app.listen(0, "127.0.0.1", resolve));
        try {
          for (const call of [
            () => createPreparedService({}, "node", runtime),
            () => prepareService(),
            () => openServer(app, {}, runtime),
            () => openFetch(() => new Response("app"), {}, runtime),
          ]) {
            const failure = await Promise.resolve()
              .then<unknown>(call)
              .catch((error: unknown) => error);
            expect(failure).toBeInstanceOf(TnlError);
            expect(failure).toMatchObject({
              code: "sdk.configuration_invalid",
              message: new TnlError("sdk.configuration_invalid").message,
            });
          }
          expect(start).not.toHaveBeenCalled();
        } finally {
          await new Promise<void>((resolve) => app.close(() => resolve()));
        }
      },
    );
  },
);
